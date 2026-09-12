'use strict';

require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { Pool } = require('pg');

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ======================================================
// CONFIG
// ======================================================

const CONFIG = {
  PORT: process.env.PORT || 3000,
  JWT_SECRET: process.env.JWT_SECRET || 'real-estate-super-secret-key',
  JWT_EXPIRY_SECONDS: 7 * 24 * 60 * 60,
  SALT_BYTES: 16,
  SCRYPT_KEY_LENGTH: 64,
  MIN_PASSWORD_LENGTH: 6
};

// ======================================================
// DATABASE
// ======================================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL &&
       process.env.DATABASE_URL.includes('neon.tech')
    ? { rejectUnauthorized: false }
    : false
});

async function query(text, params) {
  const result = await pool.query(text, params);
  return result.rows;
}

// ======================================================
// PASSWORD HASHING
// ======================================================

async function hashPassword(password) {
  return await bcrypt.hash(
    password,
    CONFIG.BCRYPT_SALT_ROUNDS
  );
}

async function verifyPassword(password, stored) {
  try {
    return await bcrypt.compare(password, stored);
  } catch (err) {
    return false;
  }
function verifyToken(token) {
  const segments = token.split('.');

  if (segments.length !== 3) {
    throw new Error('Malformed token');
  }

  const header = segments[0];
  const body = segments[1];
  const signature = segments[2];

  const expectedSignature = crypto
    .createHmac('sha256', CONFIG.JWT_SECRET)
    .update(header + '.' + body)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  if (signature !== expectedSignature) {
    throw new Error('Invalid token signature');
  }

  const payload = JSON.parse(
    Buffer.from(body, 'base64').toString('utf8')
  );

  if (
    !payload.exp ||
    payload.exp < Math.floor(Date.now() / 1000)
  ) {
    throw new Error('Token expired');
  }

  return payload;
}

// ======================================================
// AUTHENTICATION
// ======================================================

async function getAuthenticatedUser(req) {
  const authHeader = req.headers.authorization;

  if (
    !authHeader ||
    !authHeader.startsWith('Bearer ')
  ) {
    return null;
  }

  try {
    const token = authHeader.slice(7);
    const decoded = verifyToken(token);

    const users = await query(
      `
      SELECT
        u.id,
        u.full_name,
        u.email,
        u.phone,
        u.is_active,
        r.name AS role
      FROM users u
      JOIN roles r ON r.id = u.role_id
      WHERE u.id = $1
        AND u.is_active = true
      `,
      [decoded.userId]
    );

    if (users.length === 0) {
      return null;
    }

    const user = users[0];

    const permissions = await query(
      `
      SELECT p.slug
      FROM permissions p
      JOIN role_permissions rp
        ON rp.permission_id = p.id
      JOIN roles r
        ON r.id = rp.role_id
      WHERE r.name = $1
      `,
      [user.role]
    );

    return {
      id: user.id,
      fullName: user.full_name,
      email: user.email,
      phone: user.phone,
      role: user.role,
      permissions: permissions.map(
        function (p) {
          return p.slug;
        }
      )
    };
  } catch (err) {
    return null;
  }
}

function hasPermission(user, permission) {
  return (
    user &&
    user.permissions &&
    user.permissions.indexOf(permission) !== -1
  );
}

async function requireAuth(req, res, next) {
  const user = await getAuthenticatedUser(req);

  if (!user) {
    return res.status(401).json({
      error: 'Unauthorized'
    });
  }

  req.user = user;
  next();
}

function requirePermission(permission) {
  return async function (req, res, next) {
    const user = await getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        error: 'Unauthorized'
      });
    }

    if (!hasPermission(user, permission)) {
      return res.status(403).json({
        error: 'Forbidden',
        requiredPermission: permission
      });
    }

    req.user = user;
    next();
  };
}

// ======================================================
// ADMIN SEED
// ======================================================

async function seedAdminIfMissing() {
  try {
    const existing = await query(
      'SELECT id FROM users WHERE email = $1',
      ['admin@test.com']
    );

    if (existing.length > 0) {
      console.log('Admin user already exists');
      return;
    }

    const adminRole = await query(
      "SELECT id FROM roles WHERE name = 'admin'"
    );

    if (adminRole.length === 0) {
      console.log('Admin role not found');
      return;
    }

    const passwordHash = await hashPassword('admin123');

    await query(
      `
      INSERT INTO users
        (role_id, full_name, email, password_hash, is_active)
      VALUES
        ($1, $2, $3, $4, true)
      `,
      [
        adminRole[0].id,
        'System Administrator',
        'admin@test.com',
        passwordHash
      ]
    );

    console.log('Default admin user created');
  } catch (err) {
    console.error(
      'Admin seed error:',
      err.message
    );
  }
}

// ======================================================
// IMAGE UPLOAD
// ======================================================

const uploadsDir = path.join(
  __dirname,
  'uploads'
);

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, {
    recursive: true
  });
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },

  filename: function (req, file, cb) {
    const extension =
      path.extname(file.originalname) || '.jpg';

    const filename =
      Date.now() +
      '-' +
      crypto.randomBytes(6).toString('hex') +
      extension;

    cb(null, filename);
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024
  },
  fileFilter: function (req, file, cb) {
    const allowed = [
      'image/jpeg',
      'image/png',
      'image/webp'
    ];

    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(
        new Error(
          'Only JPG, PNG and WEBP images are allowed'
        )
      );
    }
  }
});

app.use(
  '/uploads',
  express.static(uploadsDir)
);

// ======================================================
// ROOT
// ======================================================

app.get('/', function (req, res) {
  res.json({
    status: 'ok',
    service: 'real-estate-backend-api',
    database: 'postgresql',
    timestamp: new Date().toISOString()
  });
});

// ======================================================
// AUTH - REGISTER
// ======================================================

app.post(
  '/api/auth/register',
  async function (req, res) {
    try {
      const body = req.body;

      if (
        !body.full_name ||
        !body.email ||
        !body.password
      ) {
        return res.status(400).json({
          error: 'Missing required fields',
          required: [
            'full_name',
            'email',
            'password'
          ]
        });
      }

      if (
        body.password.length <
        CONFIG.MIN_PASSWORD_LENGTH
      ) {
        return res.status(400).json({
          error:
            'Password must be at least ' +
            CONFIG.MIN_PASSWORD_LENGTH +
            ' characters'
        });
      }

      const email =
        String(body.email)
          .trim()
          .toLowerCase();

      const existing = await query(
        'SELECT id FROM users WHERE email = $1',
        [email]
      );

      if (existing.length > 0) {
        return res.status(409).json({
          error: 'Email already registered'
        });
      }

      const clientRole = await query(
        "SELECT id FROM roles WHERE name = 'client'"
      );

      if (clientRole.length === 0) {
        return res.status(500).json({
          error: 'Client role not configured'
        });
      }

      const passwordHash =
        hashPassword(body.password);

      const inserted = await query(
        `
        INSERT INTO users
          (
            role_id,
            full_name,
            email,
            phone,
            password_hash,
            is_active
          )
        VALUES
          ($1, $2, $3, $4, $5, true)
        RETURNING id, full_name, email
        `,
        [
          clientRole[0].id,
          body.full_name,
          email,
          body.phone || null,
          passwordHash
        ]
      );

      return res.status(201).json({
        message:
          'User registered successfully',

        user: {
          id: inserted[0].id,
          full_name:
            inserted[0].full_name,
          email: inserted[0].email,
          role: 'client'
        }
      });
    } catch (err) {
      return res.status(500).json({
        error: err.message
      });
    }
  }
);

// ======================================================
// AUTH - LOGIN
// ======================================================

app.post(
  '/api/auth/login',
  async function (req, res) {
    try {
      const body = req.body;

      if (
        !body.email ||
        !body.password
      ) {
        return res.status(400).json({
          error:
            'Email and password are required'
        });
      }

      const email =
        String(body.email)
          .trim()
          .toLowerCase();

      const users = await query(
        `
        SELECT
          u.id,
          u.full_name,
          u.email,
          u.password_hash,
          u.is_active,
          r.name AS role
        FROM users u
        JOIN roles r
          ON r.id = u.role_id
        WHERE u.email = $1
        `,
        [email]
      );

      if (users.length === 0) {
        return res.status(401).json({
          error: 'Invalid credentials'
        });
      }

      const user = users[0];

      if (!user.is_active) {
        return res.status(403).json({
          error: 'Account is disabled'
        });
      }

      if (
        !verifyPassword(
          body.password,
          user.password_hash
        )
      ) {
        return res.status(401).json({
          error: 'Invalid credentials'
        });
      }

      const token = signToken({
        userId: user.id,
        role: user.role
      });

      return res.json({
        message: 'Login successful',
        token: token,

        user: {
          id: user.id,
          full_name: user.full_name,
          email: user.email,
          role: user.role
        }
      });
    } catch (err) {
      return res.status(500).json({
        error: err.message
      });
    }
  }
);

// ======================================================
// AUTH - ME
// ======================================================

app.get(
  '/api/auth/me',
  requireAuth,
  async function (req, res) {
    return res.json({
      user: req.user
    });
  }
);

// ======================================================
// ADMIN - USERS
// ======================================================

app.get(
  '/api/admin/users',
  requirePermission('user:read'),
  async function (req, res) {
    try {
      const users = await query(
        `
        SELECT
          u.id,
          u.full_name,
          u.email,
          u.phone,
          u.is_active,
          u.created_at,
          r.name AS role
        FROM users u
        JOIN roles r
          ON r.id = u.role_id
        ORDER BY u.created_at DESC
        `
      );

      return res.json({
        count: users.length,
        users: users
      });
    } catch (err) {
      return res.status(500).json({
        error: err.message
      });
    }
  }
);

// ======================================================
// ADMIN - CHANGE ROLE
// ======================================================

app.patch(
  '/api/admin/users/:id/role',
  requirePermission('user:update'),
  async function (req, res) {
    try {
      const allowedRoles = [
        'admin',
        'agent',
        'client'
      ];

      const newRole = req.body.role;

      if (
        !newRole ||
        !allowedRoles.includes(newRole)
      ) {
        return res.status(400).json({
          error: 'Invalid role',
          allowed: allowedRoles
        });
      }

      const userId =
        parseInt(req.params.id, 10);

      if (Number.isNaN(userId)) {
        return res.status(400).json({
          error: 'Invalid user id'
        });
      }

      const target = await query(
        'SELECT id FROM users WHERE id = $1',
        [userId]
      );

      if (target.length === 0) {
        return res.status(404).json({
          error: 'User not found'
        });
      }

      const role = await query(
        'SELECT id FROM roles WHERE name = $1',
        [newRole]
      );

      if (role.length === 0) {
        return res.status(400).json({
          error: 'Role not configured'
        });
      }

      await query(
        `
        UPDATE users
        SET
          role_id = $1,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $2
        `,
        [
          role[0].id,
          userId
        ]
      );

      return res.json({
        message:
          'User role updated successfully',
        user_id: userId,
        new_role: newRole
      });
    } catch (err) {
      return res.status(500).json({
        error: err.message
      });
    }
  }
);

// ======================================================
// CATEGORIES - GET
// ======================================================

app.get(
  '/api/categories',
  async function (req, res) {
    try {
      const categories = await query(
        `
        SELECT id, name, slug
        FROM categories
        ORDER BY name ASC
        `
      );

      return res.json({
        count: categories.length,
        categories: categories
      });
    } catch (err) {
      return res.status(500).json({
        error: err.message
      });
    }
  }
);

// ======================================================
// CATEGORIES - CREATE
// ======================================================

app.post(
  '/api/categories',
  requirePermission('category:create'),
  async function (req, res) {
    try {
      const name =
        String(req.body.name || '').trim();

      const slug =
        String(req.body.slug || '')
          .trim()
          .toLowerCase();

      if (!name || !slug) {
        return res.status(400).json({
          error:
            'name and slug are required'
        });
      }

      const inserted = await query(
        `
        INSERT INTO categories
          (name, slug)
        VALUES
          ($1, $2)
        RETURNING id, name, slug
        `,
        [name, slug]
      );

      return res.status(201).json({
        message:
          'Category created successfully',
        category: inserted[0]
      });
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({
          error:
            'Category name or slug already exists'
        });
      }

      return res.status(500).json({
        error: err.message
      });
    }
  }
);

// ======================================================
// PROPERTIES - LIST + FILTER + PAGINATION
// ======================================================

app.get(
  '/api/properties',
  async function (req, res) {
    try {
      const page =
        Math.max(
          parseInt(req.query.page, 10) || 1,
          1
        );

      const limit = 10;
      const offset =
        (page - 1) * limit;

      const values = [];
      const conditions = [];

      if (req.query.category) {
        values.push(req.query.category);

        conditions.push(
          `(c.slug = $${values.length}
            OR c.name = $${values.length})`
        );
      }

      if (req.query.min_price) {
        const price =
          Number(req.query.min_price);

        if (Number.isNaN(price)) {
          return res.status(400).json({
            error: 'Invalid min_price'
          });
        }

        values.push(price);

        conditions.push(
          `p.price >= $${values.length}`
        );
      }

      if (req.query.max_price) {
        const price =
          Number(req.query.max_price);

        if (Number.isNaN(price)) {
          return res.status(400).json({
            error: 'Invalid max_price'
          });
        }

        values.push(price);

        conditions.push(
          `p.price <= $${values.length}`
        );
      }

      if (req.query.city) {
        values.push(
          String(req.query.city).trim()
        );

        conditions.push(
          `LOWER(p.city) = LOWER($${values.length})`
        );
      }

      if (req.query.status) {
        values.push(req.query.status);

        conditions.push(
          `p.status = $${values.length}`
        );
      }

      const where =
        conditions.length > 0
          ? 'WHERE ' + conditions.join(' AND ')
          : '';

      const countResult = await query(
        `
        SELECT COUNT(*)::integer AS total
        FROM properties p
        JOIN categories c
          ON c.id = p.category_id
        ${where}
        `,
        values
      );

      const total =
        countResult[0].total;

      const dataValues =
        values.slice();

      dataValues.push(limit);
      const limitParam =
        dataValues.length;

      dataValues.push(offset);
      const offsetParam =
        dataValues.length;

      const properties = await query(
        `
        SELECT
          p.id,
          p.user_id,
          p.category_id,
          c.name AS category,
          c.slug AS category_slug,
          p.title,
          p.description,
          p.price,
          p.city,
          p.address,
          p.status,
          p.created_at,

          (
            SELECT pi.image_url
            FROM property_images pi
            WHERE pi.property_id = p.id
            ORDER BY
              pi.is_primary DESC,
              pi.id ASC
            LIMIT 1
          ) AS primary_image

        FROM properties p

        JOIN categories c
          ON c.id = p.category_id

        ${where}

        ORDER BY p.created_at DESC

        LIMIT $${limitParam}
        OFFSET $${offsetParam}
        `,
        dataValues
      );

      return res.json({
        page: page,
        limit: limit,
        total: total,
        total_pages:
          Math.ceil(total / limit),
        properties: properties
      });
    } catch (err) {
      return res.status(500).json({
        error: err.message
      });
    }
  }
);

// ======================================================
// PROPERTY - GET ONE
// ======================================================

app.get(
  '/api/properties/:id',
  async function (req, res) {
    try {
      const propertyId =
        parseInt(req.params.id, 10);

      if (Number.isNaN(propertyId)) {
        return res.status(400).json({
          error: 'Invalid property id'
        });
      }

      const properties = await query(
        `
        SELECT
          p.id,
          p.user_id,
          p.category_id,
          c.name AS category,
          c.slug AS category_slug,
          p.title,
          p.description,
          p.price,
          p.city,
          p.address,
          p.status,
          p.created_at
        FROM properties p
        JOIN categories c
          ON c.id = p.category_id
        WHERE p.id = $1
        `,
        [propertyId]
      );

      if (properties.length === 0) {
        return res.status(404).json({
          error: 'Property not found'
        });
      }

      const images = await query(
        `
        SELECT
          id,
          image_url,
          is_primary
        FROM property_images
        WHERE property_id = $1
        ORDER BY
          is_primary DESC,
          id ASC
        `,
        [propertyId]
      );

      return res.json({
        property: properties[0],
        images: images
      });
    } catch (err) {
      return res.status(500).json({
        error: err.message
      });
    }
  }
);

// ======================================================
// PROPERTY - CREATE
// ======================================================

app.post(
  '/api/properties',
  requirePermission('property:create'),
  async function (req, res) {
    try {
      const {
        category_id,
        title,
        description,
        price,
        city,
        address,
        status
      } = req.body;

      if (
        !category_id ||
        !title ||
        price === undefined ||
        !city
      ) {
        return res.status(400).json({
          error:
            'category_id, title, price and city are required'
        });
      }

      const numericPrice =
        Number(price);

      if (
        Number.isNaN(numericPrice) ||
        numericPrice < 0
      ) {
        return res.status(400).json({
          error: 'Invalid price'
        });
      }

      const categoryId =
        parseInt(category_id, 10);

      if (Number.isNaN(categoryId)) {
        return res.status(400).json({
          error: 'Invalid category_id'
        });
      }

      const propertyStatus =
        status || 'available';

      const allowedStatuses = [
        'available',
        'sold',
        'pending'
      ];

      if (
        !allowedStatuses.includes(
          propertyStatus
        )
      ) {
        return res.status(400).json({
          error: 'Invalid property status',
          allowed: allowedStatuses
        });
      }

      const category = await query(
        'SELECT id FROM categories WHERE id = $1',
        [categoryId]
      );

      if (category.length === 0) {
        return res.status(400).json({
          error: 'Category not found'
        });
      }

      const inserted = await query(
        `
        INSERT INTO properties
          (
            user_id,
            category_id,
            title,
            description,
            price,
            city,
            address,
            status
          )
        VALUES
          ($1,$2,$3,$4,$5,$6,$7,$8)
        RETURNING *
        `,
        [
          req.user.id,
          categoryId,
          title,
          description || null,
          numericPrice,
          city,
          address || null,
          propertyStatus
        ]
      );

      return res.status(201).json({
        message:
          'Property created successfully',
        property: inserted[0]
      });
    } catch (err) {
      return res.status(500).json({
        error: err.message
      });
    }
  }
);

// ======================================================
// PROPERTY - UPDATE
// ======================================================

app.put(
  '/api/properties/:id',
  requirePermission('property:update'),
  async function (req, res) {
    try {
      const propertyId =
        parseInt(req.params.id, 10);

      if (Number.isNaN(propertyId)) {
        return res.status(400).json({
          error: 'Invalid property id'
        });
      }

      const properties = await query(
        `
        SELECT *
        FROM properties
        WHERE id = $1
        `,
        [propertyId]
      );

      if (properties.length === 0) {
        return res.status(404).json({
          error: 'Property not found'
        });
      }

      const property =
        properties[0];

      if (
        req.user.role !== 'admin' &&
        property.user_id !== req.user.id
      ) {
        return res.status(403).json({
          error:
            'You can only update your own properties'
        });
      }

      const allowedStatuses = [
        'available',
        'sold',
        'pending'
      ];

      const categoryId =
        req.body.category_id !== undefined
          ? parseInt(
              req.body.category_id,
              10
            )
          : property.category_id;

      const price =
        req.body.price !== undefined
          ? Number(req.body.price)
          : property.price;

      const status =
        req.body.status !== undefined
          ? req.body.status
          : property.status;

      if (
        Number.isNaN(categoryId) ||
        Number.isNaN(price)
      ) {
        return res.status(400).json({
          error:
            'Invalid category_id or price'
        });
      }

      if (
        !allowedStatuses.includes(status)
      ) {
        return res.status(400).json({
          error: 'Invalid status',
          allowed: allowedStatuses
        });
      }

      const updated = await query(
        `
        UPDATE properties
        SET
          category_id = $1,
          title = $2,
          description = $3,
          price = $4,
          city = $5,
          address = $6,
          status = $7
        WHERE id = $8
        RETURNING *
        `,
        [
          categoryId,
          req.body.title !== undefined
            ? req.body.title
            : property.title,

          req.body.description !== undefined
            ? req.body.description
            : property.description,

          price,

          req.body.city !== undefined
            ? req.body.city
            : property.city,

          req.body.address !== undefined
            ? req.body.address
            : property.address,

          status,
          propertyId
        ]
      );

      return res.json({
        message:
          'Property updated successfully',
        property: updated[0]
      });
    } catch (err) {
      return res.status(500).json({
        error: err.message
      });
    }
  }
);

// ======================================================
// PROPERTY - DELETE
// ======================================================

app.delete(
  '/api/properties/:id',
  requirePermission('property:delete'),
  async function (req, res) {
    try {
      const propertyId =
        parseInt(req.params.id, 10);

      if (Number.isNaN(propertyId)) {
        return res.status(400).json({
          error: 'Invalid property id'
        });
      }

      const properties = await query(
        `
        SELECT *
        FROM properties
        WHERE id = $1
        `,
        [propertyId]
      );

      if (properties.length === 0) {
        return res.status(404).json({
          error: 'Property not found'
        });
      }

      const property =
        properties[0];

      if (
        req.user.role !== 'admin' &&
        property.user_id !== req.user.id
      ) {
        return res.status(403).json({
          error:
            'You can only delete your own properties'
        });
      }

      await query(
        'DELETE FROM properties WHERE id = $1',
        [propertyId]
      );

      return res.json({
        message:
          'Property deleted successfully',
        property_id: propertyId
      });
    } catch (err) {
      return res.status(500).json({
        error: err.message
      });
    }
  }
);

// ======================================================
// PROPERTY IMAGES - UPLOAD
// ======================================================

app.post(
  '/api/properties/:id/images',
  requirePermission('property:image:create'),
  upload.array('images', 10),
  async function (req, res) {
    try {
      const propertyId =
        parseInt(req.params.id, 10);

      if (Number.isNaN(propertyId)) {
        return res.status(400).json({
          error: 'Invalid property id'
        });
      }

      const properties = await query(
        `
        SELECT *
        FROM properties
        WHERE id = $1
        `,
        [propertyId]
      );

      if (properties.length === 0) {
        return res.status(404).json({
          error: 'Property not found'
        });
      }

      if (
        req.user.role !== 'admin' &&
        properties[0].user_id !== req.user.id
      ) {
        return res.status(403).json({
          error:
            'You can only upload images to your own properties'
        });
      }

      const insertedImages = [];

      // Multipart files
      if (
        req.files &&
        req.files.length > 0
      ) {
        const existingImages =
          await query(
            `
            SELECT COUNT(*)::integer AS count
            FROM property_images
            WHERE property_id = $1
            `,
            [propertyId]
          );

        let makePrimary =
          existingImages[0].count === 0;

        for (
          const file of req.files
        ) {
          const imageUrl =
            '/uploads/' +
            file.filename;

          const inserted = await query(
            `
            INSERT INTO property_images
              (
                property_id,
                image_url,
                is_primary
              )
            VALUES
              ($1, $2, $3)
            RETURNING *
            `,
            [
              propertyId,
              imageUrl,
              makePrimary
            ]
          );

          insertedImages.push(
            inserted[0]
          );

          makePrimary = false;
        }
      }

      // JSON image URL
      if (
        req.body &&
        req.body.image_url
      ) {
        const existingImages =
          await query(
            `
            SELECT COUNT(*)::integer AS count
            FROM property_images
            WHERE property_id = $1
            `,
            [propertyId]
          );

        const inserted = await query(
          `
          INSERT INTO property_images
            (
              property_id,
              image_url,
              is_primary
            )
          VALUES
            ($1, $2, $3)
          RETURNING *
          `,
          [
            propertyId,
            req.body.image_url,
            existingImages[0].count === 0
          ]
        );

        insertedImages.push(
          inserted[0]
        );
      }

      if (insertedImages.length === 0) {
        return res.status(400).json({
          error:
            'Upload images using multipart field "images" or provide image_url'
        });
      }

      return res.status(201).json({
        message:
          'Property images uploaded successfully',
        images: insertedImages
      });
    } catch (err) {
      return res.status(500).json({
        error: err.message
      });
    }
  }
);

// ======================================================
// PROPERTY IMAGES - DELETE
// ======================================================

app.delete(
  '/api/properties/images/:image_id',
  requirePermission('property:image:delete'),
  async function (req, res) {
    try {
      const imageId =
        parseInt(
          req.params.image_id,
          10
        );

      if (Number.isNaN(imageId)) {
        return res.status(400).json({
          error: 'Invalid image id'
        });
      }

      const images = await query(
        `
        SELECT
          pi.*,
          p.user_id
        FROM property_images pi
        JOIN properties p
          ON p.id = pi.property_id
        WHERE pi.id = $1
        `,
        [imageId]
      );

      if (images.length === 0) {
        return res.status(404).json({
          error: 'Image not found'
        });
      }

      const image = images[0];

      if (
        req.user.role !== 'admin' &&
        image.user_id !== req.user.id
      ) {
        return res.status(403).json({
          error:
            'You can only delete images from your own properties'
        });
      }

      await query(
        `
        DELETE FROM property_images
        WHERE id = $1
        `,
        [imageId]
      );

      // Delete local file if it belongs to uploads
      if (
        image.image_url &&
        image.image_url.startsWith('/uploads/')
      ) {
        const filePath = path.join(
          __dirname,
          image.image_url
            .replace('/uploads/', 'uploads' + path.sep)
        );

        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      }

      return res.json({
        message:
          'Property image deleted successfully',
        image_id: imageId
      });
    } catch (err) {
      return res.status(500).json({
        error: err.message
      });
    }
  }
);

// ======================================================
// FAVORITES - TOGGLE
// ======================================================

app.post(
  '/api/properties/:id/favorite',
  requireAuth,
  async function (req, res) {
    try {
      if (req.user.role !== 'client') {
        return res.status(403).json({
          error:
            'Only clients can manage favorites'
        });
      }

      const propertyId =
        parseInt(req.params.id, 10);

      if (Number.isNaN(propertyId)) {
        return res.status(400).json({
          error: 'Invalid property id'
        });
      }

      const properties = await query(
        'SELECT id FROM properties WHERE id = $1',
        [propertyId]
      );

      if (properties.length === 0) {
        return res.status(404).json({
          error: 'Property not found'
        });
      }

      const existing = await query(
        `
        SELECT user_id, property_id
        FROM favorites
        WHERE user_id = $1
          AND property_id = $2
        `,
        [
          req.user.id,
          propertyId
        ]
      );

      if (existing.length > 0) {
        await query(
          `
          DELETE FROM favorites
          WHERE user_id = $1
            AND property_id = $2
          `,
          [
            req.user.id,
            propertyId
          ]
        );

        return res.json({
          message:
            'Property removed from favorites',
          favorited: false
        });
      }

      await query(
        `
        INSERT INTO favorites
          (
            user_id,
            property_id
          )
        VALUES
          ($1, $2)
        `,
        [
          req.user.id,
          propertyId
        ]
      );

      return res.status(201).json({
        message:
          'Property added to favorites',
        favorited: true
      });
    } catch (err) {
      return res.status(500).json({
        error: err.message
      });
    }
  }
);

// ======================================================
// FAVORITES - GET
// ======================================================

app.get(
  '/api/favorites',
  requireAuth,
  async function (req, res) {
    try {
      if (req.user.role !== 'client') {
        return res.status(403).json({
          error:
            'Only clients can view favorites'
        });
      }

      const favorites = await query(
        `
        SELECT
          f.created_at AS favorited_at,
          p.id,
          p.title,
          p.description,
          p.price,
          p.city,
          p.address,
          p.status,
          c.name AS category,

          (
            SELECT pi.image_url
            FROM property_images pi
            WHERE pi.property_id = p.id
            ORDER BY
              pi.is_primary DESC,
              pi.id ASC
            LIMIT 1
          ) AS primary_image

        FROM favorites f

        JOIN properties p
          ON p.id = f.property_id

        JOIN categories c
          ON c.id = p.category_id

        WHERE f.user_id = $1

        ORDER BY f.created_at DESC
        `,
        [req.user.id]
      );

      return res.json({
        count: favorites.length,
        favorites: favorites
      });
    } catch (err) {
      return res.status(500).json({
        error: err.message
      });
    }
  }
);

// ======================================================
// INQUIRY - CREATE
// ======================================================

app.post(
  '/api/properties/:id/inquire',
  requireAuth,
  async function (req, res) {
    try {
      if (req.user.role !== 'client') {
        return res.status(403).json({
          error:
            'Only clients can send inquiries'
        });
      }

      const propertyId =
        parseInt(req.params.id, 10);

      if (Number.isNaN(propertyId)) {
        return res.status(400).json({
          error: 'Invalid property id'
        });
      }

      const message =
        String(req.body.message || '').trim();

      if (!message) {
        return res.status(400).json({
          error: 'Message is required'
        });
      }

      const properties = await query(
        `
        SELECT id
        FROM properties
        WHERE id = $1
        `,
        [propertyId]
      );

      if (properties.length === 0) {
        return res.status(404).json({
          error: 'Property not found'
        });
      }

      const inserted = await query(
        `
        INSERT INTO inquiries
          (
            property_id,
            client_id,
            message,
            status
          )
        VALUES
          ($1, $2, $3, 'pending')
        RETURNING *
        `,
        [
          propertyId,
          req.user.id,
          message
        ]
      );

      return res.status(201).json({
        message:
          'Inquiry sent successfully',
        inquiry: inserted[0]
      });
    } catch (err) {
      return res.status(500).json({
        error: err.message
      });
    }
  }
);

// ======================================================
// AGENT - INQUIRIES
// ======================================================

app.get(
  '/api/agent/inquiries',
  requirePermission('inquiry:read'),
  async function (req, res) {
    try {
      let inquiries;

      if (req.user.role === 'admin') {
        inquiries = await query(
          `
          SELECT
            i.id,
            i.property_id,
            p.title AS property_title,
            i.client_id,
            u.full_name AS client_name,
            u.email AS client_email,
            i.message,
            i.status,
            i.created_at
          FROM inquiries i
          JOIN properties p
            ON p.id = i.property_id
          JOIN users u
            ON u.id = i.client_id
          ORDER BY i.created_at DESC
          `
        );
      } else {
        inquiries = await query(
          `
          SELECT
            i.id,
            i.property_id,
            p.title AS property_title,
            i.client_id,
            u.full_name AS client_name,
            u.email AS client_email,
            i.message,
            i.status,
            i.created_at
          FROM inquiries i
          JOIN properties p
            ON p.id = i.property_id
          JOIN users u
            ON u.id = i.client_id
          WHERE p.user_id = $1
          ORDER BY i.created_at DESC
          `,
          [req.user.id]
        );
      }

      return res.json({
        count: inquiries.length,
        inquiries: inquiries
      });
    } catch (err) {
      return res.status(500).json({
        error: err.message
      });
    }
  }
);

// ======================================================
// INQUIRY - UPDATE STATUS
// ======================================================

app.patch(
  '/api/inquiries/:id/status',
  requirePermission('inquiry:update'),
  async function (req, res) {
    try {
      const inquiryId =
        parseInt(req.params.id, 10);

      if (Number.isNaN(inquiryId)) {
        return res.status(400).json({
          error: 'Invalid inquiry id'
        });
      }

      const allowedStatuses = [
        'pending',
        'replied',
        'closed'
      ];

      const status =
        req.body.status;

      if (
        !allowedStatuses.includes(status)
      ) {
        return res.status(400).json({
          error: 'Invalid inquiry status',
          allowed: allowedStatuses
        });
      }

      const inquiries = await query(
        `
        SELECT
          i.*,
          p.user_id AS property_owner
        FROM inquiries i
        JOIN properties p
          ON p.id = i.property_id
        WHERE i.id = $1
        `,
        [inquiryId]
      );

      if (inquiries.length === 0) {
        return res.status(404).json({
          error: 'Inquiry not found'
        });
      }

      const inquiry =
        inquiries[0];

      if (
        req.user.role !== 'admin' &&
        inquiry.property_owner !== req.user.id
      ) {
        return res.status(403).json({
          error:
            'You can only update inquiries for your properties'
        });
      }

      const updated = await query(
        `
        UPDATE inquiries
        SET status = $1
        WHERE id = $2
        RETURNING *
        `,
        [
          status,
          inquiryId
        ]
      );

      return res.json({
        message:
          'Inquiry status updated successfully',
        inquiry: updated[0]
      });
    } catch (err) {
      return res.status(500).json({
        error: err.message
      });
    }
  }
);

// ======================================================
// ======================================================
// ANALYTICS
// ======================================================

app.get(
  '/api/agent/analytics',
  requirePermission('analytics:read'),
  async function (req, res) {
    try {
      let properties;
      let inquiries;
      let favorites;

      if (req.user.role === 'admin') {
        properties = await query(
          `
          SELECT
            COUNT(*)::integer AS total,
            COUNT(*) FILTER (
              WHERE p.status = 'available'
            )::integer AS available,
            COUNT(*) FILTER (
              WHERE p.status = 'sold'
            )::integer AS sold,
            COUNT(*) FILTER (
              WHERE p.status = 'pending'
            )::integer AS pending
          FROM properties p
          `
        );

        inquiries = await query(
          `
          SELECT
            COUNT(*)::integer AS total,
            COUNT(*) FILTER (
              WHERE i.status = 'pending'
            )::integer AS pending,
            COUNT(*) FILTER (
              WHERE i.status = 'replied'
            )::integer AS replied,
            COUNT(*) FILTER (
              WHERE i.status = 'closed'
            )::integer AS closed
          FROM inquiries i
          `
        );

        favorites = await query(
          `
          SELECT COUNT(*)::integer AS total
          FROM favorites f
          `
        );
      } else {
        properties = await query(
          `
          SELECT
            COUNT(*)::integer AS total,
            COUNT(*) FILTER (
              WHERE p.status = 'available'
            )::integer AS available,
            COUNT(*) FILTER (
              WHERE p.status = 'sold'
            )::integer AS sold,
            COUNT(*) FILTER (
              WHERE p.status = 'pending'
            )::integer AS pending
          FROM properties p
          WHERE p.user_id = $1
          `,
          [req.user.id]
        );

        inquiries = await query(
          `
          SELECT
            COUNT(*)::integer AS total,
            COUNT(*) FILTER (
              WHERE i.status = 'pending'
            )::integer AS pending,
            COUNT(*) FILTER (
              WHERE i.status = 'replied'
            )::integer AS replied,
            COUNT(*) FILTER (
              WHERE i.status = 'closed'
            )::integer AS closed
          FROM inquiries i
          JOIN properties p
            ON p.id = i.property_id
          WHERE p.user_id = $1
          `,
          [req.user.id]
        );

        favorites = await query(
          `
          SELECT
            COUNT(*)::integer AS total
          FROM favorites f
          JOIN properties p
            ON p.id = f.property_id
          WHERE p.user_id = $1
          `,
          [req.user.id]
        );
      }

      return res.json({
        analytics: {
          properties: properties[0],
          inquiries: inquiries[0],
          favorites: favorites[0]
        }
      });
    } catch (err) {
      return res.status(500).json({
        error: err.message
      });
    }
  }
);
// MULTER ERROR HANDLER
// ======================================================

app.use(
  function (err, req, res, next) {
    if (err instanceof multer.MulterError) {
      return res.status(400).json({
        error: err.message
      });
    }

    if (err) {
      return res.status(400).json({
        error: err.message
      });
    }

    next();
  }
);

// ======================================================
// 404
// ======================================================

app.use(
  function (req, res) {
    res.status(404).json({
      error: 'Route not found',
      path: req.path,
      method: req.method
    });
  }
);

// ======================================================
// START SERVER
// ======================================================

async function bootstrap() {
  try {
    await pool.query('SELECT 1');

    await seedAdminIfMissing();

    app.listen(
      CONFIG.PORT,
      '0.0.0.0',
      function () {
        console.log(
          'Real Estate Backend API running on port ' +
          CONFIG.PORT
        );

        console.log(
          'Connected to PostgreSQL database'
        );

        console.log(
          'Default admin: admin@test.com / admin123'
        );
      }
    );
  } catch (err) {
    console.error(
      'Server startup failed:',
      err.message
    );

    process.exit(1);
  }
}

bootstrap();





}
