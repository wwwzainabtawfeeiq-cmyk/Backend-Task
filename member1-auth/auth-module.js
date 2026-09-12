"use strict";

const express = require("express");
const crypto = require("crypto");
const { neon } = require("@neondatabase/serverless");

const app = express();
app.use(express.json());

const CONFIG = {
  PORT: process.env.PORT || 3000,
  JWT_SECRET: process.env.JWT_SECRET || "auth-module-secret-2025",
  JWT_EXPIRY_SECONDS: 7 * 24 * 60 * 60,
  SALT_BYTES: 16,
  SCRYPT_KEY_LENGTH: 64,
  MIN_PASSWORD_LENGTH: 6,
};

const sql = neon(process.env.DATABASE_URL);

function hashPassword(password) {
  const salt = crypto.randomBytes(CONFIG.SALT_BYTES).toString("hex");
  const derivedKey = crypto.scryptSync(
    password,
    salt,
    CONFIG.SCRYPT_KEY_LENGTH,
  );
  return salt + ":" + derivedKey.toString("hex");
}

function verifyPassword(password, stored) {
  const segments = stored.split(":");
  const salt = segments[0];
  const expectedHash = segments[1];
  const computedHash = crypto
    .scryptSync(password, salt, CONFIG.SCRYPT_KEY_LENGTH)
    .toString("hex");

  const expectedBuffer = Buffer.from(expectedHash, "hex");
  const computedBuffer = Buffer.from(computedHash, "hex");

  if (expectedBuffer.length !== computedBuffer.length) {
    return false;
  }
  return crypto.timingSafeEqual(expectedBuffer, computedBuffer);
}

function base64UrlEncode(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function signToken(payload) {
  const header = base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const claims = Object.assign({}, payload, {
    exp: Math.floor(Date.now() / 1000) + CONFIG.JWT_EXPIRY_SECONDS,
    iat: Math.floor(Date.now() / 1000),
  });
  const body = base64UrlEncode(JSON.stringify(claims));
  const signature = crypto
    .createHmac("sha256", CONFIG.JWT_SECRET)
    .update(header + "." + body)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  return header + "." + body + "." + signature;
}

function verifyToken(token) {
  const segments = token.split(".");
  if (segments.length !== 3) {
    throw new Error("Malformed token");
  }

  const header = segments[0];
  const body = segments[1];
  const signature = segments[2];

  const expectedSignature = crypto
    .createHmac("sha256", CONFIG.JWT_SECRET)
    .update(header + "." + body)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  if (signature !== expectedSignature) {
    throw new Error("Invalid token signature");
  }

  const payload = JSON.parse(Buffer.from(body, "base64").toString("utf8"));

  if (payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error("Token expired");
  }

  return payload;
}

async function seedAdminIfMissing() {
  try {
    const existing =
      await sql`SELECT id FROM users WHERE email = 'admin@test.com'`;
    if (existing.length > 0) {
      console.log("Admin user already exists");
      return;
    }

    const adminRole = await sql`SELECT id FROM roles WHERE name = 'admin'`;
    if (adminRole.length === 0) {
      console.log("Admin role not found, skipping admin seed");
      return;
    }

    const passwordHash = hashPassword("admin123");
    await sql`
      INSERT INTO users (role_id, full_name, email, password_hash, is_active)
      VALUES (${adminRole[0].id}, 'System Administrator', 'admin@test.com', ${passwordHash}, true)
    `;
    console.log("Default admin user created");
  } catch (err) {
    console.error("Seed error:", err.message);
  }
}

async function getAuthenticatedUser(req) {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return null;
  }

  try {
    const decoded = verifyToken(authHeader.slice(7));
    const users = await sql`
      SELECT u.id, u.full_name, u.email, u.phone, u.is_active,
             r.name AS role
      FROM users u
      JOIN roles r ON r.id = u.role_id
      WHERE u.id = ${decoded.userId} AND u.is_active = true
    `;

    if (users.length === 0) return null;

    const user = users[0];
    const permissions = await sql`
      SELECT p.slug
      FROM permissions p
      JOIN role_permissions rp ON rp.permission_id = p.id
      JOIN roles r ON r.id = rp.role_id
      WHERE r.name = ${user.role}
    `;

    return {
      id: user.id,
      fullName: user.full_name,
      email: user.email,
      phone: user.phone,
      role: user.role,
      permissions: permissions.map(function (p) {
        return p.slug;
      }),
    };
  } catch (err) {
    return null;
  }
}

function hasPermission(user, slug) {
  return user && user.permissions && user.permissions.indexOf(slug) !== -1;
}

app.get("/", function (req, res) {
  res.json({
    status: "ok",
    service: "auth-module",
    database: "neon-postgresql",
    timestamp: new Date().toISOString(),
  });
});

app.post("/api/auth/register", async function (req, res) {
  try {
    const body = req.body;

    if (!body.full_name || !body.email || !body.password) {
      return res.status(400).json({
        error: "Missing required fields",
        required: ["full_name", "email", "password"],
      });
    }

    if (body.password.length < CONFIG.MIN_PASSWORD_LENGTH) {
      return res.status(400).json({
        error:
          "Password must be at least " +
          CONFIG.MIN_PASSWORD_LENGTH +
          " characters",
      });
    }

    const existing =
      await sql`SELECT id FROM users WHERE email = ${body.email}`;
    if (existing.length > 0) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const clientRole = await sql`SELECT id FROM roles WHERE name = 'client'`;
    if (clientRole.length === 0) {
      return res.status(500).json({ error: "Client role not configured" });
    }

    const passwordHash = hashPassword(body.password);
    const inserted = await sql`
      INSERT INTO users (role_id, full_name, email, phone, password_hash, is_active)
      VALUES (${clientRole[0].id}, ${body.full_name}, ${body.email},
              ${body.phone || null}, ${passwordHash}, true)
      RETURNING id, full_name, email
    `;

    return res.status(201).json({
      message: "User registered successfully",
      user: {
        id: inserted[0].id,
        full_name: inserted[0].full_name,
        email: inserted[0].email,
        role: "client",
      },
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post("/api/auth/login", async function (req, res) {
  try {
    const body = req.body;

    if (!body.email || !body.password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const users = await sql`
      SELECT u.id, u.full_name, u.email, u.password_hash, u.is_active,
             r.name AS role
      FROM users u
      JOIN roles r ON r.id = u.role_id
      WHERE u.email = ${body.email}
    `;

    if (users.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = users[0];

    if (!user.is_active) {
      return res.status(403).json({ error: "Account is disabled" });
    }

    if (!verifyPassword(body.password, user.password_hash)) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = signToken({ userId: user.id, role: user.role });

    return res.json({
      message: "Login successful",
      token: token,
      user: {
        id: user.id,
        full_name: user.full_name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.get("/api/auth/me", async function (req, res) {
  const user = await getAuthenticatedUser(req);
  if (!user) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  return res.json({ user: user });
});

app.get("/api/admin/users", async function (req, res) {
  try {
    const user = await getAuthenticatedUser(req);
    if (!user) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    if (!hasPermission(user, "user:read")) {
      return res.status(403).json({
        error: "Forbidden",
        requiredPermission: "user:read",
      });
    }

    const users = await sql`
      SELECT u.id, u.full_name, u.email, u.phone, u.is_active, u.created_at,
             r.name AS role
      FROM users u
      JOIN roles r ON r.id = u.role_id
      ORDER BY u.created_at DESC
    `;

    return res.json({
      count: users.length,
      users: users,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.patch("/api/admin/users/:id/role", async function (req, res) {
  try {
    const user = await getAuthenticatedUser(req);
    if (!user) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    if (!hasPermission(user, "user:update")) {
      return res.status(403).json({
        error: "Forbidden",
        requiredPermission: "user:update",
      });
    }

    const body = req.body;
    const allowedRoles = ["admin", "agent", "client"];

    if (!body.role || allowedRoles.indexOf(body.role) === -1) {
      return res.status(400).json({
        error: "Invalid role",
        allowed: allowedRoles,
      });
    }

    const userId = parseInt(req.params.id, 10);
    const targetUsers = await sql`SELECT id FROM users WHERE id = ${userId}`;
    if (targetUsers.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const newRoles = await sql`SELECT id FROM roles WHERE name = ${body.role}`;
    if (newRoles.length === 0) {
      return res.status(400).json({ error: "Role not configured" });
    }

    await sql`
      UPDATE users
      SET role_id = ${newRoles[0].id}, updated_at = CURRENT_TIMESTAMP
      WHERE id = ${userId}
    `;

    return res.json({
      message: "User role updated successfully",
      user_id: userId,
      new_role: body.role,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.use(function (req, res) {
  res.status(404).json({
    error: "Route not found",
    path: req.path,
    method: req.method,
  });
});

async function bootstrap() {
  await seedAdminIfMissing();

  app.listen(CONFIG.PORT, "0.0.0.0", function () {
    console.log("Authentication module running on port " + CONFIG.PORT);
    console.log("Connected to Neon PostgreSQL database");
    console.log("Default admin: admin@test.com / admin123");
  });
}

bootstrap();
