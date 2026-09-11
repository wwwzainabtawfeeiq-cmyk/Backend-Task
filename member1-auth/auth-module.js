'use strict';

const http = require('http');
const crypto = require('crypto');

const CONFIG = {
  PORT: 3000,
  JWT_SECRET: 'auth-module-secret-2025',
  JWT_EXPIRY_SECONDS: 7 * 24 * 60 * 60,
  SALT_BYTES: 16,
  SCRYPT_KEY_LENGTH: 64,
  MIN_PASSWORD_LENGTH: 6
};

const store = {
  roles: [],
  permissions: [],
  rolePermissions: [],
  users: [],
  sequences: {
    roles: 1,
    permissions: 1,
    users: 1
  }
};

function hashPassword(password) {
  const salt = crypto.randomBytes(CONFIG.SALT_BYTES).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, CONFIG.SCRYPT_KEY_LENGTH);
  return salt + ':' + derivedKey.toString('hex');
}

function verifyPassword(password, stored) {
  const segments = stored.split(':');
  const salt = segments[0];
  const expectedHash = segments[1];
  const computedHash = crypto
    .scryptSync(password, salt, CONFIG.SCRYPT_KEY_LENGTH)
    .toString('hex');

  const expectedBuffer = Buffer.from(expectedHash, 'hex');
  const computedBuffer = Buffer.from(computedHash, 'hex');

  if (expectedBuffer.length !== computedBuffer.length) {
    return false;
  }
  return crypto.timingSafeEqual(expectedBuffer, computedBuffer);
}

function base64UrlEncode(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function signToken(payload) {
  const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const claims = Object.assign({}, payload, {
    exp: Math.floor(Date.now() / 1000) + CONFIG.JWT_EXPIRY_SECONDS,
    iat: Math.floor(Date.now() / 1000)
  });
  const body = base64UrlEncode(JSON.stringify(claims));
  const signature = crypto
    .createHmac('sha256', CONFIG.JWT_SECRET)
    .update(header + '.' + body)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  return header + '.' + body + '.' + signature;
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

  const payload = JSON.parse(Buffer.from(body, 'base64').toString('utf8'));

  if (payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('Token expired');
  }

  return payload;
}

function seedDatabase() {
  const roleNames = ['admin', 'agent', 'client'];
  roleNames.forEach(function (name) {
    store.roles.push({ id: store.sequences.roles++, name: name });
  });

  const permissionSlugs = [
    'user:read',
    'user:update',
    'property:create',
    'property:read',
    'property:update',
    'property:delete',
    'category:read',
    'category:create',
    'inquiry:read',
    'inquiry:update'
  ];
  permissionSlugs.forEach(function (slug) {
    store.permissions.push({ id: store.sequences.permissions++, slug: slug });
  });

  function assignPermissions(roleName, slugs) {
    const role = store.roles.find(function (r) { return r.name === roleName; });
    slugs.forEach(function (slug) {
      const permission = store.permissions.find(function (p) { return p.slug === slug; });
      if (permission) {
        store.rolePermissions.push({
          roleId: role.id,
          permissionId: permission.id
        });
      }
    });
  }

  assignPermissions('admin', permissionSlugs);
  assignPermissions('agent', [
    'property:create',
    'property:read',
    'property:update',
    'property:delete',
    'category:read',
    'inquiry:read',
    'inquiry:update'
  ]);
  assignPermissions('client', ['property:read', 'category:read']);

  const adminRole = store.roles.find(function (r) { return r.name === 'admin'; });
  store.users.push({
    id: store.sequences.users++,
    roleId: adminRole.id,
    fullName: 'System Administrator',
    email: 'admin@test.com',
    phone: null,
    passwordHash: hashPassword('admin123'),
    isActive: true,
    createdAt: new Date().toISOString()
  });
}

function readJsonBody(req) {
  return new Promise(function (resolve) {
    let raw = '';
    req.on('data', function (chunk) { raw += chunk; });
    req.on('end', function () {
      try {
        resolve(JSON.parse(raw || '{}'));
      } catch (err) {
        resolve({});
      }
    });
  });
}

function sendJson(res, status, payload) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS'
  });
  res.end(JSON.stringify(payload, null, 2));
}

function getAuthenticatedUser(req) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }

  try {
    const decoded = verifyToken(authHeader.slice(7));
    const user = store.users.find(function (u) { return u.id === decoded.userId; });

    if (!user || !user.isActive) {
      return null;
    }

    const role = store.roles.find(function (r) { return r.id === user.roleId; });
    const permissionIds = store.rolePermissions
      .filter(function (rp) { return rp.roleId === role.id; })
      .map(function (rp) { return rp.permissionId; });

    const permissions = store.permissions
      .filter(function (p) { return permissionIds.indexOf(p.id) !== -1; })
      .map(function (p) { return p.slug; });

    return {
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      phone: user.phone,
      role: role.name,
      permissions: permissions
    };
  } catch (err) {
    return null;
  }
}

function hasPermission(user, permissionSlug) {
  return user && user.permissions && user.permissions.indexOf(permissionSlug) !== -1;
}

function handleHealthCheck(req, res) {
  return sendJson(res, 200, {
    status: 'ok',
    service: 'auth-module',
    timestamp: new Date().toISOString()
  });
}

async function handleRegister(req, res) {
  const body = await readJsonBody(req);

  if (!body.full_name || !body.email || !body.password) {
    return sendJson(res, 400, {
      error: 'Missing required fields',
      required: ['full_name', 'email', 'password']
    });
  }

  if (body.password.length < CONFIG.MIN_PASSWORD_LENGTH) {
    return sendJson(res, 400, {
      error: 'Password must be at least ' + CONFIG.MIN_PASSWORD_LENGTH + ' characters'
    });
  }

  const existing = store.users.find(function (u) { return u.email === body.email; });
  if (existing) {
    return sendJson(res, 409, { error: 'Email already registered' });
  }

  const clientRole = store.roles.find(function (r) { return r.name === 'client'; });

  const newUser = {
    id: store.sequences.users++,
    roleId: clientRole.id,
    fullName: body.full_name,
    email: body.email,
    phone: body.phone || null,
    passwordHash: hashPassword(body.password),
    isActive: true,
    createdAt: new Date().toISOString()
  };

  store.users.push(newUser);

  return sendJson(res, 201, {
    message: 'User registered successfully',
    user: {
      id: newUser.id,
      full_name: newUser.fullName,
      email: newUser.email,
      role: 'client'
    }
  });
}

async function handleLogin(req, res) {
  const body = await readJsonBody(req);

  if (!body.email || !body.password) {
    return sendJson(res, 400, {
      error: 'Email and password are required'
    });
  }

  const user = store.users.find(function (u) { return u.email === body.email; });

  if (!user) {
    return sendJson(res, 401, { error: 'Invalid credentials' });
  }

  if (!user.isActive) {
    return sendJson(res, 403, { error: 'Account is disabled' });
  }

  if (!verifyPassword(body.password, user.passwordHash)) {
    return sendJson(res, 401, { error: 'Invalid credentials' });
  }

  const role = store.roles.find(function (r) { return r.id === user.roleId; });
  const token = signToken({ userId: user.id, role: role.name });

  return sendJson(res, 200, {
    message: 'Login successful',
    token: token,
    user: {
      id: user.id,
      full_name: user.fullName,
      email: user.email,
      role: role.name
    }
  });
}

function handleGetProfile(req, res) {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return sendJson(res, 401, { error: 'Unauthorized' });
  }
  return sendJson(res, 200, { user: user });
}

function handleListUsers(req, res) {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return sendJson(res, 401, { error: 'Unauthorized' });
  }
  if (!hasPermission(user, 'user:read')) {
    return sendJson(res, 403, {
      error: 'Forbidden',
      requiredPermission: 'user:read'
    });
  }

  const users = store.users.map(function (u) {
    const role = store.roles.find(function (r) { return r.id === u.roleId; });
    return {
      id: u.id,
      full_name: u.fullName,
      email: u.email,
      phone: u.phone,
      is_active: u.isActive,
      created_at: u.createdAt,
      role: role.name
    };
  });

  return sendJson(res, 200, {
    count: users.length,
    users: users
  });
}

async function handleUpdateUserRole(req, res, userId) {
  const user = getAuthenticatedUser(req);
  if (!user) {
    return sendJson(res, 401, { error: 'Unauthorized' });
  }
  if (!hasPermission(user, 'user:update')) {
    return sendJson(res, 403, {
      error: 'Forbidden',
      requiredPermission: 'user:update'
    });
  }

  const body = await readJsonBody(req);
  const allowedRoles = ['admin', 'agent', 'client'];

  if (!body.role || allowedRoles.indexOf(body.role) === -1) {
    return sendJson(res, 400, {
      error: 'Invalid role',
      allowed: allowedRoles
    });
  }

  const targetUser = store.users.find(function (u) { return u.id === userId; });
  if (!targetUser) {
    return sendJson(res, 404, { error: 'User not found' });
  }

  const newRole = store.roles.find(function (r) { return r.name === body.role; });
  targetUser.roleId = newRole.id;

  return sendJson(res, 200, {
    message: 'User role updated successfully',
    user_id: targetUser.id,
    new_role: body.role
  });
}

const server = http.createServer(async function (req, res) {
  const path = req.url.split('?')[0];
  const method = req.method;

  if (method === 'OPTIONS') {
    return sendJson(res, 200, {});
  }

  try {
    if (path === '/' && method === 'GET') {
      return handleHealthCheck(req, res);
    }

    if (path === '/api/auth/register' && method === 'POST') {
      return await handleRegister(req, res);
    }

    if (path === '/api/auth/login' && method === 'POST') {
      return await handleLogin(req, res);
    }

    if (path === '/api/auth/me' && method === 'GET') {
      return handleGetProfile(req, res);
    }

    if (path === '/api/admin/users' && method === 'GET') {
      return handleListUsers(req, res);
    }

    const roleRouteMatch = path.match(/^\/api\/admin\/users\/(\d+)\/role$/);
    if (roleRouteMatch && method === 'PATCH') {
      return await handleUpdateUserRole(req, res, parseInt(roleRouteMatch[1], 10));
    }

    return sendJson(res, 404, {
      error: 'Route not found',
      path: path,
      method: method
    });

  } catch (err) {
    return sendJson(res, 500, {
      error: 'Internal server error',
      message: err.message
    });
  }
});

seedDatabase();

server.listen(CONFIG.PORT, function () {
  console.log('Authentication module running on port ' + CONFIG.PORT);
  console.log('Default admin credentials: admin@test.com / admin123');
  setTimeout(runSmokeTests, 1000);
});

async function runSmokeTests() {
  const baseUrl = 'http://localhost:' + CONFIG.PORT;

  function report(label, payload) {
    console.log('\n--- ' + label + ' ---');
    console.log(JSON.stringify(payload, null, 2));
  }

  try {
    let response = await fetch(baseUrl + '/');
    report('Health Check', await response.json());

    response = await fetch(baseUrl + '/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        full_name: 'Ahmed Client',
        email: 'ahmed@test.com',
        password: 'ahmed123'
      })
    });
    report('User Registration', await response.json());

    response = await fetch(baseUrl + '/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@test.com', password: 'admin123' })
    });
    const adminLogin = await response.json();
    report('Admin Login', {
      message: adminLogin.message,
      token_preview: adminLogin.token ? adminLogin.token.slice(0, 60) + '...' : null,
      user: adminLogin.user
    });
    const adminToken = adminLogin.token;

    response = await fetch(baseUrl + '/api/auth/me', {
      headers: { 'Authorization': 'Bearer ' + adminToken }
    });
    const profile = await response.json();
    report('Authenticated Profile', {
      user: profile.user,
      permission_count: profile.user.permissions.length
    });

    response = await fetch(baseUrl + '/api/admin/users', {
      headers: { 'Authorization': 'Bearer ' + adminToken }
    });
    const userList = await response.json();
    report('Admin User List', {
      count: userList.count,
      users: userList.users.map(function (u) {
        return { id: u.id, email: u.email, role: u.role };
      })
    });

    response = await fetch(baseUrl + '/api/admin/users/2/role', {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + adminToken
      },
      body: JSON.stringify({ role: 'agent' })
    });
    report('Role Update', await response.json());

    response = await fetch(baseUrl + '/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'ahmed@test.com', password: 'ahmed123' })
    });
    const clientLogin = await response.json();
    const clientToken = clientLogin.token;

    response = await fetch(baseUrl + '/api/admin/users', {
      headers: { 'Authorization': 'Bearer ' + clientToken }
    });
    report('RBAC Enforcement', await response.json());

    console.log('\nAll smoke tests completed successfully.\n');
  } catch (err) {
    console.error('Smoke test failure:', err.message);
  }
}
