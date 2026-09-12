-- =========================================
-- REAL ESTATE PLATFORM - DATABASE SCHEMA
-- =========================================

-- =========================
-- AUTH / RBAC
-- =========================

CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    slug VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(150) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    phone VARCHAR(30),
    role_id INTEGER NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

-- =========================
-- ROLES
-- =========================

INSERT INTO roles (name)
VALUES ('admin'), ('agent'), ('client')
ON CONFLICT (name) DO NOTHING;

-- =========================
-- PERMISSIONS
-- =========================

INSERT INTO permissions (slug, description)
VALUES
    ('user:read', 'View users'),
    ('user:update', 'Update user role'),

    ('property:create', 'Create properties'),
    ('property:read', 'View properties'),
    ('property:update', 'Update properties'),
    ('property:delete', 'Delete properties'),

    ('category:read', 'View categories'),
    ('category:create', 'Create categories'),

    ('property:image:create', 'Upload property images'),
    ('property:image:delete', 'Delete property images'),

    ('inquiry:read', 'View inquiries'),
    ('inquiry:update', 'Update inquiry status'),

    ('analytics:read', 'View analytics')
ON CONFLICT (slug) DO NOTHING;

-- =========================
-- ADMIN PERMISSIONS
-- =========================

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;

-- =========================
-- AGENT PERMISSIONS
-- =========================

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.slug IN (
    'property:create',
    'property:read',
    'property:update',
    'property:delete',
    'property:image:create',
    'property:image:delete',
    'category:read',
    'inquiry:read',
    'inquiry:update',
    'analytics:read'
)
WHERE r.name = 'agent'
ON CONFLICT DO NOTHING;

-- =========================
-- CLIENT PERMISSIONS
-- =========================

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.slug IN (
    'property:read',
    'category:read'
)
WHERE r.name = 'client'
ON CONFLICT DO NOTHING;

-- =========================
-- CATEGORIES
-- =========================

CREATE TABLE IF NOT EXISTS categories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    slug VARCHAR(120) UNIQUE NOT NULL
);

INSERT INTO categories (name, slug)
VALUES
    ('House', 'house'),
    ('Apartment', 'apartment'),
    ('Villa', 'villa'),
    ('Land', 'land'),
    ('Commercial', 'commercial')
ON CONFLICT (name) DO NOTHING;

-- =========================
-- PROPERTIES
-- =========================

CREATE TABLE IF NOT EXISTS properties (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,

    category_id INTEGER NOT NULL
        REFERENCES categories(id) ON DELETE RESTRICT,

    title VARCHAR(200) NOT NULL,
    description TEXT,

    price DECIMAL(12,2) NOT NULL,

    city VARCHAR(100) NOT NULL,
    address TEXT,

    status VARCHAR(20) NOT NULL DEFAULT 'available'
        CHECK (status IN ('available', 'sold', 'pending')),

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =========================
-- PROPERTY IMAGES
-- =========================

CREATE TABLE IF NOT EXISTS property_images (
    id SERIAL PRIMARY KEY,

    property_id INTEGER NOT NULL
        REFERENCES properties(id) ON DELETE CASCADE,

    image_url TEXT NOT NULL,

    is_primary BOOLEAN DEFAULT false
);

-- =========================
-- INQUIRIES
-- =========================

CREATE TABLE IF NOT EXISTS inquiries (
    id SERIAL PRIMARY KEY,

    property_id INTEGER NOT NULL
        REFERENCES properties(id) ON DELETE CASCADE,

    client_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,

    message TEXT NOT NULL,

    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'replied', 'closed')),

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =========================
-- FAVORITES
-- =========================

CREATE TABLE IF NOT EXISTS favorites (
    user_id INTEGER NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,

    property_id INTEGER NOT NULL
        REFERENCES properties(id) ON DELETE CASCADE,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (user_id, property_id)
);

-- =========================
-- INDEXES
-- =========================

CREATE INDEX IF NOT EXISTS idx_users_email
ON users(email);

CREATE INDEX IF NOT EXISTS idx_users_role
ON users(role_id);

CREATE INDEX IF NOT EXISTS idx_properties_user
ON properties(user_id);

CREATE INDEX IF NOT EXISTS idx_properties_category
ON properties(category_id);

CREATE INDEX IF NOT EXISTS idx_properties_city
ON properties(city);

CREATE INDEX IF NOT EXISTS idx_properties_status
ON properties(status);

CREATE INDEX IF NOT EXISTS idx_property_images_property
ON property_images(property_id);

CREATE INDEX IF NOT EXISTS idx_inquiries_property
ON inquiries(property_id);

CREATE INDEX IF NOT EXISTS idx_inquiries_client
ON inquiries(client_id);

CREATE INDEX IF NOT EXISTS idx_inquiries_status
ON inquiries(status);

CREATE INDEX IF NOT EXISTS idx_favorites_property
ON favorites(property_id);