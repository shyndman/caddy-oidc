-- Schema for the caddy-oidc authorization directory.
-- The reverse proxy holds a read-only connection and never writes to this
-- schema. Apply it with a separate writable role during setup.

CREATE TABLE roles (
    name TEXT PRIMARY KEY
);

CREATE TABLE users (
    email TEXT PRIMARY KEY,
    name TEXT NOT NULL
);

CREATE TABLE user_roles (
    user_email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
    role_name  TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE,
    PRIMARY KEY (user_email, role_name)
);