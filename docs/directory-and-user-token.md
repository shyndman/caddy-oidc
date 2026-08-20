# Directory and User Token

## Purpose

This fork adds authorization roles from a PostgreSQL database to caddy-oidc. It also mints a signed user token for application servers.

Each configuration initializes one directory snapshot. The proxy loads the users, the roles, and the links between them into memory when the configuration starts. An early request can force the same one-time load and waits for it. A Caddy reload builds a new configuration. The proxy loads a new snapshot at each reload.

## Configuration

The global `oidc` directive gains two options.

```caddyfile
{
    oidc {
        issuer https://accounts.google.com
        client_id "{env.OAUTH_CLIENT_ID}"

        postgres "postgresql://caddy_ro:...@db:5432/homelab?sslmode=require"

        authenticate cookie {
            name caddy
            secret "{env.COOKIE_SECRET}"
            claim email
        }

        user_token {
            private_key "{env.SIGNING_PRIVATE_KEY}"
        }
    }
}
```

`postgres` sets the connection string for the database. The PostgreSQL role that the connection uses holds SELECT grants only.

`user_token` enables the minted user token. `private_key` supplies the ES256 private key in PEM form. The proxy resolves placeholder values at one-time initialization.

### Handler

The handler directive accepts role clauses as shorthand.

```caddyfile
friends.example.com {
    oidc allow residents, media_consumers
    reverse_proxy localhost:8080
}
```

`allow` and `deny` take a comma-separated list of role names. Each clause is optional. The configuration must contain at least one `allow` clause. The role shorthand coexists with the existing matcher rules.

For example, `allow residents, media_consumers` becomes one allow rule. The rule matches a request when the session user holds any of those roles.

## Data Model

The repository holds the schema SQL. The proxy never runs the schema. A separate writable role applies the schema during setup.

```sql
CREATE TABLE roles (
    name TEXT PRIMARY KEY
);

CREATE TABLE users (
    email TEXT PRIMARY KEY,
    name  TEXT NOT NULL
);

CREATE TABLE user_roles (
    user_email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
    role_name  TEXT NOT NULL REFERENCES roles(name)  ON DELETE CASCADE,
    PRIMARY KEY (user_email, role_name)
);
```

The tables use natural keys. There is no surrogate ID. Email identifies a user. The `name` column stores a display name, such as "Steve".

The load uses one query.

```sql
SELECT u.email, u.name, r.name
FROM users u
JOIN user_roles ur ON ur.user_email = u.email
JOIN roles r ON r.name = ur.role_name;
```

The result builds an in-memory map. The map keys by email. It holds the role set and the display name for each user.

## Authorization

The `role` matcher checks a session against the directory. A session carries the identity as the email claim. The cookie authenticator copies the `email` claim from the OAuth response into the session.

The matcher reads the email claim from the request context. Then it looks the email up in the loaded directory. It matches when the directory holds any of the configured roles.

An anonymous session has no email claim. The matcher never matches an anonymous session.

## User Token

After authorization passes, the proxy mints a user token. It signs the token with the configured private key.

The token carries these claims:

- `sub` holds the user email.
- `roles` holds the role set.
- `name` holds the display name.
- `iss` holds the OIDC issuer. `iat` and `exp` hold the issue and expiry times.

The token carries no audience. Application servers identify the signing key from the JWKS endpoint.

`exp` matches the session expiry. The proxy injects the token into the upstream request as an `Authorization: Bearer` header.

The token replaces the claim headers as the identity mechanism for application servers. The proxy does not forward separate claim headers to the applications.

Application servers verify the token signature and read the identity directly. They need no session store and no database access.

The proxy mints a fresh token for each request. Each token reflects the current directory snapshot. The signing cost is one ES256 operation per request.

The directory is the authorization source. The proxy mints the token after authorization passes. The directory and the token always agree within a request.

## JWKS Endpoint

The proxy exposes the public key for token verification at a standard well-known endpoint.

`/.well-known/jwks.json`

The endpoint requires no authentication. Application servers fetch the public key from this endpoint to verify token signatures. The `user_token` block on the global directive enables the endpoint.

## Reload Behavior

A Caddy reload builds a new configuration. The new configuration loads the directory from PostgreSQL again. An early request can force the same one-time load and waits for it. If the database is unreachable, the reload fails. Caddy keeps serving the old configuration.

The proxy never touches the database at request time. It uses the database only at configuration load. If the database fails mid-flight, the proxy keeps serving with the loaded snapshot.