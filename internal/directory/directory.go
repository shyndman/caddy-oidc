// Package directory loads the users, roles, and user-role associations from a
// PostgreSQL database into an immutable in-memory index.
package directory

import (
	"context"
	"slices"
	"sort"

	"github.com/jackc/pgx/v5"
)

// usersQuery loads every user together with their roles in one pass.
//
// Users with no rows do not appear in the directory.
const usersQuery = `
SELECT u.email, u.name, r.name
FROM users u
JOIN user_roles ur ON ur.user_email = u.email
JOIN roles r ON r.name = ur.role_name
`

// Queryer executes the directory query. A *pgx.Conn satisfies this interface.
type Queryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// User is a person that the directory knows about.
type User struct {
	// Name is the display name of the user.
	Name string
	// Roles contains the role names for the user, sorted.
	Roles []string
}

// Directory is an immutable in-memory index of users and their roles.
type Directory struct {
	byEmail map[string]*User
}

// Load reads all users and roles from the database through conn and builds an
// in-memory index. The returned Directory is immutable.
func Load(ctx context.Context, conn Queryer) (*Directory, error) {
	rows, err := conn.Query(ctx, usersQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	dir := &Directory{
		byEmail: make(map[string]*User),
	}

	for rows.Next() {
		var email, name, role string

		if err := rows.Scan(&email, &name, &role); err != nil {
			return nil, err
		}

		user := dir.byEmail[email]
		if user == nil {
			user = &User{Name: name}
			dir.byEmail[email] = user
		}

		user.Roles = append(user.Roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, user := range dir.byEmail {
		sort.Strings(user.Roles)
	}

	return dir, nil
}

// User looks up a user by email. It reports false when the directory does not
// know the email or the Directory is nil.
func (d *Directory) User(email string) (*User, bool) {
	if d == nil {
		return nil, false
	}

	u, ok := d.byEmail[email]

	return u, ok
}

// HasRole reports whether the user identified by email holds role.
func (d *Directory) HasRole(email string, role string) bool {
	u, ok := d.User(email)
	if !ok {
		return false
	}

	return slices.Contains(u.Roles, role)
}
