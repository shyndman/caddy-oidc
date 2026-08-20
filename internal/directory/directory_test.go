package directory

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeRows struct {
	rows [][]string
	pos  int
	err  error
}

func (f *fakeRows) Next() bool {
	if f.pos >= len(f.rows) {
		return false
	}

	f.pos++

	return true
}

func (f *fakeRows) Scan(dest ...any) error {
	row := f.rows[f.pos-1]

	for i, d := range dest {
		*(d.(*string)) = row[i] //nolint:forcetypeassert
	}

	return nil
}

func (f *fakeRows) Err() error { return f.err }

func (*fakeRows) Close() {}

func (*fakeRows) Conn() *pgx.Conn { return nil }

func (f *fakeRows) Values() ([]any, error) {
	row := f.rows[f.pos-1]

	values := make([]any, len(row))
	for i, v := range row {
		values[i] = v
	}

	return values, nil
}

func (*fakeRows) RawValues() [][]byte { return nil }

func (*fakeRows) CommandTag() pgconn.CommandTag { return pgconn.CommandTag{} }

func (*fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }

type fakeQueryer struct{ rows *fakeRows }

func (q *fakeQueryer) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	return q.rows, nil
}

func TestLoad(t *testing.T) {
	t.Parallel()

	q := &fakeQueryer{
		rows: &fakeRows{
			rows: [][]string{
				{"a@example.com", "Alice", "admin"},
				{"a@example.com", "Alice", "reader"},
				{"b@example.com", "Bob", "reader"},
			},
		},
	}

	dir, err := Load(context.Background(), q)
	require.NoError(t, err)

	alice, ok := dir.User("a@example.com")
	require.True(t, ok)
	assert.Equal(t, "Alice", alice.Name)
	assert.Equal(t, []string{"admin", "reader"}, alice.Roles)

	bob, ok := dir.User("b@example.com")
	require.True(t, ok)
	assert.Equal(t, "Bob", bob.Name)
	assert.Equal(t, []string{"reader"}, bob.Roles)

	_, ok = dir.User("nobody@example.com")
	assert.False(t, ok)

	assert.True(t, dir.HasRole("a@example.com", "admin"))
	assert.True(t, dir.HasRole("b@example.com", "reader"))
	assert.False(t, dir.HasRole("a@example.com", "owner"))
	assert.False(t, dir.HasRole("nobody@example.com", "reader"))
}

func TestLoad_Empty(t *testing.T) {
	t.Parallel()

	q := &fakeQueryer{rows: &fakeRows{}}

	dir, err := Load(context.Background(), q)
	require.NoError(t, err)

	_, ok := dir.User("a@example.com")
	assert.False(t, ok)
}

func TestLoad_QueryError(t *testing.T) {
	t.Parallel()

	q := &fakeQueryer{rows: &fakeRows{err: errors.New("boom")}}

	_, err := Load(context.Background(), q)
	require.Error(t, err)
}

func TestLoad_CaseInsensitive(t *testing.T) {
	t.Parallel()

	q := &fakeQueryer{
		rows: &fakeRows{
			rows: [][]string{
				{"Steve.Flex@Example.com", "Steve", "admin"},
			},
		},
	}

	dir, err := Load(context.Background(), q)
	require.NoError(t, err)

	u, ok := dir.User("steve.flex@example.com")
	require.True(t, ok)
	assert.Equal(t, "Steve", u.Name)
	assert.True(t, dir.HasRole("STEVE.FLEX@EXAMPLE.COM", "admin"))
	assert.False(t, dir.HasRole("someone-else@example.com", "admin"))
}

func TestNormalizeEmail(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "a@example.com", NormalizeEmail("A@Example.COM"))
	assert.Equal(t, "a@example.com", NormalizeEmail("  a@example.com  "))
	assert.Equal(t, "a@example.com", NormalizeEmail("a@example.com"))
}
