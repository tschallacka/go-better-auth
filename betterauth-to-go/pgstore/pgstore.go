// Package pgstore implements betterauth.Store on PostgreSQL with pgx. It is
// the only package that imports pgx. Queries follow the library's Kysely
// adapter, except that LIKE wildcards in a value are escaped (D13) and an
// empty In/NotIn list is an error before it reaches the database (the
// library's query fails on it in PostgreSQL instead).
package pgstore

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	betterauth "github.com/tschallacka/go-better-auth/betterauth-to-go"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/jsuri"
)

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Store is a betterauth.Store over a pgx pool, or over one transaction inside
// Transaction.
type Store struct {
	q querier
}

var _ betterauth.Store = (*Store)(nil)

// New returns a Store using pool. The pool is the project's own; Store never
// closes it.
func New(pool *pgxpool.Pool) *Store {
	return &Store{q: pool}
}

func ident(name string) string {
	return pgx.Identifier{name}.Sanitize()
}

// query accumulates SQL text and its arguments.
type query struct {
	b    strings.Builder
	args []any
}

func (q *query) arg(v any) string {
	q.args = append(q.args, v)
	return "$" + strconv.Itoa(len(q.args))
}

func (q *query) WriteString(s string) { q.b.WriteString(s) }

// likeEscape escapes LIKE wildcards so a value matches itself only. The
// library puts the value into the pattern as written (D13).
func likeEscape(v any) string {
	s := fmt.Sprint(v)
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

func asSlice(v any) ([]any, bool) {
	switch s := v.(type) {
	case []any:
		return s, true
	case []string:
		out := make([]any, len(s))
		for i, x := range s {
			out[i] = x
		}
		return out, true
	case []int:
		out := make([]any, len(s))
		for i, x := range s {
			out[i] = x
		}
		return out, true
	case []int64:
		out := make([]any, len(s))
		for i, x := range s {
			out[i] = x
		}
		return out, true
	}
	return nil, false
}

func allStrings(vs []any) bool {
	for _, v := range vs {
		if _, ok := v.(string); !ok {
			return false
		}
	}
	return true
}

func (q *query) condition(w betterauth.Where) (string, error) {
	col := ident(w.Column)
	op := w.Operator
	if op == "" {
		op = betterauth.Eq
	}
	_, isString := w.Value.(string)
	switch op {
	case betterauth.In, betterauth.NotIn:
		vals, ok := asSlice(w.Value)
		if !ok {
			vals = []any{w.Value}
		}
		if len(vals) == 0 {
			return "", betterauth.ErrEmptyList
		}
		insensitive := w.Insensitive && allStrings(vals)
		lhs := col
		if insensitive {
			lhs = "lower(" + col + ")"
		}
		parts := make([]string, len(vals))
		for i, v := range vals {
			if insensitive {
				v = jsuri.ToLowerCase(v.(string))
			}
			parts[i] = q.arg(v)
		}
		kw := " IN ("
		if op == betterauth.NotIn {
			kw = " NOT IN ("
		}
		return lhs + kw + strings.Join(parts, ", ") + ")", nil
	case betterauth.Contains, betterauth.StartsWith, betterauth.EndsWith:
		pattern := likeEscape(w.Value)
		switch op {
		case betterauth.Contains:
			pattern = "%" + pattern + "%"
		case betterauth.StartsWith:
			pattern += "%"
		default:
			pattern = "%" + pattern
		}
		kw := " LIKE "
		if w.Insensitive && isString {
			kw = " ILIKE "
		}
		return col + kw + q.arg(pattern) + ` ESCAPE '\'`, nil
	case betterauth.Eq, betterauth.Ne:
		if w.Value == nil {
			if op == betterauth.Eq {
				return col + " IS NULL", nil
			}
			return col + " IS NOT NULL", nil
		}
		sym := " = "
		if op == betterauth.Ne {
			sym = " <> "
		}
		if w.Insensitive && isString {
			// The library lowercases the value in JavaScript, not in SQL; the
			// two disagree outside ASCII under some collations.
			return "lower(" + col + ")" + sym + q.arg(jsuri.ToLowerCase(w.Value.(string))), nil
		}
		return col + sym + q.arg(w.Value), nil
	case betterauth.Lt:
		return col + " < " + q.arg(w.Value), nil
	case betterauth.Lte:
		return col + " <= " + q.arg(w.Value), nil
	case betterauth.Gt:
		return col + " > " + q.arg(w.Value), nil
	case betterauth.Gte:
		return col + " >= " + q.arg(w.Value), nil
	}
	return "", fmt.Errorf("pgstore: unknown operator %q", op)
}

func (q *query) where(ws []betterauth.Where) error {
	var and, or []string
	for _, w := range ws {
		c, err := q.condition(w)
		if err != nil {
			return err
		}
		if w.Connector == betterauth.Or {
			or = append(or, c)
		} else {
			and = append(and, c)
		}
	}
	var groups []string
	if len(and) > 0 {
		groups = append(groups, "("+strings.Join(and, " AND ")+")")
	}
	if len(or) > 0 {
		groups = append(groups, "("+strings.Join(or, " OR ")+")")
	}
	if len(groups) > 0 {
		q.WriteString(" WHERE " + strings.Join(groups, " AND "))
	}
	return nil
}

func sortedKeys(r betterauth.Row) []string {
	keys := make([]string, 0, len(r))
	for k := range r {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func collect(rows pgx.Rows) ([]betterauth.Row, error) {
	defer rows.Close()
	var out []betterauth.Row
	fields := rows.FieldDescriptions()
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return nil, err
		}
		r := make(betterauth.Row, len(fields))
		for i, f := range fields {
			r[f.Name] = vals[i]
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) rows(ctx context.Context, q *query) ([]betterauth.Row, error) {
	rows, err := s.q.Query(ctx, q.b.String(), q.args...)
	if err != nil {
		return nil, err
	}
	return collect(rows)
}

// Create implements betterauth.Store.
func (s *Store) Create(ctx context.Context, table string, data betterauth.Row) (betterauth.Row, error) {
	if len(data) == 0 {
		return nil, errors.New("pgstore: create with no data")
	}
	q := &query{}
	keys := sortedKeys(data)
	cols := make([]string, len(keys))
	vals := make([]string, len(keys))
	for i, k := range keys {
		cols[i] = ident(k)
		vals[i] = q.arg(data[k])
	}
	q.WriteString("INSERT INTO " + ident(table) + " (" + strings.Join(cols, ", ") + ") VALUES (" + strings.Join(vals, ", ") + ") RETURNING *")
	rows, err := s.rows(ctx, q)
	if err != nil {
		return nil, err
	}
	return rows[0], nil
}

func selectList(cols []string) string {
	if len(cols) == 0 {
		return "*"
	}
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = ident(c)
	}
	return strings.Join(out, ", ")
}

// FindOne implements betterauth.Store.
func (s *Store) FindOne(ctx context.Context, table string, where []betterauth.Where) (betterauth.Row, error) {
	rows, err := s.FindMany(ctx, table, where, betterauth.FindOptions{Limit: 1})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, betterauth.ErrNotFound
	}
	return rows[0], nil
}

// FindMany implements betterauth.Store.
func (s *Store) FindMany(ctx context.Context, table string, where []betterauth.Where, opt betterauth.FindOptions) ([]betterauth.Row, error) {
	q := &query{}
	q.WriteString("SELECT " + selectList(opt.Select) + " FROM " + ident(table))
	if err := q.where(where); err != nil {
		return nil, err
	}
	if opt.Sort != nil {
		dir := " ASC"
		if opt.Sort.Desc {
			dir = " DESC"
		}
		q.WriteString(" ORDER BY " + ident(opt.Sort.Column) + dir)
	}
	if opt.Limit > 0 {
		q.WriteString(" LIMIT " + q.arg(opt.Limit))
	}
	if opt.Offset > 0 {
		q.WriteString(" OFFSET " + q.arg(opt.Offset))
	}
	return s.rows(ctx, q)
}

// Count implements betterauth.Store.
func (s *Store) Count(ctx context.Context, table string, where []betterauth.Where) (int64, error) {
	q := &query{}
	q.WriteString("SELECT count(*) FROM " + ident(table))
	if err := q.where(where); err != nil {
		return 0, err
	}
	rows, err := s.q.Query(ctx, q.b.String(), q.args...)
	if err != nil {
		return 0, err
	}
	n, err := pgx.CollectExactlyOneRow(rows, pgx.RowTo[int64])
	return n, err
}

func (s *Store) update(table string, where []betterauth.Where, data betterauth.Row, returning bool) (*query, error) {
	if len(data) == 0 {
		return nil, errors.New("pgstore: update with no data")
	}
	q := &query{}
	keys := sortedKeys(data)
	sets := make([]string, len(keys))
	for i, k := range keys {
		sets[i] = ident(k) + " = " + q.arg(data[k])
	}
	q.WriteString("UPDATE " + ident(table) + " SET " + strings.Join(sets, ", "))
	if err := q.where(where); err != nil {
		return nil, err
	}
	if returning {
		q.WriteString(" RETURNING *")
	}
	return q, nil
}

// Update implements betterauth.Store.
func (s *Store) Update(ctx context.Context, table string, where []betterauth.Where, data betterauth.Row) (betterauth.Row, error) {
	q, err := s.update(table, where, data, true)
	if err != nil {
		return nil, err
	}
	rows, err := s.rows(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, betterauth.ErrNotFound
	}
	return rows[0], nil
}

// UpdateMany implements betterauth.Store.
func (s *Store) UpdateMany(ctx context.Context, table string, where []betterauth.Where, data betterauth.Row) (int64, error) {
	q, err := s.update(table, where, data, false)
	if err != nil {
		return 0, err
	}
	tag, err := s.q.Exec(ctx, q.b.String(), q.args...)
	return tag.RowsAffected(), err
}

// Delete implements betterauth.Store.
func (s *Store) Delete(ctx context.Context, table string, where []betterauth.Where) error {
	_, err := s.DeleteMany(ctx, table, where)
	return err
}

// ConsumeOne implements betterauth.Store. The row is chosen and locked in one
// statement, so of several concurrent callers exactly one deletes it; the
// others re-check after the lock is released, find it gone, and get
// ErrNotFound.
func (s *Store) ConsumeOne(ctx context.Context, table string, where []betterauth.Where) (betterauth.Row, error) {
	q := &query{}
	t := ident(table)
	q.WriteString("DELETE FROM " + t + " WHERE ctid = (SELECT ctid FROM " + t)
	if err := q.where(where); err != nil {
		return nil, err
	}
	q.WriteString(" LIMIT 1 FOR UPDATE) RETURNING *")
	rows, err := s.rows(ctx, q)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, betterauth.ErrNotFound
	}
	return rows[0], nil
}

// DeleteMany implements betterauth.Store.
func (s *Store) DeleteMany(ctx context.Context, table string, where []betterauth.Where) (int64, error) {
	q := &query{}
	q.WriteString("DELETE FROM " + ident(table))
	if err := q.where(where); err != nil {
		return 0, err
	}
	tag, err := s.q.Exec(ctx, q.b.String(), q.args...)
	return tag.RowsAffected(), err
}

// Transaction implements betterauth.Store. Inside a transaction it nests as
// a savepoint.
func (s *Store) Transaction(ctx context.Context, fn func(betterauth.Store) error) error {
	return pgx.BeginFunc(ctx, s.q, func(tx pgx.Tx) error {
		return fn(&Store{q: tx})
	})
}
