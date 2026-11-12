// Package betterauth is a Go implementation of the better-auth 1.6.14 server,
// reading and writing the same tables and cookies so both can run side by
// side. See PLAN.md.
package betterauth

import (
	"context"
	"errors"
)

// Row is one record keyed by column name. Values are what the driver returns
// and accepts: string, bool, int64, float64, time.Time, []byte or nil.
type Row map[string]any

// Operator is a comparison in a Where condition, as better-auth names them.
type Operator string

// Operators.
const (
	Eq         Operator = "eq"
	Ne         Operator = "ne"
	Lt         Operator = "lt"
	Lte        Operator = "lte"
	Gt         Operator = "gt"
	Gte        Operator = "gte"
	In         Operator = "in"
	NotIn      Operator = "not_in"
	Contains   Operator = "contains"
	StartsWith Operator = "starts_with"
	EndsWith   Operator = "ends_with"
)

// Connector joins a condition to the others. Conditions with AND are all
// required, and at least one OR condition must hold when there are any:
// (and1 AND and2 ...) AND (or1 OR or2 ...), as the library's adapter does.
type Connector string

// Connectors.
const (
	And Connector = "AND"
	Or  Connector = "OR"
)

// Where is one condition on a column.
type Where struct {
	Column    string
	Operator  Operator // empty means Eq
	Value     any      // a slice for In and NotIn; nil with Eq or Ne tests for NULL
	Connector Connector
	// Insensitive compares case-insensitively when Value is a string or a
	// slice of strings, like the library's mode: "insensitive".
	Insensitive bool
}

// Sort orders FindMany results.
type Sort struct {
	Column string
	Desc   bool
}

// FindOptions limit and order FindMany.
type FindOptions struct {
	Limit  int // 0 means no limit
	Offset int
	Sort   *Sort
	Select []string // columns to return; empty means all
}

// Store is the database access the module needs, over physical table and
// column names; the auth layer maps the schema's logical names before calling
// it. pgstore implements it for PostgreSQL; a project can adapt its own
// database layer.
//
// Store holds no state of its own and must be safe for concurrent use.
type Store interface {
	// Create inserts data, which includes the id, and returns the stored row.
	Create(ctx context.Context, table string, data Row) (Row, error)
	// FindOne returns the first matching row, or ErrNotFound.
	FindOne(ctx context.Context, table string, where []Where) (Row, error)
	FindMany(ctx context.Context, table string, where []Where, opt FindOptions) ([]Row, error)
	Count(ctx context.Context, table string, where []Where) (int64, error)
	// Update changes every matching row, as the library's adapter does, and
	// returns the first, or ErrNotFound when none matched.
	Update(ctx context.Context, table string, where []Where, data Row) (Row, error)
	UpdateMany(ctx context.Context, table string, where []Where, data Row) (int64, error)
	// Delete removes every matching row; no match is not an error.
	Delete(ctx context.Context, table string, where []Where) error
	DeleteMany(ctx context.Context, table string, where []Where) (int64, error)
	// Transaction runs fn with a Store bound to one transaction, committing
	// when fn returns nil and rolling back otherwise.
	Transaction(ctx context.Context, fn func(Store) error) error
}

// ErrNotFound is returned by FindOne and Update when no row matches.
var ErrNotFound = errors.New("betterauth: not found")
