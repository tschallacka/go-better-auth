package pgstore

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tschallacka/go-better-auth/betterauth-to-go/schema"
)

// Kind classifies a Difference.
type Kind string

// Kinds of difference. The first four make the module fail at runtime; the
// rest cost performance or a guarantee the module also enforces in code.
const (
	MissingTable      Kind = "missing_table"
	MissingColumn     Kind = "missing_column"
	TypeMismatch      Kind = "type_mismatch"
	UnexpectedNotNull Kind = "unexpected_not_null" // optional field, NOT NULL column: inserts without it fail
	MissingNotNull    Kind = "missing_not_null"    // required field, nullable column
	MissingUnique     Kind = "missing_unique"
	MissingIndex      Kind = "missing_index"
)

// Difference is one way the database differs from the schema.
type Difference struct {
	Table  string // database table name
	Column string // empty for a table-level difference
	Kind   Kind
	Detail string
}

// Blocking reports whether the module cannot work with this difference.
func (d Difference) Blocking() bool {
	switch d.Kind {
	case MissingTable, MissingColumn, TypeMismatch, UnexpectedNotNull:
		return true
	}
	return false
}

func (d Difference) String() string {
	where := d.Table
	if d.Column != "" {
		where += "." + d.Column
	}
	return fmt.Sprintf("%s: %s (%s)", where, d.Kind, d.Detail)
}

// typeFamilies are the PostgreSQL types the library's migrator accepts for
// each field type (get-migration.ts postgresMap), as udt names.
var typeFamilies = map[schema.Type][]string{
	schema.String:  {"varchar", "text", "uuid", "bpchar"},
	schema.Number:  {"int2", "int4", "int8", "numeric", "float4", "float8"},
	schema.Boolean: {"bool"},
	schema.Date:    {"timestamptz", "timestamp", "date"},
	schema.JSON:    {"json", "jsonb"},
}

func typeMatches(t schema.Type, udt string) bool {
	if t == schema.StringArray || t == schema.NumberArray {
		return strings.Contains(udt, "json")
	}
	for _, u := range typeFamilies[t] {
		if u == udt {
			return true
		}
	}
	return false
}

type column struct {
	udt      string
	nullable bool
}

// CheckSchema compares the tables in the connection's current schema with s
// and returns every difference. It reads the catalogue only and changes
// nothing; use it at startup and in CI.
func CheckSchema(ctx context.Context, pool *pgxpool.Pool, s schema.Schema) ([]Difference, error) {
	var current string
	if err := pool.QueryRow(ctx, "SELECT current_schema()").Scan(&current); err != nil {
		return nil, fmt.Errorf("pgstore: current schema: %w", err)
	}

	cols := map[string]map[string]column{}
	rows, err := pool.Query(ctx, `SELECT table_name, column_name, udt_name, is_nullable = 'YES'
		FROM information_schema.columns WHERE table_schema = $1`, current)
	if err != nil {
		return nil, fmt.Errorf("pgstore: reading columns: %w", err)
	}
	for rows.Next() {
		var table, name, udt string
		var nullable bool
		if err := rows.Scan(&table, &name, &udt, &nullable); err != nil {
			rows.Close()
			return nil, err
		}
		if cols[table] == nil {
			cols[table] = map[string]column{}
		}
		cols[table][name] = column{udt: udt, nullable: nullable}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Single-column indexes, keyed table/column, and whether one is unique.
	indexed := map[string]bool{}
	unique := map[string]bool{}
	rows, err = pool.Query(ctx, `SELECT t.relname, a.attname, i.indisunique
		FROM pg_index i
		JOIN pg_class t ON t.oid = i.indrelid
		JOIN pg_namespace n ON n.oid = t.relnamespace
		JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = i.indkey[0]
		WHERE n.nspname = $1 AND i.indnkeyatts = 1`, current)
	if err != nil {
		return nil, fmt.Errorf("pgstore: reading indexes: %w", err)
	}
	for rows.Next() {
		var table, col string
		var isUnique bool
		if err := rows.Scan(&table, &col, &isUnique); err != nil {
			rows.Close()
			return nil, err
		}
		indexed[table+"/"+col] = true
		if isUnique {
			unique[table+"/"+col] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var diffs []Difference
	for _, t := range s.Tables {
		live, ok := cols[t.Model]
		if !ok {
			diffs = append(diffs, Difference{Table: t.Model, Kind: MissingTable, Detail: "table " + t.Name})
			continue
		}
		fields := append([]schema.Field{{Name: "id", Type: schema.String, Required: true, Unique: true}}, t.Fields...)
		for _, f := range fields {
			name := f.ColumnName()
			c, ok := live[name]
			if !ok {
				diffs = append(diffs, Difference{Table: t.Model, Column: name, Kind: MissingColumn, Detail: string(f.Type)})
				continue
			}
			if !typeMatches(f.Type, c.udt) {
				diffs = append(diffs, Difference{Table: t.Model, Column: name, Kind: TypeMismatch,
					Detail: fmt.Sprintf("want %s, column is %s", f.Type, c.udt)})
			}
			switch {
			case f.Required && c.nullable:
				diffs = append(diffs, Difference{Table: t.Model, Column: name, Kind: MissingNotNull, Detail: "required field, nullable column"})
			case !f.Required && !c.nullable:
				diffs = append(diffs, Difference{Table: t.Model, Column: name, Kind: UnexpectedNotNull, Detail: "optional field, NOT NULL column"})
			}
			key := t.Model + "/" + name
			if f.Unique && !unique[key] {
				diffs = append(diffs, Difference{Table: t.Model, Column: name, Kind: MissingUnique})
			}
			if f.Index && !f.Unique && !indexed[key] {
				diffs = append(diffs, Difference{Table: t.Model, Column: name, Kind: MissingIndex})
			}
		}
	}
	sort.SliceStable(diffs, func(i, j int) bool {
		if diffs[i].Table != diffs[j].Table {
			return diffs[i].Table < diffs[j].Table
		}
		return diffs[i].Column < diffs[j].Column
	})
	return diffs, nil
}
