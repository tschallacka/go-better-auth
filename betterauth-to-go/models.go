package betterauth

import (
	"context"
	"fmt"
	"time"

	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/crypto"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/schema"
)

// jsTime is a time that encodes the way JavaScript's Date.prototype.toJSON
// does: UTC with millisecond precision.
type jsTime time.Time

func (t jsTime) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Time(t).UTC().Format("2006-01-02T15:04:05.000Z") + `"`), nil
}

// nowMs is the clock at JavaScript's precision, so both implementations
// write the same values.
func (a *Auth) nowMs() time.Time {
	return a.now().UTC().Truncate(time.Millisecond)
}

const idAlphabet = crypto.LowerAlpha + crypto.UpperAlpha + crypto.Digits

// generateID is the library's generateId(32): 32 characters of a-zA-Z0-9.
func (a *Auth) generateID() (string, error) {
	return crypto.RandomString(a.rand, 32, idAlphabet)
}

// model reads and writes one logical table through the Store, mapping field
// names to columns and applying the schema's defaults.
type model struct {
	a *Auth
	t schema.Table
}

func (a *Auth) model(name string) model {
	t, ok := a.schema.Table(name)
	if !ok {
		panic("betterauth: no table " + name) // a programming error: tables are fixed by Build
	}
	return model{a: a, t: t}
}

func (m model) column(field string) string {
	if field == "id" {
		return "id"
	}
	if f, ok := m.t.Field(field); ok {
		return f.ColumnName()
	}
	panic(fmt.Sprintf("betterauth: no field %s.%s", m.t.Name, field))
}

func (m model) where(ws []Where) []Where {
	out := make([]Where, len(ws))
	for i, w := range ws {
		w.Column = m.column(w.Column)
		out[i] = w
	}
	return out
}

func (m model) valueFor(f schema.Field, generated bool) any {
	if f.Type == schema.Date && generated {
		return m.a.nowMs()
	}
	if f.DefaultFunc != nil {
		return f.DefaultFunc()
	}
	return f.Default
}

// toRow maps logical data to columns. On create, a missing field takes its
// default; on update, a field with an on-update value takes it unless given.
func (m model) toRow(data map[string]any, create bool) Row {
	row := Row{}
	if id, ok := data["id"]; ok {
		row["id"] = id
	}
	for _, f := range m.t.Fields {
		v, ok := data[f.Name]
		switch {
		case ok:
		case create && (f.DefaultFunc != nil || f.Default != nil):
			v, ok = m.valueFor(f, f.DefaultFunc != nil), true
		case !create && f.OnUpdate != nil:
			v, ok = m.valueFor(f, true), true
		}
		if ok {
			if t, isTime := v.(time.Time); isTime {
				v = t.UTC().Truncate(time.Millisecond)
			}
			row[f.ColumnName()] = v
		}
	}
	return row
}

// toObject maps a stored row back to logical names in the schema's order,
// with id last, as the library's adapter returns rows.
func (m model) toObject(r Row) *object {
	o := newObject()
	for _, f := range m.t.Fields {
		v, ok := r[f.ColumnName()]
		if !ok {
			continue
		}
		if t, isTime := v.(time.Time); isTime {
			v = jsTime(t)
		}
		o.set(f.Name, v)
	}
	if id, ok := r["id"]; ok {
		o.set("id", id)
	}
	return o
}

func (m model) create(ctx context.Context, s Store, data map[string]any) (*object, error) {
	if _, ok := data["id"]; !ok {
		id, err := m.a.generateID()
		if err != nil {
			return nil, err
		}
		data["id"] = id
	}
	r, err := s.Create(ctx, m.t.Model, m.toRow(data, true))
	if err != nil {
		return nil, err
	}
	return m.toObject(r), nil
}

func (m model) findOne(ctx context.Context, s Store, where ...Where) (*object, error) {
	r, err := s.FindOne(ctx, m.t.Model, m.where(where))
	if err != nil {
		return nil, err
	}
	return m.toObject(r), nil
}

func (m model) update(ctx context.Context, s Store, data map[string]any, where ...Where) (*object, error) {
	r, err := s.Update(ctx, m.t.Model, m.where(where), m.toRow(data, false))
	if err != nil {
		return nil, err
	}
	return m.toObject(r), nil
}

func (m model) deleteMany(ctx context.Context, s Store, where ...Where) error {
	_, err := s.DeleteMany(ctx, m.t.Model, m.where(where))
	return err
}

// timeOf reads a time field of an object.
func timeOf(o *object, field string) (time.Time, bool) {
	v, ok := o.get(field)
	if !ok {
		return time.Time{}, false
	}
	t, ok := v.(jsTime)
	return time.Time(t), ok
}

// stringOf reads a string field of an object.
func stringOf(o *object, field string) string {
	v, _ := o.get(field)
	s, _ := v.(string)
	return s
}
