package schema_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tschallacka/go-better-auth/betterauth-to-go/internal/testvectors"
	"github.com/tschallacka/go-better-auth/betterauth-to-go/schema"
)

// ordered decodes a JSON object keeping its key order.
func ordered(t *testing.T, raw json.RawMessage) ([]string, map[string]json.RawMessage) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("not an object: %s", raw)
	}
	var keys []string
	vals := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		k := tok.(string)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
		vals[k] = v
	}
	return keys, vals
}

// norm is a field reduced to what both sides can express, with the library's
// defaults filled in.
type norm struct {
	Column, Type                              string
	Required, Unique, Index, Sortable, BigInt bool
	Input, Returned                           bool
	RefModel, RefField, RefOnDelete           string
	DefaultKind                               string // "", "literal", "fn"
	DefaultValue                              string
	OnUpdate                                  bool
}

func fromLibrary(t *testing.T, name string, raw json.RawMessage) norm {
	t.Helper()
	var f struct {
		Type       string                                   `json:"type"`
		FieldName  string                                   `json:"fieldName"`
		Required   bool                                     `json:"required"`
		Unique     bool                                     `json:"unique"`
		Index      bool                                     `json:"index"`
		Sortable   bool                                     `json:"sortable"`
		BigInt     bool                                     `json:"bigint"`
		Input      *bool                                    `json:"input"`
		Returned   *bool                                    `json:"returned"`
		References *struct{ Model, Field, OnDelete string } `json:"references"`
		Default    json.RawMessage                          `json:"defaultValue"`
		OnUpdate   json.RawMessage                          `json:"onUpdate"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	n := norm{Column: f.FieldName, Type: f.Type, Required: f.Required, Unique: f.Unique, Index: f.Index,
		Sortable: f.Sortable, BigInt: f.BigInt, Input: f.Input == nil || *f.Input, Returned: f.Returned == nil || *f.Returned,
		OnUpdate: len(f.OnUpdate) > 0}
	if n.Column == "" {
		n.Column = name
	}
	if f.References != nil {
		n.RefModel, n.RefField, n.RefOnDelete = f.References.Model, f.References.Field, f.References.OnDelete
	}
	var compact bytes.Buffer
	if len(f.Default) > 0 {
		if err := json.Compact(&compact, f.Default); err != nil {
			t.Fatal(err)
		}
		f.Default = compact.Bytes()
	}
	switch {
	case len(f.Default) == 0:
	case string(f.Default) == `{"fn":true}`:
		n.DefaultKind = "fn"
	default:
		n.DefaultKind, n.DefaultValue = "literal", string(f.Default)
	}
	return n
}

func fromGo(f schema.Field) norm {
	n := norm{Column: f.ColumnName(), Type: string(f.Type), Required: f.Required, Unique: f.Unique, Index: f.Index,
		Sortable: f.Sortable, BigInt: f.BigInt, Input: !f.NoInput, Returned: !f.Hidden, OnUpdate: f.OnUpdate != nil}
	if f.References != nil {
		n.RefModel, n.RefField, n.RefOnDelete = f.References.Model, f.References.Field, f.References.OnDelete
	}
	switch {
	case f.DefaultFunc != nil:
		n.DefaultKind = "fn"
	case f.Default != nil:
		b, _ := json.Marshal(f.Default)
		n.DefaultKind, n.DefaultValue = "literal", string(b)
	}
	return n
}

func TestBuildMatchesLibrary(t *testing.T) {
	for _, name := range testvectors.SchemaScenarios {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(testvectors.FixturesDir(), "schema", name+".tables.json"))
			if err != nil {
				t.Fatal(err)
			}
			got := testvectors.SchemaFor(t, name)
			tableKeys, tables := ordered(t, raw)
			var gotKeys []string
			for _, tb := range got.Tables {
				gotKeys = append(gotKeys, tb.Name)
			}
			if !reflect.DeepEqual(gotKeys, tableKeys) {
				t.Fatalf("tables %v; library %v", gotKeys, tableKeys)
			}
			for _, key := range tableKeys {
				var lib struct {
					ModelName string          `json:"modelName"`
					Order     int             `json:"order"`
					Fields    json.RawMessage `json:"fields"`
				}
				if err := json.Unmarshal(tables[key], &lib); err != nil {
					t.Fatal(err)
				}
				tb, _ := got.Table(key)
				if tb.Model != lib.ModelName || tb.Order != lib.Order {
					t.Errorf("%s: model %q order %d; library %q %d", key, tb.Model, tb.Order, lib.ModelName, lib.Order)
				}
				fieldKeys, fields := ordered(t, lib.Fields)
				var goKeys []string
				for _, f := range tb.Fields {
					goKeys = append(goKeys, f.Name)
				}
				if !reflect.DeepEqual(goKeys, fieldKeys) {
					t.Errorf("%s fields %v; library %v", key, goKeys, fieldKeys)
					continue
				}
				for _, fk := range fieldKeys {
					f, _ := tb.Field(fk)
					if g, l := fromGo(f), fromLibrary(t, fk, fields[fk]); g != l {
						t.Errorf("%s.%s:\n go  %+v\n lib %+v", key, fk, g, l)
					}
				}
			}
		})
	}
}

func TestPluginOptionsDoNotLeak(t *testing.T) {
	// The library's mergeSchema writes renames into the plugin's shared
	// default schema, so a later instance inherits them. Here it must not.
	if _, err := schema.TwoFactor(schema.TwoFactorOptions{TwoFactor: schema.PluginTable{ModelName: "renamed", Fields: map[string]string{"secret": "s"}}}); err != nil {
		t.Fatal(err)
	}
	fresh, err := schema.TwoFactor(schema.TwoFactorOptions{})
	if err != nil {
		t.Fatal(err)
	}
	tf := fresh.Tables[1]
	if tf.Model != "twoFactor" {
		t.Errorf("model %q leaked from an earlier instance", tf.Model)
	}
	if f, _ := tf.Field("secret"); f.ColumnName() != "secret" {
		t.Errorf("column %q leaked from an earlier instance", f.ColumnName())
	}
}

func TestPluginsRejectUnsupportedOptions(t *testing.T) {
	for _, o := range []schema.OrganizationOptions{{Teams: true}, {DynamicAccessControl: true}} {
		if _, err := schema.Organization(o); err == nil {
			t.Errorf("Organization(%+v) accepted an unsupported option", o)
		}
	}
	extra := schema.PluginTable{Additional: []schema.Field{{Name: "x", Type: schema.String}}}
	if _, err := schema.TwoFactor(schema.TwoFactorOptions{TwoFactor: extra}); err == nil {
		t.Error("TwoFactor accepted additional fields it would have ignored")
	}
	if _, err := schema.TwoFactor(schema.TwoFactorOptions{User: extra}); err == nil {
		t.Error("TwoFactor accepted additional user fields it would have ignored")
	}
	if _, err := schema.Passkey(schema.PasskeyOptions{Passkey: extra}); err == nil {
		t.Error("Passkey accepted additional fields it would have ignored")
	}
}

func TestSecondaryStorageAndRateLimit(t *testing.T) {
	s := schema.Build(schema.Options{SecondaryStorage: true, RateLimitInDatabase: true})
	var names []string
	for _, tb := range s.Tables {
		names = append(names, tb.Name)
	}
	if fmt.Sprint(names) != "[user account rateLimit]" {
		t.Errorf("tables %v; want user, account, rateLimit", names)
	}
	s = schema.Build(schema.Options{SecondaryStorage: true, StoreSessionInDatabase: true, StoreVerificationInDatabase: true})
	if len(s.Tables) != 4 {
		t.Errorf("%d tables; want session and verification kept in the database", len(s.Tables))
	}
}
