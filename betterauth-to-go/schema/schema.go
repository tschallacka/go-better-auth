// Package schema describes the tables better-auth 1.6.14 uses, built from
// configuration the way the library's getAuthTables builds them: core tables
// with their configurable model and column names, plugin tables merged in,
// and additional fields. Nothing here touches a database.
package schema

import (
	"fmt"
	"time"
)

// Type is a field's logical type.
type Type string

// Field types of the library.
const (
	String      Type = "string"
	Number      Type = "number"
	Boolean     Type = "boolean"
	Date        Type = "date"
	JSON        Type = "json"
	StringArray Type = "string[]"
	NumberArray Type = "number[]"
)

// Reference is a foreign key.
type Reference struct {
	Model    string // logical table name, or a model name when the library gives one
	Field    string
	OnDelete string // "" means the migration default, cascade
}

// Field is one column.
type Field struct {
	Name       string // logical name, used in code
	Column     string // column name; empty means Name
	Type       Type
	Required   bool
	Unique     bool
	Index      bool
	Sortable   bool
	BigInt     bool
	NoInput    bool // input: false; a client can never set it
	Hidden     bool // returned: false; never sent to a client
	References *Reference

	Default     any        // literal default, applied on create when the value is missing
	DefaultFunc func() any // computed default; takes precedence over Default
	OnUpdate    func() any // value written on every update
}

// ColumnName is the column the field is stored in.
func (f Field) ColumnName() string {
	if f.Column != "" {
		return f.Column
	}
	return f.Name
}

// Table is one model.
type Table struct {
	Name   string // logical name, e.g. "user"
	Model  string // table name in the database
	Order  int    // creation order for core tables; 0 for plugin tables
	Fields []Field
}

// Field returns the field with the logical name, if any.
func (t Table) Field(name string) (Field, bool) {
	for _, f := range t.Fields {
		if f.Name == name {
			return f, true
		}
	}
	return Field{}, false
}

// Schema is every table in configuration order.
type Schema struct {
	Tables []Table
}

// Table returns the table with the logical name, if any.
func (s Schema) Table(name string) (Table, bool) {
	for _, t := range s.Tables {
		if t.Name == name {
			return t, true
		}
	}
	return Table{}, false
}

// ModelName resolves a reference model to a database table name: a logical
// name maps to its table's model, anything else is taken as given.
func (s Schema) ModelName(model string) string {
	if t, ok := s.Table(model); ok {
		return t.Model
	}
	return model
}

// Model configures one core table: its name, column renames and extra fields.
type Model struct {
	ModelName  string
	Fields     map[string]string // logical name -> column name
	Additional []Field
}

// RateLimitModel configures the rate-limit table.
type RateLimitModel struct {
	ModelName string
	Fields    map[string]string
}

// Options are the schema-relevant parts of the library's configuration.
type Options struct {
	User, Session, Account, Verification Model

	// SecondaryStorage keeps sessions and verifications out of the database
	// unless the matching Store...InDatabase flag is set.
	SecondaryStorage            bool
	StoreSessionInDatabase      bool
	StoreVerificationInDatabase bool

	RateLimitInDatabase bool
	RateLimit           RateLimitModel

	Plugins []Plugin
}

// Plugin is the schema one plugin contributes: new tables, and fields added
// to existing ones (a table named "user" adds columns to the user table).
type Plugin struct {
	ID     string
	Tables []Table
}

// Now is the default and on-update value of the library's timestamp fields.
func Now() any { return time.Now() }

func col(m map[string]string, name string) string {
	if c := m[name]; c != "" {
		return c
	}
	return name
}

func orName(name, fallback string) string {
	if name != "" {
		return name
	}
	return fallback
}

// spread merges src into dst as JavaScript's {...dst, ...src} does: a field
// already present keeps its position and takes the new definition; a new
// field is appended.
func spread(dst []Field, src ...Field) []Field {
	out := append([]Field(nil), dst...)
	for _, f := range src {
		replaced := false
		for i := range out {
			if out[i].Name == f.Name {
				out[i] = f
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, f)
		}
	}
	return out
}

// Build returns the schema for options, mirroring getAuthTables.
func Build(o Options) Schema {
	// Plugin tables, merged across plugins in order; the last model name wins.
	var plugin []Table
	for _, p := range o.Plugins {
		for _, t := range p.Tables {
			found := false
			for i := range plugin {
				if plugin[i].Name == t.Name {
					plugin[i].Fields = spread(plugin[i].Fields, t.Fields...)
					plugin[i].Model = orName(t.Model, t.Name)
					found = true
					break
				}
			}
			if !found {
				plugin = append(plugin, Table{Name: t.Name, Model: orName(t.Model, t.Name), Fields: spread(nil, t.Fields...)})
			}
		}
	}
	pluginFields := func(name string) []Field {
		for _, t := range plugin {
			if t.Name == name {
				return t.Fields
			}
		}
		return nil
	}

	userModel := orName(o.User.ModelName, "user")
	userRef := func() *Reference { return &Reference{Model: userModel, Field: "id", OnDelete: "cascade"} }

	u, s, a, v := o.User.Fields, o.Session.Fields, o.Account.Fields, o.Verification.Fields
	user := Table{Name: "user", Model: userModel, Order: 1, Fields: []Field{
		{Name: "name", Column: col(u, "name"), Type: String, Required: true, Sortable: true},
		{Name: "email", Column: col(u, "email"), Type: String, Required: true, Unique: true, Sortable: true},
		{Name: "emailVerified", Column: col(u, "emailVerified"), Type: Boolean, Required: true, Default: false, NoInput: true},
		{Name: "image", Column: col(u, "image"), Type: String},
		{Name: "createdAt", Column: col(u, "createdAt"), Type: Date, Required: true, DefaultFunc: Now},
		{Name: "updatedAt", Column: col(u, "updatedAt"), Type: Date, Required: true, DefaultFunc: Now, OnUpdate: Now},
	}}
	user.Fields = spread(spread(user.Fields, pluginFields("user")...), o.User.Additional...)

	session := Table{Name: "session", Model: orName(o.Session.ModelName, "session"), Order: 2, Fields: []Field{
		{Name: "expiresAt", Column: col(s, "expiresAt"), Type: Date, Required: true},
		{Name: "token", Column: col(s, "token"), Type: String, Required: true, Unique: true},
		{Name: "createdAt", Column: col(s, "createdAt"), Type: Date, Required: true, DefaultFunc: Now},
		{Name: "updatedAt", Column: col(s, "updatedAt"), Type: Date, Required: true, OnUpdate: Now},
		{Name: "ipAddress", Column: col(s, "ipAddress"), Type: String},
		{Name: "userAgent", Column: col(s, "userAgent"), Type: String},
		{Name: "userId", Column: col(s, "userId"), Type: String, Required: true, Index: true, References: userRef()},
	}}
	session.Fields = spread(spread(session.Fields, pluginFields("session")...), o.Session.Additional...)

	account := Table{Name: "account", Model: orName(o.Account.ModelName, "account"), Order: 3, Fields: []Field{
		{Name: "accountId", Column: col(a, "accountId"), Type: String, Required: true},
		{Name: "providerId", Column: col(a, "providerId"), Type: String, Required: true},
		{Name: "userId", Column: col(a, "userId"), Type: String, Required: true, Index: true, References: userRef()},
		{Name: "accessToken", Column: col(a, "accessToken"), Type: String, Hidden: true},
		{Name: "refreshToken", Column: col(a, "refreshToken"), Type: String, Hidden: true},
		{Name: "idToken", Column: col(a, "idToken"), Type: String, Hidden: true},
		{Name: "accessTokenExpiresAt", Column: col(a, "accessTokenExpiresAt"), Type: Date, Hidden: true},
		{Name: "refreshTokenExpiresAt", Column: col(a, "refreshTokenExpiresAt"), Type: Date, Hidden: true},
		{Name: "scope", Column: col(a, "scope"), Type: String},
		{Name: "password", Column: col(a, "password"), Type: String, Hidden: true},
		{Name: "createdAt", Column: col(a, "createdAt"), Type: Date, Required: true, DefaultFunc: Now},
		{Name: "updatedAt", Column: col(a, "updatedAt"), Type: Date, Required: true, OnUpdate: Now},
	}}
	account.Fields = spread(spread(account.Fields, pluginFields("account")...), o.Account.Additional...)

	verification := Table{Name: "verification", Model: orName(o.Verification.ModelName, "verification"), Order: 4, Fields: []Field{
		{Name: "identifier", Column: col(v, "identifier"), Type: String, Required: true, Index: true},
		{Name: "value", Column: col(v, "value"), Type: String, Required: true},
		{Name: "expiresAt", Column: col(v, "expiresAt"), Type: Date, Required: true},
		{Name: "createdAt", Column: col(v, "createdAt"), Type: Date, Required: true, DefaultFunc: Now},
		{Name: "updatedAt", Column: col(v, "updatedAt"), Type: Date, Required: true, DefaultFunc: Now, OnUpdate: Now},
	}}
	verification.Fields = spread(spread(verification.Fields, pluginFields("verification")...), o.Verification.Additional...)

	out := Schema{Tables: []Table{user}}
	if !o.SecondaryStorage || o.StoreSessionInDatabase {
		out.Tables = append(out.Tables, session)
	}
	out.Tables = append(out.Tables, account)
	if !o.SecondaryStorage || o.StoreVerificationInDatabase {
		out.Tables = append(out.Tables, verification)
	}
	for _, t := range plugin {
		switch t.Name {
		case "user", "session", "account", "verification":
			continue
		}
		out.Tables = append(out.Tables, t)
	}
	if o.RateLimitInDatabase {
		r := o.RateLimit.Fields
		out.Tables = append(out.Tables, Table{Name: "rateLimit", Model: orName(o.RateLimit.ModelName, "rateLimit"), Fields: []Field{
			{Name: "key", Column: col(r, "key"), Type: String, Required: true, Unique: true},
			{Name: "count", Column: col(r, "count"), Type: Number, Required: true},
			{Name: "lastRequest", Column: col(r, "lastRequest"), Type: Number, Required: true, BigInt: true,
				DefaultFunc: func() any { return time.Now().UnixMilli() }},
		}})
	}
	return out
}

// PluginTable configures one table of a plugin: its name, column renames and,
// where the plugin allows them, additional fields.
type PluginTable struct {
	ModelName  string
	Fields     map[string]string
	Additional []Field
}

// rename applies a plugin's schema option the way mergeSchema does, on a copy:
// the library writes into its shared default and leaks the change into every
// later instance; this does not.
func rename(t Table, opt PluginTable) Table {
	out := Table{Name: t.Name, Model: t.Model, Fields: append([]Field(nil), t.Fields...)}
	if opt.ModelName != "" {
		out.Model = opt.ModelName
	}
	for i := range out.Fields {
		if c := opt.Fields[out.Fields[i].Name]; c != "" {
			out.Fields[i].Column = c
		}
	}
	return out
}

// OrganizationOptions are the organization plugin's schema options.
type OrganizationOptions struct {
	Organization, Member, Invitation, Session PluginTable
	Teams                                     bool // not supported yet
	DynamicAccessControl                      bool // not supported yet
}

// Organization returns the organization plugin's schema.
func Organization(o OrganizationOptions) (Plugin, error) {
	if o.Teams || o.DynamicAccessControl {
		return Plugin{}, fmt.Errorf("schema: organization teams and dynamic access control are not supported yet")
	}
	ref := func(model string) *Reference { return &Reference{Model: model, Field: "id"} }
	org := Table{Name: "organization", Model: "organization", Fields: []Field{
		{Name: "name", Type: String, Required: true, Sortable: true},
		{Name: "slug", Type: String, Required: true, Unique: true, Sortable: true, Index: true},
		{Name: "logo", Type: String},
		{Name: "createdAt", Type: Date, Required: true},
		{Name: "metadata", Type: String},
	}}
	member := Table{Name: "member", Model: "member", Fields: []Field{
		{Name: "organizationId", Type: String, Required: true, Index: true, References: ref("organization")},
		{Name: "userId", Type: String, Required: true, Index: true, References: ref("user")},
		{Name: "role", Type: String, Required: true, Sortable: true, Default: "member"},
		{Name: "createdAt", Type: Date, Required: true},
	}}
	invitation := Table{Name: "invitation", Model: "invitation", Fields: []Field{
		{Name: "organizationId", Type: String, Required: true, Index: true, References: ref("organization")},
		{Name: "email", Type: String, Required: true, Sortable: true, Index: true},
		{Name: "role", Type: String, Sortable: true},
		{Name: "status", Type: String, Required: true, Sortable: true, Default: "pending"},
		{Name: "expiresAt", Type: Date, Required: true},
		{Name: "createdAt", Type: Date, Required: true, DefaultFunc: Now},
		{Name: "inviterId", Type: String, Required: true, References: ref("user")},
	}}
	session := Table{Name: "session", Model: "session", Fields: []Field{
		{Name: "activeOrganizationId", Type: String},
	}}
	org = rename(org, o.Organization)
	org.Fields = spread(org.Fields, o.Organization.Additional...)
	member = rename(member, o.Member)
	member.Fields = spread(member.Fields, o.Member.Additional...)
	invitation = rename(invitation, o.Invitation)
	invitation.Fields = spread(invitation.Fields, o.Invitation.Additional...)
	session = rename(session, o.Session)
	return Plugin{ID: "organization", Tables: []Table{session, org, member, invitation}}, nil
}

// TwoFactorOptions are the two-factor plugin's schema options.
type TwoFactorOptions struct {
	User, TwoFactor PluginTable
}

// errNoAdditional rejects additional fields on a plugin table that takes none.
func errNoAdditional(plugin string, tables ...PluginTable) error {
	for _, t := range tables {
		if len(t.Additional) > 0 {
			return fmt.Errorf("schema: the %s plugin takes no additional fields", plugin)
		}
	}
	return nil
}

// TwoFactor returns the two-factor plugin's schema. It takes renames only;
// additional fields are refused rather than ignored.
func TwoFactor(o TwoFactorOptions) (Plugin, error) {
	if err := errNoAdditional("two-factor", o.User, o.TwoFactor); err != nil {
		return Plugin{}, err
	}
	user := Table{Name: "user", Model: "user", Fields: []Field{
		{Name: "twoFactorEnabled", Type: Boolean, Default: false, NoInput: true},
	}}
	tf := Table{Name: "twoFactor", Model: "twoFactor", Fields: []Field{
		{Name: "secret", Type: String, Required: true, Hidden: true, Index: true},
		{Name: "backupCodes", Type: String, Required: true, Hidden: true},
		{Name: "userId", Type: String, Required: true, Hidden: true, Index: true, References: &Reference{Model: "user", Field: "id"}},
		{Name: "verified", Type: Boolean, Default: true, NoInput: true},
	}}
	return Plugin{ID: "two-factor", Tables: []Table{rename(user, o.User), rename(tf, o.TwoFactor)}}, nil
}

// PasskeyOptions are the passkey plugin's schema options.
type PasskeyOptions struct {
	Passkey PluginTable
}

// Passkey returns the passkey plugin's schema. It takes renames only;
// additional fields are refused rather than ignored.
func Passkey(o PasskeyOptions) (Plugin, error) {
	if err := errNoAdditional("passkey", o.Passkey); err != nil {
		return Plugin{}, err
	}
	pk := Table{Name: "passkey", Model: "passkey", Fields: []Field{
		{Name: "name", Type: String},
		{Name: "publicKey", Type: String, Required: true},
		{Name: "userId", Type: String, Required: true, Index: true, References: &Reference{Model: "user", Field: "id"}},
		{Name: "credentialID", Type: String, Required: true, Index: true},
		{Name: "counter", Type: Number, Required: true},
		{Name: "deviceType", Type: String, Required: true},
		{Name: "backedUp", Type: Boolean, Required: true},
		{Name: "transports", Type: String},
		{Name: "createdAt", Type: Date},
		{Name: "aaguid", Type: String},
	}}
	return Plugin{ID: "passkey", Tables: []Table{rename(pk, o.Passkey)}}, nil
}
