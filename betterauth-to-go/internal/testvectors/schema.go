package testvectors

import (
	"testing"

	"github.com/tschallacka/go-better-auth/betterauth-to-go/schema"
)

// SchemaScenarios are the configurations testdata/gen/schema.mjs records.
var SchemaScenarios = []string{"core", "phase-a", "custom"}

// SchemaFor returns the Go schema for a recorded scenario, configured the same
// way schema.mjs configures the library.
func SchemaFor(t testing.TB, name string) schema.Schema {
	t.Helper()
	switch name {
	case "core":
		return schema.Build(schema.Options{})
	case "phase-a":
		org, err := schema.Organization(schema.OrganizationOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return schema.Build(schema.Options{Plugins: []schema.Plugin{
			org,
			schema.TwoFactor(schema.TwoFactorOptions{}),
			schema.Passkey(schema.PasskeyOptions{}),
		}})
	case "custom":
		org, err := schema.Organization(schema.OrganizationOptions{
			Organization: schema.PluginTable{ModelName: "orgs", Additional: []schema.Field{
				{Name: "joinCode", Type: schema.String, NoInput: true, Unique: true},
			}},
			Member: schema.PluginTable{Fields: map[string]string{"organizationId": "org_id"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return schema.Build(schema.Options{
			User: schema.Model{
				ModelName: "users",
				Fields:    map[string]string{"email": "email_address", "emailVerified": "email_verified"},
				Additional: []schema.Field{
					{Name: "isInstanceAdmin", Type: schema.Boolean, Default: false, NoInput: true},
					{Name: "locale", Column: "user_locale", Type: schema.String},
				},
			},
			Session: schema.Model{
				ModelName:  "sessions",
				Fields:     map[string]string{"userId": "user_id"},
				Additional: []schema.Field{{Name: "device", Type: schema.String}},
			},
			Account:      schema.Model{ModelName: "accounts"},
			Verification: schema.Model{ModelName: "verifications"},
			Plugins: []schema.Plugin{
				org,
				schema.TwoFactor(schema.TwoFactorOptions{TwoFactor: schema.PluginTable{ModelName: "two_factors"}}),
				schema.Passkey(schema.PasskeyOptions{}),
			},
		})
	}
	t.Fatalf("unknown schema scenario %q", name)
	return schema.Schema{}
}
