// Records better-auth 1.6.14's database schema for the Go tests:
//
// - fixtures/schema/<scenario>.tables.json: getAuthTables(options), the
//   logical schema (model and column names, types, flags) the Go schema
//   builder must reproduce for the same configuration.
// - fixtures/schema/<scenario>.sql: the PostgreSQL DDL the library itself
//   compiles for that configuration on an empty database.
// - ../../migrations/000N_*.sql: the shipped migrations, compiled step by
//   step (core, then each plugin) so a project can apply only what it uses.
//
// Needs a scratch PostgreSQL: PG_URL=$(pg-scratch url) npm run schema
import { mkdirSync, writeFileSync } from "node:fs";
import pg from "pg";
import { getAuthTables } from "@better-auth/core/db";
import { getMigrations } from "better-auth/db/migration";
import { organization, twoFactor, emailOTP, genericOAuth } from "better-auth/plugins";
import { passkey } from "@better-auth/passkey";

const adminURL = process.env.PG_URL;
if (!adminURL) {
  console.error("PG_URL is not set; start pg-scratch and pass its URL");
  process.exit(2);
}

const base = {
  secret: "fixture-secret-0123456789abcdef0123456789",
  baseURL: "http://localhost:3000",
  emailAndPassword: { enabled: true },
  logger: { disabled: true },
};
const phaseA = () => [
  organization(),
  twoFactor({ issuer: "Fixture" }),
  passkey({ rpID: "localhost", rpName: "Fixture" }),
  emailOTP({ async sendVerificationOTP() {} }),
  genericOAuth({
    config: [{ providerId: "oidc", clientId: "fixture", discoveryUrl: "https://idp.invalid/.well-known/openid-configuration" }],
  }),
];

// Configurations are built only when used: constructing a plugin with schema
// options changes the plugin's shared default schema for the whole process
// (better-auth 1.6.14; observed: twoFactor({schema: {twoFactor: {modelName}}})
// renamed the table of every later twoFactor()). The custom one comes last.
const scenarios = {
  core: () => ({ ...base }),
  "phase-a": () => ({ ...base, plugins: phaseA() }),
  custom: () => ({
    user: {
      modelName: "users",
      fields: { email: "email_address", emailVerified: "email_verified" },
      additionalFields: {
        isInstanceAdmin: { type: "boolean", required: false, defaultValue: false, input: false },
        locale: { type: "string", required: false, fieldName: "user_locale" },
      },
    },
    session: { modelName: "sessions", fields: { userId: "user_id" }, additionalFields: { device: { type: "string", required: false } } },
    account: { modelName: "accounts" },
    verification: { modelName: "verifications" },
    plugins: [
      organization({
        schema: {
          organization: {
            modelName: "orgs",
            additionalFields: { joinCode: { type: "string", required: false, input: false, unique: true } },
          },
          member: { fields: { organizationId: "org_id" } },
        },
      }),
      twoFactor({ issuer: "Fixture", schema: { twoFactor: { modelName: "two_factors" } } }),
      passkey({ rpID: "localhost", rpName: "Fixture" }),
    ],
  }),
};

// Functions (default values, onUpdate, validators) cannot be compared across
// languages; record that they exist and keep plain values as they are.
function plain(v) {
  if (typeof v === "function") return { fn: true };
  if (Array.isArray(v)) return v.map(plain);
  if (v && typeof v === "object") {
    const o = {};
    for (const [k, x] of Object.entries(v)) {
      if (k === "validator" || k === "transform") continue;
      o[k] = plain(x);
    }
    return o;
  }
  return v;
}

async function freshDatabase(name) {
  const admin = new pg.Client({ connectionString: adminURL });
  await admin.connect();
  await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
  await admin.query(`CREATE DATABASE ${name}`);
  await admin.end();
  const url = new URL(adminURL);
  url.pathname = "/" + name;
  return new pg.Pool({ connectionString: url.toString() });
}

async function compileAndRun(options, pool, label) {
  console.error(`schema: ${label}`);
  const { compileMigrations, runMigrations } = await getMigrations({ ...options, database: pool });
  const sql = await compileMigrations();
  await runMigrations();
  return sql;
}

const fixtures = new URL("../fixtures/schema/", import.meta.url);
const migrations = new URL("../../migrations/", import.meta.url);
mkdirSync(fixtures, { recursive: true });
mkdirSync(migrations, { recursive: true });

// Shipped migrations: each step compiles only what the previous ones lack.
// They run first: a configuration that renames models changes state the
// plugins share within one process (observed: after the custom scenario a
// later twoFactor() referenced "users"), so the custom scenario runs last.
const steps = [
  ["0001_core", []],
  ["0002_organization", [organization()]],
  ["0003_two_factor", [organization(), twoFactor({ issuer: "Fixture" })]],
  ["0004_passkey", [organization(), twoFactor({ issuer: "Fixture" }), passkey({ rpID: "localhost", rpName: "Fixture" })]],
];
const stepPool = await freshDatabase("gen_schema_steps");
for (const [file, plugins] of steps) {
  const sql = await compileAndRun({ ...base, plugins }, stepPool, file);
  writeFileSync(
    new URL(`${file}.sql`, migrations),
    `-- Generated by testdata/gen/schema.mjs from better-auth 1.6.14. Do not edit.\n${sql}\n`,
  );
}
await stepPool.end();

for (const [name, build] of Object.entries(scenarios)) {
  const options = build();
  writeFileSync(new URL(`${name}.tables.json`, fixtures), JSON.stringify(plain(getAuthTables(options)), null, 2) + "\n");
  const pool = await freshDatabase(`gen_schema_${name.replace("-", "_")}`);
  writeFileSync(new URL(`${name}.sql`, fixtures), await compileAndRun(options, pool, name));
  await pool.end();
}
