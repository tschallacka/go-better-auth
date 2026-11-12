// Records what better-auth 1.6.14's own database adapter returns for a set of
// read queries over fixed rows, so pgstore can be compared with it row for
// row. Writes ../fixtures/adapter-vectors.json.
//
//   PG_URL=$(pg-scratch url) npm run adapter
import { writeFileSync } from "node:fs";
import pg from "pg";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";

const adminURL = process.env.PG_URL;
if (!adminURL) {
  console.error("PG_URL is not set; start pg-scratch and pass its URL");
  process.exit(2);
}

const admin = new pg.Client({ connectionString: adminURL });
await admin.connect();
await admin.query("DROP DATABASE IF EXISTS gen_adapter WITH (FORCE)");
await admin.query("CREATE DATABASE gen_adapter");
await admin.end();
const url = new URL(adminURL);
url.pathname = "/gen_adapter";
const pool = new pg.Pool({ connectionString: url.toString() });

const options = {
  secret: "fixture-secret-0123456789abcdef0123456789",
  baseURL: "http://localhost:3000",
  emailAndPassword: { enabled: true },
  logger: { disabled: true },
  database: pool,
};
await (await getMigrations(options)).runMigrations();

// Plain SQL so the Go test can load exactly the same rows.
const seed = `INSERT INTO "user" ("id", "name", "email", "emailVerified", "image", "createdAt", "updatedAt") VALUES
  ('u1', 'Ann', 'ann@example.com', true, NULL, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'),
  ('u2', 'Bob', 'BOB@Example.com', false, 'b.png', '2026-02-01T00:00:00Z', '2026-02-01T00:00:00Z'),
  ('u3', '50%_off', 'c@example.org', false, NULL, '2026-03-01T00:00:00Z', '2026-03-01T00:00:00Z'),
  ('u4', '50xyoff', 'd@example.org', true, 'd.png', '2026-04-01T00:00:00Z', '2026-04-01T00:00:00Z'),
  ('u5', 'Émile', 'ÉMILE@x.com', false, NULL, '2026-05-01T00:00:00Z', '2026-05-01T00:00:00Z'),
  ('u6', 'straße', 'STRASSE@x.com', false, NULL, '2026-06-01T00:00:00Z', '2026-06-01T00:00:00Z'),
  ('u7', 'Σίσυφος', 'ΣΊΣΥΦΟΣ@x.gr', true, NULL, '2026-07-01T00:00:00Z', '2026-07-01T00:00:00Z'),
  ('u8', 'zoë', 'zoe@x.com', false, NULL, '2026-08-01T00:00:00Z', '2026-08-01T00:00:00Z');`;
await pool.query(seed);

const adapter = (await betterAuth(options).$context).adapter;

const w = (field, operator, value, extra = {}) => ({ field, operator, value, ...extra });
const ci = { mode: "insensitive" };
const or = { connector: "OR" };
const date = (s) => ({ $date: s });
const revive = (v) => (v && typeof v === "object" && "$date" in v ? new Date(v.$date) : v);

// [name, where, findMany options]. Dates are written as {$date} so both
// sides can rebuild the same value.
const queries = [
  ["eq", [w("name", "eq", "Ann")]],
  ["eq is case sensitive", [w("email", "eq", "ann@EXAMPLE.com")]],
  ["eq insensitive ascii", [w("email", "eq", "BOB@EXAMPLE.COM", ci)]],
  ["eq insensitive accented", [w("email", "eq", "émile@x.com", ci)]],
  ["eq insensitive accented upper", [w("email", "eq", "ÉMILE@X.COM", ci)]],
  ["eq insensitive greek", [w("email", "eq", "σίσυφος@x.gr", ci)]],
  ["eq insensitive sharp s", [w("email", "eq", "strasse@x.com", ci)]],
  ["ne", [w("name", "ne", "Ann")]],
  ["ne insensitive", [w("email", "ne", "bob@example.com", ci)]],
  ["eq null", [w("image", "eq", null)]],
  ["ne null", [w("image", "ne", null)]],
  ["eq boolean", [w("emailVerified", "eq", true)]],
  ["in", [w("id", "in", ["u1", "u3", "nope"])]],
  ["in insensitive", [w("email", "in", ["ANN@EXAMPLE.COM", "bob@example.com", "émile@x.com"], ci)]],
  ["not in", [w("id", "not_in", ["u1", "u2", "u3"])]],
  ["not in insensitive", [w("email", "not_in", ["ANN@EXAMPLE.COM", "bob@example.com"], ci)]],
  ["in empty", [w("id", "in", [])]],
  ["not in empty", [w("id", "not_in", [])]],
  ["contains", [w("email", "contains", "example")]],
  ["contains wildcards (D13)", [w("name", "contains", "%_")]],
  ["starts with wildcard (D13)", [w("name", "starts_with", "50%")]],
  ["ends with", [w("email", "ends_with", ".org")]],
  ["contains insensitive", [w("email", "contains", "EXAMPLE", ci)]],
  ["contains insensitive accented", [w("email", "contains", "émile", ci)]],
  ["gt string", [w("name", "gt", "Bob")]],
  ["lte string", [w("name", "lte", "Bob")]],
  ["gte date", [w("createdAt", "gte", date("2026-06-01T00:00:00Z"))]],
  ["lt date", [w("createdAt", "lt", date("2026-03-01T00:00:00Z"))]],
  ["and with or", [w("email", "ends_with", ".com"), w("id", "eq", "u1", or), w("id", "eq", "u3", or)]],
  ["or only", [w("id", "eq", "u1", or), w("name", "eq", "zoë", or)]],
  ["and and", [w("emailVerified", "eq", false), w("image", "eq", null)]],
  ["sorted page", [w("emailVerified", "eq", false)], { sortBy: { field: "name", direction: "desc" }, limit: 3, offset: 1 }],
];

const out = { generator: "better-auth 1.6.14", seed, queries: [] };
for (const [name, where, opts = {}] of queries) {
  const entry = { name, where, options: opts };
  try {
    const rows = await adapter.findMany({ model: "user", where: where.map((c) => ({ ...c, value: revive(c.value) })), ...opts });
    entry.ids = rows.map((r) => r.id);
    if (!opts.sortBy) entry.ids.sort();
    entry.count = await adapter.count({ model: "user", where: where.map((c) => ({ ...c, value: revive(c.value) })) });
  } catch (e) {
    entry.error = String(e?.message ?? e).split("\n")[0];
  }
  out.queries.push(entry);
}
await pool.end();

writeFileSync(new URL("../fixtures/adapter-vectors.json", import.meta.url), JSON.stringify(out, null, 2) + "\n");
for (const q of out.queries) console.error(`${q.name}: ${q.error ? "error: " + q.error : JSON.stringify(q.ids)}`);
