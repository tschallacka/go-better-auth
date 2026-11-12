// Runs the real better-auth 1.6.14 for the Go differential tests
// (internal/difftest). It is started by the tests, never in production.
//
// Environment:
//   PG_URL   database this instance uses; its tables are created with the
//            library's own migrator on start
//   CONFIG   JSON: { secret, baseURL, options, plugins: [{name, options}] }
//            options is merged into the betterAuth() options as plain data
//
// It listens on 127.0.0.1 on a free port and prints "ready <port>" once.
// Besides /api/auth/* it serves GET /__outbox, which returns and clears every
// message the library asked to send (verification links, reset links, OTPs,
// invitations), so tests can read tokens without a mail server.
import { createServer } from "node:http";
import pg from "pg";
import { betterAuth } from "better-auth";
import { toNodeHandler } from "better-auth/node";
import { getMigrations } from "better-auth/db/migration";
import { organization, twoFactor, emailOTP, genericOAuth } from "better-auth/plugins";
import { passkey } from "@better-auth/passkey";

const config = JSON.parse(process.env.CONFIG ?? "{}");
if (!process.env.PG_URL || !config.secret || !config.baseURL) {
  console.error("server.mjs needs PG_URL and CONFIG with secret and baseURL");
  process.exit(2);
}

const outbox = [];
const record = (kind) => async (data) => {
  // Keep only plain values; user objects are reduced to id and email.
  const plain = {};
  for (const [k, v] of Object.entries(data ?? {})) {
    if (v && typeof v === "object" && "email" in v) plain[k] = { id: v.id, email: v.email };
    else if (v && typeof v === "object" && "id" in v) plain[k] = { id: v.id };
    else if (typeof v !== "function") plain[k] = v;
  }
  outbox.push({ kind, ...plain });
};

const options = structuredClone(config.options ?? {});
if (options.emailAndPassword) options.emailAndPassword.sendResetPassword = record("reset-password");
if (options.emailVerification) options.emailVerification.sendVerificationEmail = record("verification-email");
if (options.user?.changeEmail?.enabled) options.user.changeEmail.sendChangeEmailVerification = record("change-email");
if (options.user?.deleteUser?.enabled) options.user.deleteUser.sendDeleteAccountVerification = record("delete-account");

const builders = {
  organization: (o) => organization({ ...o, sendInvitationEmail: record("invitation") }),
  twoFactor: (o) => twoFactor(o),
  passkey: (o) => passkey(o),
  emailOTP: (o) => emailOTP({ ...o, sendVerificationOTP: record("otp") }),
  genericOAuth: (o) => genericOAuth(o),
};
const plugins = (config.plugins ?? []).map(({ name, options: o }) => {
  const build = builders[name];
  if (!build) {
    console.error(`server.mjs: unknown plugin ${name}`);
    process.exit(2);
  }
  return build(o ?? {});
});

const pool = new pg.Pool({ connectionString: process.env.PG_URL });
const auth = betterAuth({
  ...options,
  secret: config.secret,
  baseURL: config.baseURL,
  database: pool,
  plugins,
  logger: { disabled: true },
});
await (await getMigrations({ ...options, secret: config.secret, baseURL: config.baseURL, database: pool, plugins })).runMigrations();

const handler = toNodeHandler(auth);
const server = createServer((req, res) => {
  if (req.url === "/__outbox" && req.method === "GET") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(outbox.splice(0)));
    return;
  }
  handler(req, res);
});
server.listen(0, "127.0.0.1", () => {
  process.stdout.write(`ready ${server.address().port}\n`);
});

const stop = async () => {
  server.close();
  await pool.end();
  process.exit(0);
};
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
// The test that started this process owns it: when its stdin closes, exit.
process.stdin.on("end", stop);
process.stdin.resume();
