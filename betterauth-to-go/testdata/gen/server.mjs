// Runs the real better-auth 1.6.14 for the Go differential tests
// (internal/difftest). It is started by the tests, never in production.
//
// Environment (internal/difftest passes exactly these, nothing inherited):
//   PG_URL      database this instance uses; its tables are created with the
//               library's own migrator on start
//   CONFIG      JSON: { secret, baseURL, rateLimit, originCheck, options,
//               plugins: [{name, options}] }. rateLimit and originCheck are
//               required booleans so no test inherits them by accident.
//               options is merged into the betterAuth() options as plain data.
//   NODE_ENV    "production", pinned by the caller: "test" (or TEST=1) would
//               silently switch off the library's origin check.
//   PARENT_PID  the Go test process; this server exits when it is gone.
//
// It listens on 127.0.0.1 on a free port and prints "ready <port>" once.
// Besides /api/auth/* it serves GET /__outbox, which returns and clears every
// message the library asked to send (verification links, reset links, OTPs,
// invitations), so tests can read tokens without a mail server. It is test
// tooling: never run it anywhere but a developer machine or CI.
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
if (typeof config.rateLimit !== "boolean" || typeof config.originCheck !== "boolean") {
  console.error("server.mjs needs CONFIG.rateLimit and CONFIG.originCheck as explicit booleans");
  process.exit(2);
}
if (process.env.NODE_ENV !== "production" || process.env.TEST) {
  console.error("server.mjs must run with NODE_ENV=production and no TEST variable");
  process.exit(2);
}

const outbox = [];
const record = (kind) => async (data) => {
  // Everything the library hands over, as plain JSON (dates as ISO strings,
  // functions dropped), so tests can compare all of it.
  outbox.push({ kind, ...JSON.parse(JSON.stringify(data ?? {})) });
};

const options = structuredClone(config.options ?? {});
options.rateLimit = { ...options.rateLimit, enabled: config.rateLimit };
options.advanced = { ...options.advanced, disableOriginCheck: !config.originCheck };
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
  // Warnings and errors go to stderr, which the Go test prints on failure.
  logger: { level: "warn", log: (level, message, ...args) => console.error(`[${level}] ${message}`, ...args) },
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
// The test that started this process owns it: when its stdin closes, or the
// process itself is gone (a test binary killed hard), exit.
process.stdin.on("end", stop);
const parent = Number(process.env.PARENT_PID);
if (parent > 0) {
  setInterval(() => {
    try {
      process.kill(parent, 0);
    } catch {
      stop();
    }
  }, 1000).unref();
}
process.stdin.resume();
