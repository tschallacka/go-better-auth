// Reads values the Go implementation produced (JSON on stdin) and reports what
// the real better-auth 1.6.14 makes of them (JSON on stdout). Used by
// compat_test to prove the other direction: Go writes, the library reads.
import { verifyPassword, symmetricDecrypt } from "better-auth/crypto";
import { createInternalContext } from "better-call";

let input = "";
for await (const chunk of process.stdin) input += chunk;
const req = JSON.parse(input);

const attempt = async (f) => {
  try {
    return { value: await f() };
  } catch (e) {
    return { error: String(e?.message ?? e) };
  }
};

const res = { passwords: [], ciphertexts: [], versioned: [], cookies: [] };
for (const p of req.passwords) {
  res.passwords.push(await attempt(() => verifyPassword({ hash: p.hash, password: p.password })));
}
for (const c of req.ciphertexts) {
  res.ciphertexts.push(await attempt(() => symmetricDecrypt({ key: c.secret, data: c.ciphertext })));
}
for (const v of req.versioned) {
  const key = {
    keys: new Map(Object.entries(v.keys).map(([k, s]) => [Number(k), s])),
    currentVersion: v.currentVersion,
    legacySecret: v.legacySecret || undefined,
  };
  res.versioned.push(await attempt(() => symmetricDecrypt({ key, data: v.ciphertext })));
}
for (const c of req.cookies) {
  const ctx = await createInternalContext({ headers: new Headers({ cookie: c.cookie }) }, { options: { method: "GET" }, path: "/x" });
  res.cookies.push(await attempt(() => ctx.getSignedCookie(c.name, c.secret, c.prefix || undefined)));
}
process.stdout.write(JSON.stringify(res));
