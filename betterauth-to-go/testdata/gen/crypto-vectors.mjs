// Records crypto test vectors from the real better-auth 1.6.14 code paths.
// Every output value is produced by the library itself; nothing is computed
// here. Secrets and passwords are fixed fake values, never real data.
//
//   npm run vectors   (writes ../fixtures/crypto-vectors.json)
import {
  hashPassword,
  verifyPassword,
  symmetricEncrypt,
  symmetricDecrypt,
  makeSignature,
  constantTimeEqual,
} from "better-auth/crypto";
import { createInternalContext, serializeSignedCookie } from "better-call";

import { readFileSync } from "node:fs";
const pkg = JSON.parse(readFileSync(new URL("./node_modules/better-auth/package.json", import.meta.url), "utf8"));

const passwords = [
  "correct horse battery staple",
  "p",
  "ünïcödé-pässwörd",
  "ｐａｓｓ", // fullwidth "pass": NFKC folds it to ASCII
  "é", // e + combining acute: NFKC composes to é
  "é", // precomposed é, same key as the line above after NFKC
  "colon:inside:password",
  "x".repeat(128),
];

const out = {
  generator: `better-auth ${pkg.version}`,
  passwordHashes: [],
  passwordChecks: [],
  symmetric: [],
  symmetricVersioned: [],
  signatures: [],
  signedCookieHeaders: [],
  signedCookieReads: [],
  constantTimeEqual: [],
};

for (const password of passwords) {
  out.passwordHashes.push({ password, hash: await hashPassword(password) });
}

const h = out.passwordHashes[0].hash;
const nfkc = out.passwordHashes.find((v) => v.password === "é").hash;
for (const [hash, password] of [
  [h, "correct horse battery staple"],
  [h, "correct horse battery stapl"],
  [h, "Correct horse battery staple"],
  [h, ""],
  [nfkc, "é"],
  [nfkc, "e"],
  [out.passwordHashes[3].hash, "pass"],
]) {
  out.passwordChecks.push({ hash, password, ok: await verifyPassword({ hash, password }) });
}

const secrets = ["fixture-secret-0123456789abcdef0123456789", "short", "ünïcödé secret"];
for (const secret of secrets) {
  for (const plaintext of ["", "JBSWY3DPEHPK3PXP", '["code-1","code-2"]', "ünïcödé"]) {
    out.symmetric.push({ secret, plaintext, ciphertext: await symmetricEncrypt({ key: secret, data: plaintext }) });
  }
}

const keys = new Map([
  [1, "fixture-secret-v1-aaaaaaaaaaaaaaaaaaaaaaaa"],
  [2, "fixture-secret-v2-bbbbbbbbbbbbbbbbbbbbbbbb"],
]);
for (const currentVersion of [1, 2]) {
  const key = { keys, currentVersion, legacySecret: secrets[0] };
  const ciphertext = await symmetricEncrypt({ key, data: "versioned-plaintext" });
  out.symmetricVersioned.push({
    keys: Object.fromEntries(keys),
    currentVersion,
    legacySecret: secrets[0],
    plaintext: "versioned-plaintext",
    ciphertext,
    decrypted: await symmetricDecrypt({ key, data: ciphertext }),
  });
}
// A bare-hex payload written before versioning is read through the legacy secret.
{
  const legacy = await symmetricEncrypt({ key: secrets[0], data: "legacy-plaintext" });
  const key = { keys, currentVersion: 2, legacySecret: secrets[0] };
  out.symmetricVersioned.push({
    keys: Object.fromEntries(keys),
    currentVersion: 2,
    legacySecret: secrets[0],
    plaintext: "legacy-plaintext",
    ciphertext: legacy,
    decrypted: await symmetricDecrypt({ key, data: legacy }),
  });
}

for (const secret of secrets) {
  for (const value of ["", "abc", "Gm3aT1kq9xYz2bLw7nPs4dRf.with-dot", "ünïcödé"]) {
    out.signatures.push({ secret, value, signature: await makeSignature(value, secret) });
  }
}

const cookieSecret = secrets[0];
for (const [name, value, opt] of [
  ["better-auth.session_token", "Gm3aT1kq9xYz2bLw7nPs4dRf", { path: "/", httpOnly: true, sameSite: "lax", maxAge: 604800 }],
  ["better-auth.session_token", "tok/with+chars=", { prefix: "secure", path: "/", httpOnly: true, secure: true, sameSite: "lax" }],
  ["__Host-x", "v", { path: "/other", domain: "example.com" }],
  ["better-auth.two_factor", "tf", { maxAge: 600, sameSite: "strict", partitioned: true }],
]) {
  out.signedCookieHeaders.push({
    name,
    value,
    secret: cookieSecret,
    options: opt,
    header: await serializeSignedCookie(name, value, cookieSecret, { ...opt }),
  });
}

const good = (await serializeSignedCookie("st", "Gm3aT1kq9xYz2bLw7nPs4dRf", cookieSecret, {})).split(";")[0].slice(3);
const raw = decodeURIComponent(good);
const sig = raw.slice(raw.lastIndexOf(".") + 1);
const cookieCases = [
  ["valid encoded", `st=${good}`],
  ["valid unencoded", `st=${raw}`],
  ["valid quoted", `st="${good}"`],
  ["valid among others", `a=1; st=${good}; b=2`],
  ["first occurrence wins", `st=${good}; st=x.${sig}`],
  ["tampered value", `st=Gm3aT1kq9xYz2bLw7nPs4dRg.${sig}`],
  ["tampered signature", `st=Gm3aT1kq9xYz2bLw7nPs4dRf.${sig.slice(0, 42)}A=`],
  ["truncated signature", `st=Gm3aT1kq9xYz2bLw7nPs4dRf.${sig.slice(0, 40)}`],
  ["signature without padding", `st=Gm3aT1kq9xYz2bLw7nPs4dRf.${sig.slice(0, 43)}`],
  ["no dot", "st=Gm3aT1kq9xYz2bLw7nPs4dRf"],
  ["leading dot only", `st=.${sig}`],
  ["empty value", "st="],
  ["missing cookie", "other=1"],
  ["wrong secret", `st=${(await serializeSignedCookie("st", "v", "other-secret", {})).split(";")[0].slice(3)}`],
  ["bad percent escape", `st=%E0%A4%A.${sig}`],
  ["non-base64 signature", `st=v.${"!".repeat(43)}=`],
];
for (const [label, cookie] of cookieCases) {
  const ctx = await createInternalContext({ headers: new Headers({ cookie }) }, { options: { method: "GET" }, path: "/x" });
  out.signedCookieReads.push({ label, cookie, name: "st", secret: cookieSecret, result: await ctx.getSignedCookie("st", cookieSecret) });
}

for (const [a, b] of [["", ""], ["a", "a"], ["a", "b"], ["abc", "ab"], ["ab", "abc"], ["ünï", "ünï"]]) {
  out.constantTimeEqual.push({ a, b, equal: constantTimeEqual(a, b) });
}

// JavaScript built-ins the wire format depends on, recorded from this runtime
// so the Go copies in internal/jsuri are checked against the real thing.
const attempt = (f) => {
  try {
    return { value: f() };
  } catch (e) {
    return { error: e.name };
  }
};
const hex = (s) => Buffer.from(s, "latin1").toString("hex");
out.builtins = {
  encodeURIComponent: ["", "abc", "a b+c/d?e=f&g", "-_.!~*'()", "ünï€😀", "%", "\u0000\u007f"].map((s) => ({
    in: s,
    out: encodeURIComponent(s),
  })),
  decodeURIComponent: [
    "", "abc", "%20", "%2b%2B", "%C3%BC", "%E2%82%AC", "%F0%9F%98%80", "%", "%2", "%zz", "%C3", "%C3%28",
    "%C0%AF", "%ED%A0%80", "%F4%90%80%80", "%80", "%E0%A4%A", "a%20b%", "100%25",
  ].map((s) => ({ in: s, ...attempt(() => decodeURIComponent(s)) })),
  atob: [
    "", "YQ==", "YQ=", "YQ", "Y", "YWJj", "YW Jj", "YW\nJj", "YR==", "YQ===", "Y===", "!!!!", "YWJj=", "YéQ=",
    "R15uTA4K9nx6VNhyAltiqmlztrez7IsXEm+ZqKqpNnc=",
  ].map((s) => {
    const r = attempt(() => atob(s));
    return r.error ? { in: s, error: r.error } : { in: s, hex: hex(r.value) };
  }),
  parseInt: ["0", "12", " 7", " 7", "﻿8", "+3", "-0", "-4", "", "x", "2abc", "1.5", "0x10", "99999999999999999999"].map(
    (s) => ({ in: s, out: Number.isNaN(parseInt(s, 10)) ? null : String(parseInt(s, 10)) }),
  ),
  trim: [" a ", "\t\n a ", "﻿a　", " a ", "​a"].map((s) => ({ in: s, out: s.trim() })),
};

process.stdout.write(JSON.stringify(out, null, 2) + "\n");
