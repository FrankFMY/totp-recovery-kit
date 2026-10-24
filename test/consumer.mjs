import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { encodeTotpSecret, decodeTotpSecret, generateTotpCode, verifyTotpCode, encryptTotpSecret, decryptTotpSecret, generateRecoveryCodes, hashRecoveryCode, verifyRecoveryCode } from "@frankfmy/totp-recovery-kit";
// RFC 6238 Appendix B SHA-1 vectors; public interoperability data, not a credential.
const secret = new TextEncoder().encode("12345678901234567890");
assert.equal(encodeTotpSecret(secret), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
assert.deepEqual(decodeTotpSecret(encodeTotpSecret(secret).toLowerCase()), secret);
for (const invalid of ["A", "AAA", "AAAAAA", "AB", "A="]) assert.throws(() => decodeTotpSecret(invalid));
for (const [seconds, code] of [[59,"94287082"],[1111111109,"07081804"],[1111111111,"14050471"],[1234567890,"89005924"],[2000000000,"69279037"],[20000000000,"65353130"]]) {
  const now = new Date(seconds * 1000);
  assert.equal(generateTotpCode({ secret, now, digits: 8 }), code);
  const accepted = verifyTotpCode({ secret, now, digits: 8, code, window: 0 }); assert.ok(accepted);
  assert.equal(verifyTotpCode({ secret, now, digits: 8, code, lastAcceptedStep: accepted.step, window: 0 }), null);
}
const now = new Date(120000), past = new Date(90000), pastCode = generateTotpCode({ secret, now: past });
assert.equal(verifyTotpCode({ secret, now, code: pastCode, window: 0 }), null);
assert.deepEqual(verifyTotpCode({ secret, now, code: pastCode, window: 1 }), { step: 3 });
for (const lastAcceptedStep of [NaN, -1, 1.5, Infinity]) assert.equal(verifyTotpCode({ secret, now, code: generateTotpCode({ secret, now }), lastAcceptedStep }), null);
const keyring = new Map([["v1", randomBytes(32)], ["v2", randomBytes(32)]]);
const context = { subjectId: "fixture-account", factorId: "fixture-factor", keyring };
const envelope = encryptTotpSecret({ ...context, secret, keyVersion: "v1" });
assert.deepEqual(Buffer.from(decryptTotpSecret({ ...context, envelope })), Buffer.from(secret));
assert.equal(envelope.nonce.length, 12); assert.equal(envelope.encryptedSecret.length, secret.length + 16);
const another = encryptTotpSecret({ ...context, secret, keyVersion: "v1" }); assert.notDeepEqual(envelope.nonce, another.nonce);
for (const delta of [{ subjectId: "other" }, { factorId: "other" }, { keyring: new Map() }]) assert.throws(() => decryptTotpSecret({ ...context, ...delta, envelope }), /cannot be decrypted/);
for (const key of ["nonce", "encryptedSecret"]) {
  const bytes = Uint8Array.from(envelope[key]); bytes[0] ^= 1;
  assert.throws(() => decryptTotpSecret({ ...context, envelope: { ...envelope, [key]: bytes } }), /cannot be decrypted/);
}
assert.throws(() => decryptTotpSecret({ ...context, envelope: { ...envelope, keyVersion: "v2" } }), /cannot be decrypted/);
const rotated = encryptTotpSecret({ ...context, secret: decryptTotpSecret({ ...context, envelope }), keyVersion: "v2" });
const retired = new Map([["v2", keyring.get("v2")]]);
assert.deepEqual(Buffer.from(decryptTotpSecret({ ...context, keyring: retired, envelope: rotated })), Buffer.from(secret));
assert.throws(() => decryptTotpSecret({ ...context, keyring: retired, envelope }), /cannot be decrypted/);
const codes = generateRecoveryCodes(); assert.equal(codes.length, 10); assert.equal(new Set(codes).size, 10);
for (const code of codes) assert.match(code, /^[A-HJ-NP-Z2-9]{5}(?:-[A-HJ-NP-Z2-9]{5}){3}$/);
const hash = await hashRecoveryCode(codes[0]); assert.match(hash, /^\$argon2id\$/);
assert.ok(await verifyRecoveryCode(codes[0].toLowerCase().replaceAll("-", " "), hash));
assert.equal(await verifyRecoveryCode(codes[1], hash), false); assert.equal(await verifyRecoveryCode("invalid", hash), false); assert.equal(await verifyRecoveryCode(codes[0], "invalid-hash"), false);
const bcrypt = await Bun.password.hash(codes[0].replaceAll("-", ""), { algorithm: "bcrypt", cost: 4 }); assert.equal(await verifyRecoveryCode(codes[0], bcrypt), false);
// Replay persistence, authorization, atomic one-time consumption and key retirement are caller responsibilities; no database proof is claimed here.
console.log("installed Bun RFC-vectors/replay/envelope/tamper/key-rotation/Argon2id/recovery consumer: PASS");
