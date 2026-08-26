import { describe, expect, test } from "bun:test";
import {
  decodeTotpSecret,
  decryptTotpSecret,
  encodeTotpSecret,
  encryptTotpSecret,
  generateRecoveryCodes,
  generateTotpCode,
  hashRecoveryCode,
  verifyRecoveryCode,
  verifyTotpCode,
} from "../src/index.js";

describe("TOTP and recovery custody", () => {
  test("matches the RFC 6238 SHA-1 vector and rejects replayed steps", () => {
    const secret = new TextEncoder().encode("12345678901234567890");
    const encoded = encodeTotpSecret(secret);
    expect(encoded).toBe("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    expect([...decodeTotpSecret(encoded)]).toEqual([...secret]);

    const now = new Date(59_000);
    expect(generateTotpCode({ digits: 8, now, secret })).toBe("94287082");
    const code = generateTotpCode({ now, secret });
    const accepted = verifyTotpCode({ code, now, secret, window: 1 });
    expect(accepted).toEqual({ step: 1 });
    expect(verifyTotpCode({ code, lastAcceptedStep: accepted?.step, now, secret, window: 1 })).toBeNull();
  });

  test("rejects non-canonical Base32 and invalid protocol parameters", () => {
    expect(() => decodeTotpSecret("A")).toThrow("canonical");
    expect(() => generateTotpCode({ digits: 5, now: new Date(0), secret: new Uint8Array(20) })).toThrow("digits");
    expect(() => generateTotpCode({ now: new Date(Number.NaN), secret: new Uint8Array(20) })).toThrow("time");
    expect(verifyTotpCode({ code: "123456", now: new Date(0), secret: new Uint8Array(20), window: 3 })).toBeNull();
  });

  test("round-trips a TOTP secret only under exact identity-bound AES-GCM AAD", () => {
    const keyring = new Map([["v1", Uint8Array.from({ length: 32 }, (_, index) => index + 1)]]);
    const secret = new TextEncoder().encode("twenty-byte-secret!!");
    const envelope = encryptTotpSecret({ factorId: "factor-a", keyVersion: "v1", keyring, secret, subjectId: "subject-a" });
    expect(envelope.nonce).toHaveLength(12);
    expect(envelope.encryptedSecret).toHaveLength(secret.length + 16);
    expect(Buffer.from(envelope.encryptedSecret).includes(Buffer.from(secret))).toBe(false);
    expect([...decryptTotpSecret({ envelope, factorId: "factor-a", keyring, subjectId: "subject-a" })]).toEqual([...secret]);
    expect(() => decryptTotpSecret({ envelope, factorId: "factor-b", keyring, subjectId: "subject-a" })).toThrow("cannot be decrypted");
    expect(() => decryptTotpSecret({ envelope, factorId: "factor-a", keyring, subjectId: "subject-b" })).toThrow("cannot be decrypted");
  });

  test("generates unique human-readable codes and verifies only Argon2id hashes", async () => {
    const codes = generateRecoveryCodes();
    expect(codes).toHaveLength(10);
    expect(new Set(codes).size).toBe(10);
    for (const code of codes) expect(code).toMatch(/^[A-HJ-NP-Z2-9]{5}(?:-[A-HJ-NP-Z2-9]{5}){3}$/u);

    const hash = await hashRecoveryCode(codes[0]!);
    expect(hash).toStartWith("$argon2id$");
    expect(hash).not.toContain(codes[0]!);
    expect(await verifyRecoveryCode(codes[0]!.toLowerCase().replaceAll("-", " "), hash)).toBe(true);
    expect(await verifyRecoveryCode(codes[1]!, hash)).toBe(false);
    expect(await verifyRecoveryCode("not-a-valid-code", hash)).toBe(false);
  });
});
