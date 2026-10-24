import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const recoveryAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const defaultDigits = 6;
const defaultPeriodSeconds = 30;
const recoveryCodeCount = 10;
const recoveryCodeSymbols = 20;

export const encodeTotpSecret = (secret: Uint8Array): string => {
  if (secret.length === 0) throw new TypeError("TOTP secret is empty");
  let buffer = 0;
  let bits = 0;
  let encoded = "";
  for (const byte of secret) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      encoded += base32Alphabet[(buffer >>> bits) & 31];
    }
  }
  if (bits > 0) encoded += base32Alphabet[(buffer << (5 - bits)) & 31];
  return encoded;
};

export const decodeTotpSecret = (value: string): Uint8Array => {
  const normalized = value.replace(/[\s-]+/gu, "").toUpperCase();
  if (normalized.length === 0 || !/^[A-Z2-7]+$/u.test(normalized)) throw new TypeError("TOTP secret is invalid");
  if (![0, 2, 4, 5, 7].includes(normalized.length % 8)) throw new TypeError("TOTP secret is not canonical");
  let buffer = 0;
  let bits = 0;
  const decoded: number[] = [];
  for (const character of normalized) {
    buffer = (buffer << 5) | base32Alphabet.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      decoded.push((buffer >>> bits) & 255);
    }
  }
  if (decoded.length === 0 || (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0)) {
    throw new TypeError("TOTP secret is not canonical");
  }
  return Uint8Array.from(decoded);
};

const assertTotpParameters = (input: {
  digits: number;
  now: Date;
  periodSeconds: number;
  secret: Uint8Array;
}): void => {
  if (!Number.isInteger(input.digits) || input.digits < 6 || input.digits > 8) throw new RangeError("TOTP digits are invalid");
  if (!Number.isInteger(input.periodSeconds) || input.periodSeconds < 15 || input.periodSeconds > 120) {
    throw new RangeError("TOTP period is invalid");
  }
  if (!Number.isFinite(input.now.getTime()) || input.now.getTime() < 0) throw new RangeError("TOTP time is invalid");
  if (input.secret.length < 1 || input.secret.length > 128) throw new RangeError("TOTP secret length is invalid");
};

const totpStep = (now: Date, periodSeconds: number): number => Math.floor(now.getTime() / 1_000 / periodSeconds);

const codeForStep = (secret: Uint8Array, step: number, digits: number): string => {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const digest = createHmac("sha1", Buffer.from(secret)).update(counter).digest();
  const offset = digest[digest.length - 1]! & 15;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 10 ** digits).padStart(digits, "0");
};

export const generateTotpCode = (input: {
  digits?: number;
  now: Date;
  periodSeconds?: number;
  secret: Uint8Array;
}): string => {
  const digits = input.digits ?? defaultDigits;
  const periodSeconds = input.periodSeconds ?? defaultPeriodSeconds;
  assertTotpParameters({ digits, now: input.now, periodSeconds, secret: input.secret });
  return codeForStep(input.secret, totpStep(input.now, periodSeconds), digits);
};

export const verifyTotpCode = (input: {
  code: string;
  digits?: number;
  lastAcceptedStep?: number | null;
  now: Date;
  periodSeconds?: number;
  secret: Uint8Array;
  window?: number;
}): { step: number } | null => {
  const digits = input.digits ?? defaultDigits;
  const periodSeconds = input.periodSeconds ?? defaultPeriodSeconds;
  const window = input.window ?? 1;
  assertTotpParameters({ digits, now: input.now, periodSeconds, secret: input.secret });
  if (!new RegExp(`^[0-9]{${digits}}$`, "u").test(input.code) || !Number.isInteger(window) || window < 0 || window > 2) return null;
  if (
    input.lastAcceptedStep !== undefined &&
    input.lastAcceptedStep !== null &&
    (!Number.isSafeInteger(input.lastAcceptedStep) || input.lastAcceptedStep < 0)
  ) {
    return null;
  }

  const currentStep = totpStep(input.now, periodSeconds);
  const deltas = [0, ...Array.from({ length: window }, (_, index) => [-(index + 1), index + 1]).flat()];
  for (const delta of deltas) {
    const step = currentStep + delta;
    if (step < 0 || (input.lastAcceptedStep !== undefined && input.lastAcceptedStep !== null && step <= input.lastAcceptedStep)) continue;
    const expected = Buffer.from(codeForStep(input.secret, step, digits));
    const actual = Buffer.from(input.code);
    if (expected.length === actual.length && timingSafeEqual(expected, actual)) return { step };
  }
  return null;
};

export interface TotpSecretEnvelope {
  encryptedSecret: Uint8Array;
  keyVersion: string;
  nonce: Uint8Array;
}

export type TotpKeyring = ReadonlyMap<string, Uint8Array>;

const isOpaqueIdentity = (value: string): boolean =>
  value.length >= 1 && value.length <= 200 && value === value.trim() && ![...value].some((character) => {
    const code = character.codePointAt(0);
    return code !== undefined && (code <= 0x1f || code === 0x7f);
  });

const requireIdentity = (value: string, label: string): string => {
  if (!isOpaqueIdentity(value)) throw new Error(`${label} is invalid`);
  return value;
};

const requireKey = (keyring: TotpKeyring, keyVersion: string): Buffer => {
  requireIdentity(keyVersion, "keyVersion");
  const key = keyring.get(keyVersion);
  if (!key || key.length !== 32) throw new Error("TOTP envelope key is unavailable");
  return Buffer.from(key);
};

const envelopeAad = (subjectId: string, factorId: string, keyVersion: string): Buffer =>
  Buffer.from(JSON.stringify(["totp-recovery-kit.v1", subjectId, factorId, keyVersion]), "utf8");

export const encryptTotpSecret = (input: {
  factorId: string;
  keyVersion: string;
  keyring: TotpKeyring;
  secret: Uint8Array;
  subjectId: string;
}): TotpSecretEnvelope => {
  if (input.secret.length < 16 || input.secret.length > 64) throw new RangeError("TOTP secret length is invalid");
  const subjectId = requireIdentity(input.subjectId, "subjectId");
  const factorId = requireIdentity(input.factorId, "factorId");
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", requireKey(input.keyring, input.keyVersion), nonce);
  cipher.setAAD(envelopeAad(subjectId, factorId, input.keyVersion));
  const encrypted = Buffer.concat([cipher.update(Buffer.from(input.secret)), cipher.final(), cipher.getAuthTag()]);
  return { encryptedSecret: encrypted, keyVersion: input.keyVersion, nonce };
};

export const decryptTotpSecret = (input: {
  envelope: TotpSecretEnvelope;
  factorId: string;
  keyring: TotpKeyring;
  subjectId: string;
}): Uint8Array => {
  try {
    if (input.envelope.nonce.length !== 12 || input.envelope.encryptedSecret.length <= 16) throw new Error("invalid envelope");
    const subjectId = requireIdentity(input.subjectId, "subjectId");
    const factorId = requireIdentity(input.factorId, "factorId");
    const key = requireKey(input.keyring, input.envelope.keyVersion);
    const encrypted = Buffer.from(input.envelope.encryptedSecret);
    const ciphertext = encrypted.subarray(0, -16);
    const authTag = encrypted.subarray(-16);
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(input.envelope.nonce));
    decipher.setAAD(envelopeAad(subjectId, factorId, input.envelope.keyVersion));
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error("TOTP secret cannot be decrypted");
  }
};

const normalizeRecoveryCode = (value: string): string => value.replace(/[\s-]+/gu, "").toUpperCase();

const requireRecoveryCode = (value: string): string => {
  const normalized = normalizeRecoveryCode(value);
  if (normalized.length !== recoveryCodeSymbols || [...normalized].some((character) => !recoveryAlphabet.includes(character))) {
    throw new TypeError("Recovery code is invalid");
  }
  return normalized;
};

const formatRecoveryCode = (value: string): string => value.match(/.{5}/gu)!.join("-");

export const generateRecoveryCodes = (): string[] => {
  const codes = new Set<string>();
  while (codes.size < recoveryCodeCount) {
    const bytes = randomBytes(recoveryCodeSymbols);
    let code = "";
    for (const byte of bytes) code += recoveryAlphabet[byte & 31];
    codes.add(formatRecoveryCode(code));
  }
  return [...codes];
};

export const hashRecoveryCode = (code: string): Promise<string> =>
  Bun.password.hash(requireRecoveryCode(code), { algorithm: "argon2id" });

export const verifyRecoveryCode = async (code: string, hash: string): Promise<boolean> => {
  try {
    return await Bun.password.verify(requireRecoveryCode(code), hash, "argon2id");
  } catch {
    return false;
  }
};
