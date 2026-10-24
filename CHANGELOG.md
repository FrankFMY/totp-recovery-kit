# Changelog

## 0.1.1

- Reject zero-extended noncanonical Base32 lengths.
- Build automatically before packing and qualify the full installed Bun API: RFC SHA-1 vectors, replay, identity-bound envelopes, tamper rejection, key rotation, recovery codes and Argon2id-only verification.
- Add positive/negative installed TypeScript checks and precise runtime/security/lifecycle/package/contact documentation.

## 0.1.0 — 2026-08-26

- Added canonical Base32 and RFC 6238 SHA-1 TOTP generation/verification.
- Added fail-closed replay-step authority validation.
- Added identity- and key-version-bound AES-256-GCM secret envelopes.
- Added Argon2id recovery-code hashing and verification.
- Added clean package consumer, security, and registry release gates.
