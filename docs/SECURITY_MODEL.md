# Security Model

## TOTP replay

A correct code is not enough. `verifyTotpCode()` returns the accepted time step and rejects steps less than or equal to `lastAcceptedStep`. The caller must lock the factor row, verify against the current accepted step, and persist the new step in the same transaction as proof issuance or the protected mutation.

## Secret custody

TOTP secrets are encrypted with AES-256-GCM using a 12-byte random nonce and a 32-byte key selected by key version. Authenticated additional data binds:

- protocol namespace;
- subject identity;
- factor identity;
- key version.

Keys must live outside the database envelope. Key rotation should add a new version, decrypt under the recorded old version, re-encrypt under the new version, verify, and only then retire old key custody.

## Recovery code custody

Recovery codes are high-entropy one-time credentials. Display plaintext once, store only Argon2id hashes, and consume one hash transactionally. Regenerating a set should invalidate the old set atomically. Never log submitted or generated codes.

## Scope exclusions

This package does not implement:

- registration or session cookies;
- account/factor database schemas;
- authorization or fresh-auth proof lifetimes;
- rate limiting or lockout policy;
- QR-code generation;
- trusted clock synchronization;
- one-time database consumption;
- audit/event persistence;
- key-management infrastructure.

Those controls must be designed around this cryptographic core.
