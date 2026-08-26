# TOTP Recovery Kit

Vendor-neutral RFC 6238 TOTP, canonical Base32, replay-step verification, identity-bound AES-256-GCM secret envelopes, and Argon2id recovery codes for TypeScript and Bun.

I built this package for first-party authentication systems that need explicit custody boundaries instead of storing plaintext TOTP secrets or treating a valid six-digit code as replay-safe by itself.

## Capabilities

- canonical unpadded Base32 encoding/decoding;
- RFC 6238 SHA-1 TOTP with 6–8 digits;
- bounded 15–120 second periods and verification windows;
- constant-time code comparison;
- accepted-step output for replay prevention;
- AES-256-GCM TOTP secret envelopes;
- authenticated binding to subject ID, factor ID, and key version;
- versioned keyring lookup;
- ten unique 20-symbol human-readable recovery codes;
- normalization without ambiguous characters;
- Argon2id hashing and verification;
- no plaintext recovery-code storage contract.

## TOTP

```ts
import {
  decodeTotpSecret,
  generateTotpCode,
  verifyTotpCode,
} from "@frankfmy/totp-recovery-kit";

const secret = decodeTotpSecret(manualKey);
const now = new Date();
const code = generateTotpCode({ now, secret });
const accepted = verifyTotpCode({
  code,
  now,
  secret,
  lastAcceptedStep: storedLastAcceptedStep,
  window: 1,
});

if (!accepted) throw new Error("invalid or replayed code");
```

Persist `accepted.step` atomically with the protected action or proof issuance. The library returns replay authority; it cannot make an in-memory check durable.

## Secret envelope

```ts
import {
  decryptTotpSecret,
  encryptTotpSecret,
} from "@frankfmy/totp-recovery-kit";

const keyring = new Map([
  ["v1", encryptionKeyBytes],
]);

const envelope = encryptTotpSecret({
  subjectId: accountId,
  factorId,
  keyVersion: "v1",
  keyring,
  secret,
});

const plaintext = decryptTotpSecret({
  subjectId: accountId,
  factorId,
  keyring,
  envelope,
});
```

The authenticated-data namespace is `totp-recovery-kit.v1`. Changing that namespace, subject identity, factor identity, or key version makes existing envelopes undecryptable by design.

## Recovery codes

```ts
import {
  generateRecoveryCodes,
  hashRecoveryCode,
  verifyRecoveryCode,
} from "@frankfmy/totp-recovery-kit";

const codes = generateRecoveryCodes();
const hashes = await Promise.all(codes.map(hashRecoveryCode));
const valid = await verifyRecoveryCode(submittedCode, storedHash);
```

Only hashes belong in durable storage. One-time consumption, set replacement, session binding, audit, and concurrent double-use prevention remain database-transaction responsibilities.

## Security boundary

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md). This is cryptographic custody plumbing, not a complete authentication service.

## Package status

The GitHub repository is public and the package is released on npm from immutable Git tags. Future releases use npm Trusted Publishing.

```bash
npm install @frankfmy/totp-recovery-kit
```

The first npm version is bootstrapped once from its clean exact tag with interactive account 2FA using `scripts/bootstrap-first-npm-release.sh`. After registry readback, the repository workflow is configured as the trusted publisher; no long-lived npm token is stored in GitHub.

## Development

```bash
git clone https://github.com/FrankFMY/totp-recovery-kit.git
cd totp-recovery-kit
bun install --frozen-lockfile
bun run verify
```

## Author

**Artem Prianishnikov**

- GitHub: https://github.com/FrankFMY
- Website: https://frankfmy.com
- Email: Pryanishnikovartem@gmail.com

## License

Apache-2.0 © 2026 Artem Prianishnikov. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
