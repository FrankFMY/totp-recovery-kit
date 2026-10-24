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
import { randomBytes } from "node:crypto";
import {
  generateTotpCode,
  verifyTotpCode,
} from "@frankfmy/totp-recovery-kit";

const secret = randomBytes(20); // fresh volatile demonstration secret; provision/persist separately
const now = new Date();
const code = generateTotpCode({ now, secret });
const accepted = verifyTotpCode({
  code,
  now,
  secret,
  lastAcceptedStep: null, // load the current persisted step inside your transaction
  window: 1,
});

if (!accepted) throw new Error("invalid or replayed code");
```

Persist `accepted.step` atomically with the protected action or proof issuance. The library returns replay authority; it cannot make an in-memory check durable.

## Secret envelope

```ts
import { randomBytes } from "node:crypto";
import {
  decryptTotpSecret,
  encryptTotpSecret,
} from "@frankfmy/totp-recovery-kit";

const accountId = "example-account";
const factorId = "example-factor";
const secret = randomBytes(20);
const keyring = new Map([
  ["v1", randomBytes(32)], // volatile example; production keys belong in external key custody
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
const hashes: string[] = [];
for (const code of codes) hashes.push(await hashRecoveryCode(code));
const valid = await verifyRecoveryCode(codes[0]!, hashes[0]!); // demonstration only
```

Only hashes belong in durable storage. One-time consumption, set replacement, session binding, audit, and concurrent double-use prevention remain database-transaction responsibilities.

## Security boundary

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md). This is cryptographic custody plumbing, not a complete authentication service or a claimed independent cryptographic audit. TOTP supports SHA-1 only (not the optional SHA-256/SHA-512 modes), zero epoch, 6–8 digits and 15–120 second periods; the verifier window is 0–2 steps. Noncanonical zero-extended Base32 lengths are rejected after case/whitespace/hyphen normalization. Provision unique high-entropy secrets and rate-limit attempts. Recovery hashing uses the supported Bun Argon2id implementation/default cost policy; budget memory and concurrency for hashing rather than creating an unbounded batch.

## Package status

ESM on Bun 1.4+ is the supported full runtime: recovery hashing uses `Bun.password`. Node-only/browser use of the complete API is not supported. [npm package](https://www.npmjs.com/package/@frankfmy/totp-recovery-kit) · [source](https://github.com/FrankFMY/totp-recovery-kit).

```bash
npm install @frankfmy/totp-recovery-kit
```

Use the registry command when the desired version is public. Otherwise use the source checkout below, run `bun run build && npm pack`, and install the tarball. Packing builds the package; automatic release-triggered registry publication is not enabled.

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
- Email: Pryanishnikovartem@gmail.com · frankfmy@proton.me
- Telegram: https://t.me/FrankFMY
- LinkedIn: https://www.linkedin.com/in/frankfmy/
- X: https://x.com/FrankFMY
- npm: https://www.npmjs.com/~frankfmy

## License

Apache-2.0 © 2026 Artem Prianishnikov. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
