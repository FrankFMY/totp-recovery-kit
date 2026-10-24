import { generateTotpCode, verifyTotpCode, hashRecoveryCode, encryptTotpSecret } from "@frankfmy/totp-recovery-kit";
import type { TotpSecretEnvelope } from "@frankfmy/totp-recovery-kit";
const secret = new Uint8Array(20), now = new Date();
const code: string = generateTotpCode({ secret, now });
const accepted = verifyTotpCode({ secret, now, code });
if (accepted) { const step: number = accepted.step; void step; }
const hash: Promise<string> = hashRecoveryCode("AAAAA-AAAAA-AAAAA-AAAAA");
const envelope: TotpSecretEnvelope = encryptTotpSecret({ secret, keyring: new Map(), keyVersion: "v1", factorId: "a", subjectId: "b" });
// @ts-expect-error secrets are bytes, not Base32 strings
generateTotpCode({ secret: "SECRET", now });
// @ts-expect-error replay authority is numeric
verifyTotpCode({ secret, now, code, lastAcceptedStep: "step" });
// @ts-expect-error recovery hashes are asynchronous values
const invalid: string = hash;
void [envelope, invalid];
