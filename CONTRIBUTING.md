# Contributing

TOTP Recovery Kit is maintained by Artem Prianishnikov.

Cryptographic behavior changes require standards vectors plus RED then GREEN tests. Preserve Base32 canonicalization, timing-safe comparison, replay-step output, AAD identity binding, key-version custody, and hash-only recovery semantics. Run `bun run verify` before submitting a change.
