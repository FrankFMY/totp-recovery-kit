import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const target = mkdtempSync(join(tmpdir(), "totp-recovery-kit-consumer-"));

try {
  const output = execFileSync("npm", ["pack", "--silent", "--pack-destination", target], {
    cwd: root,
    encoding: "utf8",
  }).trim();
  const tarball = join(target, output.split("\n").at(-1));
  writeFileSync(join(target, "package.json"), '{"name":"totp-recovery-kit-consumer","private":true,"type":"module"}\n');
  execFileSync("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", tarball], {
    cwd: target,
    stdio: "pipe",
  });
  writeFileSync(
    join(target, "check.mjs"),
    [
      'import { generateTotpCode, verifyTotpCode } from "@frankfmy/totp-recovery-kit";',
      'const secret = new TextEncoder().encode("12345678901234567890");',
      'const now = new Date(59_000);',
      'const code = generateTotpCode({ digits: 8, now, secret });',
      'if (code !== "94287082" || verifyTotpCode({ code, digits: 8, lastAcceptedStep: Number.NaN, now, secret }) !== null) process.exit(1);',
      'console.log("isolated TOTP package consumer: PASS");',
      "",
    ].join("\n"),
  );
  execFileSync(process.execPath, [join(target, "check.mjs")], { cwd: target, stdio: "inherit" });
} finally {
  rmSync(target, { force: true, recursive: true });
}
