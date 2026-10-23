# Changelog

Значимые изменения документируются здесь. Проект следует Semantic Versioning,
насколько это возможно до выпуска 1.0.

## [0.34.1] - 2026-10-23

### Security

- CAS publication re-hashes the copied staging payload before promotion. A file
  replaced after the initial inventory can no longer be published under the
  original signed digest.
- Idempotent publication verifies the stored object before returning success;
  missing, corrupted, and symlinked payloads fail closed.
- CAS receipts strictly validate product/channel, object path, hashes,
  publication time, and predecessor. Release verification enforces the same
  immediate-predecessor and validity-window constraints as the signer.
- Gitleaks now loads its built-in detection rules. Previously the custom
  allowlist-only config replaced the default rules and could report a clean scan
  without detecting credentials. Exemptions now require an exact fixture value
  and a named file; CI proves detection with synthetic positive controls.
- CI pins action commits and the scanner archive checksum, scans complete Git
  history, and disables inline secret-scan suppression.
- Live time clients run asynchronously under a hard deadline and a combined
  stdout/stderr limit. Timeout and overflow terminate the ordinary POSIX process
  group and close pipes; a SIGTERM-resistant client or a descendant holding a
  pipe cannot keep the verifier waiting. Client stderr and malformed JSON
  response snippets are not included in errors.
- The regression suite grows from 189 to 209 passing tests.
- Pin the transitive `@vercel/cli-config` dependency on Zod to 4.6.6, replacing
  its upstream 4.1.11 pin affected by
  [GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5).

Existing release v13 and CAS receipt v2 formats remain unchanged. Previously
accepted malformed receipts are intentionally rejected. Protected storage and
isolated signing services remain required for production trust boundaries.

## [0.34.0] - 2026-10-23

### Added

- live-challenged external time authority для assessment, provenance, release и
  CAS publication;
- release attestation v13 с request/response/consumption bindings;
- CAS publisher receipt v2 с полным live-time provenance;
- deterministic installed dependency closure, связанный с owner policy;
- 189 automated security and regression tests.

### Security

- production signing отклоняет заранее выпущенные файловые time proofs;
- cached authority response не проходит свежий verifier-generated nonce;
- release signing повторно проверяет фактически установленный protector tree.

[0.34.1]: https://github.com/neuratechcompany-ops/anti-rea/releases/tag/v0.34.1
[0.34.0]: https://github.com/neuratechcompany-ops/anti-rea/releases/tag/v0.34.0
