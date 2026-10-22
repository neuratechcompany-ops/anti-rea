# Changelog

Значимые изменения документируются здесь. Проект следует Semantic Versioning,
насколько это возможно до выпуска 1.0.

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

[0.34.0]: https://github.com/neuratechcompany-ops/anti-rea/releases/tag/v0.34.0
