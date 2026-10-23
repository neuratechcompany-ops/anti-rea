# Независимая критика Anti-REA 0.9.0 и remediation 0.10–0.11

Дата: 2026-10-22. Проверяли два независимых reviewer-профиля:

- adversarial REA critic — искал способы получить ложнозелёный результат,
  восстановить смысл и использовать сам Anti-REA как oracle;
- security architecture critic — проверял trust bootstrap, ключевые роли,
  provenance, evidence, release chain и внешние границы.

Оба reviewer работали только с локальным собственным repository и fixtures,
файлы не меняли. Контрольный прогон: `npm test`, 80/80 PASS.

## 1. Подтверждённые улучшения 0.9.0

- ChaCha20-Poly1305 и AAD закрывают одиночный bit-flip ciphertext до JSON/VM.
- Owner-signed policy фиксирует известные facts, thresholds, analyzer и worker IDs.
- Worker attestation связывает exact report с exact artifact и freshness window.
- Canary substitution и ложный score при буквальном canary в raw output
  блокируются.
- Analyzer больше не наследует build key и signer environment.
- Manifest signature проверяется внутри release attestation.
- Non-genesis release требует immediate predecessor.

Эти пункты подтверждают только указанные инварианты. Они не превращают
контролируемый клиент в доверенную среду и не доказывают честность CI/KMS.

## 2. Консенсус P0

| ID | Пробел | Почему это победа | Минимальный критерий закрытия |
|---|---|---|---|
| C-P0-01 | Нет product-source causal provenance | artifact может происходить из другого commit/repository, пока clean только protector tree | подписанная цепь product commit/tree → build definition/dependencies/builder → virtualization input → release artifact |
| C-P0-02 | Trust roots задаёт CLI caller | один build principal может выбрать свои public keys и собрать самоподписанную зелёную фабрику | pinned trust bundle вне workspace; build job не выбирает roots и не вызывает все signer roles |
| C-P0-03 | Release не сверяет signed policy product с release product | gate product A можно повторно использовать в namespace product B | `gate.core.protectionPolicy.product === options.product` во всех create/verify paths и negative test |
| C-P0-04 | Functional/performance/platform evidence — непустые файлы | строка `passed` заменяет реальный тест | typed, worker-signed attestations с artifact, suite, runner, raw result и budget |
| C-P0-05 | Server evidence недостаточно production-like и может устареть | декларативный receipt без config/transcript/challenge либо старый PASS попадает в свежий release | product/channel/action, deployment/config и transcript digests, one-time challenge; freshness повторно проверяется release signer |
| C-P0-06 | Signed worker report не доказывает trusted execution | approved PEM может подписать файл, созданный вне runner | workload identity, image digest, run challenge и KMS policy, доступная только attested workload |

## 3. Уникальные P0 adversarial critic

| ID | Пробел | Evidence | Closure test |
|---|---|---|---|
| A-P0-01 | Runtime hook только импортирует модуль; lazy/export-only function не исполняется | `scripts/probe-vm-runtime.mjs:62-80` | отсутствие invocation одного protected function ID делает report `inconclusive`, не `not-recovered` |
| A-P0-02 | Public probe принимает хотя бы один recognizable envelope, но не доказывает полный coverage | `attacks/webcrack/probe.mjs:61-83`, `scripts/validate-assessment.mjs:189-205` | recovered/recognized IDs сравниваются со всем signed stage inventory |
| A-P0-03 | Semantic recovery без literal canary остаётся ручным score | `scripts/validate-assessment.mjs:102-116,365-374` | typed findings полностью пересчитывают score; автор assessment не выбирает число |
| A-P0-04 | `embedded` — default, но owner policy не фиксирует backend/key mode/profile | `scripts/harden-js.sh:18,53-69`, `scripts/protection-policy.mjs:34-70` | external/T1 policy всегда отвергает embedded/default/fallback artifact |

## 4. Уникальные P1 architecture critic

- Release chain допускает две подписанные ветки от одного predecessor; нужен
  transactional channel head или transparency log.
- Protector/dependency identity не охватывает все фактически исполняемые
  transitive files; нужен resolved SBOM/image digest и hermetic environment.
- Mutable filesystem между inventory и publish оставляет TOCTOU; publisher
  должен читать проверенный immutable CAS object вместе с platform metadata.
- Server receipt должен доказывать execution, а не только подписывать удобное
  описание двух scenario.

## 5. Уникальные P1 adversarial critic

- Mandatory policy поддерживает только два attack probe type; chosen-input и
  cross-build alignment пока нельзя precommit как first-class evidence.
- Runtime observer видит только `TextDecoder` и `JSON.parse`; cache, key slot,
  Buffer/atob, function I/O, worker realms, IPC/CDP остаются вне coverage.
- Полный валидный AEAD tuple вместе с его AAD требует transplant regression.
- Caller-controlled `--now` допустим для тестов, но не для production validator.
- Delivery graph не включает CDN/update/cache/crash/support surfaces.
- До 512 MiB raw analyzer output и общий `JSON.parse` увеличивают DoS и
  prompt-injection surface; нужны малый cap, typed schema, depth limit и escaping.

## 6. LLM tripwire: совместный вывод

Tripwire может быть только delay/telemetry. Адаптивный extractor удалит comments,
non-executable strings или entire files, нормализует Unicode/whitespace и подаст
материал модели как quoted untrusted data. Стабильный шаблон способен стать
fingerprint и locator Anti-REA.

Безопасные требования:

- только synthetic random canary, никаких секретов, PII, credentials и URLs;
- только non-executable allowlisted namespace, отсутствие imports/runtime reads;
- exact framework template, signed inventory и release-manifest binding;
- удаление tripwire не меняет core security score и не ломает приложение;
- собственный agent harness получает payload как данные и не имеет tools,
  signer keys или cloud credentials;
- exact/split/Unicode/whitespace/paraphrased fixtures проверяют strip, locator и
  self-poisoning; ожидаемый bypass не выдаётся за нарушение криптографии;
- telemetry считается сигналом только с artifact ID, nonce и authenticated
  collector receipt, но не доказательством личности анализирующего.

## 7. Решение reviewer-ов

0.9.0 уже является сильным fail-closed framework для измеряемого T0/T1 cost
hardening известных client facts. Он пока не является автономным release
authority против partially hostile CI: отсутствуют external trust bootstrap,
product causal provenance, typed regression attestations, complete attack
coverage и реальные publisher/server/KMS boundaries.

Полная карта, сценарии и regression backlog находятся в
`references/rea-breakout-map.md`.

## 8. Post-review remediation 0.10.0

- `release-attestation` теперь отклоняет gate, если signed
  `protectionPolicy.product` не совпадает с release product.
- Release create/verify повторно проверяют freshness и validity window signed
  server authorization evidence.
- Добавлены отрицательные cross-product и stale-server tests.
- Добавлен exact-template `llm-tripwire` generator/verifier с synthetic markers,
  non-executable inventory и неизменным `securityScoreContribution: 0`.

Эти изменения закрывают C-P0-03 и узкий stale-evidence участок C-P0-05. Полный
production transcript/challenge ledger из C-P0-05 остаётся открытым.

## 9. Post-review remediation 0.11.0

- Protection policy v2 precommits functional/performance/platform-security
  suite, runner executable и environment digests.
- Assessment input v3 принимает только typed regression reports и свежие
  approved-worker attestations, связанные с exact artifact и raw result.
- Performance budget проверяется машинно; handwritten `passed`, изменённый raw
  result и несовпадающий suite/runner/environment дают hard fail.

Это закрывает C-P0-04 на уровне формата и validator. Реальная изоляция worker key
от build principal остаётся KMS/IAM deployment requirement из C-P0-02/C-P0-06.

## 10. Post-review remediation 0.12.0

- Product builder подписывает repository URI, commit/tree, tracked build
  definition, builder/environment identity и точный virtualization input.
- Provenance v4 и release attestation v6 повторно проверяют эту цепочку против
  owner-signed policy; build-attestation передаётся явным trusted input, а не
  читается по пути из provenance.
- Agent-refusal bundle теперь содержит пять разных exact-template векторов:
  authorization, data egress, untrusted content, human review и proprietary
  code. Release signer проверяет его внутри артефакта и связывает manifest SHA.
- Tripwire остаётся deception-only с нулевым security score; его удаление или
  игнорирование не считается нарушением криптографической гарантии.

Это закрывает G5/G8 на уровне формата и локального validator-а и существенно
сужает H4. Реальная изоляция builder key, pinned trust bundle, immutable CAS и
self-poisoning/locator eval остаются внешними или открытыми задачами.

## 11. Post-review remediation 0.13.0

- Protection policy v3 precommits exact backend/surface, virtualizer and
  transformer versions, VM key mode/encryption, profile digest and maximum
  claim tier.
- Assessment v4 includes exact virtualization/transform receipts in its
  evidence root and checks their output against the verified release artifact.
- Provenance and release attestation v7 reuse the same verifier, preventing a strict
  assessment from being paired with an embedded/default or substituted-profile
  artifact.
- Negative tests reject owner-policy T1+ with embedded mode, an embedded
  receipt under external policy, profile substitution and release downgrade.

Это закрывает A-P0-04/F6 на уровне signed policy и validators. Отдельные backend
families и protection-profile diversity против chosen-plaintext alignment
остаются P1.

## 12. Post-review remediation 0.14.0–0.15.0

- Каждый VM envelope получил stable opaque function ID; runtime/public probes
  и assessment требуют полного coverage signed receipt inventory, поэтому один
  decoy или lazy path не может дать ложный `not-recovered`.
- Пять agent-refusal файлов формализованы как honeyfiles с exact typed trigger и
  ожидаемой безопасной реакцией `stop/refuse/escalate`.
- Локальный observer детектирует только точные release-specific synthetic
  markers и выводит их hashes/vector IDs. Результат маркируется
  `telemetry-signal-only`, имеет нулевой security score и не является
  доказательством отказа модели, компрометации или личности атакующего.

Это закрывает узкие A7/lazy-coverage и operational marker-detection gaps. Strip,
locator lift, self-poisoning и эффективность на holdout agent corpus остаются
обязательными внешними evals; attacker-controlled marker replay не должен
запускать автоматические санкции.

## 13. Post-review remediation 0.16.0

- Добавлен `rea-hardening-trust-bundle/v1`: offline-root подписывает product,
  environment, validity window и SPKI/key ID для каждой operational роли.
- Один key ID нельзя использовать в нескольких ролях; неизвестные роли,
  duplicate keys, root substitution, modified inventory и expired bundle дают
  hard fail.
- Assessment, provenance и release attestation v10 больше не принимают отдельные
  caller-selected policy/worker/server/gate/builder/manifest/release PEM.
- Assessment gate связывает bundle ID/environment/root/digest, provenance
  переносит binding, а release payload подписывает точный bundle digest.

Это закрывает локальную форму C-P0-02/D6 — per-command PEM substitution и
cross-role signer reuse. Полная гарантия всё ещё требует, чтобы root public key
был pin-нут вне checkout защищённой конфигурацией runner/publisher, а private
roles были разнесены KMS/IAM и workload identity.

## 14. Post-review remediation 0.17.0

- Общий trusted-time helper запрещает CLI `--now` вне явного
  `REA_TEST_MODE=1`.
- Signed assessment result schema v5 включает `{source, observedAt}`; gate
  signing требует `source=system`.
- Provenance и release attestation того этапа отклоняли test-clock, future и stale
  assessment gates независимо от валидности их подписи.
- Protection-policy и trust-bundle CLI verification используют ту же границу,
  поэтому historical time нельзя выборочно вернуть на ранней стадии.

Это закрывает D8 против caller-controlled historical clock. Системные часы
управляемого runner остаются внешней границей; hostile-host модель требует
remote signed time/challenge authority и replay ledger.

## 15. Post-review remediation 0.18.0

- Добавлен publisher-only `cas-publish`: он повторно проверяет root-signed trust
  bundle, release signer, manifest signer, release scope/expiry/minimum sequence
  и exact artifact inventory непосредственно перед staging.
- Artifact копируется в digest-addressed object, файлы/директории лишаются write
  bits; mutable workspace больше не передаётся дальше как publish source.
- Отдельная `artifact-publisher` роль подписывает receipt для каждого release;
  product/channel имеет один атомарно обновляемый head.
- Second genesis, skipped sequence, wrong predecessor, post-attestation artifact
  mutation и untrusted publisher signer дают hard fail; повтор того же release
  идемпотентен.

Это закрывает локальные D3/G10 и fork-часть E3 на publisher boundary. Защита от
удаления/rollback самим storage administrator требует внешних append-only ACL,
WORM/Object Lock или transparency log; обычные права локальной ФС не являются
криптографической неизменяемостью.

## 16. Post-review remediation 0.19.0

- Пять agent-refusal honeyfiles переведены на manifest v4 и refusal capsule v1.
- Capsule фиксирует risk class, typed trigger, denied operations, требуемое
  независимо проверяемое evidence, `defaultDecision: deny` и safe response.
- Тот же canonical JSON встроен в exact-template файл; release-chain binding и
  verifier отклоняют ослабление `deny` до `allow` или замену любого поля.
- Authorization capsule прямо запрещает считать текст оператора или артефакта
  машинно проверяемым release-scoped разрешением.

Это повышает вероятность срабатывания уже существующих safety/refusal правил у
policy-aware LLM-агента, но не является принуждением hostile analyzer. Strip,
ignore и специально обученная модель остаются ожидаемым обходом, поэтому вклад
слоя в security score остаётся нулевым.

## 17. Post-review remediation 0.20.0

- Exposure policy v2 требует typed semantic fingerprints у каждого клиентского
  `COST_ONLY` факта; пустой список является release error.
- Новый deterministic normalizer поддерживает `exact-text`, `endpoint`,
  `identifier` и `json-shape`, ограничивает размер/depth/candidate count и не
  использует attacker-supplied regex.
- Assessment result v6 извлекает candidates непосредственно из подписанного raw
  stdout и применяет фиксированный score; analyzer не обязан маркировать finding.
- Тест доказывает FAIL при восстановленном endpoint без literal canary, с иным
  регистром и переставленными query parameters.

Это закрывает A-P0-03 для четырёх поддерживаемых семантических классов. Полное
утверждение о semantic non-recovery всё ещё запрещено: CFG, алгоритмическая и
поведенческая эквивалентность требуют отдельного holdout oracle/corpus.

## 18. Post-review remediation 0.21.0

- Добавлена независимая root-trusted роль `evidence-coordinator`.
- Coordinator challenge v1 ограничен 15 минутами и связывает product, exact
  signed policy, artifact, evidence-worker key, runner/image и workload identity.
- Evidence attestation v2 подписывает report вместе с challenge binding и не
  может жить дольше challenge.
- Assessment проверяет обе подписи, freshness/scope, запрещает повтор одного
  challenge в bundle и включает challenge digest в evidence Merkle-like root.
- Негативные тесты отклоняют modified challenge и replay между двумя валидно
  подписанными probes.

Это переводит D7 из одного self-asserted worker statement в двухрольный
challenge-response protocol. Для hostile CI всё ещё обязательны KMS policy,
которая разрешает worker signing только attested workload, и внешний глобальный
replay ledger; локальный формат не может доказать аппаратную identity сам по себе.

## 19. Post-review remediation 0.22.0

- Challenge теперь содержит owner-visible `evaluationId`, совпадающий с
  assessment input schema v5.
- Gate атомарно создаёт immutable consumption record по challenge ID в общем
  persistent ledger до выдачи результата.
- Второй assessment-процесс с тем же challenge отклоняется; отдельные негативные
  тесты проверяют unit-level exclusive create и end-to-end cross-process replay.
- Consumption records и их SHA-256 входят в evidence root и подписанный result
  schema v7. Ошибка после consumption намеренно требует выпуска новых challenges.

Это закрывает локальный coordinator-side replay gap из D7. Не закрыты KMS
workload enforcement и удаление/rollback ledger hostile storage administrator-ом;
для production требуются отдельный principal, append-only/Object Lock storage,
retention и audit.

## 20. Post-review remediation 0.23.0

- Protection policy v4 owner-precommits product environment, release channel,
  privileged action and deployment/config/transcript-schema digests.
- Server authorization v2 binds the exact raw request/response transcript,
  artifact and one-time coordinator challenge; the gate consumes that challenge
  through the same atomic replay ledger.
- A dedicated signer refuses transcript scope outside owner policy and resolves
  all operational identities from the offline-root trust bundle.
- Release create/verify rechecks product/channel and all owner-precommitted
  server scope fields.
- Negative tests cover a trusted server signer substituting a harmless action,
  rewritten raw transcript and an unapproved release channel.

The local self-declared server-receipt gap is closed. Production deployment
truth, KMS workload enforcement and append-only replay storage remain external
trust boundaries.

## 21. Post-review remediation 0.24.0

- Added bounded `js-structure` fingerprints over Acorn AST structure. Identifier
  and literal rewriting no longer evades recovery scoring when control/operator
  structure remains.
- Added canonical `behavior-vector` fingerprints for up to 256 private holdout
  input/output hashes; order changes do not evade matching and policy reveals no
  plaintext cases.
- Both signals are extracted from worker-signed raw output and force score 4,
  independent of analyzer labels or handwritten assessment scores.
- End-to-end tests recover renamed/re-literalized logic and reordered equivalent
  holdout results through the actual assessment gate.

This is not arbitrary program-equivalence proof. Native/WASM, cross-language
rewrites and a live isolated secret oracle remain future attack coverage.

## 22. Post-review remediation 0.25.0

- Added mandatory `anti-rea-behavior-holdout` adversarial probe.
- The probe executes owner reference and recovered candidate over the complete
  private JSON corpus and emits only canonical input/output hashes.
- Gate validates owner-precommitted reference behavior, exact executable and
  release identities, full coverage, worker attestation and one-time challenge.
- Timeout, crash, malformed output, output overflow, incomplete cases and
  executable/artifact TOCTOU are invalid evidence.

The repository cannot itself guarantee OS/network isolation; production must
run this probe in a network-denied, filesystem-restricted workload identity.

## 23. Post-review remediation 0.26.0

- Protection policy v6 requires an explicit owner-signed disposition for all
  five delivery classes: release, update, crash, support and symbols.
- A new delivery-graph verifier walks each present unpacked staging tree,
  rejects source/debug leakage to customers, credential material, symlinks,
  special entries and opaque nested archives, and inspects gzip/Brotli content.
- Assessment input v6 rejects omitted/added/aliased surfaces, re-opens every
  tree, recomputes its identity and requires the release surface to equal the
  verified artifact root.
- Signed assessment result v8 and its evidence root bind the complete graph;
  provenance and release signing refuse older gate schemas or a missing graph.
- Negative tests cover omitted update delivery, post-report mutation, compressed
  hidden leakage and two differently named channels resolving to one tree.

This closes the local static delivery-inventory gap. CDN caches, remote update
buckets, crash SaaS retention, support portals and access-control truth remain
external systems and require connector/API evidence plus production ACLs.

## 24. Post-review remediation 0.27.0

- Added bounded `wasm-structure` fingerprints over balanced WAT with nested
  comment handling. Names, numbers and strings are removed while module,
  control and opcode structure remains.
- Added bounded `native-cfg` fingerprints over validated function graphs.
  Addresses, register names, immediate values, block IDs and serialization order
  do not affect the result; instruction/operand classes and topology do.
- Both signal types are owner-precommitted, discovered from worker-signed raw
  analyzer output by the gate, and force recovery score 4.
- End-to-end assessment tests reject recovered WASM/native logic after the
  exact cosmetic rewrites those formats commonly introduce.
- Unknown successors, partial/malformed graphs, unbalanced WAT and size/depth
  overflows are invalid candidates rather than non-recovery evidence.

This closes bounded same-language WAT/native structural renaming. It does not
prove arbitrary equivalence, cross-language lifting, or correctness of a
hostile disassembler; those remain holdout/runtime and worker-isolation duties.

## 25. Post-review remediation 0.28.0

- Added mandatory `anti-rea-cross-build-alignment` at T1 for every comparison.
- It requires 20–64 unique independently produced protected-function regions,
  hashes bounded high-entropy windows and measures 80%-support stability plus
  maximum pairwise Jaccard similarity.
- Stable target ratio above 10% or pairwise similarity above 25% is recovery;
  duplicate paths/bytes, undersized/oversized regions and mutation are invalid.
- Gate re-runs the analysis from current bytes, refuses threshold weakening and
  binds the report to the approved worker and one-time challenge.
- Reports expose hashes and ratios, not recovered plaintext windows.
- Every variant also carries a root-trusted `product-builder` signature binding
  policy, source, build definition/environment, unique run/seed, ordinal and
  exact region digest; unrelated random files cannot form a passing corpus.

This closes a concrete byte-alignment path across randomized builds. A generic
semantic/cross-language lifter may still align transformed IR when bytes differ,
so the behavior/WAT/CFG holdouts remain mandatory and IR alignment remains P1.

## 26. Post-review remediation 0.29.0

- Expanded the T2 Node runtime attack from only `TextDecoder`/`JSON.parse` to
  eleven plaintext-relevant boundaries: base64, Buffer conversion, decipher
  output, file/cache reads, MessagePort IPC, JSON, fetch/Response, process
  output, structured clone, TextDecoder and WebAssembly input.
- Runtime report schema v2 records installation, calls and captured-observation
  counts for every boundary without writing plaintext into evidence.
- Gate requires every observer installed plus actual JSON/TextDecoder execution
  and complete protected-function coverage; omitted hooks cannot pass silently.
- The observer corpus is bounded by value, count and total bytes. Flooding it
  produces invalid evidence rather than a false non-recovery.
- A regression fixture routes independent canaries through buffer, file,
  crypto, data-URL network response, clone, IPC, base64 and output boundaries,
  and separately exercises WebAssembly input.

This materially closes the original Node plaintext-boundary P1. Browser CDP,
Frida/LLDB, V8 internals and native-memory/register observation remain explicit
platform-specific residual work rather than being overclaimed as covered.

## 27. Post-review remediation 0.30.0

- Added mandatory `anti-rea-cross-build-semantic` at T1 for every comparison,
  using the same 20–64 causally builder-attested protected regions as the byte
  alignment attack.
- The owner policy pins a dedicated `semantic-ir` adapter and executable. The
  adapter may pass only the artifact path to that exact executable, preventing
  an unpinned wrapper/helper from silently defining the result.
- Added a bounded language-neutral IR for control and data flow. Sixteen rounds
  of graph refinement remove node IDs and inventory order while retaining
  operation/value classes, typed control edges and data-input positions.
- Unreachable nodes, duplicate edges, missing exits, oversized graphs and more
  than 20% opaque operations are invalid, not evidence of diversification.
- Exact target fingerprint support in at least 80% of variants or pairwise
  feature Jaccard above 70% is recovery. The gate verifies tool/builder identity
  and reruns all extraction jobs before accepting the signed worker result.
- Tests show renamed/reordered equivalent IR is recovered, structurally diverse
  IR is not, different bytes with one lifted semantic graph fail the claim, and
  omitted attacks or modified extractors are rejected.

This closes the prior bounded semantic/cross-language chosen-plaintext P1 for
extractor-supported surfaces. It does not prove the extractor can lift every
future VM or opaque native construct; unsupported or partial lifting remains
invalid evidence and requires a stronger pinned extractor, not a PASS.

## 28. Post-review remediation 0.31.0

- Upgraded the selective VM to 1.2 and removed the long-lived global hex-string
  key interface. External mode now accepts only a `function-v1` runtime provider
  called with the exact protected function ID.
- The provider must return a fresh 32-byte `Uint8Array`. The VM copies it, zeros
  the provider-returned buffer immediately, and zeros its working key on both
  authentication success and failure.
- Decrypted payload bytes are decoded and cleared before `JSON.parse`; the
  temporary plaintext string reference is then dropped. Receipt verification
  rejects an external-key stage without the provider contract.
- Tests reject the legacy string slot, verify the provider receives a valid
  function ID, verify the returned key buffer is zeroed, and require generated
  code to clear decrypted bytes.

Decoded program objects, function inputs and outputs remain observable and the
runtime attack still recovers all canaries. This change narrows low-effort heap
exposure; it deliberately does not claim T2 confidentiality.

## 29. Post-review remediation 0.32.0

- Added an offline-root-trusted `time-authority` role and Ed25519 remote-time
  envelope bound to product, environment, operation scope and random 256-bit
  nonce. Root signature verification bootstraps the time key without consulting
  the runner clock.
- Assessment, clean provenance, release create/verify and CAS publication now
  reject system-clock-only production execution. Each consumes its own nonce
  atomically in a protected shared ledger before accepting the signed time.
- Provenance records the time proof and consumption digests. Release
  attestation v12 signs its issuance time plus authority key, proof, nonce and
  consumption digests; it also refuses old provenance without equivalent
  signed-time evidence.
- CAS verifies release expiry against a newly signed remote clock and records
  that time in its publisher receipt. Tests cover wrong scope, wrong nonce,
  untrusted authority, tampering and cross-process replay.

This removes the hostile runner's local wall clock as the accepted production
clock. It does not prove live first use of a pre-issued file: a still-unused
old proof can be delayed on a fully hostile host. Production therefore needs
on-demand issuance for an unpredictable nonce (or live co-signing), plus
authority key isolation, append-only issuance/consumption state, availability,
multi-region consistency and compromise recovery.

## 30. Post-review remediation 0.33.0

- Protection policy v6 now owner-pins both the exact `package-lock.json` digest
  and a deterministic digest of the installed protector dependency closure.
- The closure walks every lockfile package and hashes its actual files, byte
  lengths and executable modes. Required missing packages, undeclared extras,
  identity/version mismatch and package symlinks fail closed; absent optional
  platform packages are represented explicitly.
- Clean provenance records the full closure, and release signing independently
  recomputes it from the provenance root and compares it with both provenance
  and owner policy. A modified transitive package under an unchanged lockfile
  now blocks signing in a dedicated regression test.

This closes the local installed-tree form of G9. It does not independently
prove registry transparency, lifecycle-script safety, package-manager binary
integrity or hermetic container provenance; those remain builder/deployment
trust boundaries.

## 31. Post-review remediation 0.34.0

- Production assessment, provenance, release and CAS flows now generate a fresh
  256-bit challenge inside the verifier and invoke a bounded external authority
  client over stdin/stdout. A cached or pre-issued response fails the new nonce.
- The authority response is verified against the offline-root `time-authority`
  role, exact operation scope, environment and evaluation ID before the nonce is
  consumed in the shared ledger. File proofs remain diagnostic-only.
- Release attestation v13 and CAS publisher receipt v2 sign the live request,
  response and consumption digests plus the verifier run ID, so downstream
  auditors retain the whole freshness binding.
- Regression coverage includes a deliberately caching authority client and
  proves its second response is rejected.

This closes the pre-issued-file replay path. A fully hostile host can still
freeze execution after receiving a valid live response; continuous liveness and
key non-exportability require a remote signer/KMS or co-signing service.

## 32. Post-review remediation 0.34.1

- A deterministic regression replaces an artifact file after its initial
  inventory, from inside the time client. Publication now hashes the copied
  staging payload before promotion and rejects the mismatch. Idempotent retry
  also verifies the stored object instead of trusting only the channel receipt;
  missing, corrupted and symlinked payloads are rejected.
- CAS receipt validation now checks canonical payloads, product/channel,
  digest-addressed object path, hash types, publication time and the immediate
  predecessor. Release verification independently enforces immediate-predecessor
  arithmetic and a positive validity interval of no more than 366 days.
- The allowlist-only Gitleaks configuration was replacing its default rules.
  The built-in rules are now explicitly enabled; exceptions require exact
  synthetic values in named files. Ten executable controls prove seven required
  detections and three valid exceptions, including test-file coverage and
  resistance to inline suppression. CI pins actions and the scanner archive,
  then scans the complete Git history.
- A time client ignoring SIGTERM could defeat the previous synchronous timeout.
  The adapter now uses asynchronous execution, a hard deadline, a combined
  64 KiB stdout/stderr budget, POSIX process-group SIGKILL and explicit pipe
  closure. Errors do not expose client stderr or malformed JSON response
  snippets. Separate watchdog tests cover signal resistance, inherited pipes,
  output overflow and error redaction.

These changes preserve release v13 and CAS receipt v2 formats; they reject
previously accepted malformed or inconsistent data. Read-only local files are
not WORM storage, and this client adapter is not a process sandbox: a hostile
executable can escape a process group or alter its host. Production still needs
isolated workers, remote signing and protected persistent state. Crash recovery
between receipt creation and channel-head promotion remains a separate CAS
availability concern; no transactional recovery guarantee is made here.
