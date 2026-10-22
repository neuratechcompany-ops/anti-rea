# Adaptive REA threat map

Assume the attacker has the complete Anti-REA repository, documentation, tests,
profiles, fixtures, and unlimited chosen-input builds. Assume REA will add a
provider dedicated to this framework. Security claims that rely on the framework
remaining unfamiliar are invalid.

## Three required protection planes

1. **Trust plane:** secrets, privileged decisions, critical business rules, and
   final authorization stay on a server controlled by the product owner. The
   client receives only scoped, short-lived capabilities and minimum output.
2. **Cost plane:** diversified transforms, selective VM/bytecode/native/WASM,
   stripping, packaging, and runtime signals increase analysis cost for logic
   that is acceptable to disclose eventually.
3. **Evidence plane:** the exact shipped artifact, analyzer identities, raw
   evidence, negative controls, regressions, provenance, and signing are bound
   into a fail-closed release decision.

No cost-plane control may substitute for the trust plane. A local integrity
check is an input to server risk policy, never local authorization.

## Attack paths and release requirements

| Priority | Attack path | Recovered result | Required countermeasure | Mandatory negative test |
|---|---|---|---|---|
| P0 | Read public framework and recognize generated signatures | protector family, marker, profiles, ISA | design for public knowledge; maintain generic extractors in the corpus | current public extractor attacks every release |
| P0 | Extract embedded ciphertext, seed, decoder, and VM switch | constants, property names, operators, CFG | classify embedded-key VM as cost-only; move critical logic server-side | static VM unpacker and lifted semantic score |
| P0 | Hook `atob`, `Buffer.from`, `TextDecoder`, `JSON.parse`, VM cache, inputs, or outputs | decoded program and operational behavior | T2/T3 client facts must be explicitly accepted or server-side | preload hooks before first protected call |
| P0 | Patch return value, branch, entitlement, telemetry, or anti-debug result | local policy bypass | server independently authorizes privileged operations | modified client always returns favorable result |
| P0 | Forge assessment JSON or aliases for one executable | false release PASS | evidence schema v2, raw hash verification, artifact binding, executable identity, negative control | missing/tampered evidence and same-executable aliases fail |
| P0 | Skip virtualization/profile/probes through a legacy build path | unprotected release | one publisher-accepted orchestrator and stage receipts | omit each stage in turn; publication must fail |
| P0 | Leak a canary in caller, schema, chunk, map, update, or support bundle | semantic names/contracts | scan the complete delivery graph, not one function | contaminate every delivery surface independently |
| P1 | Chosen-plaintext builds with one construct changed | source construct to VM mapping | holdout corpus; multiple backend families and instruction decompositions | known-source and chosen-plaintext alignment |
| P1 | Cross-build diff across seeds/releases/customers | stable interpreter and business CFG | per-ticket structural diversity, not opcode renumbering only | mandatory hash-only alignment attack over 20–64 unique protected regions; stable-window/Jaccard recovery blocks gate |
| P1 | Deobfuscate known `javascript-obfuscator` patterns | readable dispatcher and strings | treat profiles as baseline; regularly run current deobfuscators | public deobfuscator corpus |
| P1 | Recognize bytenode loader and matching V8 | bytecode, literals, execution boundary | bytecode is AST-removal only; include matching-runtime dump | hook `runBytecodeFile` and inspect matching V8 |
| P1 | Inspect source maps, caches, precompressed files, installers, crash/support archives | original sources and reports | exact inventory and delivery-channel scans | inject map/report in each channel |
| P1 | Use reports as an oracle | seeds, paths, function names, counts, hashes | keep evidence outside release; opaque IDs; controlled evidence access | search every release/update/support payload |
| P1 | Replace analyzer, adapter, dependency, profile, Node, or build script | false evidence or source exfiltration | pinned digest, sanitized environment, hermetic builder, SBOM/provenance | mutate every tool after ticket issuance |
| P1 | Replay an older signed vulnerable release | downgrade | monotonic channel metadata, expiry/revocation, server minimum version | old valid manifest rejected after minimum increases |
| P1 | Mutate artifact during or after probe | TOCTOU bypass | hash before/after probe and immediately before publication | analyzer writes artifact; gate fails |
| P2 | Observe API/network/IPC/storage/service workers | endpoints, schemas, server responses | minimize contracts; authorization/rules remain server-side | browser capture and Electron IPC trace |
| P2 | Proxy/getter observes property access order | hidden input schema and branch behavior | protect a complete semantic slice or accept disclosure | Proxy-backed inputs log reads |
| P2 | Disable or spoof local telemetry | clean-looking modified client | nonce-bound server correlation; missing telemetry is risk, not trust | block/replay/reorder telemetry |
| P2 | Trigger semantic VM edge cases to force operational disablement | downgrade by reliability failure | differential/property testing | `undefined`, `-0`, `NaN`, coercion, getters, errors, key order |

## Classification gate

Every protected fact must have one of these dispositions before implementation:

- `PUBLIC`: may be recovered; protect integrity and minimize accidental detail.
- `COST_ONLY`: client recovery is eventually acceptable; set T0/T1 recovery and
  performance budgets.
- `SERVER_REQUIRED`: disclosure or patching changes security, money,
  authorization, fraud, licensing, privileged access, or durable competitive
  value. The authoritative implementation and decision must not ship.

Examples that are always `SERVER_REQUIRED`: signing/master keys, long-lived API
credentials, license issuance, final entitlement, full antifraud/risk/pricing
rules, server thresholds, and the only copy of a critical algorithm.

## Current selective VM assurance

The default embedded-key `anti-rea-selective-vm` is a cost-plane prototype. It
removes selected plaintext and the original source AST before the ordinary
transformer, but ships ciphertext, key derivation, and interpreter together.
The pinned public deobfuscator plus envelope extractor and the runtime hook both
recover its program, so it receives no T1+ confidentiality claim.

The opt-in external-key mode encrypts payloads with ChaCha20-Poly1305, a random
256-bit build key supplied outside the artifact, a random nonce per payload,
and context AAD. In the
current corpus the public T1 deobfuscator recognizes the envelope but recovers
no declared canary; the T2 hook recovers all canaries after authorized key
provisioning. Therefore only a named T1 offline-analysis claim is eligible, and
only for `COST_ONLY` facts. Captured authorized sessions, runtime hooks, key
reuse, provisioning compromise, and client patching remain explicit bypasses.

Per-build byte differences are not evidence of semantic diversity. Measure
whether a public generic extractor can cluster, decode, align, and lift builds.

## Required adaptive-REA regression corpus

- pinned public JavaScript deobfuscator followed by the framework-specific VM
  envelope extractor (implemented in `attacks/webcrack/`);
- runtime decode/cache/input/output hooks;
- known-source and chosen-plaintext fixtures;
- cross-seed and cross-release aligner;
- public JavaScript deobfuscators;
- matching-runtime bytenode/V8 observation;
- browser/CDP network and script capture;
- Electron IPC and preload boundary capture;
- artifact mutation, evidence forgery, tool alias, and stage-downgrade tests;
- contaminated maps, reports, chunks, installers, updates, crash, and support bundles;
- property-based semantic equivalence tests;
- patched-client test proving the server rejects a favorable local decision.

## Honest completion rule

Report `PASS` only for named facts, attacker tiers, artifact digest, analyzer
versions/digests, and measured budgets. If a generic extractor recovers the
fact, record the recovery and either move the fact server-side or lower the
claim. Never respond by hiding the extractor or weakening the probe.
