# Anti-REA agent playbook

This is the mandatory operating contract for an agent hardening a product. The
objective is measurable degradation of useful reverse-engineering output, not
the presence of a named tool or a large obfuscator configuration.

## 1. Establish scope before edits

Record the source root, clean build command, exact release output, deployment
format, language/runtime, signing and update paths, and supported architectures.
List high-value algorithms, rules, endpoints, IPC surfaces, schemas, flags,
integrations, and data. Mark anything that must leave the client rather than be
hidden.

Select attacker tiers explicitly:

- T0: strings, archive extraction, metadata, public maps;
- T1: static REA, AST/decompiler, symbols and dependency recovery;
- T2: debugger, proxy, CDP, bytecode/disassembly, patched client;
- T3: administrator/root, Frida/injection, memory and plaintext capture.

Do not silently reduce the tier because a chosen control cannot resist it.

## 2. Create a leakage inventory

Before hardening, make one row per protected fact:

| ID | Fact | Surface | Tiers | Baseline probe | Required result |
|---|---|---|---|---|---|
| L-01 | example rule name | main bundle | T0-T2 | REA + strings | no static semantic name |

Use unique non-secret canaries in test builds when a generic scanner cannot
prove recoverability. Include negative goals: a public API hostname may remain
observable while its authorization rule must be server-side.

## 3. Capture a reproducible baseline

Build production settings without Anti-REA transforms. Preserve outside the
artifact:

- source revision and dirty-state note;
- build command, environment, artifact digest, and file inventory;
- analyzer version, command, exit status, stdout, stderr, duration, raw output;
- REA plus an independent probe such as strings, archive extraction, a platform
  decompiler, symbols, network capture, or runtime instrumentation;
- recovered facts mapped to leakage IDs.

Classify every probe `valid`, `invalid`, or `blocked`. Tool errors, timeouts,
unsupported formats, and environment failures are never protection passes.
Use `scripts/run-probe.mjs` so this classification and raw evidence hashing are
machine-recorded rather than inferred from an agent summary.

## 4. Choose controls from evidence

- source maps/source/configuration: remove from the release boundary;
- semantic names: rename, strip metadata, and minimize exports;
- literal recovery: transform selected values, then test runtime interception;
- control-flow recovery: flatten or virtualize selected cold, valuable paths;
- package extraction: bytecode/native/WASM or protected packaging;
- privileged logic or secrets: move behind a server-side boundary;
- runtime observation: reduce exposed hooks and connect independent detection
  signals to server-side risk policy.

Do not apply maximum settings globally. Protect selected modules, measure cost,
and expand only when evidence justifies it.

## 5. Attack the transformed artifact

Run identical baseline probes on the exact hardened output, then target the
controls themselves:

- hook transformed string accessors and decrypted-value boundaries;
- inspect maps, chunks, caches, precompressed variants, updates, and sidecars;
- unpack every container layer;
- inspect imports, exports, reflection metadata, errors, and schemas;
- attach debugger/CDP/Frida when the tier includes them;
- capture network, IPC, storage, workers, and runtime plaintext;
- patch local anti-debug branches and verify the server does not trust them;
- confirm moved logic is not duplicated in another client surface.

Use at least two independent evidence sources. REA alone is insufficient.

## 6. Score recovery

For each leakage ID and attacker tier assign:

- `0`: not recovered by a valid probe;
- `1`: existence inferred, useful semantics not recovered;
- `2`: fragments or partial semantics recovered;
- `3`: substantially recovered;
- `4`: directly recovered or operationally replayable.

Record analyzer validity separately. A crash cannot receive score `0`. Set
thresholds before viewing the hardened result. Secrets and signing keys are
forbidden client-side; authorization decisions are server-side; public endpoints
are inventoried rather than described as secret.

## 7. Iterate without training to one fixture

When a target fails, identify the evidence, change one control family or trust
boundary, rebuild cleanly, rerun every prior probe, and rerun functional and
performance tests. Add each bypass to a regression corpus. Rotate canaries and
use structurally different samples so the framework does not optimize for one
signature, fixture, or REA version.

Include a negative control in every gate run: an intentionally contaminated copy
must fail for the expected reason. A gate that cannot reject its negative control
is invalid even when it passes the release artifact.

## 8. Required evidence bundle

Keep this outside the release directory:

```text
anti-rea-evidence/
  scope.md
  leakage-inventory.json
  exposure-policy.json
  protection-policy.signed.json
  product-build.signed.json
  tripwire-manifest.json
  toolchain.json
  baseline/artifact-digest.json
  baseline/probes/
  hardened/artifact-digest.json
  hardened/probes/
  worker-attestations/
  regression-reports/
  regression-attestations/
  vm-runtime.json
  comparison.json
  negative-control.json
  patched-client-server-authorization.signed.json
  residual-risk.md
```

`comparison.json` identifies each leakage ID, tier, probe validity, before score,
after score, adversarial probe, and supporting evidence path. The runtime attack
must be bound to the exact release file and named comparisons; recovered facts
make the assessment fail. Sign or otherwise authenticate the complete release
inventory; reject missing, modified, and extra files.

Before building, the product/security owner signs the exposure-policy digest,
required facts/comparisons, tiers, thresholds, minimum improvement, approved
analyzer identities, and required adversarial probes with
`scripts/protection-policy.mjs`. The implementing agent cannot change this
ticket after seeing results. `comparison.json` must reference both the signed
ticket and the exact exposure policy. Each adversarial report must carry the
full supplied-canary hash set, which must exactly match its approved facts.
Every analyzer and adversarial report must also carry a fresh
`rea-hardening-evidence-attestation/v2` signature from a worker key ID already
approved in the signed protection policy, plus a distinct unexpired
`rea-hardening-evidence-challenge/v1` signed by the root-trusted coordinator and
bound to exact policy/artifact/runner image/workload identity and the unique
assessment `evaluationId`. The gate must atomically consume every challenge in
a protected persistent ledger shared across runners; a failed validation burns
its challenges. The build/implementation agent must possess neither key.
The product build must separately carry a fresh
`rea-hardening-product-build-attestation/v1` from the owner-approved builder
identity. Provenance must match its repository URI, commit, tree, tracked build
definition, builder environment and exact virtualization input. The five-file
agent-refusal bundle is exact-template verified inside the artifact; its
manifest digest is bound by release attestation but contributes zero to the
security score.
Functional, performance and platform-security evidence must use typed
`rea-hardening-regression-report/v1` reports and fresh
`rea-hardening-regression-attestation/v1` signatures. Protection policy v6
precommits the exact suite, runner executable and environment digests; raw test
results are hash-bound. It also precommits backend, virtualizer/transformer
versions, key mode, encryption, profile digest, maximum claim tier, package-lock
digest and the actual installed protector dependency closure. Provenance and
release independently re-inventory the package trees. Assessment v8 requires
the exact stage receipts. A handwritten `passed` file
or an embedded/default downgrade is invalid evidence.

Validate `comparison.json` with `scripts/validate-assessment.mjs`, generate clean
source provenance, create and verify the exact inventory, then sign the channel
entry with `scripts/release-attestation.mjs` and enforce its anti-rollback
minimum sequence.

The assessment command receives the staging server and product-owner policy
trusted Ed25519 public keys from publisher configuration. Never take either key
from the assessment bundle.
The signed `rea-hardening-server-authorization/v2` receipt is valid for at most
24 hours. It must match the owner-precommitted product, environment, channel,
privileged action, deployment/config and transcript-schema digests, bind the
raw request/response transcript, and answer a fresh one-time coordinator
challenge for the exact artifact and evaluation.

## 9. Final report

Lead with `PASS`, `FAIL`, or `INCOMPLETE`, then report:

1. exact artifact and digest;
2. tiers actually tested;
3. controls implemented and where;
4. before/after recovery;
5. functional and performance results;
6. remaining bypasses and observable facts;
7. missing evidence and next iteration.

Never write “protected from reverse engineering.” State tested resistance,
tools and tiers, and remaining recovery paths.
