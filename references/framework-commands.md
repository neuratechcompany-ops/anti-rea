# Framework commands and adapter contract

Use these commands after defining scope and leakage targets in the agent
playbook. Evidence paths must remain outside both baseline and hardened release
directories.

## Run analyzer adapters

Adapters are trusted executable configuration. Review repository-provided or
third-party adapters before running them; an adapter chooses a local executable
and arguments.

```bash
export REA_CLI=/absolute/path/to/pinned/rea

node scripts/run-probe.mjs \
  --adapter adapters/rea-javascript.json \
  --artifact /absolute/path/to/baseline \
  --evidence /absolute/path/to/evidence/baseline/rea

node scripts/run-probe.mjs \
  --adapter adapters/rea-javascript.json \
  --artifact /absolute/path/to/hardened \
  --evidence /absolute/path/to/evidence/hardened/rea
```

The evidence directory must not exist. It receives raw stdout, raw stderr, and
`probe.json` with their hashes, analyzer family, resolved executable path and
executable digest, plus the artifact identity before and after execution. Status meanings:

- `valid`: executable completed, required output exists, and declared format is
  parseable;
- `invalid`: nonzero exit, timeout, output-limit violation, empty required
  output, or malformed output;
- `blocked`: executable is unavailable or cannot start.

Only `valid` probes can support recovery scores. The adapter digest is recorded
so changing its command, timeout, or parser creates distinguishable evidence.

## Enforce the trust boundary

Create the role inventory outside the build workspace using
`examples/trust-bundle.descriptor.example.json`, then sign it with an offline
root. Every operational public key is embedded by SPKI digest and may belong to
only one role:

```bash
node scripts/trust-bundle.mjs sign \
  --descriptor /offline/trust-bundle.descriptor.json \
  --private-key /offline/trust-root-private.pem \
  --out /trusted/production-trust-bundle.signed.json

node scripts/trust-bundle.mjs verify \
  --bundle /trusted/production-trust-bundle.signed.json \
  --root-public-key /pinned/offline-root-public.pem \
  --product ExampleProduct
```

The root public key path must be injected by protected runner/publisher
configuration, not selected from the repository or build artifact. The bundle
prevents per-command PEM substitution and cross-role key reuse; it cannot make
an attacker-controlled CI variable externally trustworthy.

Classify every protected fact before applying a client transform. Financial,
authorization, and security-impacting facts are automatically required to be
server-authoritative and absent as client implementations:

```bash
node scripts/validate-exposure-policy.mjs \
  --policy /absolute/path/to/exposure-policy.json \
  --artifact-report /absolute/path/to/artifact-verification.json \
  --report /absolute/path/to/evidence/exposure-policy.json
```

Exposure policy schema v2 requires each client `COST_ONLY` fact to contain at
least one `recoverySignals` entry. Generate only the fingerprint, not a plaintext
copy of a sensitive expected result, with:

```bash
node scripts/semantic-recovery.mjs fingerprint \
  --kind endpoint --value 'https://api.example.test/v1/orders?a=1&b=2'
```

For recoverable business logic, also precommit `js-structure` over the owned
reference function and `behavior-vector` over 1–256 private holdout cases. A
behavior vector is `{schemaVersion:1,cases:[{inputSha256,outputSha256,status}]}`;
only hashes enter policy/evidence. The gate extracts both kinds from signed raw
analyzer output and assigns score `4`; identifiers, formatting, literal values
and case order cannot hide a match. This is bounded JavaScript structural and
holdout equivalence, not a proof of arbitrary program equivalence.

The behavior signal is not accepted as a voluntary analyzer claim. Run the
mandatory oracle probe in an external network-denied, filesystem-restricted
worker. Reference and candidate are JSON-stdin/JSON-stdout Node programs:

```bash
node scripts/probe-behavior-holdout.mjs \
  --artifact /release/app.js \
  --reference /owner/reference-oracle.mjs \
  --candidate /evidence/recovered-candidate.mjs \
  --corpus /owner/private-holdout.json \
  --timeout-ms 5000 \
  --report /evidence/behavior-holdout.json
```

The probe hashes canonical inputs/outputs, requires complete execution by both
programs, detects executable/artifact mutation during the run, and emits no
plaintext corpus values. Timeout, crash, malformed JSON, output overflow,
partial coverage or TOCTOU makes evidence invalid. Sign the report with the
same adversarial worker/challenge flow as other attacks.

Run the mandatory T1 cross-build alignment attack over 20–64 independently
produced protected-function regions. Do not supply whole runtimes or containers:
their intentionally stable framework bytes would measure the wrong surface.
The manifest contains `{path,attestation}` entries relative to itself and must
include the exact release file passed as `--artifact`. Each attestation is
signed by the owner-approved `product-builder` key and binds exact policy,
source commit/tree, build definition, builder environment, unique run ID,
unique diversity-seed commitment, ordinal and region digest:

```bash
node scripts/cross-build-variant-attestation.mjs sign \
  --descriptor /builder/variant-01.descriptor.json \
  --private-key /builder/product-builder-private.pem \
  --out /evidence/build-01/variant.attestation.json
```

```bash
node scripts/probe-cross-build-alignment.mjs \
  --artifact /release/protected-region.bin \
  --manifest /evidence/cross-build-manifest.json \
  --report /evidence/cross-build-alignment.json
```

The probe hashes 32-byte high-entropy windows at an 8-byte stride, counts
windows present in at least 80% of variants and measures maximum pairwise
Jaccard similarity. More than 10% stable target windows or pairwise similarity
above 25% is `recovered`. Duplicate bytes/paths, fewer than 20 variants,
post-read mutation, short/oversized regions or no analyzable windows are invalid.
Only hashes, ratios and attestation identities enter the report. Assessment
verifies every builder signature through the root-signed trust bundle, requires
the same owner-approved source/build/environment, unique run/seed commitments,
re-runs the algorithm, requires T1 coverage for every comparison and rejects
threshold weakening.

Run the mandatory semantic companion over the same manifest. The configured
extractor must itself be the pinned executable and receives only the artifact
path; wrapper scripts or extra adapter arguments are rejected:

```bash
export ANTI_REA_SEMANTIC_IR_EXTRACTOR=/opt/pinned/semantic-ir-extractor

node scripts/probe-cross-build-semantic.mjs \
  --artifact /release/protected-region.bin \
  --manifest /evidence/cross-build-manifest.json \
  --adapter adapters/semantic-ir.json \
  --report /evidence/cross-build-semantic.json
```

The extractor outputs schema-v1 JSON with exact top-level fields
`schemaVersion`, `entry`, `nodes`, `controlEdges`, and `dataEdges`. Nodes have
`id`, `op`, and `valueClass`; control edges have `from`, `to`, `kind`; data
edges have `from`, `to`, and input ordinal. The canonicalizer permits at most
4096 nodes and 16384 edges, requires every node reachable from entry and an
observable return/output, rejects duplicate edges and more than 20% opaque
operations, and removes node naming/order through sixteen graph-refinement
rounds. Exact fingerprint support in at least 80% of variants or maximum
pairwise feature Jaccard above 70% is recovery. The assessment gate verifies
the builder attestations and owner-approved tool digests, then reruns every
extraction instead of trusting the submitted report.

Supported fixed-score kinds are `exact-text` (4), `js-structure` (4),
`wasm-structure` (4), `native-cfg` (4), `behavior-vector` (4), `endpoint` (3),
`json-shape` (3), and `identifier` (2).
Endpoint matching canonicalizes scheme/host, duplicate
slashes, fragment and query order; JSON shape preserves sorted keys and value
types but not primitive values. The gate also checks raw and Base64 test canaries
for `SERVER_REQUIRED` facts. These mechanisms cover only owner-precommitted
normalizers and do not constitute exhaustive semantic proof; the policy itself
still needs architecture review.

For WASM, fingerprint owner WAT and recovered WAT from a file. The normalizer
supports nested comments, requires a balanced module, replaces symbols,
numbers and strings, and retains section/control/opcode structure:

```bash
node scripts/semantic-recovery.mjs fingerprint \
  --kind wasm-structure --file /owner/reference.wat
```

For native code, make the isolated analyzer serialize each target function as
`examples/native-cfg.example.json`. Instructions contain only a mnemonic and
operand classes (`register`, `immediate`, `memory`, `relative`, `stack`,
`symbol`, `other`); blocks contain successor IDs. Fingerprinting canonicalizes
the graph independently of addresses, register names, block IDs and block order:

```bash
node scripts/semantic-recovery.mjs fingerprint \
  --kind native-cfg --file /owner/reference-function.cfg.json
```

The exact recovered WAT/CFG must appear in worker-signed raw analyzer output;
the gate discovers nested candidates itself. Partial CFGs, unknown successors,
unbalanced WAT, excessive depth/counts and malformed operand classes are not
scored. These are bounded structural equivalence signals, not proofs of general
binary equivalence.

Repository adapters `adapters/wabt-wasm2wat.json` and
`adapters/native-cfg-export.json` route those outputs through the same isolated
probe runner. Set `WASM2WAT` to a pinned WABT executable. Set
`ANTI_REA_NATIVE_CFG_EXPORTER` to a reviewed wrapper around the selected
REA/IDA/Ghidra provider which writes only the exact CFG schema to stdout; its
resolved executable digest is owner-precommitted like every analyzer.

Before any before/after result exists, the product/security owner signs the
policy ticket. Fill `examples/protection-policy.example.json` with the exact
exposure-policy digest, approved analyzer identities, facts, tiers, thresholds,
minimum improvement, and required attack probes:

```bash
node scripts/dependency-closure.mjs \
  --root /absolute/path/to/rea-hardening \
  > /owner-review/protector-dependency-closure.json

node scripts/protection-policy.mjs sign \
  --policy /approved/protection-policy.json \
  --private-key /owner-controlled/policy-private.pem \
  --out /evidence/protection-policy.signed.json

node scripts/protection-policy.mjs verify \
  --policy /evidence/protection-policy.signed.json \
  --public-key /trusted/product-owner-policy-public.pem
```

Copy `packageLockSha256` and `closureSha256` from the reviewed closure into
policy v6 `protectorDependencies`. Generate this after the exact production
install; do not accept a hash supplied only by the implementation agent.

The implementing agent must not own this signing role. The signed policy is
valid for at most 31 days. Every client `COST_ONLY` fact must remain covered by
an approved comparison, and analyzer digests cannot be changed after precommit.

Materialize every owner-declared `present` delivery surface as an unpacked
staging tree, then scan it before assessment. The descriptor must contain the
same IDs, kinds and audiences as policy v6; archives are rejected until an
upstream platform-specific unpacker has exposed their contents:

```bash
node scripts/delivery-graph.mjs \
  --descriptor /evidence/delivery-descriptor.json \
  --report /evidence/delivery-graph.json
```

The assessment re-opens all reported roots, recomputes every file/tree digest,
requires the `release` root to equal the verified artifact root, and rejects a
missing, added, changed or owner-policy-mismatched channel.

Run analyzers in an isolated worker without build/signing secrets or network
access. Before signing, a separate `evidence-coordinator` role issues a challenge
valid for at most 15 minutes and bound to the exact policy, artifact, worker key,
runner identity, environment image digest and workload identity:

```bash
node scripts/evidence-challenge.mjs issue \
  --product ExampleProduct \
  --evaluation-id release-2026-10-22-build-1234 \
  --policy-sha256 "$SIGNED_POLICY_SHA256" \
  --artifact-sha256 "$ARTIFACT_SHA256" \
  --kind analyzer-probe \
  --worker-key-id "$WORKER_KEY_ID" \
  --runner-id isolated-analysis-runner \
  --environment-sha256 "$RUNNER_IMAGE_SHA256" \
  --workload-identity spiffe://example.internal/anti-rea/evidence-worker \
  --private-key /coordinator/evidence-coordinator-private.pem \
  --expires-at 2026-10-22T17:15:00.000Z \
  --out /evidence/rea-after.challenge.json
```

The worker then signs each exact `probe.json` or adversarial report together
with that challenge:

```bash
node scripts/evidence-attestation.mjs sign \
  --report /evidence/hardened/rea/probe.json \
  --kind analyzer-probe \
  --challenge /evidence/rea-after.challenge.json \
  --coordinator-public-key /trusted/evidence-coordinator-public.pem \
  --private-key /analysis-worker/worker-private.pem \
  --run-id ci-run-1234-rea-after \
  --expires-at 2026-10-22T18:00:00.000Z \
  --out /evidence/rea-after.attestation.json
```

Use `--kind adversarial-probe` for the runtime-hook and public-deobfuscator
reports. Assessment rejects a stale, wrong-policy, wrong-artifact, modified or
reused challenge and binds its digest into the evidence root. A build job holding
either private key defeats this trust boundary; production must use remote KMS
policies that release the worker operation only to the challenged workload.
Every assessment must use a unique `evaluationId` and a persistent protected
`--challenge-ledger` directory shared by all gate runners. Consumption creates
the challenge-ID record atomically with exclusive-create semantics, so a second
assessment process cannot reuse it. Validation errors after consumption burn the
challenge intentionally; issue a new challenge rather than deleting a record.
The local ledger does not resist a hostile storage administrator: production
still needs append-only/Object-Lock storage and restrictive ACLs around it.

## Attack the framework-specific VM

```bash
node scripts/probe-vm-runtime.mjs \
  --artifact /absolute/path/to/release/app.js \
  --canaries /absolute/path/to/canaries.json \
  --virtualization-report /absolute/path/to/evidence/virtualization.json \
  --report /absolute/path/to/evidence/vm-runtime.json
```

Exit `2` means protected facts were recovered through common decode hooks. This
is valid adverse evidence, not a broken probe. A recovered `SERVER_REQUIRED`
fact blocks release and must be moved out of the client. A `COST_ONLY` fact may
proceed only if its predeclared tier and recovery budget permit the result.
Every protected function receives a stable opaque ID in the signed stage
receipt. Runtime and public probes must report the exact complete ID set;
missing/lazy paths produce `invalid` evidence rather than `not-recovered`.

## Validate the agent assessment

Create schema-v6 `comparison.json` from the example, assign a globally unique
`evaluationId`, and replace every fixture
value with a relative reference and digest from the same evidence directory:

```bash
node scripts/validate-assessment.mjs \
  /absolute/path/to/evidence/comparison.json \
  --trust-bundle /trusted/production-trust-bundle.signed.json \
  --trust-root-public-key /pinned/offline-root-public.pem \
  --challenge-ledger /protected/evidence-challenge-ledger \
  --time-authority-client /controlled/time-authority-client \
  --gate-private-key /controlled/assessment-gate-private.pem \
  --out /absolute/path/to/evidence/assessment-result.json
```

The gate opens every referenced report and raw stream, recomputes hashes,
rechecks the current executable digest, binds after-probes to the verified
release, rejects same-executable aliases, and requires matching before/after
identity for two analyzer families. Functional, platform-security and
performance evidence must use typed, worker-signed regression attestations;
patched-client server authorization uses its own signed receipt. The
authorization test must demonstrate that a favorable local
decision cannot grant the privileged operation. Its evidence must be a fresh
Ed25519-signed `rea-hardening-server-authorization/v2` receipt bound to the
owner-precommitted product/environment/channel/action, deployment and config
digests, transcript schema, exact raw transcript, artifact and one-time
coordinator challenge. Create it only through `scripts/server-authorization.mjs sign`;
the command resolves policy/coordinator/server roles from the root-signed
trust bundle. The transcript scenarios show a legitimate client
allowed and a patched-favorable client independently denied. Assessment-owned,
self-signed, stale, and modified receipts are rejected. A contaminated artifact must
have a bound verifier report with `status: failed`. `adversarialProbes` is
mandatory: it binds at least one T2/T3 VM runtime attack to a file inside the
exact release and to the leakage comparisons it challenges. A recovered
canary is a release failure, not an analyzer error.

```bash
node scripts/server-authorization.mjs sign \
  --transcript /evidence/server-authorization.transcript.json \
  --transcript-schema /owner/server-authorization-transcript.schema.json \
  --protection-policy /evidence/protection-policy.signed.json \
  --trust-bundle /trusted/production-trust-bundle.signed.json \
  --trust-root-public-key /pinned/offline-root-public.pem \
  --challenge /evidence/server-authorization.challenge.json \
  --private-key /server-runner/server-authorization-private.pem \
  --expires-at 2026-10-23T12:00:00.000Z \
  --out /evidence/server-authorization.signed.json
```

Production gate signing requires a root-trusted response to a live verifier
challenge and atomically consumes its nonce. File time proofs are diagnostic
only and cannot sign a production gate. `--now` is accepted only with
`REA_TEST_MODE=1`; such a result is labelled `test-override`, cannot be signed
with `--gate-private-key`, and is rejected by provenance and release even when
every other signature is valid.

The validator verifies the owner signature and exact exposure-policy digest,
requires every signed comparison and attack family, matches every adversarial
probe's full supplied-canary hash set to its approved facts, and rejects
post-result changes to tier, target, analyzer identity, or minimum improvement.
Exact approved canaries found in raw analyzer output force an evidence-derived
recovery score of `4` even if the assessment claims `0`. Assessment result v7
also records deterministic semantic matches derived directly from hashed raw
stdout. The analyzer need not label or admit the match: a precommitted endpoint,
identifier, text or JSON shape raises the fixed score and can fail the release.

The assessment also requires `anti-rea-vm-public-deobfuscator`: pinned
`webcrack@2.16.0` removes the ordinary JavaScript obfuscation layer, then the
framework-specific unpacker recovers the embedded seed and VM payload. Install
its isolated attack environment with pnpm under Node 24 in
`attacks/webcrack/`. A missing, crashed, or unrecognized VM payload is invalid
evidence rather than a successful protection result.

`assessment-result.json` used for release must carry
`rea-hardening-assessment-gate/v1`, signed by a separate controlled CI/publisher
key. Diagnostic unsigned output is allowed during iteration, but provenance and
release attestation reject a handwritten or modified PASS.
The signed core includes the exact assessment digest and a deterministic root
over the policy, reports, worker attestations, regressions, negative control,
and artifact verification, so downstream provenance commits the complete
validated evidence set rather than only a human-readable summary.

Functional, performance and platform-security reports use
`rea-hardening-regression-report/v1`. Protection policy v6 precommits each
suite, runner executable and environment digest. After the isolated runner
writes its typed report and raw result, its approved worker role signs the exact
bundle:

```bash
node scripts/regression-attestation.mjs sign \
  --report /evidence/functional.regression.json \
  --private-key /controlled/regression-worker-private.pem \
  --run-id ci-run-12345 \
  --expires-at 2026-10-22T18:00:00.000Z \
  --out /evidence/functional.regression.attestation.json
```

Repeat for `performance` and `platform-security`. Performance metrics must
respect their signed budgets. Policy v3 also precommits the protection
surface/backend, virtualizer and transformer versions, VM key mode and
encryption, exact profile digest and maximum claim tier. Assessment v4 binds
the exact `virtualization.json` and `transform.json`; an embedded fallback,
profile substitution or skipped stage is rejected before scoring.
satisfy `value <= maximum`; the other kinds require at least one passing test,
zero failures and consistent totals. The validator rehashes the suite, runner
executable and raw result, matches them against owner policy, verifies worker
identity and freshness, then commits report and attestation to the evidence
root. A handwritten `passed` file is rejected.

For the opt-in external-key T1 mode, provide a 32-byte lowercase-hex secret
through the build environment, never a command argument or evidence file:

```bash
export ANTI_REA_VM_KEY_SLOT=__ANTI_REA_DEPLOYMENT_KEY__
export ANTI_REA_VM_BUILD_KEY="$(openssl rand -hex 32)"
export ANTI_REA_ATTACK_NODE=/pinned/node-24/bin/node
bash scripts/harden-js.sh INPUT.js OUT EVIDENCE CANARIES.json EXPOSURE_POLICY.json \
  PROTECTION_POLICY.signed.json /trusted/product-owner-policy-public.pem 41823 99175
```

Transfer the build key directly to the server-side provisioning secret store,
then unset it. The key is build-scoped and is delivered only to authenticated
sessions; an authorized T2 client can still capture it. Reusing it across builds
is forbidden even though each payload receives a random nonce.

VM 1.2 does not accept the key as a global string. After authenticated release,
install a narrowly scoped provider at `ANTI_REA_VM_KEY_SLOT`; it receives the
64-hex protected function ID and returns a fresh 32-byte `Uint8Array`. Never
return the provider's only retained key buffer: the VM intentionally zeroes the
returned value, copies it for AEAD, then zeroes both its key copy and decrypted
payload bytes. A native/preload provider may enforce session and function-ID
policy, but T2 instrumentation can still hook the call or decoded program.

## Add defensive agent-refusal tripwires

Generate these before the final release manifest. The tool accepts no custom
prompt text: it creates only exact, non-executable templates with synthetic
markers and an explicit zero security-score contribution.

```bash
node scripts/llm-tripwire.mjs create \
  --out-dir /absolute/path/to/release/META-INF/anti-rea \
  --manifest /absolute/path/to/evidence/tripwire-manifest.json \
  --product ExampleProduct --release 1.2.3 --count 5

node scripts/llm-tripwire.mjs verify \
  --root /absolute/path/to/release/META-INF/anti-rea \
  --manifest /absolute/path/to/evidence/tripwire-manifest.json \
  --product ExampleProduct --release 1.2.3
```

The five templates cover authorization, data-egress, untrusted-content,
human-review and proprietary-code refusal vectors. Each manifest entry binds a
typed risk class, trigger, denied-operation list, independently verifiable
evidence requirement, fail-closed `defaultDecision: deny`, and the expected safe
`stop/refuse/escalate` response. The same v4 refusal capsule is embedded as
canonical one-line JSON in the corresponding file. Verification rejects changed
templates, a changed deny default, product/release confusion, extra files,
symlinks and executable bits.

The capsule is authenticated data for a policy-aware controller, not an
instruction that an artifact is allowed to impose on the framework's own agent.
An attacker-controlled agent may strip or ignore it. Its purpose is to activate
existing authorization, data-egress, sensitive-data and circumvention refusal
policies where they exist; it cannot create such a policy in a hostile model.

To check whether a synthetic marker was copied into an analyzer transcript,
scan it locally against the verified bundle:

```bash
node scripts/llm-tripwire.mjs observe \
  --root /absolute/path/to/release/META-INF/anti-rea \
  --manifest /absolute/path/to/evidence/tripwire-manifest.json \
  --product ExampleProduct --release 1.2.3 \
  --input /absolute/path/to/evidence/analyzer-output.txt
```

The observation report contains only marker hashes and typed vector IDs. A hit
means that a release-specific synthetic marker appeared in the inspected bytes;
it does not prove that an LLM refused, identify an attacker, or authorize an
automated response. An attacker can deliberately replay a visible marker.
The final manifest and channel attestation bind both their bytes and the
tripwire-manifest digest. A sophisticated analyzer can strip or ignore them;
they are deception/telemetry only and never compensate for a failed probe.

## Sign the release inventory

Use an Ed25519 private key held outside the repository and release directory.
Encrypted PKCS#8 keys can receive their passphrase through
`REA_MANIFEST_PASSPHRASE`; do not place it in command arguments or files next to
the artifact.

```bash
node scripts/release-manifest.mjs create \
  --root /absolute/path/to/release \
  --private-key /controlled/issuer-private.pem \
  --product ExampleProduct \
  --release 1.2.3 \
  --out /absolute/path/to/evidence/release.manifest.json

node scripts/release-manifest.mjs verify \
  --root /absolute/path/to/release \
  --public-key /trusted/issuer-public.pem \
  --product ExampleProduct \
  --release 1.2.3 \
  --manifest /absolute/path/to/evidence/release.manifest.json
```

Verification rejects an untrusted signing key, invalid signature, wrong trusted
product/release, symlinks, unsupported filesystem entries, modified files,
missing files, and extra files. The manifest authenticates bytes and inventory;
it does not encrypt code, prove newest-version policy, or force a patched client
to perform local verification.

## Bind provenance and prevent rollback

Release provenance refuses a dirty Git tree by default and inventories the
protector scripts, profiles, adapters, references, tests, package lock, exact
Node/V8 executable, evidence results, and the chained virtualization/transform
stage receipts. First have the isolated product builder sign the exact product
commit/tree, tracked build definition and virtualization input:

```bash
node scripts/product-build-attestation.mjs sign \
  --product ExampleProduct \
  --product-root /absolute/path/to/product \
  --repository-uri https://git.example/product.git \
  --build-definition /absolute/path/to/product/build.mjs \
  --virtualization-input /build/input.js \
  --builder-id production-builder \
  --environment-sha256 "$BUILDER_ENVIRONMENT_SHA256" \
  --private-key /controlled/builder-private.pem \
  --run-id "$BUILD_RUN_ID" \
  --expires-at 2026-10-23T00:00:00.000Z \
  --out /evidence/product-build.signed.json
```

Then bind both the product and protector repositories:

For every production stage, configure `--time-authority-client` as an executable
that reads one JSON request from stdin and returns one signed time attestation
on stdout. The verifier generates the fresh 256-bit nonce internally; the client
must forward that request to the separately protected `time-authority`.
Assessment scope is
the comparison `evaluationId`; provenance scope is
`provenance:<sha256(assessment-result bytes)>`; release scope is
`release:<sha256(assessment-result bytes)>`; publisher scope is
`publish:<sha256(release-attestation bytes)>`. Never reuse a nonce. All stages
must point at the same protected, shared time ledger. The default client timeout
is 10 seconds, and combined stdout/stderr output is limited to 64 KiB. Timeout
and overflow close the client's pipes and kill its ordinary POSIX process group;
stderr is not included in errors. This is a bounded protocol adapter, not a
sandbox for an untrusted executable. Request and consumption
digests are recorded in downstream attestations. The authority response itself
signs product, environment, evaluation ID and nonce; `verifierRunId` and the full
request digest are recorded by the verifier, not independently signed by the
time authority.

```bash
node scripts/create-provenance.mjs \
  --root /absolute/path/to/rea-hardening \
  --product-root /absolute/path/to/product \
  --build-definition /absolute/path/to/product/build.mjs \
  --virtualization-input /build/input.js \
  --build-attestation /evidence/product-build.signed.json \
  --protection-policy /evidence/protection-policy.signed.json \
  --artifact-report /evidence/artifact-verification.json \
  --assessment-result /evidence/assessment-result.json \
  --exposure-report /evidence/exposure-policy.json \
  --virtualization-report /evidence/virtualization.json \
  --transform-report /evidence/transform.json \
  --trust-bundle /trusted/production-trust-bundle.signed.json \
  --trust-root-public-key /pinned/offline-root-public.pem \
  --time-authority-client /controlled/time-authority-client \
  --time-ledger /protected/time-ledger \
  --out /evidence/provenance.json
```

After creating the ordinary release manifest, sign the channel entry. Keep the
private key in a separate signer/KMS workflow in production:

```bash
node scripts/release-attestation.mjs create \
  --artifact-report /evidence/artifact-verification.json \
  --assessment-result /evidence/assessment-result.json \
  --exposure-report /evidence/exposure-policy.json \
  --virtualization-report /evidence/virtualization.json \
  --transform-report /evidence/transform.json \
  --provenance /evidence/provenance.json \
  --protection-policy /evidence/protection-policy.signed.json \
  --build-attestation /evidence/product-build.signed.json \
  --tripwire-root /absolute/path/to/release/META-INF/anti-rea \
  --tripwire-manifest /evidence/tripwire-manifest.json \
  --release-manifest /evidence/release.manifest.json \
  --trust-bundle /trusted/production-trust-bundle.signed.json \
  --trust-root-public-key /pinned/offline-root-public.pem \
  --time-authority-client /controlled/time-authority-client \
  --time-ledger /protected/time-ledger \
  --private-key /controlled/attestation-private.pem \
  --product ExampleProduct --channel stable --release 1.2.3 \
  --sequence 42 --expires-at 2027-01-01T00:00:00.000Z \
  --previous-attestation /trusted/stable-41.json \
  --out /evidence/stable-42.json
```

Verification requires the caller's trusted minimum sequence; the signature
alone cannot prevent a client from accepting an older correctly signed file:

```bash
node scripts/release-attestation.mjs verify \
  --attestation /evidence/stable-42.json \
  --artifact-report /evidence/artifact-verification.json \
  --assessment-result /evidence/assessment-result.json \
  --exposure-report /evidence/exposure-policy.json \
  --virtualization-report /evidence/virtualization.json \
  --transform-report /evidence/transform.json \
  --provenance /evidence/provenance.json \
  --protection-policy /evidence/protection-policy.signed.json \
  --build-attestation /evidence/product-build.signed.json \
  --tripwire-root /absolute/path/to/release/META-INF/anti-rea \
  --tripwire-manifest /evidence/tripwire-manifest.json \
  --release-manifest /evidence/release.manifest.json \
  --trust-bundle /trusted/production-trust-bundle.signed.json \
  --trust-root-public-key /pinned/offline-root-public.pem \
  --time-authority-client /controlled/time-authority-client \
  --time-ledger /protected/time-ledger \
  --product ExampleProduct --channel stable --release 1.2.3 \
  --minimum-sequence 42 \
  --previous-attestation /trusted/stable-41.json
```

The publisher must consume the verified release through CAS staging rather than
uploading the mutable workspace directly:

```bash
node scripts/cas-publish.mjs \
  --artifact /absolute/path/to/release \
  --cas-root /publisher/content-addressed-store \
  --release-manifest /evidence/release.manifest.json \
  --release-attestation /evidence/stable-42.json \
  --trust-bundle /trusted/production-trust-bundle.signed.json \
  --trust-root-public-key /pinned/offline-root-public.pem \
  --time-authority-client /controlled/time-authority-client \
  --time-ledger /protected/time-ledger \
  --publisher-private-key /publisher/artifact-publisher-private.pem \
  --product ExampleProduct --channel stable --release 1.2.3 \
  --minimum-sequence 42
```

The command re-verifies the exact artifact, manifest, release attestation,
trust-bundle binding and publisher role. It re-hashes the actual copied staging
payload before promoting it to its digest-addressed object, removes write bits,
signs a per-release receipt and atomically advances
one product/channel head. A second genesis, skipped sequence or mismatched
predecessor is rejected. Repeating a publish revalidates the stored payload
before returning `already-published`; missing/corrupted objects and symlinked
payload roots are rejected. On local filesystems this is a verifiable CAS protocol,
not protection from a hostile storage administrator; production must enforce
append-only/Object Lock and publisher-only ACLs externally.

## Required ordering

1. Pin the offline trust-root public key in protected runner/publisher config,
   then create and verify the role-separated signed trust bundle.
2. Build baseline and hardened artifacts into separate fresh directories.
3. Run matching adapters on both.
4. Execute the bypass and regression corpus.
5. Score the leakage inventory and validate `comparison.json`.
6. Produce the isolated product-builder attestation and bind the product source,
   VM and obfuscation stage receipts into clean provenance.
7. Create and verify all five exact-template agent-refusal tripwires.
8. Sign the final release inventory only after all transformations and signing
   steps that change distributed bytes.
9. Verify the manifest and channel attestation again immediately before
   publication.
10. Publish only the CAS object and signed publisher receipt; never upload the
    mutable build workspace. Enforce external append-only/Object-Lock policy.
