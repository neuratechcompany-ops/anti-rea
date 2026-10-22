#!/usr/bin/env bash
# Fail-closed reference pipeline for a single owned JavaScript bundle. Intermediate
# artifacts and analyzer evidence stay outside the shipped directory.
set -euo pipefail

if [[ "$#" -ne 9 ]]; then
  echo "usage: harden-js.sh INPUT.js OUT_DIR EVIDENCE_DIR CANARIES.json EXPOSURE_POLICY.json SIGNED_PROTECTION_POLICY.json POLICY_PUBLIC_KEY.pem VM_SEED OBFUSCATION_SEED" >&2
  exit 64
fi

INPUT="$1"
OUT="$2"
EVIDENCE="$3"
CANARIES="$4"
EXPOSURE_POLICY="$5"
PROTECTION_POLICY="$6"
POLICY_PUBLIC_KEY="$7"
VM_SEED="$8"
OBFUSCATION_SEED="$9"
VM_KEY_SLOT="${ANTI_REA_VM_KEY_SLOT:-__ANTI_REA_DEPLOYMENT_KEY__}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"

absolute_new_path() {
  local target="$1"
  local parent base
  parent="$(dirname "$target")"
  base="$(basename "$target")"
  mkdir -p "$parent"
  printf '%s/%s\n' "$(cd "$parent" && pwd -P)" "$base"
}

if [[ ! -f "$INPUT" || ! -f "$CANARIES" || ! -f "$EXPOSURE_POLICY" || ! -f "$PROTECTION_POLICY" || ! -f "$POLICY_PUBLIC_KEY" ]]; then
  echo "INPUT, CANARIES, EXPOSURE_POLICY, SIGNED_PROTECTION_POLICY, and POLICY_PUBLIC_KEY must be existing regular files" >&2
  exit 64
fi
INPUT="$(cd "$(dirname "$INPUT")" && pwd -P)/$(basename "$INPUT")"
CANARIES="$(cd "$(dirname "$CANARIES")" && pwd -P)/$(basename "$CANARIES")"
EXPOSURE_POLICY="$(cd "$(dirname "$EXPOSURE_POLICY")" && pwd -P)/$(basename "$EXPOSURE_POLICY")"
PROTECTION_POLICY="$(cd "$(dirname "$PROTECTION_POLICY")" && pwd -P)/$(basename "$PROTECTION_POLICY")"
POLICY_PUBLIC_KEY="$(cd "$(dirname "$POLICY_PUBLIC_KEY")" && pwd -P)/$(basename "$POLICY_PUBLIC_KEY")"
SOURCE_DIR="$(dirname "$INPUT")"
OUT="$(absolute_new_path "$OUT")"
EVIDENCE="$(absolute_new_path "$EVIDENCE")"

case "$OUT" in /|"$SOURCE_DIR"|"$SOURCE_DIR"/*) echo "OUT must not contain or overwrite source" >&2; exit 64;; esac
case "$EVIDENCE" in /|"$OUT"|"$OUT"/*|"$SOURCE_DIR"|"$SOURCE_DIR"/*) echo "EVIDENCE must be isolated from source and release" >&2; exit 64;; esac
if [[ -e "$OUT" || -e "$EVIDENCE" ]]; then
  echo "OUT and EVIDENCE must not already exist" >&2
  exit 64
fi
if [[ ! "$VM_SEED" =~ ^(0|[1-9][0-9]{0,9})$ || ! "$OBFUSCATION_SEED" =~ ^(0|[1-9][0-9]{0,9})$ || "$VM_SEED" == "$OBFUSCATION_SEED" ]]; then
  echo "seeds must be different unsigned decimal integers" >&2
  exit 64
fi
POLICY_RESULT="$(node "$SCRIPT_DIR/protection-policy.mjs" verify --policy "$PROTECTION_POLICY" --public-key "$POLICY_PUBLIC_KEY")"
VM_KEY_MODE="$(printf '%s' "$POLICY_RESULT" | node -e 'let s="";process.stdin.on("data",c=>s+=c).on("end",()=>process.stdout.write(JSON.parse(s).protectionTransform.keyMode))')"
PROFILE_ID="$(printf '%s' "$POLICY_RESULT" | node -e 'let s="";process.stdin.on("data",c=>s+=c).on("end",()=>process.stdout.write(JSON.parse(s).protectionTransform.profileId))')"
EXPECTED_PROFILE_SHA256="$(printf '%s' "$POLICY_RESULT" | node -e 'let s="";process.stdin.on("data",c=>s+=c).on("end",()=>process.stdout.write(JSON.parse(s).protectionTransform.profileSha256))')"
PROFILE_PATH="$ROOT/profiles/$PROFILE_ID.json"
if [[ ! "$PROFILE_ID" =~ ^[a-z0-9][a-z0-9-]{1,62}$ || ! -f "$PROFILE_PATH" ]]; then
  echo "owner policy selects an unavailable protection profile" >&2
  exit 65
fi
ACTUAL_PROFILE_SHA256="$(node -e 'const{createHash}=require("node:crypto"),{readFileSync}=require("node:fs");process.stdout.write(createHash("sha256").update(readFileSync(process.argv[1])).digest("hex"))' "$PROFILE_PATH")"
if [[ "$ACTUAL_PROFILE_SHA256" != "$EXPECTED_PROFILE_SHA256" ]]; then
  echo "owner policy profile digest does not match the installed profile" >&2
  exit 65
fi
VIRTUALIZE_KEY_ARGS=()
RUNTIME_KEY_ARGS=()
VM_BUILD_KEY=""
if [[ "$VM_KEY_MODE" == "external" ]]; then
  if [[ ! "$VM_KEY_SLOT" =~ ^[A-Za-z_\$][A-Za-z0-9_\$]{3,63}$ || ! "${ANTI_REA_VM_BUILD_KEY:-}" =~ ^[a-f0-9]{64}$ ]]; then
    echo "external VM mode requires a valid ANTI_REA_VM_KEY_SLOT and 32-byte lowercase-hex ANTI_REA_VM_BUILD_KEY" >&2
    exit 64
  fi
  VIRTUALIZE_KEY_ARGS=(--key-mode external --key-slot "$VM_KEY_SLOT" --key-env ANTI_REA_VM_BUILD_KEY)
  RUNTIME_KEY_ARGS=(--key-slot "$VM_KEY_SLOT" --key-env ANTI_REA_PIPELINE_VM_KEY)
  VM_BUILD_KEY="$ANTI_REA_VM_BUILD_KEY"
  unset ANTI_REA_VM_BUILD_KEY
fi
if [[ -z "${REA_CLI:-}" || ! -x "$REA_CLI" ]]; then
  echo "set REA_CLI to the pinned executable under test" >&2
  exit 69
fi
if [[ -z "${ANTI_REA_ATTACK_NODE:-}" || ! -x "$ANTI_REA_ATTACK_NODE" ]]; then
  echo "set ANTI_REA_ATTACK_NODE to a pinned Node 24 executable for the public-deobfuscator probe" >&2
  exit 69
fi
if [[ "$("$ANTI_REA_ATTACK_NODE" -p 'process.versions.node.split(".")[0]')" != "24" || ! -d "$ROOT/attacks/webcrack/node_modules/webcrack" ]]; then
  echo "public-deobfuscator probe requires Node 24 and pinned attacks/webcrack dependencies" >&2
  exit 69
fi

mkdir "$OUT" "$EVIDENCE"
mkdir "$EVIDENCE/baseline-artifact"
cp "$INPUT" "$EVIDENCE/baseline-artifact/app.js"

echo "[1/6] Capture baseline with pinned REA"
node "$SCRIPT_DIR/run-probe.mjs" --adapter "$ROOT/adapters/rea-javascript.json" --artifact "$EVIDENCE/baseline-artifact" --evidence "$EVIDENCE/rea-before"
node "$SCRIPT_DIR/run-probe.mjs" --adapter "$ROOT/adapters/strings.json" --artifact "$EVIDENCE/baseline-artifact/app.js" --evidence "$EVIDENCE/strings-before"

echo "[2/6] Virtualize explicitly marked pure functions"
if [[ "$VM_KEY_MODE" == "external" ]]; then
  ANTI_REA_VM_BUILD_KEY="$VM_BUILD_KEY" node "$SCRIPT_DIR/virtualize-javascript.mjs" --input "$INPUT" --output "$EVIDENCE/virtualized.js" --report "$EVIDENCE/virtualization.json" --seed "$VM_SEED" --canaries "$CANARIES" "${VIRTUALIZE_KEY_ARGS[@]}"
else
  node "$SCRIPT_DIR/virtualize-javascript.mjs" --input "$INPUT" --output "$EVIDENCE/virtualized.js" --report "$EVIDENCE/virtualization.json" --seed "$VM_SEED" --canaries "$CANARIES" "${VIRTUALIZE_KEY_ARGS[@]}"
fi

echo "[3/6] Apply pinned, VM-required obfuscation profile"
node "$SCRIPT_DIR/transform-javascript.mjs" --input "$EVIDENCE/virtualized.js" --output "$OUT/app.js" --profile "$PROFILE_PATH" --report "$EVIDENCE/transform.json" --seed "$OBFUSCATION_SEED" --canaries "$CANARIES" --virtualization-report "$EVIDENCE/virtualization.json"

echo "[4/6] Verify release and enforce the declared trust boundary"
node "$SCRIPT_DIR/verify-web-artifact.mjs" --artifact "$OUT" --report "$EVIDENCE/artifact-verification.json"
node "$SCRIPT_DIR/validate-exposure-policy.mjs" --policy "$EXPOSURE_POLICY" --artifact-report "$EVIDENCE/artifact-verification.json" --report "$EVIDENCE/exposure-policy.json"

echo "[5/6] Capture hardened static and framework-specific runtime evidence"
node "$SCRIPT_DIR/run-probe.mjs" --adapter "$ROOT/adapters/rea-javascript.json" --artifact "$OUT" --evidence "$EVIDENCE/rea-after"
node "$SCRIPT_DIR/run-probe.mjs" --adapter "$ROOT/adapters/strings.json" --artifact "$OUT/app.js" --evidence "$EVIDENCE/strings-after"
set +e
if [[ "$VM_KEY_MODE" == "external" ]]; then
  ANTI_REA_PIPELINE_VM_KEY="$VM_BUILD_KEY" node "$SCRIPT_DIR/probe-vm-runtime.mjs" --artifact "$OUT/app.js" --canaries "$CANARIES" --virtualization-report "$EVIDENCE/virtualization.json" --report "$EVIDENCE/vm-runtime.json" "${RUNTIME_KEY_ARGS[@]}"
else
  node "$SCRIPT_DIR/probe-vm-runtime.mjs" --artifact "$OUT/app.js" --canaries "$CANARIES" --virtualization-report "$EVIDENCE/virtualization.json" --report "$EVIDENCE/vm-runtime.json"
fi
VM_PROBE_EXIT="$?"
set -e
if [[ "$VM_PROBE_EXIT" -eq 1 || "$VM_PROBE_EXIT" -gt 2 ]]; then
  echo "VM runtime probe was invalid" >&2
  exit 2
fi
set +e
env -i PATH="${PATH:-}" LANG="${LANG:-C}" "$ANTI_REA_ATTACK_NODE" "$ROOT/attacks/webcrack/probe.mjs" --artifact "$OUT/app.js" --canaries "$CANARIES" --virtualization-report "$EVIDENCE/virtualization.json" --report "$EVIDENCE/vm-public-deobfuscator.json"
PUBLIC_PROBE_EXIT="$?"
set -e
if [[ "$PUBLIC_PROBE_EXIT" -eq 1 || "$PUBLIC_PROBE_EXIT" -gt 2 ]]; then
  echo "public-deobfuscator probe was invalid" >&2
  exit 2
fi

cp -R "$OUT" "$EVIDENCE/negative-artifact"
printf '{"sourcesContent":["intentional negative control"]}\n' > "$EVIDENCE/negative-artifact/intentional.map"
if node "$SCRIPT_DIR/verify-web-artifact.mjs" --artifact "$EVIDENCE/negative-artifact" --report "$EVIDENCE/negative-control.json"; then
  echo "negative control unexpectedly passed" >&2
  exit 2
fi

echo "[6/6] Pipeline complete; assessment (including both VM attacks), clean provenance, signed manifest, and anti-rollback attestation are still mandatory release gates"
echo "artifact: $OUT"
echo "evidence: $EVIDENCE"
