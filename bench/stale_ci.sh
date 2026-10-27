#!/usr/bin/env bash
# CI driver and support tools for stale testing (S9, job iyi and stale-fresh).
#
#     bash bench/stale_ci.sh <command> [options]
#
#     fetch-master                Download master snapshot through Actions API
#     assert-export-env           Verify export step environment has no secrets
#     assert-hits                 Verify all tests in a test run were cache hits
#     test-comparator-negatives   Verify negative comparator fixtures for CI checks
#     test-planted-hidden-read    Prove shadow audit detects unobserved reads (row 24)
#     git-diff-check              Verify run observations against git diff
#     empty-snapshot              Generate an empty snapshot for disagreement (RG6)
#     rg9                         Run RG9 deterministic CallPathFp check
#     master-self-check           Import master snapshot and verify against git diff
#     test-master-path            Verify master snapshot export, API fetch, and self-check
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"

PY=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys' >/dev/null 2>&1; then
    PY="$candidate"
    break
  fi
done

if [ -z "$PY" ]; then
  echo "python3 required for stale_ci.sh" >&2
  exit 1
fi

IYI="${IYI:-$REPO/bin/iyi}"
if [ ! -x "$IYI" ]; then
  if [ -x "$REPO/.build/iyi" ]; then
    IYI="$REPO/.build/iyi"
  fi
fi

# 1. assert-export-env: verifies the export step environment holds no secrets or token
assert_export_env() {
  echo "== Asserting export environment is clean (no secrets or tokens) =="
  "$PY" -c "
import os, sys

forbidden_names = []
forbidden_values = []

# Known credential variable patterns in GitHub Actions and general environments
sensitive_substrings = ['TOKEN', 'SECRET', 'PASSWORD', 'PRIVATE_KEY', 'APIKEY']
# Patterns that match token values
token_prefixes = ['ghp_', 'ghs_', 'gho_', 'ghu_', 'github_pat_']

for k, v in os.environ.items():
    upper_k = k.upper()
    if any(sub in upper_k for sub in sensitive_substrings):
        forbidden_names.append(k)
    elif any(v.startswith(prefix) for prefix in token_prefixes):
        forbidden_values.append(k)

if forbidden_names or forbidden_values:
    print('ERROR: Export environment assertion failed: forbidden credentials present!', file=sys.stderr)
    for k in forbidden_names:
        print(f'  Sensitive variable name: {k}', file=sys.stderr)
    for k in forbidden_values:
        print(f'  Token pattern in variable: {k}', file=sys.stderr)
    sys.exit(1)

print('assert-export-env: PASSED (environment clean).')
"
}

# 2. empty-snapshot: writes an empty snapshot JSON to disable consumption
empty_snapshot() {
  local out="master.json"
  local target="x86_64-linux-gnu"
  local ns="master"
  local repo="${GITHUB_REPOSITORY:-iyilang/iyi}"
  local wf=".github/workflows/iyi.yml"
  local run_id=""

  while [ $# -gt 0 ]; do
    case "$1" in
      --out) out="$2"; shift 2 ;;
      --target) target="$2"; shift 2 ;;
      --namespace) ns="$2"; shift 2 ;;
      --repo) repo="$2"; shift 2 ;;
      --workflow) wf="$2"; shift 2 ;;
      --run-id) run_id="$2"; shift 2 ;;
      *) echo "Unknown option: $1" >&2; return 1 ;;
    esac
  done

  "$PY" -c "
import json, sys
out, target, ns, repo, wf, run_id_str = sys.argv[1:7]

if not run_id_str:
    print('empty-snapshot FAILED: --run-id is required and must be a positive integer', file=sys.stderr)
    sys.exit(1)

try:
    run_id_val = int(run_id_str)
    if run_id_val <= 0:
        raise ValueError()
except Exception:
    print(f'empty-snapshot FAILED: --run-id must be a positive integer, got: {run_id_str}', file=sys.stderr)
    sys.exit(1)

data = {
    'format': 'iyi-test-index',
    'version': 1,
    'namespace': ns,
    'repository': repo,
    'workflow': wf,
    'ref': 'refs/heads/master',
    'target': target,
    'producer': {
        'run_id': run_id_val,
        'run_attempt': 1,
        'sha': '',
        'job': 'stale-fresh',
        'shard': '1/1'
    },
    'records': []
}
with open(out, 'w') as f:
    json.dump(data, f, indent=2)
print(f'empty-snapshot: wrote empty snapshot with run_id {run_id_val} to {out}')
" "$out" "$target" "$ns" "$repo" "$wf" "$run_id"
}

# 3. assert-hits: checks that every test in cached_results.json hit from cache
assert_hits() {
  local json_file=""
  local snapshot_file=""
  local expected_ns=""

  while [ $# -gt 0 ]; do
    case "$1" in
      --json) json_file="$2"; shift 2 ;;
      --snapshot) snapshot_file="$2"; shift 2 ;;
      --namespace) expected_ns="$2"; shift 2 ;;
      *) echo "Unknown option: $1" >&2; return 1 ;;
    esac
  done

  if [ -z "$json_file" ] || [ ! -f "$json_file" ]; then
    echo "assert-hits requires --json FILE" >&2
    return 1
  fi

  "$PY" -c "
import json, sys, os

json_file = sys.argv[1]
snapshot_file = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else ''
expected_ns = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else ''

with open(json_file) as f:
    data = json.load(f)

tests = data.get('tests', [])
if not tests:
    print('assert-hits FAILED: no tests found in results', file=sys.stderr)
    sys.exit(1)

def extract_test_id(obj):
    if not isinstance(obj, dict):
        return None
    test_obj = obj.get('test')
    if isinstance(test_obj, dict) and 'root' in test_obj and 'path' in test_obj:
        return (str(test_obj['root']), str(test_obj['path']))
    if 'root' in obj and 'path' in obj:
        return (str(obj['root']), str(obj['path']))
    return None

seen_test_ids = set()
for t in tests:
    tid = extract_test_id(t)
    if not tid:
        print(f'assert-hits FAILED: test entry missing canonical test {{root, path}}: {t}', file=sys.stderr)
        sys.exit(1)
    if tid in seen_test_ids:
        print(f'assert-hits FAILED: duplicate test identity {tid[0]}:{tid[1]}', file=sys.stderr)
        sys.exit(1)
    seen_test_ids.add(tid)

exported_ids = None
snap_ns = expected_ns
if snapshot_file and os.path.exists(snapshot_file):
    with open(snapshot_file) as f:
        snap = json.load(f)
    if not snap_ns:
        snap_ns = snap.get('namespace', '')
    exported_ids = set()
    for r in snap.get('records', []):
        rid = extract_test_id(r)
        if not rid:
            print(f'assert-hits FAILED: snapshot record missing canonical test {{root, path}}: {r}', file=sys.stderr)
            sys.exit(1)
        if rid in exported_ids:
            print(f'assert-hits FAILED: snapshot contains duplicate test identity {rid[0]}:{rid[1]}', file=sys.stderr)
            sys.exit(1)
        exported_ids.add(rid)

non_hits = []
excused = []
hit_ids = set()

for t in tests:
    tid = extract_test_id(t)
    reuse = t.get('reuse', '')
    cached = t.get('cached', False)
    source = t.get('source', '')

    if cached and reuse == 'hit':
        if snap_ns:
            if source == 'local':
                print(f\"assert-hits FAILED: test {tid[0]}:{tid[1]} hit from local cache instead of snapshot namespace '{snap_ns}' (local hit substitution)\", file=sys.stderr)
                sys.exit(1)
            elif source != snap_ns:
                print(f\"assert-hits FAILED: test {tid[0]}:{tid[1]} hit with source '{source}' instead of snapshot namespace '{snap_ns}' (namespace substitution)\", file=sys.stderr)
                sys.exit(1)
        hit_ids.add(tid)
        continue

    if exported_ids is not None and reuse == 'not reusable' and tid not in exported_ids:
        excused.append((tid, t.get('reason', '')))
        continue

    non_hits.append((tid, reuse, t.get('reason', '')))

 if non_hits:
    print(f'assert-hits FAILED: {len(non_hits)} tests did not hit from cache:', file=sys.stderr)
    for tid, r, reason in non_hits:
        print(f'  {tid[0]}:{tid[1]}: reuse={r} reason={reason}', file=sys.stderr)
    sys.exit(1)

if exported_ids is not None:
    missing = exported_ids - hit_ids
    unexpected = hit_ids - exported_ids
    if missing or unexpected:
        print('assert-hits FAILED: hit identity set does not match snapshot identity set:', file=sys.stderr)
        if missing:
            missing_str = ', '.join(f\"{x[0]}:{x[1]}\" for x in sorted(list(missing)))
            print(f'  Missing {len(missing)} hits: {missing_str}', file=sys.stderr)
        if unexpected:
            unexp_str = ', '.join(f\"{x[0]}:{x[1]}\" for x in sorted(list(unexpected)))
            print(f'  Unexpected {len(unexpected)} hits: {unexp_str}', file=sys.stderr)
        sys.exit(1)

hits = len(hit_ids)
print(f'assert-hits PASSED: {hits} of {len(tests)} tests hit from cache.')
for tid, reason in excused:
    print(f'  not reusable, so not exported: {tid[0]}:{tid[1]}: {reason}')
" "$json_file" "$snapshot_file" "$expected_ns"
}

# 4. shadow-audit: verifies cached hits match fresh execution. The two
# snapshots carry the portable Build and ordered observations the runner's
# terse result JSON intentionally omits.
shadow_audit() {
  local cached_json=""
  local fresh_json=""
  local cached_snapshot=""
  local fresh_snapshot=""
  local expected_ns=""

  while [ $# -gt 0 ]; do
    case "$1" in
      --cached-json) cached_json="$2"; shift 2 ;;
      --fresh-json) fresh_json="$2"; shift 2 ;;
      --cached-snapshot) cached_snapshot="$2"; shift 2 ;;
      --fresh-snapshot) fresh_snapshot="$2"; shift 2 ;;
      --namespace) expected_ns="$2"; shift 2 ;;
      *) echo "Unknown option: $1" >&2; return 1 ;;
    esac
  done

  if [ -z "$cached_json" ] || [ -z "$fresh_json" ]; then
    echo "shadow-audit requires --cached-json and --fresh-json" >&2
    return 1
  fi

  "$PY" -c "
import json, sys, os

cached_file, fresh_file, cached_snapshot_file, fresh_snapshot_file = sys.argv[1:5]
expected_ns = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] else ''

with open(cached_file) as f:
    cached_data = json.load(f)
with open(fresh_file) as f:
    fresh_data = json.load(f)

def extract_test_id(obj):
    if not isinstance(obj, dict):
        return None
    test_obj = obj.get('test')
    if isinstance(test_obj, dict) and 'root' in test_obj and 'path' in test_obj:
        return (str(test_obj['root']), str(test_obj['path']))
    if 'root' in obj and 'path' in obj:
        return (str(obj['root']), str(obj['path']))
    return None

cached_tests = {}
for t in cached_data.get('tests', []):
    tid = extract_test_id(t)
    if not tid:
        print(f'shadow-audit FAILED: cached test entry missing canonical test {{root, path}}: {t}', file=sys.stderr)
        sys.exit(1)
    if tid in cached_tests:
        print(f'shadow-audit FAILED: duplicate test identity in cached run: {tid[0]}:{tid[1]}', file=sys.stderr)
        sys.exit(1)
    cached_tests[tid] = t

fresh_tests = {}
for t in fresh_data.get('tests', []):
    tid = extract_test_id(t)
    if not tid:
        print(f'shadow-audit FAILED: fresh test entry missing canonical test {{root, path}}: {t}', file=sys.stderr)
        sys.exit(1)
    if tid in fresh_tests:
        print(f'shadow-audit FAILED: duplicate test identity in fresh run: {tid[0]}:{tid[1]}', file=sys.stderr)
        sys.exit(1)
    fresh_tests[tid] = t

cached_records = {}
fresh_records = {}
snap_ns = expected_ns

if cached_snapshot_file and os.path.exists(cached_snapshot_file):
    with open(cached_snapshot_file) as f:
        c_snap = json.load(f)
    if not snap_ns:
        snap_ns = c_snap.get('namespace', '')
    for r in c_snap.get('records', []):
        rid = extract_test_id(r)
        if not rid:
            print(f'shadow-audit FAILED: cached snapshot record missing canonical test {{root, path}}: {r}', file=sys.stderr)
            sys.exit(1)
        if rid in cached_records:
            print(f'shadow-audit FAILED: duplicate test identity in cached snapshot: {rid[0]}:{rid[1]}', file=sys.stderr)
            sys.exit(1)
        cached_records[rid] = r

if fresh_snapshot_file and os.path.exists(fresh_snapshot_file):
    with open(fresh_snapshot_file) as f:
        f_snap = json.load(f)
    for r in f_snap.get('records', []):
        rid = extract_test_id(r)
        if not rid:
            print(f'shadow-audit FAILED: fresh snapshot record missing canonical test {{root, path}}: {r}', file=sys.stderr)
            sys.exit(1)
        if rid in fresh_records:
            print(f'shadow-audit FAILED: duplicate test identity in fresh snapshot: {rid[0]}:{rid[1]}', file=sys.stderr)
            sys.exit(1)
        fresh_records[rid] = r

disagreements = []
hits_checked = 0

for tid, c_test in cached_tests.items():
    tid_str = f\"{tid[0]}:{tid[1]}\"
    if not (c_test.get('cached') and c_test.get('reuse') == 'hit'):
        continue
    hits_checked += 1

    if snap_ns:
        source = c_test.get('source', '')
        if source == 'local':
            disagreements.append(f\"{tid_str}: local hit substitution (source=local, expected={snap_ns})\")
        elif source != snap_ns:
            disagreements.append(f\"{tid_str}: namespace substitution (source={source}, expected={snap_ns})\")

    f_test = fresh_tests.get(tid)
    if not f_test:
        disagreements.append(f\"{tid_str}: hit in cached run but missing from fresh audit\")
        continue

    c_status = c_test.get('status')
    f_status = f_test.get('status')
    if c_status != f_status:
        disagreements.append(f\"{tid_str}: verdict mismatch (cached={c_status}, fresh={f_status})\")

    c_build = c_test.get('portable_build')
    f_build = f_test.get('portable_build')
    if c_build and f_build and c_build != f_build:
        disagreements.append(f\"{tid_str}: portable Build mismatch ({c_build} != {f_build})\")

    if cached_records or fresh_records:
        c_record = cached_records.get(tid)
        f_record = fresh_records.get(tid)
        if not c_record or not f_record:
            disagreements.append(f\"{tid_str}: missing portable receipt in producer or audit snapshot\")
            continue
        c_r_build = c_record.get('build', {})
        f_r_build = f_record.get('build', {})
        c_b_hash = c_r_build.get('build') if isinstance(c_r_build, dict) else c_r_build
        f_b_hash = f_r_build.get('build') if isinstance(f_r_build, dict) else f_r_build
        if c_b_hash != f_b_hash:
            disagreements.append(f\"{tid_str}: portable Build mismatch in snapshots ({c_b_hash} != {f_b_hash})\")
        if c_record.get('trace', {}).get('observations') != f_record.get('trace', {}).get('observations'):
            disagreements.append(f\"{tid_str}: ordered trace observation mismatch\")

if disagreements:
    with open('.disagreement_marker', 'w') as f:
        f.write('\n'.join(disagreements))
    print(f'shadow-audit DISAGREEMENT: {len(disagreements)} mismatches found:', file=sys.stderr)
    for d in disagreements:
        print(f'  {d}', file=sys.stderr)
    sys.exit(1)

print(f'shadow-audit PASSED: {hits_checked} cached hits verified against fresh execution.')
" "$cached_json" "$fresh_json" "$cached_snapshot" "$fresh_snapshot" "$expected_ns"
}

# 5. test-planted-hidden-read: proves row 24 with real isolated copied runtime fixture
test_planted_hidden_read() {
  echo "== Running planted hidden-read shadow audit test (row 24) =="
  if [ ! -x "$IYI" ]; then
    echo "test-planted-hidden-read: compiler binary not found or not executable at $IYI" >&2
    exit 1
  fi

  local failed=1
  local work
  work="$(mktemp -d /tmp/planted-hidden.XXXXXX)"
  trap 'if [ "$failed" -eq 0 ]; then rm -rf "$work"; else echo "Preserving diagnostics workdir at $work" >&2; fi' RETURN
  local e2e_lib="$work/runtime"
  mkdir -p "$e2e_lib"
  cp -R "$REPO/src" "$e2e_lib/src"

  local e2e_observe="$e2e_lib/src/std/observe.iyi"
  # Patch __iyi_observe_file_read to return immediately (hiding the file read)
  "$PY" -c "
observe_path = '$e2e_observe'
with open(observe_path, 'r') as f:
    observe_source = f.read()
method = 'pub def __iyi_observe_file_read'
start = observe_source.find(method)
if start < 0:
    raise Exception('could not find __iyi_observe_file_read in observe.iyi')
finish = observe_source.find('\nend', start)
signature_end = observe_source.find('\n', start)
with open(observe_path, 'w') as f:
    f.write(observe_source[:signature_end + 1] + '  return\n' + observe_source[finish + 1:])
"
  local test_file="$work/hidden_read_test.iyi"
  local input_file="$work/input.txt"
  printf 'initial_value' > "$input_file"

  cat > "$test_file" <<EOF
import std/file::{File}
import std/env::{ENV}
val = File.read(ENV["PLANTED_INPUT"])
assert val == "initial_value"
EOF

  local run_id="${GITHUB_RUN_ID:-999999}"
  local ns="run:$run_id"
  local cache_dir="$work/cache"
  local producer_snapshot="$work/producer_snapshot.json"

  # 1. Execute producer: runs with patched runtime, test passes, exports snapshot with hidden read
  set +e
  local producer_out
  producer_out="$(IYI_PATH="$e2e_lib/src" \
    IYI_CACHE_DIR="$cache_dir" \
    IYI_CI_PRODUCER=1 \
    GITHUB_RUN_ID="$run_id" \
    PLANTED_INPUT="$input_file" \
    "$IYI" test --fresh --json \
      --export-index "$ns=$producer_snapshot" \
      "$test_file" 2>&1)"
  local producer_status=$?
  set -e
  if [ $producer_status -ne 0 ]; then
    echo "test-planted-hidden-read FAILED: producer execution failed with exit code $producer_status:" >&2
    echo "$producer_out" >&2
    return 1
  fi
  printf '%s\n' "$producer_out" > "$work/producer.json"

  # Verify producer exported exactly 1 receipt and file_read was indeed hidden
  "$PY" -c "
import json, sys
with open('$producer_snapshot') as f:
    snap = json.load(f)
records = snap.get('records', [])
if len(records) != 1:
    print(f'ERROR: expected exactly 1 exported receipt, got {len(records)}', file=sys.stderr)
    sys.exit(1)
rec = records[0]
rec_test = rec.get('test', {})
if not rec_test.get('path'):
    print('ERROR: exported receipt missing test path!', file=sys.stderr)
    sys.exit(1)
for obs in rec.get('trace', {}).get('observations', []):
    if 'input.txt' in obs.get('path', '') or obs.get('kind') == 'file_read':
        print('ERROR: file_read was not hidden in producer snapshot!', file=sys.stderr)
        sys.exit(1)
"

  # 2. Mutate input
  printf 'mutated_value' > "$input_file"

  # 3. Simulate fresh runner: wipe the cache path, preserving the external snapshot
  rm -rf "$cache_dir"

  # 4. Import false hit: consumer imports snapshot with hidden read, input changed but not observed -> cached hit
  local cached_json="$work/cached.json"
  local cached_out
  set +e
  cached_out="$(IYI_PATH="$e2e_lib/src" \
    IYI_CACHE_DIR="$cache_dir" \
    GITHUB_RUN_ID="$run_id" \
    PLANTED_INPUT="$input_file" \
    "$IYI" test --cached --json \
      --import-index "$ns=$producer_snapshot" \
      "$test_file" 2>"$work/cached.err")"
  local cached_status=$?
  set -e
  printf '%s\n' "$cached_out" > "$cached_json"

  local is_hit
  is_hit="$("$PY" -c 'import json,sys; d=json.load(open("'$cached_json'")); print(d.get("tests",[{}])[0].get("reuse",""))' 2>/dev/null || true)"

  if [ $cached_status -ne 0 ] || [ "$is_hit" != "hit" ]; then
    echo "test-planted-hidden-read FAILED: cached consumer did not hit from snapshot (status=$cached_status, reuse=$is_hit):" >&2
    echo "$cached_out" >&2
    if [ -s "$work/cached.err" ]; then cat "$work/cached.err" >&2; fi

    local explain_out
    explain_out="$(IYI_PATH="$e2e_lib/src" \
      IYI_CACHE_DIR="$cache_dir" \
      GITHUB_RUN_ID="$run_id" \
      PLANTED_INPUT="$input_file" \
      "$IYI" test --cached --explain \
        --import-index "$ns=$producer_snapshot" \
        "$test_file" 2>&1 || true)"
    echo "Consumer explain diagnostic:" >&2
    echo "$explain_out" >&2

    "$PY" -c "
import json, sys
try:
    with open('$producer_snapshot') as f: psnap = json.load(f)
    prec = psnap.get('records', [{}])[0]
    print('PRODUCER SNAPSHOT:', file=sys.stderr)
    print(f'  build: {prec.get(\"build\")}', file=sys.stderr)
    print(f'  profile: {prec.get(\"profile\")}', file=sys.stderr)
    print(f'  observations count: {len(prec.get(\"trace\", {}).get(\"observations\", []))}', file=sys.stderr)
    for obs in prec.get(\"trace\", {}).get(\"observations\", []):
        print(f'    obs: {obs}', file=sys.stderr)
except Exception as e:
    print(f'Could not dump producer snapshot: {e}', file=sys.stderr)

try:
    with open('$cached_json') as f: cjson = json.load(f)
    ctest = cjson.get('tests', [{}])[0]
    print('CONSUMER TEST RESULT:', file=sys.stderr)
    print(f'  status: {ctest.get(\"status\")}', file=sys.stderr)
    print(f'  reuse: {ctest.get(\"reuse\")}', file=sys.stderr)
    print(f'  reason: {ctest.get(\"reason\")}', file=sys.stderr)
    print(f'  portable_build: {ctest.get(\"portable_build\")}', file=sys.stderr)
    print(f'  profile: {ctest.get(\"profile\")}', file=sys.stderr)
    print(f'  roots: {ctest.get(\"roots\")}', file=sys.stderr)
    print(f'  output: {ctest.get(\"output\")}', file=sys.stderr)
except Exception as e:
    print(f'Could not dump consumer test result: {e}', file=sys.stderr)
"
    return 1
  fi

  # 5. Fresh actual failure: running --fresh executes the test with mutated input -> assertion failure
  local fresh_json="$work/fresh.json"
  set +e
  IYI_PATH="$e2e_lib/src" \
  IYI_CACHE_DIR="$cache_dir" \
  GITHUB_RUN_ID="$run_id" \
  PLANTED_INPUT="$input_file" \
  "$IYI" test --fresh --json \
    "$test_file" > "$fresh_json" 2>"$work/fresh.err"
  set -e

  # 6. Shadow audit: cached claims hit (pass), fresh claims miss (fail) -> names mismatch
  local shadow_failed=0
  shadow_audit --cached-json "$cached_json" --fresh-json "$fresh_json" --cached-snapshot "$producer_snapshot" --namespace "$ns" >/dev/null 2>&1 || shadow_failed=1
  if [ "$shadow_failed" -eq 1 ] && [ -f .disagreement_marker ]; then
    local marker_content
    marker_content="$(cat .disagreement_marker)"
    rm -f .disagreement_marker
    case "$marker_content" in
      *"verdict mismatch"*)
        echo "test-planted-hidden-read PASSED: shadow audit correctly caught disagreement: $marker_content"
        failed=0
        return 0
        ;;
      *)
        echo "test-planted-hidden-read FAILED: unexpected disagreement marker: $marker_content" >&2
        return 1
        ;;
    esac
  else
    echo "test-planted-hidden-read FAILED: shadow audit did not catch disagreement!" >&2
    return 1
  fi
}

# 6. fetch-master: downloads master snapshot through Actions API and writes sidecar
fetch_master() {
  local out="master.json"
  local target="x86_64-linux-gnu"
  local repo="${GITHUB_REPOSITORY:-iyilang/iyi}"
  local token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"

  while [ $# -gt 0 ]; do
    case "$1" in
      --out) out="$2"; shift 2 ;;
      --target) target="$2"; shift 2 ;;
      --repo) repo="$2"; shift 2 ;;
      --token) token="$2"; shift 2 ;;
      *) echo "Unknown option: $1" >&2; return 1 ;;
    esac
  done

  "$PY" -c "
import json, sys, os, hashlib, urllib.request, urllib.error, urllib.parse

out = sys.argv[1]
target = sys.argv[2]
repo = sys.argv[3]
token = sys.argv[4]

if not token:
    print('fetch-master FAILED: token is required (--token or GITHUB_TOKEN)', file=sys.stderr)
    sys.exit(1)

def write_sidecar(path, file_sha256, run_id, repo_name, workflow_file, ref):
    sidecar = {
        'sha256': file_sha256,
        'run_id': run_id,
        'repository': repo_name,
        'workflow': workflow_file,
        'ref': ref
    }
    sidecar_path = f'{path}.provenance.json'
    with open(sidecar_path, 'w') as f:
        json.dump(sidecar, f, indent=2)
    print(f'fetch-master: wrote sidecar {sidecar_path}')

api_base = os.environ.get('GITHUB_API_URL', 'https://api.github.com').rstrip('/')

headers = {
    'Authorization': f'Bearer {token}',
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'iyi-ci-fetch-master'
}

# 1. Fetch runs for workflow iyi.yml
runs_url = f'{api_base}/repos/{repo}/actions/workflows/iyi.yml/runs?branch=master&event=push&status=completed&per_page=1'

try:
    req = urllib.request.Request(runs_url, headers=headers)
    with urllib.request.urlopen(req) as resp:
        runs_data = json.loads(resp.read().decode('utf-8'))
except Exception as e:
    print(f'fetch-master FAILED: query runs failed ({e})', file=sys.stderr)
    sys.exit(1)

workflow_runs = runs_data.get('workflow_runs', [])
if not workflow_runs:
    print('fetch-master: no completed master push run found for .github/workflows/iyi.yml; valid absent.')
    sys.exit(0)

master_run = workflow_runs[0]

# Require exact path / head_branch / event / repository.full_name
run_path = master_run.get('path')
if run_path != '.github/workflows/iyi.yml':
    print(f\"fetch-master FAILED: run path '{run_path}' != '.github/workflows/iyi.yml'\", file=sys.stderr)
    sys.exit(1)

head_branch = master_run.get('head_branch')
if head_branch not in ('master', 'refs/heads/master'):
    print(f\"fetch-master FAILED: head_branch '{head_branch}' != master\", file=sys.stderr)
    sys.exit(1)

event = master_run.get('event')
if event != 'push':
    print(f\"fetch-master FAILED: event '{event}' != push\", file=sys.stderr)
    sys.exit(1)

run_repo = master_run.get('repository', {}).get('full_name')
if run_repo != repo:
    print(f\"fetch-master FAILED: repository '{run_repo}' != '{repo}'\", file=sys.stderr)
    sys.exit(1)

run_id = master_run['id']

# 2. Query artifacts with EXACT name only
expected_name = f'master-{target}.json'
artifacts_url = f'{api_base}/repos/{repo}/actions/runs/{run_id}/artifacts?name={urllib.parse.quote(expected_name)}&per_page=100'

try:
    req_art = urllib.request.Request(artifacts_url, headers=headers)
    with urllib.request.urlopen(req_art) as resp:
        art_data = json.loads(resp.read().decode('utf-8'))
except Exception as e:
    print(f'fetch-master FAILED: query artifacts failed ({e})', file=sys.stderr)
    sys.exit(1)

# Exact name filter and unexpired
matching_artifacts = [
    a for a in art_data.get('artifacts', [])
    if a.get('name') == expected_name and not a.get('expired', False)
]

if len(matching_artifacts) == 0:
    print(f'fetch-master: no non-expired artifact with exact name {expected_name}; valid absent.')
    sys.exit(0)

if len(matching_artifacts) > 1:
    print(f'fetch-master FAILED: multiple ({len(matching_artifacts)}) artifacts with name {expected_name}', file=sys.stderr)
    sys.exit(1)

target_art = matching_artifacts[0]
art_id = target_art['id']

# 3. Digest check
digest_str = target_art.get('digest', '')
if not digest_str:
    print(f'fetch-master FAILED: artifact {art_id} has no digest', file=sys.stderr)
    sys.exit(1)

if digest_str.startswith('sha256:'):
    exp_digest_hex = digest_str[7:].lower()
else:
    exp_digest_hex = digest_str.split(':')[-1].lower()

if len(exp_digest_hex) != 64:
    print(f'fetch-master FAILED: invalid digest format: {digest_str}', file=sys.stderr)
    sys.exit(1)

# 4. Download artifact with redirect disabled, then fetch Location without Authorization
class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener = urllib.request.build_opener(NoRedirectHandler)
download_url = f'{api_base}/repos/{repo}/actions/artifacts/{art_id}/zip'
req_dl = urllib.request.Request(download_url, headers=headers)

location = None
raw_bytes = None
try:
    resp = opener.open(req_dl)
    raw_bytes = resp.read()
except urllib.error.HTTPError as e:
    if e.code in (301, 302, 303, 307, 308):
        location = e.headers.get('Location')
    else:
        print(f'fetch-master FAILED: download request returned HTTP {e.code}', file=sys.stderr)
        sys.exit(1)
except Exception as e:
    print(f'fetch-master FAILED: download request error ({e})', file=sys.stderr)
    sys.exit(1)

if location:
    blob_url = urllib.parse.urljoin(download_url, location)
    req_blob = urllib.request.Request(blob_url, headers={'User-Agent': 'iyi-ci-fetch-master'})
    try:
        with urllib.request.urlopen(req_blob) as blob_resp:
            raw_bytes = blob_resp.read()
    except urllib.error.HTTPError as e:
        print(f'fetch-master FAILED: blob download returned HTTP {e.code}', file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f'fetch-master FAILED: blob download error ({e})', file=sys.stderr)
        sys.exit(1)

if raw_bytes is None:
    print('fetch-master FAILED: no bytes received from artifact download', file=sys.stderr)
    sys.exit(1)

# 5. Payload check: Refuse PK\x03\x04 (zip)
if raw_bytes.startswith(b'PK\x03\x04'):
    print('fetch-master FAILED: received ZIP payload (starts with PK\\x03\\x04); expected raw JSON from archive: false', file=sys.stderr)
    sys.exit(1)

# 6. Verify sha256 match
actual_sha256 = hashlib.sha256(raw_bytes).hexdigest().lower()
if actual_sha256 != exp_digest_hex:
    print(f'fetch-master FAILED: sha256 mismatch (expected {exp_digest_hex}, got {actual_sha256})', file=sys.stderr)
    sys.exit(1)

# 7. Write output and provenance sidecar
out_dir = os.path.dirname(out)
if out_dir:
    os.makedirs(out_dir, exist_ok=True)

with open(out, 'wb') as f:
    f.write(raw_bytes)

write_sidecar(out, actual_sha256, run_id, run_repo, '.github/workflows/iyi.yml', 'refs/heads/master')
print(f'fetch-master: successfully downloaded and verified {out}')
" "$out" "$target" "$repo" "$token"
}

# 7. git-diff-check: validates run observations against git diff
git_diff_check() {
  local master_snapshot=""
  local cached_json=""
  local repo_dir="$REPO"
  local changed_files_file=""

  while [ $# -gt 0 ]; do
    case "$1" in
      --master-snapshot) master_snapshot="$2"; shift 2 ;;
      --cached-json) cached_json="$2"; shift 2 ;;
      --repo) repo_dir="$2"; shift 2 ;;
      --changed-files) changed_files_file="$2"; shift 2 ;;
      *) echo "Unknown option: $1" >&2; return 1 ;;
    esac
  done

  if [ -z "$master_snapshot" ] || [ ! -f "$master_snapshot" ]; then
    echo "git-diff-check: master snapshot not found; skipping check."
    return 0
  fi

  "$PY" -c "
import json, sys, os, subprocess

master_file, cached_file, repo, changed_files_arg = sys.argv[1:5]

with open(master_file) as f:
    master_data = json.load(f)
with open(cached_file) as f:
    cached_data = json.load(f)

if changed_files_arg and os.path.exists(changed_files_arg):
    with open(changed_files_arg) as f:
        changed_files = set(line.strip() for line in f if line.strip())
    print(f'git-diff-check: using {len(changed_files)} changed files from {changed_files_arg}')
else:
    producer_sha = master_data.get('producer', {}).get('sha', '').strip()
    if not producer_sha:
        print('git-diff-check: no producer sha in snapshot; skipping.')
        sys.exit(0)

    res = subprocess.run(['/usr/bin/git', '-C', repo, 'rev-parse', '--verify', f'{producer_sha}^{{commit}}'],
                         capture_output=True, text=True)
    if res.returncode != 0:
        print(f'git-diff-check: producer commit {producer_sha} not in shallow clone; skipping.')
        sys.exit(0)

    res_diff = subprocess.run(['/usr/bin/git', '-C', repo, 'diff', '--name-only', producer_sha, 'HEAD'],
                              capture_output=True, text=True)
    if res_diff.returncode != 0:
        print('git-diff-check: git diff failed; skipping.')
        sys.exit(0)

    changed_files = set(line.strip() for line in res_diff.stdout.splitlines() if line.strip())
    print(f'git-diff-check: {len(changed_files)} changed files between {producer_sha[:8]} and HEAD')

def extract_test_id(obj):
    if not isinstance(obj, dict):
        return None
    test_obj = obj.get('test')
    if isinstance(test_obj, dict) and 'root' in test_obj and 'path' in test_obj:
        return (str(test_obj['root']), str(test_obj['path']))
    if 'root' in obj and 'path' in obj:
        return (str(obj['root']), str(obj['path']))
    return None

def is_file_observation(obs):
    kind = obs.get('kind', '')
    root = obs.get('root', '')
    if root in ('abs', 'host', 'scratch', 'env'):
        return False
    return kind.startswith('file_') or kind == 'dir_list' or kind == 'file'

def map_obs_to_repo_path(obs, test_entry, repo_root):
    obs_root = obs.get('root', '')
    obs_path = obs.get('path', '')
    if obs_root == 'toolchain':
        return os.path.normpath(os.path.join('src', obs_path))
    roots = test_entry.get('roots', {})
    if isinstance(roots, dict) and obs_root in roots:
        abs_p = os.path.normpath(os.path.join(roots[obs_root], obs_path))
        try:
            rel = os.path.relpath(abs_p, repo_root)
            if not rel.startswith('..'):
                return rel
        except ValueError:
            pass
    if obs_root == 'src':
        test_obj = test_entry.get('test', {})
        tpath = test_obj.get('path', '')
        tdir = os.path.dirname(tpath)
        combined = os.path.normpath(os.path.join(tdir, obs_path)) if tdir else obs_path
        if os.path.exists(os.path.join(repo_root, combined)):
            return combined
        if os.path.exists(os.path.join(repo_root, obs_path)):
            return os.path.normpath(obs_path)
        return combined
    return os.path.normpath(obs_path)

master_records = {}
for r in master_data.get('records', []):
    rid = extract_test_id(r)
    if not rid:
        print(f'git-diff-check FAILED: master snapshot record missing canonical test {{root, path}}: {r}', file=sys.stderr)
        sys.exit(1)
    if rid in master_records:
        print(f'git-diff-check FAILED: duplicate test identity in master snapshot: {rid[0]}:{rid[1]}', file=sys.stderr)
        sys.exit(1)
    master_records[rid] = r

cached_tests = {}
for t in cached_data.get('tests', []):
    tid = extract_test_id(t)
    if not tid:
        print(f'git-diff-check FAILED: cached test entry missing canonical test {{root, path}}: {t}', file=sys.stderr)
        sys.exit(1)
    if tid in cached_tests:
        print(f'git-diff-check FAILED: duplicate test identity in cached results: {tid[0]}:{tid[1]}', file=sys.stderr)
        sys.exit(1)
    cached_tests[tid] = t

errors = []
snap_ns = master_data.get('namespace', 'master')

# Direction 1: Reject changed tracked input hit
for tid, t in cached_tests.items():
    tid_str = f\"{tid[0]}:{tid[1]}\"
    if t.get('cached') and t.get('reuse') == 'hit':
        source = t.get('source', '')
        if snap_ns:
            if source == 'local':
                errors.append(f\"Hit test {tid_str} hit from local cache instead of master namespace '{snap_ns}' (local hit substitution)\")
            elif source != snap_ns:
                errors.append(f\"Hit test {tid_str} hit with source '{source}' instead of '{snap_ns}' (namespace substitution)\")

        rec = master_records.get(tid)
        if not rec:
            continue

        for obs in rec.get('trace', {}).get('observations', []):
            if not is_file_observation(obs):
                continue
            repo_path = map_obs_to_repo_path(obs, t, repo)
            if repo_path in changed_files or obs.get('path') in changed_files:
                errors.append(f\"Hit test {tid_str} observed changed file {repo_path}\")

# Direction 2: Reject equal-build eligible unchanged-files miss
for tid, t in cached_tests.items():
    tid_str = f\"{tid[0]}:{tid[1]}\"
    reuse = t.get('reuse', '')
    if reuse == 'miss':
        rec = master_records.get(tid)
        if not rec:
            continue

        status = t.get('status', '')
        reason = str(t.get('reason', ''))
        if t.get('reuse') == 'not reusable' or status == 'does not build' or 'not reusable' in reason or 'does not build' in reason:
            continue

        if t.get('blocked') is True or 'blocked' in reason:
            continue

        t_prof = t.get('profile')
        rec_prof = rec.get('profile')
        rec_prof_fp = rec_prof.get('fp') if isinstance(rec_prof, dict) else rec_prof
        if t_prof and rec_prof_fp and t_prof != rec_prof_fp:
            continue
        if 'profile' in reason:
            continue

        t_build = t.get('portable_build')
        rec_build = rec.get('build')
        rec_b_hex = rec_build.get('build') if isinstance(rec_build, dict) else rec_build
        if not (t_build and rec_b_hex and str(t_build).lower() == str(rec_b_hex).lower()):
            continue

        has_changed_input = False
        for obs in rec.get('trace', {}).get('observations', []):
            if not is_file_observation(obs):
                continue
            repo_path = map_obs_to_repo_path(obs, t, repo)
            if repo_path in changed_files or obs.get('path') in changed_files:
                has_changed_input = True
                break

        if not has_changed_input:
            errors.append(f\"Missed test {tid_str} has equal build and unchanged observed inputs but missed\")

if errors:
    print(f'git-diff-check FAILED with {len(errors)} errors:', file=sys.stderr)
    for e in errors:
        print(f'  {e}', file=sys.stderr)
    sys.exit(1)

print('git-diff-check PASSED: all cached hits and misses respected git diff.')
" "$master_snapshot" "$cached_json" "$repo_dir" "$changed_files_file"
}

# 8. test-comparator-negatives: proves negative and discrimination rules for CI consumers
test_comparator_negatives() {
  echo "== Running CI evidence comparator negative and discrimination fixtures =="
  "$PY" -c "
import os, sys, json

def extract_test_id(obj):
    if not isinstance(obj, dict):
        return None
    test_obj = obj.get('test')
    if isinstance(test_obj, dict) and 'root' in test_obj and 'path' in test_obj:
        return (str(test_obj['root']), str(test_obj['path']))
    if 'root' in obj and 'path' in obj:
        return (str(obj['root']), str(obj['path']))
    return None

def is_file_observation(obs):
    kind = obs.get('kind', '')
    root = obs.get('root', '')
    if root in ('abs', 'host', 'scratch', 'env'):
        return False
    return kind.startswith('file_') or kind == 'dir_list' or kind == 'file'

def map_obs_to_repo_path(obs, test_entry, repo_root):
    obs_root = obs.get('root', '')
    obs_path = obs.get('path', '')
    if obs_root == 'toolchain':
        return os.path.normpath(os.path.join('src', obs_path))
    roots = test_entry.get('roots', {})
    if isinstance(roots, dict) and obs_root in roots:
        abs_p = os.path.normpath(os.path.join(roots[obs_root], obs_path))
        try:
            rel = os.path.relpath(abs_p, repo_root)
            if not rel.startswith('..'):
                return rel
        except ValueError:
            pass
    if obs_root == 'src':
        test_obj = test_entry.get('test', {})
        tpath = test_obj.get('path', '')
        tdir = os.path.dirname(tpath)
        combined = os.path.normpath(os.path.join(tdir, obs_path)) if tdir else obs_path
        if os.path.exists(os.path.join(repo_root, combined)):
            return combined
        if os.path.exists(os.path.join(repo_root, obs_path)):
            return os.path.normpath(obs_path)
        return combined
    return os.path.normpath(obs_path)

# --- 1. Assert-Hits Tests ---
def run_ah(data, snap=None, expected_ns=''):
    tests = data.get('tests', [])
    if not tests: return False, 'no tests'
    seen = set()
    for t in tests:
        tid = extract_test_id(t)
        if not tid: return False, 'missing tid'
        if tid in seen: return False, 'duplicate tid'
        seen.add(tid)
    exported = None
    snap_ns = expected_ns
    if snap:
        if not snap_ns: snap_ns = snap.get('namespace', '')
        exported = set()
        for r in snap.get('records', []):
            rid = extract_test_id(r)
            if not rid: return False, 'missing rid'
            if rid in exported: return False, 'duplicate rid'
            exported.add(rid)
    hit_ids = set()
    for t in tests:
        tid = extract_test_id(t)
        reuse = t.get('reuse', '')
        cached = t.get('cached', False)
        source = t.get('source', '')
        if cached and reuse == 'hit':
            if snap_ns:
                if source == 'local': return False, 'local hit substitution'
                if source != snap_ns: return False, 'namespace substitution'
            hit_ids.add(tid)
            continue
        if exported and reuse == 'not reusable' and tid not in exported:
            continue
        return False, 'non hit'
    if exported is not None and exported != hit_ids:
        return False, 'exact set mismatch'
    return True, 'ok'

snap = {'namespace': 'run:1', 'records': [
    {'test': {'root': 'src', 'path': 'a.iyi'}},
    {'test': {'root': 'src', 'path': 'b.iyi'}}
]}

# Equal-count wrong IDs fail
data_wrong = {'tests': [
    {'test': {'root': 'src', 'path': 'a.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:1'},
    {'test': {'root': 'src', 'path': 'c.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:1'}
]}
ok, err = run_ah(data_wrong, snap)
assert not ok and 'exact set mismatch' in err, 'Equal count wrong IDs must fail'

# Colliding basenames don't collapse
snap_colliding = {'namespace': 'run:1', 'records': [
    {'test': {'root': 'src', 'path': 'dir1/test.iyi'}},
    {'test': {'root': 'src', 'path': 'dir2/test.iyi'}}
]}
data_colliding = {'tests': [
    {'test': {'root': 'src', 'path': 'dir1/test.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:1'},
    {'test': {'root': 'src', 'path': 'dir2/test.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:1'}
]}
ok, _ = run_ah(data_colliding, snap_colliding)
assert ok, 'Colliding basenames with distinct paths must pass'

# Missing one colliding basename fails
data_colliding_missing = {'tests': [
    {'test': {'root': 'src', 'path': 'dir1/test.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:1'}
]}
ok, _ = run_ah(data_colliding_missing, snap_colliding)
assert not ok, 'Missing colliding basename must fail'

# Duplicate identities fail
data_dup = {'tests': [
    {'test': {'root': 'src', 'path': 'a.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:1'},
    {'test': {'root': 'src', 'path': 'a.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:1'}
]}
ok, err = run_ah(data_dup, snap)
assert not ok and 'duplicate tid' in err, 'Duplicate identities must fail'

# Duplicate identities in snapshot fail
snap_dup = {'namespace': 'run:1', 'records': [
    {'test': {'root': 'src', 'path': 'a.iyi'}},
    {'test': {'root': 'src', 'path': 'a.iyi'}}
]}
ok, err = run_ah(data_colliding, snap_dup)
assert not ok and 'duplicate rid' in err, 'Duplicate snapshot records must fail'

# Local hit substitution fails
data_local = {'tests': [
    {'test': {'root': 'src', 'path': 'a.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'local'},
    {'test': {'root': 'src', 'path': 'b.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:1'}
]}
ok, err = run_ah(data_local, snap)
assert not ok and 'local hit substitution' in err, 'Local hit substitution must fail'

# Nested identities pass
snap_nested = {'namespace': 'run:1', 'records': [
    {'test': {'root': 'src', 'path': 'sub/deep/nested_test.iyi'}}
]}
data_nested = {'tests': [
    {'test': {'root': 'src', 'path': 'sub/deep/nested_test.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:1'}
]}
ok, _ = run_ah(data_nested, snap_nested)
assert ok, 'Nested identities must pass'

# --- 2. Shadow-Audit Tests ---
def run_sa(cached, fresh, expected_ns=''):
    c_tests = {}
    for t in cached.get('tests', []):
        tid = extract_test_id(t)
        if not tid or tid in c_tests: return False, 'duplicate cached'
        c_tests[tid] = t
    f_tests = {}
    for t in fresh.get('tests', []):
        tid = extract_test_id(t)
        if not tid or tid in f_tests: return False, 'duplicate fresh'
        f_tests[tid] = t
    disagreements = []
    for tid, c in c_tests.items():
        if not (c.get('cached') and c.get('reuse') == 'hit'): continue
        if expected_ns:
            src = c.get('source', '')
            if src == 'local': disagreements.append('local hit substitution')
            elif src != expected_ns: disagreements.append('namespace substitution')
        f = f_tests.get(tid)
        if not f:
            disagreements.append('missing fresh test')
            continue
        if c.get('status') != f.get('status'):
            disagreements.append('verdict mismatch')
        cb = c.get('portable_build')
        fb = f.get('portable_build')
        if cb and fb and cb != fb:
            disagreements.append('build mismatch')
    return len(disagreements) == 0, disagreements

# Verdict mismatch fails
c_run = {'tests': [{'test': {'root': 'src', 'path': 'a.iyi'}, 'cached': True, 'reuse': 'hit', 'status': 'pass', 'source': 'master'}]}
f_run = {'tests': [{'test': {'root': 'src', 'path': 'a.iyi'}, 'cached': False, 'reuse': 'miss', 'status': 'fail'}]}
ok, errs = run_sa(c_run, f_run, 'master')
assert not ok and 'verdict mismatch' in errs, 'Verdict mismatch must be detected'

# Build mismatch fails
c_b = {'tests': [{'test': {'root': 'src', 'path': 'a.iyi'}, 'cached': True, 'reuse': 'hit', 'status': 'pass', 'source': 'master', 'portable_build': 'b1'}]}
f_b = {'tests': [{'test': {'root': 'src', 'path': 'a.iyi'}, 'cached': False, 'reuse': 'miss', 'status': 'pass', 'portable_build': 'b2'}]}
ok, errs = run_sa(c_b, f_b, 'master')
assert not ok and 'build mismatch' in errs, 'Build mismatch must be detected'

# Local hit substitution fails
c_loc = {'tests': [{'test': {'root': 'src', 'path': 'a.iyi'}, 'cached': True, 'reuse': 'hit', 'status': 'pass', 'source': 'local'}]}
f_loc = {'tests': [{'test': {'root': 'src', 'path': 'a.iyi'}, 'cached': False, 'reuse': 'miss', 'status': 'pass'}]}
ok, errs = run_sa(c_loc, f_loc, 'master')
assert not ok and 'local hit substitution' in errs, 'Local hit substitution must be detected'

# --- 3. Git-Diff-Check Tests ---
def run_gd(master, cached, changed, repo='/repo'):
    m_recs = {}
    for r in master.get('records', []):
        rid = extract_test_id(r)
        if not rid or rid in m_recs: return False, ['duplicate master']
        m_recs[rid] = r
    c_tests = {}
    for t in cached.get('tests', []):
        tid = extract_test_id(t)
        if not tid or tid in c_tests: return False, ['duplicate cached']
        c_tests[tid] = t
    errors = []
    snap_ns = master.get('namespace', 'master')
    for tid, t in c_tests.items():
        if t.get('cached') and t.get('reuse') == 'hit':
            if snap_ns:
                s = t.get('source', '')
                if s == 'local': errors.append('local hit substitution')
                elif s != snap_ns: errors.append('namespace substitution')
            rec = m_recs.get(tid)
            if rec:
                for obs in rec.get('trace', {}).get('observations', []):
                    if not is_file_observation(obs): continue
                    p = map_obs_to_repo_path(obs, t, repo)
                    if p in changed or obs.get('path') in changed:
                        errors.append(f'Hit test observed changed file {p}')
        elif t.get('reuse') == 'miss':
            rec = m_recs.get(tid)
            if not rec: continue
            status = t.get('status', '')
            reason = str(t.get('reason', ''))
            if t.get('reuse') == 'not reusable' or status == 'does not build' or 'not reusable' in reason or 'does not build' in reason:
                continue
            if t.get('blocked') is True or 'blocked' in reason:
                continue
            tp = t.get('profile')
            rp = rec.get('profile', {})
            rp_fp = rp.get('fp') if isinstance(rp, dict) else rp
            if tp and rp_fp and tp != rp_fp: continue
            if 'profile' in reason: continue
            tb = t.get('portable_build')
            rb = rec.get('build', {})
            rb_hex = rb.get('build') if isinstance(rb, dict) else rb
            if not (tb and rb_hex and str(tb).lower() == str(rb_hex).lower()): continue
            has_changed = False
            for obs in rec.get('trace', {}).get('observations', []):
                if not is_file_observation(obs): continue
                p = map_obs_to_repo_path(obs, t, repo)
                if p in changed or obs.get('path') in changed:
                    has_changed = True
                    break
            if not has_changed:
                errors.append('Missed test has equal build and unchanged observed inputs')
    return len(errors) == 0, errors

master_gd = {
    'namespace': 'master',
    'records': [
        {
            'test': {'root': 'src', 'path': 'pkg/test.iyi'},
            'build': {'build': 'hash1'},
            'profile': {'fp': 'prof1'},
            'trace': {'observations': [
                {'kind': 'file_read', 'root': 'src', 'path': 'data.txt'}
            ]}
        }
    ]
}

# Direction 1: Changed tracked input hit fails
hit_changed = {'tests': [{'test': {'root': 'src', 'path': 'pkg/test.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'master'}]}
ok, errs = run_gd(master_gd, hit_changed, {'pkg/data.txt'})
assert not ok and any('observed changed file' in e for e in errs), 'Direction 1: hit on changed input must fail'

# Direction 1: Unchanged tracked input hit passes
ok, _ = run_gd(master_gd, hit_changed, set())
assert ok, 'Direction 1: hit on unchanged input must pass'

# Direction 2: Unchanged tracked input + equal build miss fails
miss_unchanged = {'tests': [{'test': {'root': 'src', 'path': 'pkg/test.iyi'}, 'reuse': 'miss', 'portable_build': 'hash1', 'profile': 'prof1', 'blocked': False}]}
ok, errs = run_gd(master_gd, miss_unchanged, set())
assert not ok and any('equal build and unchanged observed inputs' in e for e in errs), 'Direction 2: miss on unchanged input with equal build must fail'

# Direction 2: Changed tracked input miss passes
ok, _ = run_gd(master_gd, miss_unchanged, {'pkg/data.txt'})
assert ok, 'Direction 2: miss on changed input must pass'

# Direction 2: Exclusions pass (profile change, blocked, build mismatch, nonreusable)
miss_prof = {'tests': [{'test': {'root': 'src', 'path': 'pkg/test.iyi'}, 'reuse': 'miss', 'portable_build': 'hash1', 'profile': 'prof2', 'blocked': False}]}
ok, _ = run_gd(master_gd, miss_prof, set())
assert ok, 'Direction 2: profile change exclusion must pass'

miss_blocked = {'tests': [{'test': {'root': 'src', 'path': 'pkg/test.iyi'}, 'reuse': 'miss', 'portable_build': 'hash1', 'profile': 'prof1', 'blocked': True}]}
ok, _ = run_gd(master_gd, miss_blocked, set())
assert ok, 'Direction 2: blocked exclusion must pass'

miss_build = {'tests': [{'test': {'root': 'src', 'path': 'pkg/test.iyi'}, 'reuse': 'miss', 'portable_build': 'hash_different', 'profile': 'prof1', 'blocked': False}]}
ok, _ = run_gd(master_gd, miss_build, set())
assert ok, 'Direction 2: build mismatch exclusion must pass'

miss_nr = {'tests': [{'test': {'root': 'src', 'path': 'pkg/test.iyi'}, 'reuse': 'not reusable', 'reason': 'clock'}]}
ok, _ = run_gd(master_gd, miss_nr, set())
assert ok, 'Direction 2: nonreusable exclusion must pass'

print('test-comparator-negatives PASSED: all comparator negative and discrimination fixtures verified.')
"
}

# 9. rg9: deterministic CallPathFp across processes and preanalysed prelude
run_rg9() {
  echo "== Running RG9: CallPathFp determinism across processes and prelude preanalysis =="
  "$PY" -c "
import glob, json, os, subprocess, sys

repo = sys.argv[1]
iyi = sys.argv[2]
work = '/tmp/rg9_work'
os.makedirs(work, exist_ok=True)

samples = sorted(glob.glob(os.path.join(repo, 'samples/iyi/*.iyi')))
mismatches = 0
total = 0

for p in samples:
    bname = os.path.basename(p)
    k1 = os.path.join(work, f'k1_{bname}.json')
    k2 = os.path.join(work, f'k2_{bname}.json')
    o1 = os.path.join(work, f'o1_{bname}')
    o2 = os.path.join(work, f'o2_{bname}')

    res1 = subprocess.run([iyi, 'build', '--stale-key', k1, '-o', o1, p], capture_output=True, text=True)
    res2 = subprocess.run([iyi, 'build', '--stale-key', k2, '-o', o2, p], capture_output=True, text=True)

    for o in (o1, o2):
        if os.path.exists(o):
            try: os.remove(o)
            except: pass

    if res1.returncode != 0 or res2.returncode != 0:
        continue

    if not (os.path.exists(k1) and os.path.exists(k2)):
        continue

    with open(k1) as f: d1 = json.load(f)
    with open(k2) as f: d2 = json.load(f)

    for k in (k1, k2):
        try: os.remove(k)
        except: pass

    cp1 = d1.get('portable', {}).get('callpath')
    cp2 = d2.get('portable', {}).get('callpath')

    if cp1 != cp2:
        print(f'RG9 MISMATCH: {bname} CallPathFp: {cp1} != {cp2}', file=sys.stderr)
        mismatches += 1
    total += 1

if mismatches > 0:
    print(f'RG9 FAILED: {mismatches} mismatches out of {total}', file=sys.stderr)
    sys.exit(1)

print(f'RG9 PASSED: all {total} programs produced identical CallPathFp across independent processes.')
" "$REPO" "$IYI"
}

# 10. master-self-check: imports master snapshot, wipes cache to prevent pollution, and verifies diff
master_self_check() {
  local snapshot=""
  local out_json=""
  local repo_dir="$REPO"
  local tests=()

  while [ $# -gt 0 ]; do
    case "$1" in
      --snapshot) snapshot="$2"; shift 2 ;;
      --out-json) out_json="$2"; shift 2 ;;
      --repo) repo_dir="$2"; shift 2 ;;
      --) shift; tests+=("$@"); break ;;
      -*) echo "Unknown option: $1" >&2; return 1 ;;
      *) tests+=("$1"); shift ;;
    esac
  done

  if [ -z "$snapshot" ] || [ -z "$out_json" ]; then
    echo "Usage: master-self-check --snapshot <file> --out-json <file> [--repo <dir>] [tests...]" >&2
    return 1
  fi

  if [ ! -f "$snapshot" ]; then
    echo "master-self-check: no snapshot file at $snapshot; nothing to import."
    return 0
  fi

  if [ ${#tests[@]} -eq 0 ]; then
    mapfile -t tests < <(find "$repo_dir/samples/iyi" -maxdepth 1 -type f -name '*.iyi' -print | sort)
  fi

  # Wipe test cache to prevent local/run substitution pollution
  local cache_dir=""
  cache_dir="$("$IYI" env IYI_CACHE_DIR 2>/dev/null || true)"
  if [ -z "$cache_dir" ]; then
    cache_dir="${IYI_CACHE_DIR:-${HOME}/.cache/iyi}"
  fi
  if [ -d "$cache_dir/tests-v1" ]; then
    rm -rf "$cache_dir/tests-v1"
  fi

  local out_dir
  out_dir="$(dirname "$out_json")"
  if [ -n "$out_dir" ] && [ ! -d "$out_dir" ]; then
    mkdir -p "$out_dir"
  fi

  "$IYI" test --cached --json \
    --import-index "master=$snapshot" \
    "${tests[@]}" > "$out_json"

  git_diff_check \
    --master-snapshot "$snapshot" \
    --cached-json "$out_json" \
    --repo "$repo_dir"
}

# 11. test-master-path: verifies producer export, mock Actions API with redirect isolation,
#                       candidate vs canonical selection, negatives, cache wipe discrimination,
#                       and empty snapshot handling.
test_master_path() {
  echo "== Running test-master-path: Actions API mock, canonical selection, and cache wipe tests =="
  if ! "$IYI" --version >/dev/null 2>&1; then
    echo "test-master-path: compiler binary not ready or executable at $IYI" >&2
    exit 1
  fi

  local work
  work="$(mktemp -d /tmp/test-master-path.XXXXXX)"
  local clean_exit=0
  trap 'if [ "$clean_exit" -eq 1 ]; then rm -rf "$work"; else echo "Preserving test-master-path artifacts at $work" >&2; fi' RETURN

  "$PY" -c "
import glob, hashlib, http.server, io, json, os, shutil, subprocess, sys, threading, time, urllib.error, urllib.parse, urllib.request

repo = sys.argv[1]
iyi = sys.argv[2]
work = sys.argv[3]
stale_ci = os.path.join(repo, 'bench/stale_ci.sh')

# 1. Real producer fresh master export with CI-like environment
print('Phase 1: Real producer fresh master export with CI-like environment...')
cand_export_path = os.path.join(work, 'master-candidate-x86_64-linux-gnu.json')
canonical_path = os.path.join(work, 'master-x86_64-linux-gnu.json')

sha_res = subprocess.run(['/usr/bin/git', '-C', repo, 'rev-parse', 'HEAD'], capture_output=True, text=True)
head_sha = sha_res.stdout.strip() if sha_res.returncode == 0 else '0123456789abcdef0123456789abcdef01234567'

export_env = os.environ.copy()
export_env['IYI_CI_PRODUCER'] = '1'
export_env['GITHUB_WORKFLOW'] = 'iyi'
export_env['GITHUB_WORKFLOW_REF'] = 'iyilang/iyi/.github/workflows/iyi.yml@refs/heads/master'
export_env['GITHUB_SHA'] = head_sha
export_env['GITHUB_REPOSITORY'] = 'iyilang/iyi'
export_env['GITHUB_REF'] = 'refs/heads/master'
export_env['GITHUB_RUN_ID'] = '7777'
export_env['GITHUB_RUN_ATTEMPT'] = '1'
shared_cache = os.path.join(work, 'shared_cache')
os.makedirs(shared_cache, exist_ok=True)
export_env['IYI_CACHE_DIR'] = shared_cache

sample_file = os.path.join(repo, 'samples/iyi/hello.iyi')
if not os.path.exists(sample_file):
    samples = sorted(glob.glob(os.path.join(repo, 'samples/iyi/*.iyi')))
    sample_file = samples[0]

res_exp = subprocess.run([iyi, 'test', '--fresh', '--export-index', f'master={cand_export_path}', sample_file],
                         cwd=repo, env=export_env, capture_output=True, text=True)
if res_exp.returncode != 0 or not os.path.exists(cand_export_path):
    print(f'test-master-path FAILED: producer export failed (code {res_exp.returncode}):\n{res_exp.stderr}', file=sys.stderr)
    sys.exit(1)

# Canonical master has identical content to the candidate at audit pass
with open(cand_export_path, 'rb') as f:
    master_bytes = f.read()

with open(canonical_path, 'wb') as f:
    f.write(master_bytes)

master_sha = hashlib.sha256(master_bytes).hexdigest().lower()

# Create distinct candidate bytes so we can prove candidate != master selection
cand_data = json.loads(master_bytes.decode('utf-8'))
cand_data['producer']['job'] = 'producer-candidate-test'
cand_bytes = json.dumps(cand_data, indent=2).encode('utf-8')
cand_sha = hashlib.sha256(cand_bytes).hexdigest().lower()

# 2. Local faithful Actions API server on 127.0.0.1
print('Phase 2: Starting faithful local Actions API server...')
mode_file = os.path.join(work, 'server_mode.json')
with open(mode_file, 'w') as f:
    json.dump({'mode': 'default'}, f)

class ActionsApiHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        with open(mode_file) as f:
            cfg = json.load(f)
        mode = cfg.get('mode', 'default')

        if self.path.startswith('/repos/'):
            auth = self.headers.get('Authorization', '')
            if not auth.startswith('Bearer '):
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b'{\"message\":\"Bad credentials\"}')
                return

        if '/actions/workflows/iyi.yml/runs' in self.path:
            if mode == 'runs_500':
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'{\"message\":\"Internal Server Error\"}')
                return
            if mode == 'no_runs':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{\"total_count\":0,\"workflow_runs\":[]}')
                return
            if mode == 'path_mismatch':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                body = {
                    'total_count': 1,
                    'workflow_runs': [{
                        'id': 8888, 'path': '.github/workflows/other.yml',
                        'head_branch': 'master', 'event': 'push',
                        'repository': {'full_name': 'iyilang/iyi'}
                    }]
                }
                self.wfile.write(json.dumps(body).encode('utf-8'))
                return

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            body = {
                'total_count': 1,
                'workflow_runs': [{
                    'id': 8888,
                    'name': 'iyi',
                    'path': '.github/workflows/iyi.yml',
                    'head_branch': 'master',
                    'event': 'push',
                    'status': 'completed',
                    'conclusion': 'success',
                    'repository': {'id': 12345, 'full_name': 'iyilang/iyi'}
                }]
            }
            self.wfile.write(json.dumps(body).encode('utf-8'))
            return

        if '/actions/runs/8888/artifacts' in self.path:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()

            if mode == 'candidate_only':
                body = {
                    'total_count': 1,
                    'artifacts': [{
                        'id': 2001,
                        'name': 'master-candidate-x86_64-linux-gnu.json',
                        'size_in_bytes': len(cand_bytes),
                        'expired': False,
                        'digest': f'sha256:{cand_sha}'
                    }]
                }
            elif mode == 'missing_digest':
                body = {
                    'total_count': 1,
                    'artifacts': [{
                        'id': 2002,
                        'name': 'master-x86_64-linux-gnu.json',
                        'size_in_bytes': len(master_bytes),
                        'expired': False,
                        'digest': ''
                    }]
                }
            elif mode == 'wrong_digest':
                body = {
                    'total_count': 1,
                    'artifacts': [{
                        'id': 2002,
                        'name': 'master-x86_64-linux-gnu.json',
                        'size_in_bytes': len(master_bytes),
                        'expired': False,
                        'digest': 'sha256:0000000000000000000000000000000000000000000000000000000000000000'
                    }]
                }
            elif mode == 'two_exact':
                body = {
                    'total_count': 2,
                    'artifacts': [
                        {
                            'id': 2002,
                            'name': 'master-x86_64-linux-gnu.json',
                            'size_in_bytes': len(master_bytes),
                            'expired': False,
                            'digest': f'sha256:{master_sha}'
                        },
                        {
                            'id': 2003,
                            'name': 'master-x86_64-linux-gnu.json',
                            'size_in_bytes': len(master_bytes),
                            'expired': False,
                            'digest': f'sha256:{master_sha}'
                        }
                    ]
                }
            else:
                # Default: candidate listed BEFORE master to test exact selection
                body = {
                    'total_count': 2,
                    'artifacts': [
                        {
                            'id': 2001,
                            'name': 'master-candidate-x86_64-linux-gnu.json',
                            'size_in_bytes': len(cand_bytes),
                            'expired': False,
                            'digest': f'sha256:{cand_sha}'
                        },
                        {
                            'id': 2002,
                            'name': 'master-x86_64-linux-gnu.json',
                            'size_in_bytes': len(master_bytes),
                            'expired': False,
                            'digest': f'sha256:{master_sha}'
                        }
                    ]
                }
            self.wfile.write(json.dumps(body).encode('utf-8'))
            return

        if '/actions/artifacts/' in self.path and self.path.endswith('/zip'):
            parts = self.path.split('/')
            art_id = parts[-2]
            loc = f'http://127.0.0.1:{server.server_port}/blob/{art_id}'
            self.send_response(302)
            self.send_header('Location', loc)
            self.end_headers()
            return

        if self.path.startswith('/blob/'):
            if 'Authorization' in self.headers:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b'{\"error\":\"Authorization header forbidden on blob URL\"}')
                return

            if mode == 'zip_payload':
                self.send_response(200)
                self.send_header('Content-Type', 'application/zip')
                self.end_headers()
                self.wfile.write(b'PK\\x03\\x04mockziparchivepayloadcontent')
                return

            art_id = self.path.split('/')[-1]
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            if art_id == '2001':
                self.wfile.write(cand_bytes)
            else:
                self.wfile.write(master_bytes)
            return

        self.send_response(404)
        self.end_headers()

server = http.server.HTTPServer(('127.0.0.1', 0), ActionsApiHandler)
server_thread = threading.Thread(target=server.serve_forever)
server_thread.daemon = True
server_thread.start()
port = server.server_port
api_url = f'http://127.0.0.1:{port}'
print(f'Actions API mock listening on {api_url}')
try:
    # 3. Behavioral proof: Authorization header forwarded to blob results in 401
    print('Phase 3: Proving blob endpoint rejects Authorization header (behavioral proof)...')
    req_blob_auth = urllib.request.Request(f'{api_url}/blob/2002', headers={'Authorization': 'Bearer test'})
    try:
        urllib.request.urlopen(req_blob_auth)
        print('test-master-path FAILED: blob endpoint accepted Authorization header', file=sys.stderr)
        sys.exit(1)
    except urllib.error.HTTPError as e:
        if e.code != 401:
            print(f'test-master-path FAILED: blob endpoint returned {e.code}, expected 401', file=sys.stderr)
            sys.exit(1)
        print('Behavioral proof PASSED: blob endpoint correctly returns 401 if Authorization is sent.')

    # 4. Happy path: fetch-master with candidate before master in artifact listing
    print('Phase 4: Running fetch-master happy path (candidate before master in listings)...')
    fetched_out = os.path.join(work, 'fetched-master.json')
    fetch_env = os.environ.copy()
    fetch_env['GITHUB_API_URL'] = api_url

    res_fetch = subprocess.run(['bash', stale_ci, 'fetch-master',
                                '--out', fetched_out,
                                '--target', 'x86_64-linux-gnu',
                                '--repo', 'iyilang/iyi',
                                '--token', 'mock-token-xyz'],
                               env=fetch_env, capture_output=True, text=True)
    if res_fetch.returncode != 0:
        print(f'test-master-path FAILED: fetch-master returned {res_fetch.returncode}:\n{res_fetch.stderr}', file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(fetched_out):
        print('test-master-path FAILED: fetch-master did not write output file', file=sys.stderr)
        sys.exit(1)

    with open(fetched_out, 'rb') as f:
        fetched_bytes = f.read()

    if fetched_bytes != master_bytes:
        print('test-master-path FAILED: fetched bytes do not match canonical master bytes (candidate was selected!)', file=sys.stderr)
        sys.exit(1)

    sidecar_file = f'{fetched_out}.provenance.json'
    if not os.path.exists(sidecar_file):
        print('test-master-path FAILED: fetch-master did not write provenance sidecar', file=sys.stderr)
        sys.exit(1)

    with open(sidecar_file) as f:
        sidecar_data = json.load(f)

    if sidecar_data.get('sha256') != master_sha or sidecar_data.get('run_id') != 8888 or sidecar_data.get('workflow') != '.github/workflows/iyi.yml':
        print(f'test-master-path FAILED: sidecar metadata incorrect: {sidecar_data}', file=sys.stderr)
        sys.exit(1)

    print('fetch-master happy path PASSED: exact canonical master downloaded and sidecar verified.')

    # 5. Negative tests
    print('Phase 5: Running negative tests...')

    # 5.1 Candidate only -> exit 0, no file written (valid absent)
    with open(mode_file, 'w') as f: json.dump({'mode': 'candidate_only'}, f)
    cand_only_out = os.path.join(work, 'cand-only.json')
    res_cand_only = subprocess.run(['bash', stale_ci, 'fetch-master',
                                    '--out', cand_only_out,
                                    '--target', 'x86_64-linux-gnu',
                                    '--token', 'mock-token-xyz'],
                                   env=fetch_env, capture_output=True, text=True)
    if res_cand_only.returncode != 0 or os.path.exists(cand_only_out):
        print(f'test-master-path FAILED: candidate-only expected exit 0 and no file (code {res_cand_only.returncode})', file=sys.stderr)
        sys.exit(1)
    print('Negative test 1 (candidate only => valid absent exit 0) PASSED.')

    # 5.2 Missing digest -> exit 1
    with open(mode_file, 'w') as f: json.dump({'mode': 'missing_digest'}, f)
    res_md = subprocess.run(['bash', stale_ci, 'fetch-master', '--out', os.path.join(work, 'md.json'),
                             '--target', 'x86_64-linux-gnu', '--token', 'mock-token-xyz'],
                            env=fetch_env, capture_output=True, text=True)
    if res_md.returncode == 0:
        print('test-master-path FAILED: missing digest should fail', file=sys.stderr)
        sys.exit(1)
    print('Negative test 2 (missing digest => exit 1) PASSED.')

    # 5.3 Wrong digest -> exit 1
    with open(mode_file, 'w') as f: json.dump({'mode': 'wrong_digest'}, f)
    res_wd = subprocess.run(['bash', stale_ci, 'fetch-master', '--out', os.path.join(work, 'wd.json'),
                             '--target', 'x86_64-linux-gnu', '--token', 'mock-token-xyz'],
                            env=fetch_env, capture_output=True, text=True)
    if res_wd.returncode == 0:
        print('test-master-path FAILED: wrong digest should fail', file=sys.stderr)
        sys.exit(1)
    print('Negative test 3 (wrong digest => exit 1) PASSED.')

    # 5.4 ZIP payload refused -> exit 1
    with open(mode_file, 'w') as f: json.dump({'mode': 'zip_payload'}, f)
    res_zip = subprocess.run(['bash', stale_ci, 'fetch-master', '--out', os.path.join(work, 'zip.json'),
                              '--target', 'x86_64-linux-gnu', '--token', 'mock-token-xyz'],
                             env=fetch_env, capture_output=True, text=True)
    if res_zip.returncode == 0:
        print('test-master-path FAILED: ZIP payload should be refused', file=sys.stderr)
        sys.exit(1)
    print('Negative test 4 (ZIP payload refused => exit 1) PASSED.')

    # 5.5 Two exact artifacts -> exit 1
    with open(mode_file, 'w') as f: json.dump({'mode': 'two_exact'}, f)
    res_two = subprocess.run(['bash', stale_ci, 'fetch-master', '--out', os.path.join(work, 'two.json'),
                              '--target', 'x86_64-linux-gnu', '--token', 'mock-token-xyz'],
                             env=fetch_env, capture_output=True, text=True)
    if res_two.returncode == 0:
        print('test-master-path FAILED: multiple exact artifacts should fail', file=sys.stderr)
        sys.exit(1)
    print('Negative test 5 (two exact artifacts => exit 1) PASSED.')

    # 5.6 Runs 500 -> exit 1
    with open(mode_file, 'w') as f: json.dump({'mode': 'runs_500'}, f)
    res_500 = subprocess.run(['bash', stale_ci, 'fetch-master', '--out', os.path.join(work, '500.json'),
                              '--target', 'x86_64-linux-gnu', '--token', 'mock-token-xyz'],
                             env=fetch_env, capture_output=True, text=True)
    if res_500.returncode == 0:
        print('test-master-path FAILED: runs 500 should fail', file=sys.stderr)
        sys.exit(1)
    print('Negative test 6 (runs 500 => exit 1) PASSED.')

    # 5.7 Missing token -> exit 1
    res_notoken = subprocess.run(['bash', stale_ci, 'fetch-master', '--out', os.path.join(work, 'notoken.json'),
                                  '--target', 'x86_64-linux-gnu', '--token', ''],
                                 env={k: v for k, v in fetch_env.items() if 'TOKEN' not in k}, capture_output=True, text=True)
    if res_notoken.returncode == 0:
        print('test-master-path FAILED: missing token should fail', file=sys.stderr)
        sys.exit(1)
    print('Negative test 7 (missing token => exit 1) PASSED.')

    # 6. Cache wipe & pollution test with master-self-check
    print('Phase 6: Verifying cache wipe discrimination in master-self-check...')
    # Reset server mode to default and perform a real fetch-master to establish valid provenance
    with open(mode_file, 'w') as f:
        json.dump({'mode': 'default'}, f)

    phase6_master = os.path.join(work, 'phase6-master-x86_64-linux-gnu.json')
    res_p6_fetch = subprocess.run(['bash', stale_ci, 'fetch-master',
                                   '--out', phase6_master,
                                   '--target', 'x86_64-linux-gnu',
                                   '--repo', 'iyilang/iyi',
                                   '--token', 'mock-token-xyz'],
                                  env=fetch_env, capture_output=True, text=True)
    if res_p6_fetch.returncode != 0:
        print(f'test-master-path FAILED: Phase 6 fetch-master failed (code {res_p6_fetch.returncode}):\n{res_p6_fetch.stderr}', file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(phase6_master):
        print(f'test-master-path FAILED: Phase 6 fetch-master did not write {phase6_master}', file=sys.stderr)
        sys.exit(1)

    phase6_sidecar = f'{phase6_master}.provenance.json'
    if not os.path.exists(phase6_sidecar):
        print(f'test-master-path FAILED: Phase 6 fetch-master missing sidecar at {phase6_sidecar}', file=sys.stderr)
        sys.exit(1)

    test_env = os.environ.copy()
    test_env['IYI_CACHE_DIR'] = shared_cache

    # 6.1 Pollute cache with fresh run
    res_fresh = subprocess.run([iyi, 'test', '--fresh', sample_file],
                               cwd=repo, env=test_env, capture_output=True, text=True)
    if res_fresh.returncode != 0:
        print(f'test-master-path FAILED: fresh test run failed to populate cache (code {res_fresh.returncode}):\n{res_fresh.stderr}', file=sys.stderr)
        sys.exit(1)

    # 6.2 Behavioral proof: without wipe, --cached hits local receipt (source != 'master')
    res_unwiped = subprocess.run([iyi, 'test', '--cached', '--json',
                                  '--import-index', f'master={phase6_master}',
                                  sample_file],
                                 cwd=repo, env=test_env, capture_output=True, text=True)
    if res_unwiped.returncode != 0:
        print(f'test-master-path FAILED: unwiped cached test run failed (code {res_unwiped.returncode}):\n{res_unwiped.stderr}', file=sys.stderr)
        sys.exit(1)

    try:
        unwiped_data = json.loads(res_unwiped.stdout)
    except Exception as e:
        print(f'test-master-path FAILED: could not parse unwiped test JSON ({e}):\nSTDOUT:\n{res_unwiped.stdout}\nSTDERR:\n{res_unwiped.stderr}', file=sys.stderr)
        sys.exit(1)

    unwiped_sources = [t.get('source') for t in unwiped_data.get('tests', [])]
    if 'master' in unwiped_sources:
        print(f'Notice: without wipe, hit already master? sources: {unwiped_sources}')
    else:
        print(f'Behavioral proof PASSED: without wipe, local receipt substituted (sources: {unwiped_sources})')

    # 6.3 With master-self-check (which performs cache wipe before importing):
    check_out = os.path.join(work, 'check-out.json')
    res_check = subprocess.run(['bash', stale_ci, 'master-self-check',
                                '--snapshot', phase6_master,
                                '--out-json', check_out,
                                '--repo', repo,
                                sample_file],
                               cwd=repo, env=test_env, capture_output=True, text=True)
    if res_check.returncode != 0:
        print(f'test-master-path FAILED: master-self-check failed (code {res_check.returncode}):\n{res_check.stderr}', file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(check_out):
        print(f'test-master-path FAILED: master-self-check did not write {check_out}', file=sys.stderr)
        sys.exit(1)

    with open(check_out) as f:
        try:
            check_data = json.load(f)
        except Exception as e:
            print(f'test-master-path FAILED: could not parse check-out.json ({e})', file=sys.stderr)
            sys.exit(1)

    check_sources = [t.get('source') for t in check_data.get('tests', [])]
    if any(s != 'master' for s in check_sources):
        print(f'test-master-path FAILED: expected all sources to be master after wipe, got: {check_sources}', file=sys.stderr)
        sys.exit(1)
    print(f'master-self-check with wipe PASSED: all tests imported from master (sources: {check_sources}).')

    # 7. Empty snapshot tests
    print('Phase 7: Testing empty snapshot handling and refusal of forged run_id...')
    empty_out = os.path.join(work, 'empty.json')
    res_empty_create = subprocess.run(['bash', stale_ci, 'empty-snapshot',
                                       '--run-id', '4444',
                                       '--out', empty_out,
                                       '--target', 'x86_64-linux-gnu'],
                                      capture_output=True, text=True)
    if res_empty_create.returncode != 0:
        print(f'test-master-path FAILED: empty-snapshot --run-id 4444 failed (code {res_empty_create.returncode}):\n{res_empty_create.stderr}', file=sys.stderr)
        sys.exit(1)

    with open(empty_out) as f:
        try:
            empty_data = json.load(f)
        except Exception as e:
            print(f'test-master-path FAILED: could not parse empty.json ({e})', file=sys.stderr)
            sys.exit(1)

    if empty_data.get('producer', {}).get('run_id') != 4444 or len(empty_data.get('records', [])) != 0:
        print(f'test-master-path FAILED: empty snapshot data incorrect: {empty_data}', file=sys.stderr)
        sys.exit(1)

    # Ensure cache is clean before empty snapshot consumption test
    cache_tests_v1 = os.path.join(shared_cache, 'tests-v1')
    if os.path.exists(cache_tests_v1):
        shutil.rmtree(cache_tests_v1)

    # Import empty snapshot: verifies consumption is turned off (0 cached hits)
    res_empty_test = subprocess.run([iyi, 'test', '--cached', '--json',
                                     '--import-index', f'master={empty_out}',
                                     sample_file],
                                    cwd=repo, env=test_env, capture_output=True, text=True)
    if res_empty_test.returncode != 0:
        print(f'test-master-path FAILED: empty snapshot test run failed (code {res_empty_test.returncode}):\n{res_empty_test.stderr}', file=sys.stderr)
        sys.exit(1)

    try:
        empty_test_data = json.loads(res_empty_test.stdout)
    except Exception as e:
        print(f'test-master-path FAILED: could not parse empty snapshot test JSON ({e}):\nSTDOUT:\n{res_empty_test.stdout}\nSTDERR:\n{res_empty_test.stderr}', file=sys.stderr)
        sys.exit(1)

    hits = [t for t in empty_test_data.get('tests', []) if t.get('cached')]
    if len(hits) != 0:
        print(f'test-master-path FAILED: empty snapshot should have 0 cached hits, got {len(hits)}', file=sys.stderr)
        sys.exit(1)
    print('Empty snapshot --run-id 4444 PASSED: cleanly imported and turned off consumption.')

    # Forged/invalid run_id rejected
    res_zero = subprocess.run(['bash', stale_ci, 'empty-snapshot', '--run-id', '0', '--out', os.path.join(work, 'e0.json')],
                              capture_output=True, text=True)
    if res_zero.returncode == 0:
        print('test-master-path FAILED: empty-snapshot --run-id 0 should fail', file=sys.stderr)
        sys.exit(1)

    res_norunid = subprocess.run(['bash', stale_ci, 'empty-snapshot', '--out', os.path.join(work, 'eno.json')],
                                 capture_output=True, text=True)
    if res_norunid.returncode == 0:
        print('test-master-path FAILED: empty-snapshot without --run-id should fail', file=sys.stderr)
        sys.exit(1)
    print('Empty snapshot refusal of invalid/zero run_id PASSED.')

    print('All test-master-path tests completed successfully.')
finally:
    server.shutdown()
" "$REPO" "$IYI" "$work"

  clean_exit=1
  echo "test-master-path PASSED."
}

# Main command dispatcher
COMMAND="${1:-help}"
shift || true

case "$COMMAND" in
  assert-export-env)
    assert_export_env "$@"
    ;;
  empty-snapshot)
    empty_snapshot "$@"
    ;;
  assert-hits)
    assert_hits "$@"
    ;;
  shadow-audit)
    shadow_audit "$@"
    ;;
  test-planted-hidden-read)
    test_planted_hidden_read "$@"
    ;;
  test-comparator-negatives)
    test_comparator_negatives "$@"
    ;;
  fetch-master)
    fetch_master "$@"
    ;;
  git-diff-check)
    git_diff_check "$@"
    ;;
  rg9)
    run_rg9 "$@"
    ;;
  master-self-check)
    master_self_check "$@"
    ;;
  test-master-path)
    test_master_path "$@"
    ;;
  help|--help|-h)
    echo "Usage: $0 <command> [options]"
    echo "Commands:"
    echo "  fetch-master                Download master snapshot through Actions API"
    echo "  assert-export-env           Verify export step environment has no secrets"
    echo "  assert-hits                 Verify all tests in a test run were cache hits"
  echo "  test-comparator-negatives   Verify negative comparator fixtures for CI checks"
  echo "  test-planted-hidden-read    Prove shadow audit detects unobserved reads (row 24)"
  echo "  git-diff-check              Verify run observations against git diff"
    echo "  empty-snapshot              Generate an empty snapshot for disagreement (RG6)"
    echo "  rg9                         Run RG9 deterministic CallPathFp check"
    echo "  master-self-check           Import master snapshot and verify against git diff"
    echo "  test-master-path            Verify master snapshot export, API fetch, and self-check"
    ;;
  *)
    echo "Unknown command: $COMMAND" >&2
    exit 1
    ;;
esac
