#!/usr/bin/env bash
# CI driver and support tools for stale testing (S9, job iyi and stale-fresh).
#
#     bash bench/stale_ci.sh <command> [options]
#
# Commands:
#     fetch-master                Download master snapshot through Actions API
#     assert-export-env           Verify export step environment has no secrets
#     assert-hits                 Verify all tests in a test run were cache hits
#     test-comparator-negatives   Verify negative comparator fixtures for CI checks
#     test-planted-hidden-read    Prove shadow audit detects unobserved reads (row 24)
#     git-diff-check              Verify run observations against git diff
#     empty-snapshot              Generate an empty snapshot for disagreement (RG6)
#     rg9                         Run RG9 deterministic CallPathFp check
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
  local repo="github.com/iyilang/iyi"
  local wf=".github/workflows/iyi.yml"

  while [ $# -gt 0 ]; do
    case "$1" in
      --out) out="$2"; shift 2 ;;
      --target) target="$2"; shift 2 ;;
      --namespace) ns="$2"; shift 2 ;;
      --repo) repo="$2"; shift 2 ;;
      --workflow) wf="$2"; shift 2 ;;
      *) echo "Unknown option: $1" >&2; return 1 ;;
    esac
  done

  "$PY" -c "
import json, sys
out, target, ns, repo, wf = sys.argv[1:6]
data = {
    'format': 'iyi-test-index',
    'version': 1,
    'namespace': ns,
    'repository': repo,
    'workflow': wf,
    'ref': 'refs/heads/master',
    'target': target,
    'producer': {
        'run_id': 0,
        'run_attempt': 1,
        'sha': '',
        'job': 'stale-fresh',
        'shard': '1/1'
    },
    'records': []
}
with open(out, 'w') as f:
    json.dump(data, f, indent=2)
print(f'empty-snapshot: wrote empty snapshot to {out}')
" "$out" "$target" "$ns" "$repo" "$wf"
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
  local mock_api=""
  local mock_artifact=""

  while [ $# -gt 0 ]; do
    case "$1" in
      --out) out="$2"; shift 2 ;;
      --target) target="$2"; shift 2 ;;
      --repo) repo="$2"; shift 2 ;;
      --token) token="$2"; shift 2 ;;
      --mock-api-file) mock_api="$2"; shift 2 ;;
      --mock-artifact-file) mock_artifact="$2"; shift 2 ;;
      *) echo "Unknown option: $1" >&2; return 1 ;;
    esac
  done

  "$PY" -c "
import json, sys, os, hashlib, zipfile, io, urllib.request

out = sys.argv[1]
target = sys.argv[2]
repo = sys.argv[3]
token = sys.argv[4]
mock_api = sys.argv[5]
mock_artifact = sys.argv[6]

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

# A. Mock API testing path (for local verification without live API)
if mock_api and os.path.exists(mock_api):
    print(f'fetch-master: using mock API file {mock_api}')
    with open(mock_api) as f:
        api_data = json.load(f)
    runs = api_data.get('workflow_runs', [])
    master_run = None
    for r in runs:
        if r.get('head_branch') in ('master', 'refs/heads/master') and r.get('event') == 'push' and r.get('status') == 'completed' and r.get('path', '.github/workflows/iyi.yml') == '.github/workflows/iyi.yml':
            master_run = r
            break
    if not master_run:
        print('fetch-master: no completed master push run in mock data; importing nothing for master.')
        sys.exit(0)

    run_id = master_run.get('id', 0)
    run_repo = master_run.get('repository', {}).get('full_name', repo)
    run_wf = master_run.get('path', '.github/workflows/iyi.yml')

    artifacts = api_data.get('artifacts', [])
    target_artifact = None
    for a in artifacts:
        name = a.get('name', '')
        if name in (f'master-{target}.json', 'master.json', f'iyi-test-index-master-{target}.json') or (target in name and 'master' in name):
            target_artifact = a
            break

    if not target_artifact:
        print(f'fetch-master: run {run_id} has no artifact for target {target}; importing nothing for master.')
        sys.exit(0)

    if mock_artifact and os.path.exists(mock_artifact):
        with open(mock_artifact, 'rb') as f:
            content = f.read()
        with open(out, 'wb') as f:
            f.write(content)
        actual_sha256 = hashlib.sha256(content).hexdigest().lower()
        exp_digest = target_artifact.get('digest', '')
        if exp_digest:
            exp_hex = exp_digest.split(':')[-1].lower()
            if actual_sha256 != exp_hex:
                print(f'fetch-master FAILED: sha256 mismatch (expected {exp_hex}, got {actual_sha256})', file=sys.stderr)
                sys.exit(1)
        write_sidecar(out, actual_sha256, run_id, run_repo, run_wf, 'refs/heads/master')
        print(f'fetch-master: verified mock artifact and wrote {out}')
        sys.exit(0)

# B. Live Actions API path (only run in CI with github.token)
if not token:
    print('fetch-master: no token provided; skipping master fetch.')
    sys.exit(0)

headers = {
    'Authorization': f'Bearer {token}',
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'iyi-ci-fetch-master'
}
api_base = os.environ.get('GITHUB_API_URL', 'https://api.github.com')
runs_url = f'{api_base}/repos/{repo}/actions/runs?branch=master&event=push&status=completed&per_page=10'

try:
    req = urllib.request.Request(runs_url, headers=headers)
    with urllib.request.urlopen(req) as resp:
        runs_data = json.loads(resp.read().decode('utf-8'))
except Exception as e:
    print(f'fetch-master: query runs failed ({e}); importing nothing for master.')
    sys.exit(0)

runs = runs_data.get('workflow_runs', [])
master_run = None
for r in runs:
    if r.get('head_branch') in ('master', 'refs/heads/master') and r.get('event') == 'push' and r.get('status') == 'completed' and r.get('path', '.github/workflows/iyi.yml') == '.github/workflows/iyi.yml':
        master_run = r
        break

if not master_run:
    print('fetch-master: no completed master push run found; importing nothing for master.')
    sys.exit(0)

run_id = master_run['id']
run_repo = master_run.get('repository', {}).get('full_name', repo)
run_wf = master_run.get('path', '.github/workflows/iyi.yml')

artifacts_url = f'{api_base}/repos/{repo}/actions/runs/{run_id}/artifacts'
try:
    req_art = urllib.request.Request(artifacts_url, headers=headers)
    with urllib.request.urlopen(req_art) as resp:
        art_data = json.loads(resp.read().decode('utf-8'))
except Exception as e:
    print(f'fetch-master: query artifacts failed ({e}); importing nothing for master.')
    sys.exit(0)

target_art = None
for a in art_data.get('artifacts', []):
    name = a.get('name', '')
    if name in (f'master-{target}.json', 'master.json') or (target in name and 'master' in name):
        target_art = a
        break

if not target_art:
    print(f'fetch-master: run {run_id} has no artifact for target {target}; importing nothing for master.')
    sys.exit(0)

art_id = target_art['id']
download_url = f'{api_base}/repos/{repo}/actions/artifacts/{art_id}/zip'
try:
    req_dl = urllib.request.Request(download_url, headers=headers)
    with urllib.request.urlopen(req_dl) as resp:
        zip_bytes = resp.read()
except Exception as e:
    print(f'fetch-master: download artifact failed ({e}); importing nothing for master.')
    sys.exit(0)

with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
    names = z.namelist()
    if not names:
        print('fetch-master: artifact zip was empty; importing nothing for master.', file=sys.stderr)
        sys.exit(0)
    with z.open(names[0]) as zf, open(out, 'wb') as out_f:
        out_f.write(zf.read())

with open(out, 'rb') as f:
    content = f.read()
actual_sha256 = hashlib.sha256(content).hexdigest().lower()
exp_digest = target_art.get('digest', '')
if exp_digest:
    exp_hex = exp_digest.split(':')[-1].lower()
    if actual_sha256 != exp_hex:
        print(f'fetch-master FAILED: sha256 mismatch ({actual_sha256} != {exp_hex})', file=sys.stderr)
        sys.exit(1)

write_sidecar(out, actual_sha256, run_id, run_repo, run_wf, 'refs/heads/master')
print(f'fetch-master: successfully fetched and verified master snapshot for {target}')
" "$out" "$target" "$repo" "$token" "$mock_api" "$mock_artifact"
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
import os, sys, json, tempfile, subprocess, shutil

repo = sys.argv[1]
stale_ci = os.path.join(repo, 'bench/stale_ci.sh')

work = tempfile.mkdtemp(prefix='comp_neg_')
empty_repo = os.path.join(work, 'empty_repo')
os.makedirs(empty_repo, exist_ok=True)
empty_diff = os.path.join(work, 'empty_diff.txt')
with open(empty_diff, 'w') as f:
    pass

def run_cmd(subcmd, args, cwd=None):
    cmd = ['bash', stale_ci, subcmd] + args
    return subprocess.run(cmd, cwd=cwd or work, capture_output=True, text=True)

def assert_negative(subcmd, args, expected_msg, cwd=None):
    res = run_cmd(subcmd, args, cwd=cwd)
    combined = res.stdout + res.stderr
    assert res.returncode == 1, f'{subcmd} expected exit 1, got {res.returncode}. Output:\n{combined}'
    assert expected_msg in combined, f'{subcmd} expected \"{expected_msg}\" in output. Output:\n{combined}'

def assert_positive(subcmd, args, cwd=None):
    res = run_cmd(subcmd, args, cwd=cwd)
    combined = res.stdout + res.stderr
    assert res.returncode == 0, f'{subcmd} expected exit 0, got {res.returncode}. Output:\n{combined}'
    assert 'PASSED' in combined, f'{subcmd} expected PASSED in output. Output:\n{combined}'

# --- 1. assert-hits cases ---
snap_valid = os.path.join(work, 'snap_valid.json')
with open(snap_valid, 'w') as f:
    json.dump({
        'namespace': 'run:100',
        'records': [
            {'test': {'root': 'src', 'path': 'a.iyi'}},
            {'test': {'root': 'src', 'path': 'b.iyi'}}
        ]
    }, f)

# Duplicate identities in results
f_dup_results = os.path.join(work, 'ah_dup_res.json')
with open(f_dup_results, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'a.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:100'},
        {'test': {'root': 'src', 'path': 'a.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:100'}
    ]}, f)
assert_negative('assert-hits', ['--json', f_dup_results, '--snapshot', snap_valid], 'duplicate test identity')

# Duplicate identities in snapshot
snap_dup = os.path.join(work, 'snap_dup.json')
with open(snap_dup, 'w') as f:
    json.dump({
        'namespace': 'run:100',
        'records': [
            {'test': {'root': 'src', 'path': 'a.iyi'}},
            {'test': {'root': 'src', 'path': 'a.iyi'}}
        ]
    }, f)
f_valid_hits = os.path.join(work, 'ah_valid_hits.json')
with open(f_valid_hits, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'a.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:100'},
        {'test': {'root': 'src', 'path': 'b.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:100'}
    ]}, f)
assert_negative('assert-hits', ['--json', f_valid_hits, '--snapshot', snap_dup], 'snapshot contains duplicate test identity')

# Equal-count wrong IDs
f_wrong_ids = os.path.join(work, 'ah_wrong_ids.json')
with open(f_wrong_ids, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'a.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:100'},
        {'test': {'root': 'src', 'path': 'c.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:100'}
    ]}, f)
assert_negative('assert-hits', ['--json', f_wrong_ids, '--snapshot', snap_valid], 'hit identity set does not match snapshot identity set')

# Missing IDs
f_missing_ids = os.path.join(work, 'ah_missing_ids.json')
with open(f_missing_ids, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'a.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:100'}
    ]}, f)
assert_negative('assert-hits', ['--json', f_missing_ids, '--snapshot', snap_valid], 'Missing 1 hits')

# Unexpected IDs
snap_single = os.path.join(work, 'snap_single.json')
with open(snap_single, 'w') as f:
    json.dump({'namespace': 'run:100', 'records': [{'test': {'root': 'src', 'path': 'a.iyi'}}]}, f)
assert_negative('assert-hits', ['--json', f_valid_hits, '--snapshot', snap_single], 'Unexpected 1 hits')

# Local hit substitution
f_local_sub = os.path.join(work, 'ah_local_sub.json')
with open(f_local_sub, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'a.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'local'},
        {'test': {'root': 'src', 'path': 'b.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:100'}
    ]}, f)
assert_negative('assert-hits', ['--json', f_local_sub, '--snapshot', snap_valid], 'local hit substitution')

# Namespace substitution
f_ns_sub = os.path.join(work, 'ah_ns_sub.json')
with open(f_ns_sub, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'a.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:other'},
        {'test': {'root': 'src', 'path': 'b.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:100'}
    ]}, f)
assert_negative('assert-hits', ['--json', f_ns_sub, '--snapshot', snap_valid], 'namespace substitution')

# Unexcused miss
f_unexcused = os.path.join(work, 'ah_unexcused.json')
with open(f_unexcused, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'a.iyi'}, 'cached': False, 'reuse': 'miss', 'reason': 'changed'},
        {'test': {'root': 'src', 'path': 'b.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:100'}
    ]}, f)
assert_negative('assert-hits', ['--json', f_unexcused, '--snapshot', snap_valid], 'tests did not hit from cache')

# Excused not reusable (not in snapshot)
f_excused = os.path.join(work, 'ah_excused.json')
with open(f_excused, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'a.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:100'},
        {'test': {'root': 'src', 'path': 'b.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:100'},
        {'test': {'root': 'src', 'path': 'clock.iyi'}, 'cached': False, 'reuse': 'not reusable', 'reason': 'clock'}
    ]}, f)
assert_positive('assert-hits', ['--json', f_excused, '--snapshot', snap_valid])

# Colliding basenames don't collapse (both distinct pass)
snap_col = os.path.join(work, 'snap_col.json')
with open(snap_col, 'w') as f:
    json.dump({'namespace': 'run:100', 'records': [
        {'test': {'root': 'src', 'path': 'd1/t.iyi'}},
        {'test': {'root': 'src', 'path': 'd2/t.iyi'}}
    ]}, f)
f_col_pass = os.path.join(work, 'ah_col_pass.json')
with open(f_col_pass, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'd1/t.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:100'},
        {'test': {'root': 'src', 'path': 'd2/t.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:100'}
    ]}, f)
assert_positive('assert-hits', ['--json', f_col_pass, '--snapshot', snap_col])

# Nested identities pass
snap_nest = os.path.join(work, 'snap_nest.json')
with open(snap_nest, 'w') as f:
    json.dump({'namespace': 'run:100', 'records': [
        {'test': {'root': 'src', 'path': 'deep/sub/dir/test.iyi'}}
    ]}, f)
f_nest_pass = os.path.join(work, 'ah_nest_pass.json')
with open(f_nest_pass, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'deep/sub/dir/test.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:100'}
    ]}, f)
assert_positive('assert-hits', ['--json', f_nest_pass, '--snapshot', snap_nest])

# --- 2. shadow-audit cases ---
sa_dir = os.path.join(work, 'sa_run')
os.makedirs(sa_dir, exist_ok=True)

# Verdict mismatch (cached pass vs fresh fail)
c_fail = os.path.join(work, 'sa_c_fail.json')
with open(c_fail, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'a.iyi'}, 'status': 'pass', 'cached': True, 'reuse': 'hit', 'source': 'master'}
    ]}, f)
f_fail = os.path.join(work, 'sa_f_fail.json')
with open(f_fail, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'a.iyi'}, 'status': 'fail', 'cached': False, 'reuse': 'miss'}
    ]}, f)
assert_negative('shadow-audit', ['--cached-json', c_fail, '--fresh-json', f_fail], 'verdict mismatch', cwd=sa_dir)
assert os.path.exists(os.path.join(sa_dir, '.disagreement_marker')), 'shadow-audit must write .disagreement_marker'
os.remove(os.path.join(sa_dir, '.disagreement_marker'))

# Portable build mismatch in test result
c_build = os.path.join(work, 'sa_c_build.json')
with open(c_build, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'a.iyi'}, 'status': 'pass', 'cached': True, 'reuse': 'hit', 'source': 'master', 'portable_build': 'b1'}
    ]}, f)
f_build = os.path.join(work, 'sa_f_build.json')
with open(f_build, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'a.iyi'}, 'status': 'pass', 'cached': False, 'reuse': 'miss', 'portable_build': 'b2'}
    ]}, f)
assert_negative('shadow-audit', ['--cached-json', c_build, '--fresh-json', f_build], 'portable Build mismatch', cwd=sa_dir)
if os.path.exists(os.path.join(sa_dir, '.disagreement_marker')):
    os.remove(os.path.join(sa_dir, '.disagreement_marker'))

# Local hit substitution
c_loc = os.path.join(work, 'sa_c_loc.json')
with open(c_loc, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'a.iyi'}, 'status': 'pass', 'cached': True, 'reuse': 'hit', 'source': 'local'}
    ]}, f)
f_pass = os.path.join(work, 'sa_f_pass.json')
with open(f_pass, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'a.iyi'}, 'status': 'pass', 'cached': False, 'reuse': 'miss'}
    ]}, f)
assert_negative('shadow-audit', ['--cached-json', c_loc, '--fresh-json', f_pass, '--namespace', 'master'], 'local hit substitution', cwd=sa_dir)
if os.path.exists(os.path.join(sa_dir, '.disagreement_marker')):
    os.remove(os.path.join(sa_dir, '.disagreement_marker'))

# Namespace substitution
c_ns = os.path.join(work, 'sa_c_ns.json')
with open(c_ns, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'a.iyi'}, 'status': 'pass', 'cached': True, 'reuse': 'hit', 'source': 'run:other'}
    ]}, f)
assert_negative('shadow-audit', ['--cached-json', c_ns, '--fresh-json', f_pass, '--namespace', 'master'], 'namespace substitution', cwd=sa_dir)
if os.path.exists(os.path.join(sa_dir, '.disagreement_marker')):
    os.remove(os.path.join(sa_dir, '.disagreement_marker'))

# Missing fresh test
f_empty = os.path.join(work, 'sa_f_empty.json')
with open(f_empty, 'w') as f:
    json.dump({'tests': []}, f)
assert_negative('shadow-audit', ['--cached-json', c_fail, '--fresh-json', f_empty], 'missing from fresh audit', cwd=sa_dir)
if os.path.exists(os.path.join(sa_dir, '.disagreement_marker')):
    os.remove(os.path.join(sa_dir, '.disagreement_marker'))

# Snapshot Build mismatch
snap_b1 = os.path.join(work, 'snap_b1.json')
with open(snap_b1, 'w') as f:
    json.dump({'records': [{'test': {'root': 'src', 'path': 'a.iyi'}, 'build': {'build': 'hash1'}, 'trace': {'observations': []}}]}, f)
snap_b2 = os.path.join(work, 'snap_b2.json')
with open(snap_b2, 'w') as f:
    json.dump({'records': [{'test': {'root': 'src', 'path': 'a.iyi'}, 'build': {'build': 'hash2'}, 'trace': {'observations': []}}]}, f)
assert_negative('shadow-audit', ['--cached-json', c_fail, '--fresh-json', f_pass, '--cached-snapshot', snap_b1, '--fresh-snapshot', snap_b2], 'portable Build mismatch in snapshots', cwd=sa_dir)
if os.path.exists(os.path.join(sa_dir, '.disagreement_marker')):
    os.remove(os.path.join(sa_dir, '.disagreement_marker'))

# Ordered observations mismatch
snap_obs1 = os.path.join(work, 'snap_obs1.json')
with open(snap_obs1, 'w') as f:
    json.dump({'records': [{'test': {'root': 'src', 'path': 'a.iyi'}, 'build': {'build': 'hash1'}, 'trace': {'observations': [{'path': 'p1'}]}}]}, f)
snap_obs2 = os.path.join(work, 'snap_obs2.json')
with open(snap_obs2, 'w') as f:
    json.dump({'records': [{'test': {'root': 'src', 'path': 'a.iyi'}, 'build': {'build': 'hash1'}, 'trace': {'observations': [{'path': 'p2'}]}}]}, f)
assert_negative('shadow-audit', ['--cached-json', c_fail, '--fresh-json', f_pass, '--cached-snapshot', snap_obs1, '--fresh-snapshot', snap_obs2], 'ordered trace observation mismatch', cwd=sa_dir)
if os.path.exists(os.path.join(sa_dir, '.disagreement_marker')):
    os.remove(os.path.join(sa_dir, '.disagreement_marker'))

# Matching pass
assert_positive('shadow-audit', ['--cached-json', c_fail, '--fresh-json', f_pass, '--cached-snapshot', snap_b1, '--fresh-snapshot', snap_b1], cwd=sa_dir)

# --- 3. git-diff-check cases ---
# ALWAYS pass --changed-files FILE (empty okay) + --repo empty dir
snap_gd = os.path.join(work, 'snap_gd.json')
with open(snap_gd, 'w') as f:
    json.dump({
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
    }, f)

diff_changed = os.path.join(work, 'diff_changed.txt')
with open(diff_changed, 'w') as f:
    f.write('pkg/data.txt\n')

# Direction 1: Changed tracked input hit fails
f_gd_hit = os.path.join(work, 'gd_hit.json')
with open(f_gd_hit, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'pkg/test.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'master'}
    ]}, f)
assert_negative('git-diff-check', ['--master-snapshot', snap_gd, '--cached-json', f_gd_hit, '--changed-files', diff_changed, '--repo', empty_repo], 'observed changed file')

# Direction 1: Local hit substitution
f_gd_loc = os.path.join(work, 'gd_loc.json')
with open(f_gd_loc, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'pkg/test.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'local'}
    ]}, f)
assert_negative('git-diff-check', ['--master-snapshot', snap_gd, '--cached-json', f_gd_loc, '--changed-files', empty_diff, '--repo', empty_repo], 'local hit substitution')

# Direction 1: Namespace substitution
f_gd_ns = os.path.join(work, 'gd_ns.json')
with open(f_gd_ns, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'pkg/test.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'run:other'}
    ]}, f)
assert_negative('git-diff-check', ['--master-snapshot', snap_gd, '--cached-json', f_gd_ns, '--changed-files', empty_diff, '--repo', empty_repo], 'namespace substitution')

# Direction 1: Unchanged tracked input hit passes
assert_positive('git-diff-check', ['--master-snapshot', snap_gd, '--cached-json', f_gd_hit, '--changed-files', empty_diff, '--repo', empty_repo])

# Direction 2: Unchanged tracked input + equal build miss fails
f_gd_miss = os.path.join(work, 'gd_miss.json')
with open(f_gd_miss, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'pkg/test.iyi'}, 'reuse': 'miss', 'portable_build': 'hash1', 'profile': 'prof1', 'blocked': False}
    ]}, f)
assert_negative('git-diff-check', ['--master-snapshot', snap_gd, '--cached-json', f_gd_miss, '--changed-files', empty_diff, '--repo', empty_repo], 'has equal build and unchanged observed inputs but missed')

# Direction 2: Changed tracked input miss passes
assert_positive('git-diff-check', ['--master-snapshot', snap_gd, '--cached-json', f_gd_miss, '--changed-files', diff_changed, '--repo', empty_repo])

# Direction 2: Profile changed miss passes (exclusion)
f_gd_prof = os.path.join(work, 'gd_prof.json')
with open(f_gd_prof, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'pkg/test.iyi'}, 'reuse': 'miss', 'portable_build': 'hash1', 'profile': 'prof2', 'blocked': False}
    ]}, f)
assert_positive('git-diff-check', ['--master-snapshot', snap_gd, '--cached-json', f_gd_prof, '--changed-files', empty_diff, '--repo', empty_repo])

# Direction 2: Blocked miss passes (exclusion)
f_gd_blocked = os.path.join(work, 'gd_blocked.json')
with open(f_gd_blocked, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'pkg/test.iyi'}, 'reuse': 'miss', 'portable_build': 'hash1', 'profile': 'prof1', 'blocked': True}
    ]}, f)
assert_positive('git-diff-check', ['--master-snapshot', snap_gd, '--cached-json', f_gd_blocked, '--changed-files', empty_diff, '--repo', empty_repo])

# Direction 2: Build changed miss passes (exclusion)
f_gd_b = os.path.join(work, 'gd_b.json')
with open(f_gd_b, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'pkg/test.iyi'}, 'reuse': 'miss', 'portable_build': 'hash_different', 'profile': 'prof1', 'blocked': False}
    ]}, f)
assert_positive('git-diff-check', ['--master-snapshot', snap_gd, '--cached-json', f_gd_b, '--changed-files', empty_diff, '--repo', empty_repo])

# Direction 2: Not reusable miss passes (exclusion)
f_gd_nr = os.path.join(work, 'gd_nr.json')
with open(f_gd_nr, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'pkg/test.iyi'}, 'reuse': 'not reusable', 'reason': 'clock'}
    ]}, f)
assert_positive('git-diff-check', ['--master-snapshot', snap_gd, '--cached-json', f_gd_nr, '--changed-files', empty_diff, '--repo', empty_repo])

# Duplicate identities in master snapshot
snap_gd_dup = os.path.join(work, 'snap_gd_dup.json')
with open(snap_gd_dup, 'w') as f:
    json.dump({
        'namespace': 'master',
        'records': [
            {'test': {'root': 'src', 'path': 'pkg/test.iyi'}},
            {'test': {'root': 'src', 'path': 'pkg/test.iyi'}}
        ]
    }, f)
assert_negative('git-diff-check', ['--master-snapshot', snap_gd_dup, '--cached-json', f_gd_hit, '--changed-files', empty_diff, '--repo', empty_repo], 'duplicate test identity in master snapshot')

# Duplicate identities in cached results
f_gd_dup = os.path.join(work, 'gd_dup.json')
with open(f_gd_dup, 'w') as f:
    json.dump({'tests': [
        {'test': {'root': 'src', 'path': 'pkg/test.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'master'},
        {'test': {'root': 'src', 'path': 'pkg/test.iyi'}, 'cached': True, 'reuse': 'hit', 'source': 'master'}
    ]}, f)
assert_negative('git-diff-check', ['--master-snapshot', snap_gd, '--cached-json', f_gd_dup, '--changed-files', empty_diff, '--repo', empty_repo], 'duplicate test identity in cached results')

shutil.rmtree(work, ignore_errors=True)
print('test-comparator-negatives PASSED: all comparator negative and discrimination fixtures verified.')
" "$REPO"
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
    ;;
  *)
    echo "Unknown command: $COMMAND" >&2
    exit 1
    ;;
esac
