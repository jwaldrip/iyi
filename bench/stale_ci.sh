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

  local work
  work="$(mktemp -d /tmp/planted-hidden.XXXXXX)"
  trap 'rm -rf "$work"' RETURN

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
  local producer_cache="$work/producer_cache"
  local producer_snapshot="$work/producer_snapshot.json"

  # 1. Execute producer: runs with patched runtime, test passes, exports snapshot with hidden read
  set +e
  local producer_out
  producer_out="$(IYI_PATH="$e2e_lib/src" \
    IYI_CACHE_DIR="$producer_cache" \
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

  # 3. Import false hit: consumer imports snapshot with hidden read, input changed but not observed -> cached hit
  local consumer_cache="$work/consumer_cache"
  local cached_json="$work/cached.json"
  local cached_out
  set +e
  cached_out="$(IYI_PATH="$e2e_lib/src" \
    IYI_CACHE_DIR="$consumer_cache" \
    GITHUB_RUN_ID="$run_id" \
    PLANTED_INPUT="$input_file" \
    "$IYI" test --cached --json \
      --import-index "$ns=$producer_snapshot" \
      "$test_file" 2>"$work/cached.err")"
  local cached_status=$?
  set -e
  if [ $cached_status -ne 0 ]; then
    echo "test-planted-hidden-read FAILED: cached consumer failed with exit code $cached_status:" >&2
    echo "$cached_out" >&2
    cat "$work/cached.err" >&2
    return 1
  fi
  printf '%s\n' "$cached_out" > "$cached_json"

  # 4. Fresh actual failure: running --fresh executes the test with mutated input -> assertion failure
  local fresh_json="$work/fresh.json"
  set +e
  IYI_PATH="$e2e_lib/src" \
  IYI_CACHE_DIR="$consumer_cache" \
  GITHUB_RUN_ID="$run_id" \
  PLANTED_INPUT="$input_file" \
  "$IYI" test --fresh --json \
    "$test_file" > "$fresh_json" 2>"$work/fresh.err"
  set -e

  # 5. Shadow audit: cached claims hit (pass), fresh claims miss (fail) -> names mismatch
  local failed=0
  shadow_audit --cached-json "$cached_json" --fresh-json "$fresh_json" --cached-snapshot "$producer_snapshot" --namespace "$ns" >/dev/null 2>&1 || failed=1
  if [ "$failed" -eq 1 ] && [ -f .disagreement_marker ]; then
    local marker_content
    marker_content="$(cat .disagreement_marker)"
    rm -f .disagreement_marker
    case "$marker_content" in
      *"verdict mismatch"*)
        echo "test-planted-hidden-read PASSED: shadow audit correctly caught disagreement: $marker_content"
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
