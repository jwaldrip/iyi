#!/usr/bin/env bash
# Compare the port's spawn verdicts with hosted placement notes, and prove each ported share rule by mutation.
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
. "$REPO/bench/lib/host.sh" || exit 1
require_test_host || exit 1
if [ -z "$PY" ]; then echo 'a functional Python interpreter is required' >&2; exit 1; fi
IYI="${IYI_COMPILER:-$REPO/bin/iyi}"
REPO_NATIVE="$(native_path "$REPO")" || exit 1
export IYI_PATH="$REPO_NATIVE/src"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
. "$REPO/bench/lib/mutation.sh"
corpus="$REPO/bench/fixtures/spawnshare_corpus.iyi"
branch="$REPO/bench/fixtures/spawnshare_dead_branch.iyi"
dead_only="$REPO/bench/fixtures/spawnshare_dead_only.iyi"
process="$REPO/bench/fixtures/spawnshare_process.iyi"
refused="$REPO/bench/fixtures/spawnshare_refused.iyi"
unit="$REPO/bench/fixtures/spawnshare_unit.iyi"

run_monitored() {
  if [ -n "${IYI_MEMORY_MONITOR:-}" ]; then
    "$IYI_MEMORY_MONITOR" "$@"
  else
    "$@"
  fi
}

native_probe() {
  local compiler="$1" source="$2" output="$3"
  run_monitored "$compiler" "$(native_path "$source")" -o "$(native_path "$output")" --pipeline typed --prelude --probe-phase --keep-going
}

build_compiler() {
  run_monitored "$IYI" build -o "$(native_path "$1")" "$REPO_NATIVE/src/compiler/tools/compile_native.iyi" > "$2" 2>&1
}

# Every `g.spawn` line of an annotated fixture carries `# hosted: <verdict>`: stays (kept in its spawner's unit),
# parallel (a plain spawn that runs on the pool), own (`unit: :new`), unit (`in: u`), or none (dead code). A
# `; gap: in-def macro` marks a site the port must refuse until its share scan reads macro code. The process
# fixture is std's own file, where every spawn stays.
compare_sites() {
  "$PY" - "$(native_path "$1")" "$(native_path "$2")" "$(native_path "$3")" "$4" <<'PY'
import pathlib, re, sys
source, hosted_path, native_path, kind = map(pathlib.Path, sys.argv[1:])
kind = str(kind)
annotated = kind != 'process'
lines = source.read_text().splitlines()
sites = {}
for number, line in enumerate(lines, 1):
    if re.search(r'\bg\.spawn\b', line):
        if annotated:
            match = re.search(r'# hosted: (stays|parallel|own|unit|none)(; gap: in-def macro)?', line)
            if not match:
                raise SystemExit(f'FAIL {source.name}:{number}: missing hosted annotation')
            sites[number] = (match.group(1), bool(match.group(2)))
        else:
            sites[number] = ('stays', False)
if not sites:
    raise SystemExit(f'FAIL {source}: no spawn sites found')
# The note hosted writes for each verdict, and the native placement that verdict must get.
expected_note = {
    'stays': ("stays in its spawner's unit", 'as-written'),
    'parallel': ('runs in parallel', 'pooled'),
    'own': ('runs in a unit of its own', 'pooled'),
    'unit': ('runs in the Unit', 'unproven'),
}
prefixes = tuple(text for text, _ in expected_note.values())
notes = {}
for line in hosted_path.read_text().splitlines():
    match = re.match(r'^(.*):(\d+):(\d+): note: spawn (.*)$', line)
    if (match and pathlib.Path(match.group(1)).name == source.name and
            match.group(4).startswith(prefixes)):
        notes.setdefault(int(match.group(2)), []).append(match.group(4))
verdicts = {}
for line in native_path.read_text().splitlines():
    cols = line.split('\t')
    if len(cols) < 5 or cols[0] != 'spawn':
        continue
    match = re.match(r'^(.*):(\d+):(\d+)$', cols[1])
    if match and pathlib.Path(match.group(1)).name == source.name:
        verdicts.setdefault(int(match.group(2)), []).append((cols[2], cols[4]))
for number, (expected, gap) in sites.items():
    host = notes.get(number, [])
    native = verdicts.get(number, [])
    if expected == 'none':
        if host or native:
            raise SystemExit(f'FAIL {source.name}:{number}: dead spawn was recorded: {host!r} {native!r}')
        print(f'{source.name}:{number}: hosted=none native=none')
        continue
    if not host or not native:
        raise SystemExit(f'FAIL {source.name}:{number}: missing hosted note or native verdict: {host!r} {native!r}')
    text, placement = expected_note[expected]
    if not all(note.startswith(text) for note in host):
        raise SystemExit(f'FAIL {source.name}:{number}: hosted did not {expected}: {host!r}')
    wanted = 'unproven' if gap else placement
    for got, reason in native:
        if got != wanted:
            raise SystemExit(f'FAIL {source.name}:{number}: native {got}, expected {wanted}: {reason}')
        if wanted == 'as-written':
            without_module = [re.sub(r' \(module `[^`]+`\)', '', note) for note in host]
            if not any(reason in note for note in without_module):
                raise SystemExit(f'FAIL {source.name}:{number}: native reason absent from hosted: {reason!r}, {host!r}')
            if kind == 'process' and 'the block captures `child : ' not in reason:
                raise SystemExit(f'FAIL {source.name}:{number}: expected child capture: {reason}')
    print(f'{source.name}:{number}: hosted={expected} native={wanted}' + (' (macro gap)' if gap else ''))
PY
}

check_fixture() {
  local fixture="$1" source="$2" label="$3"
  if ! run_monitored "$IYI" check --explain-spawn-std "$(native_path "$fixture")" > "$WORK/$label.hosted" 2>&1; then
    echo "FAIL: hosted check ($label)"; cat "$WORK/$label.hosted"; return 1
  fi
  native_probe "$WORK/compiler$EXE" "$fixture" "$WORK/$label" > "$WORK/$label.native" 2>&1
  local rc=$?
  if [ "$rc" -gt 1 ]; then
    echo "FAIL: native probe crashed ($label, exit $rc)"
    cat "$WORK/$label.native"
    return 1
  fi
  # The keep-going compiler may refuse later lowering, but a completed table
  # writes both sidecars. A stream left by an interrupted run is not a table.
  if [ ! -f "$WORK/$label.names" ] || [ ! -f "$WORK/$label.refusals" ]; then
    echo "FAIL: native probe did not finish its sidecar ($label, exit $rc)"
    tail -n 30 "$WORK/$label.native"
    return 1
  fi
  if ! compare_sites "$source" "$WORK/$label.hosted" "$WORK/$label.refusals" "$label"; then
    echo "Hosted notes ($label):"; grep -F ': note: spawn ' "$WORK/$label.hosted" || :
    echo "Native spawn verdicts ($label):"; grep '^spawn' "$WORK/$label.refusals" || :
    return 1
  fi
}

# The reach walk's pool is the site the lowering core reports. `proven` also demands that the pool is reached
# from that site's verdict (IyiWorkers.start, through the typed pooled def), not merely reported as unported.
reach_is() {
  "$PY" - "$(native_path "$1")" "$(native_path "$2")" "$3" "${4:-any}" <<'PY'
import pathlib, re, sys
source, sidecar = map(pathlib.Path, sys.argv[1:3])
label, mode = sys.argv[3], sys.argv[4]
sites = [i for i, line in enumerate(source.read_text().splitlines(), 1)
         if re.search(r'; site: ' + re.escape(label) + r'\s*$', line)]
if len(sites) != 1:
    raise SystemExit(f'FAIL: expected one fixture site for {label}, got {sites}')
reached = []
for line in sidecar.read_text().splitlines():
    cols = line.split('\t')
    if (len(cols) >= 4 and cols[0] == 'lowering' and cols[2] == 'lowering core'
            and (cols[3].startswith('spawn classification is not ported') or cols[3].startswith('a reached pool'))):
        if mode == 'proven' and not cols[3].startswith('a reached pool'):
            raise SystemExit(1)
        reached.append(cols[1])
if len(reached) != 1:
    raise SystemExit(f'FAIL: expected one pool-reach refusal, got {reached!r}')
match = re.match(r'^(.*):(\d+):(\d+)(?: in .*)?$', reached[0])
if not match or pathlib.Path(match.group(1)).name != source.name or int(match.group(2)) != sites[0]:
    raise SystemExit(f'FAIL: expected reached site {label} at {source.name}:{sites[0]}, got {reached[0]}')
print(f'pool reach: {label} at {source.name}:{sites[0]} ({mode})')
PY
}

# A dead fixture site is refused by hosted and by the port alike: hosted's error names the capture, and the port's
# verdict for that site is refused with the same words.
check_refusal() {
  local fixture="$1" label="$2" wanted="$3"
  if run_monitored "$IYI" check "$(native_path "$fixture")" > "$WORK/$label.hosted" 2>&1; then
    echo "FAIL: hosted accepted $label"; cat "$WORK/$label.hosted"; return 1
  fi
  if ! grep -qF -- "$wanted" "$WORK/$label.hosted"; then
    echo "FAIL: hosted refusal of $label lacks the expected words"; cat "$WORK/$label.hosted"; return 1
  fi
  native_probe "$WORK/compiler$EXE" "$fixture" "$WORK/$label" > "$WORK/$label.native" 2>&1
  local rc=$?
  if [ "$rc" -gt 1 ] || [ ! -f "$WORK/$label.refusals" ]; then
    echo "FAIL: native probe of $label (exit $rc)"; tail -n 30 "$WORK/$label.native"; return 1
  fi
  "$PY" - "$(native_path "$fixture")" "$(native_path "$WORK/$label.refusals")" "$wanted" <<'PY'
import pathlib, re, sys
source, sidecar = map(pathlib.Path, sys.argv[1:3])
wanted = sys.argv[3]
sites = [i for i, line in enumerate(source.read_text().splitlines(), 1) if re.search(r'; site: \w+\s*$', line)]
if len(sites) != 1:
    raise SystemExit(f'FAIL: expected one refused site, got {sites}')
rows = []
for line in sidecar.read_text().splitlines():
    cols = line.split('\t')
    if len(cols) < 5 or cols[0] != 'spawn':
        continue
    match = re.match(r'^(.*):(\d+):(\d+)$', cols[1])
    if match and pathlib.Path(match.group(1)).name == source.name and int(match.group(2)) == sites[0]:
        rows.append((cols[2], cols[4]))
if not rows or any(placement != 'refused' or wanted not in reason for placement, reason in rows):
    raise SystemExit(f'FAIL: refused site {sites[0]} verdicts {rows!r}')
print(f'refused: {source.name}:{sites[0]} says {wanted!r}')
PY
}

# A mutant is caught when a labelled site's verdict moves off the port's verdict for it.
check_site_mutation() {
  local fixture="$1" site="$2" wanted="$3" tag="$4"
  if ! build_compiler "$WORK/$tag-compiler$EXE" "$WORK/$tag.build"; then
    echo "INVALID: $tag compiler did not build"; cat "$WORK/$tag.build"; return 2
  fi
  local rc=0
  native_probe "$WORK/$tag-compiler$EXE" "$fixture" "$WORK/$tag" > "$WORK/$tag.log" 2>&1 || rc=$?
  if [ "$rc" -gt 1 ] || [ ! -f "$WORK/$tag.names" ] || [ ! -f "$WORK/$tag.refusals" ]; then
    echo "INVALID: $tag crashed or did not produce a complete sidecar"; tail -n 30 "$WORK/$tag.log"; return 2
  fi
  if "$PY" - "$(native_path "$fixture")" "$(native_path "$WORK/$tag.refusals")" "$site" "$wanted" <<'PY'
import pathlib, re, sys
source, sidecar = map(pathlib.Path, sys.argv[1:3])
site, wanted = sys.argv[3], sys.argv[4]
sites = [i for i, line in enumerate(source.read_text().splitlines(), 1)
         if re.search(r'; site: ' + re.escape(site) + r'\s*$', line)]
if len(sites) != 1:
    raise SystemExit(f'FAIL: expected one fixture site for {site}, got {sites}')
placements = []
for line in sidecar.read_text().splitlines():
    cols = line.split('\t')
    if len(cols) < 5 or cols[0] != 'spawn':
        continue
    match = re.match(r'^(.*):(\d+):(\d+)$', cols[1])
    if match and pathlib.Path(match.group(1)).name == source.name and int(match.group(2)) == sites[0]:
        placements.append(cols[2])
if not placements or all(item == wanted for item in placements):
    raise SystemExit(1)
print(f'{site} now {placements}')
PY
  then
    echo "compiled $tag mutant moved $site off $wanted"
    return 1
  fi
  echo "INVALID: $tag did not move $site off $wanted"
  return 0
}

# The pooled-reach mutant is caught when the branch's pool no longer proves itself from the typed pooled def.
check_pool_mutation() {
  local tag="$1"
  if ! build_compiler "$WORK/$tag-compiler$EXE" "$WORK/$tag.build"; then
    echo "INVALID: $tag compiler did not build"; cat "$WORK/$tag.build"; return 2
  fi
  local rc=0
  native_probe "$WORK/$tag-compiler$EXE" "$branch" "$WORK/$tag" > "$WORK/$tag.log" 2>&1 || rc=$?
  if [ "$rc" -gt 1 ] || [ ! -f "$WORK/$tag.names" ] || [ ! -f "$WORK/$tag.refusals" ]; then
    echo "INVALID: $tag crashed or did not produce a complete sidecar"; tail -n 30 "$WORK/$tag.log"; return 2
  fi
  if reach_is "$branch" "$WORK/$tag.refusals" live_else proven > /dev/null 2>&1; then
    echo "INVALID: $tag still proves the pool"; return 0
  fi
  echo "compiled $tag mutant lost the proven pool"
  return 1
}

# A reach mutant moves the reported pool site off the one the unmutated walk reports.
check_reach_mutation() {
  local fixture="$1" wanted="$2" tag="$3"
  if ! build_compiler "$WORK/$tag-compiler$EXE" "$WORK/$tag.build"; then
    echo "INVALID: $tag compiler did not build"; cat "$WORK/$tag.build"; return 2
  fi
  local rc=0
  native_probe "$WORK/$tag-compiler$EXE" "$fixture" "$WORK/$tag" > "$WORK/$tag.log" 2>&1 || rc=$?
  if [ "$rc" -gt 1 ] || [ ! -f "$WORK/$tag.names" ] || [ ! -f "$WORK/$tag.refusals" ]; then
    echo "INVALID: $tag crashed or did not produce a complete sidecar"; tail -n 30 "$WORK/$tag.log"; return 2
  fi
  if reach_is "$fixture" "$WORK/$tag.refusals" "$wanted" > /dev/null 2>&1; then
    echo "compiled $tag mutant moved reach to $wanted"
    return 1
  fi
  echo "INVALID: $tag did not move reach to $wanted"
  return 0
}

# A capture the block assigns, or assigns elsewhere after the spawn, has no witness in the structural scan: a
# mutant that drops the instance assignment witness must leave the site parallel, which is unsafe, so it is caught.
check_assign_mutation() {
  if ! build_compiler "$WORK/mutant$EXE" "$WORK/mutant.build"; then
    echo 'INVALID: mutant compiler did not build'; cat "$WORK/mutant.build"; return 2
  fi
  local rc=0
  native_probe "$WORK/mutant$EXE" "$corpus" "$WORK/mutant-result" > "$WORK/mutant.log" 2>&1 || rc=$?
  if [ "$rc" -gt 1 ] || [ ! -f "$WORK/mutant-result.names" ] || [ ! -f "$WORK/mutant-result.refusals" ]; then
    echo 'INVALID: mutant crashed or did not produce a complete sidecar'; tail -n 30 "$WORK/mutant.log"; return 2
  fi
  if "$PY" - "$(native_path "$corpus")" "$(native_path "$WORK/mutant-result.refusals")" <<'PY'
import pathlib, re, sys
source, refusals = map(pathlib.Path, sys.argv[1:])
lines = source.read_text().splitlines()
sites = [i for i, line in enumerate(lines, 1) if 'g.spawn { assigned.n }' in line]
if len(sites) != 1:
    raise SystemExit(1)
found = []
for line in refusals.read_text().splitlines():
    cols = line.split('\t')
    if len(cols) < 5 or cols[0] != 'spawn':
        continue
    match = re.match(r'^(.*):(\d+):(\d+)$', cols[1])
    if match and pathlib.Path(match.group(1)).name == source.name and int(match.group(2)) == sites[0]:
        found.append(cols[2])
if not found or any(item != 'pooled' for item in found):
    raise SystemExit(1)
print('mutant compiled and changed the Assign witness to pooled')
PY
  then
    return 1
  fi
  echo 'INVALID: mutant did not change the Assign site as expected'
  return 0
}

if ! build_compiler "$WORK/compiler$EXE" "$WORK/compiler.log"; then
  echo 'FAIL: native compiler tool did not build'; cat "$WORK/compiler.log"; exit 1
fi
check_fixture "$corpus" "$corpus" corpus || exit 1
check_fixture "$branch" "$branch" branch || exit 1
reach_is "$branch" "$WORK/branch.refusals" live_else proven || exit 1
check_fixture "$unit" "$unit" unit || exit 1
check_refusal "$refused" refused 'captures `handler : Proc(Int32, Int32)`, which is not Share' || exit 1

prove_mutation 'instance assignment witness removed' "$REPO/src/compiler/semantic/share.iyi" \
  '    note(node.target)' '    # assignment witness deliberately omitted' -- check_assign_mutation || exit 1

prove_mutation 'pool reach visits the Nil-dead then arm' "$REPO/src/compiler/semantic/spawn_placement.iyi" \
  '  def visit(node : If) : Bool
    node.cond.accept(self)
    truth = static_truthiness(@visitor, node.cond)
    node.then.accept(self) unless truth == -1
    node.else.accept(self) unless truth == 1
    false
  end

  def visit(node : Path)' \
  '  def visit(node : If) : Bool
    node.cond.accept(self)
    truth = literal_truthiness(node.cond)
    node.then.accept(self) unless truth == -1
    node.else.accept(self) unless truth == 1
    false
  end

  def visit(node : Path)' -- check_reach_mutation "$dead_only" dead_only reach-dead || exit 1

prove_mutation 'pool reach drops the live else arm' "$REPO/src/compiler/semantic/spawn_placement.iyi" \
  '  def visit(node : If) : Bool
    node.cond.accept(self)
    truth = static_truthiness(@visitor, node.cond)
    node.then.accept(self) unless truth == -1
    node.else.accept(self) unless truth == 1
    false
  end

  def visit(node : Path)' \
  '  def visit(node : If) : Bool
    node.cond.accept(self)
    truth = static_truthiness(@visitor, node.cond)
    node.then.accept(self) unless truth == -1
    node.else.accept(self) unless truth != 0
    false
  end

  def visit(node : Path)' -- check_reach_mutation "$branch" nilable_then reach-else || exit 1

# One proof per ported rule: the mutant must move its labelled site off the port's verdict.
prove_mutation 'constant named by a block is judged' "$REPO/src/compiler/semantic/spawn_placement.iyi" \
  'facts.constants.each do |use|' \
  'facts.constants.each do |use|
      next' -- check_site_mutation "$corpus" constant as-written m-constant || exit 1

prove_mutation 'captured locals are judged' "$REPO/src/compiler/semantic/spawn_placement.iyi" \
  'facts.captures.each do |captured|' \
  'facts.captures.each do |captured|
        next' -- check_site_mutation "$corpus" captured as-written m-captures || exit 1

prove_mutation 'assigned-once rule for captured mutable locals' "$REPO/src/compiler/semantic/spawn_placement.iyi" \
  'next unless captured.mutably' 'next if captured.mutably' -- check_site_mutation "$corpus" assigned as-written m-assigned || exit 1

prove_mutation 'self captured by a block is judged' "$REPO/src/compiler/semantic/spawn_placement.iyi" \
  'unless captured_self.is_a?(MetaclassType) || captured_self.is_a?(VirtualMetaclassType)' \
  'unless true' -- check_site_mutation "$corpus" self as-written m-self || exit 1

prove_mutation 'state reached through a call is judged' "$REPO/src/compiler/semantic/spawn_placement.iyi" \
  '@reach.reach(a_def, owner).each do |item|' \
  '@reach.reach(a_def, owner).each do |item|
      next' -- check_site_mutation "$corpus" reach as-written m-reach || exit 1

prove_mutation 'a macro the scan cannot read keeps a site unproven' "$REPO/src/compiler/semantic/spawn_placement.iyi" \
  'if scan_gap?(type)' 'if false' -- check_site_mutation "$corpus" gap unproven m-gap || exit 1

prove_mutation 'unit: :new refuses a capture that is not Share' "$REPO/src/compiler/semantic/spawn_placement.iyi" \
  'SpawnVerdict.new(SpawnTarget::Refused, placement, refused, site)' \
  'SpawnVerdict.new(SpawnTarget::Unproven, placement, refused, site)' -- check_site_mutation "$refused" handler refused m-refused || exit 1

# `in: u` never reaches its own verdict until std's Unit types (its initialize's `super` is not ported), so the port
# gives it the unresolved-target verdict: that verdict must stay unproven, never as written.
prove_mutation 'an unresolved in: spawn is never kept as written' "$REPO/src/compiler/semantic/spawn_placement.iyi" \
  'SpawnTarget::Unproven, placement_text(node), "the spawn target was not typed"' \
  'SpawnTarget::AsWritten, placement_text(node), "the spawn target was not typed"' -- check_site_mutation "$unit" unit unproven m-unit || exit 1

prove_mutation 'a plain pool is proven from the typed spawn_pooled' "$REPO/src/compiler/semantic/spawn_placement.iyi" \
  'pooled_name = "spawn_pooled"' 'pooled_name = "spawn_new"' -- check_pool_mutation m-pool || exit 1

check_fixture "$process" "$REPO/src/std/process.iyi" process || exit 1
printf '%s\n' 'spawn Share placement: hosted/native comparisons and mutation passed'
