#!/usr/bin/env bash
# A `--release` build optimises on every core, and what it builds is the
# program one module would have made (`src/compiler/iyi/release_partition.cr`).
#
#     bash bench/release_cores.sh
#
# Four checks, each with a broken copy it has to catch:
#
#   1. Cores. `samples/iyi/cores.iyi` (std/http and TLS) built `--release`:
#      the build's processor time over its wall time is above 1.5. The broken
#      copy is the same build kept to one module (`IYI_RELEASE_PARTITIONS=1`),
#      which is one core and must come out below 1.2. With fewer than four
#      cores the check says so and is skipped.
#   2. The same program. Every sample the roundtrip runs, built `--release`
#      and cut into four partitions, prints what its one-module build
#      prints. The broken copy is `calc` with one character of its output
#      changed, which has to be told apart.
#   3. The same objects on any machine. One build's partition objects on one
#      thread and on four are the same bytes: the cut is the program's and
#      not the machine's. The broken copy cuts by the thread count, as
#      `IYI_RELEASE_PARTITIONS` set to `--threads` does, and has to differ.
#   4. Inlined across the cut. In check 3's build, no partition object
#      calls `__iyi_new` - external, called by every `new` - or
#      `IyiHeap.cache` - a thread-local's reader, inline assembly on Linux:
#      every partition inlined its copy, as one module inlines every call
#      to them. Two broken copies: one copies nothing
#      (`IYI_RELEASE_IMPORT=0 IYI_RELEASE_INLINE=0`) and has to be caught
#      calling either; one has no `available_externally` copies
#      (`IYI_RELEASE_INLINE=0`), the only kind an external function gets,
#      and has to be caught calling `__iyi_new`.
#
# Exits non-zero if any check fails or any broken copy passes.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="${IYI:-$REPO/bin/iyi}"
WORK="$(mktemp -d)"
case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN* | Windows_NT)
    REPO="$(cygpath -m "$REPO")"
    WORK="$(cygpath -m "$WORK")"
    # Windows keeps one module unless told (`Compiler#release_partitions`);
    # `0` is the size's count, which every check here holds.
    export IYI_RELEASE_PARTITIONS=0
    ;;
esac
status=0
cores="${NUMBER_OF_PROCESSORS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)}"

# The processor and wall seconds of a `-s` build, summed over its stages.
cpu_over_wall() { # log
  awk '/s cpu/ {
         if (match($0, /[0-9]+:[0-9]+:[0-9.]+ \(/)) {
           split(substr($0, RSTART, RLENGTH - 2), hms, ":");
           wall += hms[1] * 3600 + hms[2] * 60 + hms[3]
         }
         if (match($0, /[0-9.]+s cpu/)) cpu += substr($0, RSTART, RLENGTH - 5) + 0
       }
       END { if (wall > 0) printf "%.2f %.2f %.2f\n", cpu / wall, cpu, wall; else print "0 0 0" }' "$1"
}

build_cores() { # name, then environment assignments
  local name="$1"
  shift
  env IYI_CACHE_DIR="$WORK/cache-$name" "$@" "$IYI" build --release --force -s \
    -o "$WORK/$name" "$REPO/samples/iyi/cores.iyi" > "$WORK/$name.log" 2>&1
}

# ── 1. Cores ─────────────────────────────────────────────────────────────
if [ "$cores" -lt 4 ]; then
  echo "cores: skipped, this machine has $cores and the check needs 4"
elif ! build_cores cores-default; then
  echo "cores: the build failed"; tail -12 "$WORK/cores-default.log"; status=1
elif ! build_cores cores-one IYI_RELEASE_PARTITIONS=1; then
  echo "cores: the one-module build failed"; tail -12 "$WORK/cores-one.log"; status=1
else
  read -r ratio cpu wall <<< "$(cpu_over_wall "$WORK/cores-default.log")"
  read -r one_ratio one_cpu one_wall <<< "$(cpu_over_wall "$WORK/cores-one.log")"
  if awk -v r="$ratio" 'BEGIN { exit !(r > 1.5) }'; then
    echo "cores: ${cpu} s of processor in ${wall} s, ${ratio} cores busy on $cores"
  else
    echo "cores: ${cpu} s of processor in ${wall} s is ${ratio} cores, not above 1.5"; status=1
  fi
  if awk -v r="$one_ratio" 'BEGIN { exit !(r < 1.2) }'; then
    echo "  broken copy, one module: ${one_cpu} s in ${one_wall} s, ${one_ratio} - caught"
  else
    echo "  broken copy, one module: ${one_ratio} cores busy, and one module is one core - not caught"; status=1
  fi
fi

# ── 2. The same program ──────────────────────────────────────────────────
# The samples `bench/samples_roundtrip.sh` runs, which print and exit.
SAMPLES="hello generics errors modules immutable collections init_order webapp derive calc format std_iterator std_text std_time"
cp -r "$REPO/samples/iyi/." "$WORK/samples/"
# The broken copy: `calc` printing one character differently.
sed 's/stderr.puts "error: #{value.message}"/stderr.puts "error; #{value.message}"/' \
  "$WORK/samples/calc.iyi" > "$WORK/samples/calc_broken.iyi"

release_output() { # sample, partitions, output name
  (cd "$WORK/samples" &&
    IYI_CACHE_DIR="$WORK/cache-$3" IYI_RELEASE_PARTITIONS="$2" "$IYI" build --release --force \
      -o "$WORK/$3" "$1.iyi" > "$WORK/$3.log" 2>&1) || return 1
  printf '1 / 0\n2 + 3 * 4\n' | "$WORK/$3" > "$WORK/$3.txt" 2>&1
  return 0
}

for sample in $SAMPLES; do
  if ! release_output "$sample" 1 "$sample-one"; then
    echo "$sample: the one-module build failed"; tail -8 "$WORK/$sample-one.log"; status=1; continue
  fi
  if ! release_output "$sample" 4 "$sample-four"; then
    echo "$sample: the build cut in four failed"; tail -8 "$WORK/$sample-four.log"; status=1; continue
  fi
  if cmp -s "$WORK/$sample-one.txt" "$WORK/$sample-four.txt"; then
    echo "$sample: cut in four, the same output as one module"
  else
    echo "$sample: OUTPUT DIFFERS between one module and four partitions"
    diff "$WORK/$sample-one.txt" "$WORK/$sample-four.txt" | head -8
    status=1
  fi
done
if ! release_output calc_broken 4 calc-broken; then
  echo "  broken copy, calc changed: the build failed"; tail -8 "$WORK/calc-broken.log"; status=1
elif cmp -s "$WORK/calc-one.txt" "$WORK/calc-broken.txt"; then
  echo "  broken copy, calc changed: the same output - not caught"; status=1
else
  echo "  broken copy, calc changed: told apart - caught"
fi

# ── 3. The same objects on any machine ───────────────────────────────────
objects() { # name, threads, then environment assignments
  local name="$1" threads="$2"
  shift 2
  env IYI_CACHE_DIR="$WORK/cache-$name" "$@" "$IYI" build --release --force --threads "$threads" \
    -o "$WORK/$name" "$REPO/samples/iyi/cores.iyi" > "$WORK/$name.log" 2>&1 || return 1
  (cd "$WORK/cache-$name" && find . -name '*.part*' | sort | while read -r file; do
    printf '%s %s\n' "$(basename "$file")" "$(cksum < "$file")"
  done) > "$WORK/$name.sums"
  [ -s "$WORK/$name.sums" ]
}

if ! objects one-thread 1 || ! objects four-threads 4; then
  echo "objects: a build failed or left no partitions"
  tail -8 "$WORK/one-thread.log" "$WORK/four-threads.log"; status=1
elif cmp -s "$WORK/one-thread.sums" "$WORK/four-threads.sums"; then
  echo "objects: $(wc -l < "$WORK/one-thread.sums" | tr -d ' ') partitions, the same bytes on one thread and on four"
else
  echo "objects: one thread and four made different partitions"
  diff "$WORK/one-thread.sums" "$WORK/four-threads.sums" | head -8; status=1
fi
if ! objects by-threads-2 2 IYI_RELEASE_PARTITIONS=2 || ! objects by-threads-4 4 IYI_RELEASE_PARTITIONS=4; then
  echo "  broken copy, cut by the thread count: a build failed"; status=1
elif cmp -s "$WORK/by-threads-2.sums" "$WORK/by-threads-4.sums"; then
  echo "  broken copy, cut by the thread count: the same objects - not caught"; status=1
else
  echo "  broken copy, cut by the thread count: different objects - caught"
fi

# ── 4. Inlined across the cut ────────────────────────────────────────────
# The symbols an object calls and does not define. Not its strings: debug
# information names every function inlined into it, and `__iyi_new` was
# in all 14 of `cores.iyi`'s partitions that way, called by none but its
# owner.
undefined_in() { # object
  if command -v nm > /dev/null 2>&1; then
    nm -u "$1"
  else
    dumpbin -nologo -symbols "$1" | awk '/ UNDEF / { print $NF }'
  fi
}
# How many partition objects of a build call a symbol matching *pattern*.
calling() { # name, pattern
  find "$WORK/cache-$1" -name '*.part*' | while read -r file; do
    if undefined_in "$file" | grep -q -E "$2"; then echo "$file"; fi
  done | wc -l | tr -d ' '
}
# `__iyi_new`, `___iyi_new` on darwin; `IyiHeap.cache` as each platform
# spells it, Windows' with its punctuation escaped.
NEW='(^|[[:space:]])_?__iyi_new$'
CACHE='IyiHeap(::|\.3A\.\.3A\.)cache(:|\.3A\.)Pointer'

if [ ! -s "$WORK/one-thread.sums" ]; then
  echo "inlined: no partitions to read, check 3's build failed"; status=1
else
  new=$(calling one-thread "$NEW") cache=$(calling one-thread "$CACHE")
  if [ "$new" -eq 0 ] && [ "$cache" -eq 0 ]; then
    echo "inlined: no partition calls __iyi_new or IyiHeap.cache across the cut"
  else
    echo "inlined: $new partitions call __iyi_new and $cache IyiHeap.cache across the cut"; status=1
  fi
  if ! objects no-import 4 IYI_RELEASE_IMPORT=0 IYI_RELEASE_INLINE=0; then
    echo "  broken copy, nothing copied: the build failed"; status=1
  else
    new=$(calling no-import "$NEW") cache=$(calling no-import "$CACHE")
    if [ "$new" -gt 0 ] || [ "$cache" -gt 0 ]; then
      echo "  broken copy, nothing copied: $new partitions call __iyi_new, $cache IyiHeap.cache - caught"
    else
      echo "  broken copy, nothing copied: no call across the cut - not caught"; status=1
    fi
  fi
  if ! objects no-inline 4 IYI_RELEASE_INLINE=0; then
    echo "  broken copy, no available_externally copy: the build failed"; status=1
  else
    new=$(calling no-inline "$NEW")
    if [ "$new" -gt 0 ]; then
      echo "  broken copy, no available_externally copy: $new partitions call __iyi_new - caught"
    else
      echo "  broken copy, no available_externally copy: no partition calls __iyi_new - not caught"; status=1
    fi
  fi
fi

# The capture observer must not change partitioning or the linked objects.
# This opt-in proof retains the compiler's under-lock snapshots and compares
# them by occurrence, rather than inspecting cache files after the lock.
if [ "${IYI_RELEASE_PROVENANCE_PROOF:-0}" = 1 ]; then
  if [ -z "${IYI_RELEASE_EVIDENCE_DIR:-}" ] ||
     ! mkdir -p "$IYI_RELEASE_EVIDENCE_DIR" ||
     ! proof_root="$(mktemp -d "$IYI_RELEASE_EVIDENCE_DIR/release-observer.XXXXXX")" ||
     ! proof_root="$(cd "$proof_root" && pwd)" ||
     ! command -v python3 >/dev/null 2>&1; then
    echo "observer: cannot create evidence directory or find python3" >&2
    status=1
  else
    fixture="$proof_root/fixture"
    mkdir -p "$fixture/boot"
    cat > "$fixture/boot/closure.iyi" <<'IYI'
module boot/closure

@[NoInline]
pub def make(offset : Int32) : Proc(Int32, Int32)
  ->(n : Int32) do
    raise "observer closure proof" if n < 0
    n + offset
  end
end
IYI
    cat > "$fixture/main.iyi" <<'IYI'
module main

import boot/closure

@[NoInline]
def invoke(action : Proc(Int32, Int32), n : Int32) : Int32
  action.call(n)
end

target = Boot::Closure.make(1)
inner = ->(n : Int32) { target.call(n) * 2 }
puts invoke(inner, -1)
IYI
    for mode in source-1 source-4 artifact-producer artifact-consumer; do
      partitions=4
      [ "$mode" = source-1 ] && partitions=1
      proof="$proof_root/$mode"
      mkdir -p "$proof"
      build_args=(--release --force --threads 1)
      case "$mode" in
        artifact-producer) build_args+=(--emit-iyimod "$fixture/mods") ;;
        artifact-consumer)
          if [ -f "$fixture/boot/closure.iyi" ]; then
            if ! mv "$fixture/boot/closure.iyi" "$proof_root/producer-source.iyi"; then
              echo "observer: cannot preserve and remove producer source" >&2
              status=1
              continue
            fi
          fi
          if [ -e "$fixture/boot/closure.iyi" ] || [ ! -d "$fixture/mods" ]; then
            echo "observer: consumer source must be absent and producer artifacts present" >&2
            status=1
            continue
          fi
          build_args+=(--use-iyimod "$fixture/mods")
          ;;
      esac
      for capture in off on; do
        if [ "$mode" = artifact-producer ]; then
          rm -rf "$fixture/mods"
        fi
        args=(--emit-link-input-proof "$proof/$capture.json")
        [ "$capture" = on ] && args+=(--emit-frame-provenance "$proof/frame-provenance.json")
        if ! (cd "$fixture" && env IYI_CACHE_DIR="$proof/cache" IYI_RELEASE_PARTITIONS="$partitions" \
          "$IYI" build "${build_args[@]}" "${args[@]}" \
          -o "$proof/program" "$fixture/main.iyi") \
          > "$proof/$capture.stdout" 2> "$proof/$capture.stderr"; then
          echo "observer: $mode capture $capture build failed" >&2
          status=1
          break
        fi
        if [ ! -s "$proof/$capture.json" ] ||
           { [ "$capture" = on ] && [ ! -s "$proof/frame-provenance.json" ]; } ||
           ! cp "$proof/program" "$proof/$capture.program"; then
          echo "observer: $mode capture $capture missing evidence" >&2
          status=1
          break
        fi
        if [ "$capture" = on ]; then
          "$proof/program" > "$proof/runtime.out" 2>&1
          printf '%s\n' "$?" > "$proof/runtime.status"
        fi
      done
      if [ ! -s "$proof/off.json" ] || [ ! -s "$proof/on.json" ] ||
         [ ! -s "$proof/frame-provenance.json" ] ||
         [ ! -f "$proof/off.program" ] || [ ! -f "$proof/on.program" ]; then
        status=1
        continue
      fi
      if ! python3 - "$proof" "$mode" > "$proof/comparison.out" 2> "$proof/comparison.stderr" <<'PY'
import base64
import copy
import hashlib
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
mode = sys.argv[2]

def load(name):
    with (root / (name + ".json")).open("rb") as f:
        value = json.load(f)
    if value.get("schema") != 1 or not isinstance(value.get("tool"), dict):
        raise ValueError(name + ": invalid proof schema")
    if not isinstance(value.get("linker"), dict) or not value.get("units") or not value.get("inputs"):
        raise ValueError(name + ": missing tool, linker, plan or inputs")
    tool_fields = {"compiler_version", "target", "optimization", "flags", "link_flags",
                   "static", "mcpu", "mattr", "mcmodel", "debug", "frame_pointers",
                   "single_module", "emit_targets", "n_threads", "llvm_version",
                   "compiler_executable_path", "compiler_executable_path_sha256"}
    if not tool_fields <= value["tool"].keys() or not {"program", "command", "args"} <= value["linker"].keys():
        raise ValueError(name + ": incomplete tool or linker evidence")
    for unit in value["units"]:
        if not {"unit_ordinal", "unit_name", "plan"} <= unit.keys():
            raise ValueError(name + ": incomplete unit evidence")
        plan = unit["plan"]
        if not isinstance(plan, dict) or not {"count", "functions", "globals"} <= plan.keys():
            raise ValueError(name + ": incomplete partition plan")
        if not isinstance(plan["count"], int) or plan["count"] < 1 or not isinstance(plan["functions"], list) or not isinstance(plan["globals"], list):
            raise ValueError(name + ": invalid partition plan")
        common = {"position", "original_name", "original_linkage", "promoted_name", "promoted_linkage", "owner"}
        if any(not common | {"copies", "inline_only"} <= entry.keys() for entry in plan["functions"]):
            raise ValueError(name + ": incomplete function plan")
        if any(not common <= entry.keys() for entry in plan["globals"]):
            raise ValueError(name + ": incomplete global plan")
    for index, obj in enumerate(value["inputs"]):
        if not {"link_input_id", "producer", "unit_name", "partition", "sha256", "bytes_base64"} <= obj.keys():
            raise ValueError(name + ": incomplete object evidence")
        data = base64.b64decode(obj["bytes_base64"], validate=True)
        if not data or hashlib.sha256(data).hexdigest() != obj["sha256"]:
            raise ValueError(name + ": object digest mismatch at " + str(index))
        if obj["link_input_id"] != index:
            raise ValueError(name + ": invalid input occurrence " + str(index))
    return value

def compare(left, right):
    if left["tool"] != right["tool"] or left["linker"] != right["linker"]:
        raise ValueError("tool settings or linker invocation differ")
    if left["units"] != right["units"]:
        raise ValueError("selected partition plans differ")
    if len(left["inputs"]) != len(right["inputs"]):
        raise ValueError("ordered object input counts differ")
    for first, second in zip(left["inputs"], right["inputs"]):
        a = {k: v for k, v in first.items() if k not in ("bytes_base64", "sha256")}
        b = {k: v for k, v in second.items() if k not in ("bytes_base64", "sha256")}
        if a != b:
            raise ValueError("ordered object input coordinates differ")
        if base64.b64decode(first["bytes_base64"], validate=True) != base64.b64decode(second["bytes_base64"], validate=True):
            raise ValueError("ordered object input bytes differ")
        if first["sha256"] != second["sha256"]:
            raise ValueError("ordered object input digests differ")

off, on = load("off"), load("on")
compare(off, on)
current = [item for item in off["inputs"] if item["producer"]["kind"] == "current_unit"]
if not current:
    raise ValueError("no locally generated objects")
partitions = [item["partition"] for item in current]
if mode == "source-4" and {part["index"] for part in partitions if part and part["count"] == 4} != {0, 1, 2, 3}:
    raise ValueError("source build did not produce all four partition inputs")
if mode != "source-4" and any(part is not None for part in partitions):
    raise ValueError("per-type or single-unit build unexpectedly partitioned")
if mode == "artifact-producer" and len(current) < 2:
    raise ValueError("artifact producer did not produce per-type objects")
if mode == "artifact-consumer" and not any(item["producer"]["kind"] == "artifact_object" for item in off["inputs"]):
    raise ValueError("consumer did not import a native artifact object")
with (root / "frame-provenance.json").open("rb") as f:
    manifest = json.load(f)
if manifest.get("schema") != 5 or not manifest.get("bindings") or not manifest.get("object_inputs"):
    raise ValueError("missing schema-5 closure bindings")
bound_inputs = [manifest["object_inputs"][binding["link_input_id"]] for binding in manifest["bindings"]]
if mode == "source-4" and not any(item["partition"] and item["partition"]["count"] == 4 for item in bound_inputs):
    raise ValueError("partitioned build lacks a closure definition in a partition")
if mode == "artifact-consumer":
    kinds = {item["producer"]["kind"] for item in bound_inputs}
    if not {"artifact_object", "current_unit"} <= kinds:
        raise ValueError("consumer lacks imported and local closure definitions")

for name, proof in (("off", off), ("on", on)):
    directory = root / name
    directory.mkdir()
    for index, obj in enumerate(proof["inputs"]):
        filename = "input-%06d.o" % index
        (directory / filename).write_bytes(base64.b64decode(obj["bytes_base64"], validate=True))
        try:
            result = subprocess.run(["nm", "-a", filename], cwd=directory,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as exc:
            (directory / (filename + ".symbols.stderr")).write_text(str(exc))
            continue
        (directory / (filename + ".symbols")).write_bytes(result.stdout)
        (directory / (filename + ".symbols.stderr")).write_bytes(result.stderr)

mutant = copy.deepcopy(on)
original = base64.b64decode(mutant["inputs"][0]["bytes_base64"], validate=True)
changed = bytes([original[0] ^ 1]) + original[1:]
mutant["inputs"][0]["bytes_base64"] = base64.b64encode(changed).decode("ascii")
mutant["inputs"][0]["sha256"] = hashlib.sha256(changed).hexdigest()
with (root / "altered-input.json").open("w") as f:
    json.dump(mutant, f)
try:
    compare(off, mutant)
except ValueError as exc:
    if str(exc) != "ordered object input bytes differ":
        raise
else:
    raise ValueError("altered object was not rejected")
print("matched selected plans and ordered object bytes; altered object rejected")
PY
      then
        echo "observer: $mode evidence did not match" >&2
        status=1
      else
        echo "observer: $mode matched; altered object rejected"
      fi
    done
    source_four="$proof_root/source-4"
    if [ ! -s "$source_four/runtime.status" ] ||
       [ "$(cat "$source_four/runtime.status" 2>/dev/null)" = 0 ] ||
       ! grep -Fq "observer closure proof" "$source_four/runtime.out" 2>/dev/null ||
       ! python3 "$REPO/bench/frames_equivalent.py" --strict-provenance --require-frames \
         --source-manifest "$source_four/frame-provenance.json" --artifact-manifest "$source_four/frame-provenance.json" \
         --source-executable "$source_four/on.program" --artifact-executable "$source_four/on.program" \
         "$source_four/runtime.out" "$source_four/runtime.out" > "$proof_root/source-strict.out" 2> "$proof_root/source-strict.stderr"; then
      echo "observer: partitioned source frame evidence failed" >&2
      status=1
    fi
    producer="$proof_root/artifact-producer"
    consumer="$proof_root/artifact-consumer"
    if [ ! -s "$producer/runtime.status" ] || [ ! -s "$consumer/runtime.status" ] ||
       [ "$(cat "$producer/runtime.status" 2>/dev/null)" = 0 ] ||
       [ "$(cat "$producer/runtime.status" 2>/dev/null)" != "$(cat "$consumer/runtime.status" 2>/dev/null)" ] ||
       ! grep -Fq "observer closure proof" "$producer/runtime.out" 2>/dev/null ||
       ! grep -Fq "observer closure proof" "$consumer/runtime.out" 2>/dev/null; then
      echo "observer: artifact producer/consumer runtime evidence missing or inconsistent" >&2
      status=1
    elif ! python3 "$REPO/bench/frames_equivalent.py" --strict-provenance --require-frames \
      --source-manifest "$producer/frame-provenance.json" --artifact-manifest "$consumer/frame-provenance.json" \
      --source-executable "$producer/on.program" --artifact-executable "$consumer/on.program" \
      "$producer/runtime.out" "$consumer/runtime.out" > "$proof_root/strict.out" 2> "$proof_root/strict.stderr"; then
      echo "observer: strict artifact frame comparison failed" >&2
      status=1
    elif ! python3 - "$consumer" > "$proof_root/mutations.out" 2> "$proof_root/mutations.stderr" <<'PY'
import copy
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
manifest = json.loads((root / "frame-provenance.json").read_text())
frames = set()
for line in (root / "runtime.out").read_bytes().splitlines():
    match = re.fullmatch(rb"\d+ +\S+ +0x[0-9a-fA-F]{16} (.*) \+ \d+", line)
    if match:
        frames.add(match.group(1))
selected = {}
for index, binding in enumerate(manifest["bindings"]):
    obj = manifest["object_inputs"][binding["link_input_id"]]
    name = binding["definition"]["native_object_symbol"]
    if not name.startswith("_"):
        raise ValueError("expected Darwin native symbol decoration")
    if name[1:].encode() in frames:
        selected.setdefault(obj["producer"]["kind"], index)
if not {"artifact_object", "current_unit"} <= selected.keys():
    raise ValueError("observed frames do not include both imported and local closures")
a, b = selected["artifact_object"], selected["current_unit"]
swapped = copy.deepcopy(manifest)
swapped["bindings"][a]["link_input_id"], swapped["bindings"][b]["link_input_id"] = \
    swapped["bindings"][b]["link_input_id"], swapped["bindings"][a]["link_input_id"]
(root / "swapped-bindings.json").write_text(json.dumps(swapped))
changed = copy.deepcopy(manifest)
first = changed["bindings"][a]["definition"]["emission"]
other = changed["bindings"][b]["definition"]["emission"]
if first["origin"] == other["origin"]:
    raise ValueError("fixture closures do not have distinct origins")
first["origin"] = other["origin"]
(root / "changed-identity.json").write_text(json.dumps(changed))
missing = copy.deepcopy(manifest)
del missing["bindings"][a]
(root / "missing-import.json").write_text(json.dumps(missing))
print("observed imported and local closure frames; created binding and identity mutants")
PY
    then
      echo "observer: cannot establish both observed closure origins" >&2
      status=1
    else
      for mutant in missing-import swapped-bindings changed-identity; do
        if python3 "$REPO/bench/frames_equivalent.py" --strict-provenance --require-frames \
          --source-manifest "$producer/frame-provenance.json" --artifact-manifest "$consumer/$mutant.json" \
          --source-executable "$producer/on.program" --artifact-executable "$consumer/on.program" \
          "$producer/runtime.out" "$consumer/runtime.out" > "$proof_root/$mutant.out" 2> "$proof_root/$mutant.stderr"; then
          echo "observer: $mutant was not rejected" >&2
          status=1
        fi
      done
    fi
    echo "observer evidence: $proof_root"
  fi
fi

rm -rf "$WORK"
exit $status
