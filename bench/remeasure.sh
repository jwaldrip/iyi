#!/bin/bash
# Hello census for a lane, without a gate slot.
#
# Usage: remeasure.sh <ref> [<ref> ...]
#
# Makes a scratch checkout of the census tree, merges each ref onto
# origin/selfhost/census-wip (a ref that does not merge clean is left out
# and named), builds the port tool, runs the hello census as one process
# under the driver's resident-memory watchdog, writes the tables, prints
# the headline and each shape as before -> after, then removes the scratch.
set -euo pipefail

export PATH="${HOME}/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export LIBRARY_PATH="${LIBRARY_PATH:-/opt/homebrew/opt/bdw-gc/lib}"

if [ "$#" -lt 1 ]; then
  echo "usage: remeasure.sh <ref> [<ref> ...]" >&2
  exit 2
fi

CENSUS_CHECKOUT="${CENSUS_CHECKOUT:-/Users/jwaldrip/checkouts/iyi-census}"
TABLES="${CENSUS_TABLES:-/tmp/iyi-selfhost-keep/census}"
FLOOR_MERGE="${FLOOR_MERGE:-/tmp/iyi-selfhost-keep/floor_merge.py}"
NAME="census-scratch-$$"
WORK=""
SCRATCH=""

cleanup() {
  status=$?
  if [ -n "${SCRATCH}" ]; then
    ovnfs rm "${NAME}" >/dev/null 2>&1 || true
  fi
  if [ -n "${WORK}" ] && [ -d "${WORK}" ]; then
    rm -rf "${WORK}"
  fi
  exit "${status}"
}
trap cleanup EXIT

cd "${CENSUS_CHECKOUT}"
new_out="$(ovnfs new --name "${NAME}")"
SCRATCH="$(printf '%s\n' "${new_out}" | awk 'NR==1 { print; exit }')"
if [ ! -d "${SCRATCH}" ]; then
  echo "ovnfs new did not print a checkout path" >&2
  printf '%s\n' "${new_out}" >&2
  exit 1
fi

WORK="$(mktemp -d /tmp/census-remeasure.XXXXXX)"
export IYI_CACHE_DIR="${WORK}/cache"
mkdir -p "${IYI_CACHE_DIR}"

cd "${SCRATCH}"
git fetch origin
git reset --hard origin/selfhost/census-wip

left_out=""
merged=""
for ref in "$@"; do
  if git merge --no-ff --no-edit "${ref}"; then
    merged="${merged} ${ref}"
    continue
  fi
  conflicted="$(git diff --name-only --diff-filter=U || true)"
  floors_only=1
  if [ -z "${conflicted}" ]; then
    floors_only=0
  fi
  while IFS= read -r path; do
    [ -z "${path}" ] && continue
    case "${path}" in
      *.floor) ;;
      *) floors_only=0 ;;
    esac
  done <<EOF
${conflicted}
EOF
  if [ "${floors_only}" = 1 ] && [ -n "${conflicted}" ] && [ -f "${FLOOR_MERGE}" ]; then
    floor_ok=1
    while IFS= read -r path; do
      [ -z "${path}" ] && continue
      if ! python3 "${FLOOR_MERGE}" "${path}"; then
        floor_ok=0
        break
      fi
      git add "${path}"
    done <<EOF
${conflicted}
EOF
    if [ "${floor_ok}" = 1 ] && git commit --no-edit; then
      merged="${merged} ${ref}"
      echo "merged ${ref} (floor rows unioned)"
      continue
    fi
  fi
  git merge --abort || true
  left_out="${left_out} ${ref}"
  echo "left out ${ref} (does not merge clean)"
done

sha="$(git rev-parse --short=9 HEAD)"
echo "measuring hello at ${sha}"
if [ -n "${merged}" ]; then
  echo "merged:${merged}"
fi
if [ -n "${left_out}" ]; then
  echo "left out:${left_out}"
fi

if ! ./bin/iyi build -o "${WORK}/tool" src/compiler/tools/compile_native.iyi >"${WORK}/tool.build.log" 2>&1; then
  echo "port tool build failed; log ${WORK}/tool.build.log" >&2
  # Keep the log: disable the trap's work deletion by moving it aside.
  kept="${WORK}"
  WORK=""
  echo "build log kept at ${kept}/tool.build.log" >&2
  exit 1
fi

if ! ./bin/iyi build --no-debug --emit llvm-ir -o "${WORK}/hello-hosted" samples/iyi/hello.iyi >"${WORK}/hello-hosted.log" 2>&1; then
  echo "hosted hello IR failed; log ${WORK}/hello-hosted.log" >&2
  kept="${WORK}"
  WORK=""
  echo "IR log kept at ${kept}/hello-hosted.log" >&2
  exit 1
fi

if [ -f "${WORK}/hello-hosted.ll" ]; then
  hosted_ll="${WORK}/hello-hosted.ll"
else
  hosted_ll="${WORK}/hello-hosted"
fi

python3 bench/pipeline_census.py names "${hosted_ll}" -o "${WORK}/hello.names"
# One port-tool process. The driver stops it above 3 GiB.
if ! python3 bench/pipeline_census.py run "${WORK}/tool" samples/iyi/hello.iyi "${WORK}/hello.names" "${WORK}/run" --chunk 10000 --hosted "${hosted_ll}"; then
  kept="${WORK}"
  WORK=""
  echo "census failure logs kept at ${kept}/run" >&2
  exit 1
fi

out_dir="${TABLES}/${sha}-hello"
before_shapes=""
newest=""
newest_mtime=0
if [ -d "${TABLES}" ]; then
  for census_txt in "${TABLES}"/*-hello/census.txt; do
    [ -f "${census_txt}" ] || continue
    shapes="${census_txt%/census.txt}/shapes.tsv"
    [ -f "${shapes}" ] || continue
    mtime="$(stat -f %m "${shapes}")"
    if [ "${mtime}" -gt "${newest_mtime}" ]; then
      newest_mtime="${mtime}"
      newest="${shapes}"
    fi
  done
fi
if [ -n "${newest}" ]; then
  cp "${newest}" "${WORK}/before-shapes.tsv"
  before_shapes="${WORK}/before-shapes.tsv"
fi

mkdir -p "${out_dir}"
python3 bench/pipeline_census.py report "${WORK}/run" --hosted "${hosted_ll}" --write-dir "${out_dir}"

python3 - "${out_dir}/census.txt" "${out_dir}/shapes.tsv" "${before_shapes}" <<'PY'
import sys
from pathlib import Path

census = Path(sys.argv[1]).read_text(encoding="utf-8")
asked = clean = refused = naming = scaffold = "?"
for line in census.splitlines():
    if line.startswith("census:"):
        for part in line.split():
            if "=" in part:
                key, val = part.split("=", 1)
                if key == "asked":
                    asked = val
                elif key == "clean":
                    clean = val
                elif key == "scaffold-failed":
                    scaffold = val
    elif line.startswith("refused="):
        for part in line.split():
            if "=" in part:
                key, val = part.split("=", 1)
                if key == "refused":
                    refused = val
                elif key == "naming":
                    naming = val
print(f"asked={asked} clean={clean} refused={refused} naming={naming} scaffold={scaffold}")

def load(path):
    rows = {}
    if not path:
        return rows
    text = Path(path).read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines:
        return rows
    for line in lines[1:]:
        cols = line.split("\t")
        if len(cols) < 5:
            continue
        shape = cols[4]
        rows[shape] = (cols[1], cols[2])
    return rows

after = load(sys.argv[2])
before = load(sys.argv[3])
shapes = sorted(set(before) | set(after), key=lambda s: (-int(after.get(s, ("0", "0"))[0]), s))
for shape in shapes:
    b = before.get(shape, ("0", "0"))
    a = after.get(shape, ("0", "0"))
    print(f"{b[0]}/{b[1]} -> {a[0]}/{a[1]}\t{shape}")
PY

echo "tables: ${out_dir}"
