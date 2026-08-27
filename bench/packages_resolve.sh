#!/usr/bin/env bash
# Drives SPEC.md III.7 step 1: `iyi.mod`, minimal version selection, and a
# git fetcher — source only, no registry, no network. The registry-shaped
# half of III.7 (artifacts, signatures, the index) is later steps and is
# not exercised here.
#
#     bash bench/packages_resolve.sh
#
# Everything runs against `IYI_MOD_MIRROR`, the offline hook: a directory
# whose layout is the module path and whose entries are bare git repos, so
# the fetch is real git against a fixture this script builds. Five steps,
# two of them failure proofs:
#
#   1. MVS picks the highest minimum: the app asks for liba v1.0.0, its
#      other dependency asks for v1.1.0, and the program must print v1.1.0
#      and never v1.0.0.
#   2. The second build resolves from the cache: the mirror is deleted and
#      the build must still succeed, because a checkout, once fetched, is
#      read rather than refetched.
#   3. A dotted import with no manifest is refused naming `iyi.mod`.
#   4. A require whose tag does not exist is refused naming the tag.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
WORK="$(mktemp -d)"
export IYI_CACHE_DIR="$WORK/cache"
export IYI_MOD_MIRROR="$WORK/mirror"

cd "$WORK" || exit 1

step() { echo "== $1"; }
mkrepo() { git init -q "$1" && git -C "$1" config user.email t@t && git -C "$1" config user.name t; }

# ── The fixture: two packages, three versions, one raise ─────────────────
mkrepo work/liba
printf 'module example.test/user/liba\n' > work/liba/iyi.mod
printf 'module liba\n\npub def greeting : String\n  "hello from liba v1.0.0"\nend\n' > work/liba/liba.iyi
printf 'module colors\n\npub def favourite : String\n  "green"\nend\n' > work/liba/colors.iyi
git -C work/liba add -A && git -C work/liba commit -qm one && git -C work/liba tag v1.0.0
sed -i 's/v1.0.0/v1.1.0/' work/liba/liba.iyi
git -C work/liba commit -qam two && git -C work/liba tag v1.1.0

mkrepo work/libb
printf 'module example.test/user/libb\nrequire example.test/user/liba v1.1.0\n' > work/libb/iyi.mod
printf 'module libb\n\nimport example.test/user/liba\nusing example.test/user/liba::{greeting}\n\npub def doubled : String\n  greeting + " / " + greeting\nend\n' > work/libb/libb.iyi
git -C work/libb add -A && git -C work/libb commit -qm one && git -C work/libb tag v1.0.0

mkdir -p mirror/example.test/user
git clone -q --bare work/liba mirror/example.test/user/liba
git clone -q --bare work/libb mirror/example.test/user/libb

mkdir -p app
printf 'module example.test/user/app\nrequire example.test/user/liba v1.0.0\nrequire example.test/user/libb v1.0.0\n' > app/iyi.mod
cat > app/main.iyi <<'IYI'
import example.test/user/liba
import example.test/user/liba/colors
import example.test/user/libb
using example.test/user/liba::{greeting}
using example.test/user/liba/colors::{favourite}
using example.test/user/libb::{doubled}

puts greeting
puts favourite
puts doubled
IYI

# ── 1. MVS: the highest of the minimums, observably ──────────────────────
step "MVS picks the raised version"
if ! (cd app && "$IYI" build main.iyi -o app) > build.log 2>&1; then
  echo "build failed:"
  tail -8 build.log
  exit 1
fi
./app/app > answers.txt 2>&1
grep -q 'hello from liba v1.1.0' answers.txt || { echo "v1.1.0 never ran:"; cat answers.txt; exit 1; }
grep -q 'v1.0.0' answers.txt && { echo "the version MVS discarded still ran:"; cat answers.txt; exit 1; }
grep -q 'green' answers.txt || { echo "the sub-module import lost:"; cat answers.txt; exit 1; }

# ── 2. The cache is the second build's source ────────────────────────────
step "a fetched checkout is read, not refetched"
rm -rf mirror app/app
if ! (cd app && "$IYI" build main.iyi -o app) > build2.log 2>&1; then
  echo "the second build refetched, and there was nothing to fetch from:"
  tail -8 build2.log
  exit 1
fi
./app/app | grep -q 'v1.1.0' || { echo "cache-built program answered differently"; exit 1; }

# ── 3. Failure proof: a package import needs a manifest ──────────────────
step "failure proof: a dotted import without iyi.mod names the manifest"
mkdir -p bare
printf 'import example.test/user/liba\nputs 1\n' > bare/main.iyi
(cd bare && "$IYI" build main.iyi -o bare) > bare.log 2>&1
if [ $? -eq 0 ] || ! grep -q 'iyi.mod' bare.log; then
  echo "the refusal did not name the manifest:"
  tail -6 bare.log
  exit 1
fi

# ── 4. Failure proof: a version is a tag that must exist ─────────────────
step "failure proof: a missing tag is refused by name"
mkdir -p wrong
printf 'module example.test/user/wrong\nrequire example.test/user/libb v9.9.9\n' > wrong/iyi.mod
printf 'import example.test/user/libb\nputs 1\n' > wrong/main.iyi
mkdir -p mirror/example.test/user
git clone -q --bare work/libb mirror/example.test/user/libb
(cd wrong && "$IYI" build main.iyi -o wrong) > wrong.log 2>&1
if [ $? -eq 0 ] || ! grep -q 'v9.9.9' wrong.log; then
  echo "the refusal did not name the tag:"
  tail -6 wrong.log
  exit 1
fi

echo "workdir $WORK"
echo "packages gate: every step held"
exit 0
