#!/usr/bin/env bash
# Copy beside the packaged binaries every shared library they need at
# runtime that a fresh machine has no reason to own — so "extract, put
# bin on PATH" is true rather than true-on-the-machine-that-built-it.
#
# The list is not curated, and that is the point. Every release before
# this script existed shipped a `bin/iyi` that could not start without the
# exact libLLVM it linked against, and no gate saw it because every proof
# of the tarball ran where that library is present by construction. Two
# rounds of "surely that is the last one" followed (libLLVM, then
# libedit), which is what curation buys you. So: take what the loader
# says, minus the handful every glibc/macOS install has by definition,
# and let CI's clean room — a bare image with nothing but a C toolchain —
# be the judge.
#
# Usage: bundle-runtime-libs.sh <package-root>
set -euo pipefail

root=${1:?usage: bundle-runtime-libs.sh <package-root>}
lib="$root/lib"
mkdir -p "$lib"

case "$(uname -s)" in
Linux)
  # What a glibc machine has because it is a glibc machine. Bundling any
  # of these is how you break a package rather than fix it.
  is_base() {
    case "$1" in
    libc.so.* | libm.so.* | libdl.so.* | libpthread.so.* | librt.so.* | \
      libgcc_s.so.* | libresolv.so.* | ld-linux*) return 0 ;;
    esac
    return 1
  }

  # `ldd` on the *packaged* binary reports the whole closure, so one pass
  # per binary is enough: libLLVM's own libedit shows up here too.
  for bin in "$root/bin/"*; do
    [ -f "$bin" ] || continue
    ldd "$bin" 2>/dev/null | awk '/=> \// {print $3}' | while read -r so; do
      base=$(basename "$so")
      is_base "$base" && continue
      [ -e "$lib/$base" ] || cp -L "$so" "$lib/$base"
    done
  done

  ls "$lib" | grep -q '^libLLVM' || {
    echo "bundle-runtime-libs: no libLLVM landed in $lib — the package would"
    echo "need the host's, which is the bug this script exists for."
    exit 1
  }
  ;;

Darwin)
  # macOS ships its own libraries under /usr/lib and /System; anything
  # else came from a package manager the downloader may not have. The
  # walk is iterative rather than recursive: a bundled dylib's own
  # references are rewritten too, and a fixed point ends it.
  outside() {
    case "$1" in
    /usr/lib/* | /System/*) return 1 ;;
    esac
    return 0
  }

  rewrite() { # rewrite <file>
    otool -L "$1" | tail -n +2 | awk '{print $1}' | while read -r ref; do
      case "$ref" in @*) continue ;; esac
      outside "$ref" || continue
      base=$(basename "$ref")
      [ -e "$lib/$base" ] || cp -L "$ref" "$lib/$base"
      chmod u+w "$lib/$base"
      install_name_tool -change "$ref" "@rpath/$base" "$1"
    done
    codesign --force --sign - "$1" >/dev/null 2>&1 || true
  }

  for bin in "$root/bin/"*; do
    [ -f "$bin" ] || continue
    rewrite "$bin"
  done

  # Fixed point: a dylib copied in the pass above may itself name one
  # that is not here yet.
  while :; do
    before=$(ls "$lib" | wc -l)
    for dylib in "$lib"/*; do
      [ -f "$dylib" ] || continue
      install_name_tool -id "@rpath/$(basename "$dylib")" "$dylib" 2>/dev/null || true
      # A dylib resolves its *own* `@rpath` references against its own
      # rpaths, not the executable's — the Mach-O shape of the same
      # lesson `--disable-new-dtags` teaches on Linux.
      install_name_tool -add_rpath "@loader_path" "$dylib" 2>/dev/null || true
      rewrite "$dylib"
    done
    [ "$(ls "$lib" | wc -l)" = "$before" ] && break
  done

  ls "$lib" | grep -q 'libLLVM' || {
    echo "bundle-runtime-libs: no libLLVM landed in $lib — the package would"
    echo "need the host's, which is the bug this script exists for."
    exit 1
  }
  ;;
esac

echo "bundled beside the binaries:"
ls -1 "$lib" | sed 's/^/  /'
