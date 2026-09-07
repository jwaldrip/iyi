#!/bin/sh
# Installs the latest iyi release into ~/.local (bin/, lib/, share/iyi/):
#
#   curl -fsSL https://raw.githubusercontent.com/sdogruyol/iyi/master/install.sh | sh
#
# IYI_PREFIX   where to unpack, default ~/.local; the tarball is relocatable
# IYI_VERSION  a release to pin, e.g. 0.10.0; default is the latest release
#
# POSIX sh, curl and tar are all it needs. The release is resolved by
# following GitHub's /releases/latest redirect, not the API, so there is
# no token and no rate limit in the way.
set -eu

repo="sdogruyol/iyi"
prefix="${IYI_PREFIX:-$HOME/.local}"
version="${IYI_VERSION:-}"

say() { printf '%s\n' "$*" >&2; }
die() { say "install.sh: $*"; exit 1; }

for tool in curl tar; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

os="$(uname -s)"
arch="$(uname -m)"
case "$os-$arch" in
  Linux-x86_64) target=linux-x86_64 ;;
  Darwin-arm64) target=darwin-arm64 ;;
  *) die "no release for $os $arch: releases ship linux-x86_64 and darwin-arm64, see README.md (Getting it) to build from source" ;;
esac

if [ -z "$version" ]; then
  tag_url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest")" ||
    die "could not resolve the latest release of $repo"
  version="${tag_url##*/tag/v}"
  [ "$version" != "$tag_url" ] || die "unexpected redirect for the latest release: $tag_url"
fi
version="${version#v}"

asset="iyi-$version-$target.tar.gz"
url="https://github.com/$repo/releases/download/v$version/$asset"

mkdir -p "$prefix" 2>/dev/null && [ -w "$prefix" ] ||
  die "$prefix is not writable; set IYI_PREFIX to a directory that is"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "iyi $version for $target"
curl -fSL --progress-bar -o "$tmp/$asset" "$url" || die "download failed: $url"
tar -xzf "$tmp/$asset" -C "$prefix"

"$prefix/bin/iyi" version >/dev/null || die "$prefix/bin/iyi does not start"

say "installed $prefix/bin/iyi"
command -v cc >/dev/null 2>&1 ||
  say "note: no C compiler on PATH; iyi links through cc, so install gcc or clang before building"

case ":$PATH:" in
  *":$prefix/bin:"*) ;;
  *) say "note: add $prefix/bin to PATH, e.g. export PATH=\"$prefix/bin:\$PATH\"" ;;
esac
say "try: $prefix/bin/iyi run $prefix/share/iyi/samples/hello.iyi"
