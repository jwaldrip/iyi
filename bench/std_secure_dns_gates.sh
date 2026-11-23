#!/usr/bin/env bash
# A manual probe, not run by CI. It runs bench/std_secure_dns_exercise.sh COUNT
# times and holds each run to the gate's full verdict: the holds line, 18 caught
# mutations, and every section reported ok in plain and in release.
#
#     bash bench/std_secure_dns_gates.sh "$(command -v bash)" 20 bash-here
#
# Run it from the repository root. The matching controls are
# bench/std_secure_dns_controls.py.
set -u
shell="$1" count="$2" label="$3"
for n in $(seq 1 "$count"); do
  log="$(mktemp)"
  echo "=== $label secure DNS exercise $n/$count ==="
  if "$shell" bench/std_secure_dns_exercise.sh >"$log" 2>&1; then code=0; else code=$?; fi
  cat "$log"
  holds="$(grep -Fc 'the std/secure_dns exercise holds' "$log" || true)"
  catches="$(grep -Fc 'caught at "' "$log" || true)"
  plain="$(grep -Ec '^  plain: all [0-9]+ sections reported ok$' "$log" || true)"
  release="$(grep -Ec '^  release: all [0-9]+ sections reported ok$' "$log" || true)"
  rm -f "$log"
  if [ "$code" -ne 0 ] || [ "$holds" -ne 1 ] || [ "$catches" -ne 18 ] || [ "$plain" -ne 1 ] || [ "$release" -ne 1 ]; then
    echo "FAIL: $label run $n had exit=$code holds=$holds catches=$catches plain=$plain release=$release"
    exit 1
  fi
  echo "=== $label secure DNS exercise $n/$count verified ==="
done
