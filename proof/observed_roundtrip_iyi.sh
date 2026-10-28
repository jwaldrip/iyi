#!/usr/bin/env bash
# Route B wrapper: observed producer/consumer roundtrip shim for iyi
# Usage:
#   IYI=proof/observed_roundtrip_iyi.sh \
#   IYI_ROUNDTRIP_REAL=<path_to_compiler> \
#   IYI_ROUNDTRIP_LEDGER=<path_to_ledger_file> \
#   IYI_ROUNDTRIP_CANONICAL=<colon_separated_canonical_roots> \
#   [other environment...] command [args...]

set -euo pipefail

REAL="${IYI_ROUNDTRIP_REAL:-}"
if [ -z "$REAL" ]; then
  # Fallback to repo build if present
  REPO="$(cd "$(dirname "$0")/.." && pwd -P)"
  if [ -x "$REPO/.build/iyi" ]; then
    REAL="$REPO/.build/iyi"
  else
    echo "ERROR: IYI_ROUNDTRIP_REAL must point to the real compiler binary" >&2
    exit 1
  fi
fi

LEDGER="${IYI_ROUNDTRIP_LEDGER:-}"
CANONICAL_SET="${IYI_ROUNDTRIP_CANONICAL:-}"

# Compute canonical roots if not provided
if [ -z "$CANONICAL_SET" ]; then
  W="$(cd "$(dirname "$0")/.." && pwd -P)"
  C_LIST=()
  [ -d "$W/src" ] && C_LIST+=("$(cd "$W/src" && pwd -P)")
  [ -d "$W/samples/iyi" ] && C_LIST+=("$(cd "$W/samples/iyi" && pwd -P)")

  REAL_DIR="$(cd "$(dirname "$REAL")" && pwd -P)"
  P_DIR="$(cd "$REAL_DIR/.." 2>/dev/null && pwd -P || true)"
  if [ -n "$P_DIR" ] && [ -d "$P_DIR" ]; then
    [ -d "$P_DIR/src" ] && C_LIST+=("$(cd "$P_DIR/src" && pwd -P)")
    [ -d "$P_DIR/samples/iyi" ] && C_LIST+=("$(cd "$P_DIR/samples/iyi" && pwd -P)")
  fi

  # Query compiler default path
  DEFAULT_PATH_OUT="$(env -u IYI_PATH -u CRYSTAL_PATH "$REAL" env IYI_PATH 2>/dev/null || true)"
  if [ -n "$DEFAULT_PATH_OUT" ]; then
    IFS=':' read -ra D_ENTRIES <<< "$DEFAULT_PATH_OUT"
    for d in "${D_ENTRIES[@]}"; do
      if [ -n "$d" ] && [ -d "$d" ]; then
        C_LIST+=("$(cd "$d" && pwd -P)")
      fi
    done
  fi

  # Deduplicate canonical list
  CANONICAL_SET="$(printf "%s\n" "${C_LIST[@]}" | sort -u | tr '\n' ':' | sed 's/:$//')"
fi

is_canonical_root() {
  local target="$1"
  local old_ifs="$IFS"
  IFS=':'
  local matched=1
  for c in $CANONICAL_SET; do
    if [ "$target" = "$c" ]; then
      matched=0
      break
    fi
  done
  IFS="$old_ifs"
  return "$matched"
}

log_ledger() {
  local l_mode="$1"
  local l_code="$2"
  local l_args="$3"
  if [ -n "$LEDGER" ]; then
    local ts
    ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    mkdir -p "$(dirname "$LEDGER")" 2>/dev/null || true
    printf "%s\t%s\t%s\t%s\t%s\t%s\n" \
      "$ts" "$l_mode" "$l_code" "$(pwd -P)" "${REAL_ROOTS:-none}" "$l_args" >> "$LEDGER"
  fi
}

CMD="${1:-}"
if [ $# -eq 0 ]; then
  exec "$REAL"
fi

# Detect search path from environment
SEARCH_PATH=""
if [ -n "${IYI_PATH+x}" ] && [ -n "$IYI_PATH" ]; then
  SEARCH_PATH="$IYI_PATH"
elif [ -n "${CRYSTAL_PATH+x}" ] && [ -n "$CRYSTAL_PATH" ]; then
  SEARCH_PATH="$CRYSTAL_PATH"
fi

IS_PATCHED=0
REAL_ROOTS=""
if [ -n "$SEARCH_PATH" ]; then
  old_ifs="$IFS"
  IFS=':' read -ra PATH_ENTRIES <<< "$SEARCH_PATH"
  IFS="$old_ifs"
  for entry in "${PATH_ENTRIES[@]}"; do
    [ -n "$entry" ] || continue
    if [ -d "$entry" ]; then
      real_dir="$(cd "$entry" 2>/dev/null && pwd -P || true)"
      if [ -n "$real_dir" ]; then
        REAL_ROOTS="${REAL_ROOTS:+$REAL_ROOTS:}$real_dir"
        if ! is_canonical_root "$real_dir"; then
          IS_PATCHED=1
        fi
      fi
    fi
  done
fi

# 1. Check for 'unchanged' triggers:
# If command is not 'build' and not 'run', or args include cross-compile, crystal, etc.
IS_UNCHANGED=0
if [ "$CMD" != "build" ] && [ "$CMD" != "run" ]; then
  IS_UNCHANGED=1
fi

for arg in "$@"; do
  case "$arg" in
    --crystal|--cross-compile*|--no-codegen|--emit|--emit=*|--emit-bind|--emit-bind=*)
      IS_UNCHANGED=1
      ;;
  esac
done

if [ "$IS_UNCHANGED" -eq 1 ]; then
  set +e
  "$REAL" "$@"
  rc=$?
  set -e
  log_ledger "unchanged" "$rc" "$*"
  exit "$rc"
fi

# 2. Check for 'observed-passthrough':
# If args already include --emit-iyimod or --use-iyimod
IS_PASSTHROUGH=0
for arg in "$@"; do
  case "$arg" in
    --emit-iyimod*|--use-iyimod*)
      IS_PASSTHROUGH=1
      ;;
  esac
done

if [ "$IS_PASSTHROUGH" -eq 1 ]; then
  # Check if -Diyi_observe is already in args
  has_obs=0
  for a in "$@"; do
    if [ "$a" = "-Diyi_observe" ]; then
      has_obs=1
      break
    fi
  done
  set +e
  if [ "$has_obs" -eq 1 ]; then
    "$REAL" "$@"
  else
    "$REAL" "$CMD" "-Diyi_observe" "${@:2}"
  fi
  rc=$?
  set -e
  log_ledger "observed-passthrough" "$rc" "$*"
  exit "$rc"
fi

# 3. Patched build or run
if [ "$IS_PATCHED" -eq 1 ]; then
  has_obs=0
  for a in "$@"; do
    if [ "$a" = "-Diyi_observe" ]; then
      has_obs=1
      break
    fi
  done

  if [ "$CMD" = "build" ]; then
    mode="observed-source"
  else
    mode="observed-run"
  fi

  set +e
  if [ "$has_obs" -eq 1 ]; then
    "$REAL" "$@"
  else
    "$REAL" "$CMD" "-Diyi_observe" "${@:2}"
  fi
  rc=$?
  set -e
  log_ledger "$mode" "$rc" "$*"
  exit "$rc"
fi

# 4. Canonical build or run
if [ "$CMD" = "build" ]; then
  # Roundtrip: observed producer then observed consumer
  MODS="$(mktemp -d "${TMPDIR:-/tmp}/iyi_rt_mods.XXXXXX")"
  cleanup_mods() {
    rm -rf "$MODS" 2>/dev/null || true
  }
  trap cleanup_mods EXIT

  # Producer build
  set +e
  "$REAL" build -Diyi_observe --emit-iyimod "$MODS" "${@:2}"
  prod_rc=$?
  set -e
  if [ "$prod_rc" -ne 0 ]; then
    log_ledger "roundtrip" "$prod_rc" "$* (producer exit $prod_rc)"
    exit "$prod_rc"
  fi

  # Consumer build
  set +e
  "$REAL" build -Diyi_observe --use-iyimod "$MODS" "${@:2}"
  cons_rc=$?
  set -e

  log_ledger "roundtrip" "$cons_rc" "$*"
  exit "$cons_rc"

elif [ "$CMD" = "run" ]; then
  # Check if '--' is in arguments
  has_dash_dash=0
  split_idx=-1
  idx=0
  for a in "${@:2}"; do
    if [ "$a" = "--" ]; then
      has_dash_dash=1
      split_idx=$idx
      break
    fi
    idx=$((idx + 1))
  done

  if [ "$has_dash_dash" -eq 1 ]; then
    # Roundtrip: build binary with producer/consumer, then execute
    all_run_args=("${@:2}")
    build_args=("${all_run_args[@]:0:$split_idx}")
    run_args=("${all_run_args[@]:$((split_idx + 1))}")

    has_dash_o=0
    out_bin=""
    b_idx=0
    while [ "$b_idx" -lt "${#build_args[@]}" ]; do
      arg="${build_args[$b_idx]}"
      if [ "$arg" = "-o" ]; then
        has_dash_o=1
        out_bin="${build_args[$((b_idx + 1))]}"
        break
      elif [[ "$arg" =~ ^-o(.+)$ ]]; then
        has_dash_o=1
        out_bin="${BASH_REMATCH[1]}"
        break
      fi
      b_idx=$((b_idx + 1))
    done

    clean_bin=0
    if [ "$has_dash_o" -eq 0 ]; then
      out_bin="$(mktemp "${TMPDIR:-/tmp}/iyi_rt_bin.XXXXXX")"
      build_args+=("-o" "$out_bin")
      clean_bin=1
    fi

    MODS="$(mktemp -d "${TMPDIR:-/tmp}/iyi_rt_mods.XXXXXX")"
    cleanup_run() {
      rm -rf "$MODS" 2>/dev/null || true
      if [ "$clean_bin" -eq 1 ]; then
        rm -f "$out_bin" 2>/dev/null || true
      fi
    }
    trap cleanup_run EXIT

    # Producer build
    set +e
    "$REAL" build -Diyi_observe --emit-iyimod "$MODS" "${build_args[@]}"
    prod_rc=$?
    set -e
    if [ "$prod_rc" -ne 0 ]; then
      log_ledger "roundtrip" "$prod_rc" "$* (producer exit $prod_rc)"
      exit "$prod_rc"
    fi

    # Consumer build
    set +e
    "$REAL" build -Diyi_observe --use-iyimod "$MODS" "${build_args[@]}"
    cons_rc=$?
    set -e
    if [ "$cons_rc" -ne 0 ]; then
      log_ledger "roundtrip" "$cons_rc" "$* (consumer exit $cons_rc)"
      exit "$cons_rc"
    fi

    # Execute consumer binary with runtime arguments
    set +e
    "$out_bin" "${run_args[@]}"
    run_rc=$?
    set -e
    log_ledger "roundtrip" "$run_rc" "$*"
    exit "$run_rc"

  else
    # Canonical run without '--': observed-run
    has_obs=0
    for a in "$@"; do
      if [ "$a" = "-Diyi_observe" ]; then
        has_obs=1
        break
      fi
    done
    set +e
    if [ "$has_obs" -eq 1 ]; then
      "$REAL" "$@"
    else
      "$REAL" run -Diyi_observe "${@:2}"
    fi
    run_rc=$?
    set -e
    log_ledger "observed-run" "$run_rc" "$*"
    exit "$run_rc"
  fi
fi
