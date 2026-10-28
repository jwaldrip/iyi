#!/usr/bin/env bash
# Master orchestration harness for Observed Corpus Final Proof
# Executes Run 1, Run 2, and Run 3 with mandatory identity checks,
# disk space guards, and ledger verifications.
#
# Usage:
#   bash proof/run_proof.sh [--check-identity | --run1 | --run2 | --run3 | --all]

set -euo pipefail

W="$(cd "$(dirname "$0")/.." && pwd -P)"
P="${P_DIR:-/Users/jwaldrip/dev/worktrees/iyi-stale-integration-repair}"
COMPILER="${COMPILER:-$P/.build/iyi}"

# Verify worktree and compiler presence
if [ ! -d "$P" ]; then
  echo "ERROR: Primary worktree P not found at $P" >&2
  exit 1
fi
if [ ! -x "$COMPILER" ]; then
  echo "ERROR: Compiler binary not executable at $COMPILER" >&2
  exit 1
fi

REPORT_DIR="${REPORT_DIR:-/tmp/iyi_proof_reports_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$REPORT_DIR"

# Compute canonical roots
CANONICAL_SET="${IYI_ROUNDTRIP_CANONICAL:-}"
if [ -z "$CANONICAL_SET" ]; then
  C_LIST=()
  [ -d "$W/src" ] && C_LIST+=("$(cd "$W/src" && pwd -P)")
  [ -d "$W/samples/iyi" ] && C_LIST+=("$(cd "$W/samples/iyi" && pwd -P)")
  [ -d "$P/src" ] && C_LIST+=("$(cd "$P/src" && pwd -P)")
  [ -d "$P/samples/iyi" ] && C_LIST+=("$(cd "$P/samples/iyi" && pwd -P)")

  DEFAULT_PATH_OUT="$(env -u IYI_PATH -u CRYSTAL_PATH "$COMPILER" env IYI_PATH 2>/dev/null || true)"
  if [ -n "$DEFAULT_PATH_OUT" ]; then
    IFS=':' read -ra D_ENTRIES <<< "$DEFAULT_PATH_OUT"
    for d in "${D_ENTRIES[@]}"; do
      if [ -n "$d" ] && [ -d "$d" ]; then
        C_LIST+=("$(cd "$d" && pwd -P)")
      fi
    done
  fi
  CANONICAL_SET="$(printf "%s\n" "${C_LIST[@]}" | sort -u | tr '\n' ':' | sed 's/:$//')"
fi

# Pinning variables
P_SOURCE_SHA="${P_SOURCE_SHA:-$(git -C "$P" rev-parse HEAD)}"
W_HEAD="${W_HEAD:-$(git -C "$W" rev-parse HEAD)}"
BIN_SHA="${BIN_SHA:-$(shasum -a 256 "$COMPILER" | awk '{print $1}')}"

check_disk() {
  local avail_gb
  avail_gb=$(df -g /tmp | awk 'NR==2 {print $4}')
  if [ "$avail_gb" -lt 20 ]; then
    echo "ERROR: Less than 20 GB free on /tmp ($avail_gb GB). Halting per specification!" >&2
    exit 1
  fi
}

check_identity() {
  local step_label="$1"
  echo "--- Checking identity: $step_label ---"

  # 1. P HEAD == P_SOURCE_SHA and P clean
  local p_curr
  p_curr="$(git -C "$P" rev-parse HEAD)"
  if [ "$p_curr" != "$P_SOURCE_SHA" ]; then
    echo "ERROR: P HEAD mutated! Expected $P_SOURCE_SHA, got $p_curr" >&2
    exit 1
  fi
  if [ -n "$(git -C "$P" status --porcelain)" ]; then
    echo "ERROR: P worktree is dirty!" >&2
    exit 1
  fi

  # 2. W HEAD == W_HEAD and W clean
  local w_curr
  w_curr="$(git -C "$W" rev-parse HEAD)"
  if [ "$w_curr" != "$W_HEAD" ]; then
    echo "ERROR: W HEAD mutated! Expected $W_HEAD, got $w_curr" >&2
    exit 1
  fi
  if [ -n "$(git -C "$W" status --porcelain)" ]; then
    echo "ERROR: W worktree is dirty!" >&2
    exit 1
  fi

  # 3. P_SOURCE_SHA is ancestor of W_HEAD
  if ! git -C "$W" merge-base --is-ancestor "$P_SOURCE_SHA" "$W_HEAD"; then
    echo "ERROR: P_SOURCE_SHA ($P_SOURCE_SHA) is not ancestor of W_HEAD ($W_HEAD)!" >&2
    exit 1
  fi

  # 4. diff lists only paths under proof/
  local diff_paths
  diff_paths="$(git -C "$W" diff --name-only "$P_SOURCE_SHA" "$W_HEAD")"
  for p in $diff_paths; do
    if [[ "$p" != proof/* ]]; then
      echo "ERROR: Non-proof file modified in W: $p" >&2
      exit 1
    fi
  done
  if ! git -C "$W" diff --quiet "$P_SOURCE_SHA" "$W_HEAD" -- . ':(exclude)proof'; then
    echo "ERROR: Product files in W differ from P_SOURCE_SHA!" >&2
    exit 1
  fi

  # 5. Compiler binary hash equals BIN_SHA
  local bin_curr
  bin_curr="$(shasum -a 256 "$COMPILER" | awk '{print $1}')"
  if [ "$bin_curr" != "$BIN_SHA" ]; then
    echo "ERROR: Compiler binary hash changed! Expected $BIN_SHA, got $bin_curr" >&2
    exit 1
  fi

  echo "Identity verified: P=$P_SOURCE_SHA, W=$W_HEAD, BIN=$BIN_SHA (clean)"
}

run_run1() {
  echo "=========================================================="
  echo "RUN 1: Existing Gates and Foundation"
  echo "=========================================================="
  check_disk

  # 1.1 stale_equivalence.sh all
  echo "== Run 1.1: stale_equivalence.sh all =="
  IYI="$COMPILER" bash "$W/bench/stale_equivalence.sh" all </dev/null 2>&1 | tee "$REPORT_DIR/run1_equiv.log"
  check_identity "after Run 1.1 (stale_equivalence.sh all)"

  # 1.2 std_observe_exercise.sh
  echo "== Run 1.2: std_observe_exercise.sh =="
  IYI="$COMPILER" bash "$W/bench/std_observe_exercise.sh" </dev/null 2>&1 | tee "$REPORT_DIR/run1_observe.log"
  check_identity "after Run 1.2 (std_observe_exercise.sh)"

  # 1.3 stale_rg9.py (IYI_RG9_C3_SAMPLE unset)
  echo "== Run 1.3: stale_rg9.py =="
  local rg9_work
  rg9_work="$(mktemp -d /tmp/rg9_work.XXXXXX)"
  (
    env -u IYI_OPTS -u CRYSTAL_OPTS -u IYI_WARM -u IYI_OBSERVE -u IYI_RG9_C3_SAMPLE \
      python3 "$W/bench/stale_rg9.py" --repo "$W" --compiler "$COMPILER" --work "$rg9_work"
  ) 2>&1 | tee "$REPORT_DIR/run1_rg9.log"
  rm -rf "$rg9_work"
  check_identity "after Run 1.3 (stale_rg9.py)"

  # 1.4 std_exercise.sh (plain foundation + unsharded 115 siblings)
  echo "== Run 1.4: std_exercise.sh with siblings =="
  (
    STD_SIBLINGS=1 IYI="$COMPILER" bash "$W/bench/std_exercise.sh" </dev/null
  ) 2>&1 | tee "$REPORT_DIR/run1_std_exercise.log"
  check_identity "after Run 1.4 (std_exercise.sh)"

  echo "RUN 1 PASSED."
}

run_run2() {
  echo "=========================================================="
  echo "RUN 2: All 141 Artifact Legs (P, C1, C2, C3)"
  echo "=========================================================="
  check_disk

  local run2_work
  run2_work="$(mktemp -d /tmp/run2_artifact_work.XXXXXX)"
  python3 "$W/proof/artifact_legs.py" \
    --repo "$W" \
    --compiler "$COMPILER" \
    --work "$run2_work" \
    --report "$REPORT_DIR/run2_artifact_legs.jsonl" \
    --workers 2 2>&1 | tee "$REPORT_DIR/run2_artifact_legs.log"
  rm -rf "$run2_work"

  check_identity "after Run 2"
  echo "RUN 2 PASSED."
}

run_run3() {
  echo "=========================================================="
  echo "RUN 3: 29 Driver-Required Exercises"
  echo "=========================================================="
  check_disk

  local drivers=(
    acme autocert cookie dns fileserver http router secure_dns
    signal smtp sse term tls websocket
    bzip2 compress hpke math mlkem png regex shlex tar xz zip zstd
    file file_utils fuzz
  )

  # Check if run2 report identified additional p_nonzero programs
  if [ -f "$REPORT_DIR/run2_artifact_legs.jsonl" ]; then
    while IFS= read -r line; do
      local is_pnz name
      is_pnz="$(echo "$line" | grep '"p_nonzero": true' || true)"
      if [ -n "$is_pnz" ]; then
        name="$(echo "$line" | sed -E 's/.*"base": "([^"]+)".*/\1/')"
        # Strip std_ and _exercise
        drv_name="$(echo "$name" | sed -E 's/^std_//; s/_exercise$//')"
        # Add if not already in drivers
        local found=0
        for d in "${drivers[@]}"; do
          if [ "$d" = "$drv_name" ]; then
            found=1
            break
          fi
        done
        if [ "$found" -eq 0 ]; then
          echo "Adding P-nonzero exercise to Run 3: $drv_name"
          drivers+=("$drv_name")
        fi
      fi
    done < "$REPORT_DIR/run2_artifact_legs.jsonl"
  fi

  for drv in "${drivers[@]}"; do
    echo "--- Running Driver: $drv ---"
    check_disk

    local drv_script="$W/bench/std_${drv}_exercise.sh"
    if [ ! -f "$drv_script" ]; then
      echo "WARNING: Driver script $drv_script not found, skipping"
      continue
    fi

    local ledger="$REPORT_DIR/ledger_${drv}.tsv"
    local drv_cache
    drv_cache="$(mktemp -d /tmp/drv_cache_${drv}.XXXXXX)"

    set +e
    (
      env -u IYI_PATH -u CRYSTAL_PATH -u IYI_OPTS -u CRYSTAL_OPTS -u IYI_WARM -u IYI_OBSERVE \
        IYI="$W/proof/observed_roundtrip_iyi.sh" \
        IYI_ROUNDTRIP_REAL="$COMPILER" \
        IYI_ROUNDTRIP_LEDGER="$ledger" \
        IYI_ROUNDTRIP_CANONICAL="$CANONICAL_SET" \
        IYI_CACHE_DIR="$drv_cache" \
        bash "$drv_script" </dev/null
    ) 2>&1 | tee "$REPORT_DIR/driver_${drv}.log"
    local drv_rc=$?
    set -e

    rm -rf "$drv_cache"

    if [ "$drv_rc" -ne 0 ]; then
      echo "ERROR: Driver $drv failed with exit $drv_rc" >&2
      exit 1
    fi

    # Verify ledger
    python3 "$W/proof/verify_ledger.py" --ledger "$ledger" --driver "$drv"

    # Identity check after each driver (also guards against patches written into tree)
    check_identity "after driver $drv"
  done

  echo "RUN 3 PASSED."
}

MODE="${1:---plan}"

case "$MODE" in
  --check-identity)
    check_identity "manual check"
    ;;
  --run1)
    check_identity "before Run 1"
    run_run1
    ;;
  --run2)
    check_identity "before Run 2"
    run_run2
    ;;
  --run3)
    check_identity "before Run 3"
    run_run3
    ;;
  --all)
    check_identity "initial pre-run check"
    run_run1
    run_run2
    run_run3
    check_identity "final post-run check"
    echo "=========================================================="
    echo "ALL OBSERVED CORPUS PROOF RUNS PASSED SUCCESSFULLY!"
    echo "Reports preserved under: $REPORT_DIR"
    echo "=========================================================="
    ;;
  --plan)
    echo "Observed Corpus Final Proof Harness"
    echo "  P:        $P (SHA: $P_SOURCE_SHA)"
    echo "  W:        $W (HEAD: $W_HEAD)"
    echo "  Compiler: $COMPILER (SHA: $BIN_SHA)"
    echo "  Reports:  $REPORT_DIR"
    echo "Usage: $0 [--check-identity | --run1 | --run2 | --run3 | --all]"
    ;;
  *)
    echo "Unknown option: $MODE" >&2
    echo "Usage: $0 [--check-identity | --run1 | --run2 | --run3 | --all]" >&2
    exit 1
    ;;
esac
