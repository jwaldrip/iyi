#!/usr/bin/env bash
# Shared mutation proof for the selfhost gates (SPEC 3.8).
#
#   . "$REPO/bench/lib/mutation.sh"
#   prove_mutation     <label> <file> <old> <new> -- <check command...>
#   prove_mutation_all <label> <file> <old> <new> -- <check command...>
#
# Copies <file> aside, replaces <old> with <new> (literal text, not a pattern),
# then runs the check and requires it to FAIL.
#   prove_mutation     replaces the FIRST occurrence of <old>.
#   prove_mutation_all replaces EVERY occurrence, as sed's s/// does on each
#                      matching line. Use it where the mutation is meant to
#                      change every site the label names.
#   - check fails  -> prints "    caught: <label>", returns 0
#   - check passes -> prints "    FAIL: mutation was not caught: <label>", returns 1
#   - <old> absent, or the patch changes nothing -> prints
#     "PATCH CHANGED NOTHING: this proves nothing", exits 3
#
# The check runs as a background job in its own process group. The file is
# restored, and the copy aside removed, through traps on EXIT, INT and TERM,
# so an interrupt never leaves a mutated source behind. The traps that were
# set before the call (for example a WORK cleanup) are put back afterwards.
#
# The check is a command or a shell function. It must return non-zero when
# the mutated file is detected. A check that cannot run also counts as caught,
# which is why each check should exit 0 only on the unmutated behaviour.

_PM_ARMED=0
_PM_FILE=""
_PM_BACKUP=""
_PM_CHILD=""
_PM_MONITOR=0
_PM_SAVED_EXIT=""
_PM_SAVED_INT=""
_PM_SAVED_TERM=""

_prove_mutation_restore() {
  if [ -n "$_PM_CHILD" ]; then
    if [ "$_PM_MONITOR" -eq 1 ]; then
      kill -TERM -- "-$_PM_CHILD" 2>/dev/null || true
    else
      kill -TERM "$_PM_CHILD" 2>/dev/null || true
    fi
    wait "$_PM_CHILD" 2>/dev/null || true
    _PM_CHILD=""
  fi
  if [ -n "$_PM_BACKUP" ] && [ -f "$_PM_BACKUP" ]; then
    cp "$_PM_BACKUP" "$_PM_FILE"
    rm -f "$_PM_BACKUP"
  fi
  _PM_BACKUP=""
}

_prove_mutation_disarm() {
  [ "$_PM_ARMED" -eq 1 ] || return 0
  _prove_mutation_restore
  trap - EXIT INT TERM
  [ -n "$_PM_SAVED_EXIT" ] && eval "$_PM_SAVED_EXIT"
  [ -n "$_PM_SAVED_INT" ] && eval "$_PM_SAVED_INT"
  [ -n "$_PM_SAVED_TERM" ] && eval "$_PM_SAVED_TERM"
  _PM_ARMED=0
}

_prove_mutation_signal() {
  _prove_mutation_disarm
  exit "$1"
}

_prove_mutation_arm() {
  _PM_FILE="$1"
  _PM_BACKUP="$2"
  _PM_SAVED_EXIT="$(trap -p EXIT)"
  _PM_SAVED_INT="$(trap -p INT)"
  _PM_SAVED_TERM="$(trap -p TERM)"
  _PM_ARMED=1
  trap '_prove_mutation_restore' EXIT
  trap '_prove_mutation_signal 130' INT
  trap '_prove_mutation_signal 143' TERM
}

# _prove_mutation_run <all|first> <label> <file> <old> <new> -- <check...>
_prove_mutation_run() {
  local mode="$1" label="$2" file="$3" old="$4" new="$5"
  shift 5
  if [ "${1:-}" != "--" ]; then
    echo "prove_mutation: expected -- before the check command ($label)" >&2
    exit 2
  fi
  shift
  if [ "$#" -eq 0 ]; then
    echo "prove_mutation: no check command given ($label)" >&2
    exit 2
  fi

  local original patched backup log rc=0 monitor_was_on=0
  original="$(cat "$file"; printf x)"
  original="${original%x}"
  case "$original" in
    *"$old"*) ;;
    *)
      echo "PATCH CHANGED NOTHING: this proves nothing ($label: text not found in $file)"
      exit 3
      ;;
  esac
  # The replacement is written unquoted. bash 3.2 (darwin's /bin/bash, which a runner with no newer bash on its PATH
  # runs these gates with) keeps a quoted replacement's quotes as text: every mutation arrived wrapped in '"', and a
  # patch that changes nothing changed two bytes and was run as a mutation. From bash 5.2 an unquoted '&' in a
  # replacement is the matched text unless patsub_replacement is off, so it is turned off around the edit.
  local patsub_was_on=0
  if shopt -q patsub_replacement 2>/dev/null; then
    patsub_was_on=1
    shopt -u patsub_replacement
  fi
  if [ "$mode" = all ]; then
    patched="${original//"$old"/$new}"
  else
    patched="${original/"$old"/$new}"
  fi
  if [ "$patsub_was_on" -eq 1 ]; then shopt -s patsub_replacement; fi
  if [ "$patched" = "$original" ]; then
    echo "PATCH CHANGED NOTHING: this proves nothing ($label: replacement left $file unchanged)"
    exit 3
  fi

  backup="$(mktemp)"
  cp "$file" "$backup"
  log="$(mktemp)"

  case $- in *m*) monitor_was_on=1 ;; esac
  set -m
  _PM_MONITOR=1
  _prove_mutation_arm "$file" "$backup"
  printf '%s' "$patched" > "$file"

  { "$@" > "$log" 2>&1 & } 2>/dev/null
  _PM_CHILD=$!
  wait "$_PM_CHILD" || rc=$?
  _PM_CHILD=""

  _prove_mutation_disarm
  [ "$monitor_was_on" -eq 1 ] || set +m
  _PM_MONITOR=0

  if [ "$rc" -ne 0 ]; then
    rm -f "$log"
    echo "    caught: $label"
    return 0
  fi
  echo "    FAIL: mutation was not caught: $label"
  echo "    check output (last lines):"
  tail -n 20 "$log" | sed 's/^/      /'
  rm -f "$log"
  return 1
}

prove_mutation() {
  _prove_mutation_run first "$@"
}

prove_mutation_all() {
  _prove_mutation_run all "$@"
}
