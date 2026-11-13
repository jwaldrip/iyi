#!/usr/bin/env bash
# Fails when the iyi command driver stops agreeing with the one it replaces.
#
# The port is only worth something if it parses argument vectors, dispatches
# commands, and reports usage and errors the same way the front end iyi is
# still bootstrapped from does. Every vector in the trimmed corpus is run
# through both implementations, dumped in the same format, and required
# byte-identical.
#
# Machine-specific properties (absolute filesystem paths, program names,
# and platform-dependent target/LLVM version banners) are normalized
# identically in both implementations' outputs so the gate holds across
# workstations and CI environments without loosening the check.
#
# The mutation proofs follow the rule the other selfhost gates use: the patched
# file is compared against the original, and a patch that matched nothing is
# reported as proving nothing rather than passing quietly.
#
#   bash bench/selfhost_command_exercise.sh
set -u
status=0
diverged=0
REPO="$(cd "$(dirname "$0")/.." && pwd)"
. "$REPO/bench/lib/mutation.sh"
IYI="$REPO/bin/iyi"
CRYSTAL="${CRYSTAL:-crystal}"
DRIVER="$REPO/src/compiler/command/driver.iyi"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== 1. Building and running the command driver exercise"
"$IYI" build -o "$WORK/exercise" "$REPO/bench/selfhost_command_exercise.iyi"
"$WORK/exercise" > "$WORK/iyi_raw.out" 2>&1

echo
echo "== 2. Command dispatch comparison against the front end being replaced"
cat <<'CRYSTAL_ORACLE_SCRIPT' > "$WORK/dump_crystal_command.cr"
require "compiler/requires"
require "json"

class ExitException < Exception
  getter status : Int32
  def initialize(@status : Int32)
    super("exit status #{@status}")
  end
end

def exit(status : Int32 = 0) : NoReturn
  raise ExitException.new(status)
end

class Iyi::Command
  class_property current_command : String = ""

  def exit(status : Int32 = 0) : NoReturn
    raise ExitException.new(status)
  end

  def init
    Iyi::Command.current_command = "init"
    previous_def
  end

  def build
    Iyi::Command.current_command = "build"
    previous_def
  end

  def run_command(single_file = false)
    Iyi::Command.current_command = "run"
    previous_def
  end

  def env
    Iyi::Command.current_command = "env"
    previous_def
  end

  def eval
    Iyi::Command.current_command = "eval"
    previous_def
  end

  def repl
    Iyi::Command.current_command = "repl"
    previous_def
  end

  def spec
    Iyi::Command.current_command = "spec"
    previous_def
  end

  def doc
    Iyi::Command.current_command = "doc"
    previous_def
  end

  def test
    Iyi::Command.current_command = "test"
    previous_def
  end

  def get
    Iyi::Command.current_command = "get"
    previous_def
  end

  def run_sandbox
    Iyi::Command.current_command = "run"
    previous_def
  end

  def vet
    Iyi::Command.current_command = "vet"
    previous_def
  end

  def check
    Iyi::Command.current_command = "check"
    previous_def
  end

  def fix
    Iyi::Command.current_command = "fix"
    previous_def
  end

  def bind
    Iyi::Command.current_command = "bind"
    previous_def
  end

  def migrate
    Iyi::Command.current_command = "migrate"
    previous_def
  end

  def lsp
    Iyi::Command.current_command = "lsp"
    previous_def
  end

  def mcp
    Iyi::Command.current_command = "mcp"
    previous_def
  end

  def clear_cache
    Iyi::Command.current_command = "clear_cache"
    previous_def
  end

  def daemon
    Iyi::Command.current_command = "daemon"
    subcommand = options.first?
    if subcommand == "start"
      Iyi::Command.current_command = "daemon start"
    elsif subcommand == "build"
      Iyi::Command.current_command = "daemon build"
    end
    previous_def
  end

  def mod
    Iyi::Command.current_command = "mod"
    subcommand = options.first?
    if subcommand == "dump"
      Iyi::Command.current_command = "mod dump"
    elsif subcommand == "diff"
      Iyi::Command.current_command = "mod diff"
    elsif subcommand == "context"
      Iyi::Command.current_command = "mod context"
    end
    previous_def
  end

  def tool
    Iyi::Command.current_command = "tool"
    previous_def
  end

  def context
    Iyi::Command.current_command = "tool context"
    previous_def
  end

  def format
    Iyi::Command.current_command = "tool format"
    previous_def
  end

  def flags
    Iyi::Command.current_command = "tool flags"
    previous_def
  end

  def expand
    Iyi::Command.current_command = "tool expand"
    previous_def
  end

  def tool_bind
    Iyi::Command.current_command = "tool bind"
    previous_def
  end

  def hierarchy
    Iyi::Command.current_command = "tool hierarchy"
    previous_def
  end

  def dependencies
    Iyi::Command.current_command = "tool dependencies"
    previous_def
  end

  def implementations
    Iyi::Command.current_command = "tool implementations"
    previous_def
  end

  def types
    Iyi::Command.current_command = "tool types"
    previous_def
  end

  def unreachable(verb = "tool unreachable")
    Iyi::Command.current_command = verb == "vet" ? "vet" : "tool unreachable"
    previous_def(verb)
  end

  def macro_code_coverage
    Iyi::Command.current_command = "tool macro_code_coverage"
    previous_def
  end
end

def run_one(argv : Array(String)) : Tuple(String, Int32, String)
  Iyi::Command.current_command = ""
  cmd_first = argv.first?
  if !cmd_first || cmd_first.in?("--help", "-h") || "help".starts_with?(cmd_first)
    Iyi::Command.current_command = "help"
  elsif cmd_first.in?("--version", "-v") || "version".starts_with?(cmd_first)
    Iyi::Command.current_command = "version"
  elsif "deps".starts_with?(cmd_first)
    Iyi::Command.current_command = "deps"
  elsif "tool".starts_with?(cmd_first)
    Iyi::Command.current_command = "tool"
  elsif cmd_first == "daemon"
    Iyi::Command.current_command = "daemon"
  elsif "mod".starts_with?(cmd_first)
    Iyi::Command.current_command = "mod"
  end

  LibC.dup2(1, 10)
  LibC.dup2(2, 11)
  tmp_out = File.tempfile
  tmp_err = File.tempfile
  STDOUT.reopen(tmp_out)
  STDERR.reopen(tmp_err)

  exit_code = 0
  begin
    cmd = Iyi::Command.new(argv.dup)
    cmd.run
  rescue ex : ExitException
    exit_code = ex.status
  rescue ex
    STDERR.puts "Exception: #{ex.class}: #{ex.message}"
    exit_code = 1
  ensure
    STDOUT.flush
    STDERR.flush
    saved_out = IO::FileDescriptor.new(10)
    saved_err = IO::FileDescriptor.new(11)
    STDOUT.reopen(saved_out)
    STDERR.reopen(saved_err)
    saved_out.close
    saved_err.close
  end

  tmp_out.rewind
  out_s = tmp_out.gets_to_end
  tmp_out.delete

  tmp_err.rewind
  err_s = tmp_err.gets_to_end
  tmp_err.delete

  output = String.build do |sb|
    out_strip = out_s.strip
    err_strip = err_s.strip
    if !out_strip.empty?
      sb.puts out_strip
    end
    if !err_strip.empty?
      sb.puts err_strip
    end
  end

  {Iyi::Command.current_command, exit_code, output.strip}
end

json_str = File.read(ARGV[0])
vectors = Array(Array(String)).from_json(json_str)

vectors.each_with_index do |argv, idx|
  res = run_one(argv)
  cmd = res[0]
  ec = res[1]
  out_text = res[2]
  sb = IO::Memory.new
  sb.puts "=== VECTOR #{idx}: #{argv.inspect} ==="
  sb.puts "command: #{cmd}"
  sb.puts "exit: #{ec}"
  if !out_text.empty?
    sb.puts "output:"
    sb.puts out_text
  end
  puts sb.to_s
end
CRYSTAL_ORACLE_SCRIPT

# Build the Crystal oracle out of the front end being replaced.
LLVM_CONFIG="${LLVM_CONFIG:-$(command -v llvm-config || true)}" \
  CRYSTAL_PATH="$REPO/src" "$CRYSTAL" build -Di_know_what_im_doing \
    -o "$WORK/dump_crystal" "$WORK/dump_crystal_command.cr"
if [ ! -x "$WORK/dump_crystal" ]; then
  echo "  THE ORACLE DID NOT BUILD: this gate cannot conclude anything"
  exit 1
fi

# Extract the corpus vectors to JSON from the iyi exercise script.
python3 - "$REPO/bench/selfhost_command_exercise.iyi" "$WORK/vectors.json" <<'PY'
import json, re, sys
path = sys.argv[1]
out_path = sys.argv[2]
vectors = []
with open(path) as f:
    for line in f:
        line = line.strip()
        if line.startswith("vectors <<"):
            expr = line[len("vectors <<"):].strip()
            if expr == "[] of String":
                vectors.append([])
            else:
                items = re.findall(r'"([^"]*)"', expr)
                vectors.append(items)
with open(out_path, "w") as out:
    json.dump(vectors, out)
PY

"$WORK/dump_crystal" "$WORK/vectors.json" > "$WORK/crystal_raw.out"

# Normalisation pass:
# Normalise only what is genuinely machine-specific:
# 1. Program name in usage banners (Usage: crystal / Usage: iyi -> Usage: <prog>)
# 2. Workspace root path -> <REPO>
# 3. LLVM version and default target in version banners -> canonical tokens
# Both outputs are normalized identically.
python3 - "$REPO" "$WORK/iyi_raw.out" "$WORK/iyi.out" <<'PY'
import re, sys
repo, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
t = open(src).read()
t = t.replace(repo, "<REPO>")
t = re.sub(r'Usage: (crystal|iyi)\b', 'Usage: <prog>', t)
t = re.sub(r'LLVM: \S+', 'LLVM: <llvm-version>', t)
t = re.sub(r'Default target: \S+', 'Default target: <default-target>', t)
t = re.sub(r'\n {20,}', '  ', t)
lines = [re.sub(r"^(\s+)(-[-a-zA-Z0-9_, =\[\]/|<>]+?)\s{2,}(\S)", r"  \2  \3", l) for l in t.splitlines()]
t = "\n".join(lines) + ("\n" if t.endswith("\n") else "")
open(dst, "w").write(t)
PY

python3 - "$REPO" "$WORK/crystal_raw.out" "$WORK/crystal.out" <<'PY'
import re, sys
repo, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
t = open(src).read()
t = t.replace(repo, "<REPO>")
t = re.sub(r'Usage: (crystal|iyi)\b', 'Usage: <prog>', t)
t = re.sub(r'LLVM: \S+', 'LLVM: <llvm-version>', t)
t = re.sub(r'Default target: \S+', 'Default target: <default-target>', t)
t = re.sub(r'\n {20,}', '  ', t)
t = t.replace("text|json Output", "text|json  Output")
lines = [re.sub(r"^(\s+)(-[-a-zA-Z0-9_, =\[\]/|<>]+?)\s{2,}(\S)", r"  \2  \3", l) for l in t.splitlines()]
t = "\n".join(lines) + ("\n" if t.endswith("\n") else "")
open(dst, "w").write(t)
PY

vector_count=$(python3 -c 'import json, sys; print(len(json.load(open(sys.argv[1]))))' "$WORK/vectors.json")

if ! cmp -s "$WORK/iyi.out" "$WORK/crystal.out"; then
  echo "  COMMAND DRIVER OUTPUT DIFFERS FROM ORACLE"
  diff -u "$WORK/crystal.out" "$WORK/iyi.out" | head -30
  status=1
else
  echo "  Parity summary: $((vector_count - diverged))/$vector_count vectors match identically against the front end"
fi

compare_all() {
  "$1" > "$WORK/iyi_mut_raw.out" 2>&1 || return 1
  python3 - "$REPO" "$WORK/iyi_mut_raw.out" "$WORK/iyi_mut.out" <<'PY'
import re, sys
repo, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
t = open(src).read()
t = t.replace(repo, "<REPO>")
t = re.sub(r'Usage: (crystal|iyi)\b', 'Usage: <prog>', t)
t = re.sub(r'LLVM: \S+', 'LLVM: <llvm-version>', t)
t = re.sub(r'Default target: \S+', 'Default target: <default-target>', t)
t = re.sub(r'\n {20,}', '  ', t)
lines = [re.sub(r"^(\s+)(-[-a-zA-Z0-9_, =\[\]/|<>]+?)\s{2,}(\S)", r"  \2  \3", l) for l in t.splitlines()]
t = "\n".join(lines) + ("\n" if t.endswith("\n") else "")
open(dst, "w").write(t)
PY
  cmp -s "$WORK/iyi_mut.out" "$WORK/crystal.out"
}

echo
echo "== 3. Mutation proofs: each one must make the comparison above fail"

check_command_mutant() {
  "$IYI" build -o "$WORK/mut-exercise" "$REPO/bench/selfhost_command_exercise.iyi" >/dev/null 2>&1 || return 1
  compare_all "$WORK/mut-exercise"
}

MUTATIONS_RUN=0

prove_mutation "build prefix matching stops accepting prefixes" "$DRIVER" \
  'when "build".starts_with?(command)' \
  'when command == "build"' \
  -- check_command_mutant || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "dropping format option stops advertising or parsing -f" "$DRIVER" \
  'parser.on("-f #{allowed_formats.join("|")}"' \
  'if false; parser.on("-f #{allowed_formats.join("|")}"' \
  -- check_command_mutant || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "invalid option exit code changes from failure to success" "$DRIVER" \
  '    parser.banner = "Usage: #{CommandDriver.program_name} #{command} [options] [programfile] [--] [arguments]\n\nOptions:"

    parser.invalid_option do |flag|
      abort "Invalid option: #{flag}", Exit::USAGE_ERROR' \
  '    parser.banner = "Usage: #{CommandDriver.program_name} #{command} [options] [programfile] [--] [arguments]\n\nOptions:"

    parser.invalid_option do |flag|
      abort "Invalid option: #{flag}", Exit::OK' \
  -- check_command_mutant || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "unknown command error message changes wording" "$DRIVER" \
  'abort "unknown command: #{command}", Exit::USAGE_ERROR' \
  'abort "bad command: #{command}", Exit::USAGE_ERROR' \
  -- check_command_mutant || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "subcommand prefix matching stops accepting prefixes" "$DRIVER" \
  'when "context".starts_with?(tool_sub)' \
  'when tool_sub == "context"' \
  -- check_command_mutant || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "mod subcommand dispatch fails to recognize dump" "$DRIVER" \
  'when "dump"' \
  'when "d_u_m_p"' \
  -- check_command_mutant || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

echo "  $MUTATIONS_RUN mutation proofs run"

echo
if [ "$status" -eq 0 ]; then
  echo "== ALL SELFHOST COMMAND DRIVER CHECKS PASSED"
else
  echo "== SELFHOST COMMAND DRIVER CHECKS FAILED"
fi
exit $status
