#!/usr/bin/env python3
"""Probe for the observed chmod program that overflows its stack on Windows.

A probe, not a gate (see .github/workflows/stale-win-probe.yml). It builds the
program bench/stale_chmod_failure.sh builds, with the same overlay, and says:

  * whether the failure repeats across runs of one binary,
  * what a debugger sees at the first stack-overflow, guard-page or
    access-violation exception (the SDK's cdb, where the runner has one),
  * what a larger fiber stack, no fiber at all, and a deeper call do to it,
  * what the fault handler itself can say about the stack it stands on.

Usage: stale_win_probe_chmod.py REPO IYI WORK
"""
import collections
import os
from pathlib import Path
import shutil
import subprocess
import sys

repo = Path(sys.argv[1])
iyi = sys.argv[2]
work = Path(sys.argv[3])
work.mkdir(parents=True, exist_ok=True)

RUNS = int(os.environ.get("CHMOD_PROBE_RUNS", "20"))


def say(text=""):
    print(text, flush=True)


def clip(text, limit=6000):
    text = text.replace("\r", "")
    if len(text) <= limit:
        return text
    return text[: limit // 2] + "\n... omitted ...\n" + text[-limit // 2:]


project = work / "project"
project.mkdir(exist_ok=True)
scratch = work / "scratch"
scratch.mkdir(exist_ok=True)
(project / "absent_marker").write_text("x")  # keeps the directory non-empty
target = project / "absent"

ORIGINAL_TEST = '''import std/file::{File}
path = Program.env("IYI_CHMOD_FAILURE_PATH") || raise "missing path"
group do |g|
  task = g.spawn do
    File.chmod(path, 0o600)
    0
  end
  assert task.value.is_a?(Panicked)
end
'''


def make_overlay(name, prelude_patch=None):
    """The overlay stale_chmod_failure.sh makes, with an optional patch of the prelude."""
    overlay = work / name
    if overlay.exists():
        shutil.rmtree(overlay)
    observer = overlay / "std" / "observe.iyi"
    observer.parent.mkdir(parents=True)
    original = (repo / "src" / "std" / "observe.iyi").read_text(encoding="utf-8")
    scheduler = (repo / "src" / "iyi" / "concurrency.iyi").read_text(encoding="utf-8").splitlines()
    matches = [line for line, text in enumerate(scheduler, 1) if "def self.resolved : Int32" in text]
    if len(matches) != 1:
        raise AssertionError("scheduler resolved fixture no longer applies")
    site = f"iyi/concurrency.iyi:{matches[0]}"
    before = 'pub def __iyi_observe_process(site : String) : Nil\n  not_reusable(36_u8, site)\nend'
    after = ('pub def __iyi_observe_process(site : String) : Nil\n'
             f'  not_reusable(36_u8, site) unless site.includes?("{site}")\nend')
    if original.count(before) != 1:
        raise AssertionError("scheduler process observer fixture no longer applies")
    observer.write_text(original.replace(before, after), encoding="utf-8")
    prelude = overlay / "iyi" / "prelude.iyi"
    prelude.parent.mkdir(parents=True)
    source = (repo / "src" / "iyi" / "prelude.iyi").read_text(encoding="utf-8")
    if source.count('require "../std/observe"') != 1:
        raise AssertionError("observer prelude fixture no longer applies")
    runtime_path = os.path.relpath(repo / "src" / "iyi", prelude.parent).replace("\\", "/")
    source = source.replace('require "./', f'require "{runtime_path}/')
    if prelude_patch:
        source = prelude_patch(source)
    prelude.write_text(source, encoding="utf-8")
    return overlay


def environment(overlay):
    env = os.environ.copy()
    env["IYI_CACHE_DIR"] = str(work / "cache")
    base_path = env.get("IYI_PATH") or os.pathsep.join((str(repo / "src"), str(repo / "samples" / "iyi")))
    env["IYI_PATH"] = os.pathsep.join((str(overlay), base_path))
    env["IYI_LIBRARY_PATH"] = str(repo / "lib")
    env["IYI_CHMOD_FAILURE_PATH"] = str(target)
    return env


def observed(env, trace):
    out = env.copy()
    out.update({"TMPDIR": str(scratch), "TEMP": str(scratch), "TMP": str(scratch), "IYI_OBSERVE": str(trace)})
    return out


def build(label, overlay, source):
    test = project / f"{label}.iyi"
    test.write_text(source, encoding="utf-8")
    exe = work / f"{label}.exe"
    env = environment(overlay)
    result = subprocess.run([iyi, "build", "-Diyi_observe", "-o", str(exe), str(test)], cwd=project, env=env,
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
    if result.returncode:
        say(f"== {label}: build failed, exit {result.returncode}\n{clip(result.stdout)}\n{clip(result.stderr)}")
        return None, env
    return exe, env


def runs(label, exe, env, count, use_observe=True):
    tally = collections.Counter()
    for index in range(count):
        trace = work / f"{label}-{index}.trace"
        trace.unlink(missing_ok=True)
        run_env = observed(env, trace) if use_observe else env
        result = subprocess.run([str(exe)], cwd=project, env=run_env, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=180)
        head = (result.stderr.strip().splitlines() or [""])[0][:110]
        tally[(result.returncode, head)] += 1
    mode = "observed" if use_observe else "unobserved"
    for (code, head), count_ in sorted(tally.items(), key=lambda item: -item[1]):
        say(f"   {label} {mode}: {count_} x exit {code}: {head}")


def find_cdb():
    for root in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
        if root:
            candidate = Path(root) / "Windows Kits" / "10" / "Debuggers" / "x64" / "cdb.exe"
            if candidate.exists():
                return candidate
    return None


CDB_SCRIPT = r"""
sxd eh
sxi ld
sxi ud
sxi out
sxe -c ".echo ==== STACK OVERFLOW; .exr -1; .ecxr; r; .echo ---- teb stackbase stacklimit; dq @$teb+8 L2; .echo ---- teb dealloc; dq @$teb+0x1478 L1; .echo ---- teb guarantee; dq @$teb+0x1748 L1; .echo ---- thread; ~; .echo ---- k; k 40; .echo ---- rsp words; dq @rsp L40; .echo ---- address rsp; !address @rsp; .echo ---- address rsp-0x1000; !address @rsp-0x1000; q" sov
sxe -c ".echo ==== GUARD PAGE; .exr -1; .ecxr; r; .echo ---- teb; dq @$teb+8 L2; dq @$teb+0x1478 L1; dq @$teb+0x1748 L1; .echo ---- k; k 20; .echo ---- address fault; !address @rsp; g" gp
sxe -c ".echo ==== ACCESS VIOLATION; .exr -1; .ecxr; r; .echo ---- teb; dq @$teb+8 L2; dq @$teb+0x1478 L1; dq @$teb+0x1748 L1; .echo ---- k; k 20; .echo ---- address rsp; !address @rsp; q" av
g
"""


def under_debugger(label, exe, env, count=1):
    cdb = find_cdb()
    if cdb is None:
        say(f"== {label}: no cdb on this machine")
        return
    script = work / "cdb-commands.txt"
    script.write_text(CDB_SCRIPT, encoding="utf-8")
    for index in range(count):
        trace = work / f"{label}-cdb-{index}.trace"
        trace.unlink(missing_ok=True)
        run_env = observed(env, trace)
        say(f"== {label} under cdb, run {index}")
        try:
            result = subprocess.run([str(cdb), "-G", "-cf", str(script), "-y", str(work), str(exe)], cwd=project,
                                    env=run_env, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                    timeout=240)
            lines = [line for line in result.stdout.replace("\r", "").splitlines() if not line.startswith("ModLoad")]
            say(f"   cdb exit {result.returncode}")
            say(clip("\n".join(lines), 14000))
            if result.stderr.strip():
                say("   cdb stderr: " + clip(result.stderr, 2000))
        except subprocess.TimeoutExpired:
            say("   cdb timed out")


# ---- the fault handler's own account, written without allocating -----------

HELPERS = '''
  def __iyi_dbg_say(handle : Void*, text : String) : Nil
    written = uninitialized Int32
    LibC.WriteFile(handle, text.to_unsafe.as(Void*), text.bytesize, pointerof(written), nil)
  end

  def __iyi_dbg_hex(handle : Void*, label : String, value : UInt64) : Nil
    __iyi_dbg_say(handle, label)
    buffer = uninitialized StaticArray(UInt8, 19)
    bytes = pointerof(buffer).as(Pointer(UInt8))
    bytes[0] = 48_u8
    bytes[1] = 120_u8
    index = 0
    while index < 16
      digit = value.unsafe_shr(((15 - index) * 4).to_u64) & 15_u64
      bytes[index + 2] = digit < 10 ? (48_u64 + digit).to_u8 : (87_u64 + digit).to_u8
      index = index + 1
    end
    bytes[18] = 10_u8
    written = uninitialized Int32
    LibC.WriteFile(handle, bytes.as(Void*), 19, pointerof(written), nil)
  end

  def __iyi_dbg_overflow(info : Void*, record : UInt64, handle : Void*) : Nil
    __iyi_dbg_say(handle, "DUMP stack overflow\\n")
    __iyi_dbg_hex(handle, "DUMP record flags       ", Pointer(Int32).new(record + 4_u64).value.to_u64)
    __iyi_dbg_hex(handle, "DUMP record address     ", Pointer(UInt64).new(record + 16_u64).value)
    __iyi_dbg_hex(handle, "DUMP record nparams     ", Pointer(UInt64).new(record + 24_u64).value)
    __iyi_dbg_hex(handle, "DUMP record param0      ", Pointer(UInt64).new(record + 32_u64).value)
    __iyi_dbg_hex(handle, "DUMP record param1      ", Pointer(UInt64).new(record + 40_u64).value)
    context = Pointer(UInt64).new(info.address + 8_u64).value
    rsp = Pointer(UInt64).new(context + 0x98_u64).value
    __iyi_dbg_hex(handle, "DUMP context rsp        ", rsp)
    __iyi_dbg_hex(handle, "DUMP context rip        ", Pointer(UInt64).new(context + 0xF8_u64).value)
    __iyi_dbg_hex(handle, "DUMP context rbp        ", Pointer(UInt64).new(context + 0xA0_u64).value)
    base = uninitialized UInt64
    asm("movq %gs:0x08, $0" : "=r"(base) :: : "volatile")
    __iyi_dbg_hex(handle, "DUMP teb stack base     ", base)
    limit = uninitialized UInt64
    asm("movq %gs:0x10, $0" : "=r"(limit) :: : "volatile")
    __iyi_dbg_hex(handle, "DUMP teb stack limit    ", limit)
    dealloc = uninitialized UInt64
    asm("movq %gs:0x1478, $0" : "=r"(dealloc) :: : "volatile")
    __iyi_dbg_hex(handle, "DUMP teb dealloc        ", dealloc)
    guarantee = uninitialized UInt64
    asm("movq %gs:0x1748, $0" : "=r"(guarantee) :: : "volatile")
    __iyi_dbg_hex(handle, "DUMP teb guarantee      ", guarantee & 0xFFFFFFFF_u64)
    thread = uninitialized UInt64
    asm("movq %gs:0x48, $0" : "=r"(thread) :: : "volatile")
    __iyi_dbg_hex(handle, "DUMP teb thread         ", thread)
    top = IyiScheduler.current_stack_top
    __iyi_dbg_hex(handle, "DUMP fiber stack top    ", top)
    __iyi_dbg_hex(handle, "DUMP handler rsp        ", rsp)
    if top != 0_u64 && rsp < top && rsp + 512_u64 < top && rsp > top - 1048576_u64
      index = 0_u64
      while index < 24_u64
        __iyi_dbg_hex(handle, "DUMP rsp word           ", Pointer(UInt64).new(rsp + index * 8_u64).value)
        index = index + 1_u64
      end
    end
  end

'''


def dump_patch(source):
    anchor = "  fun __iyi_win_fault(info : Void*) : Int32\n"
    entry = "    if code == IYI_WIN_STACK_OVERFLOW\n"
    if source.count(anchor) != 1 or source.count(entry) != 1:
        raise AssertionError("fault handler anchors changed")
    source = source.replace(anchor, HELPERS + anchor, 1)
    return source.replace(entry, entry + "      __iyi_dbg_overflow(info, record, handle)\n", 1)


def with_stack(bytes_):
    return ORIGINAL_TEST.replace("group do |g|", f"IyiFiber.stack_bytes = {bytes_}_u64\ngroup do |g|", 1)


MAIN_TEST = '''import std/file::{File}
path = Program.env("IYI_CHMOD_FAILURE_PATH") || raise "missing path"
File.chmod(path, 0o600)
'''


def nested(depth):
    return f'''import std/file::{{File}}
def deep(n : Int32, path : String) : Int32
  if n == 0
    File.chmod(path, 0o600)
    0
  else
    deep(n - 1, path) + 1
  end
end
path = Program.env("IYI_CHMOD_FAILURE_PATH") || raise "missing path"
group do |g|
  task = g.spawn do
    deep({depth}, path)
  end
  assert task.value.is_a?(Panicked)
end
'''


say(f"== probe host: {os.environ.get('OS')}, cdb: {find_cdb()}")
version = subprocess.run(["cmd", "/c", "ver"], capture_output=True, text=True).stdout.strip() if os.name == "nt" else ""
say(f"   {version}")

base_overlay = make_overlay("overlay")
exe, env = build("chmod", base_overlay, ORIGINAL_TEST)
if exe:
    say(f"== chmod: {RUNS} observed runs, then 5 unobserved")
    runs("chmod", exe, env, RUNS)
    runs("chmod", exe, env, 5, use_observe=False)
    under_debugger("chmod", exe, env)

for label, source in (
    ("big8m", with_stack(8388608)),
    ("big1m", with_stack(1048576)),
    ("mainfiber", MAIN_TEST),
    ("deep100", nested(100)),
    ("deep1000", nested(1000)),
    ("deep3000", nested(3000)),
):
    exe, env = build(label, base_overlay, source)
    if exe:
        say(f"== {label}: 10 observed runs, 3 unobserved")
        runs(label, exe, env, 10)
        runs(label, exe, env, 3, use_observe=False)

say("== the fault handler's own account")
dump_overlay = make_overlay("overlay-dump", dump_patch)
exe, env = build("dump", dump_overlay, ORIGINAL_TEST)
if exe:
    for index in range(10):
        trace = work / f"dump-{index}.trace"
        trace.unlink(missing_ok=True)
        result = subprocess.run([str(exe)], cwd=project, env=observed(env, trace), capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=180)
        say(f"   dump run {index}: exit {result.returncode}")
        if "DUMP" in result.stderr or result.returncode:
            say(clip(result.stderr, 4000))
