#!/usr/bin/env python3
"""Measure typed/lowered Mach-O compiler footprint on macOS.

Usage: python3 bench/measure_lower_memory.py NAME REPO STAGE1 ROOT OUTPUT_DIR
Run through the shared slot pool. Samples are process physical footprint,
including compressed memory, from the installed memory-guard libproc reader.
The 56 GB ceiling terminates the compiler before the machine guard's 64 GB.
"""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

name, repo, exe, root, output_dir = sys.argv[1:]
base = Path(output_dir)
base.mkdir(parents=True, exist_ok=True)
guard = Path.home() / ".config/memory-guard/memory_guard.py"
spec = importlib.util.spec_from_file_location("memory_guard", guard)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
env = os.environ.copy()
env.update(IYI_PATH=repo + "/src", MACOSX_DEPLOYMENT_TARGET="28.0", LIBRARY_PATH="/opt/homebrew/opt/bdw-gc/lib")
cmd = ["/usr/bin/time", "-l", exe, root, "-o", str(base / (name + ".ir")),
       "--pipeline", "typed", "--prelude", "--probe-phase", "--emit", "ir"]
start = time.monotonic()
peak = maxrss = 0
typed = lower = pid = None
reason = "exited"
with (base / (name + ".log")).open("w") as stdout, (base / (name + ".time")).open("w") as stderr, (base / (name + ".samples")).open("w") as samples:
    process = subprocess.Popen(cmd, stdout=stdout, stderr=stderr, cwd=repo, env=env)
    while process.poll() is None:
        children = subprocess.run(["pgrep", "-P", str(process.pid)], capture_output=True, text=True).stdout.split()
        if children:
            pid = int(children[0])
            usage = module.usage(pid)
            if usage:
                peak = max(peak, usage.footprint)
                maxrss = max(maxrss, usage.resident)
                text = (base / (name + ".log")).read_text(errors="replace")
                if "[phase] bodies: pass" in text and typed is None:
                    typed = usage.footprint
                if "[phase] lower: pass" in text and lower is None:
                    lower = usage.footprint
                phase = "lowered" if lower is not None else ("lowering" if typed is not None else "typing")
                print(f"{time.monotonic() - start:.1f}\t{usage.footprint}\t{usage.resident}\t{phase}", file=samples, flush=True)
                if usage.footprint >= 56_000_000_000:
                    reason = "56GB stop"
                    os.kill(pid, signal.SIGTERM)
                    break
        time.sleep(0.5)
    try:
        status = process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        status = process.wait()
print(json.dumps(dict(root=root, pid=pid, reason=reason, peak_footprint=peak, max_sample_rss=maxrss,
                      typed_footprint=typed, lower_footprint=lower,
                      wall_s=round(time.monotonic() - start, 2), status=status)))
