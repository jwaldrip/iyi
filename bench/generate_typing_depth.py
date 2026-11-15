#!/usr/bin/env python3
"""Generate nested typing workloads in a scratch directory, never the repo.

Usage: python3 bench/generate_typing_depth.py /tmp/typing-depth
Each root invokes a chain of eight or fewer defs. All loops terminate at
runtime. The generated source is a benchmark, not a compiler fixture.
"""
import sys
from pathlib import Path

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
for kind in ("widen", "block", "plain", "recursive"):
    for depth in range(1, 9):
        lines = []
        for level in range(depth, 0, -1):
            name = f"f{level}"
            lines.append(f"def {name}(n : Int32)")
            if level == depth:
                lines.append("  n &+ 1")
            elif kind == "widen":
                lines += ["  x = nil", "  i = n", "  while i > 0", "    x = 1",
                          f"    f{level + 1}(i)", "    i = i &- 1", "  end", "  x"]
            elif kind == "plain":
                lines += ["  i = n", "  while i > 0", f"    f{level + 1}(i)",
                          "    i = i &- 1", "  end", "  i"]
            elif kind == "block":
                lines += [f"  [1, 2].each {{ |a| f{level + 1}(a) }}", "  n"]
            else:
                lines += ["  if n > 0", f"    {name}(n &- 1)",
                          f"    f{level + 1}(n &- 1)", "  else", "    n", "  end"]
            lines.append("end")
            lines.append("")
        lines.append("f1(1)")
        (out / f"{kind}-{depth}.iyi").write_text("\n".join(lines) + "\n")
