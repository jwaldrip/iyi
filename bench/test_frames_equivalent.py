#!/usr/bin/env python3
"""Focused behavioral tests for bench/frames_equivalent.py.

Verifies:
1. Exact semantic equivalence on real captured Linux named frames from
   run 42573044166 (normal.stderr vs artifact.stderr).
2. Discriminating mutations for index, function, location, position, count, text.
3. Explicit named-frame proof that rejects zero-frame false positives while
   allowing zero-frame corpus outputs under default comparison.
4. Approved std source (src/std/X.iyi) vs modular artifact (mods/std/X.iyimod)
   canonicalization, without masking actual line, column, function, or module changes.
5. Unknown addresses and unrecognized lines preserved exact without normalization.
6. Preservation of existing Darwin comparator behavior and rules.
7. Across-optimization chunking across frame and text boundaries.
"""

import base64
import copy
import hashlib
import io
import json
import contextlib
import os
import struct
import sys
import tempfile
from unittest.mock import patch

# Ensure bench/ is on sys.path
BENCH_DIR = os.path.dirname(os.path.abspath(__file__))
if BENCH_DIR not in sys.path:
    sys.path.insert(0, BENCH_DIR)

import frames_equivalent as frames
from frames_equivalent import (
    FRAME_RE,
    DARWIN_FRAME_RE,
    LINUX_FRAME_RE,
    canonical_file,
    canonical_function,
    compare_across_opt,
    compare_same_opt,
    generate_mutant,
    is_frame,
    parse_frame,
)

# Real captured outputs from run 42573044166
CAPTURED_NORMAL = b"""iyi: panic: frame qualification
  at /__w/_temp/frame-probe/probe.iyi:5
0   frame_inner at /__w/_temp/frame-probe/probe.iyi:5:3
1   frame_inner at /__w/_temp/frame-probe/probe.iyi:6:3
2   frame_inner at /__w/_temp/frame-probe/probe.iyi:6:3
3   frame_inner at /__w/_temp/frame-probe/probe.iyi:6:3
4   __iyi_main at /__w/_temp/frame-probe/probe.iyi:8:1
5   __iyi_program at /__w/iyi/iyi/src/iyi/prelude.iyi:10096:3
6   __iyi_enter at /__w/iyi/iyi/src/iyi/prelude.iyi:10086:3
7   main at /__w/iyi/iyi/src/iyi/prelude.iyi:11042:3
"""

CAPTURED_ARTIFACT = b"""iyi: panic: frame qualification
  at /__w/_temp/frame-probe/probe.iyi:5
0   frame_inner at /__w/_temp/frame-probe/probe.iyi:5:3
1   frame_inner at /__w/_temp/frame-probe/probe.iyi:6:3
2   frame_inner at /__w/_temp/frame-probe/probe.iyi:6:3
3   frame_inner at /__w/_temp/frame-probe/probe.iyi:6:3
4   __iyi_main at /__w/_temp/frame-probe/probe.iyi:8:1
5   __iyi_program at /__w/iyi/iyi/src/iyi/prelude.iyi:10096:3
6   __iyi_enter at /__w/iyi/iyi/src/iyi/prelude.iyi:10086:3
7   main at /__w/iyi/iyi/src/iyi/prelude.iyi:11042:3
"""

# Real Darwin frames
DARWIN_SAMPLE_1 = b"""0   a.out                               0x0000000100003f50 ~proc3@samples/iyi/hello.iyi:1 + 16
1   a.out                               0x0000000100004120 main + 32
"""

DARWIN_SAMPLE_2 = b"""0   a.out                               0x0000000100099999 ~proc3@samples/iyi/hello.iyi:1 + 48
1   a.out                               0x0000000100088888 main + 64
"""


def capture_violation(fn, *args, **kwargs):
    """Run fn and capture reported violation rule and output."""
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        ret = fn(*args, **kwargs)
        out = sys.stdout.getvalue()
        rule = None
        for line in out.splitlines():
            if "rule " in line:
                rule = line.split("rule ")[1].strip()
                break
        return ret, rule, out
    finally:
        sys.stdout = old_stdout


def test_captured_linux_equivalence():
    lines_n = CAPTURED_NORMAL.splitlines(keepends=True)
    lines_a = CAPTURED_ARTIFACT.splitlines(keepends=True)

    # Both same_opt and across_opt must evaluate as equivalent (0)
    ret, rule, _ = capture_violation(compare_same_opt, lines_n, lines_a)
    assert ret == 0, f"normal vs artifact same_opt returned {ret}"

    ret, rule, _ = capture_violation(compare_across_opt, lines_n, lines_a)
    assert ret == 0, f"normal vs artifact across_opt returned {ret}"

    # Also equivalent with require_frames=True
    ret, rule, _ = capture_violation(compare_same_opt, lines_n, lines_a, require_frames=True)
    assert ret == 0, f"normal vs artifact with require_frames=True returned {ret}"

    ret, rule, _ = capture_violation(compare_across_opt, lines_n, lines_a, require_frames=True)
    assert ret == 0, f"normal vs artifact across_opt with require_frames=True returned {ret}"


def test_discriminating_mutations_linux():
    lines = CAPTURED_NORMAL.splitlines(keepends=True)

    # 1. index mutant
    mut = generate_mutant("index", lines)
    ret, rule, _ = capture_violation(compare_same_opt, lines, mut)
    assert ret == 1, "index mutant did not fail"
    assert rule == "index", f"index mutant reported rule {rule!r}, expected 'index'"

    # 2. function mutant
    mut = generate_mutant("function", lines)
    ret, rule, _ = capture_violation(compare_same_opt, lines, mut)
    assert ret == 1, "function mutant did not fail"
    assert rule == "function", f"function mutant reported rule {rule!r}, expected 'function'"

    # 3. location mutant (line change)
    mut = generate_mutant("location", lines)
    ret, rule, _ = capture_violation(compare_same_opt, lines, mut)
    assert ret == 1, "location mutant did not fail"
    assert rule == "location", f"location mutant reported rule {rule!r}, expected 'location'"

    # 4. location mutant via column change
    mut = generate_mutant("column", lines)
    ret, rule, _ = capture_violation(compare_same_opt, lines, mut)
    assert ret == 1, "column mutant did not fail"
    assert rule == "location", f"column mutant reported rule {rule!r}, expected 'location'"

    # 5. location mutant via file change
    mut = generate_mutant("file", lines)
    ret, rule, _ = capture_violation(compare_same_opt, lines, mut)
    assert ret == 1, "file mutant did not fail"
    assert rule == "location", f"file mutant reported rule {rule!r}, expected 'location'"

    # 6. position mutant (frame line swapped with nonframe line)
    mut = generate_mutant("position", lines)
    ret, rule, _ = capture_violation(compare_same_opt, lines, mut)
    assert ret == 1, "position mutant did not fail"
    assert rule == "position", f"position mutant reported rule {rule!r}, expected 'position'"

    # 7. count / drop mutant (frame line dropped)
    mut = generate_mutant("count", lines)
    ret, rule, _ = capture_violation(compare_same_opt, lines, mut)
    assert ret == 1, "count mutant did not fail"
    assert rule == "line_count", f"count mutant reported rule {rule!r}, expected 'line_count'"

    # 8. text mutant (nonframe line mutated)
    mut = generate_mutant("text", lines)
    ret, rule, _ = capture_violation(compare_same_opt, lines, mut)
    assert ret == 1, "text mutant did not fail"
    assert rule == "text", f"text mutant reported rule {rule!r}, expected 'text'"


def test_explicit_named_frame_proof_rejects_zero_frames():
    # Normal corpus output without any panic / frames
    corpus_no_frames = [
        b"compilation successful\n",
        b"running test suite\n",
        b"42 tests passed\n",
    ]

    # Without require_frames: passes (no requirement every corpus output has frames)
    ret, rule, _ = capture_violation(compare_same_opt, corpus_no_frames, corpus_no_frames, require_frames=False)
    assert ret == 0, f"corpus without frames failed under default require_frames=False: {rule}"

    # With require_frames: must be REJECTED as zero-frame false positive
    ret, rule, _ = capture_violation(compare_same_opt, corpus_no_frames, corpus_no_frames, require_frames=True)
    assert ret == 1, "zero-frame output unexpectedly passed under require_frames=True"
    assert rule == "zero_frames", f"expected rule 'zero_frames', got {rule!r}"

    # In across_opt as well
    ret, rule, _ = capture_violation(compare_across_opt, corpus_no_frames, corpus_no_frames, require_frames=True)
    assert ret == 1, "zero-frame output unexpectedly passed in across_opt under require_frames=True"
    assert rule == "zero_frames", f"expected rule 'zero_frames', got {rule!r}"

    # Empty files under require_frames=True must also be rejected
    ret, rule, _ = capture_violation(compare_same_opt, [], [], require_frames=True)
    assert ret == 1, "empty output unexpectedly passed under require_frames=True"
    assert rule == "zero_frames", f"expected rule 'zero_frames', got {rule!r}"

    # Address-only frame [0x...] without a named function
    addr_only_frames = [
        b"iyi: panic: test\n",
        b"0   [0x7f0001] at /path/test.iyi:1:2\n",
    ]
    ret, rule, _ = capture_violation(compare_same_opt, addr_only_frames, addr_only_frames, require_frames=False)
    assert ret == 0, f"identical address-only frames failed under require_frames=False: {rule}"

    # Under require_frames=True, address-only frames MUST be rejected as zero named frames
    ret, rule, _ = capture_violation(compare_same_opt, addr_only_frames, addr_only_frames, require_frames=True)
    assert ret == 1, "address-only frame unexpectedly passed under require_frames=True"
    assert rule == "zero_frames", f"expected rule 'zero_frames', got {rule!r}"

    # Across-opt with address-only frames under require_frames=True MUST also be rejected
    ret, rule, _ = capture_violation(compare_across_opt, addr_only_frames, addr_only_frames, require_frames=True)
    assert ret == 1, "address-only frame unexpectedly passed across-opt under require_frames=True"
    assert rule == "zero_frames", f"expected rule 'zero_frames', got {rule!r}"

def test_approved_std_canonicalization():
    # Source vs modular artifact in std/
    source_line = b"0   proc_work at /home/runner/work/iyi/iyi/src/std/debug.iyi:100:15\n"
    artifact_line = b"0   proc_work at /tmp/scratch/mods/std/debug.iyimod:100:15\n"
    ret, rule, _ = capture_violation(compare_same_opt, [source_line], [artifact_line])
    assert ret == 0, f"std source vs artifact unexpectedly differed: {rule}"

    # Submodule in std/
    source_sub = b"0   fn at /home/runner/src/std/crypto/sha256.iyi:42:1\n"
    artifact_sub = b"0   fn at /home/runner/mods/std/crypto/sha256.iyimod:42:1\n"
    ret, rule, _ = capture_violation(compare_same_opt, [source_sub], [artifact_sub])
    assert ret == 0, f"std submodule source vs artifact unexpectedly differed: {rule}"

    # MUST NOT mask line difference
    line_diff = b"0   proc_work at /tmp/scratch/mods/std/debug.iyimod:101:15\n"
    ret, rule, _ = capture_violation(compare_same_opt, [source_line], [line_diff])
    assert ret == 1, "actual line change was masked"
    assert rule == "location", f"expected 'location', got {rule!r}"

    # MUST NOT mask column difference
    col_diff = b"0   proc_work at /tmp/scratch/mods/std/debug.iyimod:100:16\n"
    ret, rule, _ = capture_violation(compare_same_opt, [source_line], [col_diff])
    assert ret == 1, "actual column change was masked"
    assert rule == "location", f"expected 'location', got {rule!r}"

    # MUST NOT mask function change
    fn_diff = b"0   proc_other at /tmp/scratch/mods/std/debug.iyimod:100:15\n"
    ret, rule, _ = capture_violation(compare_same_opt, [source_line], [fn_diff])
    assert ret == 1, "actual function change was masked"
    assert rule == "function", f"expected 'function', got {rule!r}"

    # MUST NOT mask module change (std/debug vs std/digest)
    mod_diff = b"0   proc_work at /tmp/scratch/mods/std/digest.iyimod:100:15\n"
    ret, rule, _ = capture_violation(compare_same_opt, [source_line], [mod_diff])
    assert ret == 1, "module change was masked"
    assert rule == "location", f"expected 'location', got {rule!r}"

    # Non-std paths MUST NOT be canonicalized
    non_std_src = b"0   fn at /home/runner/work/src/other/test.iyi:10:5\n"
    non_std_art = b"0   fn at /home/runner/work/mods/other/test.iyimod:10:5\n"
    ret, rule, _ = capture_violation(compare_same_opt, [non_std_src], [non_std_art])
    assert ret == 1, "non-std path difference was unexpectedly canonicalized"
    assert rule == "location", f"expected 'location', got {rule!r}"


def test_unknown_addresses_not_normalized():
    # Unknown addresses in nonframe lines must compare byte-for-byte exact
    line1 = b"0   [0x00007fff12345678]\n"
    line2 = b"0   [0x00007fff87654321]\n"
    ret, rule, _ = capture_violation(compare_same_opt, [line1], [line2])
    assert ret == 1, "differing unknown address lines were normalized away"
    assert rule == "text", f"expected 'text', got {rule!r}"

    # Unknown address in function name must compare byte-for-byte exact
    fn_addr1 = b"0   [0x7f0001] at /path/test.iyi:1:2\n"
    fn_addr2 = b"0   [0x7f0002] at /path/test.iyi:1:2\n"
    ret, rule, _ = capture_violation(compare_same_opt, [fn_addr1], [fn_addr2])
    assert ret == 1, "unknown address in function name was normalized away"
    assert rule == "function", f"expected 'function', got {rule!r}"


def test_darwin_backward_compatibility():
    d1 = DARWIN_SAMPLE_1.splitlines(keepends=True)
    d2 = DARWIN_SAMPLE_2.splitlines(keepends=True)

    # Equivalent despite differing 16-hex addresses and instruction offsets
    ret, rule, _ = capture_violation(compare_same_opt, d1, d2)
    assert ret == 0, f"Darwin equivalence failed: {rule}"

    # Legacy paths may correspond, but distinct ordinals do not.
    sym_a = b"0   a.out                               0x0000000100003f50 ~proc123@src/std/big.iyi:10 + 16\n"
    sym_b = b"0   a.out                               0x0000000100009999 ~proc123@mods/std/big.iyimod:10 + 32\n"
    ret, rule, _ = capture_violation(compare_same_opt, [sym_a], [sym_b])
    assert ret == 0, f"Darwin proc/std canonicalization failed: {rule}"
    ret, rule, _ = capture_violation(compare_same_opt, [sym_a], [sym_b.replace(b'proc123', b'proc456')])
    assert ret == 1 and rule == "function", "legacy proc ordinal was discarded"

    sym_c = b"0   a.out                               0x0000000100003f50 run_loop~iyi + 16\n"
    sym_d = b"0   a.out                               0x0000000100009999 run_loop + 32\n"
    ret, rule, _ = capture_violation(compare_same_opt, [sym_c], [sym_d])
    assert ret == 1 and rule == "function", "function suffix was discarded"
    # Darwin mutations fail with their expected rules
    mut_idx = generate_mutant("index", d1)
    ret, rule, _ = capture_violation(compare_same_opt, d1, mut_idx)
    assert ret == 1 and rule == "index", f"Darwin index mutant: {rule}"

    mut_img = generate_mutant("image", d1)
    ret, rule, _ = capture_violation(compare_same_opt, d1, mut_img)
    assert ret == 1 and rule == "image", f"Darwin image mutant: {rule}"

    mut_fn = generate_mutant("function", d1)
    ret, rule, _ = capture_violation(compare_same_opt, d1, mut_fn)
    assert ret == 1 and rule == "function", f"Darwin function mutant: {rule}"

    # Darwin across-opt named vs address-only 0x0 (real prelude.iyi:10397 shape)
    darwin_named = [b"0   a.out                               0x0000000100003f50 main + 16\n"]
    darwin_addr_only = [b"0   ???                                 0x0000000100009999 0x0 + 32\n"]

    # Default relaxed across-opt preserves Darwin equivalence across inlined/unnamed frames
    ret, rule, _ = capture_violation(compare_across_opt, darwin_named, darwin_addr_only, require_frames=False)
    assert ret == 0, f"Darwin across-opt default relaxed mode failed on named vs 0x0: {rule}"
    ret, rule, _ = capture_violation(compare_across_opt, darwin_addr_only, darwin_named, require_frames=False)
    assert ret == 0, f"Darwin across-opt default relaxed mode failed on reversed 0x0 vs named: {rule}"

    # Under require_frames=True, both same-order and reversed MUST reject with zero_frames
    ret, rule, _ = capture_violation(compare_across_opt, darwin_named, darwin_addr_only, require_frames=True)
    assert ret == 1, "Darwin across-opt named vs 0x0 unexpectedly passed with require_frames=True"
    assert rule == "zero_frames", f"expected 'zero_frames', got {rule!r}"

    ret, rule, _ = capture_violation(compare_across_opt, darwin_addr_only, darwin_named, require_frames=True)
    assert ret == 1, "Darwin across-opt reversed 0x0 vs named unexpectedly passed with require_frames=True"
    assert rule == "zero_frames", f"expected 'zero_frames', got {rule!r}"

    ret, rule, _ = capture_violation(compare_across_opt, darwin_addr_only, darwin_addr_only, require_frames=True)
    assert ret == 1, "Darwin across-opt both 0x0 unexpectedly passed with require_frames=True"
    assert rule == "zero_frames", f"expected 'zero_frames', got {rule!r}"

def test_cross_format_mismatch():
    darwin_line = b"0   a.out                               0x0000000100003f50 main + 16\n"
    linux_line = b"0   main at /path/test.iyi:1:2\n"
    ret, rule, _ = capture_violation(compare_same_opt, [darwin_line], [linux_line])
    assert ret == 1, "Darwin frame vs Linux frame unexpectedly matched"
    assert rule == "position", f"expected 'position', got {rule!r}"


def test_strict_linux_across_opt():
    lines_n = CAPTURED_NORMAL.splitlines(keepends=True)

    # 1. Synthetic replacement with wrong frame count / contents
    synthetic_wrong = [
        b"iyi: panic: frame qualification\n",
        b"  at /__w/_temp/frame-probe/probe.iyi:5\n",
        b"99   wrong at /wrong.iyi:99:99\n",
    ]
    ret, rule, _ = capture_violation(compare_across_opt, lines_n, synthetic_wrong)
    assert ret == 1, "across_opt accepted wrong Linux frame chunk length/contents"
    assert rule == "line_count", f"expected 'line_count', got {rule!r}"

    # 2. Mutating index in real captured Linux frames must fail across_opt
    mut_idx = generate_mutant("index", lines_n)
    ret, rule, _ = capture_violation(compare_across_opt, lines_n, mut_idx)
    assert ret == 1, "across_opt accepted index mutation"
    assert rule == "index", f"expected 'index', got {rule!r}"

    # 3. Mutating function in real captured Linux frames must fail across_opt
    mut_fn = generate_mutant("function", lines_n)
    ret, rule, _ = capture_violation(compare_across_opt, lines_n, mut_fn)
    assert ret == 1, "across_opt accepted function mutation"
    assert rule == "function", f"expected 'function', got {rule!r}"

    # 4. Mutating location in real captured Linux frames must fail across_opt
    mut_loc = generate_mutant("location", lines_n)
    ret, rule, _ = capture_violation(compare_across_opt, lines_n, mut_loc)
    assert ret == 1, "across_opt accepted location mutation"
    assert rule == "location", f"expected 'location', got {rule!r}"


def test_module_mutant_restricts_to_recognized_frame():
    # Preceding nonframe diagnostic holding std/ path
    lines_with_diag = [
        b"compiling src/std/debug.iyi\n",
        b"0   proc_work at /home/runner/work/iyi/iyi/src/std/debug.iyi:100:15\n",
    ]
    mut = generate_mutant("module", lines_with_diag)
    # The nonframe diagnostic must remain completely untouched
    assert mut[0] == lines_with_diag[0], f"nonframe line was incorrectly mutated: {mut[0]!r}"
    # The frame line must be mutated
    assert mut[1] != lines_with_diag[1], "frame line was not mutated"
    assert b"std/mutant_mod" in mut[1], f"expected std/mutant_mod in frame line: {mut[1]!r}"
    # Comparison must fail via location rule on the frame, NOT text on nonframe line
    ret, rule, _ = capture_violation(compare_same_opt, lines_with_diag, mut)
    assert ret == 1, "module mutant comparison did not fail"
    assert rule == "location", f"expected 'location', got {rule!r}"

    # Darwin module mutant also leaves preceding nonframe text untouched
    darwin_with_diag = [
        b"loading src/std/big.iyi\n",
        b"0   a.out                               0x0000000100003f50 ~proc@src/std/big.iyi:10 + 16\n",
    ]
    darwin_mut = generate_mutant("module", darwin_with_diag)
    assert darwin_mut[0] == darwin_with_diag[0], f"Darwin nonframe line was mutated: {darwin_mut[0]!r}"
    assert darwin_mut[1] != darwin_with_diag[1], "Darwin frame line was not mutated"
    ret, rule, _ = capture_violation(compare_same_opt, darwin_with_diag, darwin_mut)
    assert ret == 1, "Darwin module mutant did not fail"
    assert rule == "function", f"expected 'function', got {rule!r}"

def test_captured_darwin_proc_and_collisions():
    source = b'4   std_http_exercise                   0x0000000105d32a54 ~procProc(Int32)^/Users/runner/work/iyi/iyi/.build/../src/std/http.iyi:1832 + 80\n'
    artifact = b'4   std_http_exercise                   0x00000001047074a4 ~procProc(Int32)^mods/std/http.iyimod:1832 + 80\n'
    ret, rule, _ = capture_violation(compare_same_opt, [source], [artifact], require_frames=True)
    assert ret == 0, f"captured HTTP frames differed: {rule}"

    colon_source = source.replace(b'/Users/runner/work/iyi/iyi/.build/..', b'/tmp/build:debug')
    ret, rule, _ = capture_violation(compare_same_opt, [colon_source], [artifact])
    assert ret == 0, f"colon in source path prevented equivalence: {rule}"
    for old, new in [(b'http.iyimod', b'debug.iyimod'),
                     (b':1832', b':1833'),
                     (b'Proc(Int32)', b'Proc(Int64)')]:
        ret, _, _ = capture_violation(compare_same_opt, [colon_source], [artifact.replace(old, new, 1)])
        assert ret == 1, f"colon path masked {old!r} mismatch"
    colon_mutant = generate_mutant("location", [colon_source])
    assert b'/tmp/build:debug/' in colon_mutant[0] and b':14177 +' in colon_mutant[0]
    ret, _, _ = capture_violation(compare_same_opt, [colon_source], colon_mutant)
    assert ret == 1, "colon path location mutant survived"

    colon_escaped = colon_source.replace(b'http.iyi', b'http%5E.iyi')
    artifact_escaped = artifact.replace(b'http.iyimod', b'http%5E.iyimod')
    ret, _, _ = capture_violation(compare_same_opt, [colon_escaped], [artifact_escaped])
    assert ret == 0, "escaped caret with colon path did not survive aliasing"
    ret, _, _ = capture_violation(compare_same_opt, [colon_escaped], [artifact_escaped.replace(b'%5E', b'^')])
    assert ret == 1, "escaped caret collided with a literal caret"

    for old, new in [
        (b'http.iyimod', b'debug.iyimod'),
        (b':1832', b':1833'),
        (b'Proc(Int32)', b'Proc(Int64)'),
        (b'~procProc', b'~proc2Proc'),
        (b'~procProc', b'~funProc'),
        (b'std_http_exercise', b'other_image'),
        (b'4   ', b'5   '),
        (b'mods/std/http.iyimod', b'std/http'),
        (b'mods/std/http.iyimod', b'mods/std/../std/http.iyimod'),
    ]:
        changed = artifact.replace(old, new, 1)
        assert changed != artifact
        ret, _, _ = capture_violation(compare_same_opt, [source], [changed])
        assert ret == 1, f"masked difference {old!r} -> {new!r}"

    parallel_source = b'2   std_parallel_exercise               0x00000001030158e0 ~proc3Proc(Array(Tuple(Int64, Array(Int32))))^/Users/runner/work/iyi/iyi/.build/../src/std/parallel.iyi:215 + 396\n'
    parallel_artifact = b'2   std_parallel_exercise               0x0000000102f63c64 ~proc2Proc(Array(Tuple(Int64, Array(Int32))))^mods/std/parallel.iyimod:215 + 444\n'
    ret, rule, _ = capture_violation(compare_same_opt, [parallel_source], [parallel_artifact])
    assert ret == 1 and rule == "function", "unverified parallel ordinal alias accepted"
    ret, _, _ = capture_violation(compare_same_opt, [parallel_source], [parallel_artifact.replace(b'~proc2', b'~proc3')])
    assert ret == 0, "nested type path alias failed"

    escaped_source = source.replace(b'Proc(Int32)', b'Proc(NamedTuple("a%5Eb%40c%25": Array(Int32)))').replace(b'http.iyi', b'http%5E%40%25.iyi')
    escaped_artifact = artifact.replace(b'Proc(Int32)', b'Proc(NamedTuple("a%5Eb%40c%25": Array(Int32)))').replace(b'http.iyimod', b'http%5E%40%25.iyimod')
    ret, _, _ = capture_violation(compare_same_opt, [escaped_source], [escaped_artifact])
    assert ret == 0, "escaped type or module did not survive aliasing"
    for old, new in [(b'%5E', b'^'), (b'%40', b'@'), (b'%25', b'%2525')]:
        ret, _, _ = capture_violation(compare_same_opt, [escaped_source], [escaped_artifact.replace(old, new, 1)])
        assert ret == 1, f"escaped bytes {old!r} were collapsed"

    for bad in [
        artifact.replace(b'Proc(Int32)', b'Proc(Int32'),
        artifact.replace(b'Proc(Int32)^', b'Proc(Int32)junk^'),
        artifact.replace(b'Proc(Int32)^', b'Proc(Int32)^extra^'),
        artifact.replace(b':1832', b':1832extra'),
    ]:
        ret, _, _ = capture_violation(compare_same_opt, [source], [bad])
        assert ret == 1, "malformed proc grammar accepted"

    other = b'5   std_http_exercise                   0x0000000105d32a54 another + 80\n'
    original = [b'panic\n', source, other]
    for changed in ([b'changed\n', artifact, other], [b'panic\n', other, artifact],
                    [b'panic\n', artifact], [b'panic\n', artifact, other, other]):
        ret, _, _ = capture_violation(compare_same_opt, original, changed)
        assert ret == 1, "text, order, or count difference was masked"
    for kind in ("location", "line", "module", "function", "index", "image"):
        mutant = generate_mutant(kind, original)
        assert mutant[0] == original[0], f"{kind} mutant touched nonframe text"
        ret, _, _ = capture_violation(compare_same_opt, original, mutant)
        assert ret == 1, f"{kind} mutant survived"


def macho_fixture(file_type, entries, flags=0x80000400):
    """Construct bytes and literal expected evidence without the reader."""
    strings = bytearray(b"\0")
    records, symbols = bytearray(), []
    for index, (name, typ, section, desc, value) in enumerate(entries):
        string_index = len(strings) if name else 0
        if name: strings.extend(name + b"\0")
        records.extend(struct.pack("<IBBHQ", string_index, typ, section, desc, value))
        symbols.append({"index": index, "string_index": string_index, "name_base64": base64.b64encode(name).decode(),
                        "type": typ, "section": section, "desc": desc, "value": f"{value:016x}"})
    segment = struct.pack("<II16sQQQQiiII", 0x19, 152, b"", 0x10, 16, 208, 16, 7, 5, 1, 0)
    section = struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT", 0x10, 16, 208, 0, 0, 0, flags, 0, 0, 0)
    symoff = 224
    stroff = symoff + len(records)
    header = struct.pack("<8I", 0xfeedfacf, 0x0100000c, 0, file_type, 2, 176, 0, 0)
    binary = header + segment + section + struct.pack("<6I", 2, 24, symoff, len(entries), stroff, len(strings)) + bytes(16) + records + strings
    evidence = {"format": "macho64-le-symtab-v1", "cpu_type": 0x0100000c, "cpu_subtype": 0,
                "file_type": file_type, "sections": [{"index": 1,
                "segment_name_base64": base64.b64encode(b"__TEXT".ljust(16, b"\0")).decode(),
                "section_name_base64": base64.b64encode(b"__text".ljust(16, b"\0")).decode(),
                "address": "0000000000000010", "size": "0000000000000010", "file_offset": 208, "flags": flags}],
                "symbols": symbols}
    return bytes(binary), evidence


def test_macho_reader_controls():
    names = [b"_a\n0000000000000010 (__TEXT,__text) external _fake\r", b" space [cold func] \xff"]
    entries = [(names[0], 0x0e, 1, 0x400, 0x10), (names[1], 0x1f, 1, 0x80, 0x11),
               (b"_common", 0x01, 0, 0, 4), (b"_absolute", 0x03, 0, 0, 3),
               (b"_debug", 0xe0, 255, 0, 0xffff)]
    binary, expected = macho_fixture(1, entries)
    assert frames.macho_summary(binary, 1) == expected
    assert [name for name, _ in frames.direct_code_symbols(expected)] == names
    for flags in (0, 0x02000400):
        data, summary = macho_fixture(1, entries[:1], flags)
        assert frames.macho_summary(data, 1) == summary
        assert not frames.direct_code_symbols(summary)
    data, summary = macho_fixture(1, entries[:1], 0x80000408)
    assert not frames.direct_code_symbols(frames.macho_summary(data, 1))
    data, summary = macho_fixture(1, entries[:1], 0x80000409)
    try: frames.direct_code_symbols(frames.macho_summary(data, 1))
    except ValueError: pass
    else: raise AssertionError("unsupported instruction section accepted")
    for typ, section, value in ((0, 0, 5), (2, 0, 0x10), (0xe0, 1, 0x10), (0x0e, 1, 0x20)):
        data, summary = macho_fixture(1, [(b"_x", typ, section, 0, value)])
        assert not frames.direct_code_symbols(frames.macho_summary(data, 1))
    header_symbol = (b"__mh_execute_header", 0x0f, 1, 0x10, 0)
    data, summary = macho_fixture(2, [header_symbol, (b"_code", 0x0f, 1, 0, 0x10)])
    assert frames.macho_summary(data, 2) == summary
    assert [name for name, _ in frames.direct_code_symbols(summary)] == [b"_code"]
    suffix = bytearray(binary)
    struct.pack_into("<I", suffix, 240, 2)
    suffix_summary = frames.macho_summary(bytes(suffix), 1)
    assert base64.b64decode(suffix_summary["symbols"][1]["name_base64"]) == names[0][1:]
    empty = bytearray(binary)
    struct.pack_into("<I", empty, 224, 0)
    assert frames.macho_summary(bytes(empty), 1)["symbols"][0]["name_base64"] == ""
    def reject(data):
        try: frames.macho_summary(bytes(data), 1)
        except ValueError: return
        raise AssertionError("malformed Mach-O accepted")
    reject(binary[:31])
    for magic in (b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"!<ar"):
        reject(magic + binary[4:])
    for offset, value in ((4, 7), (12, 2), (16, 100), (20, 8), (36, 7), (96, 100),
                          (184, 3), (188, 16), (192, 0), (196, 0xffffffff),
                          (200, 0), (204, 0xffffffff), (224, 0xffffffff)):
        malformed = bytearray(binary)
        struct.pack_into("<I", malformed, offset, value)
        reject(malformed)
    malformed = bytearray(binary)
    malformed[229] = 2
    reject(malformed)
    malformed = bytearray(binary)
    malformed[228] = 0x0a
    reject(malformed)
    malformed = bytearray(binary)
    malformed[-1] = 1
    reject(malformed)
    malformed = bytearray(binary)
    struct.pack_into("<Q", malformed, 136, 0xfffffffffffffff8)
    reject(malformed)
    malformed = bytearray(binary)
    struct.pack_into("<I", malformed, 152, 0xffffffff)
    reject(malformed)
    malformed = bytearray(binary)
    malformed[228] = 0x06
    reject(malformed)
    for bad in (True, -1, 0x100000000):
        altered = copy.deepcopy(expected)
        altered["cpu_type"] = bad
        try: frames.evidence(altered, binary, 1)
        except ValueError: pass
        else: raise AssertionError("invalid evidence integer accepted")
    # A compact, valid string table can be referenced repeatedly or through
    # different suffixes. Charge each resulting record, not each unique index.
    small, small_expected = macho_fixture(1, [(b"x" * 30000, 0x0e, 1, 0, 0x10)])
    assert frames.macho_summary(small, 1) == small_expected
    exact, exact_expected = macho_fixture(1, [(b"abc", 0x0e, 1, 0, 0x10)])
    with patch.object(frames, "NATIVE_EVIDENCE_BUDGET", 256 * 2 + 3 + 4):
        assert frames.macho_summary(exact, 1) == exact_expected
    with patch.object(frames, "NATIVE_EVIDENCE_BUDGET", 256 * 2 + 3 + 4 - 1):
        try: frames.macho_summary(exact, 1)
        except ValueError as exc: assert str(exc) == "native evidence size limit"
        else: raise AssertionError("over-budget symbol accepted")
    for suffixes in (False, True):
        count = 1000
        data, _ = macho_fixture(1, [(b"", 0x0e, 1, 0, 0x10)] * count)
        data = bytearray(data)
        for i in range(count):
            struct.pack_into("<I", data, 224 + 16 * i, 1 + (i % 100 if suffixes else 0))
        data.extend(b"x" * 30000 + b"\0")
        struct.pack_into("<I", data, 204, 30002)
        try: frames.macho_summary(bytes(data), 1)
        except ValueError as exc: assert str(exc) == "native evidence size limit"
        else: raise AssertionError("amplified symbol names accepted")


def test_strict_manifest_synthetic_controls():
    # These are synthetic unit fixtures, not correspondence for captured logs.
    def written(kind, role, offset):
        return {"kind": "Written", "source_identity": {"module": "Example", "file": "example.iyi"},
                "input_byte_offset": offset, "anchor_kind": kind, "role": role}

    closure = written("ProcLiteral", "arrow", 17)
    proc = {"kind": "Iyi::ProcInstanceType", "arguments": [], "return": {"kind": "Iyi::IntegerType", "name": "Int32"}}
    identity = {"origin": closure, "specialization": {"kind": "program_scope", "source_identity": {"module": "Example", "file": "example.iyi"}},
                "capture_descriptor": {"proc_type": proc, "is_closure": False, "environment": None},
                "displayed_source_location": {"file": "example.iyi", "line": 9, "column": 3}}
    def fixture(name, raw_name):
        entry = [((b"_" + raw_name.encode()), 0x0f, 1, 0, 0x10)]
        binary, executable_evidence = macho_fixture(2, entry)
        obj, object_evidence = macho_fixture(1, entry)
        emission = {"requested_symbol": raw_name, "actual_llvm_symbol": raw_name, "unit_name": "unit", "linkage": "external", **copy.deepcopy(identity)}
        manifest = {"schema": 5, "object_input_scope": "compiler_supplied_link_inputs",
                    "executable_sha256": hashlib.sha256(binary).hexdigest(), "executable_symbols": executable_evidence,
                    "object_inputs": [{"link_input_id": 0, "producer": {"kind": "current_unit", "unit_ordinal": 0},
                                       "unit_name": "unit", "partition": None, "sha256": hashlib.sha256(obj).hexdigest(),
                                       "bytes_base64": base64.b64encode(obj).decode(), "native_evidence": object_evidence}],
                    "bindings": [{"link_input_id": 0, "definition": {"emission": emission, "post_partition_llvm_symbol": raw_name,
                                  "native_object_symbol": "_" + raw_name, "post_partition_linkage": "external", "partition_role": "single"}}]}
        return binary, manifest

    left_symbol = "~proc3Proc(Int32)^example.iyi:9"
    right_symbol = "~proc2Proc(Int32)^example.iyi:9"
    binary_a, manifest_a = fixture("a", left_symbol)
    binary_b, manifest_b = fixture("b", right_symbol)
    line_a = ("0   fixture 0x0000000100000001 " + left_symbol + " + 1\n").encode()
    line_b = ("0   fixture 0x0000000100000002 " + right_symbol + " + 2\n").encode()

    with tempfile.TemporaryDirectory() as directory:
        executable_a = os.path.join(directory, "a")
        executable_b = os.path.join(directory, "b")
        path = os.path.join(directory, "manifest.json")
        with open(executable_a, "wb") as f: f.write(binary_a)
        with open(executable_b, "wb") as f: f.write(binary_b)

        def load(manifest, executable):
            with open(path, "w", encoding="utf-8") as f: json.dump(manifest, f)
            return frames.FrameManifest(path, executable)

        def reject(manifest, executable=executable_b):
            try: load(manifest, executable)
            except (ValueError, TypeError, KeyError): return
            raise AssertionError("corrupt manifest accepted")

        with contextlib.nullcontext():
            left, right = load(manifest_a, executable_a), load(manifest_b, executable_b)
            assert capture_violation(compare_same_opt, [line_a], [line_b], require_frames=True, manifests=(left, right))[0] == 0
            same_output = os.path.join(directory, "same.out")
            with open(same_output, "wb") as f: f.write(line_a)
            missing = os.path.join(directory, "missing.json")
            argv = ["frames_equivalent.py", "--strict-provenance", "--source-manifest", missing,
                    "--artifact-manifest", missing, "--source-executable", executable_a,
                    "--artifact-executable", executable_a, same_output, same_output]
            with patch.object(sys, "argv", argv), patch.object(sys, "stderr", io.StringIO()):
                try: frames.main()
                except SystemExit as exc: assert exc.code != 0
                else: raise AssertionError("equal output bypassed missing manifests")
            for mutation in ("origin", "specialization", "capture", "missing-binding", "object", "binary", "schema", "symbol", "location"):
                altered = copy.deepcopy(manifest_b)
                record = altered["bindings"][0]["definition"]["emission"]
                if mutation == "origin": record["origin"]["input_byte_offset"] += 1
                elif mutation == "specialization": record["specialization"]["source_identity"]["module"] = "Other"
                elif mutation == "capture": record["capture_descriptor"]["proc_type"]["return"]["name"] = "Int64"
                elif mutation == "missing-binding": altered["bindings"] = []
                elif mutation == "object": altered["object_inputs"][0]["bytes_base64"] = base64.b64encode(b"changed").decode()
                elif mutation == "binary": altered["executable_sha256"] = "0" * 64
                elif mutation == "schema": altered["schema"] = 4
                elif mutation == "symbol": altered["bindings"][0]["definition"]["native_object_symbol"] = "_fake"
                else: record["displayed_source_location"]["line"] = 10
                if mutation in ("origin", "specialization", "capture", "location"):
                    other = load(altered, executable_b)
                    assert capture_violation(compare_same_opt, [line_a], [line_b], manifests=(left, other))[0] == 1, mutation
                else: reject(altered)
            forged = copy.deepcopy(manifest_b)
            obj = forged["object_inputs"][0]
            obj["bytes_base64"] = base64.b64encode(b"forged object").decode()
            obj["sha256"] = hashlib.sha256(b"forged object").hexdigest()
            reject(forged)
            forged = copy.deepcopy(manifest_b)
            forged["object_inputs"][0]["native_evidence"]["symbols"][0]["desc"] = 1
            reject(forged)
            absent = copy.deepcopy(manifest_b)
            absent["object_inputs"][0]["native_evidence"]["symbols"] = []
            reject(absent)
            for typ, section, desc, value, flags in (
                    (0, 0, 0, 8, 0x80000400), (2, 0, 0, 0x10, 0x80000400),
                    (0xe0, 1, 0, 0x10, 0x80000400), (0x0e, 1, 0, 0x20, 0x80000400),
                    (0x0e, 1, 0, 0, 0x80000400), (0x0e, 1, 0, 0x21, 0x80000400),
                    (0x0e, 1, 0, 0x10, 0), (0x0e, 1, 0, 0x10, 0x80000408),
                    (0x0e, 1, 0x100, 0x10, 0x80000400), (0x0e, 1, 0x200, 0x10, 0x80000400)):
                changed = copy.deepcopy(manifest_b)
                data, summary = macho_fixture(1, [(b"_" + right_symbol.encode(), typ, section, desc, value)], flags)
                item = changed["object_inputs"][0]
                item["bytes_base64"], item["sha256"], item["native_evidence"] = base64.b64encode(data).decode(), hashlib.sha256(data).hexdigest(), summary
                reject(changed)
            changed = copy.deepcopy(manifest_b)
            data, summary = macho_fixture(1, [(b"_different", 0x0e, 1, 0, 0x10)])
            item = changed["object_inputs"][0]
            item["bytes_base64"], item["sha256"], item["native_evidence"] = base64.b64encode(data).decode(), hashlib.sha256(data).hexdigest(), summary
            reject(changed)
            for typ, desc in ((0x0e, 0), (0x1f, 0x80), (0x0f, 0x400)):
                changed = copy.deepcopy(manifest_b)
                data, summary = macho_fixture(1, [(b"_" + right_symbol.encode(), typ, 1, desc, 0x10)])
                item = changed["object_inputs"][0]
                item["bytes_base64"], item["sha256"], item["native_evidence"] = base64.b64encode(data).decode(), hashlib.sha256(data).hexdigest(), summary
                load(changed, executable_b)
            changed = copy.deepcopy(manifest_b)
            data, summary = macho_fixture(1, [(b"_" + right_symbol.encode(), 0x0e, 1, 0, 0x10)] * 2)
            item = changed["object_inputs"][0]
            item["bytes_base64"], item["sha256"], item["native_evidence"] = base64.b64encode(data).decode(), hashlib.sha256(data).hexdigest(), summary
            reject(changed)
            duplicated = copy.deepcopy(manifest_b)
            duplicated["bindings"].append(copy.deepcopy(duplicated["bindings"][0]))
            reject(duplicated)
            with open(executable_b, "ab") as f: f.write(b"changed")
            reject(manifest_b)
            with open(executable_b, "wb") as f: f.write(binary_b)
            for changed in (line_b.replace(b"fixture", b"other"), line_b.replace(b":9", b":10"),
                            line_b.replace(b"Int32", b"Int64"), line_b.replace(b"0   ", b"1   ")):
                assert capture_violation(compare_same_opt, [line_a], [changed], manifests=(left, right))[0] == 1
            assert capture_violation(compare_same_opt, [b"panic\n", line_a], [b"changed\n", line_b], manifests=(left, right))[0] == 1
            assert capture_violation(compare_same_opt, [line_a], [], manifests=(left, right))[0] == 1
            copies = copy.deepcopy(manifest_b)
            extra = copy.deepcopy(copies["object_inputs"][0])
            extra["link_input_id"] = 1
            extra["producer"] = {"kind": "artifact_object", "artifact_identity": "artifact", "object_ordinal": 0}
            copies["object_inputs"].append(extra)
            extra_binding = copy.deepcopy(copies["bindings"][0])
            extra_binding["link_input_id"] = 1
            copies["bindings"].append(extra_binding)
            same_identity_copies = load(copies, executable_b)
            assert capture_violation(compare_same_opt, [line_a], [line_b], manifests=(left, same_identity_copies))[0] == 0
            missing = copy.deepcopy(copies)
            missing["bindings"].pop()
            reject(missing)
            collision = copy.deepcopy(copies)
            collision["bindings"][1]["definition"]["emission"]["origin"]["input_byte_offset"] += 1
            reject(collision)
            # Equal semantic identities must not hide two direct executable
            # definitions at different addresses.
            duplicate_binary, duplicate_evidence = macho_fixture(2, [
                (b"_" + right_symbol.encode(), 0x0f, 1, 0, 0x10),
                (b"_" + right_symbol.encode(), 0x0e, 1, 0, 0x11)])
            duplicate = copy.deepcopy(copies)
            duplicate["executable_sha256"] = hashlib.sha256(duplicate_binary).hexdigest()
            duplicate["executable_symbols"] = duplicate_evidence
            with open(executable_b, "wb") as f: f.write(duplicate_binary)
            try: load(duplicate, executable_b)
            except ValueError as exc: assert str(exc) == "ambiguous executable definition"
            else: raise AssertionError("duplicate executable definition accepted")
            with open(executable_b, "wb") as f: f.write(binary_b)
            partition_missing = copy.deepcopy(manifest_b)
            partition_missing["object_inputs"][0]["partition"] = {"index": 0, "count": 2}
            partition_missing["bindings"][0]["definition"]["partition_role"] = "owner"
            reject(partition_missing)
            # Two separate native objects, with a swapped link-input mapping.
            _, second = fixture("second", left_symbol)
            combined = copy.deepcopy(manifest_b)
            combined_binary, combined_evidence = macho_fixture(2, [
                (b"_" + right_symbol.encode(), 0x0f, 1, 0, 0x10),
                (b"_" + left_symbol.encode(), 0x0f, 1, 0, 0x11)])
            combined["executable_sha256"] = hashlib.sha256(combined_binary).hexdigest()
            combined["executable_symbols"] = combined_evidence
            imported = copy.deepcopy(second["object_inputs"][0])
            imported["link_input_id"] = 1
            imported["producer"] = {"kind": "artifact_object", "artifact_identity": "other-artifact", "object_ordinal": 0}
            combined["object_inputs"].append(imported)
            second_binding = copy.deepcopy(second["bindings"][0])
            second_binding["link_input_id"] = 1
            combined["bindings"].append(second_binding)
            with open(executable_b, "wb") as f: f.write(combined_binary)
            load(combined, executable_b)
            missing_import = copy.deepcopy(combined)
            missing_import["bindings"].pop()
            try: load(missing_import, executable_b)
            except ValueError as exc: assert str(exc) == "linked closure lacks provenance"
            else: raise AssertionError("missing imported binding accepted")
            swapped = copy.deepcopy(combined)
            swapped["bindings"][0]["link_input_id"], swapped["bindings"][1]["link_input_id"] = 1, 0
            try: load(swapped, executable_b)
            except ValueError as exc: assert str(exc) == "binding absent or ambiguous in object"
            else: raise AssertionError("swapped imported and current bindings accepted")
            with open(executable_b, "wb") as f: f.write(binary_b)
            folded = copy.deepcopy(manifest_b)
            folded_binary, folded_evidence = macho_fixture(2, [
                (b"_" + right_symbol.encode(), 0x0f, 1, 0, 0x10),
                (b"_unidentified", 0x0e, 1, 0, 0x10)])
            folded["executable_sha256"] = hashlib.sha256(folded_binary).hexdigest()
            folded["executable_symbols"] = folded_evidence
            with open(executable_b, "wb") as f: f.write(folded_binary)
            reject(folded)
            with open(executable_b, "wb") as f: f.write(binary_b)
            promoted_name = right_symbol + ".iyi.part"
            promoted_binary, promoted = fixture("promoted", promoted_name)
            promoted_emission = promoted["bindings"][0]["definition"]["emission"]
            promoted_emission["requested_symbol"] = right_symbol
            promoted_emission["actual_llvm_symbol"] = right_symbol
            with open(executable_b, "wb") as f: f.write(promoted_binary)
            promoted_map = load(promoted, executable_b)
            promoted_line = line_b.replace(right_symbol.encode(), promoted_name.encode())
            assert capture_violation(compare_same_opt, [line_a], [promoted_line], manifests=(left, promoted_map))[0] == 0
            unknown_line = line_b.replace(right_symbol.encode(), (right_symbol + ".unknown").encode())
            assert capture_violation(compare_same_opt, [line_a], [unknown_line], manifests=(left, promoted_map))[0] == 1
            # The linkage namespace is resolved only by the explicit binding;
            # the requested spelling is still the unqualified proc name.
            namespaced_name = right_symbol + "^unit:" + "Boot::Half".encode().hex()
            namespaced_binary, namespaced = fixture("namespaced", namespaced_name)
            namespaced_emission = namespaced["bindings"][0]["definition"]["emission"]
            namespaced_emission["requested_symbol"] = right_symbol
            with open(executable_b, "wb") as f: f.write(namespaced_binary)
            namespaced_map = load(namespaced, executable_b)
            namespaced_line = line_b.replace(right_symbol.encode(), namespaced_name.encode())
            assert namespaced_map.resolve(namespaced_name.encode())[1] == right_symbol.encode()
            assert capture_violation(compare_same_opt, [line_a], [namespaced_line], manifests=(left, namespaced_map))[0] == 0
            for invalid_name in (namespaced_name + "00", namespaced_name[:-1] + "0"):
                assert invalid_name != namespaced_name
                invalid_line = line_b.replace(right_symbol.encode(), invalid_name.encode())
                assert capture_violation(compare_same_opt, [line_a], [invalid_line], manifests=(left, namespaced_map))[:2] == (1, "provenance")

            # Both names are actually bound, but one belongs to a different
            # semantic closure. A valid binding is not interchangeable.
            other_name = right_symbol + "^unit:" + "Boot::Other".encode().hex()
            _, other_manifest = fixture("other-namespaced", other_name)
            other_manifest["bindings"][0]["definition"]["emission"]["requested_symbol"] = right_symbol
            other_manifest["bindings"][0]["definition"]["emission"]["origin"]["input_byte_offset"] += 1
            paired = copy.deepcopy(namespaced)
            other_input = copy.deepcopy(other_manifest["object_inputs"][0])
            other_input["link_input_id"] = 1
            other_input["producer"] = {"kind": "artifact_object", "artifact_identity": "other", "object_ordinal": 0}
            paired["object_inputs"].append(other_input)
            other_binding = copy.deepcopy(other_manifest["bindings"][0])
            other_binding["link_input_id"] = 1
            paired["bindings"].append(other_binding)
            paired_binary, paired_evidence = macho_fixture(2, [
                (b"_" + namespaced_name.encode(), 0x0f, 1, 0, 0x10),
                (b"_" + other_name.encode(), 0x0e, 1, 0, 0x11)])
            paired["executable_sha256"] = hashlib.sha256(paired_binary).hexdigest()
            paired["executable_symbols"] = paired_evidence
            with open(executable_b, "wb") as f: f.write(paired_binary)
            paired_map = load(paired, executable_b)
            assert capture_violation(compare_same_opt, [line_a], [namespaced_line], manifests=(left, paired_map))[0] == 0
            other_line = line_b.replace(right_symbol.encode(), other_name.encode())
            assert capture_violation(compare_same_opt, [line_a], [other_line], manifests=(left, paired_map))[:2] == (1, "function")
            # Equal raw names are not evidence of identity, even under a counter permutation.
            same_binary, same_manifest = fixture("same", left_symbol)
            with open(executable_b, "wb") as f: f.write(same_binary)
            same_manifest["bindings"][0]["definition"]["emission"]["origin"]["input_byte_offset"] += 1
            other = load(same_manifest, executable_b)
            assert capture_violation(compare_same_opt, [line_a], [line_a], manifests=(left, other))[0] == 1
            valid_json = json.dumps(same_manifest)
            duplicated_json = valid_json.replace('"schema": 5', '"schema": 5, "schema": 5', 1)
            assert duplicated_json != valid_json
            with open(path, "w", encoding="utf-8") as f: f.write(duplicated_json)
            try: frames.FrameManifest(path, executable_b)
            except ValueError as exc: assert str(exc) == "duplicate JSON key"
            else: raise AssertionError("duplicate JSON key accepted")

    invocation = written("Call", "method", 2)
    definition = written("Macro", "keyword", 4)
    emitter = written("MacroDirective", "expression", 6)
    expanded = {"kind": "Expanded", "invocation_origin": invocation, "macro_definition_origin": definition,
                "expansion_guard": "sha256:" + "a" * 64, "anchor_kind": "ProcLiteral", "role": "arrow", "name_context": None,
                "token_event": {"input_start": 8, "input_end": 10, "token_kind": "->", "token_text": "->",
                                "lexical_mode": "Crystal", "selection": "Whole",
                                "byte_parts": [{"kind": "AstAnchor", "start_offset": 8, "end_offset": 10, "emitter_origin": emitter, "source_origin": closure}]},
                "anchor_use": {"kind": "Direct"}}
    assert frames.checked_origin(expanded) == ("ProcLiteral", "arrow")
    for kind in ("Include", "Extend", "ClassDef", "Def", "Macro"):
        hook = copy.deepcopy(expanded)
        hook["invocation_origin"] = written(kind, "keyword", 2)
        assert frames.checked_origin(hook) == ("ProcLiteral", "arrow")
    for kind, role in (("Include", "method"), ("Extend", "control"), ("ClassDef", "method"),
                       ("Def", "method"), ("Macro", "control"), ("Module", "keyword")):
        invalid = copy.deepcopy(expanded)
        invalid["invocation_origin"] = written(kind, role, 2)
        try: frames.checked_origin(invalid)
        except ValueError: pass
        else: raise AssertionError("invalid hook ancestry accepted: " + kind + "/" + role)
    invalid_definition = copy.deepcopy(expanded)
    invalid_definition["invocation_origin"] = written("Include", "keyword", 2)
    invalid_definition["macro_definition_origin"] = written("Def", "keyword", 4)
    try: frames.checked_origin(invalid_definition)
    except ValueError: pass
    else: raise AssertionError("invalid hook macro definition accepted")
    for change in ("gap", "empty", "wrong-emitter", "v2"):
        invalid = copy.deepcopy(expanded)
        if change == "gap": invalid["token_event"]["byte_parts"][0]["start_offset"] = 9
        elif change == "empty": invalid["token_event"]["byte_parts"] = []
        elif change == "wrong-emitter": invalid["token_event"]["byte_parts"][0]["emitter_origin"] = closure
        else: del invalid["token_event"]["byte_parts"]
        try: frames.checked_origin(invalid)
        except ValueError: pass
        else: raise AssertionError("invalid origin accepted: " + change)
    nested_emitter = emitter
    for index in range(128):
        nested_emitter = {"kind": "Expanded", "invocation_origin": invocation, "macro_definition_origin": definition,
                          "expansion_guard": "sha256:" + f"{index:064x}", "anchor_kind": "MacroDirective", "role": "expression", "name_context": None,
                          "token_event": {"input_start": 0, "input_end": 1, "token_kind": "IDENT", "token_text": "x", "lexical_mode": "Crystal",
                                          "selection": "Whole", "byte_parts": [{"kind": "Generated", "start_offset": 0, "end_offset": 1, "emitter_origin": nested_emitter, "producer": "MacroTemplate"}]},
                          "anchor_use": {"kind": "Direct"}}
    assert frames.checked_origin(nested_emitter) == ("MacroDirective", "expression")
    deep = copy.deepcopy(closure)
    for _ in range(129):
        deep = {"kind": "Synthetic", "parent_origin": deep, "synthesis_kind": "defer", "structural_slot": "cleanup"}
    try: frames.checked_origin(deep)
    except ValueError: pass
    else: raise AssertionError("over-deep origin accepted")
    huge = copy.deepcopy(closure)
    huge["source_identity"]["file"] = "x" * (8 * 1024 * 1024)
    try: frames.checked_origin(huge)
    except ValueError: pass
    else: raise AssertionError("overlarge origin accepted")
    class IdentityMap:
        def __init__(self, value): self.value = value
        def resolve(self, symbol):
            return ((self.value, identity["specialization"], identity["capture_descriptor"], identity["displayed_source_location"]), symbol)

    for change in ("directive", "part", "splice", "occurrence", "nested"):
        altered = copy.deepcopy(expanded)
        event = altered["token_event"]
        if change == "directive": event["byte_parts"][0]["emitter_origin"]["input_byte_offset"] += 1
        elif change == "part":
            event["byte_parts"][0] = {"kind": "Generated", "start_offset": 8, "end_offset": 10,
                                       "emitter_origin": emitter, "producer": "MacroTemplate"}
        elif change == "splice": event["byte_parts"][0]["source_origin"]["input_byte_offset"] += 1
        elif change == "occurrence":
            event["input_start"] += 2
            event["input_end"] += 2
            event["byte_parts"][0]["start_offset"] += 2
            event["byte_parts"][0]["end_offset"] += 2
        else:
            event["byte_parts"][0]["source_origin"] = copy.deepcopy(expanded)
        frames.checked_origin(altered)
        assert not frames.compare_functions(left_symbol.encode(), left_symbol.encode(), (IdentityMap(expanded), IdentityMap(altered))), change
    binding = {"name": "x", "binding_origin": {"kind": "Synthetic", "parent_origin": written("Call", "method", 30),
               "synthesis_kind": "local_binding", "structural_slot": "assignment"},
               "scope": {"kind": "program"}, "type": {"kind": "Iyi::IntegerType", "name": "Int32"}, "mutable": True}
    capture = {"proc_type": proc, "is_closure": True,
               "environment": {"captured_self_type": None, "bindings": [binding], "parent": None}}
    record = {"requested_symbol": left_symbol, "actual_llvm_symbol": left_symbol, "unit_name": "unit",
              "linkage": "external", "origin": closure, "specialization": identity["specialization"],
              "capture_descriptor": capture, "displayed_source_location": identity["displayed_source_location"]}
    base_identity = frames.emission_identity(record)
    class CompleteMap:
        def __init__(self, value): self.value = value
        def resolve(self, symbol): return self.value, symbol

    shadow = copy.deepcopy(record)
    shadow["capture_descriptor"]["environment"]["bindings"][0]["binding_origin"]["parent_origin"]["input_byte_offset"] += 1
    assert not frames.compare_functions(left_symbol.encode(), left_symbol.encode(),
                                        (CompleteMap(base_identity), CompleteMap(frames.emission_identity(shadow))))
    specialized = copy.deepcopy(record)
    specialized["specialization"] = {
        "definition_origin": written("Def", "keyword", 7),
        "dispatch_type": {"kind": "Iyi::ClassType", "name": "First"},
        "defining_owner": {"kind": "Iyi::ClassType", "name": "Owner"},
        "ordered_argument_types": [{"kind": "Iyi::IntegerType", "name": "Int32"}],
        "block_parameter_type": None, "named_argument_types": [], "free_variable_bindings": [],
        "expansion_shape": {"positional_count": 1, "splat_index": None, "double_splat_name": None,
                            "formal_parameters": [{"name": "x", "external_name": "x", "has_default": False}]},
        "lexical_block_specialization": None,
    }
    specialized_identity = frames.emission_identity(specialized)
    for key in ("dispatch", "argument", "owner"):
        different = copy.deepcopy(specialized)
        spec = different["specialization"]
        if key == "dispatch": spec["dispatch_type"]["name"] = "Second"
        elif key == "argument": spec["ordered_argument_types"][0]["name"] = "Int64"
        else: spec["defining_owner"]["name"] = "OtherOwner"
        assert not frames.compare_functions(left_symbol.encode(), left_symbol.encode(),
            (CompleteMap(specialized_identity), CompleteMap(frames.emission_identity(different)))), key
    unknown = copy.deepcopy(record)
    unknown["capture_descriptor"]["proc_type"]["return"]["kind"] = "Iyi::UnknownType"
    try: frames.emission_identity(unknown)
    except ValueError: pass
    else: raise AssertionError("unknown capture type accepted")


def test_composed_origin_controls():
    def written(kind, role, offset):
        return {"kind": "Written", "source_identity": {"module": "Example", "file": "example.iyi"},
                "input_byte_offset": offset, "anchor_kind": kind, "role": role}

    def source(offset):
        lexical = written("Call", "method", offset)
        return {"lexical_origin": lexical, "binding_origin": None, "context": "method_name",
                "input_sha256": "a" * 64, "input_bytesize": 100, "input_start": offset,
                "input_end": offset + 1, "lexical_mode": "Crystal", "token_kind": "IDENT", "raw_text": "a"}

    def contribution(start, source_token):
        return {"kind": "NameSplice", "start_offset": start, "end_offset": start + 1,
                "emitter_origin": None, "source_name": {"kind": "Observed", "source_token": source_token}}

    invocation = {"kind": "Expanded", "invocation_origin": written("Call", "method", 1),
                  "macro_definition_origin": written("Macro", "keyword", 2), "expansion_guard": "sha256:" + "b" * 64,
                  "anchor_kind": "Call", "role": "method", "name_context": "method_name",
                  "token_event": {"input_start": 10, "input_end": 12, "token_kind": "IDENT", "token_text": "aa", "lexical_mode": "Crystal", "selection": "Whole",
                                  "byte_parts": [contribution(10, source(20)), contribution(11, source(30))]},
                  "anchor_use": {"kind": "Direct"}}
    closure = {"kind": "Expanded", "invocation_origin": invocation, "macro_definition_origin": written("Macro", "keyword", 3),
               "expansion_guard": "sha256:" + "c" * 64, "anchor_kind": "ProcLiteral", "role": "arrow", "name_context": None,
               "token_event": {"input_start": 4, "input_end": 6, "token_kind": "->", "token_text": "->",
                               "lexical_mode": "Crystal", "selection": "Whole", "byte_parts": [
                                   {"kind": "AstAnchor", "start_offset": 4, "end_offset": 6,
                                    "emitter_origin": None, "source_origin": written("ProcLiteral", "arrow", 40)}]},
               "anchor_use": {"kind": "Direct"}}
    proc = {"kind": "Iyi::ProcInstanceType", "arguments": [], "return": {"kind": "Iyi::IntegerType", "name": "Int32"}}
    emission = {"requested_symbol": "~proc", "actual_llvm_symbol": "~proc", "unit_name": "unit", "linkage": "external",
                "origin": closure, "specialization": {"kind": "program_scope", "source_identity": {"module": "Example", "file": "example.iyi"}},
                "capture_descriptor": {"proc_type": proc, "is_closure": False, "environment": None},
                "displayed_source_location": {"file": "example.iyi", "line": 1, "column": 1}}
    baseline = frames.emission_identity(emission)
    name_source = source(20)
    name_source["raw_text"] = "empty"
    name_source["input_end"] = 25
    name_source["binding_origin"] = {"kind": "Synthetic", "parent_origin": copy.deepcopy(name_source["lexical_origin"]),
                                     "synthesis_kind": "local_binding", "structural_slot": "assignment"}
    class_name = copy.deepcopy(invocation)
    class_name.update({"anchor_kind": "Name", "role": "class_variable", "name_context": "class_variable"})
    class_name["token_event"] = {"input_start": 38, "input_end": 45, "token_kind": "CLASS_VAR", "token_text": "@@empty",
                                 "lexical_mode": "Crystal", "selection": "Whole",
                                 "byte_parts": [{"kind": "Generated", "start_offset": 38, "end_offset": 40,
                                                 "emitter_origin": None, "producer": "MacroTemplate"},
                                                {"kind": "NameSplice", "start_offset": 40, "end_offset": 45,
                                                 "emitter_origin": None, "source_name": {"kind": "Observed", "source_token": name_source}}]}
    assert frames.checked_origin(class_name) == ("Name", "class_variable")
    without_prefix = copy.deepcopy(class_name)
    without_prefix["token_event"]["byte_parts"].pop(0)
    try: frames.checked_origin(without_prefix)
    except ValueError: pass
    else: raise AssertionError("missing generated name prefix accepted")
    path_source = {"lexical_origin": written("Name", "path_segment", 20), "binding_origin": None,
                   "context": "path_segment", "input_sha256": "a" * 64, "input_bytesize": 100,
                   "input_start": 20, "input_end": 21, "lexical_mode": "Crystal", "token_kind": "CONST", "raw_text": "A"}
    child = copy.deepcopy(invocation)
    child.update({"anchor_kind": "Name", "role": "path_segment", "name_context": "path_segment"})
    child["token_event"] = {"input_start": 10, "input_end": 11, "token_kind": "CONST", "token_text": "A",
                            "lexical_mode": "Crystal", "selection": "Whole", "byte_parts": [contribution(10, path_source)]}
    parent = copy.deepcopy(child)
    parent.update({"anchor_kind": "Literal", "role": "array", "name_context": None,
                   "anchor_use": {"kind": "HeadOf", "rule": "NamedArrayHead", "emitter_origin": None,
                                  "evidence": {"kind": "Spliced", "source_origin": written("Literal", "array", 50)},
                                  "head": {"kind": "Anchor", "origin": child}}})
    assert frames.checked_origin(parent) == ("Literal", "array")
    constructed = copy.deepcopy(parent)
    constructed["anchor_use"]["evidence"] = {"kind": "Constructed", "producer": "ConstructedAst"}
    assert frames.checked_origin(constructed) == ("Literal", "array")
    witness_event = {"input_start": 12, "input_end": 13, "token_kind": "{", "token_text": "{",
                     "lexical_mode": "Crystal", "selection": "Whole",
                     "byte_parts": [{"kind": "Generated", "start_offset": 12, "end_offset": 13,
                                     "emitter_origin": None, "producer": "MacroTemplate"}]}
    raw_parent = copy.deepcopy(parent)
    raw_parent["anchor_use"]["evidence"] = {"kind": "RawSyntax", "witnesses": [{"role": "Open", "event": witness_event}]}
    assert frames.checked_origin(raw_parent) == ("Literal", "array")
    owner = copy.deepcopy(parent)
    owner.update({"anchor_kind": "Literal", "role": "regex", "anchor_use": {"kind": "Direct"},
                  "token_event": {"input_start": 1, "input_end": 2, "token_kind": "/", "token_text": "/",
                                  "lexical_mode": "Crystal", "selection": "Whole",
                                  "byte_parts": [{"kind": "Generated", "start_offset": 1, "end_offset": 2,
                                                  "emitter_origin": None, "producer": "MacroTemplate"}]}})
    payload = copy.deepcopy(owner)
    payload.update({"role": "interpolation",
                    "anchor_use": {"kind": "PayloadOf", "rule": "RegexInterpolationPayload", "emitter_origin": None,
                                   "evidence": {"kind": "DerivedFromOwner"}, "owner_origin": owner}})
    assert frames.checked_origin(payload) == ("Literal", "interpolation")
    for mutation in ("missing_use", "wrong_parent", "wrong_child", "event_mismatch", "bad_rule",
                     "bad_producer", "bad_witness", "wrong_owner", "payload_position", "missing_bytes"):
        node = copy.deepcopy(raw_parent if mutation in ("bad_producer", "bad_witness") else
                             payload if mutation in ("wrong_owner", "payload_position") else parent)
        if mutation == "missing_use": del node["anchor_use"]
        elif mutation == "wrong_parent": node["anchor_use"]["evidence"]["source_origin"]["role"] = "hash"
        elif mutation == "wrong_child": node["anchor_use"]["head"]["origin"]["role"] = "method_name"
        elif mutation == "event_mismatch": node["anchor_use"]["head"]["origin"]["token_event"]["byte_parts"][0]["source_name"]["source_token"]["input_sha256"] = "c" * 64
        elif mutation == "bad_rule": node["anchor_use"]["rule"] = "Unrelated"
        elif mutation == "bad_producer": node["anchor_use"]["evidence"]["witnesses"][0]["event"]["byte_parts"][0]["producer"] = "ConstructedAst"
        elif mutation == "bad_witness": node["anchor_use"]["evidence"]["witnesses"][0]["role"] = "Equals"
        elif mutation == "wrong_owner": node["anchor_use"]["owner_origin"]["role"] = "array"
        elif mutation == "payload_position": node["token_event"]["input_start"] = 2
        else: node["token_event"]["byte_parts"] = []
        try: frames.checked_origin(node)
        except (ValueError, KeyError, TypeError): pass
        else: raise AssertionError("invalid shared event accepted: " + mutation)
    def derived(raw, token_kind, result="Argument", projection="StripVariablePrefix", fresh=None):
        encoded = raw.encode("utf-8")
        source_token = {"lexical_origin": written("Name", "parameter", 20), "binding_origin": None,
                        "context": "parameter", "input_sha256": "e" * 64, "input_bytesize": 100,
                        "input_start": 20, "input_end": 20 + len(encoded), "lexical_mode": "Crystal",
                        "token_kind": token_kind, "raw_text": raw}
        return {"kind": "DerivedName", "derivation_kind": "ParameterLowering", "source_token": source_token, "definition_origin": written("Def", "keyword", 9),
                "parameter_slot": "positional", "parameter_index": 0, "result": result,
                "projection": projection, "fresh_index": fresh}

    for node, role, spelling in (
            (derived("@x", "INSTANCE_VAR"), "parameter", b"x"),
            (derived("@@éclair", "CLASS_VAR", "LocalValue"), "local_reference", "éclair".encode()),
            (derived("@x", "INSTANCE_VAR", "Target", "Whole"), "instance_variable", b"@x"),
            (derived("@@x", "CLASS_VAR", "Target", "Whole"), "class_variable", b"@@x"),
            (derived("@select", "INSTANCE_VAR", "Argument", "FreshParameterName", 7), "parameter", b"__arg7"),
            (derived("@select", "INSTANCE_VAR", "DefaultExternal"), "named_entry", b"select")):
        assert frames.checked_origin(node) == ("Name", role)
        assert frames.derived_name(node, 0)[1] == spelling
    lowered = derived("@é", "INSTANCE_VAR")
    part = {"kind": "NameSplice", "start_offset": 10, "end_offset": 12, "emitter_origin": None,
            "source_name": {"kind": "Derived", "origin": lowered}}
    composed = copy.deepcopy(invocation)
    composed["token_event"].update({"input_end": 12, "token_text": "é", "byte_parts": [part]})
    assert frames.checked_origin(composed) == ("Call", "method")
    for mutation in ("prefix", "kind", "source_context", "source_role", "definition", "slot", "index",
                     "result", "projection", "fresh", "missing", "unknown_name", "bytes"):
        invalid = copy.deepcopy(composed)
        part = invalid["token_event"]["byte_parts"][0]
        derivation = part["source_name"]["origin"]
        token = derivation["source_token"]
        if mutation == "prefix": token["raw_text"] = "$é"
        elif mutation == "kind": token["token_kind"] = "CLASS_VAR"
        elif mutation == "source_context": token["context"] = "instance_variable"
        elif mutation == "source_role": token["lexical_origin"]["role"] = "instance_variable"
        elif mutation == "definition": derivation["definition_origin"]["anchor_kind"] = "Macro"
        elif mutation == "slot": derivation["parameter_slot"] = "unknown"
        elif mutation == "index": derivation["parameter_index"] = -1
        elif mutation == "result": derivation["result"] = "Target"
        elif mutation == "projection": derivation["projection"] = "Whole"
        elif mutation == "fresh": derivation["fresh_index"] = 1
        elif mutation == "missing": del derivation["definition_origin"]
        elif mutation == "unknown_name": part["source_name"]["kind"] = "Unknown"
        else: invalid["token_event"]["token_text"] = "ê"
        try: frames.checked_origin(invalid)
        except (ValueError, UnicodeError, TypeError, KeyError): pass
        else: raise AssertionError("invalid derived name accepted: " + mutation)
    for bad in (
            derived("@x", "INSTANCE_VAR", "Argument", "FreshParameterName", 1),
            derived("@select", "INSTANCE_VAR", "Argument", "FreshParameterName", None),
            derived("@select", "INSTANCE_VAR", "LocalValue", "StripVariablePrefix"),
            derived("@x", "INSTANCE_VAR", "DefaultExternal"),
            {**derived("@x", "INSTANCE_VAR"), "parameter_slot": "block", "parameter_index": 1},
            {**derived("@x", "INSTANCE_VAR"), "parameter_slot": "double_splat", "parameter_index": 1}):
        try: frames.checked_origin(bad)
        except (ValueError, TypeError): pass
        else: raise AssertionError("invalid parameter derivation accepted")
    for change in ("parameter_index", "definition_origin", "source_token"):
        changed = copy.deepcopy(lowered)
        if change == "parameter_index": changed[change] = 1
        elif change == "definition_origin": changed[change]["input_byte_offset"] += 1
        else: changed[change]["input_sha256"] = "f" * 64
        original_emission = copy.deepcopy(emission)
        original_emission["origin"]["invocation_origin"] = copy.deepcopy(composed)
        changed_emission = copy.deepcopy(original_emission)
        changed_emission["origin"]["invocation_origin"]["token_event"]["byte_parts"][0]["source_name"]["origin"] = changed
        assert frames.emission_identity(changed_emission) != frames.emission_identity(original_emission), change
    def regex_derivation(raw, result):
        encoded = raw.encode("utf-8")
        source_token = {"lexical_origin": written("Name", "regex_match_index", 20), "binding_origin": None,
                        "context": "regex_match_index", "input_sha256": "e" * 64, "input_bytesize": 100,
                        "input_start": 20, "input_end": 20 + len(encoded), "lexical_mode": "Crystal",
                        "token_kind": "GLOBAL_MATCH_DATA_INDEX", "raw_text": raw}
        return {"kind": "DerivedName", "derivation_kind": "RegexMatchIndex", "source_token": source_token, "result": result}

    for raw, result, role, spelling in (
            ("$0", "MatchData", ("Name", "special_global"), b"$~"),
            ("$1", "Lookup", ("Call", "method"), b"[]"),
            ("$2147483647?", "Lookup", ("Call", "method"), b"[]?")):
        node = regex_derivation(raw, result)
        assert frames.checked_origin(node) == role
        assert frames.derived_name(node, 0)[1] == spelling
    for raw in ("$0?", "$01", "$foo", "$-1", "$2147483648", "$999999999999999999999"):
        try: frames.checked_origin(regex_derivation(raw, "Lookup"))
        except ValueError: pass
        else: raise AssertionError("invalid regex source accepted: " + raw)
    regex = regex_derivation("$1?", "Lookup")
    wrong_lookup = copy.deepcopy(invocation)
    wrong_lookup["token_event"].update({"input_start": 0, "input_end": 2, "token_kind": "[]",
                         "token_text": "[]", "byte_parts": [{"kind": "NameSplice", "start_offset": 0,
                         "end_offset": 2, "emitter_origin": None, "source_name": {"kind": "Derived", "origin": regex}}]})
    try: frames.checked_origin(wrong_lookup)
    except ValueError: pass
    else: raise AssertionError("wrong regex lookup spelling accepted")
    for change in ("wrong_source", "wrong_result", "extra", "wrong_parent"):
        bad = copy.deepcopy(regex)
        if change == "wrong_source": bad["source_token"]["context"] = "special_global"
        elif change == "wrong_result": bad["result"] = "Unknown"
        elif change == "extra": bad["projection"] = "Whole"
        else: bad["source_token"]["lexical_origin"]["anchor_kind"] = "Call"
        try: frames.checked_origin(bad)
        except (ValueError, KeyError): pass
        else: raise AssertionError("invalid regex derivation accepted: " + change)

    def sugar(production, result, index, spellings):
        witnesses = []
        offset = 20
        for spelling in spellings:
            token_kind = "IDENT" if spelling in ("self?", "nil?") else spelling
            witnesses.append({"lexical_origin": written("TypeSyntax", "token", offset),
                              "input_sha256": "a" * 64, "input_bytesize": 100, "input_start": offset,
                              "input_end": offset + len(spelling), "lexical_mode": "Crystal",
                              "token_kind": token_kind, "raw_text": spelling})
            offset += len(spelling) + 1
        return {"kind": "DerivedName", "derivation_kind": "TypeSugar", "production": production,
                "witnesses": witnesses, "result": result, "lowering_index": index}

    for production, result, index, spelling in (
            ("Pointer", "Pointer", 0, ["*"]), ("DoublePointer", "Pointer", 1, ["**"]),
            ("NilableType", "Nil", 0, ["?"]), ("NilableExpression", "Union", 0, ["?"]),
            ("SelfNilableType", "Nil", 0, ["self?"]), ("StaticArray", "StaticArray", 0, ["[", "]"]),
            ("Tuple", "Tuple", 0, ["{", "}"]), ("NamedTuple", "NamedTuple", 0, ["{", "}"]),
            ("NilPredicate", "Nil", 0, ["nil?"])):
        valid = sugar(production, result, index, spelling)
        assert frames.checked_origin(valid) == ("Name", "path_segment")
        assert frames.derived_name(valid, 0)[1] == result.encode()
    for mutation in ("production", "result", "index", "reversed", "duplicate", "guard", "source_role", "wrong_token"):
        bad = sugar("StaticArray", "StaticArray", 0, ["[", "]"])
        if mutation == "production": bad["production"] = "Unknown"
        elif mutation == "result": bad["result"] = "Pointer"
        elif mutation == "index": bad["lowering_index"] = 1
        elif mutation == "reversed": bad["witnesses"].reverse()
        elif mutation == "duplicate": bad["witnesses"][1] = copy.deepcopy(bad["witnesses"][0])
        elif mutation == "guard": bad["witnesses"][1]["input_sha256"] = "b" * 64
        elif mutation == "source_role": bad["witnesses"][0]["lexical_origin"]["role"] = "keyword"
        else: bad["witnesses"][0]["token_kind"] = "IDENT"
        try: frames.checked_origin(bad)
        except (ValueError, KeyError, TypeError): pass
        else: raise AssertionError("invalid type sugar accepted: " + mutation)

    for context, kind, raw in (("enum_member", "CONST", "Member"),
                               ("special_global", "$~", "$~"), ("special_global", "$?", "$?")):
        token = {"lexical_origin": written("Name", context, 20), "binding_origin": None,
                 "context": context, "input_sha256": "a" * 64, "input_bytesize": 100,
                 "input_start": 20, "input_end": 20 + len(raw.encode()), "lexical_mode": "Crystal",
                 "token_kind": kind, "raw_text": raw}
        assert frames.source_name(token, 0) == raw.encode()
        forged = copy.deepcopy(token)
        forged["lexical_origin"] = written("Call", "method", 20)
        try: frames.source_name(forged, 0)
        except ValueError: pass
        else: raise AssertionError("generic call authorized " + context)
    for mutation in ("file", "offset", "digest", "binding", "emitter", "order"):
        changed = copy.deepcopy(emission)
        parts = changed["origin"]["invocation_origin"]["token_event"]["byte_parts"]
        token = parts[0]["source_name"]["source_token"]
        if mutation == "file": token["lexical_origin"]["source_identity"]["file"] = "other.iyi"
        elif mutation == "offset":
            token["input_start"] += 1; token["input_end"] += 1
            token["lexical_origin"]["input_byte_offset"] += 1
        elif mutation == "digest": token["input_sha256"] = "d" * 64
        elif mutation == "binding":
            token["binding_origin"] = {"kind": "Synthetic", "parent_origin": copy.deepcopy(token["lexical_origin"]),
                                       "synthesis_kind": "local_binding", "structural_slot": "assignment"}
        elif mutation == "emitter": parts[0]["emitter_origin"] = written("MacroDirective", "expression", 50)
        else: parts[0]["source_name"], parts[1]["source_name"] = parts[1]["source_name"], parts[0]["source_name"]
        assert frames.emission_identity(changed) != baseline, mutation

    for mutation in ("missing", "overlap", "short", "source_role", "input_bound", "slice", "projection",
                     "utf8", "unknown_part", "unknown_context", "wrong_call_context", "unknown_mode", "unknown_token", "token_text", "old_shape"):
        changed = copy.deepcopy(emission)
        node = changed["origin"]["invocation_origin"]
        parts = node["token_event"]["byte_parts"]
        token = parts[0]["source_name"]["source_token"]
        if mutation == "missing": parts.pop()
        elif mutation == "overlap": parts[1]["start_offset"] = 10
        elif mutation == "short": node["token_event"]["input_end"] = 11
        elif mutation == "source_role": token["lexical_origin"]["role"] = "keyword"
        elif mutation == "input_bound": token["input_bytesize"] = 20
        elif mutation == "slice": parts[0]["slice_end"] = 0
        elif mutation == "projection": parts[0]["projection"] = "arbitrary"
        elif mutation == "utf8": token["raw_text"] = "\ud800"
        elif mutation == "unknown_part": parts[0]["kind"] = "Other"
        elif mutation == "unknown_context": node["name_context"] = "unknown"
        elif mutation == "wrong_call_context": node["name_context"] = "local_reference"
        elif mutation == "unknown_mode": token["lexical_mode"] = "unknown"
        elif mutation == "unknown_token": token["token_kind"] = "unknown"
        elif mutation == "token_text": token["token_kind"] = "CONST"
        else: node["spliced_origin"] = None
        try: frames.emission_identity(changed)
        except (ValueError, UnicodeError, TypeError, KeyError): pass
        else: raise AssertionError("accepted malformed composition: " + mutation)

    for kind, raw, mode, context, expected in (
            ("CLASS_VAR", "@@empty", "Crystal", "class_variable", True),
            ("IDENT", "éclair?", "Crystal", "method_name", True),
            ("CONST", "Example", "Crystal", "method_name", True),
            ("=", "=", "Crystal", "macro_name", True),
            ("`", "`", "Crystal", "macro_name", True),
            ("!", "!", "Crystal", "macro_name", False),
            ("CONST", "Member", "Crystal", "enum_member", True),
            ("IDENT", "member", "Crystal", "enum_member", False),
            ("CONST", "Member", "Crystal", "parameter", False),
            ("$~", "$~", "Crystal", "special_global", True),
            ("$?", "$?", "Crystal", "special_global", True),
            ("$?", "$~", "Crystal", "special_global", False),
            ("IDENT", "$~", "Crystal", "special_global", False),
            ("GLOBAL_MATCH_DATA_INDEX", "$0?", "Crystal", "regex_match_index", False),
            ("IDENT", "name!", "Crystal", "method_name", True),
            ("IDENT", "name!", "Iyi", "method_name", False),
            ("IDENT", "1name", "Crystal", "method_name", False),
            ("IDENT", "@name", "Crystal", "method_name", False),
            ("CONST", "name", "Crystal", "path_segment", False),
            ("INSTANCE_VAR", "@@name", "Crystal", "instance_variable", False),
            ("IDENT", "name", "Crystal", "class_variable", False)):
        assert frames.name_token(kind, raw, mode, context) == expected, (kind, raw, context)


def run_all_tests() -> int:
    tests = [
        ("test_composed_origin_controls", test_composed_origin_controls),
        ("test_macho_reader_controls", test_macho_reader_controls),
        ("test_strict_manifest_synthetic_controls", test_strict_manifest_synthetic_controls),
        ("test_captured_linux_equivalence", test_captured_linux_equivalence),
        ("test_discriminating_mutations_linux", test_discriminating_mutations_linux),
        ("test_explicit_named_frame_proof_rejects_zero_frames", test_explicit_named_frame_proof_rejects_zero_frames),
        ("test_strict_linux_across_opt", test_strict_linux_across_opt),
        ("test_module_mutant_restricts_to_recognized_frame", test_module_mutant_restricts_to_recognized_frame),
        ("test_approved_std_canonicalization", test_approved_std_canonicalization),
        ("test_unknown_addresses_not_normalized", test_unknown_addresses_not_normalized),
        ("test_darwin_backward_compatibility", test_darwin_backward_compatibility),
        ("test_captured_darwin_proc_and_collisions", test_captured_darwin_proc_and_collisions),
        ("test_cross_format_mismatch", test_cross_format_mismatch),
    ]
    failed = 0
    for name, test in tests:
        try:
            test()
            print(f"PASS: {name}")
        except Exception as e:
            print(f"FAIL: {name}: {e}")
            failed += 1

    if failed == 0:
        print(f"\nAll {len(tests)} test suites PASSED")
        return 0
    else:
        print(f"\n{failed}/{len(tests)} test suites FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
