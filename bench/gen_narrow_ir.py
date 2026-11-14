#!/usr/bin/env python3
"""Generate deterministic, defined integer DAGs as iyi IR.

Usage: python3 bench/gen_narrow_ir.py OUTPUT_DIR [COUNT] [FIRST_SEED]
The separate C identity function is generated next to the IR files. The same
file must be linked into both implementations, without LTO or optimization.
"""
import random
import sys
from pathlib import Path

EDGES = [0, 1, -1, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff,
         0x7fffffff, 0x80000000, 0xffffffff]
WIDTHS = (1, 8, 16, 32, 64)
OPS = ('add', 'sub', 'mul', 'and', 'or', 'xor', 'shl', 'lshr', 'ashr',
       'udiv', 'sdiv', 'urem', 'srem')
PREDS = ('eq', 'ne', 'ugt', 'uge', 'ult', 'ule', 'sgt', 'sge', 'slt', 'sle')


def generate(seed):
    r = random.Random(seed)
    lines = ['; iyi-ir 1', f'module "narrow_{seed}"',
             'target triple = "aarch64-apple-darwin"',
             'target datalayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-n32:64-S128-Fn32"',
             'declare external i32 @printf(ptr, ...)',
             'declare external i64 @identity(i64)',
             '@fmt = private constant [6 x i8] c"%lld\\0A\\00"']
    values = {}
    for w in WIDTHS:
        edges = EDGES + [-(1 << (w - 1)), (1 << (w - 1)) - 1]
        v = r.choice(edges) & ((1 << w) - 1)
        lines.append(f'@g{w} = internal global i{w} {v}, align 1')
        values[w] = v
    for w in (8, 16, 32):
        lines.append(f'@atomic{w} = internal global i{w} {values[w]}, align {w // 8}')
    lines += ['define i32 @main() {', 'entry:']
    counter = 0
    def emit(op):
        nonlocal counter
        counter += 1
        name = f'%v{counter}'
        lines.append(f'  {name} = {op}')
        return name
    def output(v, w):
        if w < 64:
            v = emit(f'zext i{w} {v} to i64')
        emit(f'call i32 (ptr, ...) @printf(ptr @fmt, i64 {v})')
    pools = {}
    for w in WIDTHS:
        v = emit(f'load i{w}, ptr @g{w}, align 1')
        c = emit(f'call i64 (i64) @identity(i64 {values[w]})')
        if w < 64:
            c = emit(f'trunc i64 {c} to i{w}')
        pools[w] = [v, c, str(values[w])]
    for w in WIDTHS:
        for op in OPS:
            a, b = r.choice(pools[w]), r.choice(pools[w])
            if op in ('sdiv', 'srem', 'udiv', 'urem'):
                # 1 is the sole nonzero, non-minus-one signed divisor for i1.
                # i1 -1 is harmless unless the dividend is also -1, so use
                # unsigned division only there and signed division with zero dividend.
                if w == 1 and op in ('sdiv', 'srem'):
                    a, b = '0', '1'
                else:
                    b = '1'
            elif op in ('shl', 'lshr', 'ashr'):
                b = emit(f'and i{w} {b}, {w - 1}')
            v = emit(f'{op} i{w} {a}, {b}')
            pools[w].append(v)
            output(v, w)
        for pred in PREDS:
            v = emit(f'icmp {pred} i{w} {r.choice(pools[w])}, {r.choice(pools[w])}')
            output(v, 1)
        v = emit(f'select i1 {r.choice(pools[1])}, i{w} {r.choice(pools[w])}, i{w} {r.choice(pools[w])}')
        output(v, w)
    for lo, hi in zip(WIDTHS, WIDTHS[1:]):
        for op in ('zext', 'sext'):
            v = emit(f'{op} i{lo} {r.choice(pools[lo])} to i{hi}')
            output(v, hi)
        v = emit(f'trunc i{hi} {r.choice(pools[hi])} to i{lo}')
        output(v, lo)
    # Bound a loaded value so both float-to-int conversions are defined.
    bounded = emit(f'and i32 {pools[32][0]}, 1')
    for op, back in (('sitofp', 'fptosi'), ('uitofp', 'fptoui')):
        v = emit(f'{op} i32 {bounded} to double')
        v = emit(f'{back} double {v} to i32')
        output(v, 32)
    for w in (8, 16, 32):
        v = emit(f'atomicrmw add ptr @atomic{w}, i{w} 1, align {w // 8} seq_cst')
        output(v, w)
        v = emit(f'cmpxchg ptr @atomic{w}, i{w} {(values[w] + 1) & ((1 << w) - 1)}, i{w} 0, align {w // 8} seq_cst monotonic')
        old = emit(f'extractvalue {{ i{w}, i1 }} {v}, 0')
        ok = emit(f'extractvalue {{ i{w}, i1 }} {v}, 1')
        output(old, w)
        output(ok, 1)
    v = emit('load i8, ptr @g8, align 1')
    lines += [f'  switch i8 {v}, label %default [ i8 128, label %high, i8 255, label %high ]',
              'high:', '  br label %done', 'default:', '  br label %done', 'done:',
              '  %switch_result = phi i64 [ 1, label %high ], [ 0, label %default ]']
    output('%switch_result', 64)
    lines += ['  ret i32 0', '}', '']
    return '\n'.join(lines)


def main():
    if len(sys.argv) < 2 or len(sys.argv) > 4:
        raise SystemExit(__doc__)
    out = Path(sys.argv[1])
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    start = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    out.mkdir(parents=True, exist_ok=True)
    (out / 'identity.c').write_text('#include <stdint.h>\nint64_t identity(int64_t x) { return x; }\n')
    for seed in range(start, start + count):
        (out / f'seed_{seed:04d}.ir').write_text(generate(seed))

if __name__ == '__main__':
    main()
