#!/usr/bin/env python3
"""Generate matched native IR and hosted division tables in the gate's work directory."""
from pathlib import Path
import sys

work = Path(sys.argv[1])
widths = (8, 16, 32, 64)

def signed_divisors(bits):
    hi = (1 << (bits - 1)) - 1
    lo = -(1 << (bits - 1))
    return sorted({lo, lo + 1, -64, -10, -7, -3, -2, -1, 1, 2, 3, 7, 10, 64, hi})

def unsigned_divisors(bits):
    hi = (1 << bits) - 1
    return sorted({1, 2, 3, 7, 10, 64, 1 << (bits - 1), hi - 4, hi})

def name(signed, bits, divisor):
    mark = ("m" + str(-divisor)) if divisor < 0 else ("p" + str(divisor))
    return ("s" if signed else "u") + str(bits) + "_" + mark

def ir_number(value, bits):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >= (1 << (bits - 1)) else value

def signed_inputs(bits, divisor):
    lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    values = {lo, lo + 1, -1, 0, 1, hi - 1, hi,
              divisor - 1, divisor, divisor + 1,
              -divisor - 1, -divisor, -divisor + 1}
    return sorted(v for v in values if lo <= v <= hi)

def unsigned_inputs(bits, divisor):
    hi = (1 << bits) - 1
    values = {0, 1, divisor - 1, divisor, divisor + 1,
              hi - 1, hi, 1 << (bits - 1)}
    return sorted(v for v in values if 0 <= v <= hi)

ir = ['; iyi-ir 1', 'module "division_table"',
      'target triple = "aarch64-apple-darwin"',
      'target datalayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-n32:64-S128-Fn32"',
      'declare external i32 @printf(ptr, ...)',
      '@fmt_s = private constant [9 x i8] c"%ld %ld\\0A\\00"',
      '@fmt_u = private constant [9 x i8] c"%lu %lu\\0A\\00"', '']
for bits in widths:
    for signed, divisors in ((True, signed_divisors(bits)), (False, unsigned_divisors(bits))):
        for divisor in divisors:
            fn = name(signed, bits, divisor)
            typ = f'i{bits}'
            divop, remop = ('sdiv', 'srem') if signed else ('udiv', 'urem')
            const = ir_number(divisor, bits)
            ir += [f'define internal void @{fn}({typ} %x) {{', 'entry:',
                   f'  %q = {divop} {typ} %x, {const}', f'  %r = {remop} {typ} %x, {const}']
            if bits < 64:
                ext = 'sext' if signed else 'zext'
                ir += [f'  %qw = {ext} {typ} %q to i64', f'  %rw = {ext} {typ} %r to i64']
                q, r = '%qw', '%rw'
            else:
                q, r = '%q', '%r'
            fmt = '@fmt_s' if signed else '@fmt_u'
            ir += [f'  %p = call i32 (ptr, ...) @printf(ptr {fmt}, i64 {q}, i64 {r})',
                   '  ret void', '}', '']

ir += ['define i32 @main() {', 'entry:', '  br label %signed8', 'signed8:',
       '  %sx = phi i32 [ -128, label %entry ], [ %snext, label %signed8 ]',
       '  %sv = trunc i32 %sx to i8']
for divisor in signed_divisors(8):
    ir.append(f'  call void (i8) @{name(True, 8, divisor)}(i8 %sv)')
ir += ['  %snext = add i32 %sx, 1', '  %smore = icmp slt i32 %sx, 127',
       '  br i1 %smore, label %signed8, label %unsigned8', 'unsigned8:',
       '  %ux = phi i32 [ 0, label %signed8 ], [ %unext, label %unsigned8 ]',
       '  %uv = trunc i32 %ux to i8']
for divisor in unsigned_divisors(8):
    ir.append(f'  call void (i8) @{name(False, 8, divisor)}(i8 %uv)')
ir += ['  %unext = add i32 %ux, 1', '  %umore = icmp slt i32 %ux, 255',
       '  br i1 %umore, label %unsigned8, label %wide', 'wide:']
for bits in widths[1:]:
    for signed, divisors in ((True, signed_divisors(bits)), (False, unsigned_divisors(bits))):
        for divisor in divisors:
            for value in (signed_inputs(bits, divisor) if signed else unsigned_inputs(bits, divisor)):
                ir.append(f'  call void (i{bits}) @{name(signed, bits, divisor)}(i{bits} {ir_number(value, bits)})')
ir += ['  ret i32 0', '}']
(work / 'division.ir').write_text('\n'.join(ir) + '\n', encoding='utf-8')

iyi = ['module division_table', '', 'import std/int', '',
       'def signed_row(a : Int64, divisor : Int64, minimum : Int64) : Nil',
       '  if a == minimum && divisor == -1_i64',
       '    puts "#{minimum} 0"',
       '  else',
       '    q = a // divisor',
       '    r = a - q * divisor',
       '    puts "#{q} #{r}"',
       '  end', 'end', '',
       'def unsigned_row(a : UInt64, divisor : UInt64) : Nil',
       '  q = a // divisor',
       '  r = a - q * divisor',
       '  puts "#{q} #{r}"', 'end', '',
       's = -128_i64', 'while s <= 127_i64']
for divisor in signed_divisors(8):
    iyi.append(f'  signed_row(s, {divisor}_i64, -128_i64)')
iyi += ['  s = s + 1_i64', 'end', '', 'u = 0_u64', 'while u <= 255_u64']
for divisor in unsigned_divisors(8):
    iyi.append(f'  unsigned_row(u, {divisor}_u64)')
iyi += ['  u = u + 1_u64', 'end', '']
for bits in widths[1:]:
    minimum = -(1 << (bits - 1))
    for divisor in signed_divisors(bits):
        for value in signed_inputs(bits, divisor):
            iyi.append(f'signed_row({value}_i64, {divisor}_i64, {minimum}_i64)')
    for divisor in unsigned_divisors(bits):
        for value in unsigned_inputs(bits, divisor):
            iyi.append(f'unsigned_row({value}_u64, {divisor}_u64)')
(work / 'division.iyi').write_text('\n'.join(iyi) + '\n', encoding='utf-8')
print('division table: exhaustive i8 dividends and signed/unsigned wide boundary cases')
