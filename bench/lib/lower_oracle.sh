# Shared by the lowering gates (bench/selfhost_lower_*_exercise.sh): the oracle module
# text the port's IR parser reads. Sourced, not run.
#
# CALL_TYPES is an awk program. It writes the forms LLVM 22 leaves out and the port's
# text form requires, into a printed LLVM module: the function type of each direct call,
# from the types of its arguments (`call T @f(A, B)` becomes `call T (typeA, typeB) @f(A,
# B)`), the `label` keyword before each block of a phi's incoming pairs, and drops the
# call-site attribute group `#N`. A call through a value, or one with an argument whose
# type is more than one word, is left as LLVM printed it, and the port then refuses the
# module by name.
CALL_TYPES='
function call_types(line,   p, rest, ret, after, op, cl, args, tail, n, parts, w, types, i, head, name, at) {
  p = index(line, " call ")
  if (p == 0) return line
  head = substr(line, 1, p + 5)
  rest = substr(line, p + 6)
  at = index(rest, " @")
  if (at == 0) return line
  ret = substr(rest, 1, at - 1)
  after = substr(rest, at + 1)
  if (substr(after, 1, 1) != "@") return line
  op = name_end(after) + 1
  if (op == 1 || substr(after, op, 1) != "(") return line
  cl = close_paren(after, op)
  if (cl == 0) return line
  name = substr(after, 1, op - 1)
  args = substr(after, op + 1, cl - op - 1)
  tail = substr(after, cl + 1)
  if (substr(tail, 1, 2) == " #") tail = ""
  n = split_top(args, parts)
  types = ""
  for (i = 1; i <= n; i++) {
    split(parts[i], w, " ")
    types = types (i > 1 ? ", " : "") w[1]
  }
  if (name ~ /^@"[*~]/) ret = "iyicc " ret
  return head ret " (" types ") " name "(" args ")" tail
}
# The last character of the callee name that starts `s` (`@name` or `@"quoted name"`), or 0. A quoted
# name holds parentheses of its own (`@"*Box(Int32)^Box(T)::new<Int32>:Box(Int32)"`), which are not the call.
function name_end(s,   i) {
  if (substr(s, 2, 1) != "\"") return index(s, "(") - 1
  for (i = 3; i <= length(s); i++) if (substr(s, i, 1) == "\"") return i
  return 0
}
# The parenthesis that closes the one at `op`, outside quoted names, or 0.
function close_paren(s, op,   i, c, depth, quoted) {
  depth = 0; quoted = 0
  for (i = op; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (c == "\"") quoted = !quoted
    else if (!quoted && c == "(") depth++
    else if (!quoted && c == ")") { depth--; if (depth == 0) return i }
  }
  return 0
}
# Splits the argument list of a call at its top-level commas, so a constant expression with commas
# (`getelementptr (T, ptr null, i32 1)`) stays whole, and a quoted name (`%"Pair(Int32, Bool)"`) too.
function split_top(s, out,   i, c, depth, cur, n, quoted) {
  n = 0; depth = 0; cur = ""; quoted = 0
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (c == "\"") quoted = !quoted
    else if (!quoted && c == "(") depth++
    else if (!quoted && c == ")") depth--
    if (c == "," && depth == 0 && !quoted) { out[++n] = cur; cur = ""; if (substr(s, i + 1, 1) == " ") i++; continue }
    cur = cur c
  }
  out[++n] = cur
  return n
}
# An argument of an intrinsic call in the IR text form: its type, then its value. `align N`
# is written `align(N)` in front of the type, as the IR fixtures write it. The other parameter
# attributes LLVM prints (writeonly, nocapture, captures, noundef, immarg, ...) are dropped.
function fix_arg(a,   n, w, i, aligns, typ, rest, tok) {
  n = split(a, w, " ")
  typ = w[1]; rest = ""; aligns = ""
  for (i = 2; i <= n; i++) {
    tok = w[i]
    if (tok == "align") { aligns = "align(" w[i + 1] ") "; i++; continue }
    if (tok ~ /^(writeonly|readonly|nocapture|noundef|immarg|nonnull|noalias|nofree|readnone|captures\()/) continue
    rest = rest (rest == "" ? "" : " ") tok
  }
  return aligns typ (rest == "" ? "" : " " rest)
}
# An intrinsic call `[%r = ]call T @llvm.NAME(ARGS)` as the IR text form writes it:
# `[%r = ]intrinsic llvm.NAME(ARGS)`.
function intrinsic_line(line,   p, lhs, rest, ret, after, op, k, cl, name, args, n, parts, m, parts2, out, i, at) {
  p = index(line, " call ")
  lhs = substr(line, 1, p - 1)
  rest = substr(line, p + 6)
  at = index(rest, " @")
  ret = substr(rest, 1, at - 1)
  after = substr(rest, at + 1)
  op = index(after, "(")
  cl = 0
  for (k = length(after); k > 0; k--) if (substr(after, k, 1) == ")") { cl = k; break }
  name = substr(after, 2, op - 2)
  args = substr(after, op + 1, cl - op - 1)
  m = split_top(args, parts2)
  out = ""
  for (i = 1; i <= m; i++) out = out (i > 1 ? ", " : "") fix_arg(parts2[i])
  if (lhs ~ /=$/) return lhs " intrinsic " name "(" out ")"
  return lhs "intrinsic " name "(" out ")"
}
# A def is `Iyi` (import.iyi convention_of: a name starting with `*` or `~`). The hosted text writes every
# function `ccc`, so the defs of the oracle get the `iyicc` word of the port here, before the return type.
function cc_define(line,   at, head, n, w, i, out) {
  at = index(line, " @\"")
  head = substr(line, 1, at - 1)
  n = split(head, w, " ")
  out = ""
  for (i = 1; i < n; i++) out = out w[i] " "
  return out "iyicc " w[n] substr(line, at)
}
{
  if ($0 ~ /^define .* @"[*~]/) $0 = cc_define($0)
  if ($0 ~ /^declare .*@llvm\./) next
  if (index($0, " phi ") > 0) gsub(/, %/, ", label %")
  if (index($0, "@llvm.") > 0 && index($0, " call ") > 0) { print intrinsic_line($0); next }
  if (index($0, " call ") > 0) print call_types($0); else print
}
'
