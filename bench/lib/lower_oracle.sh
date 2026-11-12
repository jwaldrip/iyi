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
function call_types(line,   p, rest, ret, after, op, cl, args, tail, n, parts, w, types, i, head, name) {
  p = index(line, " call ")
  if (p == 0) return line
  head = substr(line, 1, p + 5)
  rest = substr(line, p + 6)
  n = split(rest, w, " ")
  ret = w[1]
  after = substr(rest, length(ret) + 2)
  if (substr(after, 1, 1) != "@") return line
  op = index(after, "(")
  cl = index(after, ")")
  if (op == 0 || cl < op) return line
  name = substr(after, 1, op - 1)
  args = substr(after, op + 1, cl - op - 1)
  tail = substr(after, cl + 1)
  if (substr(tail, 1, 2) == " #") tail = ""
  n = split(args, parts, ", ")
  types = ""
  for (i = 1; i <= n; i++) {
    split(parts[i], w, " ")
    types = types (i > 1 ? ", " : "") w[1]
  }
  return head ret " (" types ") " name "(" args ")" tail
}
# Splits the argument list of a call at its top-level commas, so a constant expression with commas
# (`getelementptr (T, ptr null, i32 1)`) stays whole.
function split_top(s, out,   i, c, depth, cur, n) {
  n = 0; depth = 0; cur = ""
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (c == "(") depth++
    else if (c == ")") depth--
    if (c == "," && depth == 0) { out[++n] = cur; cur = ""; if (substr(s, i + 1, 1) == " ") i++; continue }
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
function intrinsic_line(line,   p, lhs, rest, ret, after, op, k, cl, name, args, n, parts, m, parts2, out, i) {
  p = index(line, " call ")
  lhs = substr(line, 1, p - 1)
  rest = substr(line, p + 6)
  n = split(rest, parts, " ")
  ret = parts[1]
  after = substr(rest, length(ret) + 2)
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
{
  if ($0 ~ /^declare .*@llvm\./) next
  if (index($0, " phi ") > 0) gsub(/, %/, ", label %")
  if (index($0, "@llvm.") > 0 && index($0, " call ") > 0) { print intrinsic_line($0); next }
  if (index($0, " call ") > 0) print call_types($0); else print
}
'
