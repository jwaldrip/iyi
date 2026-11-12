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
{
  if (index($0, " phi ") > 0) gsub(/, %/, ", label %")
  if (index($0, " call ") > 0) print call_types($0); else print
}
'
