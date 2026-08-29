require "../../spec_helper"

# iyi: `defer` — cleanup that runs however the scope is left (SPEC.md III.1.4).
#
# The expansion is the whole feature, and panics gave it its final shape:
# the cleanup becomes a proc the runtime holds (`__iyi_defer_push`), the
# `ensure` pops-and-runs it on every ordinary exit, and the panic path
# walks whatever was never popped — one list, two readers. What `defer`
# changes against `begin`/`ensure` is still where the cleanup is written:
# at the acquisition.
describe "Normalize: defer" do
  it "defers past the rest of the scope, registering the cleanup" do
    assert_normalize "a\ndefer x\nb",
      "a\n" +
      "::__iyi_defer_push(-> do\n  x\n  nil\nend)\n" +
      "begin\n  b\nensure\n  ::__iyi_defer_pop_run\nend",
      filename: "x.iyi"
  end

  it "nests a second defer inside the first, so cleanup is LIFO" do
    # `y` is pushed later and popped earlier — the reverse of acquisition
    # order, the only order that can be right when a later resource was
    # built from an earlier one — and the registry being a stack means
    # the panic path agrees without coordinating.
    assert_normalize "a\ndefer x\nb\ndefer y\nc",
      "a\n" +
      "::__iyi_defer_push(-> do\n  x\n  nil\nend)\n" +
      "begin\n" +
      "  b\n" +
      "  ::__iyi_defer_push(-> do\n    y\n    nil\n  end)\n" +
      "  begin\n    c\n  ensure\n    ::__iyi_defer_pop_run\n  end\n" +
      "ensure\n" +
      "  ::__iyi_defer_pop_run\n" +
      "end",
      filename: "x.iyi"
  end

  it "scopes to the block, not the function" do
    # The departure from Go, and it is the shape of the lowering rather than an
    # extra rule: the push and its `ensure` land inside the loop body, so
    # cleanup runs each iteration instead of piling up until the function
    # returns.
    assert_normalize "while a\n  defer x\n  b\nend",
      "while a\n" +
      "  ::__iyi_defer_push(-> do\n    x\n    nil\n  end)\n" +
      "  begin\n    b\n  ensure\n    ::__iyi_defer_pop_run\n  end\n" +
      "end",
      filename: "x.iyi"
  end

  it "guards a defer that has nothing after it" do
    assert_normalize "defer x", "begin\nensure\n  x\nend", filename: "x.iyi"
  end

  it "leaves a Crystal file's `defer` alone" do
    assert_normalize "a\ndefer x\nb", "a\ndefer(x)\nb"
  end
end
