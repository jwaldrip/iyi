require "../../spec_helper"

# iyi: `defer` — cleanup that runs however the scope is left (SPEC.md III.1.4).
#
# The expansion is the whole feature: `ensure` already runs on a normal exit, on
# a `return` through it, and on an unwind, and `!` expands to a `return`. What
# `defer` changes is the shape — the cleanup is named where the resource is
# acquired instead of wrapping everything after it.
describe "Normalize: defer" do
  it "defers past the rest of the scope" do
    assert_normalize "a\ndefer x\nb", "a\nbegin\n  b\nensure\n  x\nend", filename: "x.iyi"
  end

  it "nests a second defer inside the first, so cleanup is LIFO" do
    # `y` is the inner `ensure` and so runs first — the reverse of acquisition
    # order, the only order that can be right when a later resource was built
    # from an earlier one.
    assert_normalize "a\ndefer x\nb\ndefer y\nc",
      "a\nbegin\n  b\n  begin\n    c\n  ensure\n    y\n  end\nensure\n  x\nend",
      filename: "x.iyi"
  end

  it "scopes to the block, not the function" do
    # The departure from Go, and it is the shape of the lowering rather than an
    # extra rule: the `ensure` lands inside the loop body, so cleanup runs each
    # iteration instead of piling up until the function returns.
    assert_normalize "while a\n  defer x\n  b\nend",
      "while a\n  begin\n    b\n  ensure\n    x\n  end\nend",
      filename: "x.iyi"
  end

  it "guards a defer that has nothing after it" do
    assert_normalize "defer x", "begin\nensure\n  x\nend", filename: "x.iyi"
  end

  it "leaves a Crystal file's `defer` alone" do
    assert_normalize "a\ndefer x\nb", "a\ndefer(x)\nb"
  end
end
