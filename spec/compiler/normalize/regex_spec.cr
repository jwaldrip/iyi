require "../../spec_helper"

private def assert_expand_regex_const(from : String, to, *, flags = nil, file = __FILE__, line = __LINE__)
  from_nodes = Parser.parse(from)
  assert_expand(from_nodes, flags: flags, file: file, line: line) do |to_nodes, program|
    const = program.types[to_nodes.to_s].should be_a(Iyi::Const), file: file, line: line
    const.value.to_s.should eq(to.strip), file: file, line: line
  end
end

describe "Normalize: regex literal" do
  describe "StringLiteral" do
    it "expands to const" do
      assert_expand Parser.parse(%q(/foo/)) do |to_nodes, program|
        to_nodes.to_s.should eq "$Regex:0"
      end
    end

    it "simple" do
      assert_expand_regex_const %q(/foo/), <<-'CODE'
      ::Regex.new("foo", ::Regex::Options.new(0))
      CODE
    end
  end

  describe "StringInterpolation" do
    it "simple" do
      assert_expand %q(/#{"foo".to_s}/), <<-'CODE'
        ::Regex.new("#{"foo".to_s}", ::Regex::Options.new(0))
        CODE
    end
  end

  describe "options" do
    it "empty" do
      assert_expand_regex_const %q(//), <<-'CODE'
      ::Regex.new("", ::Regex::Options.new(0))
      CODE
    end
    it "i" do
      assert_expand_regex_const %q(//i), <<-'CODE'
      ::Regex.new("", ::Regex::Options.new(1))
      CODE
    end
    it "x" do
      assert_expand_regex_const %q(//x), <<-'CODE'
      ::Regex.new("", ::Regex::Options.new(8))
      CODE
    end
    it "im" do
      assert_expand_regex_const %q(//im), <<-'CODE'
      ::Regex.new("", ::Regex::Options.new(7))
      CODE
    end
    it "imx" do
      assert_expand_regex_const %q(//imx), <<-'CODE'
      ::Regex.new("", ::Regex::Options.new(15))
      CODE
    end
  end

  # iyi: a `.iyi` program has no runtime Regex, so its prelude offers none to
  # build one with, and the expander says so at the literal rather than
  # emitting `::Regex.new` into a program whose Regex is the empty class the
  # compiler pre-declares (SPEC.md III.10, Appendix B #17).
  describe "in an .iyi file" do
    it "is refused with the engine's semantics" do
      expect_raises(Iyi::TypeException, "regex literals are not available in iyi") do
        LiteralExpander.new(Program.new).expand(parse(%q(/foo/), filename: "foo.iyi"))
      end
    end
  end
end
