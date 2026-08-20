require "../../../spec_helper"
include Iyi

private def parse_flags(source)
  Iyi::Command::FlagsVisitor.new.tap do |visitor|
    Parser.parse(source).accept(visitor)
  end
end

describe Iyi::Command::FlagsVisitor do
  it "different flags" do
    visitor = parse_flags <<-CODE
      {%
        flag?(:foo)
        flag?("bar")
        flag?(1)
        flag?(true)
      %}
      CODE
    visitor.flag_names.should eq %w[1 bar foo true]
  end

  it "unique flags" do
    visitor = parse_flags <<-CODE
      {%
        flag?(:foo)
        flag?("foo")
        flag?(:foo)
      %}
      CODE
    visitor.flag_names.should eq %w[foo]
  end

  it "only macro" do
    visitor = parse_flags <<-CODE
      flag?(:flag)
      f.flag?(:foo)
      F.flag?(:bar)
      {% f.flag?(:baz) %}
      {% f.flag?(:qux, other: true) %}
      CODE
    visitor.flag_names.should eq %w[]
  end
end
