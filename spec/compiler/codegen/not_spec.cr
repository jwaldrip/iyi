require "../../spec_helper"

describe "Code gen: not" do
  it "codegens not number" do
    run("!1").to_b.should be_false
  end

  it "codegens not true" do
    run("!true").to_b.should be_false
  end

  it "codegens not false" do
    run("!false").to_b.should be_true
  end

  it "codegens not nil" do
    run("!nil").to_b.should be_true
  end

  it "codegens not nilable type (true)" do
    run(<<-CODE).to_b.should be_true
      class Foo
      end

      a = 1 == 2 ? Foo.new : nil
      !a
      CODE
  end

  it "codegens not nilable type (false)" do
    run(<<-CODE).to_b.should be_false
      class Foo
      end

      a = 1 == 1 ? Foo.new : nil
      !a
      CODE
  end

  it "codegens not pointer (true)" do
    run(<<-CODE).to_b.should be_true
      !Pointer(Int32).new(0_u64)
      CODE
  end

  it "codegens not pointer (false)" do
    run(<<-CODE).to_b.should be_false
      !Pointer(Int32).new(1_u64)
      CODE
  end

  it "doesn't crash" do
    run(<<-CODE).to_b.should be_false
      a = 1
      !a.is_a?(String) && !a
      CODE
  end

  it "codegens not with inlinable value (#6451)" do
    codegen(<<-CODE)
      class Test
        def test
          false
        end
      end

      !Test.new.test
      nil
      CODE
  end
end
