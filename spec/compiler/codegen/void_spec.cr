require "../../spec_helper"

describe "Code gen: void" do
  it "codegens void assignment" do
    run(<<-CODE).to_i.should eq(1)
      fun foo : Void
      end

      a = foo
      a
      1
      CODE
  end

  it "codegens void assignment in case" do
    run(<<-CODE).to_i.should eq(1)
      require "prelude"

      fun foo : Void
      end

      def bar
        case 1
        when 1
          foo
        when 2
          raise "oh no"
        else
        end
      end

      bar
      1
      CODE
  end

  it "codegens void assignment in case with local variable" do
    run(<<-CODE).to_i.should eq(1)
      require "prelude"

      fun foo : Void
      end

      def bar
        case 1
        when 1
          a = 1
          foo
        when 2
          raise "oh no"
        else
        end
      end

      bar
      1
      CODE
  end

  it "codegens unreachable code" do
    run(<<-CODE)
      a = nil
      if a
        b = a.foo
      end
      CODE
  end

  it "codegens no return assignment" do
    codegen(<<-CODE)
      lib LibC
        fun exit : NoReturn
      end

      a = LibC.exit
      a
      CODE
  end

  it "allows passing void as argument to method" do
    codegen(<<-CODE)
      lib LibC
        fun foo
      end

      def bar(x)
      end

      def baz
        LibC.foo
      end

      bar(baz)
      CODE
  end

  it "returns void from nil functions, doesn't crash when passing value" do
    run(<<-CODE).to_i.should eq(1)
      def baz(x)
        1
      end

      struct Nil
        def bar
          baz(self)
        end
      end

      def foo
        1
        nil
      end

      foo.bar
      CODE
  end
end
