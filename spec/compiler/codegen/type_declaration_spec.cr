require "../../spec_helper"

describe "Code gen: type declaration" do
  it "codegens initialize instance var" do
    run(<<-CODE).to_i.should eq(1)
      class Foo
        @x = 1

        def x
          @x
        end
      end

      Foo.new.x
      CODE
  end

  it "codegens initialize instance var of superclass" do
    run(<<-CODE).to_i.should eq(1)
      class Foo
        @x = 1

        def x
          @x
        end
      end

      class Bar < Foo
      end

      Bar.new.x
      CODE
  end

  it "codegens initialize instance var with var declaration" do
    run(<<-CODE).to_i.should eq(1)
      class Foo
        @x : Int32 = begin
          a = 1
          a
        end

        def x
          @x
        end
      end

      Foo.new.x
      CODE
  end

  it "declares and initializes" do
    run(<<-CODE).to_i.should eq(42)
      class Foo
        @x : Int32 = 42

        def x
          @x
        end
      end

      Foo.new.x
      CODE
  end

  it "declares and initializes var" do
    run(<<-CODE).to_i.should eq(42)
      a : Int32 = 42
      a
      CODE
  end
end
