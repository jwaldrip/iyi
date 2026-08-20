require "../../spec_helper"

describe "Codegen: private" do
  it "codegens private def in same file" do
    compile(<<-CODE)
      private def foo
        1
      end

      foo
      CODE
  end

  it "codegens overloaded private def in same file" do
    compile(<<-CODE)
      private def foo(x : Int32)
        1
      end

      private def foo(x : Char)
        2
      end

      a = 3 || 'a'
      foo a
      CODE
  end

  it "codegens class var of private type with same name as public type (#11620)" do
    compile(<<-CODE, <<-CODE)
      module Foo
        @@x = true
      end
    CODE
      private module Foo
        @@x = 1
      end
    CODE
  end

  it "codegens class vars of private types with same name (#11620)" do
    compile(<<-CODE, <<-CODE)
      private module Foo
        @@x = true
      end
    CODE
      private module Foo
        @@x = 1
      end
    CODE
  end

  it "doesn't include filename for private types" do
    run(<<-CODE, filename: "foo").to_string.should eq("Foo")
      private class Foo
        def foo
          {{@type.stringify}}
        end
      end

      Foo.new.foo
      CODE
  end
end
