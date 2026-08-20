require "../../spec_helper"

describe "Semantic: type" do
  it "can call methods of original type" do
    assert_type(<<-CODE, inject_primitives: true) { uint64 }
      lib Lib
        type X = Void*
        fun foo : X
      end

      Lib.foo.address
      CODE
  end

  it "can call methods of parent type" do
    assert_error(<<-CODE, "undefined method 'baz'")
      lib Lib
        type X = Void*
        fun foo : X
      end

      Lib.foo.baz
      CODE
  end

  it "can access instance variables of original type" do
    assert_type(<<-CODE) { int32 }
      lib Lib
        struct X
          x : Int32
        end

        type Y = X
        fun foo : Y
      end

      Lib.foo.@x
      CODE
  end

  it "errors if original type doesn't support instance variables" do
    assert_error(<<-CODE, "can't use instance variables inside primitive types (at Int32)")
      lib Lib
        type X = Int32
        fun foo : X
      end

      Lib.foo.@x
      CODE
  end
end
