require "../spec_helper"

describe "Code gen: experimental" do
  it "compiles with no argument" do
    run(<<-CODE).to_i.should eq(2)
      @[Experimental]
      def foo
      end

      2
      CODE
  end

  it "compiles with single string argument" do
    run(<<-CODE).to_i.should eq(2)
      @[Experimental("lorem ipsum")]
      def foo
      end

      2
      CODE
  end

  it "errors if invalid argument type" do
    assert_error <<-CODE, "first argument must be a String"
      @[Experimental(42)]
      def foo
      end
      CODE
  end

  it "errors if too many arguments" do
    assert_error <<-CODE, "wrong number of experimental annotation arguments (given 2, expected 1)"
      @[Experimental("lorem ipsum", "extra arg")]
      def foo
      end
      CODE
  end

  it "errors if missing link arguments" do
    assert_error <<-CODE, "too many named arguments (given 1, expected maximum 0)"
      @[Experimental(invalid: "lorem ipsum")]
      def foo
      end
      CODE
  end
end
