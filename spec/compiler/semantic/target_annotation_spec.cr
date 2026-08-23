require "../spec_helper"

describe "Semantic: TargetFeature annotation" do
  it "errors if invalid argument provided" do
    assert_error <<-CODE, "no argument named 'invalid', expected 'cpu'"
      @[TargetFeature(invalid: "lorem ipsum")]
      def foo
      end
      CODE
  end

  it "errors if invalid cpu argument type provided" do
    assert_error <<-CODE, "expected argument 'cpu' to be String"
      @[TargetFeature(cpu: 3)]
      def foo
      end
      CODE
  end

  it "errors if invalid cpu argument type provided and feature provided" do
    assert_error <<-CODE, "expected argument 'cpu' to be String"
      @[TargetFeature("+sve", cpu: 4)]
      def foo
      end
      CODE
  end

  it "errors if invalid feature argument type provided" do
    assert_error <<-CODE, "expected argument #1 to 'TargetFeature' to be String"
      @[TargetFeature(3)]
      def foo
      end
      CODE
  end

  it "errors if invalid feature argument type provided and cpu provided" do
    assert_error <<-CODE, "expected argument #1 to 'TargetFeature' to be String"
      @[TargetFeature(3, cpu: "apple-m1")]
      def foo
      end
      CODE
  end

  it "errors if wrong number of arguments provided" do
    assert_error <<-CODE, "wrong number of arguments for TargetFeature (given 2, expected 0..1)"
      @[TargetFeature("+sve", "+sve2")]
      def foo
      end
      CODE
  end

  it "can target a specific LLVM supported feature" do
    assert_type(<<-CODE) { int32 }
      # This feature is available on all platforms
      @[TargetFeature("+strict-align")]
      def strict_align(input : Int32) : Int32
        input
      end

      strict_align(1)
      CODE
  end
end
