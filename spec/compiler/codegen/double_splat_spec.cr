require "../../spec_helper"

describe "Codegen: double splat" do
  it "double splats named argument into arguments (1)" do
    run(<<-CODE).to_i.should eq(32 - 10)
      def foo(x, y)
        x &- y
      end

      tup = {x: 32, y: 10}
      foo **tup
      CODE
  end

  it "double splats named argument into arguments (2)" do
    run(<<-CODE).to_i.should eq(32 - 10)
      def foo(x, y)
        x &- y
      end

      tup = {y: 10, x: 32}
      foo **tup
      CODE
  end

  it "double splats named argument with positional arguments" do
    run(<<-CODE).to_i.should eq(1000 - 20*30)
      def foo(x, y, z)
        x &- y &* z
      end

      tup = {y: 20, z: 30}
      foo 1000, **tup
      CODE
  end

  it "double splats named argument with named args (1)" do
    run(<<-CODE).to_i.should eq(1000 - 20*30)
      def foo(x, y, z)
        x &- y &* z
      end

      tup = {x: 1000, z: 30}
      foo **tup, y: 20
      CODE
  end

  it "double splats named argument with named args (2)" do
    run(<<-CODE).to_i.should eq(1000 - 20*30)
      def foo(x, y, z)
        x &- y &* z
      end

      tup = {z: 30}
      foo **tup, x: 1000, y: 20
      CODE
  end

  it "double splats twice " do
    run(<<-CODE).to_i.should eq((1000 - 20*30) * 40)
      def foo(x, y, z, w)
        (x &- y &* z) &* w
      end

      tup1 = {x: 1000, z: 30}
      tup2 = {y: 20, w: 40}
      foo **tup2, **tup1
      CODE
  end

  it "matches double splat on method with named args" do
    run(<<-CODE).to_i.should eq(7)
      def foo(**options)
        options[:x] &- options[:y]
      end

      foo x: 10, y: 3
      CODE
  end

  it "matches double splat on method with named args and regular args" do
    run(<<-CODE).to_i.should eq(1000 - 20*30)
      def foo(x, **args)
        x &- args[:y] &* args[:z]
      end

      foo y: 20, z: 30, x: 1000
      CODE
  end

  it "matches double splat with regular splat" do
    run(<<-CODE).to_i.should eq((1000 - 20*30) * 40)
      def foo(*args, **options)
        (args[0] &- args[1] &* options[:z]) &* options[:w]
      end

      foo 1000, 20, z: 30, w: 40
      CODE
  end

  it "evaluates double splat argument just once (#2677)" do
    run(<<-CODE).to_i.should eq(1)
      class Global
        @@x = 0

        def self.x=(@@x)
        end

        def self.x
          @@x
        end
      end

      def data
        Global.x &+= 1
        {x: Global.x, y: Global.x, z: Global.x}
      end

      def test(x, y, z)
      end

      test(**data)

      Global.x
      CODE
  end

  it "removes literal types in all matches (#6239)" do
    run(<<-CODE).to_i.should eq(2)
      def foo(y : Float64)
        y.to_i!
      end

      def bar(x : Float64, **args)
        foo(**args)
      end

      bar(x: 1, y: 2.0)
      CODE
  end
end
