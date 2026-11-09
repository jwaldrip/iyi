require "../../spec_helper"

describe "Normalize: block" do
  it "derives distinct unpack assignments from the block and structural path" do
    parser = Iyi::Parser.new("foo do |(a, (b, c)), (d, e)|\n  1\nend")
    parser.filename = "/src/block.cr"
    parser.diagnostic_capture = true
    parser.diagnostic_source_file = "/src/block.cr"
    call = parser.parse.as(Iyi::Call)
    block_origin = call.block.not_nil!.diagnostic_origin.not_nil!
    program = Iyi::Program.new
    program.diagnostic_capture = true
    normalized = program.normalize(call).as(Iyi::Call)
    assignments = normalized.block.not_nil!.body.as(Iyi::Expressions).expressions.compact_map(&.as?(Iyi::MultiAssign))
    assignments.size.should eq(3)
    slots = assignments.map do |assignment|
      origin = assignment.diagnostic_origin.as(Iyi::DiagnosticOrigin::Synthetic)
      origin.parent_origin.should eq(block_origin)
      origin.valid_for_anchor?("Literal", "multiassign").should be_true
      origin.structural_slot
    end
    slots.to_set.should eq(Set{"block_unpack:0", "block_unpack:1", "block_unpack:0:1"})
  end

  it "normalizes unpacking with empty body" do
    assert_normalize <<-CODE, <<-CODE
      foo do |(x, y), z|
      end
      CODE
      foo do |__temp_1, z|
        x, y = __temp_1
      end
      CODE
  end

  it "normalizes unpacking with single expression body" do
    assert_normalize <<-CODE, <<-CODE
      foo do |(x, y), z|
        z
      end
      CODE
      foo do |__temp_1, z|
        x, y = __temp_1
        z
      end
      CODE
  end

  it "normalizes unpacking with multiple body expressions" do
    assert_normalize <<-CODE, <<-CODE
      foo do |(x, y), z|
        x
        y
        z
      end
      CODE
      foo do |__temp_1, z|
        x, y = __temp_1
        x
        y
        z
      end
      CODE
  end

  it "normalizes unpacking with underscore" do
    assert_normalize <<-CODE, <<-CODE
      foo do |(x, _), z|
      end
      CODE
      foo do |__temp_1, z|
        x, _ = __temp_1
      end
      CODE
  end

  it "normalizes nested unpacking" do
    assert_normalize <<-CODE, <<-CODE
      foo do |(a, (b, c))|
        1
      end
      CODE
      foo do |__temp_1|
        a, __temp_2 = __temp_1
        b, c = __temp_2
        1
      end
      CODE
  end

  it "normalizes multiple nested unpackings" do
    assert_normalize <<-CODE, <<-CODE
      foo do |(a, (b, (c, (d, e)), f))|
        1
      end
      CODE
      foo do |__temp_1|
        a, __temp_2 = __temp_1
        b, __temp_3, f = __temp_2
        c, __temp_4 = __temp_3
        d, e = __temp_4
        1
      end
      CODE
  end

  it "normalizes unpacking with splat" do
    assert_normalize <<-CODE, <<-CODE
      foo do |(x, *y, z)|
      end
      CODE
      foo do |__temp_1|
        x, *y, z = __temp_1
      end
      CODE
  end
end
