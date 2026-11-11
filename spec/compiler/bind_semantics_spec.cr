require "../spec_helper"
require "./spec_helper"

# iyi: the semantic questions `tool bind` asks of a shard, answered on a real
# analysed program. Every claim here is about what `Iyi::BindSemantics` returns
# for a restriction, a def or a name the compiler actually produced, never about
# the text of the source file.

private def semantics_program(source : String)
  compiler = create_spec_compiler
  compiler.no_codegen = true
  file = Iyi::Compiler::Source.new(File.expand_path("bind_semantics_probe.cr"), source)
  compiler.compile(file, File.expand_path("bind-semantics-probe")).program
end

private def names_set(*names : String) : Set(String)
  Set(String).new(names.to_a)
end

SEMANTICS_PROBE = <<-CR
  module Probe
    class Thing
      def take(value : String) : String
        value
      end

      def twice(x : Int32) : Int32
        x * 2
      end

      def untyped(x)
        x
      end

      def yields(&block)
        block.call
      end
    end

    module Shape
      abstract def area(scale : Int32) : Int32
    end

    class Square
      include Shape

      # The return type is written: Crystal refuses an override of a typed abstract def without one.
      def area(scale) : Int32
        scale
      end
    end
  end
  CR

describe Iyi::BindSemantics do
  program = semantics_program(SEMANTICS_PROBE)
  thing = program.types["Probe"].types["Thing"]
  square = program.types["Probe"].types["Square"]
  crystal, _private = Iyi::BindSemantics.crystal_library_types(program)

  describe ".crystal_library_types" do
    it "names the library's own types and not the shard's" do
      crystal.includes?("String").should be_true
      crystal.includes?("Array").should be_true
      crystal.includes?("Probe::Thing").should be_false
    end
  end

  describe ".global_name" do
    it "leaves a name under the root alone" do
      Iyi::BindSemantics.global_name("Probe::Thing", "Probe", names_set("String")).should eq "Probe::Thing"
    end

    it "qualifies a name whose head is a Crystal library type" do
      Iyi::BindSemantics.global_name("String", "Probe", names_set("String")).should eq "::String"
      Iyi::BindSemantics.global_name("Array::Thing", "Probe", names_set("Array")).should eq "::Array::Thing"
    end

    it "leaves a name that is not a Crystal type alone" do
      Iyi::BindSemantics.global_name("Mine", "Probe", names_set("String")).should eq "Mine"
    end

    it "leaves an already absolute name alone" do
      Iyi::BindSemantics.global_name("::String", "Probe", names_set("String")).should eq "::String"
    end
  end

  describe ".resolve_restriction_decision" do
    take = thing.lookup_first_def("take", false).not_nil!
    restriction = take.args[0].restriction.not_nil!

    it "reports the written, target, resolved and global answers for a library type" do
      written, target, resolved, add_global =
        Iyi::BindSemantics.resolve_restriction_decision(thing, restriction, true, "Probe", crystal)
      written.should eq "String"
      target.should eq "::String"
      resolved.should eq "String"
      add_global.should be_true
    end

    it "writes the bare name when the caller does not ask for qualification" do
      written, target, resolved, add_global =
        Iyi::BindSemantics.resolve_restriction_decision(thing, restriction, false, "Probe", crystal)
      written.should eq "String"
      target.should eq "String"
      resolved.should eq "String"
      add_global.should be_false
    end

    it "gives nothing for no restriction" do
      written, _, _, _ = Iyi::BindSemantics.resolve_restriction_decision(thing, nil, true, "Probe", crystal)
      written.should be_nil
    end
  end

  describe ".instantiate" do
    it "answers the return type of a method with written parameters" do
      twice = thing.lookup_first_def("twice", false).not_nil!
      call, refused, uncompilable = Iyi::BindSemantics.instantiate(thing, twice, "Probe", crystal)
      refused.should be_nil
      uncompilable.should be_false
      call.not_nil!.type?.not_nil!.to_s.should eq "Int32"
    end

    it "refuses a parameter with no restriction, and says why" do
      untyped = thing.lookup_first_def("untyped", false).not_nil!
      call, refused, uncompilable = Iyi::BindSemantics.instantiate(thing, untyped, "Probe", crystal)
      call.should be_nil
      refused.should eq "no restriction"
      uncompilable.should be_false
    end

    it "refuses a block that was never annotated, and says why" do
      yields = thing.lookup_first_def("yields", false).not_nil!
      call, refused, uncompilable = Iyi::BindSemantics.instantiate(thing, yields, "Probe", crystal)
      call.should be_nil
      refused.should eq "block is not annotated"
      uncompilable.should be_false
    end
  end

  describe ".with_ancestor_types" do
    it "copies the parameter type an abstract ancestor wrote and keeps the return type" do
      area = square.lookup_first_def("area", false).not_nil!
      copy = Iyi::BindSemantics.with_ancestor_types(square, area)
      copy.args[0].restriction.to_s.should eq "Int32"
      copy.return_type.to_s.should eq "Int32"
    end

    it "leaves the shard's own def untouched" do
      area = square.lookup_first_def("area", false).not_nil!
      Iyi::BindSemantics.with_ancestor_types(square, area)
      area.args[0].restriction.should be_nil
      area.return_type.to_s.should eq "Int32"
    end

    it "returns the same def when no ancestor answers it" do
      take = thing.lookup_first_def("take", false).not_nil!
      Iyi::BindSemantics.with_ancestor_types(thing, take).same?(take).should be_true
    end
  end

  describe ".bound_name" do
    it "is the bare name for a class root with no prefix" do
      Iyi::BindSemantics.bound_name("", "Tree").should eq "Tree"
    end

    it "qualifies the name under the module's path" do
      Iyi::BindSemantics.bound_name("Radix", "Tree").should eq "Radix::Tree"
    end
  end

  describe ".bare_bound_name?" do
    it "keeps a name the boundary alone declares" do
      Iyi::BindSemantics.bare_bound_name?("Tree", "Radix", names_set("String"), names_set("Int32")) { |_| false }.should be_true
    end

    it "refuses a name Crystal's library already owns" do
      Iyi::BindSemantics.bare_bound_name?("String", "Radix", names_set("String"), names_set("Int32")) { |_| false }.should be_false
    end

    it "refuses a builtin" do
      Iyi::BindSemantics.bare_bound_name?("Int32", "Radix", names_set("String"), names_set("Int32")) { |_| false }.should be_false
    end

    it "refuses the root itself" do
      Iyi::BindSemantics.bare_bound_name?("Radix", "Radix", names_set("String"), names_set("Int32")) { |_| false }.should be_false
    end

    it "refuses a name the shard declares under its root" do
      Iyi::BindSemantics.bare_bound_name?("Tree", "Radix", names_set("String"), names_set("Int32")) { |_| true }.should be_false
    end
  end
end
