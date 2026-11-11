require "../spec_helper"
require "./spec_helper"

# iyi: S5r controls. Every bound producer is issued through a ledger, recomputed
# against a real analysed program (captured with `capture_diagnostic_provenance`),
# and refused in the ways the plan names. Expressed against the fixed interfaces:
#
#   Iyi::BindReplayAuthority.new(program, root, module_name, artifact_dir)
#   Iyi::DiagnosticProjectionLedger.new(authority)
#   ledger.open_site / render / counts                               (S1)
#   Iyi::DiagnosticBoundRecipe.open / initialiser / constant /
#     printed / insert / project_whole / strip_root / replace_alias /
#     map_foreign                                                    (S2)
#
# Not compiled or run. Assumptions to confirm when S1 and S2 land:
#   - `ClassType#class_vars` and `NamedType#macros` exist as used below;
#   - `"(Int32 | Nil)"` is how bind prints a union return;
#   - a recipe over a parsed node carries that node's origins under capture.
#
# R2 is the refusal for a program that cannot answer or a live tie that does not
# hold. R4 is the refusal for a live answer that differs from the claim. A1 is the
# render-time site tie, which runs before recompute, so a broken declaration tie
# reports A1 through the ledger, never R2.

PROBE_SOURCE = <<-CR
  module Probe
    alias Handle = Int32
    LIMIT = 5

    module Settings
      MAX = 7
    end

    class Thing
      class Inner
      end

      @@cache : Hash(String, Int32)

      macro shout
        "shout"
      end

      def take(value : String) : String
        value
      end

      def take_inner(x : Inner)
        x
      end

      def twice(x : Int32)
        x * 2
      end

      def nothing
      end

      def maybe(flag : Bool)
        flag ? 1 : nil
      end

      def clone
        self
      end

      def yields(&block)
        block.call
      end
    end

    class Store
      @@cache : Hash(String, Int32)
    end

    class Holder
      @@maybe : Int32?
    end

    class Mine
      Mine = 1
    end

    class Plain
    end

    module Shape
      abstract def area(scale : Int32) : Int32
    end

    class Square
      include Shape

      def area(scale : Int32)
        scale * 2
      end
    end

    module Pending
      abstract def pending(x : Int32)
    end

    class Maker
      def initialize(@size : Int32)
      end
    end

    class Defaults
      def initialize(@a : Int32, @b : Int32 = 0)
      end
    end
  end

  module Other
    X = 1
  end
CR

private def capture_program(source : String) : Iyi::Program
  compiler = create_spec_compiler
  compiler.no_codegen = true
  compiler.capture_diagnostic_provenance = true
  file = Iyi::Compiler::Source.new(File.expand_path("bind_replay_probe.cr"), source)
  compiler.compile(file, File.expand_path("bind-replay-probe")).program
end

private def probe_program : Iyi::Program
  capture_program(PROBE_SOURCE)
end

# A type by its `::` path from the program root.
private def named(program : Iyi::Program, path : String) : Iyi::NamedType
  segments = path.split("::")
  current = program.types[segments[0]].as(Iyi::NamedType)
  segments[1..].each { |segment| current = current.types[segment].as(Iyi::NamedType) }
  current
end

private def const_in(program : Iyi::Program, path : String, name : String) : Iyi::Const
  named(program, path).types[name].as(Iyi::Const)
end

private def def_origin(type : Iyi::NamedType, name : String) : Iyi::DiagnosticOrigin
  type.lookup_first_def(name, false).not_nil!.diagnostic_origin.not_nil!
end

private def class_var_origin(program : Iyi::Program, path : String, name : String) : Iyi::DiagnosticOrigin
  named(program, path).as(Iyi::ClassType).class_vars[name].iyi_class_var_declaration_origin
end

private def captured_node(text : String) : Iyi::ASTNode
  parser = Iyi::Parser.new(text)
  parser.diagnostic_source_file = "/spec/bind_replay_probe.cr"
  parser.diagnostic_capture = true
  parser.parse
end

private def live_ledger(program : Iyi::Program, root = "Probe", module_name = "probe",
                        artifact_dir : String? = nil) : Iyi::DiagnosticProjectionLedger
  Iyi::DiagnosticProjectionLedger.new(Iyi::BindReplayAuthority.new(program, root, module_name, artifact_dir))
end

private def recipe_at(ledger : Iyi::DiagnosticProjectionLedger, kind : String, container : String,
                      name : String? = nil, index : Int32? = nil,
                      origin : Iyi::DiagnosticOrigin? = nil,
                      parent : Iyi::DiagnosticBoundRecipe? = nil) : Iyi::DiagnosticBoundRecipe
  Iyi::DiagnosticBoundRecipe.open(ledger, "Crystal", kind, container, name, index, origin, parent)
end

# R2: the program cannot answer, or a live tie does not hold.
private def expect_r2(kind : String, &)
  expect_raises(ArgumentError, "bound projection replay refused: #{kind}") { yield }
end

# R4: a live answer differs from the claim. The exact text is SafeProjectionPlan
# §3.8, which the ledger raises when the recomputed producer is not the claim.
private def expect_r4(&)
  expect_raises(ArgumentError, "bound projection replay differs from claimed producer") { yield }
end

# A1: the render-time site tie, which precedes recompute.
private def expect_a1(kind : String, &)
  expect_raises(ArgumentError, "bound projection is not at its declaration site: #{kind}") { yield }
end

describe Iyi::BindReplayAuthority do
  describe "StripRoot: site authorisation" do
    it "issues the bind root at every site kind the plan lists as any" do
      program = probe_program
      twice = def_origin(named(program, "Probe::Thing"), "twice")
      inside = class_var_origin(program, "Probe::Thing", "cache")
      sites = [
        {"signature", "Thing", nil, nil, twice},
        {"signature_body", "Thing", nil, nil, twice},
        {"signature_annotation", "Thing", nil, 0, twice},
        {"field", "Thing", "inside", nil, nil},
        {"class_var", "Thing", "cache", nil, inside},
        {"top_fun", "", nil, nil, nil},
        {"initialiser", "", nil, nil, nil},
      ]
      sites.each do |kind, container, name, index, origin|
        ledger = live_ledger(program)
        recipe = recipe_at(ledger, kind, container, name: name, index: index, origin: origin)
        recipe.strip_root(recipe.printed(captured_node("Probe::Thing")), "Probe")
        ledger.counts["StripRoot"]?.should eq 1
      end
    end

    it "issues the bind root at a macro site" do
      program = probe_program
      shout = named(program, "Probe::Thing").as(Iyi::ClassType).macros.not_nil!["shout"].first.diagnostic_origin.not_nil!
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "macro", "Thing", origin: shout)
      recipe.strip_root(recipe.printed(captured_node("Probe::Thing")), "Probe")
      ledger.counts["StripRoot"]?.should eq 1
    end

    it "issues a constant's bind root at a constant site" do
      program = probe_program
      max = const_in(program, "Probe::Settings", "MAX")
      declaration = max.iyi_declaration_origin.not_nil!
      ledger = live_ledger(program)
      initialiser = Iyi::DiagnosticBoundRecipe.initialiser(ledger, "Crystal")
      constant = Iyi::DiagnosticBoundRecipe.constant(ledger, "Crystal", declaration, initialiser)
      constant.strip_root(constant.printed(captured_node("Probe::Settings::MAX")), "Probe")
      ledger.counts["StripRoot"]?.should eq 1
    end

    it "issues a nested declared root at a site owned by that root" do
      program = probe_program
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "field", "Thing", name: "inside")
      recipe.strip_root(recipe.printed(captured_node("Probe::Thing::Inner")), "Probe::Thing")
      ledger.counts["StripRoot"]?.should eq 1
    end

    it "refuses a nested declared root at a site owned elsewhere (authorisation)" do
      program = probe_program
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "field", "Store", name: "elsewhere")
      expect_r2("StripRoot") do
        recipe.strip_root(recipe.printed(captured_node("Probe::Thing::Inner")), "Probe::Thing")
      end
    end

    it "refuses a nested declared root at the bind root's own site (authorisation)" do
      program = probe_program
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "top_fun", "")
      expect_r2("StripRoot") do
        recipe.strip_root(recipe.printed(captured_node("Probe::Thing::Inner")), "Probe::Thing")
      end
    end

    it "refuses a nested root that is not declared" do
      program = probe_program
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "field", "Thing", name: "ghost")
      expect_r2("StripRoot") do
        recipe.strip_root(recipe.printed(captured_node("Probe::Ghost::Inner")), "Probe::Ghost")
      end
    end

    it "refuses a root that is neither the bind root nor under it" do
      program = probe_program
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "top_fun", "")
      expect_r2("StripRoot") do
        recipe.project_whole(recipe.printed(captured_node("Other::X")), Iyi::DiagnosticBoundProducer::StripRoot.new("Other"))
      end
    end

    it "refuses a source that does not begin with the root" do
      program = probe_program
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "top_fun", "")
      expect_r2("StripRoot") do
        recipe.project_whole(recipe.printed(captured_node("Thing")), Iyi::DiagnosticBoundProducer::StripRoot.new("Probe"))
      end
    end
  end

  describe "SemanticSignatureType: restrictions and legitimate unannotated returns" do
    it "issues a written parameter restriction and stores the live def origin (same?)" do
      program = probe_program
      origin = def_origin(named(program, "Probe::Thing"), "take")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Thing", origin: origin)
      recipe.insert(Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(origin, "parameter_restriction", 0, "String"))
      ledger.counts["SemanticSignatureType"]?.should eq 1
    end

    it "refuses a parameter restriction that is a different answer (R4)" do
      program = probe_program
      origin = def_origin(named(program, "Probe::Thing"), "take")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Thing", origin: origin)
      expect_r4 do
        recipe.insert(Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(origin, "parameter_restriction", 0, "Int32"))
      end
    end

    it "issues an inferred return for a def the shard left unannotated (K10)" do
      program = probe_program
      origin = def_origin(named(program, "Probe::Thing"), "twice")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Thing", origin: origin)
      recipe.insert(Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(origin, "return_type", nil, "Int32"))
      ledger.counts["SemanticSignatureType"]?.should eq 1
    end

    it "refuses an inferred return that is a different answer (R4)" do
      program = probe_program
      origin = def_origin(named(program, "Probe::Thing"), "twice")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Thing", origin: origin)
      expect_r4 do
        recipe.insert(Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(origin, "return_type", nil, "String"))
      end
    end

    it "issues a legitimate unannotated return of nil as Nil" do
      program = probe_program
      origin = def_origin(named(program, "Probe::Thing"), "nothing")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Thing", origin: origin)
      recipe.insert(Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(origin, "return_type", nil, "Nil"))
      ledger.counts["SemanticSignatureType"]?.should eq 1
    end

    it "issues a legitimate unannotated union return as bind prints it" do
      program = probe_program
      origin = def_origin(named(program, "Probe::Thing"), "maybe")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Thing", origin: origin)
      recipe.insert(Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(origin, "return_type", nil, "(Int32 | Nil)"))
      ledger.counts["SemanticSignatureType"]?.should eq 1
    end

    it "issues a legitimate unannotated self return as the owner" do
      program = probe_program
      origin = def_origin(named(program, "Probe::Thing"), "clone")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Thing", origin: origin)
      recipe.insert(Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(origin, "return_type", nil, "Probe::Thing"))
      ledger.counts["SemanticSignatureType"]?.should eq 1
    end

    it "issues a return inherited from an abstract ancestor's written type" do
      program = probe_program
      origin = def_origin(named(program, "Probe::Square"), "area")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Square", origin: origin)
      recipe.insert(Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(origin, "return_type", nil, "Int32"))
      ledger.counts["SemanticSignatureType"]?.should eq 1
    end

    it "keeps an unannotated block-yielding def valid: bind records no return for it" do
      program = probe_program
      thing = named(program, "Probe::Thing")
      yields = thing.lookup_first_def("yields", false).not_nil!
      type, refused, uncompilable = Iyi::BindSemantics.infer_return(thing, yields, "Probe", Set(String).new)
      type.should be_nil
      refused.should eq "block is not annotated"
      uncompilable.should be_false
    end

    it "keeps an unannotated abstract def valid: bind records no return for it" do
      program = probe_program
      waiting = named(program, "Probe::Pending")
      abstract_def = waiting.lookup_first_def("pending", false).not_nil!
      type, refused, uncompilable = Iyi::BindSemantics.infer_return(waiting, abstract_def, "Probe", Set(String).new)
      type.should be_nil
      refused.should eq "abstract"
      uncompilable.should be_false
    end

    it "refuses a signature site the claimed origin does not declare (A1, not R2)" do
      program = probe_program
      thing = named(program, "Probe::Thing")
      origin = def_origin(thing, "twice")
      other = def_origin(thing, "nothing")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Thing", origin: other)
      expect_a1("SemanticSignatureType") do
        recipe.insert(Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(origin, "return_type", nil, "Int32"))
      end
    end

    it "refuses a signature producer at a field site (A1, site kind)" do
      program = probe_program
      origin = def_origin(named(program, "Probe::Thing"), "twice")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "field", "Thing", name: "twice", origin: origin)
      expect_a1("SemanticSignatureType") do
        recipe.insert(Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(origin, "return_type", nil, "Int32"))
      end
    end
  end

  describe "constant accessors (K9)" do
    it "issues an accessor's return as the constant's devirtualised value type" do
      program = probe_program
      accessor = Iyi::DiagnosticOrigin::Synthetic.new(const_in(program, "Probe", "LIMIT").iyi_declaration_origin.not_nil!,
        "constant_accessor", "getter")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "", origin: accessor)
      recipe.insert(Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(accessor, "return_type", nil, "Int32"))
      ledger.counts["SemanticSignatureType"]?.should eq 1
    end

    it "issues a constant accessor at the root prefix" do
      program = probe_program
      accessor = Iyi::DiagnosticOrigin::Synthetic.new(const_in(program, "Probe", "LIMIT").iyi_declaration_origin.not_nil!,
        "constant_accessor", "getter")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "", origin: accessor)
      recipe.insert(Iyi::DiagnosticBoundProducer::ConstantAccessor.new(accessor, "", "LIMIT", "Name"))
      ledger.counts["ConstantAccessor"]?.should eq 1
    end

    it "issues a nested constant accessor with its relative namespace as prefix" do
      program = probe_program
      accessor = Iyi::DiagnosticOrigin::Synthetic.new(const_in(program, "Probe::Settings", "MAX").iyi_declaration_origin.not_nil!,
        "constant_accessor", "getter")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Settings", origin: accessor)
      recipe.insert(Iyi::DiagnosticBoundProducer::ConstantAccessor.new(accessor, "Settings_", "MAX", "Name"))
      ledger.counts["ConstantAccessor"]?.should eq 1
    end

    it "refuses an accessor whose constant name is not the live one (R4)" do
      program = probe_program
      accessor = Iyi::DiagnosticOrigin::Synthetic.new(const_in(program, "Probe", "LIMIT").iyi_declaration_origin.not_nil!,
        "constant_accessor", "getter")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "", origin: accessor)
      expect_r4 do
        recipe.insert(Iyi::DiagnosticBoundProducer::ConstantAccessor.new(accessor, "", "Limit", "Name"))
      end
    end

    it "refuses an accessor origin not built from the live constant's declaration (R2)" do
      program = probe_program
      forged = Iyi::DiagnosticOrigin::Synthetic.new(const_in(program, "Probe::Settings", "MAX").iyi_declaration_origin.not_nil!,
        "constant_accessor", "getter")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "", origin: forged)
      expect_r2("ConstantAccessor") do
        recipe.insert(Iyi::DiagnosticBoundProducer::ConstantAccessor.new(forged, "", "LIMIT", "Name"))
      end
    end
  end

  describe "UninitializedClassVar: class variable origin (C4)" do
    it "issues an uninitialised class variable at its own class_var site" do
      program = probe_program
      declaration = class_var_origin(program, "Probe::Store", "cache")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "class_var", "Store", name: "cache", origin: declaration)
      recipe.insert(Iyi::DiagnosticBoundProducer::UninitializedClassVar.new(declaration, "Probe::Store", "cache", "Hash(String, Int32)"))
      ledger.counts["UninitializedClassVar"]?.should eq 1
    end

    it "refuses a class variable whose live type is a different answer (R4)" do
      program = probe_program
      declaration = class_var_origin(program, "Probe::Store", "cache")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "class_var", "Store", name: "cache", origin: declaration)
      expect_r4 do
        recipe.insert(Iyi::DiagnosticBoundProducer::UninitializedClassVar.new(declaration, "Probe::Store", "cache", "Array(Int32)"))
      end
    end

    it "refuses a claimed declaration that is not the variable's own (C4, R2)" do
      program = probe_program
      wrong = class_var_origin(program, "Probe::Holder", "maybe")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "class_var", "Store", name: "cache", origin: wrong)
      expect_r2("UninitializedClassVar") do
        recipe.insert(Iyi::DiagnosticBoundProducer::UninitializedClassVar.new(wrong, "Probe::Store", "cache", "Hash(String, Int32)"))
      end
    end

    it "refuses a nilable class variable (no answer, R2)" do
      program = probe_program
      declaration = class_var_origin(program, "Probe::Holder", "maybe")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "class_var", "Holder", name: "maybe", origin: declaration)
      expect_r2("UninitializedClassVar") do
        recipe.insert(Iyi::DiagnosticBoundProducer::UninitializedClassVar.new(declaration, "Probe::Holder", "maybe", "Int32?"))
      end
    end

    it "refuses a site whose owner is not the claimed owner (R2, owner tie)" do
      program = probe_program
      declaration = class_var_origin(program, "Probe::Store", "cache")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "class_var", "Holder", name: "cache", origin: declaration)
      expect_r2("UninitializedClassVar") do
        recipe.insert(Iyi::DiagnosticBoundProducer::UninitializedClassVar.new(declaration, "Probe::Store", "cache", "Hash(String, Int32)"))
      end
    end

    it "refuses a site whose name is not the variable (A1)" do
      program = probe_program
      declaration = class_var_origin(program, "Probe::Store", "cache")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "class_var", "Store", name: "other", origin: declaration)
      expect_a1("UninitializedClassVar") do
        recipe.insert(Iyi::DiagnosticBoundProducer::UninitializedClassVar.new(declaration, "Probe::Store", "cache", "Hash(String, Int32)"))
      end
    end
  end

  describe "SelfReturn: bind's rule for a metaclass new" do
    it "issues a self return where the class declares a constant of its own name" do
      program = probe_program
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Mine")
      recipe.project_whole(recipe.printed(captured_node("Probe::Mine")),
        Iyi::DiagnosticBoundProducer::SelfReturn.new("Probe::Mine", "new", "self"))
      ledger.counts["SelfReturn"]?.should eq 1
    end

    it "refuses a self return for a class with no constant of its name (R2)" do
      program = probe_program
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Plain")
      expect_r2("SelfReturn") do
        recipe.project_whole(recipe.printed(captured_node("Probe::Plain")),
          Iyi::DiagnosticBoundProducer::SelfReturn.new("Probe::Plain", "new", "self"))
      end
    end

    it "refuses a self return whose method is not new (R4)" do
      program = probe_program
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Mine")
      expect_r4 do
        recipe.project_whole(recipe.printed(captured_node("Probe::Mine")),
          Iyi::DiagnosticBoundProducer::SelfReturn.new("Probe::Mine", "old", "self"))
      end
    end

    it "refuses a self return at a site the owner does not own (R2, owner tie)" do
      program = probe_program
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Plain")
      expect_r2("SelfReturn") do
        recipe.project_whole(recipe.printed(captured_node("Probe::Mine")),
          Iyi::DiagnosticBoundProducer::SelfReturn.new("Probe::Mine", "new", "self"))
      end
    end
  end

  describe "AliasType: the owner's own alias, devirtualised" do
    it "issues an alias of the owner's own name at the owner's site" do
      program = probe_program
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "")
      recipe.replace_alias(recipe.printed(captured_node("Handle")), "Probe", "Handle", "Int32")
      ledger.counts["AliasType"]?.should eq 1
    end

    it "refuses an alias whose resolved type is a different answer (R4)" do
      program = probe_program
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "")
      expect_r4 do
        recipe.replace_alias(recipe.printed(captured_node("Handle")), "Probe", "Handle", "String")
      end
    end

    it "refuses an alias at a site the owner does not own (R2, owner tie)" do
      program = probe_program
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Thing")
      expect_r2("AliasType") do
        recipe.replace_alias(recipe.printed(captured_node("Handle")), "Probe", "Handle", "Int32")
      end
    end
  end

  describe "ResolvedRestriction: nested written restriction" do
    it "issues a nested restriction resolved to its owner path" do
      program = probe_program
      restriction = named(program, "Probe::Thing").lookup_first_def("take_inner", false).not_nil!.args[0].restriction.not_nil!
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Thing")
      recipe.project_whole(recipe.printed(restriction),
        Iyi::DiagnosticBoundProducer::ResolvedRestriction.new("Probe::Thing", "Inner", "Probe::Thing::Inner", "Probe", false))
      ledger.counts["ResolvedRestriction"]?.should eq 1
    end

    it "issues the same restriction for a metaclass owner text (.class)" do
      program = probe_program
      restriction = named(program, "Probe::Thing").lookup_first_def("take_inner", false).not_nil!.args[0].restriction.not_nil!
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Thing")
      recipe.project_whole(recipe.printed(restriction),
        Iyi::DiagnosticBoundProducer::ResolvedRestriction.new("Probe::Thing.class", "Inner", "Probe::Thing::Inner", "Probe", false))
      ledger.counts["ResolvedRestriction"]?.should eq 1
    end

    it "refuses a nested restriction resolved to a different path (R4)" do
      program = probe_program
      restriction = named(program, "Probe::Thing").lookup_first_def("take_inner", false).not_nil!.args[0].restriction.not_nil!
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Thing")
      expect_r4 do
        recipe.project_whole(recipe.printed(restriction),
          Iyi::DiagnosticBoundProducer::ResolvedRestriction.new("Probe::Thing", "Inner", "Probe::Other", "Probe", false))
      end
    end

    it "refuses a restriction at a site the owner does not own (R2, owner tie)" do
      program = probe_program
      restriction = named(program, "Probe::Thing").lookup_first_def("take_inner", false).not_nil!.args[0].restriction.not_nil!
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Store")
      expect_r2("ResolvedRestriction") do
        recipe.project_whole(recipe.printed(restriction),
          Iyi::DiagnosticBoundProducer::ResolvedRestriction.new("Probe::Thing", "Inner", "Probe::Thing::Inner", "Probe", false))
      end
    end
  end

  describe "SynthesizedConstructor: metaclass new from initialize" do
    it "issues the synthesised constructor of a class with an initialize" do
      program = probe_program
      origin = def_origin(named(program, "Probe::Maker"), "initialize")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Maker", origin: origin)
      recipe.insert(Iyi::DiagnosticBoundProducer::SynthesizedConstructor.new(origin, "definition_name"))
      ledger.counts["SynthesizedConstructor"]?.should eq 1
    end

    it "issues default-argument new expansions, which share the initialize's origin" do
      program = probe_program
      origin = def_origin(named(program, "Probe::Defaults"), "initialize")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Defaults", origin: origin)
      recipe.insert(Iyi::DiagnosticBoundProducer::SynthesizedConstructor.new(origin, "definition_name"))
      ledger.counts["SynthesizedConstructor"]?.should eq 1
    end

    it "refuses an origin that no initialize carries (R2)" do
      program = probe_program
      origin = def_origin(named(program, "Probe::Thing"), "nothing")
      ledger = live_ledger(program)
      recipe = recipe_at(ledger, "signature", "Thing", origin: origin)
      expect_r2("SynthesizedConstructor") do
        recipe.insert(Iyi::DiagnosticBoundProducer::SynthesizedConstructor.new(origin, "definition_name"))
      end
    end
  end

  describe "ConstantTarget: a constant's own declaration" do
    it "issues a nested constant with its path relative to the root" do
      program = probe_program
      declaration = const_in(program, "Probe::Settings", "MAX").iyi_declaration_origin.not_nil!
      ledger = live_ledger(program)
      initialiser = Iyi::DiagnosticBoundRecipe.initialiser(ledger, "Crystal")
      constant = Iyi::DiagnosticBoundRecipe.constant(ledger, "Crystal", declaration, initialiser)
      constant.insert(Iyi::DiagnosticBoundProducer::ConstantTarget.new(declaration, "Settings::MAX"))
      ledger.counts["ConstantTarget"]?.should eq 1
    end

    it "refuses a constant path that is a different answer (R4)" do
      program = probe_program
      declaration = const_in(program, "Probe::Settings", "MAX").iyi_declaration_origin.not_nil!
      ledger = live_ledger(program)
      initialiser = Iyi::DiagnosticBoundRecipe.initialiser(ledger, "Crystal")
      constant = Iyi::DiagnosticBoundRecipe.constant(ledger, "Crystal", declaration, initialiser)
      expect_r4 do
        constant.insert(Iyi::DiagnosticBoundProducer::ConstantTarget.new(declaration, "MAX"))
      end
    end

    it "refuses a constant declared outside the root (R2)" do
      program = probe_program
      declaration = const_in(program, "Other", "X").iyi_declaration_origin.not_nil!
      ledger = live_ledger(program)
      initialiser = Iyi::DiagnosticBoundRecipe.initialiser(ledger, "Crystal")
      constant = Iyi::DiagnosticBoundRecipe.constant(ledger, "Crystal", declaration, initialiser)
      expect_r2("ConstantTarget") do
        constant.insert(Iyi::DiagnosticBoundProducer::ConstantTarget.new(declaration, "X"))
      end
    end
  end

  describe "ForeignType: artifact bindings, read once per authority" do
    it "refuses a foreign alias when no approved artifact directory names it (R2)" do
      program = probe_program
      ledger = live_ledger(program, artifact_dir: nil)
      recipe = recipe_at(ledger, "top_fun", "")
      expect_r2("ForeignType") do
        recipe.map_foreign(recipe.printed(captured_node("Thing")), "dep_mod", "Thing", "DepMod::Thing")
      end
    end

    it "issues a foreign alias that a real approved .iyimod declares" do
      dir = File.tempname("bind-replay-foreign")
      write_dep_artifact(dir)
      program = dep_probe_program
      ledger = live_ledger(program, artifact_dir: dir)
      recipe = recipe_at(ledger, "top_fun", "")
      recipe.map_foreign(recipe.printed(captured_node("Thing")), "dep_mod", "Thing", "DepMod::Thing")
      ledger.counts["ForeignType"]?.should eq 1
    end

    it "refuses a foreign alias naming another module than the artifact carries (R4)" do
      dir = File.tempname("bind-replay-foreign")
      write_dep_artifact(dir)
      program = dep_probe_program
      ledger = live_ledger(program, artifact_dir: dir)
      recipe = recipe_at(ledger, "top_fun", "")
      expect_r4 do
        recipe.map_foreign(recipe.printed(captured_node("Thing")), "other_mod", "Thing", "DepMod::Thing")
      end
    end

    it "refuses a foreign alias naming another qualified path than the artifact carries (R4)" do
      dir = File.tempname("bind-replay-foreign")
      write_dep_artifact(dir)
      program = dep_probe_program
      ledger = live_ledger(program, artifact_dir: dir)
      recipe = recipe_at(ledger, "top_fun", "")
      expect_r4 do
        recipe.map_foreign(recipe.printed(captured_node("Thing")), "dep_mod", "Thing", "DepMod::Other")
      end
    end
  end
end

# The dependency artifact the ForeignType controls read. It is written by the same
# path bind takes (capture-on bind with `emit_bind`, then `Iyi.print_bind` into the
# artifact directory), not hand-built, so the authority reads what bind writes.
private def write_dep_artifact(dir : String) : String
  Dir.mkdir_p(dir)
  compiler = create_spec_compiler
  compiler.no_codegen = true
  compiler.emit_bind = dir
  compiler.capture_diagnostic_provenance = true
  source = Iyi::Compiler::Source.new(File.expand_path("dep_mod.cr"),
    "module DepMod\n  class Thing\n  end\nend\n")
  result = compiler.compile source, File.expand_path("dep-mod-probe")
  Iyi.print_bind result.program, "DepMod", IO::Memory.new, artifact_dir: dir
  File.join(dir, "dep_mod.iyimod")
end

# The program the foreign alias is written against. DepMod::Thing is declared, and
# nothing declares a bare Thing or Probe::Thing, so bind's bare-name rule applies.
private def dep_probe_program : Iyi::Program
  capture_program(<<-CR)
    module DepMod
      class Thing
      end
    end

    module Probe
      class Holder
      end
    end
  CR
end
