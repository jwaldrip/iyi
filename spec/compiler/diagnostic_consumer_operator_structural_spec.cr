require "../support/syntax"
require "../../src/compiler/iyi/codegen/diagnostic_provenance"

# Executes the codegen consumer's OperatorName and StructuralName validators on serialized JSON.
# The spec reopens Iyi::DiagnosticProvenance to reach the private derived_name_schema4! from inside the
# module, so production code gains no entry point. Acceptance returns {name context, rendered name};
# refusal raises with its exact message.

DCN_DIGEST      = "0" * 64
DCN_OTHER_GUARD = "sha256:" + ("1" * 64)

def dcn_written(offset : Int32, kind : String, role : String) : String
  %({"kind":"Written","source_identity":{"module":"sample","file":"sample.cr"},"input_byte_offset":#{offset},"anchor_kind":"#{kind}","role":"#{role}"})
end

def dcn_expanded(event : String, kind : String, role : String, guard : String = "sha256:#{DCN_DIGEST}") : String
  invocation = dcn_written(0, "Call", "method")
  macro_origin = dcn_written(0, "Macro", "keyword")
  %({"kind":"Expanded","invocation_origin":#{invocation},"macro_definition_origin":#{macro_origin},"expansion_guard":"#{guard}","anchor_kind":"#{kind}","role":"#{role}","name_context":null,"token_event":#{event},"anchor_use":{"kind":"Direct"}})
end

def dcn_part(start : Int32, finish : Int32, producer : String = "MacroTemplate") : String
  %({"kind":"Generated","start_offset":#{start},"end_offset":#{finish},"emitter_origin":null,"producer":"#{producer}"})
end

def dcn_event(start : Int32, raw : String, kind : String, parts : Array(String),
              selection : String = "Whole", mode : String = "Crystal") : String
  finish = start + raw.bytesize
  %({"input_start":#{start},"input_end":#{finish},"token_kind":"#{kind}","token_text":"#{raw}","lexical_mode":"#{mode}","selection":"#{selection}","byte_parts":[#{parts.join(",")}]})
end

def dcn_whole(start : Int32, raw : String, kind : String, producer : String = "MacroTemplate") : String
  dcn_event(start, raw, kind, [dcn_part(start, start + raw.bytesize, producer)])
end

def dcn_witness(start : Int32, raw : String, kind : String, selection : String = "Whole", event : String? = nil) : String
  finish = start + raw.bytesize
  event_json = event || "null"
  %({"input_start":#{start},"input_end":#{finish},"token_kind":"#{kind}","raw_text":"#{raw}","selection":"#{selection}","event":#{event_json}})
end

def dcn_operator_json(production : String, source : String, anchor : String, witnesses : Array(String),
                      rendered : String, context : String, mode : String = "Crystal") : String
  list = witnesses.join(",")
  %({"kind":"DerivedName","derivation_kind":"OperatorName","production":"#{production}","anchor_origin":#{anchor},"input_sha256":"#{DCN_DIGEST}","input_bytesize":#{source.bytesize},"lexical_mode":"#{mode}","witnesses":[#{list}],"rendered_text":"#{rendered}","producer_context":"#{context}"})
end

def dcn_structural_json(production : String, source : String, anchor : String, witnesses : Array(String),
                        fresh : String, rendered : String, context : String, mode : String = "Crystal") : String
  list = witnesses.join(",")
  %({"kind":"DerivedName","derivation_kind":"StructuralName","production":"#{production}","anchor_origin":#{anchor},"input_sha256":"#{DCN_DIGEST}","input_bytesize":#{source.bytesize},"lexical_mode":"#{mode}","witnesses":[#{list}],"fresh_index":#{fresh},"rendered_text":"#{rendered}","producer_context":"#{context}"})
end

module Iyi::DiagnosticProvenance
  # Spec-only bridge: runs the private validator from within the module. Defined here, not in production.
  def self.dcn_derived_name(value : JSON::Any) : Tuple(String, String)
    derived_name_schema4!(value, 0)
  end
end

def dcn_validate(json : String) : Tuple(String, String)
  Iyi::DiagnosticProvenance.dcn_derived_name(JSON.parse(json))
end

describe "Iyi::DiagnosticProvenance derived name consumer" do
  describe "OperatorName accepts representative derivations" do
    it "renders OpAssign from a written anchor" do
      dcn_validate(dcn_operator_json("OpAssign", "x += 1", dcn_written(2, "Call", "method"),
        [dcn_witness(2, "+=", "+=")], "+", "op_assign_operator")).should eq({"op_assign_operator", "+"})
    end

    it "renders SignedNumber from an expanded anchor whose event covers only the sign" do
      anchor = dcn_expanded(dcn_event(4, "-1", "NUMBER", [dcn_part(4, 5)], "SignedNumberSign"), "Call", "method")
      dcn_validate(dcn_operator_json("SignedNumber", "x = -1", anchor,
        [dcn_witness(4, "-1", "NUMBER", "SignedNumberSign")], "-", "method_name")).should eq({"method_name", "-"})
    end

    it "renders a written positive SignedNumber" do
      dcn_validate(dcn_operator_json("SignedNumber", "x = +7", dcn_written(4, "Call", "method"),
        [dcn_witness(4, "+7", "NUMBER", "SignedNumberSign")], "+", "method_name")).should eq({"method_name", "+"})
    end

    it "renders Index from a written anchor" do
      dcn_validate(dcn_operator_json("Index", "a[1]", dcn_written(1, "Call", "method"),
        [dcn_witness(1, "[", "["), dcn_witness(3, "]", "]")], "[]", "method_name")).should eq({"method_name", "[]"})
    end

    it "renders IndexQuery when ]? is adjacent" do
      dcn_validate(dcn_operator_json("IndexQuery", "a[1]?", dcn_written(1, "Call", "method"),
        [dcn_witness(1, "[", "["), dcn_witness(3, "]", "]"), dcn_witness(4, "?", "?")], "[]?", "method_name"))
        .should eq({"method_name", "[]?"})
    end

    it "accepts IndexQuery with mixed producers across later witnesses" do
      anchor = dcn_expanded(dcn_whole(1, "[", "["), "Call", "method")
      witnesses = [
        dcn_witness(1, "[", "["),
        dcn_witness(3, "]", "]", "Whole", dcn_whole(3, "]", "]", "MacroTemplate")),
        dcn_witness(4, "?", "?", "Whole", dcn_whole(4, "?", "?", "MacroVar")),
      ]
      dcn_validate(dcn_operator_json("IndexQuery", "a[1]?", anchor, witnesses, "[]?", "method_name"))
        .should eq({"method_name", "[]?"})
    end

    it "renders IndexAssign with spaced equals" do
      dcn_validate(dcn_operator_json("IndexAssign", "a[1] = 2", dcn_written(1, "Call", "method"),
        [dcn_witness(1, "[", "["), dcn_witness(3, "]", "]"), dcn_witness(5, "=", "=")], "[]=", "method_name"))
        .should eq({"method_name", "[]="})
    end

    it "renders IndexAssign from the combined [] token form" do
      dcn_validate(dcn_operator_json("IndexAssign", "a[] = 2", dcn_written(1, "Call", "method"),
        [dcn_witness(1, "[]", "[]"), dcn_witness(4, "=", "=")], "[]=", "method_name")).should eq({"method_name", "[]="})
    end

    it "renders a Setter with an IDENT name" do
      dcn_validate(dcn_operator_json("Setter", "f.x = 1", dcn_written(2, "Call", "method"),
        [dcn_witness(2, "x", "IDENT"), dcn_witness(4, "=", "=")], "x=", "method_name")).should eq({"method_name", "x="})
    end

    it "renders a Setter with a CONST name" do
      dcn_validate(dcn_operator_json("Setter", "f.Foo = 1", dcn_written(2, "Call", "method"),
        [dcn_witness(2, "Foo", "CONST"), dcn_witness(6, "=", "=")], "Foo=", "method_name")).should eq({"method_name", "Foo="})
    end

    it "renders a Command from its opener" do
      dcn_validate(dcn_operator_json("Command", "x = `ls`", dcn_written(4, "Call", "method"),
        [dcn_witness(4, "`", "DELIMITER_START")], "`", "method_name")).should eq({"method_name", "`"})
    end
  end

  describe "OperatorName refuses adversarial derivations with exact messages" do
    it "refuses a spaced IndexQuery suffix from a written anchor" do
      expect_raises(Exception, "invalid operator witness") do
        dcn_validate(dcn_operator_json("IndexQuery", "a[1] ?", dcn_written(1, "Call", "method"),
          [dcn_witness(1, "[", "["), dcn_witness(3, "]", "]"), dcn_witness(5, "?", "?")], "[]?", "method_name"))
      end
    end

    it "refuses a spaced IndexQuery suffix from an expanded anchor" do
      anchor = dcn_expanded(dcn_whole(1, "[", "["), "Call", "method")
      expect_raises(Exception, "invalid operator witness") do
        dcn_validate(dcn_operator_json("IndexQuery", "a[1] ?", anchor,
          [dcn_witness(1, "[", "["), dcn_witness(3, "]", "]"), dcn_witness(5, "?", "?")], "[]?", "method_name"))
      end
    end

    it "refuses IndexQuery without its suffix" do
      expect_raises(Exception, "invalid operator witness") do
        dcn_validate(dcn_operator_json("IndexQuery", "a[1]", dcn_written(1, "Call", "method"),
          [dcn_witness(1, "[", "["), dcn_witness(3, "]", "]")], "[]?", "method_name"))
      end
    end

    it "refuses an unknown production" do
      expect_raises(Exception, "unknown operator production") do
        dcn_validate(dcn_operator_json("Splat", "a[1]", dcn_written(1, "Call", "method"),
          [dcn_witness(1, "[", "["), dcn_witness(3, "]", "]")], "[]", "method_name"))
      end
    end

    it "refuses a forged rendering" do
      expect_raises(Exception, "derived operator rendering differs") do
        dcn_validate(dcn_operator_json("IndexQuery", "a[1]?", dcn_written(1, "Call", "method"),
          [dcn_witness(1, "[", "["), dcn_witness(3, "]", "]"), dcn_witness(4, "?", "?")], "[]", "method_name"))
      end
    end

    it "refuses a forged context" do
      expect_raises(Exception, "derived operator context differs") do
        dcn_validate(dcn_operator_json("OpAssign", "x += 1", dcn_written(2, "Call", "method"),
          [dcn_witness(2, "+=", "+=")], "+", "method_name"))
      end
    end

    it "refuses a witness whose span disagrees with its text" do
      bad = %({"input_start":1,"input_end":3,"token_kind":"[","raw_text":"[","selection":"Whole","event":null})
      expect_raises(Exception, "invalid operator witness span") do
        dcn_validate(dcn_operator_json("IndexQuery", "a[1]?", dcn_written(1, "Call", "method"),
          [bad, dcn_witness(3, "]", "]"), dcn_witness(4, "?", "?")], "[]?", "method_name"))
      end
    end

    it "refuses overlapping witnesses" do
      expect_raises(Exception, "invalid operator witness order") do
        dcn_validate(dcn_operator_json("IndexQuery", "a[1]?", dcn_written(1, "Call", "method"),
          [dcn_witness(1, "[", "["), dcn_witness(1, "]", "]"), dcn_witness(4, "?", "?")], "[]?", "method_name"))
      end
    end

    it "refuses an unknown witness token kind" do
      expect_raises(Exception, "invalid token classification") do
        dcn_validate(dcn_operator_json("Index", "a[1]", dcn_written(1, "Call", "method"),
          [dcn_witness(1, "[", "NOT_A_KIND"), dcn_witness(3, "]", "]")], "[]", "method_name"))
      end
    end

    it "refuses a written anchor whose offset is not the first witness" do
      expect_raises(Exception, "operator anchor offset mismatch") do
        dcn_validate(dcn_operator_json("OpAssign", "x += 1", dcn_written(3, "Call", "method"),
          [dcn_witness(2, "+=", "+=")], "+", "op_assign_operator"))
      end
    end

    it "refuses an expanded anchor whose guard names other input" do
      anchor = dcn_expanded(dcn_whole(2, "+=", "+="), "Call", "method", DCN_OTHER_GUARD)
      expect_raises(Exception, "operator witnesses use different inputs") do
        dcn_validate(dcn_operator_json("OpAssign", "x += 1", anchor, [dcn_witness(2, "+=", "+=")], "+", "op_assign_operator"))
      end
    end

    it "refuses an expanded anchor token that is not witness 0" do
      anchor = dcn_expanded(dcn_whole(3, "+=", "+="), "Call", "method")
      expect_raises(Exception, "operator anchor token differs from witness 0") do
        dcn_validate(dcn_operator_json("OpAssign", "x += 1", anchor, [dcn_witness(2, "+=", "+=")], "+", "op_assign_operator"))
      end
    end

    it "refuses an event on the anchor witness" do
      anchor = dcn_expanded(dcn_whole(2, "+=", "+="), "Call", "method")
      witness = dcn_witness(2, "+=", "+=", "Whole", dcn_whole(2, "+=", "+="))
      expect_raises(Exception, "invalid operator witness provenance") do
        dcn_validate(dcn_operator_json("OpAssign", "x += 1", anchor, [witness], "+", "op_assign_operator"))
      end
    end

    it "refuses a later event whose token text disagrees with its witness" do
      anchor = dcn_expanded(dcn_whole(1, "[", "["), "Call", "method")
      bad_event = dcn_event(3, "x", "]", [dcn_part(3, 4)])
      expect_raises(Exception, "invalid operator witness provenance") do
        dcn_validate(dcn_operator_json("IndexQuery", "a[1]?", anchor,
          [dcn_witness(1, "[", "["), dcn_witness(3, "]", "]", "Whole", bad_event), dcn_witness(4, "?", "?", "Whole", dcn_whole(4, "?", "?"))],
          "[]?", "method_name"))
      end
    end

    it "refuses a later event that leaves a byte unattributed" do
      anchor = dcn_expanded(dcn_whole(1, "[", "["), "Call", "method")
      gap_event = dcn_event(3, "]", "]", [dcn_part(4, 5)])
      expect_raises(Exception, "witness bytes not attributed by macro emission") do
        dcn_validate(dcn_operator_json("IndexQuery", "a[1]?", anchor,
          [dcn_witness(1, "[", "["), dcn_witness(3, "]", "]", "Whole", gap_event), dcn_witness(4, "?", "?", "Whole", dcn_whole(4, "?", "?"))],
          "[]?", "method_name"))
      end
    end

    it "refuses an unknown macro producer on a later event" do
      anchor = dcn_expanded(dcn_whole(1, "[", "["), "Call", "method")
      bad_producer = dcn_event(3, "]", "]", [dcn_part(3, 4, "Mystery")])
      expect_raises(Exception, "invalid operator witness provenance") do
        dcn_validate(dcn_operator_json("IndexQuery", "a[1]?", anchor,
          [dcn_witness(1, "[", "["), dcn_witness(3, "]", "]", "Whole", bad_producer), dcn_witness(4, "?", "?", "Whole", dcn_whole(4, "?", "?"))],
          "[]?", "method_name"))
      end
    end

    it "refuses NameSplice on punctuation" do
      anchor = dcn_expanded(dcn_whole(1, "[", "["), "Call", "method")
      splice = %({"kind":"NameSplice","start_offset":3,"end_offset":4,"emitter_origin":null,"source_name":null})
      bad_event = dcn_event(3, "]", "]", [splice])
      expect_raises(Exception, "invalid operator witness provenance") do
        dcn_validate(dcn_operator_json("IndexQuery", "a[1]?", anchor,
          [dcn_witness(1, "[", "["), dcn_witness(3, "]", "]", "Whole", bad_event), dcn_witness(4, "?", "?", "Whole", dcn_whole(4, "?", "?"))],
          "[]?", "method_name"))
      end
    end

    it "refuses a later event with no parts" do
      anchor = dcn_expanded(dcn_whole(1, "[", "["), "Call", "method")
      empty_event = dcn_event(3, "]", "]", [] of String)
      expect_raises(Exception, "invalid operator witness provenance") do
        dcn_validate(dcn_operator_json("IndexQuery", "a[1]?", anchor,
          [dcn_witness(1, "[", "["), dcn_witness(3, "]", "]", "Whole", empty_event), dcn_witness(4, "?", "?", "Whole", dcn_whole(4, "?", "?"))],
          "[]?", "method_name"))
      end
    end

    it "refuses a later event written in another lexical mode" do
      anchor = dcn_expanded(dcn_whole(1, "[", "["), "Call", "method")
      iyi_event = dcn_event(3, "]", "]", [dcn_part(3, 4)], "Whole", "Iyi")
      expect_raises(Exception, "operator witnesses use different inputs") do
        dcn_validate(dcn_operator_json("IndexQuery", "a[1]?", anchor,
          [dcn_witness(1, "[", "["), dcn_witness(3, "]", "]", "Whole", iyi_event), dcn_witness(4, "?", "?", "Whole", dcn_whole(4, "?", "?"))],
          "[]?", "method_name"))
      end
    end
  end

  describe "StructuralName accepts representative derivations" do
    it "renders a written UnnamedFunParameter head" do
      dcn_validate(dcn_structural_json("UnnamedFunParameter", "fun f(Int32) : Void", dcn_written(0, "FunDef", "keyword"),
        [dcn_witness(5, "(", "("), dcn_witness(6, "Int32", "CONST")], "null", "", "parameter"))
        .should eq({"parameter", ""})
    end

    it "renders a later written UnnamedFunParameter after a comma" do
      dcn_validate(dcn_structural_json("UnnamedFunParameter", "fun f(Int32, Void*) : Void", dcn_written(0, "FunDef", "keyword"),
        [dcn_witness(11, ",", ","), dcn_witness(13, "Void", "CONST")], "null", "", "parameter"))
        .should eq({"parameter", ""})
    end

    it "renders a written ShortBlockArgument at fresh index zero" do
      dcn_validate(dcn_structural_json("ShortBlockArgument", "list.map &.to_s", dcn_written(9, "Block", "ampersand"),
        [dcn_witness(9, "&", "&"), dcn_witness(10, ".", ".")], "0", "__arg0", "local_reference"))
        .should eq({"local_reference", "__arg0"})
    end

    it "renders a written ShortBlockArgument at a later fresh index" do
      dcn_validate(dcn_structural_json("ShortBlockArgument", "list.map &.to_s", dcn_written(9, "Block", "ampersand"),
        [dcn_witness(9, "&", "&"), dcn_witness(10, ".", ".")], "7", "__arg7", "local_reference"))
        .should eq({"local_reference", "__arg7"})
    end

    it "accepts an expanded UnnamedFunParameter with mixed producers across its two witnesses" do
      anchor = dcn_expanded(dcn_whole(0, "fun", "IDENT"), "FunDef", "keyword")
      witnesses = [
        dcn_witness(5, "(", "(", "Whole", dcn_whole(5, "(", "(", "MacroTemplate")),
        dcn_witness(6, "Int32", "CONST", "Whole", dcn_whole(6, "Int32", "CONST", "MacroVar")),
      ]
      dcn_validate(dcn_structural_json("UnnamedFunParameter", "fun g(Int32) : Void", anchor, witnesses, "null", "", "parameter"))
        .should eq({"parameter", ""})
    end

    it "accepts an expanded ShortBlockArgument with a mixed later witness" do
      anchor = dcn_expanded(dcn_whole(9, "&", "&"), "Block", "ampersand")
      witnesses = [
        dcn_witness(9, "&", "&"),
        dcn_witness(10, ".", ".", "Whole", dcn_whole(10, ".", ".", "MacroVar")),
      ]
      dcn_validate(dcn_structural_json("ShortBlockArgument", "list.map &.to_s", anchor, witnesses, "2", "__arg2", "local_reference"))
        .should eq({"local_reference", "__arg2"})
    end

    it "renders a written BareSplatParameter before a keyword name" do
      dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*, y)", dcn_written(0, "Def", "keyword"),
        [dcn_witness(6, "*", "*"), dcn_witness(7, ",", ",")], "null", "", "parameter"))
        .should eq({"parameter", ""})
    end

    it "renders a written BareSplatParameter after a positional parameter" do
      dcn_validate(dcn_structural_json("BareSplatParameter", "def f(x, *, y)", dcn_written(0, "Def", "keyword"),
        [dcn_witness(9, "*", "*"), dcn_witness(10, ",", ",")], "null", "", "parameter"))
        .should eq({"parameter", ""})
    end

    it "renders a written MacroBareSplatParameter" do
      dcn_validate(dcn_structural_json("MacroBareSplatParameter", "macro f(*, y)", dcn_written(0, "Macro", "keyword"),
        [dcn_witness(8, "*", "*"), dcn_witness(9, ",", ",")], "null", "", "parameter"))
        .should eq({"parameter", ""})
    end

    it "accepts an expanded BareSplatParameter whose witnesses carry their own events from mixed producers" do
      anchor = dcn_expanded(dcn_whole(0, "def", "IDENT"), "Def", "keyword")
      witnesses = [
        dcn_witness(6, "*", "*", "Whole", dcn_whole(6, "*", "*", "MacroTemplate")),
        dcn_witness(7, ",", ",", "Whole", dcn_whole(7, ",", ",", "MacroVar")),
      ]
      dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*, y)", anchor, witnesses, "null", "", "parameter"))
        .should eq({"parameter", ""})
    end

    it "accepts an expanded MacroBareSplatParameter" do
      anchor = dcn_expanded(dcn_whole(0, "macro", "IDENT"), "Macro", "keyword")
      witnesses = [
        dcn_witness(8, "*", "*", "Whole", dcn_whole(8, "*", "*")),
        dcn_witness(9, ",", ",", "Whole", dcn_whole(9, ",", ",")),
      ]
      dcn_validate(dcn_structural_json("MacroBareSplatParameter", "macro f(*, y)", anchor, witnesses, "null", "", "parameter"))
        .should eq({"parameter", ""})
    end
  end

  describe "StructuralName refuses adversarial derivations with exact messages" do
    it "refuses a fresh index on UnnamedFunParameter" do
      expect_raises(Exception, "structural witness differs") do
        dcn_validate(dcn_structural_json("UnnamedFunParameter", "fun f(Int32) : Void", dcn_written(0, "FunDef", "keyword"),
          [dcn_witness(5, "(", "("), dcn_witness(6, "Int32", "CONST")], "3", "", "parameter"))
      end
    end

    it "refuses a separator that is not ( or ," do
      expect_raises(Exception, "structural witness differs") do
        dcn_validate(dcn_structural_json("UnnamedFunParameter", "fun f(Int32) : Void", dcn_written(0, "FunDef", "keyword"),
          [dcn_witness(5, "[", "["), dcn_witness(6, "Int32", "CONST")], "null", "", "parameter"))
      end
    end

    it "refuses an IDENT head as the unnamed type" do
      expect_raises(Exception, "unnamed parameter head is not the first type token") do
        dcn_validate(dcn_structural_json("UnnamedFunParameter", "fun f(int32) : Void", dcn_written(0, "FunDef", "keyword"),
          [dcn_witness(5, "(", "("), dcn_witness(6, "int32", "IDENT")], "null", "", "parameter"))
      end
    end

    it "refuses a ... head" do
      expect_raises(Exception, "unnamed parameter head is not the first type token") do
        dcn_validate(dcn_structural_json("UnnamedFunParameter", "fun f(...) : Void", dcn_written(0, "FunDef", "keyword"),
          [dcn_witness(5, "(", "("), dcn_witness(6, "...", "...")], "null", "", "parameter"))
      end
    end

    it "refuses a null fresh index on ShortBlockArgument" do
      expect_raises(Exception, "invalid short block fresh index") do
        dcn_validate(dcn_structural_json("ShortBlockArgument", "list.map &.to_s", dcn_written(9, "Block", "ampersand"),
          [dcn_witness(9, "&", "&"), dcn_witness(10, ".", ".")], "null", "__arg0", "local_reference"))
      end
    end

    it "refuses a negative fresh index on ShortBlockArgument" do
      expect_raises(Exception, "invalid short block fresh index") do
        dcn_validate(dcn_structural_json("ShortBlockArgument", "list.map &.to_s", dcn_written(9, "Block", "ampersand"),
          [dcn_witness(9, "&", "&"), dcn_witness(10, ".", ".")], "-1", "__arg0", "local_reference"))
      end
    end

    it "refuses ShortBlockArgument witnesses that are not & then ." do
      expect_raises(Exception, "structural witness differs") do
        dcn_validate(dcn_structural_json("ShortBlockArgument", "list.map &.to_s", dcn_written(9, "Block", "ampersand"),
          [dcn_witness(9, "&", "&"), dcn_witness(10, "*", "*")], "0", "__arg0", "local_reference"))
      end
    end

    it "refuses a written unnamed anchor that does not precede the witnesses" do
      expect_raises(Exception, "anchor does not precede witnesses") do
        dcn_validate(dcn_structural_json("UnnamedFunParameter", "fun f(Int32) : Void", dcn_written(6, "FunDef", "keyword"),
          [dcn_witness(5, "(", "("), dcn_witness(6, "Int32", "CONST")], "null", "", "parameter"))
      end
    end

    it "refuses a written ShortBlockArgument anchor at the wrong offset" do
      expect_raises(Exception, "structural anchor offset mismatch") do
        dcn_validate(dcn_structural_json("ShortBlockArgument", "list.map &.to_s", dcn_written(8, "Block", "ampersand"),
          [dcn_witness(9, "&", "&"), dcn_witness(10, ".", ".")], "0", "__arg0", "local_reference"))
      end
    end

    it "refuses an UnnamedFunParameter anchored on a Call" do
      expect_raises(Exception, "invalid structural anchor") do
        dcn_validate(dcn_structural_json("UnnamedFunParameter", "fun f(Int32) : Void", dcn_written(0, "Call", "method"),
          [dcn_witness(5, "(", "("), dcn_witness(6, "Int32", "CONST")], "null", "", "parameter"))
      end
    end

    it "refuses overlapping ShortBlockArgument witnesses" do
      expect_raises(Exception, "structural witnesses overlap or are out of order") do
        dcn_validate(dcn_structural_json("ShortBlockArgument", "list.map &.to_s", dcn_written(9, "Block", "ampersand"),
          [dcn_witness(9, "&", "&"), dcn_witness(9, ".", ".")], "0", "__arg0", "local_reference"))
      end
    end

    it "refuses an expanded unnamed anchor token that is not fun" do
      anchor = dcn_expanded(dcn_whole(0, "def", "IDENT"), "FunDef", "keyword")
      witnesses = [
        dcn_witness(5, "(", "(", "Whole", dcn_whole(5, "(", "(")),
        dcn_witness(6, "Int32", "CONST", "Whole", dcn_whole(6, "Int32", "CONST")),
      ]
      expect_raises(Exception, "invalid structural anchor") do
        dcn_validate(dcn_structural_json("UnnamedFunParameter", "fun g(Int32) : Void", anchor, witnesses, "null", "", "parameter"))
      end
    end

    it "refuses an expanded unnamed anchor that reaches the first witness" do
      anchor = dcn_expanded(dcn_whole(0, "fun", "IDENT"), "FunDef", "keyword")
      witnesses = [
        dcn_witness(2, "(", "(", "Whole", dcn_whole(2, "(", "(")),
        dcn_witness(6, "Int32", "CONST", "Whole", dcn_whole(6, "Int32", "CONST")),
      ]
      expect_raises(Exception, "anchor does not precede witnesses") do
        dcn_validate(dcn_structural_json("UnnamedFunParameter", "fun g(Int32) : Void", anchor, witnesses, "null", "", "parameter"))
      end
    end

    it "refuses an expanded unnamed anchor whose guard names other input" do
      anchor = dcn_expanded(dcn_whole(0, "fun", "IDENT"), "FunDef", "keyword", DCN_OTHER_GUARD)
      witnesses = [
        dcn_witness(5, "(", "(", "Whole", dcn_whole(5, "(", "(")),
        dcn_witness(6, "Int32", "CONST", "Whole", dcn_whole(6, "Int32", "CONST")),
      ]
      expect_raises(Exception, "structural witnesses use different inputs") do
        dcn_validate(dcn_structural_json("UnnamedFunParameter", "fun g(Int32) : Void", anchor, witnesses, "null", "", "parameter"))
      end
    end

    it "refuses a token event on a written structural witness" do
      witnesses = [
        dcn_witness(5, "(", "(", "Whole", dcn_whole(5, "(", "(")),
        dcn_witness(6, "Int32", "CONST"),
      ]
      expect_raises(Exception, "structural witness has a token event for written source") do
        dcn_validate(dcn_structural_json("UnnamedFunParameter", "fun f(Int32) : Void", dcn_written(0, "FunDef", "keyword"),
          witnesses, "null", "", "parameter"))
      end
    end

    it "refuses an expanded ShortBlockArgument anchor event that is not the first witness" do
      anchor = dcn_expanded(dcn_whole(8, "&", "&"), "Block", "ampersand")
      expect_raises(Exception, "structural anchor event differs from first witness") do
        dcn_validate(dcn_structural_json("ShortBlockArgument", "list.map &.to_s", anchor,
          [dcn_witness(9, "&", "&"), dcn_witness(10, ".", ".", "Whole", dcn_whole(10, ".", "."))], "0", "__arg0", "local_reference"))
      end
    end

    it "refuses a forged ShortBlockArgument rendering" do
      expect_raises(Exception, "derived structural rendering differs") do
        dcn_validate(dcn_structural_json("ShortBlockArgument", "list.map &.to_s", dcn_written(9, "Block", "ampersand"),
          [dcn_witness(9, "&", "&"), dcn_witness(10, ".", ".")], "0", "__arg1", "local_reference"))
      end
    end

    it "refuses an unknown structural production" do
      expect_raises(Exception, "invalid structural production") do
        dcn_validate(dcn_structural_json("Foo", "fun f(Int32) : Void", dcn_written(0, "FunDef", "keyword"),
          [dcn_witness(5, "(", "("), dcn_witness(6, "Int32", "CONST")], "null", "", "parameter"))
      end
    end

    it "refuses a head split into unmerged adjacent Generated parts from the same producer" do
      anchor = dcn_expanded(dcn_whole(0, "fun", "IDENT"), "FunDef", "keyword")
      split_head = dcn_event(6, "Int32", "CONST", [dcn_part(6, 8), dcn_part(8, 11)])
      witnesses = [
        dcn_witness(5, "(", "(", "Whole", dcn_whole(5, "(", "(")),
        dcn_witness(6, "Int32", "CONST", "Whole", split_head),
      ]
      expect_raises(Exception, "invalid structural witness provenance") do
        dcn_validate(dcn_structural_json("UnnamedFunParameter", "fun g(Int32) : Void", anchor, witnesses, "null", "", "parameter"))
      end
    end

    it "refuses NameSplice on the punctuation separator" do
      anchor = dcn_expanded(dcn_whole(0, "fun", "IDENT"), "FunDef", "keyword")
      splice = %({"kind":"NameSplice","start_offset":5,"end_offset":6,"emitter_origin":null,"source_name":null})
      witnesses = [
        dcn_witness(5, "(", "(", "Whole", dcn_event(5, "(", "(", [splice])),
        dcn_witness(6, "Int32", "CONST", "Whole", dcn_whole(6, "Int32", "CONST")),
      ]
      expect_raises(Exception, "invalid structural witness provenance") do
        dcn_validate(dcn_structural_json("UnnamedFunParameter", "fun g(Int32) : Void", anchor, witnesses, "null", "", "parameter"))
      end
    end

    it "refuses a fresh index on BareSplatParameter" do
      expect_raises(Exception, "structural witness differs") do
        dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*, y)", dcn_written(0, "Def", "keyword"),
          [dcn_witness(6, "*", "*"), dcn_witness(7, ",", ",")], "3", "", "parameter"))
      end
    end

    it "refuses a bare star with no following list comma" do
      expect_raises(Exception, "structural witness differs") do
        dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*)", dcn_written(0, "Def", "keyword"),
          [dcn_witness(6, "*", "*")], "null", "", "parameter"))
      end
    end

    it "refuses a named splat relabelled as bare" do
      expect_raises(Exception, "structural witness differs") do
        dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*xs)", dcn_written(0, "Def", "keyword"),
          [dcn_witness(6, "*", "*"), dcn_witness(7, "xs", "IDENT")], "null", "", "parameter"))
      end
    end

    it "refuses a star whose token kind is an identifier" do
      expect_raises(Exception, "structural witness differs") do
        dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*, y)", dcn_written(0, "Def", "keyword"),
          [dcn_witness(6, "*", "IDENT"), dcn_witness(7, ",", ",")], "null", "", "parameter"))
      end
    end

    it "refuses a comma whose token kind is an identifier" do
      expect_raises(Exception, "structural witness differs") do
        dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*, y)", dcn_written(0, "Def", "keyword"),
          [dcn_witness(6, "*", "*"), dcn_witness(7, ",", "IDENT")], "null", "", "parameter"))
      end
    end

    it "refuses a partial selection on the star" do
      expect_raises(Exception, "structural witness differs") do
        dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*, y)", dcn_written(0, "Def", "keyword"),
          [dcn_witness(6, "*", "*", "SignedNumberSign"), dcn_witness(7, ",", ",")], "null", "", "parameter"))
      end
    end

    it "refuses a bare star anchored on a fun keyword" do
      expect_raises(Exception, "invalid structural anchor") do
        dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*, y)", dcn_written(0, "FunDef", "keyword"),
          [dcn_witness(6, "*", "*"), dcn_witness(7, ",", ",")], "null", "", "parameter"))
      end
    end

    it "refuses a macro bare star anchored on a def keyword" do
      expect_raises(Exception, "invalid structural anchor") do
        dcn_validate(dcn_structural_json("MacroBareSplatParameter", "macro f(*, y)", dcn_written(0, "Def", "keyword"),
          [dcn_witness(8, "*", "*"), dcn_witness(9, ",", ",")], "null", "", "parameter"))
      end
    end

    it "refuses a def bare star anchored on a macro keyword" do
      expect_raises(Exception, "invalid structural anchor") do
        dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*, y)", dcn_written(0, "Macro", "keyword"),
          [dcn_witness(6, "*", "*"), dcn_witness(7, ",", ",")], "null", "", "parameter"))
      end
    end

    it "refuses a written def anchor that does not precede the star" do
      expect_raises(Exception, "anchor does not precede witnesses") do
        dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*, y)", dcn_written(6, "Def", "keyword"),
          [dcn_witness(6, "*", "*"), dcn_witness(7, ",", ",")], "null", "", "parameter"))
      end
    end

    it "refuses a written bare splat that carries a token event" do
      expect_raises(Exception, "structural witness has a token event for written source") do
        dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*, y)", dcn_written(0, "Def", "keyword"),
          [dcn_witness(6, "*", "*", "Whole", dcn_whole(6, "*", "*")), dcn_witness(7, ",", ",")], "null", "", "parameter"))
      end
    end

    it "refuses an expanded bare splat whose keyword is fun" do
      expect_raises(Exception, "invalid structural anchor") do
        anchor = dcn_expanded(dcn_whole(0, "fun", "IDENT"), "Def", "keyword")
        dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*, y)", anchor,
          [dcn_witness(6, "*", "*", "Whole", dcn_whole(6, "*", "*")), dcn_witness(7, ",", ",", "Whole", dcn_whole(7, ",", ","))], "null", "", "parameter"))
      end
    end

    it "refuses an expanded macro bare splat whose keyword is def" do
      expect_raises(Exception, "invalid structural anchor") do
        anchor = dcn_expanded(dcn_whole(0, "def", "IDENT"), "Macro", "keyword")
        dcn_validate(dcn_structural_json("MacroBareSplatParameter", "macro f(*, y)", anchor,
          [dcn_witness(8, "*", "*", "Whole", dcn_whole(8, "*", "*")), dcn_witness(9, ",", ",", "Whole", dcn_whole(9, ",", ","))], "null", "", "parameter"))
      end
    end

    it "refuses an expanded bare splat whose keyword follows its star" do
      expect_raises(Exception, "anchor does not precede witnesses") do
        anchor = dcn_expanded(dcn_whole(6, "def", "IDENT"), "Def", "keyword")
        dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*, y)", anchor,
          [dcn_witness(6, "*", "*", "Whole", dcn_whole(6, "*", "*")), dcn_witness(7, ",", ",", "Whole", dcn_whole(7, ",", ","))], "null", "", "parameter"))
      end
    end

    it "refuses an expanded bare splat keyword in another lexical mode" do
      expect_raises(Exception, "invalid structural anchor") do
        anchor = dcn_expanded(dcn_event(0, "def", "IDENT", [dcn_part(0, 3)], "Whole", "Iyi"), "Def", "keyword")
        dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*, y)", anchor,
          [dcn_witness(6, "*", "*", "Whole", dcn_whole(6, "*", "*")), dcn_witness(7, ",", ",", "Whole", dcn_whole(7, ",", ","))], "null", "", "parameter"))
      end
    end

    it "refuses an expanded bare splat guard from another input" do
      expect_raises(Exception, "structural witnesses use different inputs") do
        anchor = dcn_expanded(dcn_whole(0, "def", "IDENT"), "Def", "keyword", DCN_OTHER_GUARD)
        dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*, y)", anchor,
          [dcn_witness(6, "*", "*", "Whole", dcn_whole(6, "*", "*")), dcn_witness(7, ",", ",", "Whole", dcn_whole(7, ",", ","))], "null", "", "parameter"))
      end
    end

    it "refuses an expanded bare splat whose star has no event of its own" do
      expect_raises(Exception, "invalid structural witness provenance") do
        anchor = dcn_expanded(dcn_whole(0, "def", "IDENT"), "Def", "keyword")
        dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*, y)", anchor,
          [dcn_witness(6, "*", "*"), dcn_witness(7, ",", ",", "Whole", dcn_whole(7, ",", ","))], "null", "", "parameter"))
      end
    end

    it "refuses an expanded bare splat whose comma has no event of its own" do
      expect_raises(Exception, "invalid structural witness provenance") do
        anchor = dcn_expanded(dcn_whole(0, "def", "IDENT"), "Def", "keyword")
        dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*, y)", anchor,
          [dcn_witness(6, "*", "*", "Whole", dcn_whole(6, "*", "*")), dcn_witness(7, ",", ",")], "null", "", "parameter"))
      end
    end

    it "refuses a claim writer standing in for the comma event" do
      expect_raises(Exception, "invalid structural witness provenance") do
        anchor = dcn_expanded(dcn_whole(0, "def", "IDENT"), "Def", "keyword")
        claim = %({"kind":"AstAnchor","start_offset":7,"end_offset":8,"emitter_origin":null,"source_origin":#{dcn_written(0, "Def", "keyword")}})
        dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*, y)", anchor,
          [dcn_witness(6, "*", "*", "Whole", dcn_whole(6, "*", "*")), dcn_witness(7, ",", ",", "Whole", dcn_event(7, ",", ",", [claim]))], "null", "", "parameter"))
      end
    end

    it "refuses a rendered bare splat name that is not empty" do
      expect_raises(Exception, "derived structural rendering differs") do
        dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*, y)", dcn_written(0, "Def", "keyword"),
          [dcn_witness(6, "*", "*"), dcn_witness(7, ",", ",")], "null", "x", "parameter"))
      end
    end

    it "refuses a bare splat whose producer context is not parameter" do
      expect_raises(Exception, "derived structural rendering differs") do
        dcn_validate(dcn_structural_json("BareSplatParameter", "def f(*, y)", dcn_written(0, "Def", "keyword"),
          [dcn_witness(6, "*", "*"), dcn_witness(7, ",", ",")], "null", "", "local_reference"))
      end
    end
  end
end

DCT_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

def dct_target(path : String, declaration : String = dcn_written(0, "Assign", "constant")) : String
  %({"kind":"ConstantTarget","declaration_origin":#{declaration},"path":"#{path}"})
end

def dsc_constructor(part : String, definition : String = dcn_written(0, "Def", "keyword")) : String
  %({"kind":"SynthesizedConstructor","definition_origin":#{definition},"part":"#{part}"})
end

def dct_bound(producer : String, output : String, first : Int32, last : Int32, token_kind : String = "CONST",
              context : String = "path_segment", source : String = "") : String
  %({"kind":"DerivedName","derivation_kind":"BoundProjection","producer":#{producer},"source_fragment_sha256":"#{DCT_EMPTY_SHA256}","source_text":"#{source}","source_names":[],"output_text":"#{output}","lexical_mode":"Crystal","result_start":#{first},"result_end":#{last},"token_kind":"#{token_kind}","context":"#{context}"})
end

def dct_span(output : String, selected : String) : {Int32, Int32}
  first = output.index(selected).not_nil!
  {first, first + selected.bytesize}
end

describe "producers 9 and 10 bound projections (schema4)" do
  it "accepts each CONST segment of a multi-segment ConstantTarget path" do
    path = "Alpha::Beta::Gamma"
    {"Alpha", "Beta", "Gamma"}.each do |selected|
      first, last = dct_span(path, selected)
      dcn_validate(dct_bound(dct_target(path), path, first, last)).should eq({"path_segment", selected})
    end
  end

  it "accepts a single-segment ConstantTarget path" do
    dcn_validate(dct_bound(dct_target("Alpha"), "Alpha", 0, 5)).should eq({"path_segment", "Alpha"})
  end

  it "refuses a ConstantTarget path with a non-CONST segment in the middle" do
    expect_raises(Exception, "invalid constant target projection") do
      dcn_validate(dct_bound(dct_target("Alpha::beta::Gamma"), "Alpha::beta::Gamma", 0, 5))
    end
  end

  it "refuses a ConstantTarget path with an empty segment" do
    expect_raises(Exception, "invalid constant target projection") do
      dcn_validate(dct_bound(dct_target("Alpha::::Beta"), "Alpha::::Beta", 0, 5))
    end
  end

  it "refuses a leading separator on a ConstantTarget path" do
    expect_raises(Exception, "invalid constant target projection") do
      dcn_validate(dct_bound(dct_target("::Alpha"), "::Alpha", 2, 7))
    end
  end

  it "refuses a trailing separator on a ConstantTarget path" do
    expect_raises(Exception, "invalid constant target projection") do
      dcn_validate(dct_bound(dct_target("Alpha::"), "Alpha::", 0, 5))
    end
  end

  it "refuses a ConstantTarget whose declaration is not an Assign constant" do
    expect_raises(Exception, "invalid constant target projection") do
      dcn_validate(dct_bound(dct_target("Alpha", dcn_written(0, "Def", "keyword")), "Alpha", 0, 5))
    end
  end

  it "refuses a ConstantTarget whose output differs from its path" do
    expect_raises(Exception, "invalid bound projection result") do
      dcn_validate(dct_bound(dct_target("Alpha::Gamma"), "Alpha::Beta", 0, 5))
    end
  end

  it "refuses a ConstantTarget segment in the named-entry context" do
    expect_raises(Exception, "invalid bound projection result") do
      dcn_validate(dct_bound(dct_target("Alpha::Beta"), "Alpha::Beta", 0, 5, "CONST", "named_entry"))
    end
  end

  it "refuses a ConstantTarget result span past the output" do
    expect_raises(Exception, "invalid projection result span") do
      dcn_validate(dct_bound(dct_target("Alpha"), "Alpha", 0, 9))
    end
  end

  it "refuses an empty ConstantTarget result span" do
    expect_raises(Exception, "invalid projection result span") do
      dcn_validate(dct_bound(dct_target("Alpha"), "Alpha", 2, 2))
    end
  end

  it "refuses a ConstantTarget segment whose token kind is not the one observed" do
    expect_raises(Exception, "invalid projection result token") do
      dcn_validate(dct_bound(dct_target("Alpha::Beta"), "Alpha::Beta", 0, 5, "IDENT"))
    end
  end

  it "refuses a whole multi-segment path selected as one token" do
    expect_raises(Exception) do
      dcn_validate(dct_bound(dct_target("Alpha::Beta"), "Alpha::Beta", 0, 11))
    end
  end

  it "refuses a result span that selects the separator" do
    expect_raises(Exception) do
      dcn_validate(dct_bound(dct_target("Alpha::Beta"), "Alpha::Beta", 5, 7))
    end
  end

  it "refuses a ConstantTarget that carries source text" do
    expect_raises(Exception, "bound projection requires authoritative source inventory") do
      dcn_validate(dct_bound(dct_target("Alpha"), "Alpha", 0, 5, "CONST", "path_segment", "Alpha"))
    end
  end

  it "accepts a SynthesizedConstructor definition name as new" do
    dcn_validate(dct_bound(dsc_constructor("definition_name"), "new", 0, 3, "IDENT", "definition_name")).should eq({"definition_name", "new"})
  end

  it "accepts a SynthesizedConstructor receiver as self" do
    dcn_validate(dct_bound(dsc_constructor("local_reference"), "self", 0, 4, "IDENT", "local_reference")).should eq({"local_reference", "self"})
  end

  it "refuses a SynthesizedConstructor with an unknown part" do
    expect_raises(Exception, "invalid synthesized constructor part") do
      dcn_validate(dct_bound(dsc_constructor("other"), "new", 0, 3, "IDENT", "definition_name"))
    end
  end

  it "refuses a SynthesizedConstructor whose definition is not a Def keyword" do
    expect_raises(Exception, "invalid synthesized constructor producer") do
      dcn_validate(dct_bound(dsc_constructor("definition_name", dcn_written(0, "Assign", "constant")), "new", 0, 3, "IDENT", "definition_name"))
    end
  end

  it "refuses a SynthesizedConstructor whose output is not the constructor name" do
    expect_raises(Exception, "invalid bound projection result") do
      dcn_validate(dct_bound(dsc_constructor("definition_name"), "old", 0, 3, "IDENT", "definition_name"))
    end
  end

  it "refuses a SynthesizedConstructor in the named-entry context" do
    expect_raises(Exception, "invalid bound projection result") do
      dcn_validate(dct_bound(dsc_constructor("definition_name"), "new", 0, 3, "IDENT", "named_entry"))
    end
  end

  it "refuses a SynthesizedConstructor that carries source text" do
    expect_raises(Exception, "bound projection requires authoritative source inventory") do
      dcn_validate(dct_bound(dsc_constructor("definition_name"), "new", 0, 3, "IDENT", "definition_name", "new"))
    end
  end
end
