require "../support/syntax"
require "../../src/compiler/iyi/codegen/diagnostic_provenance"

# Spelling of a macro fresh variable (`%name`, token kind MACRO_VAR), checked by the three name validators:
# the parser's observation, the Crystal model (DiagnosticSourceNameToken.valid_token?), and the codegen
# consumer (name_token?, reached through source_name_schema4!). Every check runs in Crystal and in Iyi mode.
# The module reopening below is spec-only: production code gains no entry point.

MVN_DIGEST   = "0" * 64
MVN_ACCEPTED = ["%var", "%Foo", "%_x1", "%éclair"]
MVN_REFUSED  = ["%", "var", "%var?", "%var!", "%1x", "%va-r", "%@var", "% var", "%%var"]

module Iyi::DiagnosticProvenance
  # Spec-only bridge: runs the private name-token validator from within the module.
  def self.mvn_name_token(kind : String, raw : String, mode : String, context : String) : Bool
    name_token?(kind, raw, mode, context)
  end

  # Spec-only bridge: runs the private source-name validator on serialized JSON.
  def self.mvn_source_name(value : JSON::Any) : Nil
    source_name_schema4!(value, 0)
  end
end

# Parses a source and returns the macro fresh variable observations, in lexical mode `iyi`.
def mvn_observations(source : String, iyi : Bool) : Array(Iyi::DiagnosticParsedName)
  parser = Iyi::Parser.new(source)
  parser.iyi = iyi
  parser.enable_diagnostic_name_observations
  parser.parse
  parser.diagnostic_name_observations.select { |item| item.context == "macro_fresh_variable" }
end

def mvn_valid?(kind : String, raw : String, mode : String, context : String = "macro_fresh_variable") : Bool
  Iyi::DiagnosticSourceNameToken.valid_token?(kind, raw, mode, context)
end

# A serialized source name token whose Written anchor sits at `start`, in the codegen consumer's schema.
def mvn_source_json(raw : String, start : Int32, kind : String, mode : String) : String
  finish = start + raw.bytesize
  lexical = %({"kind":"Written","source_identity":{"module":"sample","file":"sample.iyi"},"input_byte_offset":#{start},"anchor_kind":"Name","role":"macro_fresh_variable"})
  %({"lexical_origin":#{lexical},"binding_origin":null,"context":"macro_fresh_variable","input_sha256":"#{MVN_DIGEST}","input_bytesize":#{finish + 8},"input_start":#{start},"input_end":#{finish},"lexical_mode":"#{mode}","token_kind":"#{kind}","raw_text":"#{raw}"})
end

describe "macro fresh variable spelling" do
  {"Crystal" => false, "Iyi" => true}.each do |mode, iyi|
    describe "parser observation in #{mode} mode" do
      it "observes %var as one MACRO_VAR token that starts at the percent sign" do
        source = "macro m\n  %var\nend\n"
        found = mvn_observations(source, iyi)
        found.size.should eq 1
        found[0].context.should eq "macro_fresh_variable"
        found[0].token_kind.should eq "MACRO_VAR"
        found[0].token_text.should eq "%var"
        found[0].lexical_mode.should eq mode
        found[0].input_start.should eq source.index('%').not_nil!
        found[0].input_end.should eq found[0].input_start + 4
      end

      it "observes %v and leaves the following space and identifier alone" do
        found = mvn_observations("macro m\n  %v x\nend\n", iyi)
        found.map(&.token_text).should eq ["%v"]
      end

      it "observes %var{1} as the variable without its index" do
        found = mvn_observations("macro m\n  %var{1}\nend\n", iyi)
        found.map(&.token_text).should eq ["%var"]
      end

      it "observes no macro fresh variable for a bare identifier in a macro body" do
        mvn_observations("macro m\n  var\nend\n", iyi).should be_empty
      end
    end

    describe "model in #{mode} mode" do
      MVN_ACCEPTED.each do |raw|
        it "accepts #{raw} as a MACRO_VAR in the macro fresh variable context" do
          mvn_valid?("MACRO_VAR", raw, mode).should eq true
        end
      end

      MVN_REFUSED.each do |raw|
        it "refuses #{raw.inspect} as a MACRO_VAR in the macro fresh variable context" do
          mvn_valid?("MACRO_VAR", raw, mode).should eq false
        end
      end

      it "refuses an IDENT token with the macro fresh variable context" do
        mvn_valid?("IDENT", "%var", mode).should eq false
      end

      it "refuses a MACRO_VAR token in a context that takes other kinds" do
        mvn_valid?("MACRO_VAR", "%var", mode, "local_reference").should eq false
        mvn_valid?("MACRO_VAR", "%var", mode, "method_name").should eq false
      end
    end

    describe "codegen consumer in #{mode} mode" do
      (MVN_ACCEPTED + MVN_REFUSED).each do |raw|
        it "agrees with the model on #{raw.inspect}" do
          expected = mvn_valid?("MACRO_VAR", raw, mode)
          Iyi::DiagnosticProvenance.mvn_name_token("MACRO_VAR", raw, mode, "macro_fresh_variable").should eq expected
        end
      end

      it "accepts a serialized %var source token" do
        Iyi::DiagnosticProvenance.mvn_source_name(JSON.parse(mvn_source_json("%var", 10, "MACRO_VAR", mode))).should eq nil
      end

      it "refuses a serialized MACRO_VAR token whose spelling has no percent sign" do
        expect_raises(Exception, "invalid source name token") do
          Iyi::DiagnosticProvenance.mvn_source_name(JSON.parse(mvn_source_json("var", 10, "MACRO_VAR", mode)))
        end
      end

      it "refuses a serialized IDENT token spelled %var" do
        expect_raises(Exception, "invalid source name token") do
          Iyi::DiagnosticProvenance.mvn_source_name(JSON.parse(mvn_source_json("%var", 10, "IDENT", mode)))
        end
      end
    end
  end
end
