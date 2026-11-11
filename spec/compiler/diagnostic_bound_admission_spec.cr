require "../spec_helper"

# S6 admission primitives: exact placement of a restriction, the token an anchor covers, and the bytes a
# constant target must find. The spec reopens Iyi::IyiMod, as diagnostic_consumer_operator_structural_spec.cr
# does, so production gains no entry point. Refusals raise the §3.9 A1 text naming the producer kind.

module Iyi::IyiMod
  def self.dab_restriction(producer : Iyi::DiagnosticBoundProducer, field : Iyi::IyiMod::DiagnosticSignatureFieldWrite,
                           semantic_type : String) : {Int32, Int32}
    parameter_restriction_span!(producer, field, semantic_type)
  end

  def self.dab_within(producer : Iyi::DiagnosticBoundProducer, text : String, anchor : Iyi::DiagnosticAnchor,
                      lo : Int32, hi : Int32) : Nil
    anchor_token_within!(producer, text, anchor, lo, hi)
  end

  def self.dab_spans(producer : Iyi::DiagnosticBoundProducer, text : String, anchor : Iyi::DiagnosticAnchor,
                     lo : Int32, hi : Int32) : Nil
    anchor_token_spans!(producer, text, anchor, lo, hi)
  end

  def self.dab_bytes_at(text : String, start : Int32, expected : String) : Bool
    bytes_at?(text, start, expected)
  end
end

def dab_producer(type : String = "Int32") : Iyi::DiagnosticBoundProducer::SemanticSignatureType
  origin = Iyi::DiagnosticOrigin::Written.new("app/greeter", "/src/app/greeter.iyi", 0, "Def", "keyword")
  Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(origin, "parameter_restriction", 0, type)
end

def dab_field(text : String, start : Int32 = 10) : Iyi::IyiMod::DiagnosticSignatureFieldWrite
  Iyi::IyiMod::DiagnosticSignatureFieldWrite.new(Iyi::IyiMod::DiagnosticSignatureFieldKind::Parameter, 0,
    start, start + text.bytesize, text)
end

# An anchor whose one name value is a bound projection that renders *token*, as admission reads it.
def dab_anchor(offset : Int32, token : String) : Iyi::DiagnosticAnchor
  origin = Iyi::DiagnosticOrigin::DerivedName.bound_projection(dab_producer(token), ::Crystal::Digest::SHA256.hexdigest(""), "",
    [] of Iyi::DiagnosticBoundNameSource, token, "Crystal", 0, token.bytesize, "CONST", "path_segment")
  slot = Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::Primary)
  names = {slot => [Iyi::DiagnosticNameValue::Derived.new(origin).as(Iyi::DiagnosticNameValue)] of Iyi::DiagnosticNameValue}
  Iyi::DiagnosticAnchor.new(offset, "Name", "path_segment", origin, names, 0, Iyi::DiagnosticFragmentAttachment::Direct.new)
end

describe "S6 admission placement primitives" do
  describe "restriction spans" do
    it "places a restriction written without a default at its exact bytes" do
      # "x : Int32" starts at 10; the restriction begins after " : " at 14 and ends at 19.
      Iyi::IyiMod.dab_restriction(dab_producer, dab_field("x : Int32"), "Int32").should eq({14, 19})
    end

    it "places a restriction that carries a default at the same span" do
      Iyi::IyiMod.dab_restriction(dab_producer, dab_field("x : Int32 = 1"), "Int32").should eq({14, 19})
    end

    it "refuses a restriction whose written text differs from the projection's type" do
      expect_raises(ArgumentError, "bound projection is not at its declaration site: SemanticSignatureType") do
        Iyi::IyiMod.dab_restriction(dab_producer, dab_field("x : Int64"), "Int32")
      end
    end

    it "refuses a restriction that only begins with the projection's type" do
      expect_raises(ArgumentError, "bound projection is not at its declaration site: SemanticSignatureType") do
        Iyi::IyiMod.dab_restriction(dab_producer, dab_field("x : Int320"), "Int32")
      end
    end

    it "refuses a parameter field with no name separator" do
      expect_raises(ArgumentError, "bound projection is not at its declaration site: SemanticSignatureType") do
        Iyi::IyiMod.dab_restriction(dab_producer, dab_field("x"), "Int32")
      end
    end
  end

  describe "anchor tokens" do
    # "def f(x : Int32)": Int32 occupies bytes 10 through 14, so its span is [10, 15).
    it "accepts an anchor whose token is inside the span and whose bytes match" do
      Iyi::IyiMod.dab_within(dab_producer, "def f(x : Int32)", dab_anchor(10, "Int32"), 10, 15)
    end

    it "refuses an anchor that starts before the span" do
      expect_raises(ArgumentError, "bound projection is not at its declaration site: SemanticSignatureType") do
        Iyi::IyiMod.dab_within(dab_producer, "def f(x : Int32)", dab_anchor(10, "Int32"), 11, 16)
      end
    end

    it "refuses an anchor whose token runs past the span" do
      expect_raises(ArgumentError, "bound projection is not at its declaration site: SemanticSignatureType") do
        Iyi::IyiMod.dab_within(dab_producer, "def f(x : Int32)", dab_anchor(10, "Int32"), 10, 13)
      end
    end

    it "refuses an anchor whose header bytes differ from its token" do
      expect_raises(ArgumentError, "bound projection is not at its declaration site: SemanticSignatureType") do
        Iyi::IyiMod.dab_within(dab_producer, "def f(x : Int64)", dab_anchor(10, "Int32"), 10, 15)
      end
    end

    it "accepts a token that is exactly the field span" do
      Iyi::IyiMod.dab_spans(dab_producer, "def f(x : Int32)", dab_anchor(10, "Int32"), 10, 15)
    end

    it "refuses a token whose width differs from the field span" do
      expect_raises(ArgumentError, "bound projection is not at its declaration site: SemanticSignatureType") do
        Iyi::IyiMod.dab_spans(dab_producer("Int3"), "def f(x : Int32)", dab_anchor(10, "Int3"), 10, 15)
      end
    end
  end

  describe "constant target bytes" do
    it "finds the path at its start" do
      Iyi::IyiMod.dab_bytes_at("Alpha::Beta = 1", 0, "Alpha::Beta").should be_true
    end

    it "refuses a path that is not at the start it names" do
      Iyi::IyiMod.dab_bytes_at("Alpha::Beta = 1", 1, "Alpha::Beta").should be_false
    end

    it "refuses a start past the end of the text" do
      Iyi::IyiMod.dab_bytes_at("Alpha", 9, "Alpha").should be_false
    end

    it "refuses a negative start" do
      Iyi::IyiMod.dab_bytes_at("Alpha", -1, "Alpha").should be_false
    end
  end

  describe "source-bearing producers" do
    it "classifies the source-bearing producers and leaves the claims out" do
      assign = Iyi::DiagnosticOrigin::Written.new("app/greeter", "/src/app/greeter.iyi", 0, "Assign", "constant")
      Iyi::IyiMod.source_bearing_producer?(Iyi::DiagnosticBoundProducer::StripRoot.new("Root")).should be_true
      Iyi::IyiMod.source_bearing_producer?(Iyi::DiagnosticBoundProducer::SelfReturn.new("Thing", "new", "self")).should be_true
      Iyi::IyiMod.source_bearing_producer?(dab_producer).should be_false
      Iyi::IyiMod.source_bearing_producer?(Iyi::DiagnosticBoundProducer::ConstantTarget.new(assign, "Alpha")).should be_false
    end
  end
end
