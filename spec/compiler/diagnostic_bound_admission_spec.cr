require "../spec_helper"

# S6 admission. Two layers:
#
# 1. Primitives: the exact restriction span, the token an anchor covers, the bytes a constant target must find,
#    and the source-bearing classification. The spec reopens Iyi::IyiMod, as
#    diagnostic_consumer_operator_structural_spec.cr does, so production gains no entry point.
# 2. Captured artifacts: real ledger fixtures, built the way diagnostic_bound_authority_spec.cr builds them,
#    run through IyiMod.validate_diagnostic_fragments! and IyiMod.write. These cover A4, the full validate pass
#    with and without an issuer, the ConstantTarget group, the class-variable check, and the signature producers
#    (SemanticSignatureType return and parameter, SynthesizedConstructor, ConstantAccessor) over Def-rooted headers.
#
# Refusals raise the §3.9 text. A1 names the producer kind. H1 is the expected result of a correct section, and
# it stays the capture hold: no fixture here calls an artifact validated.

H1_MESSAGE = "artifact diagnostic capture authority is unavailable"
A4_MESSAGE = "bound section was not verified by its issuer"
H3_MESSAGE = "bound projection requires authoritative source inventory"
A1_PREFIX  = "bound projection is not at its declaration site: "
ADM_MODULE = "app/greeter"

class AdmRecomputingAuthority < Iyi::DiagnosticProjectionAuthority
  def recompute(request : Iyi::DiagnosticProjectionRequest) : Iyi::DiagnosticBoundProducer
    adm_copy(request.producer)
  end
end

def adm_copy(producer : Iyi::DiagnosticBoundProducer) : Iyi::DiagnosticBoundProducer
  case producer
  when Iyi::DiagnosticBoundProducer::StripRoot
    Iyi::DiagnosticBoundProducer::StripRoot.new(producer.root)
  when Iyi::DiagnosticBoundProducer::SemanticSignatureType
    Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(producer.definition_origin, producer.field,
      producer.parameter_index, producer.semantic_type)
  when Iyi::DiagnosticBoundProducer::SynthesizedConstructor
    Iyi::DiagnosticBoundProducer::SynthesizedConstructor.new(producer.definition_origin, producer.part)
  when Iyi::DiagnosticBoundProducer::ConstantAccessor
    Iyi::DiagnosticBoundProducer::ConstantAccessor.new(producer.definition_origin, producer.prefix,
      producer.constant_name, producer.part)
  when Iyi::DiagnosticBoundProducer::UninitializedClassVar
    Iyi::DiagnosticBoundProducer::UninitializedClassVar.new(producer.declaration_origin, producer.owner_type,
      producer.variable_name, producer.semantic_type)
  when Iyi::DiagnosticBoundProducer::ConstantTarget
    Iyi::DiagnosticBoundProducer::ConstantTarget.new(producer.declaration_origin, producer.path)
  else
    raise ArgumentError.new("admission spec authority has no copy for this producer")
  end
end

def adm_written(offset : Int32, kind : String, role : String) : Iyi::DiagnosticOrigin::Written
  Iyi::DiagnosticOrigin::Written.new(ADM_MODULE, "/src/app/greeter.iyi", offset, kind, role)
end

# A registered source with no text. Every source-free producer renders from it.
def adm_empty(ledger : Iyi::DiagnosticProjectionLedger) : Iyi::DiagnosticRenderedFragment
  ledger.register_source(Iyi::DiagnosticRenderedFragment.new("",
    Iyi::DiagnosticFragmentData.new("", [] of Iyi::DiagnosticTokenEvent, [] of Iyi::DiagnosticAnchor)))
end

# A registered source whose spans are CONST path segments, each anchored to its own source token.
def adm_names(ledger : Iyi::DiagnosticProjectionLedger, text : String,
              spans : Array({Int32, Int32})) : {Iyi::DiagnosticRenderedFragment, Array(Iyi::DiagnosticBoundNameSource)}
  guard = ::Crystal::Digest::SHA256.hexdigest(text)
  builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
  names = [] of Iyi::DiagnosticBoundNameSource
  spans.each do |first, last|
    origin = adm_written(first, "Name", "path_segment")
    raw = text.byte_slice(first, last - first)
    token = Iyi::DiagnosticSourceNameToken.new(origin, nil, "path_segment", guard, text.bytesize, first, last, "Crystal", "CONST", raw)
    value = Iyi::DiagnosticNameValue::Observed.new(token)
    slot = Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::PathSegment, 0)
    builder.add_written_anchor(first, last, text, Iyi::DiagnosticRenderedLexContext::TypeName, "Name", "path_segment",
      origin, {slot => [value] of Iyi::DiagnosticNameValue})
    names << Iyi::DiagnosticBoundNameSource.new(first, last, value)
  end
  {ledger.register_source(Iyi::DiagnosticRenderedFragment.new(text, builder.finish_data(text))), names}
end

# The artifact a section is checked in. Its initialiser, class variables and functions are the ones the fixtures
# render. Functions are written under the module's name, which is the container their header keys use.
def adm_artifact(initialiser : String = "",
                 class_vars : Array(Iyi::IyiMod::ClassVarDecl) = [] of Iyi::IyiMod::ClassVarDecl,
                 functions : Array(Iyi::IyiMod::Signature) = [] of Iyi::IyiMod::Signature) : Iyi::IyiMod::Artifact
  Iyi::IyiMod::Artifact.new(
    module_name: ADM_MODULE,
    source_path: "/src/app/greeter.iyi",
    compiler_version: "1.22.0-dev+abc1234",
    target_triple: "x86_64-pc-linux-gnu",
    flags: ["bits64", "linux"],
    imports: [] of Iyi::IyiMod::ImportEdge,
    exports: Iyi::IyiMod::Exports.new(functions, [] of Iyi::IyiMod::TypeDecl, [] of Iyi::IyiMod::ImplRecord, class_vars),
    initialiser: initialiser,
  )
end

def adm_with_temporary_file(&)
  path = File.tempname("admission", ".iyimod")
  begin
    yield path
  ensure
    File.delete(path) if File.exists?(path)
  end
end

def adm_section(*fragments : Iyi::IyiMod::DiagnosticFragment) : Iyi::IyiMod::DiagnosticSection
  section = Iyi::IyiMod::DiagnosticSection.new
  fragments.each { |fragment| section.add_fragment(fragment) }
  section
end

# The constant target "Inner::NAME" rendered at its own site under the initialiser. Its segment anchors are
# the projections the ledger issued.
def adm_constant_rendered(ledger : Iyi::DiagnosticProjectionLedger, origin : Iyi::DiagnosticOrigin::Written,
                          initialiser : Iyi::DiagnosticBoundSite) : Iyi::DiagnosticRenderedFragment
  child = ledger.open_site("constant", "", nil, nil, origin, initialiser)
  producer = Iyi::DiagnosticBoundProducer::ConstantTarget.new(origin, "Inner::NAME")
  ledger.render(child, producer, adm_empty(ledger), Iyi::DiagnosticByteSpan.new(0, 0), "Crystal")
end

# The initialiser fragment a constant target is written in: the assignment's head, when *head* is set, and the
# segment anchors at the indices in *keep*. The segments keep the ledger's issued origins and offsets.
def adm_constant_fragment(rendered : Iyi::DiagnosticRenderedFragment, origin : Iyi::DiagnosticOrigin::Written,
                          head : Bool, keep : Array(Int32)) : Iyi::DiagnosticRenderedFragment
  text = rendered.text
  builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
  if head
    builder.add_written_anchor(0, 5, text, Iyi::DiagnosticRenderedLexContext::TypeName, "Assign", "constant", origin,
      {} of Iyi::DiagnosticNameSlot => Array(Iyi::DiagnosticNameValue))
  end
  rendered.data.anchors.each_with_index do |anchor, index|
    next unless keep.includes?(index)
    token = anchor.name_slots.values.flatten.first.rendered_text
    builder.add_written_anchor(anchor.offset, anchor.offset + token.bytesize, text,
      Iyi::DiagnosticRenderedLexContext::TypeName, "Name", "path_segment", anchor.origin.not_nil!, anchor.name_slots)
  end
  Iyi::DiagnosticRenderedFragment.new(text, builder.finish_data(text))
end

# A signature with the given origin, written as the bind writer writes it: no visibility, not abstract.
def adm_signature(name : String, origin : Iyi::DiagnosticOrigin, receiver : String = "",
                  parameters : Array(String) = [] of String, return_type : String = "") : Iyi::IyiMod::Signature
  signature = Iyi::IyiMod::Signature.new(name, receiver, parameters, "", return_type, [] of String, false,
    free_variable_bounds: [] of {String, String}, where_bounds: [] of {String, String})
  signature.diagnostic_origin = origin
  signature
end

# The one field of *kind* at *index* in the header a signature renders, from the writer's own observer.
def adm_field(signature : Iyi::IyiMod::Signature, kind : Iyi::IyiMod::DiagnosticSignatureFieldKind,
              index : Int32) : Iyi::IyiMod::DiagnosticSignatureFieldWrite
  _text, fields = Iyi::IyiMod.render_signature_observed(signature)
  fields.find { |field| field.kind == kind && field.index == index } || raise "the header has no such field"
end

# The header's data: the keyword root at *root_offset*, and each placement's projection anchors moved by its base.
# The anchors keep the ledger's issued origins, so each projection is the one the ledger minted.
def adm_header_data(text : String, root : Iyi::DiagnosticOrigin, root_offset : Int32,
                    placements : Array({Iyi::DiagnosticRenderedFragment, Int32})) : Iyi::DiagnosticFragmentData
  builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
  builder.add_written_anchor(root_offset, root_offset + 3, text, Iyi::DiagnosticRenderedLexContext::DefOrMacroName,
    "Def", "keyword", root, {} of Iyi::DiagnosticNameSlot => Array(Iyi::DiagnosticNameValue))
  placements.each do |rendered, base|
    rendered.data.anchors.each do |anchor|
      token = anchor.name_slots.values.flatten.first.rendered_text
      lex = anchor.role == "definition_name" ? Iyi::DiagnosticRenderedLexContext::DefOrMacroName : Iyi::DiagnosticRenderedLexContext::TypeName
      builder.add_written_anchor(base + anchor.offset, base + anchor.offset + token.bytesize, text, lex,
        anchor.kind, anchor.role, anchor.origin.not_nil!, anchor.name_slots)
    end
  end
  builder.finish_data(text)
end

# The accepted header: composed from the ledger's parts and finished under its signature site, as bind does.
def adm_accepted(ledger : Iyi::DiagnosticProjectionLedger, site : Iyi::DiagnosticBoundSite, signature : Iyi::IyiMod::Signature,
                 placements : Array({Iyi::DiagnosticRenderedFragment, Int32})) : Iyi::IyiMod::DiagnosticSection
  text = Iyi::IyiMod.render_signature(signature)
  data = adm_header_data(text, signature.diagnostic_origin.not_nil!, 0, placements)
  joined = ledger.compose(site, Iyi::DiagnosticRenderedFragment.new(text, data), placements.map { |rendered, _| rendered })
  key = Iyi::IyiMod.signature_fragment_key(ADM_MODULE, signature)
  adm_section(ledger.finish(site, joined, key, signature))
end

# A misplaced header: the same anchors at the wrong fields, held directly as the section's fragment. Admission
# reads the section; the ledger's own refusals are not the subject of these controls.
def adm_misplaced(signature : Iyi::IyiMod::Signature,
                  placements : Array({Iyi::DiagnosticRenderedFragment, Int32})) : Iyi::IyiMod::DiagnosticSection
  text = Iyi::IyiMod.render_signature(signature)
  data = adm_header_data(text, signature.diagnostic_origin.not_nil!, 0, placements)
  adm_section(Iyi::IyiMod::DiagnosticFragment.new(Iyi::IyiMod.signature_fragment_key(ADM_MODULE, signature),
    data.text_sha256, data.events, data.anchors))
end

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
  origin = Iyi::DiagnosticOrigin::Written.new(ADM_MODULE, "/src/app/greeter.iyi", 0, "Def", "keyword")
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

describe "S6 admission primitives" do
  describe "restriction spans" do
    it "places a restriction written without a default at its exact bytes" do
      # "x : Int32" starts at 10; the restriction begins after " : " at 14 and ends at 19.
      Iyi::IyiMod.dab_restriction(dab_producer, dab_field("x : Int32"), "Int32").should eq({14, 19})
    end

    it "places a restriction that carries a default at the same span" do
      Iyi::IyiMod.dab_restriction(dab_producer, dab_field("x : Int32 = 1"), "Int32").should eq({14, 19})
    end

    it "refuses a restriction whose written text differs from the projection's type" do
      expect_raises(ArgumentError, A1_PREFIX + "SemanticSignatureType") do
        Iyi::IyiMod.dab_restriction(dab_producer, dab_field("x : Int64"), "Int32")
      end
    end

    it "refuses a restriction that only begins with the projection's type" do
      expect_raises(ArgumentError, A1_PREFIX + "SemanticSignatureType") do
        Iyi::IyiMod.dab_restriction(dab_producer, dab_field("x : Int320"), "Int32")
      end
    end

    it "refuses a parameter field with no name separator" do
      expect_raises(ArgumentError, A1_PREFIX + "SemanticSignatureType") do
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
      expect_raises(ArgumentError, A1_PREFIX + "SemanticSignatureType") do
        Iyi::IyiMod.dab_within(dab_producer, "def f(x : Int32)", dab_anchor(10, "Int32"), 11, 16)
      end
    end

    it "refuses an anchor whose token runs past the span" do
      expect_raises(ArgumentError, A1_PREFIX + "SemanticSignatureType") do
        Iyi::IyiMod.dab_within(dab_producer, "def f(x : Int32)", dab_anchor(10, "Int32"), 10, 13)
      end
    end

    it "refuses an anchor whose header bytes differ from its token" do
      expect_raises(ArgumentError, A1_PREFIX + "SemanticSignatureType") do
        Iyi::IyiMod.dab_within(dab_producer, "def f(x : Int64)", dab_anchor(10, "Int32"), 10, 15)
      end
    end

    it "accepts a token that is exactly the field span" do
      Iyi::IyiMod.dab_spans(dab_producer, "def f(x : Int32)", dab_anchor(10, "Int32"), 10, 15)
    end

    it "refuses a token whose width differs from the field span" do
      expect_raises(ArgumentError, A1_PREFIX + "SemanticSignatureType") do
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
      assign = adm_written(0, "Assign", "constant")
      Iyi::IyiMod.source_bearing_producer?(Iyi::DiagnosticBoundProducer::StripRoot.new("Root")).should be_true
      Iyi::IyiMod.source_bearing_producer?(Iyi::DiagnosticBoundProducer::SelfReturn.new("Thing", "new", "self")).should be_true
      Iyi::IyiMod.source_bearing_producer?(dab_producer).should be_false
      Iyi::IyiMod.source_bearing_producer?(Iyi::DiagnosticBoundProducer::ConstantTarget.new(assign, "Alpha")).should be_false
    end
  end
end

describe "S6 admission over captured artifacts" do
  describe "A4: write requires the issuer's verification" do
    it "refuses a section the issuer has not verified" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      artifact = adm_artifact
      artifact.diagnostic_provenance = Iyi::IyiMod::DiagnosticSection.new
      adm_with_temporary_file do |path|
        expect_raises(Iyi::IyiMod::Error, A4_MESSAGE) { Iyi::IyiMod.write(artifact, path, ledger) }
      end
    end

    it "refuses a section other than the one the issuer verified" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      verified = Iyi::IyiMod::DiagnosticSection.new
      ledger.verify_section!(verified).should eq(0)
      artifact = adm_artifact
      artifact.diagnostic_provenance = Iyi::IyiMod::DiagnosticSection.new
      adm_with_temporary_file do |path|
        expect_raises(Iyi::IyiMod::Error, A4_MESSAGE) { Iyi::IyiMod.write(artifact, path, ledger) }
      end
    end

    it "lets a verified empty section through to the capture hold H1" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      section = Iyi::IyiMod::DiagnosticSection.new
      ledger.verify_section!(section).should eq(0)
      artifact = adm_artifact
      artifact.diagnostic_provenance = section
      adm_with_temporary_file do |path|
        expect_raises(Iyi::IyiMod::Error, H1_MESSAGE) { Iyi::IyiMod.write(artifact, path, ledger) }
      end
    end
  end

  describe "the full validate pass" do
    it "accepts an empty verified section with an issuer" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      section = Iyi::IyiMod::DiagnosticSection.new
      ledger.verify_section!(section)
      artifact = adm_artifact
      artifact.diagnostic_provenance = section
      Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
    end

    it "accepts an empty section without an issuer, as the reader checks it" do
      artifact = adm_artifact
      artifact.diagnostic_provenance = Iyi::IyiMod::DiagnosticSection.new
      Iyi::IyiMod.validate_diagnostic_fragments!(artifact)
    end

    it "accepts a source-bearing projection placed in the initialiser when an issuer is given" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      site = ledger.open_site("initialiser", "")
      before, _ = adm_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      rendered = ledger.render(site, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), before,
        Iyi::DiagnosticByteSpan.new(0, 11), "Crystal")
      section = adm_section(ledger.finish(site, rendered, "initialiser"))
      ledger.verify_section!(section).should eq(1)
      artifact = adm_artifact("Thing")
      artifact.diagnostic_provenance = section
      Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      adm_with_temporary_file do |path|
        expect_raises(Iyi::IyiMod::Error, H1_MESSAGE) { Iyi::IyiMod.write(artifact, path, ledger) }
      end
    end

    it "refuses a source-bearing projection without an issuer as H3" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      site = ledger.open_site("initialiser", "")
      before, _ = adm_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      rendered = ledger.render(site, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), before,
        Iyi::DiagnosticByteSpan.new(0, 11), "Crystal")
      artifact = adm_artifact("Thing")
      artifact.diagnostic_provenance = adm_section(ledger.finish(site, rendered, "initialiser"))
      expect_raises(ArgumentError, H3_MESSAGE) { Iyi::IyiMod.validate_diagnostic_fragments!(artifact) }
    end
  end

  describe "the ConstantTarget group" do
    it "accepts consecutive segments under their head, with the path on one line" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      initialiser = ledger.open_site("initialiser", "")
      origin = adm_written(0, "Assign", "constant")
      rendered = adm_constant_rendered(ledger, origin, initialiser)
      joined = ledger.compose(initialiser, adm_constant_fragment(rendered, origin, true, [0, 1]), [rendered])
      section = adm_section(ledger.finish(initialiser, joined, "initialiser"))
      ledger.verify_section!(section).should eq(2)
      artifact = adm_artifact("Inner::NAME")
      artifact.diagnostic_provenance = section
      Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      adm_with_temporary_file do |path|
        expect_raises(Iyi::IyiMod::Error, H1_MESSAGE) { Iyi::IyiMod.write(artifact, path, ledger) }
      end
    end

    it "refuses segments that carry no head at the path's start" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      initialiser = ledger.open_site("initialiser", "")
      origin = adm_written(0, "Assign", "constant")
      rendered = adm_constant_rendered(ledger, origin, initialiser)
      joined = ledger.compose(initialiser, adm_constant_fragment(rendered, origin, false, [0, 1]), [rendered])
      artifact = adm_artifact("Inner::NAME")
      artifact.diagnostic_provenance = adm_section(ledger.finish(initialiser, joined, "initialiser"))
      expect_raises(ArgumentError, A1_PREFIX + "ConstantTarget") do
        Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      end
    end

    it "refuses a group whose segment count differs from the path's" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      initialiser = ledger.open_site("initialiser", "")
      origin = adm_written(0, "Assign", "constant")
      rendered = adm_constant_rendered(ledger, origin, initialiser)
      joined = ledger.compose(initialiser, adm_constant_fragment(rendered, origin, true, [0]), [rendered])
      artifact = adm_artifact("Inner::NAME")
      artifact.diagnostic_provenance = adm_section(ledger.finish(initialiser, joined, "initialiser"))
      expect_raises(ArgumentError, A1_PREFIX + "ConstantTarget") do
        Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      end
    end
  end

  describe "the class-variable check" do
    it "accepts an uninitialised class variable finished at its own site" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      origin = adm_written(0, "Name", "class_variable")
      root = Iyi::IyiMod::DIAGNOSTIC_ROOT_CONTAINER
      site = ledger.open_site("class_var", root, "@@cache", nil, origin)
      producer = Iyi::DiagnosticBoundProducer::UninitializedClassVar.new(origin, "Owner", "@@cache", "Int32")
      rendered = ledger.render(site, producer, adm_empty(ledger), Iyi::DiagnosticByteSpan.new(0, 0), "Crystal")
      rendered.text.should eq("uninitialized Int32")
      section = adm_section(ledger.finish(site, rendered, Iyi::IyiMod.class_var_fragment_key(root, "@@cache")))
      ledger.verify_section!(section).should eq(1)
      class_var = Iyi::IyiMod::ClassVarDecl.new("@@cache", "Int32", "uninitialized Int32", [] of String)
      artifact = adm_artifact("", [class_var])
      artifact.diagnostic_provenance = section
      Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      adm_with_temporary_file do |path|
        expect_raises(Iyi::IyiMod::Error, H1_MESSAGE) { Iyi::IyiMod.write(artifact, path, ledger) }
      end
    end

    it "refuses an uninitialised class variable claim placed under the initialiser's key" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      origin = adm_written(0, "Name", "class_variable")
      site = ledger.open_site("class_var", Iyi::IyiMod::DIAGNOSTIC_ROOT_CONTAINER, "@@cache", nil, origin)
      producer = Iyi::DiagnosticBoundProducer::UninitializedClassVar.new(origin, "Owner", "@@cache", "Int32")
      rendered = ledger.render(site, producer, adm_empty(ledger), Iyi::DiagnosticByteSpan.new(0, 0), "Crystal")
      misplaced = Iyi::IyiMod::DiagnosticFragment.new("initialiser", ::Crystal::Digest::SHA256.hexdigest(rendered.text),
        rendered.data.events, rendered.data.anchors)
      artifact = adm_artifact(rendered.text)
      artifact.diagnostic_provenance = adm_section(misplaced)
      expect_raises(ArgumentError, A1_PREFIX + "UninitializedClassVar") do
        Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      end
    end
  end

  describe "the signature producers over Def-rooted headers" do
    it "accepts a return type placed at the return field" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      origin = adm_written(0, "Def", "keyword")
      signature = adm_signature("greet", origin, return_type: "Int32")
      site = ledger.open_site("signature", ADM_MODULE, nil, nil, origin)
      producer = Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(origin, "return_type", nil, "Int32")
      rendered = ledger.render(site, producer, adm_empty(ledger), Iyi::DiagnosticByteSpan.new(0, 0), "Crystal")
      field = adm_field(signature, Iyi::IyiMod::DiagnosticSignatureFieldKind::ReturnType, -1)
      section = adm_accepted(ledger, site, signature, [{rendered, field.start_offset}])
      ledger.verify_section!(section).should eq(1)
      artifact = adm_artifact(functions: [signature])
      artifact.diagnostic_provenance = section
      Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      adm_with_temporary_file do |path|
        expect_raises(Iyi::IyiMod::Error, H1_MESSAGE) { Iyi::IyiMod.write(artifact, path, ledger) }
      end
    end

    it "accepts a parameter restriction placed at its parameter's restriction" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      origin = adm_written(0, "Def", "keyword")
      signature = adm_signature("greet", origin, parameters: ["x : Int32"])
      site = ledger.open_site("signature", ADM_MODULE, nil, nil, origin)
      producer = Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(origin, "parameter_restriction", 0, "Int32")
      rendered = ledger.render(site, producer, adm_empty(ledger), Iyi::DiagnosticByteSpan.new(0, 0), "Crystal")
      field = adm_field(signature, Iyi::IyiMod::DiagnosticSignatureFieldKind::Parameter, 0)
      base = field.start_offset + field.text.byte_index(" : ").not_nil! + 3
      section = adm_accepted(ledger, site, signature, [{rendered, base}])
      ledger.verify_section!(section).should eq(1)
      artifact = adm_artifact(functions: [signature])
      artifact.diagnostic_provenance = section
      Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      adm_with_temporary_file do |path|
        expect_raises(Iyi::IyiMod::Error, H1_MESSAGE) { Iyi::IyiMod.write(artifact, path, ledger) }
      end
    end

    it "accepts a SynthesizedConstructor definition name placed at the name field" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      origin = adm_written(0, "Def", "keyword")
      signature = adm_signature("new", origin, receiver: "self")
      site = ledger.open_site("signature", ADM_MODULE, nil, nil, origin)
      producer = Iyi::DiagnosticBoundProducer::SynthesizedConstructor.new(origin, "definition_name")
      rendered = ledger.render(site, producer, adm_empty(ledger), Iyi::DiagnosticByteSpan.new(0, 0), "Crystal")
      field = adm_field(signature, Iyi::IyiMod::DiagnosticSignatureFieldKind::Name, -1)
      section = adm_accepted(ledger, site, signature, [{rendered, field.start_offset}])
      ledger.verify_section!(section).should eq(1)
      artifact = adm_artifact(functions: [signature])
      artifact.diagnostic_provenance = section
      Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      adm_with_temporary_file do |path|
        expect_raises(Iyi::IyiMod::Error, H1_MESSAGE) { Iyi::IyiMod.write(artifact, path, ledger) }
      end
    end

    it "accepts a SynthesizedConstructor local reference placed at the receiver field" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      origin = adm_written(0, "Def", "keyword")
      signature = adm_signature("new", origin, receiver: "self")
      site = ledger.open_site("signature", ADM_MODULE, nil, nil, origin)
      producer = Iyi::DiagnosticBoundProducer::SynthesizedConstructor.new(origin, "local_reference")
      rendered = ledger.render(site, producer, adm_empty(ledger), Iyi::DiagnosticByteSpan.new(0, 0), "Crystal")
      field = adm_field(signature, Iyi::IyiMod::DiagnosticSignatureFieldKind::Receiver, -1)
      section = adm_accepted(ledger, site, signature, [{rendered, field.start_offset}])
      ledger.verify_section!(section).should eq(1)
      artifact = adm_artifact(functions: [signature])
      artifact.diagnostic_provenance = section
      Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      adm_with_temporary_file do |path|
        expect_raises(Iyi::IyiMod::Error, H1_MESSAGE) { Iyi::IyiMod.write(artifact, path, ledger) }
      end
    end

    it "accepts a ConstantAccessor name placed at the name field" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      origin = Iyi::DiagnosticOrigin::Synthetic.new(adm_written(0, "Assign", "constant"), "constant_accessor", "getter")
      signature = adm_signature("value", origin, receiver: "self")
      site = ledger.open_site("signature", ADM_MODULE, nil, nil, origin)
      producer = Iyi::DiagnosticBoundProducer::ConstantAccessor.new(origin, "", "VALUE", "Name")
      rendered = ledger.render(site, producer, adm_empty(ledger), Iyi::DiagnosticByteSpan.new(0, 0), "Crystal")
      field = adm_field(signature, Iyi::IyiMod::DiagnosticSignatureFieldKind::Name, -1)
      section = adm_accepted(ledger, site, signature, [{rendered, field.start_offset}])
      ledger.verify_section!(section).should eq(1)
      artifact = adm_artifact(functions: [signature])
      artifact.diagnostic_provenance = section
      Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      adm_with_temporary_file do |path|
        expect_raises(Iyi::IyiMod::Error, H1_MESSAGE) { Iyi::IyiMod.write(artifact, path, ledger) }
      end
    end

    it "accepts a ConstantAccessor receiver placed at the receiver field" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      origin = Iyi::DiagnosticOrigin::Synthetic.new(adm_written(0, "Assign", "constant"), "constant_accessor", "getter")
      signature = adm_signature("value", origin, receiver: "self")
      site = ledger.open_site("signature", ADM_MODULE, nil, nil, origin)
      producer = Iyi::DiagnosticBoundProducer::ConstantAccessor.new(origin, "", "VALUE", "Receiver")
      rendered = ledger.render(site, producer, adm_empty(ledger), Iyi::DiagnosticByteSpan.new(0, 0), "Crystal")
      field = adm_field(signature, Iyi::IyiMod::DiagnosticSignatureFieldKind::Receiver, -1)
      section = adm_accepted(ledger, site, signature, [{rendered, field.start_offset}])
      ledger.verify_section!(section).should eq(1)
      artifact = adm_artifact(functions: [signature])
      artifact.diagnostic_provenance = section
      Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      adm_with_temporary_file do |path|
        expect_raises(Iyi::IyiMod::Error, H1_MESSAGE) { Iyi::IyiMod.write(artifact, path, ledger) }
      end
    end

    # Misplaced controls. Each builds the claim through the ledger, then places it at a field it does not belong to.

    it "refuses a return type whose written return differs from the claim" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      origin = adm_written(0, "Def", "keyword")
      signature = adm_signature("greet", origin, return_type: "Int64")
      producer = Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(origin, "return_type", nil, "Int32")
      rendered = ledger.render(ledger.open_site("signature", ADM_MODULE, nil, nil, origin), producer,
        adm_empty(ledger), Iyi::DiagnosticByteSpan.new(0, 0), "Crystal")
      field = adm_field(signature, Iyi::IyiMod::DiagnosticSignatureFieldKind::ReturnType, -1)
      artifact = adm_artifact(functions: [signature])
      artifact.diagnostic_provenance = adm_misplaced(signature, [{rendered, field.start_offset}])
      expect_raises(ArgumentError, A1_PREFIX + "SemanticSignatureType") do
        Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      end
    end

    it "refuses a return type anchored one byte before the return field" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      origin = adm_written(0, "Def", "keyword")
      signature = adm_signature("greet", origin, return_type: "Int32")
      producer = Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(origin, "return_type", nil, "Int32")
      rendered = ledger.render(ledger.open_site("signature", ADM_MODULE, nil, nil, origin), producer,
        adm_empty(ledger), Iyi::DiagnosticByteSpan.new(0, 0), "Crystal")
      field = adm_field(signature, Iyi::IyiMod::DiagnosticSignatureFieldKind::ReturnType, -1)
      artifact = adm_artifact(functions: [signature])
      artifact.diagnostic_provenance = adm_misplaced(signature, [{rendered, field.start_offset - 1}])
      expect_raises(ArgumentError, A1_PREFIX + "SemanticSignatureType") do
        Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      end
    end

    it "refuses a return type anchored on a parameter restriction" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      origin = adm_written(0, "Def", "keyword")
      signature = adm_signature("greet", origin, parameters: ["x : Int32"], return_type: "Int32")
      producer = Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(origin, "return_type", nil, "Int32")
      rendered = ledger.render(ledger.open_site("signature", ADM_MODULE, nil, nil, origin), producer,
        adm_empty(ledger), Iyi::DiagnosticByteSpan.new(0, 0), "Crystal")
      param = adm_field(signature, Iyi::IyiMod::DiagnosticSignatureFieldKind::Parameter, 0)
      base = param.start_offset + param.text.byte_index(" : ").not_nil! + 3
      artifact = adm_artifact(functions: [signature])
      artifact.diagnostic_provenance = adm_misplaced(signature, [{rendered, base}])
      expect_raises(ArgumentError, A1_PREFIX + "SemanticSignatureType") do
        Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      end
    end

    it "refuses a parameter restriction whose written type differs from the claim" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      origin = adm_written(0, "Def", "keyword")
      signature = adm_signature("greet", origin, parameters: ["x : Int64"])
      producer = Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(origin, "parameter_restriction", 0, "Int32")
      rendered = ledger.render(ledger.open_site("signature", ADM_MODULE, nil, nil, origin), producer,
        adm_empty(ledger), Iyi::DiagnosticByteSpan.new(0, 0), "Crystal")
      param = adm_field(signature, Iyi::IyiMod::DiagnosticSignatureFieldKind::Parameter, 0)
      base = param.start_offset + param.text.byte_index(" : ").not_nil! + 3
      artifact = adm_artifact(functions: [signature])
      artifact.diagnostic_provenance = adm_misplaced(signature, [{rendered, base}])
      expect_raises(ArgumentError, A1_PREFIX + "SemanticSignatureType") do
        Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      end
    end

    it "refuses a parameter restriction anchored on the return type" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      origin = adm_written(0, "Def", "keyword")
      signature = adm_signature("greet", origin, parameters: ["x : Int32"], return_type: "Int64")
      producer = Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(origin, "parameter_restriction", 0, "Int32")
      rendered = ledger.render(ledger.open_site("signature", ADM_MODULE, nil, nil, origin), producer,
        adm_empty(ledger), Iyi::DiagnosticByteSpan.new(0, 0), "Crystal")
      ret = adm_field(signature, Iyi::IyiMod::DiagnosticSignatureFieldKind::ReturnType, -1)
      artifact = adm_artifact(functions: [signature])
      artifact.diagnostic_provenance = adm_misplaced(signature, [{rendered, ret.start_offset}])
      expect_raises(ArgumentError, A1_PREFIX + "SemanticSignatureType") do
        Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      end
    end

    it "refuses a definition name anchored on the receiver" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      origin = adm_written(0, "Def", "keyword")
      signature = adm_signature("new", origin, receiver: "self")
      producer = Iyi::DiagnosticBoundProducer::SynthesizedConstructor.new(origin, "definition_name")
      rendered = ledger.render(ledger.open_site("signature", ADM_MODULE, nil, nil, origin), producer,
        adm_empty(ledger), Iyi::DiagnosticByteSpan.new(0, 0), "Crystal")
      receiver = adm_field(signature, Iyi::IyiMod::DiagnosticSignatureFieldKind::Receiver, -1)
      artifact = adm_artifact(functions: [signature])
      artifact.diagnostic_provenance = adm_misplaced(signature, [{rendered, receiver.start_offset}])
      expect_raises(ArgumentError, A1_PREFIX + "SynthesizedConstructor") do
        Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      end
    end

    it "refuses a definition name whose constructor is not named new" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      origin = adm_written(0, "Def", "keyword")
      signature = adm_signature("build", origin, receiver: "self")
      producer = Iyi::DiagnosticBoundProducer::SynthesizedConstructor.new(origin, "definition_name")
      rendered = ledger.render(ledger.open_site("signature", ADM_MODULE, nil, nil, origin), producer,
        adm_empty(ledger), Iyi::DiagnosticByteSpan.new(0, 0), "Crystal")
      name = adm_field(signature, Iyi::IyiMod::DiagnosticSignatureFieldKind::Name, -1)
      artifact = adm_artifact(functions: [signature])
      artifact.diagnostic_provenance = adm_misplaced(signature, [{rendered, name.start_offset}])
      expect_raises(ArgumentError, A1_PREFIX + "SynthesizedConstructor") do
        Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      end
    end

    it "refuses a ConstantAccessor name anchored on the receiver" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      origin = Iyi::DiagnosticOrigin::Synthetic.new(adm_written(0, "Assign", "constant"), "constant_accessor", "getter")
      signature = adm_signature("value", origin, receiver: "self")
      producer = Iyi::DiagnosticBoundProducer::ConstantAccessor.new(origin, "", "VALUE", "Name")
      rendered = ledger.render(ledger.open_site("signature", ADM_MODULE, nil, nil, origin), producer,
        adm_empty(ledger), Iyi::DiagnosticByteSpan.new(0, 0), "Crystal")
      receiver = adm_field(signature, Iyi::IyiMod::DiagnosticSignatureFieldKind::Receiver, -1)
      artifact = adm_artifact(functions: [signature])
      artifact.diagnostic_provenance = adm_misplaced(signature, [{rendered, receiver.start_offset}])
      expect_raises(ArgumentError, A1_PREFIX + "ConstantAccessor") do
        Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      end
    end

    it "refuses a ConstantAccessor name whose signature is not the accessor's name" do
      ledger = Iyi::DiagnosticProjectionLedger.new(AdmRecomputingAuthority.new)
      origin = Iyi::DiagnosticOrigin::Synthetic.new(adm_written(0, "Assign", "constant"), "constant_accessor", "getter")
      signature = adm_signature("other", origin, receiver: "self")
      producer = Iyi::DiagnosticBoundProducer::ConstantAccessor.new(origin, "", "VALUE", "Name")
      rendered = ledger.render(ledger.open_site("signature", ADM_MODULE, nil, nil, origin), producer,
        adm_empty(ledger), Iyi::DiagnosticByteSpan.new(0, 0), "Crystal")
      name = adm_field(signature, Iyi::IyiMod::DiagnosticSignatureFieldKind::Name, -1)
      artifact = adm_artifact(functions: [signature])
      artifact.diagnostic_provenance = adm_misplaced(signature, [{rendered, name.start_offset}])
      expect_raises(ArgumentError, A1_PREFIX + "ConstantAccessor") do
        Iyi::IyiMod.validate_diagnostic_fragments!(artifact, ledger)
      end
    end
  end
end
