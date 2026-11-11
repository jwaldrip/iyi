require "../spec_helper"
require "../support/syntax"

# SafeProjectionPlan §3 and ProjectionNoRegressionPlan §4 (S1): the per-section projection ledger.
#
# SpecBoundAuthority recomputes every producer as a fresh copy, so a test can tell the stored producer
# from the claim by identity. SpecRefusingAuthority refuses every producer. Each negative control changes
# one thing and must refuse with its own message. The mutation proofs are a table at the end. They are run
# by hand and are not examples.

class SpecBoundAuthority < Iyi::DiagnosticProjectionAuthority
  getter calls : Int32 = 0
  getter last : Iyi::DiagnosticBoundProducer? = nil
  property forged : Iyi::DiagnosticBoundProducer? = nil

  def recompute(request : Iyi::DiagnosticProjectionRequest) : Iyi::DiagnosticBoundProducer
    @calls += 1
    result = @forged || spec_copy(request.producer)
    @last = result
    result
  end
end

class SpecRefusingAuthority < Iyi::DiagnosticProjectionAuthority
  getter calls : Int32 = 0

  def recompute(request : Iyi::DiagnosticProjectionRequest) : Iyi::DiagnosticBoundProducer
    @calls += 1
    raise Iyi::DiagnosticProjectionAuthority.refused(request.producer)
  end
end

# Attests exactly one data object, by identity. Equal values do not attest.
class SpecInventory < Iyi::DiagnosticSourceInventory
  def initialize(@attested : Iyi::DiagnosticBoundProjectionData?)
  end

  def attests?(data : Iyi::DiagnosticBoundProjectionData) : Bool
    attested = @attested
    !attested.nil? && attested.same?(data)
  end
end

# A subclass of a closed producer class. It is not a closed class, so R3 refuses it.
class SpecStripRootSubclass < Iyi::DiagnosticBoundProducer::StripRoot
end

private def spec_copy(producer : Iyi::DiagnosticBoundProducer) : Iyi::DiagnosticBoundProducer
  case producer
  when Iyi::DiagnosticBoundProducer::StripRoot
    Iyi::DiagnosticBoundProducer::StripRoot.new(producer.root)
  when Iyi::DiagnosticBoundProducer::ForeignType
    Iyi::DiagnosticBoundProducer::ForeignType.new(producer.module_name, producer.source_name, producer.qualified_name)
  when Iyi::DiagnosticBoundProducer::AliasType
    Iyi::DiagnosticBoundProducer::AliasType.new(producer.owner, producer.name, producer.resolved_type)
  when Iyi::DiagnosticBoundProducer::SelfReturn
    Iyi::DiagnosticBoundProducer::SelfReturn.new(producer.owner_type, producer.method_name, producer.receiver)
  when Iyi::DiagnosticBoundProducer::SemanticSignatureType
    Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(producer.definition_origin, producer.field,
      producer.parameter_index, producer.semantic_type)
  when Iyi::DiagnosticBoundProducer::UninitializedClassVar
    Iyi::DiagnosticBoundProducer::UninitializedClassVar.new(producer.declaration_origin, producer.owner_type,
      producer.variable_name, producer.semantic_type)
  when Iyi::DiagnosticBoundProducer::ConstantAccessor
    Iyi::DiagnosticBoundProducer::ConstantAccessor.new(producer.definition_origin, producer.prefix,
      producer.constant_name, producer.part)
  when Iyi::DiagnosticBoundProducer::ResolvedRestriction
    Iyi::DiagnosticBoundProducer::ResolvedRestriction.new(producer.owner_type, producer.written_type,
      producer.resolved_type, producer.root, producer.add_global)
  when Iyi::DiagnosticBoundProducer::SynthesizedConstructor
    Iyi::DiagnosticBoundProducer::SynthesizedConstructor.new(producer.definition_origin, producer.part)
  when Iyi::DiagnosticBoundProducer::ConstantTarget
    Iyi::DiagnosticBoundProducer::ConstantTarget.new(producer.declaration_origin, producer.path)
  else
    raise ArgumentError.new("spec copy has no closed producer")
  end
end

private def spec_written(offset : Int32, kind : String, role : String) : Iyi::DiagnosticOrigin::Written
  Iyi::DiagnosticOrigin::Written.new("app/main", "/absent/bind.cr", offset, kind, role)
end

# A registered source with no text. Every source-free producer renders from it.
private def spec_empty(ledger : Iyi::DiagnosticProjectionLedger) : Iyi::DiagnosticRenderedFragment
  ledger.register_source(Iyi::DiagnosticRenderedFragment.new("",
    Iyi::DiagnosticFragmentData.new("", [] of Iyi::DiagnosticTokenEvent, [] of Iyi::DiagnosticAnchor)))
end

# A registered source whose spans are CONST path segments, each anchored to its own source token.
# Also returns the source names those spans describe.
private def spec_names(ledger : Iyi::DiagnosticProjectionLedger, text : String,
                       spans : Array({Int32, Int32})) : {Iyi::DiagnosticRenderedFragment, Array(Iyi::DiagnosticBoundNameSource)}
  guard = ::Crystal::Digest::SHA256.hexdigest(text)
  builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
  names = [] of Iyi::DiagnosticBoundNameSource
  spans.each do |first, last|
    origin = spec_written(first, "Name", "path_segment")
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

# A new data object over the same events and anchors. Its identity is not registered.
private def spec_copy_fragment(fragment : Iyi::DiagnosticRenderedFragment) : Iyi::DiagnosticRenderedFragment
  Iyi::DiagnosticRenderedFragment.new(fragment.text,
    Iyi::DiagnosticFragmentData.new(fragment.text, fragment.data.events, fragment.data.anchors))
end

private def spec_render(ledger : Iyi::DiagnosticProjectionLedger, site : Iyi::DiagnosticBoundSite,
                        producer : Iyi::DiagnosticBoundProducer, before : Iyi::DiagnosticRenderedFragment,
                        span_end : Int32) : Iyi::DiagnosticRenderedFragment
  ledger.render(site, producer, before, Iyi::DiagnosticByteSpan.new(0, span_end), "Crystal")
end

# A minted projection has the expected text, is registered and issued, and every anchor carries a
# DerivedName whose stored producer is the one the authority recomputed.
private def spec_expect_minted(ledger : Iyi::DiagnosticProjectionLedger, authority : SpecBoundAuthority,
                               producer : Iyi::DiagnosticBoundProducer, result : Iyi::DiagnosticRenderedFragment,
                               text : String)
  result.text.should eq(text)
  ledger.registered?(result).should be_true
  result.data.anchors.should_not be_empty
  result.data.anchors.each do |anchor|
    origin = anchor.origin.not_nil!.as(Iyi::DiagnosticOrigin::DerivedName)
    origin.producer.should eq(producer)
    origin.producer.not_nil!.same?(authority.last.not_nil!).should be_true
    ledger.issued?(origin).should be_true
  end
end

private def spec_mint(ledger : Iyi::DiagnosticProjectionLedger, authority : SpecBoundAuthority,
                      site : Iyi::DiagnosticBoundSite, producer : Iyi::DiagnosticBoundProducer,
                      before : Iyi::DiagnosticRenderedFragment, span_end : Int32, text : String) : Iyi::DiagnosticRenderedFragment
  result = spec_render(ledger, site, producer, before, span_end)
  spec_expect_minted(ledger, authority, producer, result, text)
  result
end

# A fragment whose anchors all name `projection` in their slots, one anchor per span. Each origin is given
# separately, so the same projection can be an anchor's origin, or another anchor's name, or both.
private def spec_shared_fragment(text : String, spans : Array({Int32, Int32}), origins : Array(Iyi::DiagnosticOrigin),
                                 projection : Iyi::DiagnosticOrigin::DerivedName) : Iyi::DiagnosticRenderedFragment
  builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
  spans.each_with_index do |(first, last), index|
    slot = Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::PathSegment, 0)
    builder.add_written_anchor(first, last, text, Iyi::DiagnosticRenderedLexContext::TypeName, "Name", "path_segment",
      origins[index], {slot => [Iyi::DiagnosticNameValue::Derived.new(projection)] of Iyi::DiagnosticNameValue})
  end
  Iyi::DiagnosticRenderedFragment.new(text, builder.finish_data(text))
end

private def spec_with_temporary_file(&)
  path = File.tempname("authority", ".iyimod")
  begin
    yield path
  ensure
    File.delete(path) if File.exists?(path)
  end
end

private def spec_artifact(initialiser : String = "") : Iyi::IyiMod::Artifact
  Iyi::IyiMod::Artifact.new(
    module_name: "app/main",
    source_path: "/src/app/main.cr",
    compiler_version: "1.22.0-dev+abc1234",
    target_triple: "x86_64-pc-linux-gnu",
    flags: ["bits64", "linux"],
    imports: [] of Iyi::IyiMod::ImportEdge,
    exports: Iyi::IyiMod::Exports.empty,
    initialiser: initialiser,
  )
end


describe "diagnostic bound projection authority" do
  describe "positive controls minted through the ledger" do
    it "P1 mints StripRoot from a source-bearing fragment" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      site = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      spec_mint(ledger, authority, site, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), before, 11, "Thing")
    end

    it "P2 mints ForeignType from a source-bearing fragment" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      site = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Thing", [{0, 5}])
      producer = Iyi::DiagnosticBoundProducer::ForeignType.new("other", "Thing", "Other::Thing")
      spec_mint(ledger, authority, site, producer, before, 5, "Other::Thing")
    end

    it "P3 mints AliasType from a source-bearing fragment" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      site = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Thing", [{0, 5}])
      producer = Iyi::DiagnosticBoundProducer::AliasType.new("Owner", "Thing", "Other")
      spec_mint(ledger, authority, site, producer, before, 5, "Other")
    end

    it "P4 mints SelfReturn at a signature site" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      site = ledger.open_site("signature", "Owner")
      before, _ = spec_names(ledger, "Owner", [{0, 5}])
      producer = Iyi::DiagnosticBoundProducer::SelfReturn.new("Owner", "new", "self")
      spec_mint(ledger, authority, site, producer, before, 5, "self")
    end

    it "P5 mints SemanticSignatureType at its declaration site" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      origin = spec_written(0, "Def", "keyword")
      site = ledger.open_site("signature", "", nil, nil, origin)
      producer = Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(origin, "return_type", nil, "Int32")
      spec_mint(ledger, authority, site, producer, spec_empty(ledger), 0, "Int32")
    end

    it "P6 mints UninitializedClassVar at its class-variable site" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      origin = spec_written(0, "Name", "class_variable")
      site = ledger.open_site("class_var", "Owner", "@@cache", nil, origin)
      producer = Iyi::DiagnosticBoundProducer::UninitializedClassVar.new(origin, "Owner", "@@cache", "Int32")
      spec_mint(ledger, authority, site, producer, spec_empty(ledger), 0, "uninitialized Int32")
    end

    it "P7 mints ConstantAccessor at its signature site" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      getter = Iyi::DiagnosticOrigin::Synthetic.new(spec_written(0, "Assign", "constant"), "constant_accessor", "getter")
      site = ledger.open_site("signature", "", nil, nil, getter)
      producer = Iyi::DiagnosticBoundProducer::ConstantAccessor.new(getter, "", "Thing", "Name")
      spec_mint(ledger, authority, site, producer, spec_empty(ledger), 0, "thing")
    end

    it "P8 mints ResolvedRestriction with a global prefix" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      site = ledger.open_site("signature", "Owner")
      before, _ = spec_names(ledger, "Thing", [{0, 5}])
      producer = Iyi::DiagnosticBoundProducer::ResolvedRestriction.new("Owner", "Thing", "Other::Thing", "Root", true)
      spec_mint(ledger, authority, site, producer, before, 5, "::Other::Thing")
    end

    it "P9 mints SynthesizedConstructor for the definition name" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      origin = spec_written(0, "Def", "keyword")
      site = ledger.open_site("signature", "", nil, nil, origin)
      producer = Iyi::DiagnosticBoundProducer::SynthesizedConstructor.new(origin, "definition_name")
      spec_mint(ledger, authority, site, producer, spec_empty(ledger), 0, "new")
    end

    it "P10 mints SynthesizedConstructor for the local receiver" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      origin = spec_written(0, "Def", "keyword")
      site = ledger.open_site("signature", "", nil, nil, origin)
      producer = Iyi::DiagnosticBoundProducer::SynthesizedConstructor.new(origin, "local_reference")
      spec_mint(ledger, authority, site, producer, spec_empty(ledger), 0, "self")
    end

    it "P11 mints ConstantTarget under its open initialiser" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      initialiser = ledger.open_site("initialiser", "")
      origin = spec_written(0, "Assign", "constant")
      site = ledger.open_site("constant", "", nil, nil, origin, initialiser)
      producer = Iyi::DiagnosticBoundProducer::ConstantTarget.new(origin, "Inner::NAME")
      spec_mint(ledger, authority, site, producer, spec_empty(ledger), 0, "Inner::NAME")
    end

    it "P12 keeps a struct copy of a registered fragment registered" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      site = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Thing", [{0, 5}])
      result = spec_render(ledger, site, Iyi::DiagnosticBoundProducer::AliasType.new("Owner", "Thing", "Other"), before, 5)
      ledger.registered?(Iyi::DiagnosticRenderedFragment.new(result.text, result.data)).should be_true
    end

    it "P13 admits an empty-source SynthesizedConstructor through the raw constructor" do
      producer = Iyi::DiagnosticBoundProducer::SynthesizedConstructor.new(spec_written(0, "Def", "keyword"), "definition_name")
      origin = Iyi::DiagnosticOrigin::DerivedName.bound_projection(producer, ::Crystal::Digest::SHA256.hexdigest(""), "",
        [] of Iyi::DiagnosticBoundNameSource, "new", "Crystal", 0, 3, "IDENT", "definition_name")
      origin.producer.should eq(producer)
    end

    it "P14 composes a constant child into its initialiser, finishes and verifies the section" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      initialiser = ledger.open_site("initialiser", "")
      origin = spec_written(0, "Assign", "constant")
      child = ledger.open_site("constant", "", nil, nil, origin, initialiser)
      rendered = spec_mint(ledger, authority, child, Iyi::DiagnosticBoundProducer::ConstantTarget.new(origin, "Inner::NAME"),
        spec_empty(ledger), 0, "Inner::NAME")
      joined = ledger.compose(initialiser, spec_copy_fragment(rendered), [rendered])
      section = Iyi::IyiMod::DiagnosticSection.new
      section.add_fragment(ledger.finish(initialiser, joined, "initialiser"))
      # Inner::NAME has two path segments, and the parser mints one projection for each.
      ledger.verify_section!(section).should eq(2)
      ledger.counts.should eq({"ConstantTarget" => 2})
      ledger.verified?(section).should be_true
    end

    it "P15 counts issued projections per producer" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      site = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      spec_render(ledger, site, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), before, 11)
      ledger.counts.should eq({"StripRoot" => 1})
    end
  end

  describe "negative controls" do
    # N1: a raw constructor carrying source refuses with H3, through either entry point.
    it "N1 refuses a raw constructor that carries source" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      _, names = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      producer = Iyi::DiagnosticBoundProducer::StripRoot.new("Root")
      data = Iyi::DiagnosticBoundProjectionData.new(producer, ::Crystal::Digest::SHA256.hexdigest("Root::Thing"),
        "Root::Thing", names, "Thing", "Crystal", 0, 5, "CONST", "path_segment")
      error = expect_raises(ArgumentError) do
        Iyi::DiagnosticOrigin::DerivedName.new(data)
      end
      error.message.should eq("bound projection requires authoritative source inventory")
      error = expect_raises(ArgumentError) do
        Iyi::DiagnosticOrigin::DerivedName.bound_projection(producer, ::Crystal::Digest::SHA256.hexdigest("Root::Thing"),
          "Root::Thing", names, "Thing", "Crystal", 0, 5, "CONST", "path_segment")
      end
      error.message.should eq("bound projection requires authoritative source inventory")
    end

    # N1b: the ledger attests only the data object it is constructing, so the same object refuses outside render.
    it "N1b refuses a source-bearing DerivedName built with the ledger outside render" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      _, names = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      data = Iyi::DiagnosticBoundProjectionData.new(Iyi::DiagnosticBoundProducer::StripRoot.new("Root"),
        ::Crystal::Digest::SHA256.hexdigest("Root::Thing"), "Root::Thing", names, "Thing", "Crystal", 0, 5, "CONST", "path_segment")
      error = expect_raises(ArgumentError) do
        Iyi::DiagnosticOrigin::DerivedName.new(data, ledger)
      end
      error.message.should eq("bound projection requires authoritative source inventory")
      ledger.attests?(data).should be_false
    end

    # N2: a before the ledger never registered refuses to render.
    it "N2 refuses a source the ledger never registered" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      site = ledger.open_site("initialiser", "")
      unregistered = Iyi::DiagnosticRenderedFragment.new("", Iyi::DiagnosticFragmentData.new("", [] of Iyi::DiagnosticTokenEvent, [] of Iyi::DiagnosticAnchor))
      error = expect_raises(ArgumentError) do
        spec_render(ledger, site, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), unregistered, 0)
      end
      error.message.should eq("bound projection source is not registered with its authority")
      authority.calls.should eq(0)
    end

    # Registration is by identity. An equal fragment built separately is not registered.
    it "N2b treats an equal fragment built separately as unregistered" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      registered = spec_empty(ledger)
      twin = Iyi::DiagnosticRenderedFragment.new("", Iyi::DiagnosticFragmentData.new("", [] of Iyi::DiagnosticTokenEvent, [] of Iyi::DiagnosticAnchor))
      ledger.registered?(registered).should be_true
      ledger.registered?(twin).should be_false
    end

    # N2c: equal text and equal values in a new data object are not the registered object.
    it "N2c treats equal text in a new data object as unregistered" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      registered = spec_empty(ledger)
      fresh = Iyi::DiagnosticRenderedFragment.new("", Iyi::DiagnosticFragmentData.new("", [] of Iyi::DiagnosticTokenEvent, [] of Iyi::DiagnosticAnchor))
      ledger.registered?(fresh).should be_false
      ledger.registered?(registered).should be_true
    end

    # N2d: the same data object with different text is not registered.
    it "N2d refuses the registered data object with different text" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      registered = spec_empty(ledger)
      retexted = Iyi::DiagnosticRenderedFragment.new("x", registered.data)
      ledger.registered?(retexted).should be_false
    end

    # N3: a refusal from the live authority reaches the caller with its kind.
    it "N3 refuses a projection the authority refuses" do
      authority = SpecRefusingAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      site = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      error = expect_raises(ArgumentError) do
        spec_render(ledger, site, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), before, 11)
      end
      error.message.should eq("bound projection replay refused: StripRoot")
      authority.calls.should eq(1)
    end

    # N4: a fragment registered by one ledger is refused by another.
    it "N4 refuses a fragment registered by another ledger" do
      owner = Iyi::DiagnosticProjectionLedger.new(SpecBoundAuthority.new)
      other_authority = SpecBoundAuthority.new
      other = Iyi::DiagnosticProjectionLedger.new(other_authority)
      other_site = other.open_site("initialiser", "")
      before, _ = spec_names(owner, "Root::Thing", [{0, 4}, {6, 11}])
      error = expect_raises(ArgumentError) do
        spec_render(other, other_site, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), before, 11)
      end
      error.message.should eq("bound projection source is not registered with its authority")
      owner.registered?(before).should be_true
      other.registered?(before).should be_false
      other_authority.calls.should eq(0)
    end

    # N5: a source-bearing origin written by DiagnosticOrigins refuses on read.
    it "N5 refuses a source-bearing origin after DiagnosticOrigins write then read" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      site = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      result = spec_render(ledger, site, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), before, 11)
      origin = result.data.anchors.first.origin.not_nil!
      table = Iyi::IyiMod::DiagnosticOrigins.new
      table.intern(origin)
      io = IO::Memory.new
      table.write(io)
      io.rewind
      error = expect_raises(ArgumentError) do
        Iyi::IyiMod::DiagnosticOrigins.read(io)
      end
      error.message.should eq("bound projection requires authoritative source inventory")
    end

    # N6: a source-bearing origin read from JSON refuses with H3.
    it "N6 refuses a source-bearing origin read from JSON" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      site = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      result = spec_render(ledger, site, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), before, 11)
      json = result.data.anchors.first.origin.not_nil!.to_json
      error = expect_raises(ArgumentError) do
        Iyi::DiagnosticOrigin.from_json(JSON.parse(json))
      end
      error.message.should eq("bound projection requires authoritative source inventory")
    end

    # N6b: a spec-only subclass is not a closed producer. R3 refuses it before the authority is called.
    it "N6b refuses a subclass of a closed producer before the authority is called" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      site = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      error = expect_raises(ArgumentError) do
        spec_render(ledger, site, SpecStripRootSubclass.new("Root"), before, 11)
      end
      error.message.should eq("bound producer is not a closed producer class")
      authority.calls.should eq(0)
    end

    # N7: an empty source passes the inventory check, and source without an inventory raises H3.
    it "N7 admits empty source only without an inventory" do
      producer = Iyi::DiagnosticBoundProducer::StripRoot.new("Root")
      empty = Iyi::DiagnosticBoundProjectionData.new(producer, ::Crystal::Digest::SHA256.hexdigest(""), "", [] of Iyi::DiagnosticBoundNameSource,
        "", "Crystal", 0, 0, "CONST", "path_segment")
      # Typed as the production caller types it, DiagnosticSourceInventory?, rather than a literal nil.
      none : Iyi::DiagnosticSourceInventory? = nil
      Iyi::DiagnosticBoundProjection.require_source_inventory!(empty, none).should be_nil
      Iyi::DiagnosticBoundProjection.require_source_inventory!(empty, SpecInventory.new(nil)).should be_nil
      sourced = Iyi::DiagnosticBoundProjectionData.new(producer, ::Crystal::Digest::SHA256.hexdigest("Root::Thing"),
        "Root::Thing", [] of Iyi::DiagnosticBoundNameSource, "Thing", "Crystal", 0, 5, "CONST", "path_segment")
      twin = Iyi::DiagnosticBoundProjectionData.new(producer, ::Crystal::Digest::SHA256.hexdigest("Root::Thing"),
        "Root::Thing", [] of Iyi::DiagnosticBoundNameSource, "Thing", "Crystal", 0, 5, "CONST", "path_segment")
      expect_raises(ArgumentError, "bound projection requires authoritative source inventory") do
        Iyi::DiagnosticBoundProjection.require_source_inventory!(sourced, none)
      end
      # Rejections go through the constructor, the path a raw claim takes and the one N1 already exercises.
      expect_raises(ArgumentError, "bound projection requires authoritative source inventory") do
        Iyi::DiagnosticOrigin::DerivedName.new(sourced)
      end
      expect_raises(ArgumentError, "bound projection requires authoritative source inventory") do
        Iyi::DiagnosticOrigin::DerivedName.new(sourced, SpecInventory.new(nil))
      end
      # Attestation is by identity: an equal twin does not attest the data object that was built.
      expect_raises(ArgumentError, "bound projection requires authoritative source inventory") do
        Iyi::DiagnosticOrigin::DerivedName.new(sourced, SpecInventory.new(twin))
      end
      inventory = SpecInventory.new(sourced)
      inventory.attests?(sourced).should be_true
      Iyi::DiagnosticBoundProjection.require_source_inventory!(sourced, inventory).should be_nil
    end

    # N8: inputs refused before the authority never reach it. Each case is a separate refusal.
    it "N8 makes zero authority calls for inputs refused before recompute" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      site = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      strip = Iyi::DiagnosticBoundProducer::StripRoot.new("Root")

      # R14: a site the ledger never opened.
      unopened = Iyi::DiagnosticBoundSite.new("initialiser", "", nil, nil, nil, nil)
      expect_raises(ArgumentError, "bound site is not open in this ledger") do
        spec_render(ledger, unopened, strip, before, 11)
      end

      # R16: the span cuts through the first name token.
      expect_raises(ArgumentError, "bound projection source splits a token") do
        spec_render(ledger, site, strip, before, 2)
      end

      # A missing source root.
      other, _ = spec_names(ledger, "Other::Thing", [{0, 5}, {7, 12}])
      expect_raises(ArgumentError, "missing source root") do
        spec_render(ledger, site, strip, other, 12)
      end

      # R17: an anchor inside the span carries no names.
      builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
      bare = spec_written(0, "Name", "path_segment")
      builder.add_written_anchor(0, 5, "Thing", Iyi::DiagnosticRenderedLexContext::TypeName, "Name", "path_segment", bare,
        Hash(Iyi::DiagnosticNameSlot, Array(Iyi::DiagnosticNameValue)).new)
      unnamed = ledger.register_source(Iyi::DiagnosticRenderedFragment.new("Thing", builder.finish_data("Thing")))
      expect_raises(ArgumentError, "bound projection would drop a non-name anchor") do
        spec_render(ledger, site, Iyi::DiagnosticBoundProducer::AliasType.new("Owner", "Thing", "Other"), unnamed, 5)
      end

      # A1: an empty-source producer at a site of the wrong kind.
      field = ledger.open_site("field", "Owner", "name")
      expect_raises(ArgumentError, "bound projection is not at its declaration site: SemanticSignatureType") do
        spec_render(ledger, field, Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(spec_written(0, "Def", "keyword"),
          "return_type", nil, "Int32"), spec_empty(ledger), 0)
      end

      authority.calls.should eq(0)
    end

    # N9: a replacement issued by another ledger is not issued for this edit (R5).
    it "N9 refuses an apply whose replacement this ledger never issued" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      site = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      other = Iyi::DiagnosticProjectionLedger.new(SpecBoundAuthority.new)
      other_site = other.open_site("initialiser", "")
      other_before, _ = spec_names(other, "Root::Thing", [{0, 4}, {6, 11}])
      replacement = spec_render(other, other_site, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), other_before, 11)
      edit = Iyi::DiagnosticByteEdit.new(Iyi::DiagnosticByteSpan.new(0, 11), "Root::Thing", replacement,
        Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), [] of Iyi::DiagnosticAnchorTransfer)
      error = expect_raises(ArgumentError) do
        ledger.apply(site, before, [edit], "Crystal")
      end
      error.message.should eq("bound projection replacement was not issued for this edit")
    end

    # N10: the same text in a twin before is not the issued before object (R5).
    it "N10 refuses a replacement issued for a different before object" do
      ledger = Iyi::DiagnosticProjectionLedger.new(SpecBoundAuthority.new)
      site = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      producer = Iyi::DiagnosticBoundProducer::StripRoot.new("Root")
      issued = spec_render(ledger, site, producer, before, 11)
      twin = ledger.register_source(Iyi::DiagnosticRenderedFragment.new(before.text,
        Iyi::DiagnosticFragmentData.new(before.text, before.data.events, before.data.anchors)))
      edit = Iyi::DiagnosticByteEdit.new(Iyi::DiagnosticByteSpan.new(0, 11), "Root::Thing", issued, producer,
        [] of Iyi::DiagnosticAnchorTransfer)
      error = expect_raises(ArgumentError) do
        ledger.apply(site, twin, [edit], "Crystal")
      end
      error.message.should eq("bound projection replacement was not issued for this edit")
    end

    # N11: a replacement issued for another span is not issued for this edit (R5).
    it "N11 refuses a replacement issued for a different span" do
      ledger = Iyi::DiagnosticProjectionLedger.new(SpecBoundAuthority.new)
      site = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      producer = Iyi::DiagnosticBoundProducer::StripRoot.new("Root")
      issued = spec_render(ledger, site, producer, before, 11)
      edit = Iyi::DiagnosticByteEdit.new(Iyi::DiagnosticByteSpan.new(0, 5), "Root::", issued, producer,
        [] of Iyi::DiagnosticAnchorTransfer)
      error = expect_raises(ArgumentError) do
        ledger.apply(site, before, [edit], "Crystal")
      end
      error.message.should eq("bound projection replacement was not issued for this edit")
    end

    # N12: a source may not carry a bound projection (R6), even as a new data object over issued anchors.
    it "N12 refuses a source fragment that carries a bound projection" do
      ledger = Iyi::DiagnosticProjectionLedger.new(SpecBoundAuthority.new)
      site = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      issued = spec_render(ledger, site, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), before, 11)
      error = expect_raises(ArgumentError) do
        ledger.register_source(spec_copy_fragment(issued))
      end
      error.message.should eq("bound source fragment carries a bound projection")
    end

    # N13: a part from another site cannot be composed into this one (R7).
    it "N13 refuses a composition whose part belongs to another site" do
      ledger = Iyi::DiagnosticProjectionLedger.new(SpecBoundAuthority.new)
      first = ledger.open_site("initialiser", "A")
      second = ledger.open_site("initialiser", "B")
      before, _ = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      part = spec_render(ledger, first, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), before, 11)
      error = expect_raises(ArgumentError) do
        ledger.compose(second, spec_copy_fragment(part), [part])
      end
      error.message.should eq("bound fragment belongs to another site")
    end

    # N14: a projection placed outside the anchor that owns it is refused (R10). A valid fragment cannot name a
    # projection from an anchor it does not belong to: validate_canonical! refuses that first. So the guard is
    # exercised on the reach walk's hits, which is where the ledger reads them.
    it "N14 refuses a projection placed outside its own anchor" do
      ledger = Iyi::DiagnosticProjectionLedger.new(SpecBoundAuthority.new)
      initialiser = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      issued = spec_render(ledger, initialiser, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), before, 11)
      projection = issued.data.anchors.first.origin.not_nil!.as(Iyi::DiagnosticOrigin::DerivedName)
      anchors = issued.data.anchors
      # Anchor 1 names the projection that anchor 0 owns.
      expect_raises(ArgumentError, "bound projection lies outside its anchor") do
        Iyi::DiagnosticProjectionReach.owners([
          Iyi::DiagnosticProjectionReach::Hit.new(projection, :anchor_origin, 0),
          Iyi::DiagnosticProjectionReach::Hit.new(projection, :name_slot, 1),
        ], anchors)
      end
      # The projection is nested under an origin that is not an anchor's own origin, so no anchor owns it.
      expect_raises(ArgumentError, "bound projection lies outside its anchor") do
        Iyi::DiagnosticProjectionReach.owners([Iyi::DiagnosticProjectionReach::Hit.new(projection, :nested, 0)], anchors)
      end
      # Control: the owner's own name slot is placed correctly, and the owner map records it.
      owners = Iyi::DiagnosticProjectionReach.owners([
        Iyi::DiagnosticProjectionReach::Hit.new(projection, :anchor_origin, 0),
        Iyi::DiagnosticProjectionReach::Hit.new(projection, :name_slot, 0),
      ], anchors)
      owners[projection]?.should eq(0)
    end

    # N15: a projection placed twice in one fragment is refused (R9).
    it "N15 refuses a composition that places one projection twice" do
      ledger = Iyi::DiagnosticProjectionLedger.new(SpecBoundAuthority.new)
      initialiser = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      projection = spec_render(ledger, initialiser, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), before, 11).data.anchors.first.origin.not_nil!.as(Iyi::DiagnosticOrigin::DerivedName)
      # One issued projection is the origin of two anchors at two distinct positions. Each span holds its rendered bytes.
      doubled = spec_shared_fragment("Thing::Thing", [{0, 5}, {7, 12}], [projection.as(Iyi::DiagnosticOrigin), projection.as(Iyi::DiagnosticOrigin)], projection)
      error = expect_raises(ArgumentError) do
        ledger.compose(initialiser, doubled, [] of Iyi::DiagnosticRenderedFragment)
      end
      error.message.should eq("bound projection appears more than once")
    end

    # N16: a claim that was never issued cannot be placed in a finished fragment (R8).
    it "N16 refuses a value-equal claim at compose time" do
      ledger = Iyi::DiagnosticProjectionLedger.new(SpecBoundAuthority.new)
      initialiser = ledger.open_site("initialiser", "")
      getter = Iyi::DiagnosticOrigin::Synthetic.new(spec_written(0, "Assign", "constant"), "constant_accessor", "getter")
      producer = Iyi::DiagnosticBoundProducer::ConstantAccessor.new(getter, "", "Thing", "Name")
      kind = Iyi::DiagnosticRenderedTokens.observe_one("thing", 0, 5, "Crystal", Iyi::DiagnosticRenderedLexContext::DefOrMacroName).token_kind
      claim = Iyi::DiagnosticOrigin::DerivedName.bound_projection(producer, ::Crystal::Digest::SHA256.hexdigest(""), "",
        [] of Iyi::DiagnosticBoundNameSource, "thing", "Crystal", 0, 5, kind, "definition_name")
      slot = Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::Primary)
      builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
      builder.add_written_anchor(0, 5, "thing", Iyi::DiagnosticRenderedLexContext::DefOrMacroName, "Name", "definition_name",
        claim, {slot => [Iyi::DiagnosticNameValue::Derived.new(claim)] of Iyi::DiagnosticNameValue})
      forged = Iyi::DiagnosticRenderedFragment.new("thing", builder.finish_data("thing"))
      error = expect_raises(ArgumentError) do
        ledger.compose(initialiser, forged, [] of Iyi::DiagnosticRenderedFragment)
      end
      error.message.should eq("bound projection was not issued by this ledger")
    end

    # N17: a projection issued by another ledger is not issued by this one (R8).
    it "N17 refuses a projection another ledger issued" do
      other = Iyi::DiagnosticProjectionLedger.new(SpecBoundAuthority.new)
      other_site = other.open_site("initialiser", "")
      other_before, _ = spec_names(other, "Root::Thing", [{0, 4}, {6, 11}])
      foreign = spec_render(other, other_site, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), other_before, 11)
      ledger = Iyi::DiagnosticProjectionLedger.new(SpecBoundAuthority.new)
      site = ledger.open_site("initialiser", "")
      expect_raises(ArgumentError, "bound projection was not issued by this ledger") do
        ledger.compose(site, spec_copy_fragment(foreign), [] of Iyi::DiagnosticRenderedFragment)
      end
    end

    # N18: each empty-source producer refuses a wrong declaration or a wrong site kind (A1).
    it "N18 refuses empty-source producers at a wrong declaration" do
      ledger = Iyi::DiagnosticProjectionLedger.new(SpecBoundAuthority.new)
      declared = spec_written(0, "Def", "keyword")
      elsewhere = spec_written(9, "Def", "keyword")
      signature = ledger.open_site("signature", "", nil, nil, declared)
      expect_raises(ArgumentError, "bound projection is not at its declaration site: SynthesizedConstructor") do
        spec_render(ledger, signature, Iyi::DiagnosticBoundProducer::SynthesizedConstructor.new(elsewhere, "definition_name"),
          spec_empty(ledger), 0)
      end
      # ConstantTarget needs an Assign origin. It is refused here by its site kind, since a signature site is not a constant site.
      assign = spec_written(0, "Assign", "constant")
      expect_raises(ArgumentError, "bound projection is not at its declaration site: ConstantTarget") do
        spec_render(ledger, signature, Iyi::DiagnosticBoundProducer::ConstantTarget.new(assign, "Inner::NAME"), spec_empty(ledger), 0)
      end
      # A constant site under its own initialiser, whose declaration is a different Assign: the declaration tie refuses it.
      initialiser = ledger.open_site("initialiser", "")
      other_assign = spec_written(9, "Assign", "constant")
      constant = ledger.open_site("constant", "", nil, nil, other_assign, initialiser)
      expect_raises(ArgumentError, "bound projection is not at its declaration site: ConstantTarget") do
        spec_render(ledger, constant, Iyi::DiagnosticBoundProducer::ConstantTarget.new(assign, "Inner::NAME"), spec_empty(ledger), 0)
      end
      classvar = ledger.open_site("class_var", "Owner", "@@other", nil, spec_written(0, "Name", "class_variable"))
      expect_raises(ArgumentError, "bound projection is not at its declaration site: UninitializedClassVar") do
        spec_render(ledger, classvar, Iyi::DiagnosticBoundProducer::UninitializedClassVar.new(spec_written(0, "Name", "class_variable"),
          "Owner", "@@cache", "Int32"), spec_empty(ledger), 0)
      end
    end

    # R4: the recomputed producer must be the claim's exact class and equal by value.
    it "R4 refuses a recomputed producer that differs from the claim" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      site = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      claim = Iyi::DiagnosticBoundProducer::StripRoot.new("Root")
      [Iyi::DiagnosticBoundProducer::StripRoot.new("Other").as(Iyi::DiagnosticBoundProducer),
       Iyi::DiagnosticBoundProducer::ForeignType.new("Root", "Root", "Root").as(Iyi::DiagnosticBoundProducer),
       SpecStripRootSubclass.new("Root").as(Iyi::DiagnosticBoundProducer)].each do |forged|
        authority.forged = forged
        error = expect_raises(ArgumentError) do
          spec_render(ledger, site, claim, before, 11)
        end
        error.message.should eq("bound projection replay differs from claimed producer")
      end
    end

    # R13: a site can be opened once.
    it "R13 refuses to open the same site twice" do
      ledger = Iyi::DiagnosticProjectionLedger.new(SpecBoundAuthority.new)
      ledger.open_site("initialiser", "")
      expect_raises(ArgumentError, "bound site is already open") do
        ledger.open_site("initialiser", "")
      end
    end

    # R18: a site is finished once.
    it "R18 refuses to finish the same site twice" do
      ledger = Iyi::DiagnosticProjectionLedger.new(SpecBoundAuthority.new)
      initialiser = ledger.open_site("initialiser", "")
      empty = Iyi::DiagnosticRenderedFragment.new("", Iyi::DiagnosticFragmentData.new("", [] of Iyi::DiagnosticTokenEvent, [] of Iyi::DiagnosticAnchor))
      ledger.compose(initialiser, empty, [] of Iyi::DiagnosticRenderedFragment)
      ledger.finish(initialiser, empty, "initialiser")
      expect_raises(ArgumentError, "bound site was already finished") do
        ledger.finish(initialiser, empty, "initialiser")
      end
    end

    # R15: a finished key must be the one its site produces.
    it "R15 refuses a finished key that differs from the initialiser key" do
      ledger = Iyi::DiagnosticProjectionLedger.new(SpecBoundAuthority.new)
      initialiser = ledger.open_site("initialiser", "")
      empty = Iyi::DiagnosticRenderedFragment.new("", Iyi::DiagnosticFragmentData.new("", [] of Iyi::DiagnosticTokenEvent, [] of Iyi::DiagnosticAnchor))
      ledger.compose(initialiser, empty, [] of Iyi::DiagnosticRenderedFragment)
      expect_raises(ArgumentError, "bound site key differs from its declaration") do
        ledger.finish(initialiser, empty, "not-the-initialiser")
      end
    end

    # R11a and R11: a section must hold the finished projections and nothing more.
    it "R11a refuses a section that holds a projection nobody finished" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      initialiser = ledger.open_site("initialiser", "")
      first_origin = spec_written(0, "Assign", "constant")
      first = spec_render(ledger, ledger.open_site("constant", "", nil, nil, first_origin, initialiser),
        Iyi::DiagnosticBoundProducer::ConstantTarget.new(first_origin, "Inner::NAME"), spec_empty(ledger), 0)
      # The stray site is opened while the initialiser is still open. Once it is finished, R14 refuses any new site.
      stray_origin = spec_written(1, "Assign", "constant")
      stray = spec_render(ledger, ledger.open_site("constant", "", nil, nil, stray_origin, initialiser),
        Iyi::DiagnosticBoundProducer::ConstantTarget.new(stray_origin, "Other::NAME"), spec_empty(ledger), 0)
      joined = ledger.compose(initialiser, spec_copy_fragment(first), [first])
      finished = ledger.finish(initialiser, joined, "initialiser")
      section = Iyi::IyiMod::DiagnosticSection.new
      section.add_fragment(finished)
      section.add_fragment(stray.data.to_fragment("stray"))
      expect_raises(ArgumentError, "bound projection count differs from minted") do
        ledger.verify_section!(section)
      end
    end

    it "R11 refuses a section missing a finished key" do
      ledger = Iyi::DiagnosticProjectionLedger.new(SpecBoundAuthority.new)
      initialiser = ledger.open_site("initialiser", "")
      empty = Iyi::DiagnosticRenderedFragment.new("", Iyi::DiagnosticFragmentData.new("", [] of Iyi::DiagnosticTokenEvent, [] of Iyi::DiagnosticAnchor))
      ledger.compose(initialiser, empty, [] of Iyi::DiagnosticRenderedFragment)
      ledger.finish(initialiser, empty, "initialiser")
      expect_raises(ArgumentError, "bound section differs from finished fragments") do
        ledger.verify_section!(Iyi::IyiMod::DiagnosticSection.new)
      end
    end

    # R19: a projection filed under a key other than its site's finished key.
    it "R19 refuses a projection placed under another key" do
      ledger = Iyi::DiagnosticProjectionLedger.new(SpecBoundAuthority.new)
      initialiser = ledger.open_site("initialiser", "")
      origin = spec_written(0, "Assign", "constant")
      child = ledger.open_site("constant", "", nil, nil, origin, initialiser)
      rendered = spec_render(ledger, child, Iyi::DiagnosticBoundProducer::ConstantTarget.new(origin, "Inner::NAME"),
        spec_empty(ledger), 0)
      joined = ledger.compose(initialiser, spec_copy_fragment(rendered), [rendered])
      finished = ledger.finish(initialiser, joined, "initialiser")
      section = Iyi::IyiMod::DiagnosticSection.new
      section.add_fragment(Iyi::IyiMod::DiagnosticFragment.new("elsewhere", finished.text_sha256, finished.events, finished.anchors))
      expect_raises(ArgumentError, "bound projection was issued for another site") do
        ledger.verify_section!(section)
      end
    end

    # R12: a verified section is sealed.
    it "R12 refuses a render after the section is verified" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      initialiser = ledger.open_site("initialiser", "")
      empty = Iyi::DiagnosticRenderedFragment.new("", Iyi::DiagnosticFragmentData.new("", [] of Iyi::DiagnosticTokenEvent, [] of Iyi::DiagnosticAnchor))
      ledger.compose(initialiser, empty, [] of Iyi::DiagnosticRenderedFragment)
      section = Iyi::IyiMod::DiagnosticSection.new
      section.add_fragment(ledger.finish(initialiser, empty, "initialiser"))
      ledger.verify_section!(section).should eq(0)
      before, _ = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      expect_raises(ArgumentError, "bound projection ledger is sealed") do
        spec_render(ledger, initialiser, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), before, 11)
      end
      authority.calls.should eq(0)
    end

    # R9: a projection appearing twice inside one fragment is refused by the walk.
    it "R9 refuses a fragment whose anchor repeats a projection" do
      ledger = Iyi::DiagnosticProjectionLedger.new(SpecBoundAuthority.new)
      initialiser = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      projection = spec_render(ledger, initialiser, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), before, 11).data.anchors.first.origin.not_nil!.as(Iyi::DiagnosticOrigin::DerivedName)
      doubled = spec_shared_fragment("Thing::Thing", [{0, 5}, {7, 12}], [projection.as(Iyi::DiagnosticOrigin), projection.as(Iyi::DiagnosticOrigin)], projection)
      expect_raises(ArgumentError, "bound projection appears more than once") do
        ledger.compose(initialiser, doubled, [] of Iyi::DiagnosticRenderedFragment)
      end
      # A refused compose leaves nothing behind: the doubled fragment is not registered, and the projection stays issued.
      ledger.registered?(doubled).should be_false
      ledger.issued?(projection).should be_true
    end

    # Adversarial controls: ledger integrity validations
    it "invalidates a verified section on array or hash mutation" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      initialiser = ledger.open_site("initialiser", "")
      origin = spec_written(0, "Assign", "constant")
      child = ledger.open_site("constant", "", nil, nil, origin, initialiser)
      rendered = spec_mint(ledger, authority, child, Iyi::DiagnosticBoundProducer::ConstantTarget.new(origin, "Inner::NAME"),
        spec_empty(ledger), 0, "Inner::NAME")
      joined = ledger.compose(initialiser, spec_copy_fragment(rendered), [rendered])
      finished = ledger.finish(initialiser, joined, "initialiser")

      section = Iyi::IyiMod::DiagnosticSection.new
      section.add_fragment(finished)
      ledger.verify_section!(section).should eq(2)
      ledger.verified?(section).should be_true

      artifact = spec_artifact("Inner::NAME")
      artifact.diagnostic_provenance = section

      # Array mutation 1: mutate anchors array by appending an anchor
      extra_anchor = finished.anchors.first.copy_with(offset: 99)
      section.fragments["initialiser"].anchors << extra_anchor
      ledger.verified?(section).should be_false
      spec_with_temporary_file do |path|
        expect_raises(Iyi::IyiMod::Error, "bound section was not verified by its issuer") do
          Iyi::IyiMod.write(artifact, path, ledger)
        end
      end
      section.fragments["initialiser"].anchors.pop
      ledger.verified?(section).should be_true

      # Array mutation 2: mutate events array by popping an event
      popped_event = section.fragments["initialiser"].events.pop
      ledger.verified?(section).should be_false
      spec_with_temporary_file do |path|
        expect_raises(Iyi::IyiMod::Error, "bound section was not verified by its issuer") do
          Iyi::IyiMod.write(artifact, path, ledger)
        end
      end
      section.fragments["initialiser"].events << popped_event
      ledger.verified?(section).should be_true

      # Hash mutation 1: add a new fragment key to section.fragments
      stray_frag = Iyi::IyiMod::DiagnosticFragment.new("stray", finished.text_sha256, finished.events.dup, finished.anchors.dup)
      section.fragments["stray"] = stray_frag
      ledger.verified?(section).should be_false
      spec_with_temporary_file do |path|
        expect_raises(Iyi::IyiMod::Error, "bound section was not verified by its issuer") do
          Iyi::IyiMod.write(artifact, path, ledger)
        end
      end
      section.fragments.delete("stray")
      ledger.verified?(section).should be_true

      # Hash mutation 2: replace fragment with a substituted fragment
      other_frag = Iyi::IyiMod::DiagnosticFragment.new("initialiser", ::Crystal::Digest::SHA256.hexdigest("x"),
        [] of Iyi::DiagnosticTokenEvent, [] of Iyi::DiagnosticAnchor)
      section.fragments["initialiser"] = other_frag
      ledger.verified?(section).should be_false
      spec_with_temporary_file do |path|
        expect_raises(Iyi::IyiMod::Error, "bound section was not verified by its issuer") do
          Iyi::IyiMod.write(artifact, path, ledger)
        end
      end
      section.fragments["initialiser"] = finished
      ledger.verified?(section).should be_true

      # Mutation 3: move an issued projection across keys
      moved_anchor = section.fragments["initialiser"].anchors.pop
      section.fragments["other"] = Iyi::IyiMod::DiagnosticFragment.new("other", finished.text_sha256, finished.events.dup, [moved_anchor])
      ledger.verified?(section).should be_false
      spec_with_temporary_file do |path|
        expect_raises(Iyi::IyiMod::Error, "bound section was not verified by its issuer") do
          Iyi::IyiMod.write(artifact, path, ledger)
        end
      end
      section.fragments.delete("other")
      section.fragments["initialiser"].anchors << moved_anchor
      ledger.verified?(section).should be_true

      # Mutation 4: duplicate an issued projection across fragments
      section.fragments["dup"] = Iyi::IyiMod::DiagnosticFragment.new("dup", finished.text_sha256, finished.events.dup, [finished.anchors.first])
      ledger.verified?(section).should be_false
      spec_with_temporary_file do |path|
        expect_raises(Iyi::IyiMod::Error, "bound section was not verified by its issuer") do
          Iyi::IyiMod.write(artifact, path, ledger)
        end
      end
    end

    it "R11 refuses same-key fragment substitution with altered content or shifted anchor offset" do
      authority = SpecBoundAuthority.new
      ledger = Iyi::DiagnosticProjectionLedger.new(authority)
      initialiser = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      rendered = spec_render(ledger, initialiser, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), before, 11)
      joined = ledger.compose(initialiser, spec_copy_fragment(rendered), [rendered])
      finished = ledger.finish(initialiser, joined, "initialiser")

      # Substitution 1: Same key and projection identity, but altered text hash
      section1 = Iyi::IyiMod::DiagnosticSection.new
      altered_hash_frag = Iyi::IyiMod::DiagnosticFragment.new("initialiser",
        ::Crystal::Digest::SHA256.hexdigest("altered_text"), finished.events.dup, finished.anchors.dup)
      section1.add_fragment(altered_hash_frag)
      expect_raises(ArgumentError, "bound section differs from finished fragments") do
        ledger.verify_section!(section1)
      end

      # Substitution 2: Same key and projection identity, but shifted anchor offset
      ledger2 = Iyi::DiagnosticProjectionLedger.new(authority)
      initialiser2 = ledger2.open_site("initialiser", "")
      before2, _ = spec_names(ledger2, "Root::Thing", [{0, 4}, {6, 11}])
      rendered2 = spec_render(ledger2, initialiser2, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), before2, 11)
      joined2 = ledger2.compose(initialiser2, spec_copy_fragment(rendered2), [rendered2])
      finished2 = ledger2.finish(initialiser2, joined2, "initialiser")

      section2 = Iyi::IyiMod::DiagnosticSection.new
      shifted_anchors = [finished2.anchors.first.copy_with(offset: finished2.anchors.first.offset + 1)]
      shifted_frag = Iyi::IyiMod::DiagnosticFragment.new("initialiser", finished2.text_sha256, finished2.events.dup, shifted_anchors)
      section2.add_fragment(shifted_frag)
      expect_raises(ArgumentError, "bound section differs from finished fragments") do
        ledger2.verify_section!(section2)
      end
    end

    it "R5 refuses an apply whose replacement pads or alters the issued render" do
      ledger = Iyi::DiagnosticProjectionLedger.new(SpecBoundAuthority.new)
      site = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      producer = Iyi::DiagnosticBoundProducer::StripRoot.new("Root")
      rendered = spec_render(ledger, site, producer, before, 11)
      projection_origin = rendered.data.anchors.first.origin.not_nil!

      # Construct a replacement whose text is padded ("Evil::Thing" instead of "Thing")
      # but embedding the exact issued projection origin for the edit
      padded_text = "Evil::Thing"
      builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
      slot = Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::PathSegment, 0)
      name = Iyi::DiagnosticNameValue::Derived.new(projection_origin.as(Iyi::DiagnosticOrigin::DerivedName))
      builder.add_written_anchor(6, 11, padded_text, Iyi::DiagnosticRenderedLexContext::TypeName, "Name", "path_segment",
        projection_origin, {slot => [name] of Iyi::DiagnosticNameValue})
      padded_replacement = Iyi::DiagnosticRenderedFragment.new(padded_text, builder.finish_data(padded_text))

      edit = Iyi::DiagnosticByteEdit.new(Iyi::DiagnosticByteSpan.new(0, 11), "Root::Thing", padded_replacement, producer, [
        Iyi::DiagnosticAnchorTransfer::Project.new(0, [0], 0),
        Iyi::DiagnosticAnchorTransfer::Project.new(1, [0], 0),
      ])

      error = expect_raises(ArgumentError) do
        ledger.apply(site, before, [edit], "Crystal")
      end
      error.message.should eq("bound projection replacement was not issued for this edit")
    end

    it "refuses a low-level rewrite that splices an issued render into a registered part through compose" do
      ledger = Iyi::DiagnosticProjectionLedger.new(SpecBoundAuthority.new)
      site = ledger.open_site("initialiser", "")
      before, _ = spec_names(ledger, "Root::Thing", [{0, 4}, {6, 11}])
      producer = Iyi::DiagnosticBoundProducer::StripRoot.new("Root")
      rendered = spec_render(ledger, site, producer, before, 11)

      # Low-level rewrite: splice rendered into before using DiagnosticFragmentRewrite.apply directly
      edit = Iyi::DiagnosticByteEdit.new(Iyi::DiagnosticByteSpan.new(0, 4), "Root", rendered, producer, [
        Iyi::DiagnosticAnchorTransfer::Project.new(0, [0], 0),
      ])
      spliced = Iyi::DiagnosticFragmentRewrite.apply(before, [edit], "Crystal")

      # Attempting to register this spliced fragment through compose must be refused
      expect_raises(ArgumentError) do
        ledger.compose(site, spliced, [before, rendered])
      end
      expect_raises(ArgumentError) do
        ledger.compose(site, spliced, [rendered, before])
      end
      expect_raises(ArgumentError) do
        ledger.compose(site, spliced, [rendered])
      end
      expect_raises(ArgumentError) do
        ledger.compose(site, spliced, [before])
      end
    end
  end
end

# Mutation controls (ProjectionNoRegressionPlan §6, S1). Each is run once by hand, quoted, and reverted.
# The named control must go red. None is an example.
#
#   key the registry on the struct value              -> N2b, N2c
#   drop the text check in registered_entry           -> N2d
#   issued? by value instead of identity              -> N16
#   attests? true outside render                      -> N1b
#   DerivedName.new(data) skips the hold              -> N1, N7
#   drop the exact-class check                        -> N6b
#   drop the R4 comparison                            -> R4
#   store the claim instead of the recomputed producer -> P5 through P11 (same?)
#   call the authority before validation              -> N8
#   drop one site_tie? row                            -> N18
#   apply without the issuance check                  -> N9, N10, N11
#   register_source skips the walk                    -> N12
#   compose skips the belongs check                   -> N13
#   walk covers anchors only                          -> N14
#   verify skips the key or record check              -> R11, R19
#   no seal                                           -> R12
#   drop the R8 presence check in compose             -> N17
