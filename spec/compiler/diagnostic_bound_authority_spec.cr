require "../support/syntax"

# BoundProvenancePlan §3.2 (S1): the projection authority seam.
#
# SpecBoundAuthority is a spec-only double. It admits every producer, and it is named
# Spec so that it cannot be mistaken for a production authority. Positive controls mint
# every producer through it. Each negative control changes one thing and must refuse with
# its own message. The mutation proofs at the end are run by hand and are not examples.

class SpecBoundAuthority < Iyi::DiagnosticProjectionAuthority
  def replay!(producer : Iyi::DiagnosticBoundProducer, source_text : String) : Nil
  end
end

class SpecRefusingAuthority < Iyi::DiagnosticProjectionAuthority
  def replay!(producer : Iyi::DiagnosticBoundProducer, source_text : String) : Nil
    raise Iyi::DiagnosticProjectionAuthority.refused(producer)
  end
end

private def bound_spec_written(offset : Int32, kind : String, role : String) : Iyi::DiagnosticOrigin::Written
  Iyi::DiagnosticOrigin::Written.new("app/main", "/absent/bind.cr", offset, kind, role)
end

# A registered fragment with no text. Every source-free producer renders from it.
private def bound_spec_empty(authority : Iyi::DiagnosticProjectionAuthority) : Iyi::DiagnosticRenderedFragment
  authority.register(Iyi::DiagnosticRenderedFragment.new("", Iyi::DiagnosticFragmentData.new("", [] of Iyi::DiagnosticTokenEvent, [] of Iyi::DiagnosticAnchor)))
end

# A registered fragment whose spans are CONST path segments, each anchored to its own
# source token. Also returns the source names those spans describe.
private def bound_spec_names(authority : Iyi::DiagnosticProjectionAuthority, text : String,
                             spans : Array({Int32, Int32})) : {Iyi::DiagnosticRenderedFragment, Array(Iyi::DiagnosticBoundNameSource)}
  guard = ::Crystal::Digest::SHA256.hexdigest(text)
  builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
  names = [] of Iyi::DiagnosticBoundNameSource
  spans.each do |first, last|
    origin = bound_spec_written(first, "Name", "path_segment")
    raw = text.byte_slice(first, last - first)
    token = Iyi::DiagnosticSourceNameToken.new(origin, nil, "path_segment", guard, text.bytesize, first, last, "Crystal", "CONST", raw)
    value = Iyi::DiagnosticNameValue::Observed.new(token)
    slot = Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::PathSegment, 0)
    builder.add_written_anchor(first, last, text, Iyi::DiagnosticRenderedLexContext::TypeName, "Name", "path_segment",
      origin, {slot => [value] of Iyi::DiagnosticNameValue})
    names << Iyi::DiagnosticBoundNameSource.new(first, last, value)
  end
  {authority.register(Iyi::DiagnosticRenderedFragment.new(text, builder.finish_data(text))), names}
end

private def bound_spec_render(authority : Iyi::DiagnosticProjectionAuthority, producer : Iyi::DiagnosticBoundProducer,
                              before : Iyi::DiagnosticRenderedFragment, span_end : Int32) : Iyi::DiagnosticRenderedFragment
  Iyi::DiagnosticBoundProjection.render(authority, producer, before, Iyi::DiagnosticByteSpan.new(0, span_end), "Crystal")
end

# A minted projection has the expected text, is registered, and every anchor carries a
# DerivedName whose producer is the one that minted it.
private def bound_spec_expect_minted(authority : Iyi::DiagnosticProjectionAuthority, producer : Iyi::DiagnosticBoundProducer,
                                     result : Iyi::DiagnosticRenderedFragment, text : String)
  result.text.should eq(text)
  authority.registered?(result).should be_true
  result.data.anchors.should_not be_empty
  result.data.anchors.each do |anchor|
    origin = anchor.origin.not_nil!.as(Iyi::DiagnosticOrigin::DerivedName)
    origin.producer.should eq(producer)
    origin.bound_projection_data.should_not be_nil
  end
end

describe "diagnostic bound projection authority" do
  describe "positive controls minted through a spec authority" do
    it "mints StripRoot from a source-bearing fragment" do
      authority = SpecBoundAuthority.new
      before, _ = bound_spec_names(authority, "Root::Thing", [{0, 4}, {6, 11}])
      producer = Iyi::DiagnosticBoundProducer::StripRoot.new("Root")
      bound_spec_expect_minted(authority, producer, bound_spec_render(authority, producer, before, 11), "Thing")
    end

    it "mints ForeignType from a source-bearing fragment" do
      authority = SpecBoundAuthority.new
      before, _ = bound_spec_names(authority, "Thing", [{0, 5}])
      producer = Iyi::DiagnosticBoundProducer::ForeignType.new("other", "Thing", "Other::Thing")
      bound_spec_expect_minted(authority, producer, bound_spec_render(authority, producer, before, 5), "Other::Thing")
    end

    it "mints AliasType from a source-bearing fragment" do
      authority = SpecBoundAuthority.new
      before, _ = bound_spec_names(authority, "Thing", [{0, 5}])
      producer = Iyi::DiagnosticBoundProducer::AliasType.new("Owner", "Thing", "Other")
      bound_spec_expect_minted(authority, producer, bound_spec_render(authority, producer, before, 5), "Other")
    end

    it "mints SelfReturn from a source-bearing fragment" do
      authority = SpecBoundAuthority.new
      before, _ = bound_spec_names(authority, "Owner", [{0, 5}])
      producer = Iyi::DiagnosticBoundProducer::SelfReturn.new("Owner", "new", "self")
      bound_spec_expect_minted(authority, producer, bound_spec_render(authority, producer, before, 5), "self")
    end

    it "mints SemanticSignatureType from an empty fragment" do
      authority = SpecBoundAuthority.new
      producer = Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(bound_spec_written(0, "Def", "keyword"), "return_type", nil, "Int32")
      bound_spec_expect_minted(authority, producer, bound_spec_render(authority, producer, bound_spec_empty(authority), 0), "Int32")
    end

    it "mints UninitializedClassVar from an empty fragment" do
      authority = SpecBoundAuthority.new
      producer = Iyi::DiagnosticBoundProducer::UninitializedClassVar.new(bound_spec_written(0, "Name", "class_variable"),
        "Owner", "@@cache", "Int32")
      bound_spec_expect_minted(authority, producer, bound_spec_render(authority, producer, bound_spec_empty(authority), 0),
        "uninitialized Int32")
    end

    it "mints ConstantAccessor from an empty fragment" do
      authority = SpecBoundAuthority.new
      getter = Iyi::DiagnosticOrigin::Synthetic.new(bound_spec_written(0, "Assign", "constant"), "constant_accessor", "getter")
      producer = Iyi::DiagnosticBoundProducer::ConstantAccessor.new(getter, "", "Thing", "Name")
      bound_spec_expect_minted(authority, producer, bound_spec_render(authority, producer, bound_spec_empty(authority), 0), "thing")
    end

    it "mints ResolvedRestriction without a global prefix" do
      authority = SpecBoundAuthority.new
      before, _ = bound_spec_names(authority, "Thing", [{0, 5}])
      producer = Iyi::DiagnosticBoundProducer::ResolvedRestriction.new("Owner", "Thing", "Other::Thing", "Root", false)
      bound_spec_expect_minted(authority, producer, bound_spec_render(authority, producer, before, 5), "Other::Thing")
    end

    it "mints ResolvedRestriction with a global prefix" do
      authority = SpecBoundAuthority.new
      before, _ = bound_spec_names(authority, "Thing", [{0, 5}])
      producer = Iyi::DiagnosticBoundProducer::ResolvedRestriction.new("Owner", "Thing", "Other::Thing", "Root", true)
      bound_spec_expect_minted(authority, producer, bound_spec_render(authority, producer, before, 5), "::Other::Thing")
    end

    it "mints SynthesizedConstructor for the definition name" do
      authority = SpecBoundAuthority.new
      producer = Iyi::DiagnosticBoundProducer::SynthesizedConstructor.new(bound_spec_written(0, "Def", "keyword"), "definition_name")
      bound_spec_expect_minted(authority, producer, bound_spec_render(authority, producer, bound_spec_empty(authority), 0), "new")
    end

    # Receiver observation goes through the same TypeName path as ConstantAccessor "Receiver".
    # Not run yet: confirm the local_reference constructor observation when the spec is run.
    it "mints SynthesizedConstructor for the local receiver" do
      authority = SpecBoundAuthority.new
      producer = Iyi::DiagnosticBoundProducer::SynthesizedConstructor.new(bound_spec_written(0, "Def", "keyword"), "local_reference")
      bound_spec_expect_minted(authority, producer, bound_spec_render(authority, producer, bound_spec_empty(authority), 0), "self")
    end

    it "mints ConstantTarget from an empty fragment" do
      authority = SpecBoundAuthority.new
      producer = Iyi::DiagnosticBoundProducer::ConstantTarget.new(bound_spec_written(0, "Assign", "constant"), "Inner::NAME")
      bound_spec_expect_minted(authority, producer, bound_spec_render(authority, producer, bound_spec_empty(authority), 0), "Inner::NAME")
    end

    it "admits an empty-source SynthesizedConstructor through the raw constructor" do
      producer = Iyi::DiagnosticBoundProducer::SynthesizedConstructor.new(bound_spec_written(0, "Def", "keyword"), "definition_name")
      origin = Iyi::DiagnosticOrigin::DerivedName.bound_projection(producer, ::Crystal::Digest::SHA256.hexdigest(""), "",
        [] of Iyi::DiagnosticBoundNameSource, "new", "Crystal", 0, 3, "IDENT", "definition_name")
      origin.producer.should eq(producer)
    end
  end

  describe "negative controls" do
    # N1: a raw constructor carrying source refuses with H3.
    it "N1 refuses a raw constructor that carries source" do
      authority = SpecBoundAuthority.new
      _, names = bound_spec_names(authority, "Root::Thing", [{0, 4}, {6, 11}])
      producer = Iyi::DiagnosticBoundProducer::StripRoot.new("Root")
      data = Iyi::DiagnosticBoundProjectionData.new(producer, ::Crystal::Digest::SHA256.hexdigest("Root::Thing"),
        "Root::Thing", names, "Thing", "Crystal", 0, 5, "CONST", "path_segment")
      error = expect_raises(ArgumentError) do
        Iyi::DiagnosticOrigin::DerivedName.new(data, Iyi::DiagnosticProjectionAuthority::UNAVAILABLE)
      end
      error.message.should eq("bound projection requires authoritative source inventory")
      error = expect_raises(ArgumentError) do
        Iyi::DiagnosticOrigin::DerivedName.bound_projection(producer, ::Crystal::Digest::SHA256.hexdigest("Root::Thing"),
          "Root::Thing", names, "Thing", "Crystal", 0, 5, "CONST", "path_segment")
      end
      error.message.should eq("bound projection requires authoritative source inventory")
    end

    # N2: a before the authority never registered refuses to render.
    it "N2 refuses a source the authority never registered" do
      authority = SpecBoundAuthority.new
      unregistered = Iyi::DiagnosticRenderedFragment.new("", Iyi::DiagnosticFragmentData.new("", [] of Iyi::DiagnosticTokenEvent, [] of Iyi::DiagnosticAnchor))
      producer = Iyi::DiagnosticBoundProducer::StripRoot.new("Root")
      error = expect_raises(ArgumentError) do
        bound_spec_render(authority, producer, unregistered, 0)
      end
      error.message.should eq("bound projection source is not registered with its authority")
    end

    # Registration is by identity. An equal fragment built separately is not registered.
    it "N2b treats an equal fragment built separately as unregistered" do
      authority = SpecBoundAuthority.new
      registered = bound_spec_empty(authority)
      twin = Iyi::DiagnosticRenderedFragment.new("", Iyi::DiagnosticFragmentData.new("", [] of Iyi::DiagnosticTokenEvent, [] of Iyi::DiagnosticAnchor))
      authority.registered?(registered).should be_true
      authority.registered?(twin).should be_false
    end

    # N3: a replay refusal reaches the caller with its kind.
    it "N3 refuses a projection that replay refuses" do
      authority = SpecRefusingAuthority.new
      before, _ = bound_spec_names(authority, "Root::Thing", [{0, 4}, {6, 11}])
      producer = Iyi::DiagnosticBoundProducer::StripRoot.new("Root")
      error = expect_raises(ArgumentError) do
        bound_spec_render(authority, producer, before, 11)
      end
      error.message.should eq("bound projection replay refused: StripRoot")
    end

    # N4: a fragment registered by one authority is refused by another.
    it "N4 refuses a fragment registered by another authority" do
      owner = SpecBoundAuthority.new
      other = SpecBoundAuthority.new
      before, _ = bound_spec_names(owner, "Root::Thing", [{0, 4}, {6, 11}])
      producer = Iyi::DiagnosticBoundProducer::StripRoot.new("Root")
      error = expect_raises(ArgumentError) do
        bound_spec_render(other, producer, before, 11)
      end
      error.message.should eq("bound projection source is not registered with its authority")
      owner.registered?(before).should be_true
      other.registered?(before).should be_false
    end

    # N5: a source-bearing origin written by DiagnosticOrigins refuses on read.
    it "N5 refuses a source-bearing origin after DiagnosticOrigins write then read" do
      authority = SpecBoundAuthority.new
      before, _ = bound_spec_names(authority, "Root::Thing", [{0, 4}, {6, 11}])
      result = bound_spec_render(authority, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), before, 11)
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
      before, _ = bound_spec_names(authority, "Root::Thing", [{0, 4}, {6, 11}])
      result = bound_spec_render(authority, Iyi::DiagnosticBoundProducer::StripRoot.new("Root"), before, 11)
      json = result.data.anchors.first.origin.not_nil!.to_json
      error = expect_raises(ArgumentError) do
        Iyi::DiagnosticOrigin.from_json(JSON.parse(json))
      end
      error.message.should eq("bound projection requires authoritative source inventory")
    end

    # N7: UNAVAILABLE admits empty source only.
    it "N7 admits empty source only through UNAVAILABLE" do
      unavailable = Iyi::DiagnosticProjectionAuthority::UNAVAILABLE
      producer = Iyi::DiagnosticBoundProducer::StripRoot.new("Root")
      unavailable.replay!(producer, "").should be_nil
      error = expect_raises(ArgumentError) do
        unavailable.replay!(producer, "Root::Thing")
      end
      error.message.should eq("bound projection requires authoritative source inventory")
    end
  end
end

# Mutation proofs (BoundProvenancePlan §4 S1). Run by hand, each quoted and reverted:
#
#   1. Make DerivedName#initialize skip authority.admit! (delete that one line).
#      Expected: N1, N5 and N6 fail, with the H3 message not raised.
#   2. Make DiagnosticBoundProjection.render skip the registered? check.
#      Expected: N2 and N4 fail, with the registration message not raised.
#
# Neither proof is a spec example. Each is run once against this file and then reverted.
