require "./ast"
require "./to_s"
require "./diagnostic_origin"
require "../iyimod"

module Iyi
  # Bound text together with the registered fragment that carries its
  # provenance. Only fragments registered by the recipe's authority are used as
  # sources, so a fragment built outside the seam cannot pass as bound output.
  class DiagnosticBoundFragment
    getter rendered : DiagnosticRenderedFragment

    def initialize(@rendered : DiagnosticRenderedFragment)
    end

    def text : String
      @rendered.text
    end
  end

  # One path, found from its PathSegment anchors. Offsets are byte offsets into
  # the fragment text, which is the coordinate system both
  # DiagnosticFragmentRewrite.apply and DiagnosticBoundProjection.render use.
  #
  # `before` and `after` are the bytes either side of the whole path. `after_first`
  # is the byte after its first segment, which is where the text-level rules
  # looked for `::` or a name continuation.
  private record PathOccurrence, start : Int32, finish : Int32, names : Array(String),
    before : UInt8?, after_first : UInt8?, after : UInt8?

  # Every bound rewrite of a diagnostic fragment, token-aware.
  #
  # The text-level rewriters in tools/bind.cr (`strip_root`, `map_names`,
  # `replace_word`) are replaced here by edits on name tokens. A rewrite never
  # searches the text, so a literal that happens to spell `Root::X` stays as
  # written (D1-B). Each edit goes through DiagnosticFragmentRewrite.apply, and
  # its replacement is a projection that DiagnosticBoundProjection.render minted
  # from the exact bytes it replaces.
  class DiagnosticBoundRecipe
    getter authority : DiagnosticProjectionAuthority
    getter lexical_mode : String
    # Projections that finish has handed out, by producer kind.
    getter counts = {} of String => Int32
    @empty : DiagnosticRenderedFragment

    def initialize(@authority : DiagnosticProjectionAuthority, @lexical_mode : String)
      # Raises unless the mode is Crystal or Iyi.
      DiagnosticFragmentBuilder.new(@lexical_mode)
      @empty = @authority.register(DiagnosticRenderedFragment.new("",
        DiagnosticFragmentData.new("", [] of DiagnosticTokenEvent, [] of DiagnosticAnchor)))
    end

    # Sources

    def captured(captures : DiagnosticModeCaptures) : DiagnosticBoundFragment
      wrap(DiagnosticRenderedFragment.new(captures.text, captures.data(@lexical_mode)))
    end

    def printed(node : ASTNode) : DiagnosticBoundFragment
      io = IO::Memory.new
      builder = DiagnosticFragmentBuilder.new(@lexical_mode)
      node.to_s(io, diagnostic_fragment: builder)
      rendered_text(io, builder)
    end

    def bound_parameter_name(node : Arg, prefix : String) : DiagnosticBoundFragment
      io = IO::Memory.new
      builder = DiagnosticFragmentBuilder.new(@lexical_mode)
      ToSVisitor.write_bound_parameter_name(io, node, prefix, builder)
      rendered_text(io, builder)
    end

    # The name a def is written with, anchored as the printer anchors it:
    # one Name anchor per recorded token, with the same lexical context.
    def definition_name(node : Def) : DiagnosticBoundFragment
      slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::Primary)
      tokens = node.diagnostic_name_slots[slot]?
      raise ArgumentError.new("name lacks token evidence for definition_name") unless tokens && !tokens.empty?
      unless tokens.join(&.rendered_text) == node.name
        raise ArgumentError.new("diagnostic name was renamed without a recorded projection")
      end
      io = IO::Memory.new
      builder = DiagnosticFragmentBuilder.new(@lexical_mode)
      tokens.each do |token|
        start = io.pos.to_i32
        io << token.rendered_text
        finish = io.pos.to_i32
        origin = token.artifact_origin
        unless origin.valid_for_anchor?("Name", "definition_name")
          raise ArgumentError.new("diagnostic name lacks an artifact anchor for definition_name")
        end
        builder.add_written_anchor(start, finish, io.to_s, DiagnosticRenderedLexContext::DefOrMacroName,
          "Name", "definition_name", origin, {slot => [token] of DiagnosticNameValue})
      end
      rendered_text(io, builder)
    end

    def plain(text : String) : DiagnosticBoundFragment
      builder = DiagnosticFragmentBuilder.new(@lexical_mode)
      wrap(DiagnosticRenderedFragment.new(text, builder.finish_data(text)))
    end

    def join(parts : Array(DiagnosticBoundFragment), separator : String) : DiagnosticBoundFragment
      renders = parts.map { |part| registered!(part) }
      wrap(DiagnosticFragmentRewrite.concat(renders, separator, @lexical_mode))
    end

    # `path = value`, anchored as the printer anchors a constant Assign with a
    # Path target: an Assign/constant anchor on the path's head token, which
    # points at the path's first name anchor.
    def constant_line(declaration_origin : DiagnosticOrigin, path : DiagnosticBoundFragment,
                      value : DiagnosticBoundFragment) : DiagnosticBoundFragment
      path_rendered = registered!(path)
      value_rendered = registered!(value)
      io = IO::Memory.new
      builder = DiagnosticFragmentBuilder.new(@lexical_mode)
      DiagnosticFragmentRewrite.append_into(builder, io, path_rendered)
      head_event = (0...builder.event_count).find { |index| builder.event_at(index).selected_start == 0 }
      raise ArgumentError.new("constant line lacks a path head") unless head_event
      child = (0...builder.anchor_count).find { |index| builder.anchor_at(index).event_index == head_event }
      raise ArgumentError.new("constant line head lacks a path name") unless child
      io << " = "
      DiagnosticFragmentRewrite.append_into(builder, io, value_rendered)
      head = DiagnosticFragmentHead::Anchor.new(child).as(DiagnosticFragmentHead)
      builder.add_anchor(DiagnosticAnchor.new(0, "Assign", "constant", declaration_origin,
        {} of DiagnosticNameSlot => Array(DiagnosticNameValue), head_event,
        DiagnosticFragmentAttachment::HeadOf.new(DiagnosticHeadRule::ConstantAssignHead, head)))
      text = io.to_s
      wrap(DiagnosticRenderedFragment.new(text, builder.finish_data(text)))
    end

    # Projections. Each returns a registered fragment.

    def insert(producer : DiagnosticBoundProducer) : DiagnosticBoundFragment
      DiagnosticBoundFragment.new(DiagnosticBoundProjection.render(@authority, producer, @empty,
        DiagnosticByteSpan.new(0, 0), @lexical_mode))
    end

    # Rewrites the whole of *f* as *producer* says it is, for example a restriction
    # written as a proc notation or a generic type.
    def project_whole(f : DiagnosticBoundFragment, producer : DiagnosticBoundProducer) : DiagnosticBoundFragment
      rendered = registered!(f)
      touched_anchors(rendered, 0, rendered.text.bytesize)
      projected = DiagnosticBoundProjection.render(@authority, producer, rendered,
        DiagnosticByteSpan.new(0, rendered.text.bytesize), @lexical_mode)
      DiagnosticBoundFragment.new(projected)
    end

    # `MyRoot::Entry` becomes `Entry`. A global `::Root::X` and an interior
    # `Other::Root::Z` are not rooted at `Root`, so they stay as written.
    def strip_root(f : DiagnosticBoundFragment, root : String) : DiagnosticBoundFragment
      registered!(f)
      return f if root.empty?
      rewrite_paths(f, DiagnosticBoundProducer::StripRoot.new(root)) do |path|
        path.names.size >= 2 && path.names[0] == root && !continued_before?(path)
      end
    end

    # Replaces the bound name *name* at the head of a path with *qualified*. The
    # name must stand alone, so `JSONThing` is not `JSON`, and a path that is
    # global or interior is not rooted at *name* and is left alone.
    def map_foreign(f : DiagnosticBoundFragment, module_name : String, name : String, qualified : String) : DiagnosticBoundFragment
      registered!(f)
      return f if qualified == name
      producer = DiagnosticBoundProducer::ForeignType.new(module_name, name, qualified)
      rewrite_paths(f, producer) do |path|
        path.names[0] == name && !continued_before?(path) && !identifier_byte_at?(path.after_first)
      end
    end

    # Replaces a single-segment path *name* with *resolved*. A path with a `::`
    # neighbour is a different name and is left alone.
    def replace_alias(f : DiagnosticBoundFragment, owner : String, name : String, resolved : String) : DiagnosticBoundFragment
      registered!(f)
      return f if resolved == name
      rewrite_paths(f, DiagnosticBoundProducer::AliasType.new(owner, name, resolved)) do |path|
        path.names.size == 1 && path.names[0] == name && !continued_before?(path) && !scope_or_identifier_at?(path.after)
      end
    end

    # Close-out

    def expect!(f : DiagnosticBoundFragment, ordinary : String, site : String) : DiagnosticBoundFragment
      registered!(f)
      raise ArgumentError.new("bound provenance differs from ordinary binding at #{site}") unless f.text == ordinary
      f
    end

    # Finishes *f* as a section fragment and counts its projections by producer.
    def finish(f : DiagnosticBoundFragment, key : String) : IyiMod::DiagnosticFragment
      rendered = registered!(f)
      rendered.data.anchors.each do |anchor|
        origin = projection_origin(anchor.origin) || next
        kind = origin.producer.not_nil!.class.name.split("::").last
        @counts[kind] = (@counts[kind]? || 0) + 1
      end
      rendered.data.to_fragment(key)
    end

    # Re-admits every projection reachable from *section*, and refuses unless
    # their count equals the projections this recipe finished.
    def verify_section!(section : IyiMod::DiagnosticSection) : Int32
      reached = 0
      section.fragments.each_value do |fragment|
        fragment.anchors.each do |anchor|
          if origin = projection_origin(anchor.origin)
            admit!(origin)
            reached += 1
          end
          anchor.name_slots.each_value do |values|
            values.each do |value|
              next unless value.is_a?(DiagnosticNameValue::Derived)
              if origin = projection_origin(value.origin)
                admit!(origin)
              end
            end
          end
        end
      end
      unless reached == @counts.values.sum
        raise ArgumentError.new("bound projection count differs from minted")
      end
      reached
    end

    # Internals

    private def wrap(rendered : DiagnosticRenderedFragment) : DiagnosticBoundFragment
      DiagnosticBoundFragment.new(@authority.register(rendered))
    end

    private def rendered_text(io : IO::Memory, builder : DiagnosticFragmentBuilder) : DiagnosticBoundFragment
      text = io.to_s
      wrap(DiagnosticRenderedFragment.new(text, builder.finish_data(text)))
    end

    private def registered!(f : DiagnosticBoundFragment) : DiagnosticRenderedFragment
      unless @authority.registered?(f.rendered)
        raise ArgumentError.new("bound fragment is not registered with this recipe's authority")
      end
      f.rendered
    end

    private def projection_origin(origin : DiagnosticOrigin?) : DiagnosticOrigin::DerivedName?
      return nil unless origin.is_a?(DiagnosticOrigin::DerivedName)
      origin.derivation_kind == "BoundProjection" ? origin : nil
    end

    private def admit!(origin : DiagnosticOrigin::DerivedName) : Nil
      data = origin.bound_projection_data || raise ArgumentError.new("bound projection lacks its data")
      @authority.admit!(data)
    end

    # Every path whose segments satisfy the block gets its own edit. The edits
    # are applied in one pass over *f*.
    private def rewrite_paths(f : DiagnosticBoundFragment, producer : DiagnosticBoundProducer,
                              & : PathOccurrence -> Bool) : DiagnosticBoundFragment
      rendered = registered!(f)
      selected = [] of PathOccurrence
      paths_in(rendered).each { |path| selected << path if yield path }
      return f if selected.empty?
      edits = selected.map { |path| edit_for(rendered, path, producer) }
      wrap_applied(DiagnosticFragmentRewrite.apply(rendered, edits, @lexical_mode))
    end

    private def wrap_applied(rendered : DiagnosticRenderedFragment) : DiagnosticBoundFragment
      wrap(rendered)
    end

    # The edit for one path. Its replacement is the projection of the path's
    # bytes. Each touched name anchor is carried by that projection's first
    # anchor, which holds every source name of the path.
    private def edit_for(rendered : DiagnosticRenderedFragment, path : PathOccurrence,
                         producer : DiagnosticBoundProducer) : DiagnosticByteEdit
      span = DiagnosticByteSpan.new(path.start, path.finish)
      touched = touched_anchors(rendered, path.start, path.finish)
      replacement = DiagnosticBoundProjection.render(@authority, producer, rendered, span, @lexical_mode)
      if !touched.empty? && replacement.data.anchors.empty?
        raise ArgumentError.new("bound projection would drop a name anchor")
      end
      transfers = [] of DiagnosticAnchorTransfer
      touched.each { |index| transfers << DiagnosticAnchorTransfer::Project.new(index, [0], 0) }
      expected = rendered.text.byte_slice(path.start, path.finish - path.start)
      DiagnosticByteEdit.new(span, expected, replacement, producer, transfers)
    end

    # The anchors an edit over [start, finish) touches. The test is the one
    # DiagnosticFragmentRewrite.apply uses. A touched non-name anchor cannot be
    # carried by a projection, so it is refused.
    private def touched_anchors(rendered : DiagnosticRenderedFragment, start : Int32, finish : Int32) : Array(Int32)
      events = rendered.data.events
      touched = [] of Int32
      rendered.data.anchors.each_with_index do |anchor, index|
        event = events[anchor.event_index]
        next unless start < event.input_end && event.input_start < finish
        raise ArgumentError.new("bound projection would drop a non-name anchor") if anchor.name_slots.empty?
        touched << index
      end
      touched
    end

    # Groups PathSegment anchors into their paths, by consecutive segment
    # indices from 0. A segment that does not continue a path fails closed.
    private def paths_in(rendered : DiagnosticRenderedFragment) : Array(PathOccurrence)
      text = rendered.text
      events = rendered.data.events
      segments = [] of {Int32, Int32, Int32}
      rendered.data.anchors.each do |anchor|
        anchor.name_slots.each_key do |slot|
          next unless slot.kind == DiagnosticNameSlotKind::PathSegment
          event = events[anchor.event_index]
          segments << {slot.index, event.selected_start, event.selected_end}
        end
      end
      segments.sort_by! { |segment| segment[1] }
      groups = [] of Array({Int32, Int32, Int32})
      segments.each do |segment|
        if segment[0] == 0
          groups << [segment]
        else
          group = groups.last? || raise ArgumentError.new("path segment lacks a root segment")
          last = group.last
          unless segment[0] == last[0] + 1 && segment[1] >= last[2]
            raise ArgumentError.new("path segments are not contiguous")
          end
          group << segment
        end
      end
      groups.map do |group|
        first = group.first
        final = group.last
        after_first = first[2] < text.bytesize ? text.to_unsafe[first[2]] : nil
        after = final[2] < text.bytesize ? text.to_unsafe[final[2]] : nil
        before = first[1] > 0 ? text.to_unsafe[first[1] - 1] : nil
        PathOccurrence.new(first[1], final[2],
          group.map { |segment| text.byte_slice(segment[1], segment[2] - segment[1]) },
          before, after_first, after)
      end
    end

    # The text-level rule: a name does not start right after `:` or an
    # identifier byte.
    private def continued_before?(path : PathOccurrence) : Bool
      byte = path.before
      return false unless byte
      byte == 0x3A_u8 || identifier_byte?(byte)
    end

    private def identifier_byte_at?(byte : UInt8?) : Bool
      byte ? identifier_byte?(byte) : false
    end

    private def scope_or_identifier_at?(byte : UInt8?) : Bool
      return false unless byte
      byte == 0x3A_u8 || identifier_byte?(byte)
    end

    private def identifier_byte?(byte : UInt8) : Bool
      byte == 0x5F_u8 ||
        (byte >= 0x30_u8 && byte <= 0x39_u8) ||
        (byte >= 0x41_u8 && byte <= 0x5A_u8) ||
        (byte >= 0x61_u8 && byte <= 0x7A_u8)
    end
  end
end
