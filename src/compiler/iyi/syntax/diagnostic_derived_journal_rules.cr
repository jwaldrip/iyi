module Iyi
  # The replay journal indexed once per bound walk. Ordinals are journal order. Every scanned-token lookup is a
  # hash probe, so a walk never rescans the journal.
  class DiagnosticJournalSequence
    @entries : Array(DiagnosticRenderedToken)
    @by_start : Hash(Int32, Array(Int32))

    def initialize(journal : DiagnosticReplayJournal)
      @entries = journal.entries
      @by_start = {} of Int32 => Array(Int32)
      @entries.each_with_index do |entry, ordinal|
        (@by_start[entry.input_start] ||= [] of Int32) << ordinal
      end
    end

    # Ordinal of the one entry equal on (start, finish, kind, raw, mode); nil when none.
    # Raises "ambiguous scanned token" when more than one entry starts at `start`.
    def ordinal?(start : Int32, finish : Int32, kind : String, raw : String, mode : String) : Int32?
      ordinals = @by_start[start]?
      return nil unless ordinals
      raise ArgumentError.new("ambiguous scanned token") if ordinals.size > 1
      ordinal = ordinals[0]
      entry = @entries[ordinal]
      return nil unless entry.input_end == finish && entry.token_kind == kind &&
                        entry.token_text == raw && entry.lexical_mode == mode
      ordinal
    end

    def entry(ordinal : Int32) : DiagnosticRenderedToken
      @entries[checked_ordinal(ordinal)].dup
    end

    # The kind of one entry, read without copying it. Bracket walks use this.
    def token_kind_at(ordinal : Int32) : String
      @entries[checked_ordinal(ordinal)].token_kind
    end

    def size : Int32
      @entries.size
    end

    private def checked_ordinal(ordinal : Int32) : Int32
      raise ArgumentError.new("invalid journal ordinal") unless 0 <= ordinal < @entries.size
      ordinal
    end
  end

  # Journal rules for derived operator names and type sugar (plan §3.3, §3.4). A witness is never authority on
  # its own: each one must be a scanned token in the replay journal, and its shape (signed split, bracket pairing,
  # whitespace gap) is read back from the journal entries around it. Every journal entry visited yields one unit
  # to the caller, which charges it to the node budget.
  module DiagnosticDerivedJournalRules
    EXPANDED_OPERATOR   = "expanded operator name requires replayed expansion pragmas (contract X)"
    OPERATOR_INPUTS     = "operator witnesses use different inputs"
    OPERATOR_NOT_SCANNED = "operator witness is not a scanned token"
    SIGNED_SPLIT        = "signed operator split not witnessed"
    INDEX_BRACKETS      = "index brackets do not pair"
    QUERY_ADJACENT      = "index query suffix not adjacent"
    ASSIGN_GAP          = "assignment witness gap differs"
    NOT_OPERATOR        = "derived name is not an operator name"
    EXPANDED_SUGAR      = "expanded type sugar requires replayed expansion pragmas (contract X)"
    SUGAR_INPUTS        = "type-sugar witnesses use different inputs"
    SUGAR_NOT_SCANNED   = "type-sugar witness is not a scanned token"
    SUGAR_BRACKETS      = "type-sugar brackets do not pair"
    NOT_SUGAR           = "derived name is not a type sugar"

    INDEX_OPENERS = ["[", "@["]
    TUPLE_OPENERS = ["{", "INTERPOLATION_START"]

    def self.verify_operator!(origin : DiagnosticOrigin::DerivedName, input : AcceptedCaptureInput,
                              sequence : DiagnosticJournalSequence, &charge : UInt64 ->) : Nil
      witnesses = origin.operator_witnesses
      if origin.operator_anchor.is_a?(DiagnosticOrigin::Expanded) || witnesses.any? { |witness| !witness.event.nil? }
        raise ArgumentError.new(EXPANDED_OPERATOR)
      end
      production = origin.operator_production || raise ArgumentError.new(NOT_OPERATOR)
      unless origin.operator_input_sha256 == input.input_sha256 &&
             origin.operator_input_bytesize == input.input_bytesize &&
             origin.operator_lexical_mode == input.lexical_mode
        raise ArgumentError.new(OPERATOR_INPUTS)
      end
      mode = input.lexical_mode
      ordinals = witnesses.map do |witness|
        sequence.ordinal?(witness.input_start, witness.input_end, witness.token_kind, witness.raw_text, mode) ||
          raise ArgumentError.new(OPERATOR_NOT_SCANNED)
      end

      case production
      when DiagnosticOperatorProduction::SignedNumber
        verify_signed_split!(witnesses[0], ordinals[0], sequence, &charge)
      when DiagnosticOperatorProduction::Index
        pair_brackets!(sequence, ordinals[0], ordinals[1], INDEX_OPENERS, "]", INDEX_BRACKETS, &charge)
      when DiagnosticOperatorProduction::IndexQuery
        pair_brackets!(sequence, ordinals[0], ordinals[1], INDEX_OPENERS, "]", INDEX_BRACKETS, &charge)
        raise ArgumentError.new(QUERY_ADJACENT) unless ordinals[2] == ordinals[1] + 1
      when DiagnosticOperatorProduction::IndexAssign
        # `[`, `]`, `=` pairs its brackets; `[]`, `=` has no brackets to pair. Both need the gap before `=`.
        if witnesses.size == 3
          pair_brackets!(sequence, ordinals[0], ordinals[1], INDEX_OPENERS, "]", INDEX_BRACKETS, &charge)
        end
        last = witnesses.size - 1
        verify_gap!(sequence, witnesses[last - 1], ordinals[last - 1], witnesses[last], ordinals[last], &charge)
      when DiagnosticOperatorProduction::Setter
        verify_gap!(sequence, witnesses[0], ordinals[0], witnesses[1], ordinals[1], &charge)
      when DiagnosticOperatorProduction::OpAssign, DiagnosticOperatorProduction::Command
        # The scanned check above is the whole rule for these witnesses.
      else
        raise ArgumentError.new(NOT_OPERATOR)
      end
    end

    def self.verify_type_sugar!(origin : DiagnosticOrigin::DerivedName, input : AcceptedCaptureInput,
                                sequence : DiagnosticJournalSequence, &charge : UInt64 ->) : Nil
      witnesses = origin.witnesses
      if witnesses.any? { |witness| witness.lexical_origin.is_a?(DiagnosticOrigin::Expanded) }
        raise ArgumentError.new(EXPANDED_SUGAR)
      end
      unless witnesses.all? { |witness| witness.input_sha256 == input.input_sha256 &&
                                        witness.input_bytesize == input.input_bytesize &&
                                        witness.lexical_mode == input.lexical_mode }
        raise ArgumentError.new(SUGAR_INPUTS)
      end
      ordinals = witnesses.map do |witness|
        sequence.ordinal?(witness.input_start, witness.input_end, witness.token_kind, witness.raw_text,
          witness.lexical_mode) || raise ArgumentError.new(SUGAR_NOT_SCANNED)
      end

      production = origin.production || raise ArgumentError.new(NOT_SUGAR)
      case production
      when DiagnosticTypeSugar::StaticArray
        pair_brackets!(sequence, ordinals[0], ordinals[1], INDEX_OPENERS, "]", SUGAR_BRACKETS, &charge)
      when DiagnosticTypeSugar::Tuple, DiagnosticTypeSugar::NamedTuple
        pair_brackets!(sequence, ordinals[0], ordinals[1], TUPLE_OPENERS, "}", SUGAR_BRACKETS, &charge)
      else
        # Every other form is fully determined by its scanned witnesses.
      end
    end

    # `-1` in the journal is a NUMBER token, and the split tail is the NUMBER entry right after it: start one byte
    # later, same end, and the witness text without its sign.
    private def self.verify_signed_split!(witness : DiagnosticOperatorWitness, ordinal : Int32,
                                          sequence : DiagnosticJournalSequence, &charge : UInt64 ->) : Nil
      charge.call(1_u64)
      raise ArgumentError.new(SIGNED_SPLIT) unless ordinal + 1 < sequence.size
      tail = sequence.entry(ordinal + 1)
      text = witness.raw_text.byte_slice(1, witness.raw_text.bytesize - 1)
      unless tail.token_kind == "NUMBER" && tail.input_start == witness.input_start + 1 &&
             tail.input_end == witness.input_end && tail.token_text == text
        raise ArgumentError.new(SIGNED_SPLIT)
      end
    end

    # Walks the entries from the opener witness to the closer witness, both inclusive. Openers add one, the closer
    # subtracts one. The depth stays at least one before the closer witness and is exactly zero at it.
    private def self.pair_brackets!(sequence : DiagnosticJournalSequence, open : Int32, close : Int32,
                                    openers : Array(String), closer : String, message : String,
                                    &charge : UInt64 ->) : Nil
      raise ArgumentError.new(message) unless close > open
      depth = 0
      open.upto(close) do |ordinal|
        charge.call(1_u64)
        kind = sequence.token_kind_at(ordinal)
        if openers.includes?(kind)
          depth += 1
        elsif kind == closer
          depth -= 1
        end
        if ordinal < close
          raise ArgumentError.new(message) if depth < 1
        else
          raise ArgumentError.new(message) unless depth == 0
        end
      end
    end

    # The two witnesses must be adjacent in the journal, and every entry between them must be SPACE tiling the
    # exact byte gap from the first witness's end to the second witness's start.
    private def self.verify_gap!(sequence : DiagnosticJournalSequence,
                                 before : DiagnosticOperatorWitness, before_ordinal : Int32,
                                 after : DiagnosticOperatorWitness, after_ordinal : Int32,
                                 &charge : UInt64 ->) : Nil
      raise ArgumentError.new(ASSIGN_GAP) unless after_ordinal > before_ordinal
      cursor = before.input_end
      (before_ordinal + 1).upto(after_ordinal - 1) do |ordinal|
        charge.call(1_u64)
        space = sequence.entry(ordinal)
        unless space.token_kind == "SPACE" && space.input_start == cursor && space.input_end > cursor
          raise ArgumentError.new(ASSIGN_GAP)
        end
        cursor = space.input_end
      end
      raise ArgumentError.new(ASSIGN_GAP) unless cursor == after.input_start
    end
  end
end
