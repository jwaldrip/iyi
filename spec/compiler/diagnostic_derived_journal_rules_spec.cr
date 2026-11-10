require "../support/syntax"

# S3 journal rules (plan §3.3, §3.4). Each source is recorded and replayed the way bind! does, then every
# derived operator name and type sugar in the replayed tree must pass the rules, in both lexical modes.
# Each negative control rebuilds the replay journal (or passes another source's input) and must refuse with
# its own message. The honest journal runs first in each control, so a refusal means the change was seen.

DERIVED_RULES_SUFFIXES = [".cr", ".iyi"]

DERIVED_RULES_OPERATOR_SOURCES = [
  "x += 1\n", "a.x += 1\n", "a[1] += 2\n", "x -1\n", "x -1-1\n", "x -0x10\n", "a[1]\n", "a[b[1]]\n",
  "a[\"[\"]\n", "a[\"]\"]\n", "a[%w[x]]\n", "a[1]?\n", "a[1] = 2\n", "a[1]=2\n", "a[] = 2\n", "a[1, 2] = 3\n",
  "a.x = 1\n", "a.x=1\n", "a.x =\n 1\n", "`ls`\n", "`ls \#{x}`\n", "%x(ls)\n",
]

DERIVED_RULES_SUGAR_SOURCES = [
  "def f(x : Int32*)\nend\n", "def f(x : Int32**)\nend\n", "def f(x : Int32?)\nend\n",
  "class A\n  def f(x : self?)\n  end\nend\n", "def f(x : Int32[4])\nend\n", "def f(x : {Int32, String})\nend\n",
  "def f(x : {a: Int32})\nend\n", "def f(x : {Int32, {Int32, String}})\nend\n", "x.nil?\n", "%w()\n", "%i()\n",
]

# Records `source` over a real temp file, then replays it as bind! does. Returns the claim (the input), the
# replayed root, and the replay journal.
private def derived_rules_spec_claim(source : String, suffix : String) : {Iyi::AcceptedCaptureInput, Iyi::ASTNode, Iyi::DiagnosticReplayJournal}
  path = File.tempname("derived_rules", suffix)
  File.write(path, source)
  begin
    parser = Iyi::Parser.new(source, nil, [Set(String).new], Iyi::WarningCollection.new)
    parser.filename = path
    ledger = Iyi::DiagnosticCaptureLedger.new
    _, claim, _ = Iyi::DiagnosticCaptureAuthority.record_source(ledger, parser)
    ledger.freeze!
    replay = claim.replay_parser
    replay.enable_diagnostic_observations
    root = claim.replay_entry(replay)
    {claim, root, Iyi::DiagnosticReplayJournal.new(replay.diagnostic_lexical_observations)}
  ensure
    File.delete(path) if File.file?(path)
  end
end

# Every derived name in a replayed tree, whichever node carries it.
class DerivedRulesSpecCollector < Iyi::Visitor
  getter origins = [] of Iyi::DiagnosticOrigin::DerivedName

  def visit_any(node)
    node.diagnostic_name_slots.each_value do |values|
      values.each do |value|
        @origins << value.origin if value.is_a?(Iyi::DiagnosticNameValue::Derived)
      end
    end
    true
  end
end

private def derived_rules_spec_origins(root : Iyi::ASTNode) : Array(Iyi::DiagnosticOrigin::DerivedName)
  collector = DerivedRulesSpecCollector.new
  root.accept(collector)
  collector.origins
end

private def derived_rules_spec_operator(root : Iyi::ASTNode, production : Iyi::DiagnosticOperatorProduction) : Iyi::DiagnosticOrigin::DerivedName
  derived_rules_spec_origins(root).find { |origin| origin.operator_production == production } ||
    raise "no #{production} operator origin"
end

private def derived_rules_spec_sugar(root : Iyi::ASTNode, production : Iyi::DiagnosticTypeSugar) : Iyi::DiagnosticOrigin::DerivedName
  derived_rules_spec_origins(root).find { |origin| origin.production == production } ||
    raise "no #{production} type-sugar origin"
end

private def derived_rules_spec_operator_rules(origin : Iyi::DiagnosticOrigin::DerivedName, input : Iyi::AcceptedCaptureInput,
                                              journal : Iyi::DiagnosticReplayJournal) : Nil
  sequence = Iyi::DiagnosticJournalSequence.new(journal)
  Iyi::DiagnosticDerivedJournalRules.verify_operator!(origin, input, sequence) { |_visits| }
end

private def derived_rules_spec_sugar_rules(origin : Iyi::DiagnosticOrigin::DerivedName, input : Iyi::AcceptedCaptureInput,
                                           journal : Iyi::DiagnosticReplayJournal) : Nil
  sequence = Iyi::DiagnosticJournalSequence.new(journal)
  Iyi::DiagnosticDerivedJournalRules.verify_type_sugar!(origin, input, sequence) { |_visits| }
end

# The journal rebuilt from its own entries, with `mutate` applied to a copy.
private def derived_rules_spec_rebuild(journal : Iyi::DiagnosticReplayJournal,
                                       mutate : Array(Iyi::DiagnosticRenderedToken) -> Array(Iyi::DiagnosticRenderedToken)) : Iyi::DiagnosticReplayJournal
  Iyi::DiagnosticReplayJournal.new(mutate.call(journal.entries))
end

describe "S3 derived journal rules: positive controls" do
  DERIVED_RULES_SUFFIXES.each do |suffix|
    it "accepts every derived operator name and type sugar in #{suffix} mode" do
      counts = Hash(String, Int32).new(0)
      (DERIVED_RULES_OPERATOR_SOURCES + DERIVED_RULES_SUGAR_SOURCES).each do |source|
        claim, root, journal = derived_rules_spec_claim(source, suffix)
        sequence = Iyi::DiagnosticJournalSequence.new(journal)
        derived_rules_spec_origins(root).each do |origin|
          if origin.derivation_kind == "OperatorName"
            Iyi::DiagnosticDerivedJournalRules.verify_operator!(origin, claim, sequence) { |_visits| }
            counts[origin.operator_production.to_s] += 1
          elsif origin.derivation_kind == "TypeSugar"
            Iyi::DiagnosticDerivedJournalRules.verify_type_sugar!(origin, claim, sequence) { |_visits| }
            counts[origin.production.to_s] += 1
          end
        end
      end
      operator_names = ["OpAssign", "SignedNumber", "Index", "IndexQuery", "IndexAssign", "Setter", "Command"]
      sugar_names = ["Pointer", "DoublePointer", "NilableType", "SelfNilableType", "StaticArray", "Tuple",
                     "NamedTuple", "NilPredicate", "StringArray", "SymbolArray"]
      (operator_names + sugar_names - counts.keys).should be_empty
    end

    it "charges one journal visit per entry walked in #{suffix} mode" do
      claim, root, journal = derived_rules_spec_claim("a[1]\n", suffix)
      origin = derived_rules_spec_operator(root, Iyi::DiagnosticOperatorProduction::Index)
      visits = 0_u64
      Iyi::DiagnosticDerivedJournalRules.verify_operator!(origin, claim, Iyi::DiagnosticJournalSequence.new(journal)) do |count|
        visits += count
      end
      # `a`, `[`, `1`, `]` is four entries, and the walk runs from `[` through `]`.
      visits.should eq 3_u64
    end
  end
end

describe "S3 derived journal rules: mutation controls" do
  DERIVED_RULES_SUFFIXES.each do |suffix|
    it "refuses a witness that is not a scanned token in #{suffix} mode" do
      claim, root, journal = derived_rules_spec_claim("x += 1\n", suffix)
      origin = derived_rules_spec_operator(root, Iyi::DiagnosticOperatorProduction::OpAssign)
      derived_rules_spec_operator_rules(origin, claim, journal)
      mutant = derived_rules_spec_rebuild(journal) { |entries| entries.reject { |entry| entry.token_text == "+=" } }
      expect_raises(ArgumentError, "operator witness is not a scanned token") do
        derived_rules_spec_operator_rules(origin, claim, mutant)
      end
    end

    it "refuses a start that holds two entries in #{suffix} mode" do
      claim, root, journal = derived_rules_spec_claim("x += 1\n", suffix)
      origin = derived_rules_spec_operator(root, Iyi::DiagnosticOperatorProduction::OpAssign)
      derived_rules_spec_operator_rules(origin, claim, journal)
      mutant = derived_rules_spec_rebuild(journal) do |entries|
        entries + entries.select { |entry| entry.token_text == "+=" }
      end
      expect_raises(ArgumentError, "ambiguous scanned token") do
        derived_rules_spec_operator_rules(origin, claim, mutant)
      end
    end

    it "refuses a signed number whose split tail is not journaled in #{suffix} mode" do
      claim, root, journal = derived_rules_spec_claim("x -1\n", suffix)
      origin = derived_rules_spec_operator(root, Iyi::DiagnosticOperatorProduction::SignedNumber)
      derived_rules_spec_operator_rules(origin, claim, journal)
      witness = origin.operator_witnesses[0]
      mutant = derived_rules_spec_rebuild(journal) do |entries|
        entries.reject { |entry| entry.input_start == witness.input_start + 1 }
      end
      expect_raises(ArgumentError, "signed operator split not witnessed") do
        derived_rules_spec_operator_rules(origin, claim, mutant)
      end
    end

    it "refuses index brackets whose inner opener is not an opener in #{suffix} mode" do
      claim, root, journal = derived_rules_spec_claim("a[b[1]]\n", suffix)
      outer = derived_rules_spec_origins(root).select { |origin| origin.operator_production == Iyi::DiagnosticOperatorProduction::Index }
        .max_by { |origin| origin.operator_witnesses[1].input_end }
      derived_rules_spec_operator_rules(outer, claim, journal)
      open = outer.operator_witnesses[0]
      close = outer.operator_witnesses[1]
      mutant = derived_rules_spec_rebuild(journal) do |entries|
        entries.map do |entry|
          if entry.token_kind == "[" && entry.input_start > open.input_start && entry.input_start < close.input_start
            entry.copy_with(token_kind: "X")
          else
            entry
          end
        end
      end
      expect_raises(ArgumentError, "index brackets do not pair") do
        derived_rules_spec_operator_rules(outer, claim, mutant)
      end
    end

    it "refuses an index query suffix that is not right after its closer in #{suffix} mode" do
      claim, root, journal = derived_rules_spec_claim("a[1]?\n", suffix)
      origin = derived_rules_spec_operator(root, Iyi::DiagnosticOperatorProduction::IndexQuery)
      derived_rules_spec_operator_rules(origin, claim, journal)
      mutant = derived_rules_spec_rebuild(journal) do |entries|
        closer = entries.index { |entry| entry.token_kind == "]" }.not_nil!
        query = entries.index { |entry| entry.token_kind == "?" }.not_nil!
        swapped = entries.dup
        swapped[closer], swapped[query] = entries[query], entries[closer]
        swapped
      end
      expect_raises(ArgumentError, "index query suffix not adjacent") do
        derived_rules_spec_operator_rules(origin, claim, mutant)
      end
    end

    it "refuses an assignment whose gap before the equals sign is not tiled by spaces in #{suffix} mode" do
      claim, root, journal = derived_rules_spec_claim("a[1] = 2\n", suffix)
      origin = derived_rules_spec_operator(root, Iyi::DiagnosticOperatorProduction::IndexAssign)
      derived_rules_spec_operator_rules(origin, claim, journal)
      closer = origin.operator_witnesses[1]
      mutant = derived_rules_spec_rebuild(journal) do |entries|
        entries.reject { |entry| entry.token_kind == "SPACE" && entry.input_start == closer.input_end }
      end
      expect_raises(ArgumentError, "assignment witness gap differs") do
        derived_rules_spec_operator_rules(origin, claim, mutant)
      end
    end

    it "refuses an operator witness checked against another source's input in #{suffix} mode" do
      claim, root, journal = derived_rules_spec_claim("x += 1\n", suffix)
      origin = derived_rules_spec_operator(root, Iyi::DiagnosticOperatorProduction::OpAssign)
      derived_rules_spec_operator_rules(origin, claim, journal)
      other, _, _ = derived_rules_spec_claim("y = 2\n", suffix)
      expect_raises(ArgumentError, "operator witnesses use different inputs") do
        derived_rules_spec_operator_rules(origin, other, journal)
      end
    end

    it "refuses a type-sugar witness that is not a scanned token in #{suffix} mode" do
      claim, root, journal = derived_rules_spec_claim("def f(x : Int32*)\nend\n", suffix)
      origin = derived_rules_spec_sugar(root, Iyi::DiagnosticTypeSugar::Pointer)
      derived_rules_spec_sugar_rules(origin, claim, journal)
      mutant = derived_rules_spec_rebuild(journal) { |entries| entries.reject { |entry| entry.token_text == "*" } }
      expect_raises(ArgumentError, "type-sugar witness is not a scanned token") do
        derived_rules_spec_sugar_rules(origin, claim, mutant)
      end
    end

    it "refuses a type-sugar witness checked against another source's input in #{suffix} mode" do
      claim, root, journal = derived_rules_spec_claim("def f(x : Int32*)\nend\n", suffix)
      origin = derived_rules_spec_sugar(root, Iyi::DiagnosticTypeSugar::Pointer)
      derived_rules_spec_sugar_rules(origin, claim, journal)
      other, _, _ = derived_rules_spec_claim("def g(y : Int32)\nend\n", suffix)
      expect_raises(ArgumentError, "type-sugar witnesses use different inputs") do
        derived_rules_spec_sugar_rules(origin, other, journal)
      end
    end

    it "refuses a tuple whose inner opener is not an opener in #{suffix} mode" do
      claim, root, journal = derived_rules_spec_claim("def f(x : {Int32, {Int32, String}})\nend\n", suffix)
      outer = derived_rules_spec_origins(root).select { |origin| origin.production == Iyi::DiagnosticTypeSugar::Tuple }
        .max_by { |origin| origin.witnesses[1].input_end }
      derived_rules_spec_sugar_rules(outer, claim, journal)
      open = outer.witnesses[0]
      close = outer.witnesses[1]
      mutant = derived_rules_spec_rebuild(journal) do |entries|
        entries.map do |entry|
          if entry.token_kind == "{" && entry.input_start > open.input_start && entry.input_start < close.input_start
            entry.copy_with(token_kind: "X")
          else
            entry
          end
        end
      end
      expect_raises(ArgumentError, "type-sugar brackets do not pair") do
        derived_rules_spec_sugar_rules(outer, claim, mutant)
      end
    end
  end
end
