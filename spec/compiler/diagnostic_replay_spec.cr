require "../support/syntax"

# Fresh-parser replay fidelity for AcceptedCaptureInput.
#
# Each supported capture is taken from a parser. A fresh parser is then rebuilt
# from the recorded input alone: its text, its decoded fresh-parser contract,
# and its warning policy. The rebuilt parser must capture an identical input,
# and parsing the same text must yield byte-identical path evidence.
#
# Unsupported captures are asserted to raise their exact refusal message. None
# is skipped, pending, or counted as passing. Refusals are listed in the
# "refused captures" group below.

private class ReplayCustomWarnings < Iyi::WarningCollection
end

private def replay_fixture_parser(source : String, filename : String, *,
                                  source_unit : Bool = true,
                                  package : String? = nil,
                                  source_only : Bool = false,
                                  wants_doc : Bool = false,
                                  visibility : Iyi::Visibility? = nil,
                                  warnings : Iyi::WarningCollection = Iyi::WarningCollection.new,
                                  var_scopes : Array(Set(String)) = [Set(String).new]) : Iyi::Parser
  parser = Iyi::Parser.new(source, nil, var_scopes, warnings)
  parser.filename = filename
  parser.diagnostic_source_file = filename if source_unit
  parser.iyi_package_name = package
  parser.iyi_source_only = source_only
  parser.wants_doc = wants_doc
  parser.visibility = visibility
  parser.diagnostic_capture = true
  parser
end

private def replay_capture_input(parser : Iyi::Parser,
                                 kind : Iyi::DiagnosticCaptureInputKind = Iyi::DiagnosticCaptureInputKind::SourceFile,
                                 logical_module : String? = nil,
                                 mode : Iyi::Parser::ParseMode = Iyi::Parser::ParseMode::Normal) : Iyi::AcceptedCaptureInput
  parser.diagnostic_capture_input(kind, logical_module, Iyi::DiagnosticCaptureParseEntry::Parse, mode)
end

private def replay_parse_mode_for(mode : Iyi::DiagnosticCaptureParseMode) : Iyi::Parser::ParseMode
  case mode
  when .normal?              then Iyi::Parser::ParseMode::Normal
  when .lib?                 then Iyi::Parser::ParseMode::Lib
  when .lib_struct_or_union? then Iyi::Parser::ParseMode::LibStructOrUnion
  when .enum?                then Iyi::Parser::ParseMode::Enum
  else                            raise ArgumentError.new("unmapped capture parse mode")
  end
end

# Rebuilds the warning collection from the recorded policy. A lib path is
# cwd-derived and private to WarningCollection, so the driver refuses rather
# than approximate it.
private def replay_warnings(policy : Iyi::WarningCollection::ParseAheadPolicy) : Iyi::WarningCollection
  if policy.lib_path
    raise ArgumentError.new("replay driver cannot rebuild a lib_path policy")
  end
  warnings = Iyi::WarningCollection.new
  warnings.level = policy.level
  warnings.explain_spawn = policy.explain_spawn
  warnings.error_on_warnings = policy.error_on_warnings?
  policy.excluded_paths.each { |path| warnings.exclude_path(path) }
  warnings
end

# Builds a fresh parser from the recorded input. Everything comes from the
# input's text, its decoded contract JSON, and its warning policy. The parser
# is never handed the original parser object.
private def replay_parser_from(input : Iyi::AcceptedCaptureInput,
                               source : String = input.input,
                               warnings : Iyi::WarningCollection = replay_warnings(input.warning_policy)) : Iyi::Parser
  fields = JSON.parse(input.fresh_parser_contract).as_h
  scopes = fields["scopes"].as_a.map { |scope| Set(String).new(scope.as_a.map(&.as_s)) }
  parser = Iyi::Parser.new(source, nil, scopes, warnings)
  filename = fields["filename"].as_s
  parser.filename = filename
  parser.diagnostic_source_file = filename if fields["source_unit"].as_s?
  parser.iyi_package_name = fields["package"].as_s?
  parser.iyi_source_only = fields["source_only"].as_bool
  parser.iyi_module_extends_written = fields["module_extends_written"].as_bool
  visibility = fields["visibility"].as_s?
  parser.visibility = visibility ? Iyi::Visibility.parse(visibility) : nil
  parser.def_nest = fields["def_nest"].as_i
  parser.fun_nest = fields["fun_nest"].as_i
  parser.type_nest = fields["type_nest"].as_i
  parser.wants_doc = fields["wants_doc"].as_bool
  parser.diagnostic_capture = true
  parser
end

private def replay_capture(original : Iyi::AcceptedCaptureInput, parser : Iyi::Parser) : Iyi::AcceptedCaptureInput
  parser.diagnostic_capture_input(original.kind, original.logical_module, original.entry,
    replay_parse_mode_for(original.mode))
end

private def replay_assert_identical(original : Iyi::AcceptedCaptureInput,
                                    replay : Iyi::AcceptedCaptureInput) : Nil
  replay.input.should eq(original.input)
  replay.input_sha256.should eq(original.input_sha256)
  replay.lexical_mode.should eq(original.lexical_mode)
  replay.fresh_parser_contract.should eq(original.fresh_parser_contract)
  replay.warning_policy_json.should eq(original.warning_policy_json)
  replay.same_candidate?(original, original.input).should be_true
end

private def replay_expect_identical(original : Iyi::AcceptedCaptureInput) : Nil
  replay_assert_identical(original, replay_capture(original, replay_parser_from(original)))
end

# Parses the same source in the original parser and in a fresh replay parser.
# Returns both captured inputs and both trees, with the identity check applied.
private def replay_parse_pair(source : String, filename : String) : {Iyi::AcceptedCaptureInput, Iyi::AcceptedCaptureInput, Iyi::ASTNode, Iyi::ASTNode}
  parser = replay_fixture_parser(source, filename)
  original = replay_capture_input(parser)
  root = parser.parse
  replay_parser = replay_parser_from(original)
  replay = replay_capture(original, replay_parser)
  replay_assert_identical(original, replay)
  replay_root = replay_parser.parse
  {original, replay, root, replay_root}
end

private def replay_assert_path(original : Iyi::AcceptedCaptureInput,
                               replay : Iyi::AcceptedCaptureInput,
                               path : Iyi::Path,
                               replayed : Iyi::Path,
                               names : Array(String)) : Nil
  expected = Iyi::DiagnosticPathSnapshot.new(path, original)
  actual = Iyi::DiagnosticPathSnapshot.new(replayed, replay)
  actual.bytes.should eq(expected.bytes)
  actual.sha256.should eq(expected.sha256)
  JSON.parse(actual.bytes)["names"].as_a.map { |field| field["value"].as_s }.should eq(names)
  Iyi::DiagnosticRecordedEvidenceInputCheck.new(original).verify!(replayed)
end

private def replay_direct_input(input : String, lexical_mode : String = "Iyi") : Iyi::AcceptedCaptureInput
  policy = Iyi::WarningCollection::ParseAheadPolicy.new(Iyi::WarningLevel::All, [] of String, nil,
    Iyi::WarningCollection::ExplainSpawn::None, false)
  Iyi::AcceptedCaptureInput.new(input, Iyi::DiagnosticCaptureInputKind::SourceFile, nil, nil,
    "/spec/replay/direct.iyi", lexical_mode, Iyi::DiagnosticCaptureParseEntry::Parse,
    Iyi::DiagnosticCaptureParseMode::Normal, false, false, nil, 0, 0, 0, false, [[] of String],
    policy, "{}")
end

describe "AcceptedCaptureInput fresh-parser replay" do
  describe "identity replay of supported captures" do
    [".iyi", ".cr"].each do |extension|
      [Iyi::Parser::ParseMode::Normal, Iyi::Parser::ParseMode::Lib,
       Iyi::Parser::ParseMode::LibStructOrUnion, Iyi::Parser::ParseMode::Enum].each do |mode|
        it "replays #{extension} source captured in #{mode} mode" do
          parser = replay_fixture_parser("Root::Thing", "/spec/replay/matrix#{extension}")
          original = replay_capture_input(parser, mode: mode)
          original.lexical_mode.should eq(extension == ".iyi" ? "Iyi" : "Crystal")
          original.mode.to_s.should eq(mode.to_s)
          replay_expect_identical(original)
        end
      end
    end

    it "replays an entry buffer with a logical module and no source unit" do
      parser = replay_fixture_parser("Root::Thing", "/spec/replay/buffer.iyi", source_unit: false)
      original = replay_capture_input(parser, Iyi::DiagnosticCaptureInputKind::EntryBuffer, logical_module: "app/buffer")
      original.kind.entry_buffer?.should be_true
      original.logical_module.should eq("app/buffer")
      JSON.parse(original.fresh_parser_contract)["source_unit"].raw.should be_nil
      replay_expect_identical(original)
    end

    it "replays a byte-order-marked source with the recorded offset base" do
      parser = replay_fixture_parser("\uFEFFRoot::Thing", "/spec/replay/bom.iyi")
      original = replay_capture_input(parser)
      original.input.starts_with?('\uFEFF').should be_true
      JSON.parse(original.fresh_parser_contract)["input_offset_base"].as_i.should eq(3)
      replay_expect_identical(original)
    end

    it "replays package, source-only, documentation, and visibility state" do
      parser = replay_fixture_parser("Root::Thing", "/spec/replay/state.iyi", package: "app",
        source_only: true, wants_doc: true, visibility: Iyi::Visibility::Public)
      original = replay_capture_input(parser)
      fields = JSON.parse(original.fresh_parser_contract)
      fields["package"].as_s.should eq("app")
      fields["source_only"].as_bool.should be_true
      fields["wants_doc"].as_bool.should be_true
      fields["visibility"].as_s.should eq("Public")
      replay_expect_identical(original)
    end

    it "replays variable scopes in their recorded sorted order" do
      parser = replay_fixture_parser("Root::Thing", "/spec/replay/scopes.iyi",
        var_scopes: [Set.new(["zeta", "alpha"]), Set.new(["beta"])])
      original = replay_capture_input(parser)
      original.scopes.should eq([["alpha", "zeta"], ["beta"]])
      replay_expect_identical(original)
    end
  end

  describe "replayed evidence for names, types, and bounds" do
    it "replays Iyi path names with byte-identical evidence" do
      original, replay, root, replay_root = replay_parse_pair("Root::Thing", "/spec/replay/path.iyi")
      original.lexical_mode.should eq("Iyi")
      replay_assert_path(original, replay, root.as(Iyi::Path), replay_root.as(Iyi::Path), ["Root", "Thing"])
    end

    it "replays Crystal path names with byte-identical evidence" do
      original, replay, root, replay_root = replay_parse_pair("Root::Thing", "/spec/replay/path.cr")
      original.lexical_mode.should eq("Crystal")
      replay.lexical_mode.should eq("Crystal")
      replay_assert_path(original, replay, root.as(Iyi::Path), replay_root.as(Iyi::Path), ["Root", "Thing"])
    end

    it "replays a type restriction path with byte-identical evidence" do
      original, replay, root, replay_root = replay_parse_pair("def f(x : Root::Thing)\nend", "/spec/replay/types.iyi")
      restriction = root.as(Iyi::Def).args.first.restriction.as(Iyi::Path)
      replayed = replay_root.as(Iyi::Def).args.first.restriction.as(Iyi::Path)
      replay_assert_path(original, replay, restriction, replayed, ["Root", "Thing"])
      Iyi::DiagnosticRecordedEvidenceInputCheck.new(original).verify!(replay_root)
    end

    it "replays forall bounds with the same declared-name evidence" do
      original, replay, root, replay_root = replay_parse_pair("def f(x : T) forall T : Show\nend", "/spec/replay/bounds.iyi")
      bounds = root.as(Iyi::Def).free_var_bounds.not_nil!
      bounds.keys.should eq(["T"])
      bounds["T"].as(Iyi::Path).names.should eq(["Show"])
      replayed_bounds = replay_root.as(Iyi::Def).free_var_bounds.not_nil!
      replayed_bounds.keys.should eq(["T"])
      replayed_bounds["T"].as(Iyi::Path).names.should eq(["Show"])
      Iyi::DiagnosticRecordedEvidenceInputCheck.new(original).verify!(replay_root)
      Iyi::DiagnosticRecordedEvidenceInputCheck.new(replay).verify!(root)
    end
  end

  describe "changed input and parse-policy negative controls" do
    it "refuses a replay whose input changed by one byte" do
      source = "Root::Thing"
      parser = replay_fixture_parser(source, "/spec/replay/changed.iyi")
      original = replay_capture_input(parser)
      original_path = parser.parse.as(Iyi::Path)
      changed = replay_capture(original, replay_parser_from(original, source: source + " "))
      changed.input_sha256.should_not eq(original.input_sha256)
      changed.fresh_parser_contract.should eq(original.fresh_parser_contract)
      changed.same_candidate?(original, original.input).should be_false
      expect_raises(ArgumentError, /input mismatch/) do
        Iyi::DiagnosticPathSnapshot.new(original_path, changed)
      end
    end

    it "refuses a replay whose warning policy changed" do
      parser = replay_fixture_parser("Root::Thing", "/spec/replay/policy.iyi")
      original = replay_capture_input(parser)
      policy = original.warning_policy
      flipped = replay_warnings(policy)
      flipped.error_on_warnings = !policy.error_on_warnings?
      changed = replay_capture(original, replay_parser_from(original, warnings: flipped))
      changed.warning_policy_json.should_not eq(original.warning_policy_json)
      changed.fresh_parser_contract.should eq(original.fresh_parser_contract)
      changed.same_candidate?(original, original.input).should be_false
    end

    it "captures different inputs for different parse policies" do
      default = replay_capture_input(replay_fixture_parser("Root::Thing", "/spec/replay/policy.iyi"))
      strict_warnings = Iyi::WarningCollection.new
      strict_warnings.error_on_warnings = true
      strict = replay_capture_input(replay_fixture_parser("Root::Thing", "/spec/replay/policy.iyi",
        warnings: strict_warnings))
      strict.warning_policy.error_on_warnings?.should be_true
      strict.warning_policy_json.should_not eq(default.warning_policy_json)
      strict.same_candidate?(default, default.input).should be_false
    end

    it "refuses a replay whose recorded package changed" do
      parser = replay_fixture_parser("Root::Thing", "/spec/replay/pkg.iyi", package: "app")
      original = replay_capture_input(parser)
      changed_parser = replay_parser_from(original)
      changed_parser.iyi_package_name = "other"
      changed = replay_capture(original, changed_parser)
      changed.fresh_parser_contract.should_not eq(original.fresh_parser_contract)
      changed.same_candidate?(original, original.input).should be_false
    end

    it "refuses a replay whose recorded nesting changed" do
      parser = replay_fixture_parser("Root::Thing", "/spec/replay/nest.iyi")
      original = replay_capture_input(parser)
      changed_parser = replay_parser_from(original)
      changed_parser.def_nest = 1
      changed = replay_capture(original, changed_parser)
      changed.fresh_parser_contract.should_not eq(original.fresh_parser_contract)
      changed.same_candidate?(original, original.input).should be_false
    end

    it "captures a different lexical mode for the same text under another extension" do
      iyi = replay_capture_input(replay_fixture_parser("Root::Thing", "/spec/replay/lex.iyi"))
      cr = replay_capture_input(replay_fixture_parser("Root::Thing", "/spec/replay/lex.cr"))
      iyi.lexical_mode.should eq("Iyi")
      cr.lexical_mode.should eq("Crystal")
      cr.fresh_parser_contract.should_not eq(iyi.fresh_parser_contract)
      cr.same_candidate?(iyi, iyi.input).should be_false
    end

    it "refuses to replay a warning policy with a lib path it cannot rebuild exactly" do
      warnings = Iyi::WarningCollection.new
      warnings.exclude_lib_path = true
      parser = replay_fixture_parser("Root::Thing", "/spec/replay/lib_path.iyi", warnings: warnings)
      original = replay_capture_input(parser)
      expect_raises(ArgumentError, /cannot rebuild a lib_path policy/) do
        replay_parser_from(original)
      end
    end
  end

  describe "refused captures" do
    it "refuses a parser without a filename" do
      parser = Iyi::Parser.new("Root::Thing")
      parser.diagnostic_capture = true
      expect_raises(ArgumentError, /parser state is not eligible for capture/) do
        replay_capture_input(parser)
      end
    end

    it "refuses a parser whose mutable reader escaped" do
      parser = replay_fixture_parser("Root::Thing", "/spec/replay/reader.iyi")
      parser.reader
      expect_raises(ArgumentError, /parser state is not eligible for capture/) do
        replay_capture_input(parser)
      end
    end

    it "refuses a parser whose mutable token escaped" do
      parser = replay_fixture_parser("Root::Thing", "/spec/replay/token.iyi")
      parser.token
      expect_raises(ArgumentError, /parser state is not eligible for capture/) do
        replay_capture_input(parser)
      end
    end

    it "refuses a parser that has already parsed" do
      parser = replay_fixture_parser("Root::Thing", "/spec/replay/parsed.iyi")
      parser.parse
      expect_raises(ArgumentError, /parser state is not eligible for capture/) do
        replay_capture_input(parser)
      end
    end

    it "refuses a warning collection that cannot be represented" do
      parser = replay_fixture_parser("Root::Thing", "/spec/replay/custom.iyi", warnings: ReplayCustomWarnings.new)
      expect_raises(ArgumentError, /warning policy is not representable for capture/) do
        replay_capture_input(parser)
      end
    end

    it "refuses the ParseMode entry because it needs its original Def context" do
      parser = replay_fixture_parser("Root::Thing", "/spec/replay/entry.iyi")
      expect_raises(ArgumentError, /capture entry requires original Def context/) do
        parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile, nil,
          Iyi::DiagnosticCaptureParseEntry::ParseMode, Iyi::Parser::ParseMode::Normal)
      end
    end

    it "refuses the ParseToDef entry because it needs its original Def context" do
      parser = replay_fixture_parser("Root::Thing", "/spec/replay/entry.iyi")
      expect_raises(ArgumentError, /capture entry requires original Def context/) do
        parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile, nil,
          Iyi::DiagnosticCaptureParseEntry::ParseToDef, Iyi::Parser::ParseMode::Normal)
      end
    end

    it "refuses a macro expansion kind because it needs binding, lineage, and pragmas" do
      parser = replay_fixture_parser("Root::Thing", "/spec/replay/macro.iyi")
      expect_raises(ArgumentError, /macro capture requires expansion binding/) do
        parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::MacroExpansion, nil,
          Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
      end
    end

    it "refuses a negative nesting depth" do
      parser = replay_fixture_parser("Root::Thing", "/spec/replay/negative_nest.iyi")
      parser.def_nest = -1
      expect_raises(ArgumentError, /invalid capture nesting/) do
        replay_capture_input(parser)
      end
    end

    it "refuses a source file with an empty original filename" do
      parser = replay_fixture_parser("Root::Thing", "", source_unit: false)
      expect_raises(ArgumentError, /source capture requires original file identity/) do
        replay_capture_input(parser)
      end
    end
  end

  describe "refused bounds on direct construction" do
    it "refuses an input over the 64 MiB capture bound" do
      oversized = "a" * (Iyi::AcceptedCaptureInput::MAX_INPUT_BYTES + 1)
      expect_raises(ArgumentError, /capture input exceeds 64 MiB/) do
        replay_direct_input(oversized)
      end
    end

    it "refuses input that is not UTF-8" do
      invalid = String.new(Bytes[0xff_u8])
      expect_raises(ArgumentError, /capture input is not UTF-8/) do
        replay_direct_input(invalid)
      end
    end

    it "refuses an unknown lexical mode" do
      expect_raises(ArgumentError, /unknown capture lexical mode/) do
        replay_direct_input("Root::Thing", lexical_mode: "Ruby")
      end
    end
  end
end
