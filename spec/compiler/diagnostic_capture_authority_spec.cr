require "../support/syntax"

# CaptureAuthorityPlan slice A (D3). A capture authority is minted only by the
# live parse that ran (`DiagnosticCaptureAuthority.record_source`), and a claim
# binds only against an authority with an equal key whose replay reproduces it.
#
# Every capture is recorded over a real temp file, because the recorder classifies
# a capture by reading those bytes. Positive controls must bind. Each negative
# control changes one thing in an honest claim and must refuse with its own
# message. The D4 and D2 controls at the end run the evidence walk on replayed
# trees, the way bind! does after its digest check.

AUTHORITY_SPEC_HEADER = "module sample/identity\nvalue = 1\n"
AUTHORITY_SPEC_PLAIN  = "value = 1\n"
AUTHORITY_SPEC_D4     = "lib LibA\n  fun a : Int32\nend\nlib LibB\n  fun a = puts : Int32\nend\n"

# Writes `source` to a temp file for the block, then removes it.
private def authority_spec_with_file(source : String, stem : String, suffix : String = ".iyi", & : String ->)
  path = File.tempname(stem, suffix)
  File.write(path, source)
  begin
    yield path
  ensure
    File.delete(path) if File.file?(path)
  end
end

# The live parser of a build site: the file's bytes and name, empty scopes, no warnings.
private def authority_spec_parser(source : String, path : String) : Iyi::Parser
  parser = Iyi::Parser.new(source, nil, [Set(String).new], Iyi::WarningCollection.new)
  parser.filename = path
  parser
end

# Records `parser` into a new ledger, freezes it and binds the claim.
private def authority_spec_bind(parser : Iyi::Parser, mode : Iyi::Parser::ParseMode = Iyi::Parser::ParseMode::Normal) : Iyi::DiagnosticBoundCapture
  ledger = Iyi::DiagnosticCaptureLedger.new
  _, claim, authority = Iyi::DiagnosticCaptureAuthority.record_source(ledger, parser, mode)
  ledger.freeze!
  ledger.bind!(claim, authority)
end

# Records `parser` and freezes its ledger, returning what a negative control needs.
private def authority_spec_recorded(parser : Iyi::Parser) : {Iyi::DiagnosticCaptureLedger, Iyi::AcceptedCaptureInput, Iyi::DiagnosticCaptureAuthority}
  ledger = Iyi::DiagnosticCaptureLedger.new
  _, claim, authority = Iyi::DiagnosticCaptureAuthority.record_source(ledger, parser)
  ledger.freeze!
  {ledger, claim, authority}
end

# Binds a mutant claim against an authority and returns the refusal message.
private def authority_spec_refusal(ledger : Iyi::DiagnosticCaptureLedger, claim : Iyi::AcceptedCaptureInput,
                                   authority : Iyi::DiagnosticCaptureAuthority) : String
  ledger.bind!(claim, authority)
  raise "bind unexpectedly succeeded"
rescue ex : ArgumentError
  ex.message.to_s
end

# The honest contract JSON with one field replaced and every other field unchanged.
private def authority_spec_contract(json : String, field : String, value : JSON::Any) : String
  fields = JSON.parse(json).as_h
  fields[field] = value
  fields.to_json
end

# A claim rebuilt from explicit fields, so exactly one of them can differ.
private def authority_spec_rebuild(claim : Iyi::AcceptedCaptureInput, input : String, original_file : String?,
                                   logical_module : String?, package : String?,
                                   mode : Iyi::DiagnosticCaptureParseMode, contract : String) : Iyi::AcceptedCaptureInput
  Iyi::AcceptedCaptureInput.new(input, claim.kind, logical_module, package, original_file,
    claim.lexical_mode, claim.entry, mode, claim.module_extends_written, claim.source_only,
    claim.visibility, claim.def_nest, claim.fun_nest, claim.type_nest, claim.wants_doc,
    claim.scopes, claim.warning_policy, contract)
end

# The replayed root and journal, built as bind! builds them, before the walk.
private def authority_spec_replay(claim : Iyi::AcceptedCaptureInput) : {Iyi::ASTNode, Iyi::DiagnosticReplayJournal}
  parser = claim.replay_parser
  parser.enable_diagnostic_observations
  root = claim.replay_entry(parser)
  {root, Iyi::DiagnosticReplayJournal.new(parser.diagnostic_lexical_observations)}
end

# The walk bind! runs after its digest check, on a root a control may have mutated.
private def authority_spec_walk(claim : Iyi::AcceptedCaptureInput, root : Iyi::ASTNode,
                                journal : Iyi::DiagnosticReplayJournal) : Nil
  identity = Iyi::DiagnosticModuleIdentity.from(root, claim, journal)
  structural = Iyi::DiagnosticUnnamedParamBinder.new(claim, journal).verify!(root)
  Iyi::DiagnosticEvidenceBinding.new(claim, journal, identity, structural).verify!(root)
end

# The first fun of each lib in a root that is either one lib or several libs.
private def authority_spec_lib_funs(root : Iyi::ASTNode) : Array(Iyi::FunDef)
  libs = root.is_a?(Iyi::Expressions) ? root.expressions : [root] of Iyi::ASTNode
  libs.map do |lib|
    body = lib.as(Iyi::LibDef).body
    (body.is_a?(Iyi::Expressions) ? body.expressions.first : body).as(Iyi::FunDef)
  end
end

describe "CaptureAuthorityPlan slice A: positive controls" do
  it "AU-P1 binds a file with a module header to its declared module" do
    authority_spec_with_file(AUTHORITY_SPEC_HEADER, "identity") do |path|
      bound = authority_spec_bind(authority_spec_parser(AUTHORITY_SPEC_HEADER, path))
      bound.identity.declared.should eq "sample/identity"
    end
  end

  it "AU-P2 binds a header-less file under its live package" do
    authority_spec_with_file(AUTHORITY_SPEC_PLAIN, "plain") do |path|
      parser = authority_spec_parser(AUTHORITY_SPEC_PLAIN, path)
      parser.iyi_package_name = "app"
      bound = authority_spec_bind(parser)
      bound.identity.declared.should be_nil
      bound.identity.package.should eq "app"
    end
  end

  it "AU-P3 binds a file with a byte order mark" do
    authority_spec_with_file("\uFEFF#{AUTHORITY_SPEC_PLAIN}", "bom") do |path|
      bound = authority_spec_bind(authority_spec_parser("\uFEFF#{AUTHORITY_SPEC_PLAIN}", path))
      bound.input.input.starts_with?('\uFEFF').should be_true
    end
  end

  it "AU-P4 binds a .cr file in Crystal mode, and a .iyi file with iyi set false after filename" do
    authority_spec_with_file(AUTHORITY_SPEC_PLAIN, "crystal", ".cr") do |path|
      authority_spec_bind(authority_spec_parser(AUTHORITY_SPEC_PLAIN, path)).input.lexical_mode.should eq "Crystal"
    end
    authority_spec_with_file(AUTHORITY_SPEC_PLAIN, "iyi_off") do |path|
      parser = authority_spec_parser(AUTHORITY_SPEC_PLAIN, path)
      parser.iyi = false
      authority_spec_bind(parser).input.lexical_mode.should eq "Crystal"
    end
  end

  it "AU-P5 binds a parser whose settable fields are non-default, and records them" do
    authority_spec_with_file(AUTHORITY_SPEC_PLAIN, "fields") do |path|
      parser = authority_spec_parser(AUTHORITY_SPEC_PLAIN, path)
      parser.wants_doc = true
      parser.iyi_reads_using = true
      parser.comments_enabled = true
      parser.count_whitespace = true
      parser.wants_raw = true
      parser.slash_is_regex = false
      parser.wants_regex = false
      parser.wants_symbol = false
      bound = authority_spec_bind(parser)
      fields = JSON.parse(bound.input.fresh_parser_contract).as_h
      fields["reads_using"].as_bool.should be_true
      fields["wants_regex"].as_bool.should be_false
      fields["wants_symbol"].as_bool.should be_false
    end
  end

  it "AU-P6 binds the Lib, LibStructOrUnion and Enum entries, each in its own mode" do
    authority_spec_with_file("fun abs(x : Int32) : Int32\n", "lib_mode") do |path|
      authority_spec_bind(authority_spec_parser("fun abs(x : Int32) : Int32\n", path), Iyi::Parser::ParseMode::Lib)
    end
    authority_spec_with_file("x : Int32\n", "struct_mode") do |path|
      authority_spec_bind(authority_spec_parser("x : Int32\n", path), Iyi::Parser::ParseMode::LibStructOrUnion)
    end
    authority_spec_with_file("A = 1\nB\n", "enum_mode") do |path|
      authority_spec_bind(authority_spec_parser("A = 1\nB\n", path), Iyi::Parser::ParseMode::Enum)
    end
  end

  it "AU-P7 keeps two files in one ledger, each bound to its own authority" do
    authority_spec_with_file(AUTHORITY_SPEC_HEADER, "first") do |first|
      authority_spec_with_file(AUTHORITY_SPEC_PLAIN, "second") do |second|
        ledger = Iyi::DiagnosticCaptureLedger.new
        _, first_claim, first_authority = Iyi::DiagnosticCaptureAuthority.record_source(ledger, authority_spec_parser(AUTHORITY_SPEC_HEADER, first))
        _, second_claim, second_authority = Iyi::DiagnosticCaptureAuthority.record_source(ledger, authority_spec_parser(AUTHORITY_SPEC_PLAIN, second))
        ledger.freeze!
        ledger.size.should eq 2
        ledger.authority(first_claim.capture_key).should eq first_authority
        ledger.authority(second_claim.capture_key).should eq second_authority
        ledger.bind!(first_claim, first_authority).identity.declared.should eq "sample/identity"
        ledger.bind!(second_claim, second_authority).identity.declared.should be_nil
      end
    end
  end
end

describe "CaptureAuthorityPlan slice A: negative controls" do
  it "AU-N1 refuses a claim whose reads_using differs from its authority" do
    authority_spec_with_file(AUTHORITY_SPEC_PLAIN, "n1") do |path|
      ledger, claim, authority = authority_spec_recorded(authority_spec_parser(AUTHORITY_SPEC_PLAIN, path))
      mutant = authority_spec_rebuild(claim, claim.input, claim.original_file, claim.logical_module, claim.package,
        claim.mode, authority_spec_contract(claim.fresh_parser_contract, "reads_using", JSON::Any.new(true)))
      authority_spec_refusal(ledger, mutant, authority).should eq "capture key differs from its authority"
    end
  end

  it "AU-N2 refuses a SourceFile whose source unit names another file" do
    authority_spec_with_file(AUTHORITY_SPEC_PLAIN, "n2") do |path|
      _, claim, _ = authority_spec_recorded(authority_spec_parser(AUTHORITY_SPEC_PLAIN, path))
      contract = authority_spec_contract(claim.fresh_parser_contract, "source_unit", JSON::Any.new("source-file:/elsewhere"))
      expect_raises(ArgumentError, "source capture unit differs from its file") do
        authority_spec_rebuild(claim, claim.input, claim.original_file, claim.logical_module, claim.package, claim.mode, contract)
      end
    end
  end

  it "AU-N3 refuses a claim whose entry mode differs from its authority" do
    authority_spec_with_file(AUTHORITY_SPEC_PLAIN, "n3") do |path|
      ledger, claim, authority = authority_spec_recorded(authority_spec_parser(AUTHORITY_SPEC_PLAIN, path))
      mutant = authority_spec_rebuild(claim, claim.input, claim.original_file, claim.logical_module, claim.package,
        Iyi::DiagnosticCaptureParseMode::Lib, claim.fresh_parser_contract)
      authority_spec_refusal(ledger, mutant, authority).should eq "capture key differs from its authority"
    end
  end

  it "AU-N4 refuses a header-less claim whose package differs from its authority" do
    authority_spec_with_file(AUTHORITY_SPEC_PLAIN, "n4") do |path|
      parser = authority_spec_parser(AUTHORITY_SPEC_PLAIN, path)
      parser.iyi_package_name = "app"
      ledger, claim, authority = authority_spec_recorded(parser)
      contract = authority_spec_contract(claim.fresh_parser_contract, "package", JSON::Any.new("other"))
      mutant = authority_spec_rebuild(claim, claim.input, claim.original_file, claim.logical_module, "other", claim.mode, contract)
      authority_spec_refusal(ledger, mutant, authority).should eq "capture key differs from its authority"
    end
  end

  it "AU-N5 refuses the input bytes plus a trailing comment" do
    authority_spec_with_file(AUTHORITY_SPEC_PLAIN, "n5") do |path|
      ledger, claim, authority = authority_spec_recorded(authority_spec_parser(AUTHORITY_SPEC_PLAIN, path))
      mutant = authority_spec_rebuild(claim, "#{claim.input}# trailing\n", claim.original_file, claim.logical_module,
        claim.package, claim.mode, claim.fresh_parser_contract)
      authority_spec_refusal(ledger, mutant, authority).should eq "capture key differs from its authority"
    end
  end

  it "AU-N6 refuses an original file decoy, with its contract edited to match" do
    authority_spec_with_file(AUTHORITY_SPEC_PLAIN, "n6") do |path|
      ledger, claim, authority = authority_spec_recorded(authority_spec_parser(AUTHORITY_SPEC_PLAIN, path))
      contract = authority_spec_contract(claim.fresh_parser_contract, "filename", JSON::Any.new("/spec/decoy.iyi"))
      contract = authority_spec_contract(contract, "source_unit", JSON::Any.new("source-file:/spec/decoy.iyi"))
      mutant = authority_spec_rebuild(claim, claim.input, "/spec/decoy.iyi", claim.logical_module, claim.package, claim.mode, contract)
      authority_spec_refusal(ledger, mutant, authority).should eq "capture key differs from its authority"
    end
  end

  it "AU-N7 refuses a caller-supplied logical module" do
    authority_spec_with_file(AUTHORITY_SPEC_PLAIN, "n7") do |path|
      ledger, claim, authority = authority_spec_recorded(authority_spec_parser(AUTHORITY_SPEC_PLAIN, path))
      mutant = authority_spec_rebuild(claim, claim.input, claim.original_file, "forged/module", claim.package,
        claim.mode, claim.fresh_parser_contract)
      authority_spec_refusal(ledger, mutant, authority).should eq "capture key differs from its authority"
    end
  end

  it "AU-N8 refuses file B's claim against file A's authority" do
    authority_spec_with_file(AUTHORITY_SPEC_HEADER, "a") do |path_a|
      authority_spec_with_file(AUTHORITY_SPEC_PLAIN, "b") do |path_b|
        ledger_a, _, authority_a = authority_spec_recorded(authority_spec_parser(AUTHORITY_SPEC_HEADER, path_a))
        _, claim_b, _ = authority_spec_recorded(authority_spec_parser(AUTHORITY_SPEC_PLAIN, path_b))
        authority_spec_refusal(ledger_a, claim_b, authority_a).should eq "capture key differs from its authority"
      end
    end
  end

  it "AU-N9 refuses a temp file whose bytes differ from the parser input, and a missing file" do
    authority_spec_with_file("value = 2\n", "n9") do |path|
      expect_raises(ArgumentError, "EntryBuffer capture has no written identity rule") do
        authority_spec_recorded(authority_spec_parser("value = 1\n", path))
      end
    end
    expect_raises(ArgumentError, "EntryBuffer capture has no written identity rule") do
      authority_spec_recorded(authority_spec_parser(AUTHORITY_SPEC_PLAIN, "/spec/authority/missing.iyi"))
    end
  end

  it "AU-N10 refuses a SourceFile whose contract carries no source unit" do
    authority_spec_with_file(AUTHORITY_SPEC_PLAIN, "n10") do |path|
      _, claim, _ = authority_spec_recorded(authority_spec_parser(AUTHORITY_SPEC_PLAIN, path))
      contract = authority_spec_contract(claim.fresh_parser_contract, "source_unit", JSON::Any.new(nil))
      expect_raises(ArgumentError, "source capture unit differs from its file") do
        authority_spec_rebuild(claim, claim.input, claim.original_file, claim.logical_module, claim.package, claim.mode, contract)
      end
    end
  end

  it "AU-N11 refuses to record after the ledger is frozen" do
    ledger = Iyi::DiagnosticCaptureLedger.new
    ledger.freeze!
    expect_raises(ArgumentError, "capture ledger is frozen") do
      Iyi::DiagnosticCaptureAuthority.record_source(ledger, authority_spec_parser(AUTHORITY_SPEC_PLAIN, "/spec/authority/frozen.iyi"))
    end
  end

  it "AU-N12 refuses every flipped boolean the contract records but the constructor does not check" do
    authority_spec_with_file(AUTHORITY_SPEC_PLAIN, "n12") do |path|
      ledger, claim, authority = authority_spec_recorded(authority_spec_parser(AUTHORITY_SPEC_PLAIN, path))
      fields = JSON.parse(claim.fresh_parser_contract).as_h
      %w(reads_using doc_enabled comments_enabled count_whitespace wants_raw slash_is_regex wants_regex
         wants_def_or_macro_name wants_symbol).each do |field|
        contract = authority_spec_contract(claim.fresh_parser_contract, field, JSON::Any.new(!fields[field].as_bool))
        mutant = authority_spec_rebuild(claim, claim.input, claim.original_file, claim.logical_module, claim.package,
          claim.mode, contract)
        authority_spec_refusal(ledger, mutant, authority).should eq "capture key differs from its authority"
      end
    end
  end
end

describe "CaptureAuthorityPlan slice A: ledger rules" do
  it "refuses to bind before the ledger is frozen" do
    authority_spec_with_file(AUTHORITY_SPEC_PLAIN, "open") do |path|
      ledger = Iyi::DiagnosticCaptureLedger.new
      _, claim, authority = Iyi::DiagnosticCaptureAuthority.record_source(ledger, authority_spec_parser(AUTHORITY_SPEC_PLAIN, path))
      expect_raises(ArgumentError, "capture ledger must be frozen before binding") do
        ledger.bind!(claim, authority)
      end
    end
  end

  it "refuses an authority minted by another ledger" do
    authority_spec_with_file(AUTHORITY_SPEC_PLAIN, "foreign") do |path|
      _, claim, authority = authority_spec_recorded(authority_spec_parser(AUTHORITY_SPEC_PLAIN, path))
      other = Iyi::DiagnosticCaptureLedger.new
      other.freeze!
      expect_raises(ArgumentError, "capture authority belongs to another ledger") do
        other.bind!(claim, authority)
      end
    end
  end
end

describe "CaptureAuthorityPlan slice A: evidence controls on replayed trees" do
  it "D4-A refuses a fun that borrows another fun's name and real-name tokens" do
    authority_spec_with_file(AUTHORITY_SPEC_D4, "d4a") do |path|
      _, claim, _ = authority_spec_recorded(authority_spec_parser(AUTHORITY_SPEC_D4, path))
      root, journal = authority_spec_replay(claim)
      authority_spec_walk(claim, root, journal)
      root, journal = authority_spec_replay(claim)
      fa, fb = authority_spec_lib_funs(root)
      fa.real_name = "puts"
      fa.diagnostic_name_slots = fb.diagnostic_name_slots
      expect_raises(ArgumentError, "fun name is not the token after its fun keyword") do
        authority_spec_walk(claim, root, journal)
      end
    end
  end

  it "D4-B refuses an implicit real name forged from a parameter token" do
    source = "lib L\n  fun a = b : Int32\n  fun c(a : Int32) : Int32\nend\n"
    authority_spec_with_file(source, "d4b") do |path|
      _, claim, _ = authority_spec_recorded(authority_spec_parser(source, path))
      root, journal = authority_spec_replay(claim)
      funs = root.as(Iyi::LibDef).body.as(Iyi::Expressions).expressions.map(&.as(Iyi::FunDef))
      primary = Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::Primary)
      funs[0].real_name = "a"
      funs[0].diagnostic_name_slots = {primary => funs[1].args[0].diagnostic_name_slots[primary]}
      expect_raises(ArgumentError, "fun name is not the token after its fun keyword") do
        authority_spec_walk(claim, root, journal)
      end
    end
  end

  it "D4-C refuses two funs whose origins and name slots are swapped across libs" do
    source = "lib LibA\n  fun a\nend\nlib LibB\n  fun a = puts\nend\n"
    authority_spec_with_file(source, "d4c") do |path|
      _, claim, _ = authority_spec_recorded(authority_spec_parser(source, path))
      root, journal = authority_spec_replay(claim)
      fa, fb = authority_spec_lib_funs(root)
      origin_a = fa.diagnostic_origin
      slots_a = fa.diagnostic_name_slots
      fa.diagnostic_origin = fb.diagnostic_origin
      fa.diagnostic_name_slots = fb.diagnostic_name_slots
      fa.real_name = "puts"
      fb.diagnostic_origin = origin_a
      fb.diagnostic_name_slots = slots_a
      fb.real_name = "a"
      expect_raises(ArgumentError, /fun anchor lies outside its lib/) do
        authority_spec_walk(claim, root, journal)
      end
    end
  end

  it "D4-twin refuses a changed real name that does not carry the borrowed slots" do
    authority_spec_with_file(AUTHORITY_SPEC_D4, "d4twin") do |path|
      _, claim, _ = authority_spec_recorded(authority_spec_parser(AUTHORITY_SPEC_D4, path))
      root, journal = authority_spec_replay(claim)
      fa, _ = authority_spec_lib_funs(root)
      fa.real_name = "puts"
      expect_raises(ArgumentError, "invalid implicit foreign-name observation") do
        authority_spec_walk(claim, root, journal)
      end
    end
  end

  it "D2 refuses a heredoc string through the bound walk" do
    source = "x = <<-EOS\n  hello\n  EOS\n"
    authority_spec_with_file(source, "heredoc") do |path|
      expect_raises(ArgumentError, "literal evidence requires journal literal binding") do
        authority_spec_bind(authority_spec_parser(source, path))
      end
    end
  end

  it "D2 refuses a require, whose string source text has no literal evidence yet" do
    source = "require \"json\"\n"
    authority_spec_with_file(source, "require", ".cr") do |path|
      expect_raises(ArgumentError, "literal evidence requires journal literal binding") do
        authority_spec_bind(authority_spec_parser(source, path))
      end
    end
  end

  it "D2 refuses an asm template, whose source text has no literal evidence yet" do
    source = "def f\n  asm(\"nop\")\nend\n"
    authority_spec_with_file(source, "asm", ".cr") do |path|
      expect_raises(ArgumentError, "literal evidence requires journal literal binding") do
        authority_spec_bind(authority_spec_parser(source, path))
      end
    end
  end
end
