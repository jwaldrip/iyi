require "../support/syntax"

describe Iyi::DiagnosticPathSnapshot do
  it "freezes every original path segment independently of later AST mutation" do
    source = "Root::Thing"
    parser = Iyi::Parser.new(source)
    parser.filename = "/spec/path_capture.cr"
    parser.diagnostic_source_file = "/spec/path_capture.cr"
    parser.diagnostic_capture = true
    input = parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile,
      nil, Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
    path = parser.parse.as(Iyi::Path)
    snapshot = Iyi::DiagnosticPathSnapshot.new(path, input)
    original = snapshot.bytes
    names = JSON.parse(original)["names"].as_a.map { |field| field["value"].as_s }
    names.should eq(["Root", "Thing"])
    path.names[0] = "Changed"
    path.names.pop
    snapshot.bytes.should eq(original)
    snapshot.sha256.should eq(::Crystal::Digest::SHA256.hexdigest(original))
  end

  it "refuses a path whose actual name has lost its evidence" do
    source = "Root::Thing"
    parser = Iyi::Parser.new(source)
    parser.filename = "/spec/path_capture.cr"
    parser.diagnostic_source_file = "/spec/path_capture.cr"
    parser.diagnostic_capture = true
    input = parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile,
      nil, Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
    path = parser.parse.as(Iyi::Path)
    path.names << "Missing"
    expect_raises(ArgumentError, /does not cover all segments/) do
      Iyi::DiagnosticPathSnapshot.new(path, input)
    end
  end
end

describe Iyi::DiagnosticAstFieldSchema do
  it "classifies bounds and annotations but refuses unclassified fields" do
    Iyi::DiagnosticAstFieldSchema.classify("Def", "where_bounds").should eq(Iyi::DiagnosticAstFieldClass::NamedChildMap)
    Iyi::DiagnosticAstFieldSchema.classify("Def", "free_var_bounds").should eq(Iyi::DiagnosticAstFieldClass::NamedChildMap)
    Iyi::DiagnosticAstFieldSchema.classify("Arg", "parsed_annotations").should eq(Iyi::DiagnosticAstFieldClass::ChildList)
    expect_raises(ArgumentError, /unclassified AST field/) do
      Iyi::DiagnosticAstFieldSchema.classify("Path", "unknown")
    end
  end
end
