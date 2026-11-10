require "../spec_helper"
require "./spec_helper"

class Iyi::ParseAhead
  def wait_for_contract_spec(filename : String) : Nil
    @mutex.synchronize do
      entry = @entries[filename]? || raise "source was not queued"
      until entry.state.done?
        @parsed.wait(@mutex)
      end
    end
  end
end

private class CustomParseAheadWarnings < Iyi::WarningCollection
end

private class CustomParseAheadPool < StringPool
end

private class CustomParseAheadParser < Iyi::Parser
  getter custom_parse_called = false

  def parse
    @custom_parse_called = true
    super
  end
end

private class ParseAheadDefNameFinder < Iyi::Visitor
  getter name : String? = nil

  def visit(node : Iyi::ASTNode)
    true
  end

  def visit(node : Iyi::Def)
    @name = node.name if node.name == "value"
    true
  end
end

private def with_ahead_contract_fixture(source = "module app/left\npub def value : Int32\n  1\nend\n", capture = true, &)
  with_tempdir("parse_ahead_contract") do
    Dir.mkdir_p("app")
    File.write("main.iyi", "module main\nimport app/left\n")
    File.write("app/left.iyi", source)
    filename = Iyi.native_path(File.join(Dir.current, "app/left.iyi"))
    program = Iyi::Program.new
    program.filename = File.expand_path("main.iyi")
    program.diagnostic_capture = capture
    entry = Iyi::Parser.parse(File.read("main.iyi"))
    ahead = Iyi::ParseAhead.start(program, entry, 2).should_not be_nil
    begin
      ahead.wait_for_contract_spec(filename)
      yield program, ahead, filename, source
    ensure
      ahead.stop
    end
  end
end

describe "parse-ahead parser contract" do
  it "takes a worker result only for a matching fresh parser" do
    with_ahead_contract_fixture(capture: false) do |program, ahead, filename, source|
      parser = program.new_parser(source)
      parser.filename = filename
      ahead.parse(parser, filename, source).to_s.should contain("value")
      parser.reader.pos.should eq(0)
    end
  end

  it "takes a worker's equal-valued identifier from its own string pool" do
    with_ahead_contract_fixture(capture: false) do |program, ahead, filename, source|
      consumer_name = program.string_pool.get("value")
      parser = program.new_parser(source)
      parser.filename = filename
      nodes = ahead.parse(parser, filename, source)
      parser.reader.pos.should eq(0)
      finder = ParseAheadDefNameFinder.new
      nodes.accept(finder)
      worker_name = finder.name.should_not be_nil
      worker_name.should eq(consumer_name)
      worker_name.same?(consumer_name).should be_false
    end
  end

  it "runs a custom parser instead of substituting a base-parser result" do
    with_ahead_contract_fixture(capture: false) do |_program, ahead, filename, source|
      parser = CustomParseAheadParser.new(source)
      parser.filename = filename
      ahead.parse(parser, filename, source).to_s.should contain("value")
      parser.custom_parse_called.should be_true
    end
  end

  it "refuses captured worker acceptance without an authenticated registry" do
    with_ahead_contract_fixture do |program, ahead, filename, source|
      parser = program.new_parser(source)
      parser.filename = filename
      parser.diagnostic_source_file = filename
      expect_raises(ArgumentError, /authenticated frozen registry/) do
        ahead.parse(parser, filename, source)
      end
    end
  end

  it "parses locally when the string-pool handler is not the worker's concrete type" do
    with_ahead_contract_fixture do |program, ahead, filename, source|
      parser = Iyi::Parser.new(source, CustomParseAheadPool.new, [Set(String).new], program.warnings)
      parser.diagnostic_capture = true
      parser.filename = filename
      parser.diagnostic_source_file = filename
      parser.parse_ahead_contract.should be_nil
      ahead.parse(parser, filename, source).to_s.should contain("value")
      parser.reader.pos.should be > 0
    end
  end

  it "parses locally after the mutable reader escapes" do
    with_ahead_contract_fixture do |program, ahead, filename, source|
      parser = program.new_parser(source)
      parser.filename = filename
      parser.diagnostic_source_file = filename
      parser.reader
      parser.parse_ahead_contract.should be_nil
      ahead.parse(parser, filename, source).to_s.should contain("value")
      parser.reader.pos.should be > 0
    end
  end

  it "parses locally after the mutable token escapes" do
    with_ahead_contract_fixture do |program, ahead, filename, source|
      parser = program.new_parser(source)
      parser.filename = filename
      parser.diagnostic_source_file = filename
      parser.token
      parser.parse_ahead_contract.should be_nil
      ahead.parse(parser, filename, source).to_s.should contain("value")
      parser.reader.pos.should be > 0
    end
  end

  it "parses locally when source-only mode differs" do
    with_ahead_contract_fixture do |program, ahead, filename, source|
      parser = program.new_parser(source)
      parser.filename = filename
      parser.diagnostic_source_file = filename
      parser.iyi_source_only = true
      ahead.parse(parser, filename, source).to_s.should contain("value")
      parser.reader.pos.should be > 0
    end
  end

  it "parses locally when the lexical scope differs" do
    with_ahead_contract_fixture do |program, ahead, filename, source|
      parser = program.new_parser(source, [Set{"existing"}])
      parser.filename = filename
      parser.diagnostic_source_file = filename
      ahead.parse(parser, filename, source).to_s.should contain("value")
      parser.reader.pos.should be > 0
    end
  end

  it "parses locally when the header policy differs" do
    with_ahead_contract_fixture do |program, ahead, filename, source|
      parser = program.new_parser(source)
      parser.filename = filename
      parser.diagnostic_source_file = filename
      parser.iyi_module_extends_written = true
      ahead.parse(parser, filename, source).to_s.should contain("value")
      parser.reader.pos.should be > 0
    end
  end

  it "parses the consumer input when it differs from the supplied worker source" do
    with_ahead_contract_fixture do |program, ahead, filename, source|
      input = "module app/left\npub def different : Int32\n  2\nend\n"
      parser = program.new_parser(input)
      parser.filename = filename
      parser.diagnostic_source_file = filename
      result = ahead.parse(parser, filename, source)
      result.to_s.should contain("different")
      parser.reader.pos.should be > 0
    end
  end

  it "rejects a worker result when warning policy differs" do
    with_ahead_contract_fixture do |program, ahead, filename, source|
      parser = program.new_parser(source)
      parser.filename = filename
      parser.diagnostic_source_file = filename
      parser.warnings.level = Iyi::WarningLevel::None
      ahead.parse(parser, filename, source).to_s.should contain("value")
      parser.reader.pos.should be > 0
    end
  end

  it "does not reuse a worker under an unrecognized warning handler" do
    with_ahead_contract_fixture do |program, ahead, filename, source|
      parser = program.new_parser(source)
      parser.filename = filename
      parser.diagnostic_source_file = filename
      parser.warnings = CustomParseAheadWarnings.new
      ahead.parse(parser, filename, source).to_s.should contain("value")
      parser.reader.pos.should be > 0
    end
  end

  it "rejects a worker after the consumer warning exclusions change" do
    with_ahead_contract_fixture do |program, ahead, filename, source|
      parser = program.new_parser(source)
      parser.filename = filename
      parser.diagnostic_source_file = filename
      parser.warnings.exclude_path(filename)
      ahead.parse(parser, filename, source).to_s.should contain("value")
      parser.reader.pos.should be > 0
    end
  end

  it "delivers accepted worker warnings to the consumer's collection" do
    source = "module app/left\npub def value: Int32\n  1\nend\n"
    with_ahead_contract_fixture(source, false) do |program, ahead, filename, input|
      parser = program.new_parser(input)
      parser.filename = filename
      recipient = Iyi::WarningCollection.new
      parser.warnings = recipient
      ahead.parse(parser, filename, input)
      parser.reader.pos.should eq(0)
      recipient.reports.size.should eq(1)
      program.warnings.reports.should be_empty
    end
  end

  it "delivers worker warnings once in consumer order after existing reports" do
    with_tempdir("parse_ahead_warning_order") do
      Dir.mkdir_p("app")
      main = "module main\nimport app/left\nimport app/right\n"
      left = "module app/left\npub def left: Int32\n  1\nend\n"
      right = "module app/right\npub def right: Int32\n  2\nend\n"
      File.write("main.iyi", main)
      File.write("app/left.iyi", left)
      File.write("app/right.iyi", right)
      program = Iyi::Program.new
      program.filename = File.expand_path("main.iyi")
      program.warnings.add_warning_at(nil, "already present")
      ahead = Iyi::ParseAhead.start(program, Iyi::Parser.parse(main), 2).should_not be_nil
      begin
        left_path = Iyi.native_path(File.join(Dir.current, "app/left.iyi"))
        right_path = Iyi.native_path(File.join(Dir.current, "app/right.iyi"))
        ahead.wait_for_contract_spec(left_path)
        ahead.wait_for_contract_spec(right_path)
        right_parser = program.new_parser(right)
        right_parser.filename = right_path
        ahead.parse(right_parser, right_path, right)
        right_parser.reader.pos.should eq(0)
        left_parser = program.new_parser(left)
        left_parser.filename = left_path
        ahead.parse(left_parser, left_path, left)
        left_parser.reader.pos.should eq(0)
        reports = program.warnings.infos
        reports.size.should eq(3)
        reports[0].should contain("already present")
        reports[1].should contain("right.iyi")
        reports[2].should contain("left.iyi")

        second = program.new_parser(left)
        second.filename = left_path
        second.warnings = Iyi::WarningCollection.new.tap { |warnings| warnings.level = Iyi::WarningLevel::None }
        ahead.parse(second, left_path, left)
        second.reader.pos.should be > 0
        program.warnings.reports.size.should eq(3)
      ensure
        ahead.stop
      end
    end
  end

  it "keeps a fork's warning policy independent of later exclusions" do
    original = Iyi::WarningCollection.new
    worker = original.fork
    original.parse_ahead_policy.should eq(worker.parse_ahead_policy)
    original.exclude_path("new-exclusion")
    original.parse_ahead_policy.should_not eq(worker.parse_ahead_policy)
  end

  it "reconstructs worker warnings from the frozen policy, not later mutations" do
    original = Iyi::WarningCollection.new
    original.exclude_path("initial-exclusion")
    snapshot = original.parse_ahead_snapshot.should_not be_nil
    snapshot.excluded_paths.clear
    original.exclude_path("later-exclusion")
    worker = Iyi::WarningCollection.from_parse_ahead_snapshot(snapshot)
    worker.parse_ahead_policy.should eq(snapshot.fingerprint)
    worker.parse_ahead_policy.should_not eq(original.parse_ahead_policy)
  end

  it "lets the consumer report its own parse failure after a failed worker" do
    source = "module app/left\npub def value : Int32\n  1 +\nend\n"
    with_ahead_contract_fixture(source, false) do |program, ahead, filename, input|
      parser = program.new_parser(input)
      parser.filename = filename
      expect_raises(Iyi::SyntaxException) { ahead.parse(parser, filename, input) }
      parser.reader.pos.should be > 0
    end
  end

  it "compares the actual parser input including the BOM" do
    content = "module app/left\n"
    parser = Iyi::Parser.new("\uFEFF#{content}")
    parser.filename = "app/left.iyi"
    parser.parse_ahead_input_matches?("\uFEFF#{content}").should be_true
    parser.parse_ahead_input_matches?(content).should be_false
    Iyi::Parser.new(content).parse_ahead_input_matches?("\uFEFF#{content}").should be_false
  end
end
