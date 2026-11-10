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

private def with_ahead_contract_fixture(source = "module app/left\npub def value : Int32\n  1\nend\n", &)
  with_tempdir("parse_ahead_contract") do
    Dir.mkdir_p("app")
    File.write("main.iyi", "module main\nimport app/left\n")
    File.write("app/left.iyi", source)
    filename = Iyi.native_path(File.join(Dir.current, "app/left.iyi"))
    program = Iyi::Program.new
    program.filename = File.expand_path("main.iyi")
    program.diagnostic_capture = true
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
    with_ahead_contract_fixture do |program, ahead, filename, source|
      parser = program.new_parser(source)
      parser.filename = filename
      parser.diagnostic_source_file = filename
      ahead.parse(parser, filename, source).to_s.should contain("value")
      parser.reader.pos.should eq(0)
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

  it "delivers accepted worker warnings to the consumer's collection" do
    source = "module app/left\npub def value: Int32\n  1\nend\n"
    with_ahead_contract_fixture(source) do |program, ahead, filename, input|
      parser = program.new_parser(input)
      parser.filename = filename
      parser.diagnostic_source_file = filename
      recipient = Iyi::WarningCollection.new
      parser.warnings = recipient
      ahead.parse(parser, filename, input)
      parser.reader.pos.should eq(0)
      recipient.reports.size.should eq(1)
      program.warnings.reports.should be_empty
    end
  end

  it "keeps a fork's warning policy independent of later exclusions" do
    original = Iyi::WarningCollection.new
    worker = original.fork
    original.parse_ahead_policy.should eq(worker.parse_ahead_policy)
    original.exclude_path("new-exclusion")
    original.parse_ahead_policy.should_not eq(worker.parse_ahead_policy)
  end
end
