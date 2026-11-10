require "compiler/iyi/syntax"

# Survey of the diagnostic capture frame stream (C2, slice A).
#
# For each source, parse once with the input envelope captured before parsing,
# and digest the frame stream. Then rebuild a fresh parser from that envelope
# alone, require the replay's capture key to equal the original, parse it, and
# require the same frame digest. Any refusal fails the run. Source files are
# only read; no artifact or gate is written.
#
# Usage: diagnostic_replay_survey [--crystal] <source>...
#   --crystal  parse the sources in Crystal lexical mode instead of Iyi mode.
#
# Output per path: path bytes nodes aliases stream_bytes max_n max_f ast_sha256

crystal_mode = ARGV.includes?("--crystal")
paths = ARGV.reject { |arg| arg == "--crystal" }
abort "usage: diagnostic_replay_survey [--crystal] <source>..." if paths.empty?

ok = 0
paths.each do |path|
  begin
    parser = Iyi::Parser.new(File.read(path))
    parser.iyi = !crystal_mode
    parser.filename = path
    parser.diagnostic_source_file = path
    parser.diagnostic_capture = true
    input = parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile, nil,
      Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
    root = parser.parse
    stream = Iyi::DiagnosticAstFrameStream.new(root)
    digest = stream.stream { |_chunk| }

    replay = input.replay_parser
    replay_input = input.replay_capture_input(replay)
    raise "replay capture key differs" unless replay_input.capture_key == input.capture_key
    replay_stream = Iyi::DiagnosticAstFrameStream.new(replay.parse)
    replay_digest = replay_stream.stream { |_chunk| }
    raise "replayed frame digest differs" unless replay_digest == digest

    puts "#{path} #{input.input_bytesize} #{stream.nodes} #{stream.aliases} #{stream.stream_bytes} " \
         "#{stream.max_node_bytes} #{stream.max_filename_bytes} #{digest}"
    ok += 1
  rescue ex
    STDERR.puts "REFUSED #{path}: #{ex.class}: #{ex.message}"
  end
end
puts "RESULT #{ok}/#{paths.size} identical"
exit 1 unless ok == paths.size
