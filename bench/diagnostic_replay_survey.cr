require "compiler/iyi/syntax"

# Exploratory determinism check, not a capture authority or a strict proof.
# Pass explicit source paths. Any refused input makes the command fail.
abort "usage: diagnostic_replay_survey <source>..." if ARGV.empty?

ok = 0
ARGV.each do |path|
  begin
    source = File.read(path)
    snapshots = Array(String).new(2) do
      parser = Iyi::Parser.new(source)
      parser.filename = path
      parser.diagnostic_source_file = path
      parser.diagnostic_capture = true
      Iyi::DiagnosticAstInventorySnapshot.new(parser.parse).bytes
    end
    raise "different frozen inventories" unless snapshots[0] == snapshots[1]
    ok += 1
  rescue ex
    STDERR.puts "REFUSED #{path}: #{ex.class}: #{ex.message}"
  end
end
puts "RESULT #{ok}/#{ARGV.size} identical"
exit 1 unless ok == ARGV.size
