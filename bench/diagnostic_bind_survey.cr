require "compiler/iyi/syntax"

# Survey of the replay-bound capture authority (CaptureAuthorityPlan slice A).
#
# Each source is recorded through `DiagnosticCaptureAuthority.record_source`, which
# runs the live parser and mints its authority. Once every source is recorded the
# ledger freezes, and each claim binds against its own authority. A file gets no
# flags: its lexical mode comes from its filename, so `.cr` is Crystal and `.iyi`
# is Iyi. Source files are only read; no artifact or gate is written.
#
# Usage: diagnostic_bind_survey <source>...
#
# Output per path, exactly once: `BOUND <path> <ast_sha256>`, or
# `REFUSED <path> record|bind: <class>: <message>`. Prints `RESULT <bound>/<total>`
# and exits 1 unless every path binds.

paths = ARGV
abort "usage: diagnostic_bind_survey <source>..." if paths.empty?

ledger = Iyi::DiagnosticCaptureLedger.new
recorded = [] of {String, Iyi::AcceptedCaptureInput, Iyi::DiagnosticCaptureAuthority}

paths.each do |path|
  begin
    parser = Iyi::Parser.new(File.read(path), nil, [Set(String).new], Iyi::WarningCollection.new)
    parser.filename = path
    _, claim, authority = Iyi::DiagnosticCaptureAuthority.record_source(ledger, parser)
    recorded << {path, claim, authority}
  rescue ex
    puts "REFUSED #{path} record: #{ex.class}: #{ex.message}"
  end
end

ledger.freeze!

bound = 0
recorded.each do |path, claim, authority|
  begin
    result = ledger.bind!(claim, authority)
    puts "BOUND #{path} #{result.authority.ast_sha256}"
    bound += 1
  rescue ex
    puts "REFUSED #{path} bind: #{ex.class}: #{ex.message}"
  end
end

puts "RESULT #{bound}/#{paths.size}"
exit 1 unless bound == paths.size
