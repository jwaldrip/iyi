require "spec"
require "./support/expectations"
require "../support/tempfile"

CRYSTAL_BIN = ENV.fetch("CRYSTAL_SPEC_COMPILER_BIN") { Path[Dir.current, ".build", "crystal"].to_s }

def crystal
  CRYSTAL_BIN
end

# iyi: the compiler under its own name. Its own binary because its command
# surface is its own — and, for the daemon, because a server is the compiler it
# was built from.
IYI_BIN = ENV.fetch("IYI_SPEC_COMPILER_BIN") { Path[Dir.current, ".build", "iyi"].to_s }

def iyi
  IYI_BIN
end

def fixture_path(name : String)
  File.expand_path(File.join(__DIR__, "fixtures", name))
end
