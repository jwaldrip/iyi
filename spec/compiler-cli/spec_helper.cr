require "spec"
require "./support/expectations"
require "../support/tempfile"

CRYSTAL_BIN = ENV.fetch("CRYSTAL_SPEC_COMPILER_BIN") { Path[Dir.current, ".build", "crystal"].to_s }

def crystal
  CRYSTAL_BIN
end

# iyi: the same compiler under its other name. Nothing about it differs except
# the surface it presents, and the surface is what these specs are for.
IYI_BIN = ENV.fetch("IYI_SPEC_COMPILER_BIN") { Path[Dir.current, ".build", "iyi"].to_s }

def iyi
  IYI_BIN
end

def fixture_path(name : String)
  File.expand_path(File.join(__DIR__, "fixtures", name))
end
