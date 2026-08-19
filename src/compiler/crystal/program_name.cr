module Crystal
  # iyi: what this binary calls itself when it tells somebody how to call it.
  #
  # The same compiler ships under two names, and a person running `iyi mod` was
  # told "Usage: crystal mod": the name of a program they had not installed.
  # `src/compiler/iyi.cr` sets this, and nothing else does, so `crystal` still
  # says `crystal`. Every usage line, help banner and "run this instead" hint
  # reads it rather than spelling a name, because a hardcoded swap would have to
  # be right in two directions and this only has to be right in one.
  #
  # It lives in its own file, below every layer that reads it, rather than on
  # `Crystal::Command` where it started. The parser names the formatter in a
  # warning, and the parser is compiled without the command layer: a program
  # requiring only `compiler/crystal/syntax` gets `Crystal::Command` as a bare
  # reopened type with no `program_name` on it, so a property on the command
  # class would not compile from there.
  class_property program_name : String = "crystal"
end
