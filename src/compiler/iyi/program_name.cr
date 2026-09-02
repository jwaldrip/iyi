# iyi: what this binary is called when it tells somebody how to call it.
#
# The same compiler ships under two names, and a person running `iyi mod` was
# told "Usage: crystal mod" — the name of a program they had not installed.
# `src/compiler/iyi.cr` sets this; nothing else does, so `crystal` says
# `crystal`.
#
# It lives here rather than beside the rest of `Iyi::Command` because the front
# end has no command driver and still has to print its own name:
# `codegen/cache_dir.cr` and `util.cr` both read it, and both are required by
# `crystal_front.cr`, which is defined by not having `command.cr`. Keeping the
# declaration in `command.cr` is what made `make crystal-front` fail with
# "undefined method 'program_name' for Iyi::Command.class".
class Iyi::Command
  class_property program_name : String = "crystal"
end
