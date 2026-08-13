# iyi: `crystal mod dump FILE` — read a `.iyimod` back as text.
#
# Under the eventual `iyi` binary this reads `iyi mod dump`, which is the
# spelling SPEC.md IV.1 uses. It is required rather than optional there, and the
# reason is worth keeping in view: an opaque cache format is one nobody can
# debug, and a build cache that cannot be inspected is a build cache that gets
# distrusted and disabled.
class Crystal::Command
  private def mod
    case options.first?
    when "dump"
      options.shift
      mod_dump
    when nil, "--help", "-h"
      puts MOD_USAGE
      exit
    else
      abort! "unknown mod subcommand: #{options.first}", :USAGE_ERROR
    end
  end

  MOD_USAGE = <<-USAGE
    Usage: crystal mod [subcommand]

    Subcommand:
        dump FILE                print a .iyimod as text

    A .iyimod is a module's compiled interface: what another module reads
    instead of this one's source (SPEC.md Part IV). Produced by
    `crystal build --emit-iyimod DIR`.
    USAGE

  private def mod_dump
    filename = options.shift?
    unless filename
      abort! "expected a .iyimod path", :USAGE_ERROR
    end

    unless File.file?(filename)
      abort! "no such file: #{filename}", :USAGE_ERROR
    end

    begin
      IyiMod.dump IyiMod.read(filename), STDOUT
    rescue ex : IyiMod::Error
      abort! ex.message.to_s, :USAGE_ERROR
    end
  end
end
