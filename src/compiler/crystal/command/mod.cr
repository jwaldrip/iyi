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
        dump --declarations FILE print the iyi declarations a consumer compiles
                                 against, which is what `import` reads instead
                                 of the module's source

    A .iyimod is a module's compiled interface: what another module reads
    instead of this one's source (SPEC.md Part IV). Produced by
    `crystal build --emit-iyimod DIR`.
    USAGE

  private def mod_dump
    # Not a flag on the command, because it selects between two whole outputs:
    # the file as it is stored, and the file as the compiler reads it. The
    # second exists so that a diagnostic pointing into a `.iyimod` can be
    # looked at — the text it names is the text this prints.
    declarations = false
    if options.first? == "--declarations"
      options.shift
      declarations = true
    end

    filename = options.shift?
    unless filename
      abort! "expected a .iyimod path", :USAGE_ERROR
    end

    unless File.file?(filename)
      abort! "no such file: #{filename}", :USAGE_ERROR
    end

    begin
      # The one reader that wants the object code. `import` does not — it is a
      # front-end reader and seeks past the section — but a dump that silently
      # left out the largest thing in the file would be the opposite of what
      # this command is for.
      artifact = IyiMod.read(filename, want_object_code: !declarations)
      if declarations
        IyiMod.declarations artifact, STDOUT
      else
        IyiMod.dump artifact, STDOUT
      end
    rescue ex : IyiMod::Error
      abort! ex.message.to_s, :USAGE_ERROR
    end
  end
end
