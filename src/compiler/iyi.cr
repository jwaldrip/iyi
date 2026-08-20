# iyi: the compiler under its own name.
#
# Everything here delegates to `Iyi::Command`, which is the same compiler
# doing the same work — iyi is a fork of Crystal and this file does not pretend
# otherwise. What it changes is the surface a person meets: the commands iyi
# has, a usage line that names them, and a version that says what it is built
# from.
#
# The commands left out are left out on purpose. `init` and `spec` belong to a
# language with a package layout and a spec runner, and iyi has neither. The
# playground and the documentation generator are not here at all: they went the
# way the interpreter went, for the reason SPEC.md V.11 gives. The interpreter
# itself came back as the `repl` slice, on the macro evaluator rather than the
# removed runtime one, which is the call SPEC.md III.11 records.
{% raise("Please use `make iyi` to build it, or set the i_know_what_im_doing flag if you know what you're doing") unless env("CRYSTAL_HAS_WRAPPER") || flag?("i_know_what_im_doing") %}

require "log"
require "./requires"

Log.setup_from_env(default_level: :warn, default_sources: "crystal.*")

{% if Fiber.has_constant?(:ExecutionContext) %}
  Fiber::ExecutionContext.default.resize(Fiber::ExecutionContext.default_workers_count)
{% end %}

module Iyi
  USAGE = <<-USAGE
    Usage: iyi [command] [switches] [program file] [--] [arguments]

    Command:
        build                    build an executable
        run                      build and run a program (default)
        mod                      inspect a .iyimod module artifact
        repl                     a session: one line in, its value out
        env                      print environment information
        clear_cache              clear the compiler cache
        tool                     formatter and editor tools, Crystal's
        version                  print the version
        help                     print this text

    Switches worth knowing:
        --crystal                build against Crystal's standard library
        --emit-iyimod DIR        write a .iyimod per imported module into DIR
        --use-iyimod DIR         compile imports from DIR's .iyimod files
        --no-codegen             analyse only, produce nothing
        --release                optimise, and take longer about it

    A `.iyi` entry file gets iyi's prelude; `--crystal` gives it Crystal's
    instead, and there `require "kemal"` means what it means in Crystal. The
    rules do not change with the library. See SPEC.md for the design and
    README.md for what is and is not here.
    USAGE

  # What the binary calls itself, read from `src/IYI_VERSION` — the same file
  # the artifact's compatibility check reads (SPEC.md IV.5) and the same one
  # the Makefile names the tarball after. One number, so a released binary, the
  # artifacts it writes and the file it arrived in cannot disagree.
  VERSION = Iyi::Config.iyi_version

  # The ones that are this compiler doing this compiler's job.
  DELEGATED = %w(build run mod repl env clear_cache tool)

  # The ones that belong to Crystal and are still in the binary underneath.
  # Named rather than swallowed, because "unknown command" would be a lie.
  #
  # `eval` is here because of what it compiles: it has no filename, so it gets
  # Crystal's prelude and Crystal's rules, and `iyi eval 'require "json"'`
  # worked. A command that answers in another language is worse than one that
  # says where it went.
  CRYSTAL_ONLY = %w(init spec eval)

  def self.description : String
    String.build do |io|
      io << "iyi " << VERSION << ", a fork of " << Iyi::Config.description.lines.first
      io << "\n\nThe compiler was not built in release mode." unless Iyi::Config.release_mode?
    end
  end

  def self.run(options = ARGV) : Nil
    # The delegated commands print their own usage, and it used to name the
    # binary underneath instead of the one that was typed.
    Iyi::Command.program_name = "iyi"

    command = options.first?

    case command
    when nil
      puts USAGE
      exit
    when "help", "--help", "-h"
      puts USAGE
      exit
    when "version", "--version", "-v"
      puts description
      exit
    when .in?(CRYSTAL_ONLY)
      STDERR.puts "iyi has no `#{command}`: it belongs to Crystal, which this compiler is a fork of."
      STDERR.puts "Run it with the `crystal` binary in this checkout if you need it."
      exit 1
    when .in?(DELEGATED)
      Iyi::Command.run(options)
    else
      # A filename, which `crystal foo.iyi` reads as "run this". Kept, because
      # it is the shortest thing to type and the shell already made it a path.
      if File.file?(command)
        Iyi::Command.run(options)
      else
        STDERR.puts "iyi: unknown command or missing file: #{command}"
        STDERR.puts "Run `iyi help` for what there is."
        exit 1
      end
    end
  end
end

Iyi.run
