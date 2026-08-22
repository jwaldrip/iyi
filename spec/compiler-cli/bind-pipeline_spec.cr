require "./spec_helper"

# iyi: the four steps `crystal tool bind` prints, taken.
#
# It prints them because they are what turns a bound shard into something a
# program links against, and nothing had ever run them: the tool's other checks
# are numbers it reports, and a number cannot say whether the last step works.
# When they were first run by hand, three of the four were wrong — an `objcopy`
# line that word-split every symbol containing a space, a module name made by
# downcasing where the inverse of `camelcase` was wanted, and declarations that
# carried the producer's namespace into a file the producer does not read.
#
# Each of those is invisible until something later fails, and the later thing is
# `ld`. This is the spec that fails first instead.
private ROOT = File.expand_path(File.join(__DIR__, "..", ".."))

private def crystal_env
  {"CRYSTAL_PATH" => "lib:#{File.join(ROOT, "src")}"}
end

describe "`crystal tool bind`, all four steps" do
  it "builds and runs a program that calls a bound shard" do
    pending!("requires #{CRYSTAL_BIN} (`make crystal`)") unless File::Info.executable?(CRYSTAL_BIN)
    pending!("requires #{IYI_BIN} (`make iyi`)") unless File::Info.executable?(IYI_BIN)
    nm = Process.find_executable("nm")
    objcopy = Process.find_executable("objcopy")
    pending!("requires binutils: nm and objcopy") unless nm && objcopy

    # Both binaries, from one commit. An artifact is read only by the build that
    # wrote it (SPEC.md IV.5), and `make` bakes the commit in at link time — so
    # a tree where one of the two is a rebuild behind fails here for a reason
    # that has nothing to do with what this is checking. Saying so is cheaper
    # than reading the error.
    build_of = ->(binary : String) do
      Process.capture_result([binary, "--version"]).output.match(/\[([0-9a-f]+)\]/).try &.[1]
    end
    crystal_build = build_of.call(CRYSTAL_BIN)
    iyi_build = build_of.call(IYI_BIN)
    unless crystal_build && iyi_build && crystal_build == iyi_build
      pending!("needs `make crystal iyi` from one commit: crystal is #{crystal_build}, iyi is #{iyi_build}")
    end

    with_tempfile("bind-pipeline") do |dir|
      mods = File.join(dir, "mods")
      Dir.mkdir_p mods

      # `ABCGreeter` on purpose, for both halves of what the name has to
      # survive: an acronym, which `underscore` flattened to `abcgreeter`, and an
      # inner capital, which a plain `downcase` flattened too. `Greeter` would
      # pass through either unchanged and prove nothing.
      File.write File.join(dir, "shard.cr"), <<-CR
        module ABCGreeter
          extend self

          def polite(name : String) : String
            "hello, " + name
          end
        end
        CR

      File.write File.join(dir, "app.iyi"), <<-IYI
        module main

        import a_b_c_greeter
        using a_b_c_greeter

        puts polite("iyi")
        IYI

      Process.capture_result([CRYSTAL_BIN, "tool", "bind", "-e", "ABCGreeter",
                              "--emit-bind", "mods", "shard.cr"],
        chdir: dir, env: crystal_env).should be_success

      # The module's name is the root with `camelcase` undone, so this is the
      # file the tool wrote and not a guess about it.
      File.exists?(File.join(mods, "a_b_c_greeter.iyimod")).should be_true

      Process.capture_result([CRYSTAL_BIN, "build", "--emit", "obj", "--iyi-keep",
                              "ABCGreeter", "-o", "shard", "a_b_c_greeter_keep.cr"],
        chdir: mods, env: crystal_env).should be_success

      # Read rather than piped through a shell. A mangled name carries the types
      # it was compiled for and a union prints with spaces in it, so word
      # splitting loses exactly the symbols with the most interesting signatures.
      listing = Process.capture_result([nm, "shard.o"], chdir: mods)
      listing.should be_success
      symbols = listing.output.lines.compact_map do |line|
        line.match(/^[0-9a-f]+ t (\*ABCGreeter[@:].*)$/).try &.[1]
      end
      symbols.should_not be_empty

      arguments = [objcopy, "--localize-symbol=main", "shard.o", "shard-ready.o"]
      symbols.each { |symbol| arguments << "--globalize-symbol=#{symbol}" }
      Process.capture_result(arguments, chdir: mods).should be_success

      Process.capture_result([IYI_BIN, "build", "--use-iyimod", "mods", "-o", "app",
                              "app.iyi", "--link-flags", File.join(mods, "shard-ready.o")],
        chdir: dir, env: crystal_env).should be_success

      # The claim. Not that it compiled, not that it linked — that the program
      # ran and the answer came from the shard.
      Process.capture_result([File.join(dir, "app")], chdir: dir)
        .output.chomp.should eq "hello, iyi"
    end
  end
end
