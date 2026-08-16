require "../spec_helper"
require "./spec_helper"

describe "Compiler" do
  it "has a valid version" do
    SemanticVersion.parse(Crystal::Config.version)
  end

  it "compiles a file" do
    with_temp_executable "compiler_spec_output" do |path|
      Crystal::Command.run ["build"].concat(program_flags_options).concat([compiler_datapath("compiler_sample"), "-o", path])

      File.exists?(path).should be_true

      Process.capture(path).should eq("Hello!")
    end
  end

  # iyi: the linker probe is asked once per `PATH`, not once per build.
  #
  # Before linking, the compiler searches `PATH` for `mold` and then for
  # `ld.lld`. A name that is not on `PATH` costs a stat in every entry of it —
  # a millisecond on an ordinary Linux box, and 0.062 s per search under WSL,
  # where `PATH` carries the Windows directories. Twice a build, that was a
  # third of a warm build spent looking for linkers nobody had installed
  # (SPEC.md 0.1.0 item 2). This is the file that keeps the answer.
  it "remembers which linker it found rather than searching PATH per build" do
    with_temp_executable "compiler_spec_output" do |path|
      Crystal::Command.run ["build"].concat(program_flags_options).concat([compiler_datapath("compiler_sample"), "-o", path])

      probe = Crystal::CacheDir.instance.join("linker-probe")
      File.exists?(probe).should be_true
      # The `PATH` it was found under, so that changing `PATH` asks again.
      File.read(probe).lines.first.size.should eq 32
    end
  end

  # iyi: the link is the compiler's, not the driver's.
  #
  # `cc` does not link — it computes a command and runs `collect2`, which runs
  # `ld`. Measured here: 0.129 s through the driver against 0.014 s running the
  # same command directly, which is most of what a warm build costs (SPEC.md
  # 0.1.0 item 2). The compiler asks the driver once, keeps the answer as a
  # template, and runs `ld` itself. This is the file that holds the template,
  # and the program above having run is what says the link it built works.
  it "builds the link itself rather than asking the driver every time" do
    with_temp_executable "compiler_spec_output" do |path|
      Crystal::Command.run ["build"].concat(program_flags_options).concat([compiler_datapath("compiler_sample"), "-o", path])
      Process.capture(path).should eq("Hello!")

      # One file per set of link flags. Absent on a platform where this is not
      # attempted, which is a fallback rather than a failure — but where it is
      # attempted it must be usable.
      templates = Dir.glob(File.join(Crystal::CacheDir.instance.dir, "link-template-*"))
      templates.each do |template|
        File.read(template).lines[1]?.should_not eq "unusable"
      end
    end
  end

  # iyi: the cache cleaner asks before it deletes.
  #
  # It keeps the ten most recently modified directories in the cache and
  # removes the rest, and it runs at the end of every compile. A build's
  # directory stops looking recent while its units sit in an optimization
  # pass, writing nothing — so with enough builds around, one compiler process
  # deleted the directory another was writing its object files into. That
  # arrived as "No such file or directory" from the object emitter, or as a
  # linker asking for a `_main.o0.o` nobody had written: a lost hour reading
  # linker output for something the linker had not done.
  #
  # A build already says it is using its directory. It holds `compiler.lock`
  # there for the whole of codegen and linking; the cleaner reads it now.
  it "keeps a cache directory another compile is working in" do
    with_tempfile("cache-in-use") do |root|
      Dir.mkdir_p(root)

      working, idle = File.join(root, "working"), File.join(root, "idle")
      [working, idle].each do |dir|
        Dir.mkdir_p(dir)
        File.write(File.join(dir, "program.o"), "")
        File.write(File.join(dir, "compiler.lock"), "")
      end

      cache = Crystal::CacheDir.instance
      cache.directory_in_use?(working).should be_false # a lock nobody holds

      # Both are the oldest in a cache of twelve, so the rule above would have
      # both of them; one of them is being written to.
      12.times { |i| Dir.mkdir_p(File.join(root, "newer-#{i}")) }

      File.open(File.join(working, "compiler.lock"), "r") do |lock|
        lock.flock_exclusive(blocking: false)
        cache.directory_in_use?(working).should be_true

        cache.cleanup(root)

        File.exists?(File.join(working, "program.o")).should be_true
        Dir.exists?(idle).should be_false
      end

      cache.directory_in_use?(working).should be_false # released with the file
    end
  end

  it "runs subcommand in preference to a filename " do
    Dir.cd compiler_datapath do
      with_temp_executable "compiler_spec_output" do |path|
        Crystal::Command.run ["build"].concat(program_flags_options).concat(["compiler_sample", "-o", path])

        File.exists?(path).should be_true

        Process.capture(path).should eq("Hello!")
      end
    end
  end
end
