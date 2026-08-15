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
