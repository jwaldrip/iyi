require "./spec_helper"

describe "`crystal`" do
  describe "general commands" do
    it "shows top-level usage with --help" do
      Process.capture_result(crystal, "--help")
        .should(be_success)
        .output.should(contain("Usage: crystal [command]"))
        .should(contain("Command:"))
    end

    it "prints version information" do
      Process.capture_result(crystal, "--version")
        .should(be_success)
        .output.should(contain("Crystal"))
        .should(contain("LLVM"))
    end
  end

  # iyi: the other half of what `iyi_spec.cr` asserts. The binary reads the name
  # it was invoked as, so a change that made `iyi` right by writing `iyi` into
  # the text would break every one of these.
  describe "usage text names the running program" do
    it "in the tool list" do
      Process.capture_result(crystal, "tool")
        .should(be_success)
        .output.should(contain("Usage: crystal tool [tool] [switches] [program file] [--] [arguments]"))
        .should_not(contain("iyi"))
    end

    it "in the tool list asked for by --help" do
      Process.capture_result(crystal, "tool", "--help")
        .should(be_success)
        .output.should(contain("Usage: crystal tool [tool]"))
    end

    it "in an individual tool's help" do
      Process.capture_result(crystal, "tool", "flags", "--help")
        .should(be_success)
        .output.should(contain("Usage: crystal tool flags"))
    end

    it "in the formatter's help" do
      Process.capture_result(crystal, "tool", "format", "--help")
        .should(be_success)
        .output.should(contain("Usage: crystal tool format"))
    end

    it "in clear_cache's banner, which interpolated nothing at all" do
      Process.capture_result(crystal, "clear_cache", "--help")
        .should(be_success)
        .output.should(contain("Usage: crystal clear_cache"))
        .should_not(contain("program_name"))
    end

    # `.cr.txt`, like `syntax-error.cr.txt`: a `.cr` fixture the formatter is
    # meant to complain about would fail `tool format --check` on this repo.
    it "when a warning names the formatter to run" do
      Process.capture_result(crystal, "build", "--no-codegen", fixture_path("space-before-colon.cr.txt"))
        .should(be_success)
        .error.should(contain("run `crystal tool format` to fix this"))
    end
  end

  describe "filename argument" do
    it "runs a single Crystal file argument" do
      Process.capture_result(crystal, fixture_path("hello-world.cr"))
        .should(be_success)
        .output.should(contain("hello world"))
    end

    it "fails when source file does not exist" do
      Process.capture_result(crystal, "no_such_file.cr")
        .should(be_failure(1))
        .error.should(contain("Error: file 'no_such_file.cr' does not exist"))
    end
  end

  describe "command resolution" do
    it "fails on unknown command" do
      Process.capture_result(crystal, "frobulate")
        .should(be_failure(1))
        .error.should(contain("Error: unknown command: frobulate"))
    end

    it "fails on unknown tool" do
      Process.capture_result(crystal, "tool", "no_such_tool")
        .should(be_failure(1))
        .error.should(contain("Error: unknown tool: no_such_tool"))
    end

    it "accepts command prefix for build" do
      Process.capture_result(crystal, "bu", "--help")
        .should(be_success)
        .output.should(contain("Usage: crystal build"))
    end

    # iyi: `docs` was the other prefix tested here, and the documentation
    # generator is gone (SPEC.md V.11). `mod` is this fork's own command and
    # takes its place.
    it "accepts command prefix for mod" do
      Process.capture_result(crystal, "mo", "--help")
        .should(be_success)
        .output.should(contain("Usage: crystal mod"))
    end

    it "accepts command prefix for spec" do
      Process.capture_result(crystal, "sp", "--help")
        .should(be_success)
        .output.should(contain("Usage: crystal spec"))
    end
  end

  describe "arguments" do
    it "invalid argument value" do
      Process.capture_result(crystal, "--frobulate")
        .should(be_failure(1))
        .error.should(contain("Error: unknown command: --frobulate"))
    end
  end

  it "prints version" do
    version = Process.capture_result(crystal, "env", "CRYSTAL_VERSION")
      .should(be_success).output.strip

    Process.capture_result(crystal, "--version")
      .should(be_success)
      .output.should(contain("Crystal #{version}"))
  end
end
