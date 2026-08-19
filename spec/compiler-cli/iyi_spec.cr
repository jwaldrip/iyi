require "./spec_helper"

# iyi: one compiler answering to two names, so every claim here has a twin in
# `crystal_spec.cr` asserting that `crystal` did not move. Half of the property
# is that the usage text says `iyi`; the other half is that it says `crystal`
# when `crystal` asks, which is what makes it a name being read rather than a
# name being substituted.
describe "`iyi`" do
  describe "usage text names the running program" do
    it "in the tool list" do
      Process.capture_result(iyi, "tool")
        .should(be_success)
        .output.should(contain("Usage: iyi tool [tool] [switches] [program file] [--] [arguments]"))
        .should_not(contain("crystal"))
    end

    it "in the tool list asked for by --help" do
      Process.capture_result(iyi, "tool", "--help")
        .should(be_success)
        .output.should(contain("Usage: iyi tool [tool]"))
        .should_not(contain("crystal"))
    end

    it "in an individual tool's help" do
      Process.capture_result(iyi, "tool", "flags", "--help")
        .should(be_success)
        .output.should(contain("Usage: iyi tool flags"))
    end

    it "in the formatter's help" do
      Process.capture_result(iyi, "tool", "format", "--help")
        .should(be_success)
        .output.should(contain("Usage: iyi tool format"))
    end

    it "in a delegated command's help" do
      Process.capture_result(iyi, "build", "--help")
        .should(be_success)
        .output.should(contain("Usage: iyi build"))
    end

    it "in this fork's own command" do
      Process.capture_result(iyi, "mod")
        .should(be_success)
        .output.should(contain("Usage: iyi mod"))
        .should(contain("`iyi build --emit-iyimod DIR`"))
    end

    # The banner was a heredoc that interpolated nothing, so the expression
    # reached the terminal as source text. `--help` prints and exits, so this
    # deletes no cache.
    it "in clear_cache's banner, which interpolated nothing at all" do
      Process.capture_result(iyi, "clear_cache", "--help")
        .should(be_success)
        .output.should(contain("Usage: iyi clear_cache"))
        .should_not(contain("program_name"))
    end
  end

  describe "diagnostics name the running program" do
    # The parser is the reason the name does not live on `Crystal::Command`: it
    # points at the formatter, and it is compiled without the command layer.
    it "when a warning names the formatter to run" do
      Process.capture_result(iyi, "build", "--no-codegen", fixture_path("space-before-colon.iyi"))
        .should(be_success)
        .error.should(contain("run `iyi tool format` to fix this"))
    end

    it "when a build falls back from a daemon that is not there" do
      Process.capture_result(iyi, "build", "--no-codegen", fixture_path("space-before-colon.iyi"),
        env: {"CRYSTAL_DAEMON_SOCKET" => "/nonexistent/iyi-build.sock"})
        .should(be_success)
        .error.should(contain("iyi: no daemon at /nonexistent/iyi-build.sock"))
    end
  end
end
