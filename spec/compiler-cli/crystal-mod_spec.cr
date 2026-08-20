require "./spec_helper"

# iyi: `crystal mod diff` — the question a consumer of a module asks.
#
# Process-level rather than unit-level because what it answers is a comparison
# of two files on disk, and because the exit code is half of what a script uses
# it for.
private def build_artifact(directory : String, dir_name : String, body : String)
  File.write(File.join(directory, "app", "greeter.iyi"), body)
  Process.capture_result(
    crystal, "build", "--prelude=iyi/prelude", "--no-codegen",
    "--emit-iyimod", dir_name, "-o", "out", "main.iyi",
    chdir: directory
  ).should(be_success)
  File.join(directory, dir_name, "app", "greeter.iyimod")
end

private def with_two_versions(&)
  with_tempdir("mod_diff") do
    Dir.mkdir_p "app"
    # Imports and calls nothing: what these specs are about is the artifact,
    # and a consumer that called `polite` would stop compiling the moment the
    # second version changes it, which is the thing being measured.
    File.write "main.iyi", <<-IYI
      module app/main

      import app/greeter
      IYI

    yield Dir.current
  end
end

describe "`crystal mod diff`" do
  it "says a change that stays inside a body reaches nobody" do
    with_two_versions do |directory|
      before = build_artifact(directory, "v1", <<-IYI)
        module app/greeter

        pub def polite(name : String) : String
          "Hello, \#{name}."
        end
        IYI
      after = build_artifact(directory, "v2", <<-IYI)
        module app/greeter

        pub def polite(name : String) : String
          "Hi, \#{name}!"
        end
        IYI

      result = Process.capture_result(crystal, "mod", "diff", before, after)
      result.should(be_success)
      result.output.should(contain "interface       unchanged")
      result.output.should(contain "do not have to be rebuilt")
    end
  end

  it "names what came and went when the interface moved" do
    with_two_versions do |directory|
      before = build_artifact(directory, "v1", <<-IYI)
        module app/greeter

        pub def polite(name : String) : String
          "Hello, \#{name}."
        end

        pub def title : String
          "greeter"
        end
        IYI
      after = build_artifact(directory, "v2", <<-IYI)
        module app/greeter

        pub def polite(name : String, formal : Bool) : String
          formal ? "Good day." : "Hi."
        end
        IYI

      result = Process.capture_result(crystal, "mod", "diff", before, after)
      result.should(be_success)
      result.output.should(contain "interface       changed")
      result.output.should(contain "gone   def title : String")
      result.output.should(contain "new    def polite(name : String, formal : Bool) : String")
      result.output.should(contain "have to be rebuilt")

      # The exit code is what a script branches on, and only when asked for.
      Process.capture_result(crystal, "mod", "diff", "--exit-code", before, after)
        .status.exit_code.should eq(1)
    end
  end

  it "refuses two different modules" do
    with_two_versions do |directory|
      greeter = build_artifact(directory, "v1", <<-IYI)
        module app/greeter

        pub def polite(name : String) : String
          "Hello, \#{name}."
        end
        IYI

      Process.capture_result(crystal, "mod", "diff", greeter, greeter + ".missing")
        .status.success?.should be_false
    end
  end
end
