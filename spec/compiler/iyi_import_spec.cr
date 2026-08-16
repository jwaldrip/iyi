require "../spec_helper"
require "./spec_helper"

# iyi: `import`, which resolves against files on disk — SPEC.md R-1.
#
# `spec/compiler/semantic/iyi_spec.cr` covers everything that needs only a
# module to exist and declares it inline. What is left is what only real files
# can show: where an imported module is declared, and what happens when the
# module a build imports arrives as a `.iyimod` instead of as source.
private def with_iyi_modules(files : Hash(String, String), &)
  with_tempdir("iyi_import") do
    files.each do |path, source|
      directory = File.dirname(path)
      Dir.mkdir_p(directory) unless directory == "."
      File.write path, source
    end
    yield Dir.current
  end
end

private def semantic_iyi(entry : String, iyi_module_dir : String? = nil)
  program = Crystal::Program.new
  program.color = false
  program.filename = File.expand_path(entry)
  program.iyi_module_dir = iyi_module_dir

  parser = program.new_parser(File.read(entry))
  parser.filename = program.filename
  node = program.normalize(parser.parse)
  program.semantic node

  program
end

private def artifact_signature(name : String, parameters = [] of String, return_type = "")
  Crystal::IyiMod::Signature.new(name, "", parameters, "", return_type,
    [] of String, false)
end

private def exports(functions = [] of Crystal::IyiMod::Signature,
                    types = [] of Crystal::IyiMod::TypeDecl,
                    impls = [] of Crystal::IyiMod::ImplRecord)
  Crystal::IyiMod::Exports.new(functions, types, impls)
end

# Written by hand rather than by a compile, so that what a consumer is being
# fed is on the page: these specs are about what reading one does.
private def write_iyimod(dir : String, module_name : String,
                         exports = exports,
                         imports = [] of String,
                         compiler_version = Crystal::IyiMod.compiler_version)
  reference = Crystal::Program.new
  artifact = Crystal::IyiMod::Artifact.new(
    module_name: module_name,
    source_path: "#{module_name}.iyi",
    compiler_version: compiler_version,
    target_triple: reference.codegen_target.to_s,
    flags: reference.flags.to_a.sort!,
    imports: imports.map { |name| Crystal::IyiMod::ImportEdge.new(name) },
    exports: exports,
  )
  Crystal::IyiMod.write artifact, File.join(dir, "#{module_name}.iyimod")
end

describe "Semantic: iyi import" do
  # iyi: what the compiler says the first time somebody meets these rules.
  # Each of these used to answer with a fact about the compiler's internals —
  # an undefined constant nobody wrote, a name it could not find — rather than
  # with the rule that was broken and what to write instead.
  describe "the message a rule gives the first time it is met" do
    it "tells a file that `using` a module it has not imported to import it" do
      with_iyi_modules({
        "main.iyi"    => "module app/main\n\nusing app/dep\n",
        "app/dep.iyi" => "module app/dep\n\npub def value : Int32\n  2\nend\n",
      }) do
        expect_raises(Crystal::TypeException, /needs `import app\/dep` above it/) do
          semantic_iyi("main.iyi")
        end
      end
    end

    it "says which module exports a name that is imported but not used" do
      with_iyi_modules({
        "main.iyi"    => "module app/main\n\nimport app/dep\n\nvalue\n",
        "app/dep.iyi" => "module app/dep\n\npub def value : Int32\n  2\nend\n",
      }) do
        expect_raises(Crystal::TypeException, /`value` is exported by `app\/dep`/) do
          semantic_iyi("main.iyi")
        end
      end
    end

    it "says when the name is there and was not marked `pub`" do
      with_iyi_modules({
        "main.iyi"    => "module app/main\n\nimport app/dep\nusing app/dep\n\nsecret\n",
        "app/dep.iyi" => "module app/dep\n\ndef secret : Int32\n  2\nend\n",
      }) do
        expect_raises(Crystal::TypeException, /does not mark it `pub`/) do
          semantic_iyi("main.iyi")
        end
      end
    end

    it "refuses a library `require` and names `import` instead" do
      with_iyi_modules({
        "main.iyi" => "module app/main\n\nrequire \"json\"\n",
      }) do
        expect_raises(Crystal::TypeException, /iyi has no `require`/) do
          semantic_iyi("main.iyi")
        end
      end
    end

    it "says where it looked for a module that is not there" do
      with_iyi_modules({
        "main.iyi" => "module app/main\n\nimport app/ghost\n",
      }) do
        expect_raises(Crystal::TypeException, /this one is `app\/ghost.iyi`/) do
          semantic_iyi("main.iyi")
        end
      end
    end
  end

  # An `import` written below other code used to declare the module inside the
  # importing one — `Samples::InitOrder::Boot::Registry` — which compiled,
  # because the importing file reaches it under the same name either way. The
  # first thing to look from outside was `--emit-iyimod`, which found no
  # `Boot::Registry` at the top level and wrote an artifact with no exports.
  it "declares an imported module at the top level wherever the import is written" do
    with_iyi_modules({
      "main.iyi" => <<-IYI,
        module app/main

        def own : Int32
          1
        end

        import app/dep
        IYI
      "app/dep.iyi" => <<-IYI,
        module app/dep

        pub def value : Int32
          2
        end
        IYI
    }) do
      program = semantic_iyi("main.iyi")

      program.iyi_module_type("app/dep").should_not be_nil

      importer = program.iyi_module_type("app/main").not_nil!
      importer.types?.try(&.has_key?("App")).should be_falsey
    end
  end

  describe "from a .iyimod (SPEC.md IV.1)" do
    # R-1's contract, stated as a test: the source is not opened. Not opened
    # rather than not preferred — there is no `app/dep.iyi` on disk at all.
    it "compiles a module that has no source" do
      with_iyi_modules({
        "main.iyi" => <<-IYI,
          module app/main

          import app/dep

          def check : Int32
            App::Dep.value
          end

          check
          IYI
      }) do |root|
        write_iyimod root, "app/dep", exports(functions: [
          artifact_signature("value", return_type: "Int32"),
        ])

        program = semantic_iyi("main.iyi", iyi_module_dir: root)
        program.iyi_module_type("app/dep").should_not be_nil
      end
    end

    # The one that tells "read the artifact" apart from "read the source and
    # happened to agree": the two disagree, and what compiles is the artifact's.
    it "reads the artifact rather than the source that is sitting next to it" do
      with_iyi_modules({
        "app/dep.iyi" => <<-IYI,
          module app/dep

          pub def from_source : Int32
            1
          end
          IYI
        "main.iyi" => <<-IYI,
          module app/main

          import app/dep

          def check : Int32
            App::Dep.from_artifact
          end

          check
          IYI
      }) do |root|
        write_iyimod root, "app/dep", exports(functions: [
          artifact_signature("from_artifact", return_type: "Int32"),
        ])

        semantic_iyi("main.iyi", iyi_module_dir: root)
      end
    end

    it "does not reach a name that only the source has" do
      with_iyi_modules({
        "app/dep.iyi" => <<-IYI,
          module app/dep

          pub def from_source : Int32
            1
          end
          IYI
        "main.iyi" => <<-IYI,
          module app/main

          import app/dep

          def check : Int32
            App::Dep.from_source
          end

          check
          IYI
      }) do |root|
        write_iyimod root, "app/dep", exports(functions: [
          artifact_signature("from_artifact", return_type: "Int32"),
        ])

        expect_raises(Crystal::TypeException, /undefined method 'from_source'/) do
          semantic_iyi("main.iyi", iyi_module_dir: root)
        end
      end
    end

    # A call is typed from the return annotation, which is the whole of what
    # the front end gets from an artifact — there is no body to type.
    it "types a call from the signature alone" do
      with_iyi_modules({
        "main.iyi" => <<-IYI,
          module app/main

          import app/dep

          def check : Int32
            App::Dep.value
          end

          check
          IYI
      }) do |root|
        write_iyimod root, "app/dep", exports(functions: [
          artifact_signature("value", return_type: "String"),
        ])

        # `check` promises `Int32` and the artifact says `value` gives a
        # `String`. Nothing but the signature could have caught that.
        expect_raises(Crystal::TypeException, /must return Int32/) do
          semantic_iyi("main.iyi", iyi_module_dir: root)
        end
      end
    end

    # IV.5: rejected and rebuilt, never migrated — and never quietly swapped
    # for the source, which would make a build that asked to be compiled
    # against artifacts slower than it looks and prove nothing.
    it "refuses an artifact from another compiler" do
      with_iyi_modules({
        "main.iyi" => <<-IYI,
          module app/main

          import app/dep
          IYI
      }) do |root|
        write_iyimod root, "app/dep", exports, compiler_version: "0.0.0+nope"

        expect_raises(Crystal::TypeException, /written by compiler 0\.0\.0\+nope/) do
          semantic_iyi("main.iyi", iyi_module_dir: root)
        end
      end
    end

    it "falls back to the source when there is no artifact" do
      with_iyi_modules({
        "app/dep.iyi" => <<-IYI,
          module app/dep

          pub def from_source : Int32
            1
          end
          IYI
        "main.iyi" => <<-IYI,
          module app/main

          import app/dep

          def check : Int32
            App::Dep.from_source
          end

          check
          IYI
      }) do |root|
        semantic_iyi("main.iyi", iyi_module_dir: root)
      end
    end
  end
end
