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

private def semantic_iyi(entry : String)
  program = Crystal::Program.new
  program.color = false
  program.filename = File.expand_path(entry)

  parser = program.new_parser(File.read(entry))
  parser.filename = program.filename
  node = program.normalize(parser.parse)
  program.semantic node

  program
end

describe "Semantic: iyi import" do
  # An `import` written below other code used to declare the module inside the
  # importing one — `Samples::InitOrder::Boot::Registry` — which compiled,
  # because the importing file reaches it under the same name either way. The
  # first thing to look from outside was `--emit-iyimod`, which found no
  # `Boot::Registry` at the top level and wrote an artifact with no exports.
  it "declares an imported module at the top level wherever the import is written" do
    with_iyi_modules({
      "main.iyi"    => <<-IYI,
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
end
