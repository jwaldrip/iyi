require "../spec_helper"
require "./spec_helper"

private def with_iyi_modules(files : Hash(String, String), &)
  with_tempdir("iyi_derive") do
    files.each do |path, source|
      directory = File.dirname(path)
      Dir.mkdir_p(directory) unless directory == "."
      File.write path, source
    end
    yield Dir.current
  end
end

private def semantic_iyi(entry : String)
  program = Iyi::Program.new
  program.color = false
  program.filename = File.expand_path(entry)

  parser = program.new_parser(File.read(entry))
  parser.filename = program.filename
  program.semantic program.normalize(parser.parse)
  program
end

# iyi: `derive` (SPEC.md R-5, II.4). A derive runs once, in the module that
# declares the type. What it generates belongs to that module and travels in its
# `.iyimod` like any other declaration, so a consumer calls the derived method
# without running the macro and without the producer's source.
describe "Semantic: iyi derive" do
  it "runs the macro in the declaring module and carries what it generated" do
    with_tempdir("iyi_derive_artifact") do
      Dir.mkdir_p "app"
      # The derive reads the two facts R-5 promises it: the declaration's name
      # and its fields. It never enumerates a type it was not given.
      File.write "app/derives.iyi", <<-IYI
        module app/derives

        pub macro described(declaration)
          def described : String
            result = {{declaration[:name]}} + "("
            {% for field in declaration[:fields] %}
              result = result + {{field}} + "=" + {{field.id}}.to_s + ";"
            {% end %}
            result + ")"
          end
        end
        IYI
      File.write "app/point.iyi", <<-IYI
        module app/point

        import app/derives
        using app/derives

        pub struct Point
          @x : Int32
          @y : Int32

          def initialize(@x : Int32, @y : Int32)
          end

          derive described
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/point

        puts App::Point::Point.new(3, 4).described
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "Point(@x=3;@y=4;)"

      # R-1, taken literally: the consumer compiles against declarations, so
      # both the declaring module's source and the macro's own source go away.
      File.delete "app/point.iyi"
      File.delete "app/derives.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "Point(@x=3;@y=4;)"
    end
  end

  it "teaches that a derive names an exported macro" do
    with_iyi_modules({
      "main.iyi" => <<-IYI,
        module app/main

        pub struct Number
          derive missing
        end
        IYI
    }) do
      expect_raises(Iyi::TypeException, /not an available derive macro.*pub macro missing/) do
        semantic_iyi("main.iyi")
      end
    end
  end
end
