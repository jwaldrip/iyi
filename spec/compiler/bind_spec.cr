require "../spec_helper"
require "./spec_helper"

# iyi: what `crystal tool bind` writes, read back by a build.
#
# The tool had no spec at all, and the shape of what that cost is the reason
# this one exists. Everything it checked was a number it printed — how much of a
# surface crosses, what the boundary waits on — and a number cannot say whether
# anything can *consume* the artifact printed beside it. So nothing ever did,
# and when somebody finally tried by hand, neither root shape worked: a module
# root declared `Any` while its own fields named `JSON::Any`, and a class root
# rendered a `def` where no type was open.
#
# The consumer runs with `no_codegen` on purpose. What broke was the
# declarations, and reading them back is the whole claim here. Linking is a
# separate one — it needs `nm` and `objcopy`, which is a pipeline rather than a
# spec, and a spec that shelled out to binutils would be testing this machine.

# The program `tool bind` reads: a Crystal source, analysed under Crystal's own
# library, which is what the tool needs and why it lives in the compiler.
private def bind_artifact(source_path : String, root : String, dir : String) : String
  compiler = create_spec_compiler
  compiler.no_codegen = true
  source = Crystal::Compiler::Source.new(File.expand_path(source_path), File.read(source_path))
  result = compiler.compile source, File.expand_path("bind-probe")

  report = IO::Memory.new
  Crystal.print_bind result.program, root, report, artifact_dir: dir
  File.join(dir, "#{root.downcase}.iyimod")
end

# An iyi program that imports the boundary and nothing else. Importing is
# enough: it is the read-back, and every failure this file was written for
# happens there rather than at a call site.
private def consume(artifact_dir : String, module_name : String)
  File.write "main.iyi", <<-IYI
    module main

    import #{module_name}
    IYI

  consumer = create_spec_compiler
  consumer.prelude = "iyi/prelude"
  consumer.use_iyimod = artifact_dir
  consumer.no_codegen = true
  source = Crystal::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
  consumer.compile source, File.expand_path("consumer")
end

describe "tool bind" do
  # A module root, which is the shape a shard has: `Kemal`, `JSON`.
  #
  # `MyLib` rather than `Lib`, and the difference is the bug. The artifact's
  # module name is the root downcased, and the consumer builds a type back out
  # of it by capitalising — so `Lib` survives the trip and `MyLib` becomes
  # `Mylib`, while the declarations inside still say `MyLib::Entry`. Every real
  # namespace is the second kind: `JSON`, `YAML`, `URI`.
  #
  # The field is what fails rather than the method, and that is not incidental:
  # a consumer has to know a type's size to allocate one, so a field's type is
  # resolved on the way in while a return type can wait for a call site.
  it "writes a module's artifact that a build can read back" do
    with_tempdir("bind_module_root") do
      Dir.mkdir_p "mods"
      File.write "shard.cr", <<-CR
        module MyLib
          extend self

          class Entry
            @size : Int32

            def initialize(@size : Int32)
            end

            def size : Int32
              @size
            end
          end

          class Holder
            @entry : Entry

            def initialize(@entry : Entry)
            end

            def entry : Entry
              @entry
            end
          end

          def hold(entry : Entry) : Holder
            Holder.new(entry)
          end
        end
        CR

      File.exists?(bind_artifact("shard.cr", "MyLib", "mods")).should be_true
      consume "mods", "mylib"
    end
  end

  # A class root, which is the shape a core type has: `IO`, `Time`. Its own
  # methods are its type's rather than module functions, so the whole boundary
  # travels as one declaration holding the rest — a shape no shard produces and
  # nothing checked.
  #
  # It survives the trip the module root does not, and for a reason worth
  # keeping: a class root's own name *is* its declaration's name, so `MySink::Entry`
  # resolves against it wherever the module lands. A module root drops that name
  # and leaves the references pointing at nothing.
  it "writes a class's artifact that a build can read back" do
    with_tempdir("bind_class_root") do
      Dir.mkdir_p "mods"
      File.write "shard.cr", <<-CR
        class MySink
          @count : Int32

          def initialize
            @count = 0
          end

          def count : Int32
            @count
          end

          class Entry
            @size : Int32

            def initialize(@size : Int32)
            end

            def size : Int32
              @size
            end
          end
        end
        CR

      File.exists?(bind_artifact("shard.cr", "MySink", "mods")).should be_true
      consume "mods", "mysink"
    end
  end
end
