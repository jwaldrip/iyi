require "../spec_helper"
require "./spec_helper"

# Bound parameter text for splat and annotated declarations, read back from a bound artifact.
#
# A consumer reads the bound declaration, so its parameter text is pinned here rather than
# inferred from the printer. Each control names what it protects: a bare star is the star
# alone (no empty name, no stray comma); a named splat keeps its name; an external name keeps
# the spelling the source wrote; and an annotation the source wrote is carried into the bound
# text, in both binding modes, because it is part of the declaration the source states.

private def bare_projection_bind(source : String, dir : String, capture : Bool = false)
  File.write "shard.cr", source
  compiler = create_spec_compiler
  compiler.no_codegen = true
  if capture
    compiler.emit_bind = dir
    compiler.capture_diagnostic_provenance = true
  end
  file = Iyi::Compiler::Source.new(File.expand_path("shard.cr"), File.read("shard.cr"))
  result = compiler.compile file, File.expand_path("bare-projection-probe")
  Iyi.print_bind result.program, "Projection", IO::Memory.new, artifact_dir: dir
  Iyi::IyiMod.read(File.join(dir, "projection.iyimod"))
end

private def bare_projection_parameters(artifact, name : String) : Array(String)
  signature = artifact.exports.functions.find { |sig| sig.name == name } || raise "no #{name} in artifact"
  signature.parameters
end

describe "bound splat parameters" do
  it "binds a bare star as the star alone" do
    with_tempdir("bare_projection_bare") do
      Dir.mkdir_p "mods"
      artifact = bare_projection_bind(<<-CR, "mods")
        module Projection
          extend self

          def hold(*, y : Int32) : Int32
            y
          end
        end
        CR
      bare_projection_parameters(artifact, "hold").should eq ["*", "y : Int32"]
    end
  end

  it "keeps an annotated bare star's annotation in the bound text" do
    with_tempdir("bare_projection_annotated") do
      Dir.mkdir_p "mods"
      artifact = bare_projection_bind(<<-CR, "mods")
        module Projection
          extend self

          def hold(@[Foo] *, y : Int32) : Int32
            y
          end
        end
        CR
      bare_projection_parameters(artifact, "hold").should eq ["@[Foo] *", "y : Int32"]
    end
  end

  it "binds a named splat with its name, and a named positional with its external name" do
    with_tempdir("bare_projection_named") do
      Dir.mkdir_p "mods"
      artifact = bare_projection_bind(<<-CR, "mods")
        module Projection
          extend self

          def hold(as type : Int32, *rest) : Int32
            type
          end
        end
        CR
      bare_projection_parameters(artifact, "hold").should eq ["as type : Int32", "*rest"]
    end
  end

  it "keeps an annotated named splat's annotation before its prefix" do
    with_tempdir("bare_projection_annotated_named") do
      Dir.mkdir_p "mods"
      artifact = bare_projection_bind(<<-CR, "mods")
        module Projection
          extend self

          def hold(@[Foo] *rest : Int32) : Int32
            rest.size
          end
        end
        CR
      bare_projection_parameters(artifact, "hold").should eq ["@[Foo] *rest : Int32"]
    end
  end

  it "keeps annotated splats in capture mode, where the provenance is recorded" do
    with_tempdir("bare_projection_capture") do
      Dir.mkdir_p "mods"
      artifact = bare_projection_bind(<<-CR, "mods", capture: true)
        module Projection
          extend self

          def hold(@[Foo] *, @[Bar] *rest : Int32, y : Int32) : Int32
            y
          end
        end
        CR
      artifact.diagnostic_provenance.should_not be_nil
      bare_projection_parameters(artifact, "hold").should eq ["@[Foo] *", "@[Bar] *rest : Int32", "y : Int32"]
    end
  end

  it "keeps an annotated block's annotation before its ampersand" do
    with_tempdir("bare_projection_block") do
      Dir.mkdir_p "mods"
      artifact = bare_projection_bind(<<-CR, "mods", capture: true)
        module Projection
          extend self

          def hold(@[Foo] &block : Int32 -> Int32) : Int32
            block.call(1)
          end
        end
        CR
      signature = artifact.exports.functions.find { |sig| sig.name == "hold" } || raise "no hold in artifact"
      signature.block_parameter.should start_with "@[Foo] &block"
      signature.block_parameter.should_not contain "&@"
    end
  end
end

describe "bound parameter names" do
  it "writes the name the printer writes for an identifier external name" do
    arg = Iyi::Arg.new("xs", external_name: "ext")
    Iyi::ToSVisitor.bound_parameter_name(arg, "*").should eq Iyi::ToSVisitor.parameter_text(arg, "*")
    Iyi::ToSVisitor.bound_parameter_name(arg, "*").should eq "*ext xs"
  end

  it "writes an annotated parameter exactly as the printer does, annotation first" do
    splat = Iyi::Parser.new("def f(@[Foo] *xs)\nend").parse.as(Iyi::Def).args.first
    Iyi::ToSVisitor.bound_annotation_prefix(splat).should eq "@[Foo] "
    Iyi::ToSVisitor.bound_parameter_name(splat, "*").should eq "@[Foo] *xs"
    Iyi::ToSVisitor.bound_parameter_name(splat, "*").should eq Iyi::ToSVisitor.parameter_text(splat, "*")

    block = Iyi::Parser.new("def f(@[Foo] &b)\nend").parse.as(Iyi::Def).block_arg.not_nil!
    Iyi::ToSVisitor.bound_parameter_name(block, "&").should eq "@[Foo] &b"
    Iyi::ToSVisitor.bound_parameter_name(block, "&").should eq Iyi::ToSVisitor.parameter_text(block, "&")
  end

  it "keeps an external name's spelling, where the printer would quote it" do
    Iyi::ToSVisitor.bound_parameter_name(Iyi::Arg.new("x", external_name: "_"), "").should eq "_ x"
    Iyi::ToSVisitor.bound_parameter_name(Iyi::Arg.new("x", external_name: "é"), "").should eq "é x"
    Iyi::ToSVisitor.parameter_text(Iyi::Arg.new("x", external_name: "_"), "").should eq %("_" x)
  end

  it "writes a bare star as the star alone and prefixes named splats" do
    Iyi::ToSVisitor.bound_parameter_name(Iyi::Arg.new(""), "*").should eq "*"
    Iyi::ToSVisitor.bound_parameter_name(Iyi::Arg.new("xs"), "*").should eq "*xs"
    Iyi::ToSVisitor.bound_parameter_name(Iyi::Arg.new("opts"), "**").should eq "**opts"
    Iyi::ToSVisitor.bound_parameter_name(Iyi::Arg.new("x"), "").should eq "x"
    Iyi::ToSVisitor.bound_parameter_name(Iyi::Arg.new("b"), "&").should eq "&b"
  end

  it "refuses a prefix the bound parameter path never writes" do
    expect_raises(ArgumentError, /invalid bound parameter prefix/) do
      Iyi::ToSVisitor.bound_parameter_name(Iyi::Arg.new("b"), "@")
    end
  end
end
