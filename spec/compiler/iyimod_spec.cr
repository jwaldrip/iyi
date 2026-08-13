require "../spec_helper"
require "./spec_helper"

# iyi: the `.iyimod` container — SPEC.md IV.1.
#
# The contract these guard is that an artifact is either understood exactly or
# refused. A build cache whose worst case is "read something plausible and
# carried on" is the failure IV.1 is written to avoid, so the rejections below
# matter at least as much as the round trip.
private def sample_artifact(imports = [] of String,
                            exports = [] of Crystal::IyiMod::Signature,
                            types = [] of Crystal::IyiMod::TypeDecl,
                            impls = [] of Crystal::IyiMod::ImplRecord)
  Crystal::IyiMod::Artifact.new(
    module_name: "app/greeter",
    source_path: "/src/app/greeter.iyi",
    compiler_version: "1.22.0-dev+abc1234",
    target_triple: "x86_64-pc-linux-gnu",
    flags: ["bits64", "linux"],
    imports: imports,
    exports: Crystal::IyiMod::Exports.new(exports, types, impls),
  )
end

private def with_temporary_file(&)
  path = File.tempname("iyimod", ".iyimod")
  begin
    yield path
  ensure
    File.delete?(path)
  end
end

describe Crystal::IyiMod do
  it "round-trips an artifact" do
    with_temporary_file do |path|
      Crystal::IyiMod.write sample_artifact, path
      read = Crystal::IyiMod.read(path)

      read.module_name.should eq "app/greeter"
      read.source_path.should eq "/src/app/greeter.iyi"
      read.compiler_version.should eq "1.22.0-dev+abc1234"
      read.target_triple.should eq "x86_64-pc-linux-gnu"
      read.flags.should eq ["bits64", "linux"]
      read.imports.should be_empty
    end
  end

  it "round-trips import edges in order" do
    with_temporary_file do |path|
      Crystal::IyiMod.write sample_artifact(["std/list", "std/enumerable"]), path
      Crystal::IyiMod.read(path).imports.should eq ["std/list", "std/enumerable"]
    end
  end

  # Atomic replacement is the property IV.1 picks a single-file container for:
  # a half-written artifact that a later build reads as valid is the worst
  # failure a cache has, because it is wrong and nothing about it looks broken.
  it "leaves no temporary file behind" do
    with_temporary_file do |path|
      Crystal::IyiMod.write sample_artifact, path
      Dir[File.join(File.dirname(path), "#{File.basename(path)}.*.tmp")].should be_empty
    end
  end

  it "refuses a file that is not a .iyimod" do
    with_temporary_file do |path|
      File.write path, "this is not an artifact"
      expect_raises(Crystal::IyiMod::Error, /is not a \.iyimod/) do
        Crystal::IyiMod.read(path)
      end
    end
  end

  it "refuses a file too short to hold the magic" do
    with_temporary_file do |path|
      File.write path, "IYI"
      expect_raises(Crystal::IyiMod::Error, /too short/) do
        Crystal::IyiMod.read(path)
      end
    end
  end

  # IV.5: rejected and rebuilt, never migrated.
  it "refuses another format version" do
    with_temporary_file do |path|
      Crystal::IyiMod.write sample_artifact, path
      bytes = File.read(path).to_slice.dup
      # The version is the u32 right after the 8-byte magic.
      Crystal::IyiMod::FORMAT.encode(99_u32, bytes[8, 4])
      File.write path, bytes

      expect_raises(Crystal::IyiMod::Error, /format v99/) do
        Crystal::IyiMod.read(path)
      end
    end
  end

  # The section table exists so a reader can take what it needs and seek past
  # the rest — that is what will let a consumer read `Exports` without paging in
  # `ObjectCode`. Forward compatibility falls out of the same property, so it is
  # checked here rather than assumed when the later sections arrive.
  it "skips a section it does not know" do
    with_temporary_file do |path|
      io = IO::Memory.new
      format = Crystal::IyiMod::FORMAT
      header = IO::Memory.new
      {"app/greeter", "/src/app/greeter.iyi", "1.0", "triple"}.each do |value|
        header.write_bytes value.bytesize.to_u32, format
        header.write value.to_slice
      end
      header.write_bytes 0_u32, format # no flags
      payload = header.to_slice

      io.write Crystal::IyiMod::MAGIC
      io.write_bytes Crystal::IyiMod::FORMAT_VERSION, format
      io.write_bytes 2_u32, format
      io.write_bytes Crystal::IyiMod::Section::Header.value, format
      io.write_bytes 0_u16, format
      io.write_bytes payload.size.to_u32, format
      io.write_bytes 4242_u16, format # a kind no compiler has ever defined
      io.write_bytes 0_u16, format
      io.write_bytes 3_u32, format
      io.write payload
      io.write "xyz".to_slice

      File.write path, io.to_slice
      Crystal::IyiMod.read(path).module_name.should eq "app/greeter"
    end
  end

  it "refuses an artifact with no header" do
    with_temporary_file do |path|
      io = IO::Memory.new
      io.write Crystal::IyiMod::MAGIC
      io.write_bytes Crystal::IyiMod::FORMAT_VERSION, Crystal::IyiMod::FORMAT
      io.write_bytes 0_u32, Crystal::IyiMod::FORMAT
      File.write path, io.to_slice

      expect_raises(Crystal::IyiMod::Error, /no header/) do
        Crystal::IyiMod.read(path)
      end
    end
  end

  it "dumps as text" do
    io = IO::Memory.new
    Crystal::IyiMod.dump sample_artifact(["std/list"]), io
    text = io.to_s

    text.should contain "module        app/greeter"
    text.should contain "  std/list"
  end

  # R-2: everything exported carries full parameter and return types, which is
  # why the signature can be the annotation as written rather than a rendering
  # of an inferred type.
  it "round-trips exported signatures" do
    signatures = [
      Crystal::IyiMod::Signature.new("polite", [{"name", "String"}], "String"),
      Crystal::IyiMod::Signature.new("title", [] of {String, String}, "String"),
      Crystal::IyiMod::Signature.new("pair", [{"a", "Int32"}, {"b", "Array(String)"}], "Tuple(Int32, String)"),
    ]

    with_temporary_file do |path|
      Crystal::IyiMod.write sample_artifact(exports: signatures), path
      read = Crystal::IyiMod.read(path).exports.functions

      read.size.should eq 3
      read[0].name.should eq "polite"
      read[0].parameters.should eq [{"name", "String"}]
      read[0].return_type.should eq "String"
      read[1].parameters.should be_empty
      read[2].parameters.should eq [{"a", "Int32"}, {"b", "Array(String)"}]
      read[2].return_type.should eq "Tuple(Int32, String)"
    end
  end

  it "dumps a signature the way it was written" do
    io = IO::Memory.new
    Crystal::IyiMod.dump sample_artifact(exports: [
      Crystal::IyiMod::Signature.new("polite", [{"name", "String"}], "String"),
      Crystal::IyiMod::Signature.new("title", [] of {String, String}, "String"),
    ]), io
    text = io.to_s

    text.should contain "  def polite(name : String) : String"
    # No empty parens for a function that takes nothing.
    text.should contain "  def title : String"
  end

  # The format still stops short of what codegen needs, and a reader has no way
  # to tell an absent field list from an empty one, so the dump says so.
  it "says what the format does not carry yet" do
    io = IO::Memory.new
    Crystal::IyiMod.dump sample_artifact, io
    io.to_s.should contain "not in this file yet"
  end

  it "round-trips exported types with their parameters and methods" do
    declaration = Crystal::IyiMod::TypeDecl.new(
      name: "List",
      kind: "generic struct",
      type_parameters: ["T"],
      methods: [Crystal::IyiMod::Signature.new("at", [{"index", "Int32"}], "T")],
    )

    with_temporary_file do |path|
      Crystal::IyiMod.write sample_artifact(types: [declaration]), path
      read = Crystal::IyiMod.read(path).exports.types

      read.size.should eq 1
      read[0].name.should eq "List"
      read[0].kind.should eq "generic struct"
      read[0].type_parameters.should eq ["T"]
      read[0].methods.map(&.name).should eq ["at"]
    end
  end

  # II.4 depends on this record: it is what lets a consumer answer "does
  # `Customer` implement `ToJSON`?" without reading `Customer`.
  it "round-trips impl records" do
    impls = [
      Crystal::IyiMod::ImplRecord.new("Std::Traits::Cmp", "Int32"),
      Crystal::IyiMod::ImplRecord.new("Std::Enumerable::Enumerable", "Std::List::List(T)"),
    ]

    with_temporary_file do |path|
      Crystal::IyiMod.write sample_artifact(impls: impls), path
      read = Crystal::IyiMod.read(path).exports.impls

      read.map(&.trait_name).should eq ["Std::Traits::Cmp", "Std::Enumerable::Enumerable"]
      read.map(&.type_name).should eq ["Int32", "Std::List::List(T)"]
    end
  end

  # A constructor's result is its type and nobody writes it down, so an absent
  # return type is recorded as absent rather than filled in with a guess.
  it "renders a signature with no return annotation without one" do
    io = IO::Memory.new
    Crystal::IyiMod.dump sample_artifact(exports: [
      Crystal::IyiMod::Signature.new("initialize", [{"items", "Array(T)"}], ""),
    ]), io

    io.to_s.should contain "  def initialize(items : Array(T))\n"
  end

  it "dumps a type declaration and an impl" do
    io = IO::Memory.new
    Crystal::IyiMod.dump sample_artifact(
      types: [Crystal::IyiMod::TypeDecl.new("Greet", "trait", [] of String,
        [Crystal::IyiMod::Signature.new("greet", [] of {String, String}, "String")])],
      impls: [Crystal::IyiMod::ImplRecord.new("Greet", "User")],
    ), io
    text = io.to_s

    text.should contain "  trait Greet"
    text.should contain "    def greet : String"
    text.should contain "  impl Greet for User"
  end
end
