require "../spec_helper"
require "./spec_helper"

# iyi: the `.iyimod` container — SPEC.md IV.1.
#
# The contract these guard is that an artifact is either understood exactly or
# refused. A build cache whose worst case is "read something plausible and
# carried on" is the failure IV.1 is written to avoid, so the rejections below
# matter at least as much as the round trip.
private def sample_artifact(imports = [] of String)
  Crystal::IyiMod::Artifact.new(
    module_name: "app/greeter",
    source_path: "/src/app/greeter.iyi",
    compiler_version: "1.22.0-dev+abc1234",
    target_triple: "x86_64-pc-linux-gnu",
    flags: ["bits64", "linux"],
    imports: imports,
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
end
