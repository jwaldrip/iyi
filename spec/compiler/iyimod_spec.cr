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

private def signature(name : String,
                      parameters = [] of String,
                      return_type = "",
                      block_parameter = "",
                      free_variables = [] of String,
                      receiver = "",
                      required = false)
  Crystal::IyiMod::Signature.new(name, receiver, parameters, block_parameter,
    return_type, free_variables, required)
end

private def type_declaration(name : String,
                             kind : String,
                             type_parameters = [] of String,
                             assoc_types = [] of String,
                             supertraits = [] of String,
                             methods = [] of Crystal::IyiMod::Signature)
  Crystal::IyiMod::TypeDecl.new(name, kind, type_parameters, assoc_types,
    supertraits, methods)
end

private def impl_record(trait_name : String,
                        type_name : String,
                        trait_arguments = [] of String,
                        free_variables = [] of String,
                        free_variable_bounds = [] of {String, String},
                        assoc_types = [] of {String, String})
  Crystal::IyiMod::ImplRecord.new(trait_name, type_name, trait_arguments,
    free_variables, free_variable_bounds, assoc_types)
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
      signature("polite", ["name : String"], "String"),
      signature("title", return_type: "String"),
      signature("pair", ["a : Int32", "b : Array(String)"], "Tuple(Int32, String)"),
    ]

    with_temporary_file do |path|
      Crystal::IyiMod.write sample_artifact(exports: signatures), path
      read = Crystal::IyiMod.read(path).exports.functions

      read.size.should eq 3
      read[0].name.should eq "polite"
      read[0].parameters.should eq ["name : String"]
      read[0].return_type.should eq "String"
      read[1].parameters.should be_empty
      read[2].parameters.should eq ["a : Int32", "b : Array(String)"]
      read[2].return_type.should eq "Tuple(Int32, String)"
    end
  end

  # Everything a consumer needs and the source's `def` line carries. Each of
  # these was absent from the format until a consumer that reads the artifact
  # instead of the source went looking for it: without the block annotation
  # there is no `yield` left to infer a block from, without the `forall` the
  # return type does not resolve, and an `abstract def` read as a definition is
  # a requirement nobody is told they missed.
  it "round-trips the rest of a def's header" do
    signatures = [
      signature("map", ["a : Int32"], "Array(U)",
        block_parameter: "& : (Elem -> U)", free_variables: ["U"]),
      signature("each", return_type: "Nil",
        block_parameter: "& : (Elem -> Nil)", required: true),
      signature("zero", return_type: "self", receiver: "self"),
      signature("push", ["*values : T", "**options"]),
    ]

    with_temporary_file do |path|
      Crystal::IyiMod.write sample_artifact(exports: signatures), path
      read = Crystal::IyiMod.read(path).exports.functions

      read[0].block_parameter.should eq "& : (Elem -> U)"
      read[0].free_variables.should eq ["U"]
      read[0].required.should be_false
      read[1].required.should be_true
      read[2].receiver.should eq "self"
      read[3].parameters.should eq ["*values : T", "**options"]
    end
  end

  it "dumps a def's header the way it was written" do
    io = IO::Memory.new
    Crystal::IyiMod.dump sample_artifact(exports: [
      signature("map", ["a : Int32"], "Array(U)",
        block_parameter: "& : (Elem -> U)", free_variables: ["U"]),
      signature("each", return_type: "Nil",
        block_parameter: "& : (Elem -> Nil)", required: true),
      signature("zero", return_type: "self", receiver: "self"),
    ]), io
    text = io.to_s

    text.should contain "  def map(a : Int32, & : (Elem -> U)) : Array(U) forall U"
    # A block parameter alone still gets the parentheses it needs.
    text.should contain "  abstract def each(& : (Elem -> Nil)) : Nil"
    text.should contain "  def self.zero : self"
  end

  it "dumps a signature the way it was written" do
    io = IO::Memory.new
    Crystal::IyiMod.dump sample_artifact(exports: [
      signature("polite", ["name : String"], "String"),
      signature("title", return_type: "String"),
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
    declaration = type_declaration("List", "generic struct",
      type_parameters: ["T"],
      methods: [signature("at", ["index : Int32"], "T")])

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
      impl_record("Std::Traits::Cmp", "Int32"),
      impl_record("Std::Enumerable::Enumerable", "Std::List::List(T)",
        free_variables: ["T"], assoc_types: [{"Elem", "T"}]),
    ]

    with_temporary_file do |path|
      Crystal::IyiMod.write sample_artifact(impls: impls), path
      read = Crystal::IyiMod.read(path).exports.impls

      read.map(&.trait_name).should eq ["Std::Traits::Cmp", "Std::Enumerable::Enumerable"]
      read.map(&.type_name).should eq ["Int32", "Std::List::List(T)"]
      read[1].free_variables.should eq ["T"]
      read[1].assoc_types.should eq [{"Elem", "T"}]
    end
  end

  # A constructor's result is its type and nobody writes it down, so an absent
  # return type is recorded as absent rather than filled in with a guess.
  it "renders a signature with no return annotation without one" do
    io = IO::Memory.new
    Crystal::IyiMod.dump sample_artifact(exports: [
      signature("initialize", ["items : Array(T)"]),
    ]), io

    io.to_s.should contain "  def initialize(items : Array(T))\n"
  end

  it "dumps a type declaration and an impl" do
    io = IO::Memory.new
    Crystal::IyiMod.dump sample_artifact(
      types: [type_declaration("Greet", "trait",
        methods: [signature("greet", return_type: "String")])],
      impls: [impl_record("Greet", "User")],
    ), io
    text = io.to_s

    text.should contain "  trait Greet"
    text.should contain "    def greet : String"
    text.should contain "  impl Greet for User"
  end

  # II.6 keeps a trait's parameters and its associated types apart — the first
  # is supplied at the `impl` line and the second is answered in its body — so
  # an artifact that merged them would ask for `Elem` in the one place II.6
  # says it does not go.
  it "round-trips a trait's parameters, associated types and supertraits" do
    declaration = type_declaration("Enumerable", "generic trait",
      type_parameters: ["K"],
      assoc_types: ["Elem"],
      supertraits: ["Std::Traits::Cmp"],
      methods: [signature("each", return_type: "Nil",
        block_parameter: "& : (Elem -> Nil)", required: true)])

    with_temporary_file do |path|
      Crystal::IyiMod.write sample_artifact(types: [declaration]), path
      read = Crystal::IyiMod.read(path).exports.types[0]

      read.type_parameters.should eq ["K"]
      read.assoc_types.should eq ["Elem"]
      read.supertraits.should eq ["Std::Traits::Cmp"]
    end
  end

  it "dumps a trait and an impl as they were declared" do
    io = IO::Memory.new
    Crystal::IyiMod.dump sample_artifact(
      types: [type_declaration("Enumerable", "generic trait",
        assoc_types: ["Elem"],
        supertraits: ["Cmp"],
        methods: [signature("each", return_type: "Nil", required: true)])],
      impls: [impl_record("Std::Enumerable::Enumerable", "Std::List::List(T)",
        free_variables: ["T"],
        free_variable_bounds: [{"T", "Cmp"}],
        assoc_types: [{"Elem", "T"}])],
    ), io
    text = io.to_s

    # `generic` is how a type describes itself, not how anyone declares one.
    text.should contain "  trait Enumerable : Cmp"
    text.should contain "    type Elem"
    text.should contain "  impl Std::Enumerable::Enumerable for Std::List::List(T) forall T : Cmp"
    text.should contain "    type Elem = T"
  end

  # What `import` compiles against instead of the module's source (R-1). It is
  # iyi rather than a second grammar, so the parser that read the module reads
  # its declarations back.
  it "renders the declarations a consumer compiles against" do
    io = IO::Memory.new
    Crystal::IyiMod.declarations sample_artifact(
      exports: [signature("polite", ["name : String"], "String")],
      types: [type_declaration("Greet", "trait",
        methods: [signature("greet", return_type: "String", required: true)])],
      impls: [impl_record("Greet", "User")],
    ), io
    text = io.to_s

    text.should contain "module app/greeter"
    # A body is absent, not empty: a call is typed from the return annotation,
    # which is what makes this enough for the front end and nothing else.
    text.should contain "pub def polite(name : String) : String\nend\n"
    text.should contain "pub trait Greet\n  abstract def greet : String\nend\n"
    # An `abstract def` ends at its signature and takes no `end` of its own.
    text.should_not contain "abstract def greet : String\n  end"
    text.should contain "impl Greet for User\nend\n"
    # The impl comes after the type it targets, because the requirement check
    # reads the methods off the target rather than out of the impl's body.
    text.index("pub trait Greet").not_nil!.should be < text.index("impl Greet for User").not_nil!
  end

  it "renders a generic type and the impl that answers its associated type" do
    io = IO::Memory.new
    Crystal::IyiMod.declarations sample_artifact(
      types: [type_declaration("List", "generic struct", type_parameters: ["T"],
        methods: [signature("each", return_type: "Nil", block_parameter: "& : (T -> Nil)")])],
      impls: [impl_record("Std::Enumerable::Enumerable", "Std::List::List(T)",
        free_variables: ["T"], assoc_types: [{"Elem", "T"}])],
    ), io
    text = io.to_s

    text.should contain "pub struct List(T)"
    text.should contain "  def each(& : (T -> Nil)) : Nil\n  end\n"
    text.should contain "impl Std::Enumerable::Enumerable for Std::List::List(T) forall T\n  type Elem = T\nend\n"
  end
end
