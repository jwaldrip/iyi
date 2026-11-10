require "../spec_helper"
require "./spec_helper"

private NAMES_SOURCE = "%w(a)"

private def names_sha(text : String) : String
  ::Crystal::Digest::SHA256.hexdigest(text)
end

private def names_origin : Iyi::DiagnosticOrigin
  Iyi::DiagnosticOrigin::Written.new("spec", "/spec/literal_names.cr", 0, "TypeSyntax", "token")
end

private def names_percent_witness(kind : String, raw : String) : Iyi::DiagnosticSourceSyntaxToken
  Iyi::DiagnosticSourceSyntaxToken.new(names_origin, names_sha(NAMES_SOURCE), NAMES_SOURCE.bytesize,
    0, raw.bytesize, "Crystal", kind, raw)
end

private def names_quoted(context : String = "named_entry", text : String = "abc") : Iyi::DiagnosticOrigin
  Iyi::DiagnosticOrigin::DerivedName.quoted_name(context, names_sha("abc x"), 10, "Crystal", 0, 10, text)
end

private def names_index_of(bytes : Bytes, needle : Bytes) : Int32
  (0..bytes.size - needle.size).each do |start|
    return start if bytes[start, needle.size] == needle
  end
  raise "needle absent from the encoded table"
end

private def names_with_temporary_file(&)
  path = File.tempname("iyimod-literal-names", ".iyimod")
  begin
    yield path
  ensure
    File.delete(path) if File.exists?(path)
  end
end

describe "iyimod literal names and type sugars" do
  it "writes the current format and schema after the v64 bump" do
    Iyi::IyiMod::FORMAT_VERSION.should eq(64_u32)
    Iyi::IyiMod::DiagnosticSection::SCHEMA.should eq(5_u32)
  end

  it "appends the sugar choices without renumbering the existing ones" do
    sugars = Iyi::IyiMod::DiagnosticOrigins::TYPE_SUGARS
    sugars.index("NilPredicate").should eq(8)
    sugars.last(2).should eq(%w(StringArray SymbolArray))
    results = Iyi::IyiMod::DiagnosticOrigins::TYPE_SUGAR_RESULTS
    results.index("Self").should eq(6)
    results.last(2).should eq(%w(String Symbol))
  end

  it "encodes a QuotedName under derived-name tag 9" do
    table = Iyi::IyiMod::DiagnosticOrigins.new
    table.intern(names_quoted)
    io = IO::Memory.new
    table.write(io)
    bytes = io.to_slice.dup
    bytes[4].should eq(4_u8)
    bytes[5].should eq(9_u8)
  end

  it "keeps quoted names distinct by spelling and context during interning" do
    table = Iyi::IyiMod::DiagnosticOrigins.new
    original = names_quoted("named_entry", "abc")
    different_text = names_quoted("named_entry", "xyz")
    different_context = names_quoted("method_name", "abc")
    indices = [table.intern(original), table.intern(different_text), table.intern(different_context)]
    indices.uniq.size.should eq(3)

    io = IO::Memory.new
    table.write(io)
    restored = Iyi::IyiMod::DiagnosticOrigins.read(IO::Memory.new(io.to_slice))
    restored.parent(indices[0]).as(Iyi::DiagnosticOrigin::DerivedName).rendered_text.should eq("abc")
    restored.parent(indices[1]).as(Iyi::DiagnosticOrigin::DerivedName).rendered_text.should eq("xyz")
    restored.parent(indices[2]).as(Iyi::DiagnosticOrigin::DerivedName).producer_context.should eq("method_name")
  end

  it "round trips QuotedName, StringArray and SymbolArray byte-equal through the table" do
    quoted = names_quoted
    string_sugar = Iyi::DiagnosticOrigin::DerivedName.type_sugar(Iyi::DiagnosticTypeSugar::StringArray,
      [names_percent_witness("STRING_ARRAY_START", "%w(")], Iyi::DiagnosticTypeSugarResult::String, 0)
    symbol_sugar = Iyi::DiagnosticOrigin::DerivedName.type_sugar(Iyi::DiagnosticTypeSugar::SymbolArray,
      [names_percent_witness("SYMBOL_ARRAY_START", "%i<")], Iyi::DiagnosticTypeSugarResult::Symbol, 0)

    table = Iyi::IyiMod::DiagnosticOrigins.new
    quoted_index = table.intern(quoted)
    string_index = table.intern(string_sugar)
    symbol_index = table.intern(symbol_sugar)

    io = IO::Memory.new
    table.write(io)
    bytes = io.to_slice.dup

    restored = Iyi::IyiMod::DiagnosticOrigins.read(IO::Memory.new(bytes))
    restored.parent(quoted_index).should eq(quoted)
    restored.parent(string_index).should eq(string_sugar)
    restored.parent(symbol_index).should eq(symbol_sugar)

    restored_quoted = restored.parent(quoted_index).as(Iyi::DiagnosticOrigin::DerivedName)
    restored_quoted.producer_context.should eq("named_entry")
    restored_quoted.rendered_text.should eq("abc")
    restored_quoted.quoted_input_sha256.should eq(names_sha("abc x"))
    restored_quoted.quoted_input_bytesize.should eq(10)
    restored_quoted.quoted_lexical_mode.should eq("Crystal")
    restored_quoted.quoted_literal_start.should eq(0)
    restored_quoted.quoted_literal_end.should eq(10)

    restored_string = restored.parent(string_index).as(Iyi::DiagnosticOrigin::DerivedName)
    restored_string.production.should eq(Iyi::DiagnosticTypeSugar::StringArray)
    restored_string.sugar_result.should eq(Iyi::DiagnosticTypeSugarResult::String)
    restored_string.witnesses.size.should eq(1)

    rewritten = IO::Memory.new
    restored.write(rewritten)
    rewritten.to_slice.should eq(bytes)
  end

  it "refuses a stored QuotedName whose literal mode was altered" do
    table = Iyi::IyiMod::DiagnosticOrigins.new
    table.intern(names_quoted)
    io = IO::Memory.new
    table.write(io)
    bytes = io.to_slice.dup
    bytes[names_index_of(bytes, "Crystal".to_slice)] = 'X'.ord.to_u8
    expect_raises(ArgumentError, "invalid quoted name") do
      Iyi::IyiMod::DiagnosticOrigins.read(IO::Memory.new(bytes))
    end
  end

  it "refuses a v63 artifact with the existing version message" do
    names_with_temporary_file do |path|
      File.open(path, "wb") do |file|
        file.write Iyi::IyiMod::MAGIC
        file.write_bytes 63_u32, Iyi::IyiMod::FORMAT
        file.write_bytes 0_u32, Iyi::IyiMod::FORMAT
      end
      expect_raises(Iyi::IyiMod::Error, /format v63, this compiler writes v64/) { Iyi::IyiMod.read(path) }
    end
  end
end
