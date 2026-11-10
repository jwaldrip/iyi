require "base64"
require "../spec_helper"
require "../../src/compiler/iyi/syntax/diagnostic_semantic_defaults"

# The diagnostic AST frame stream on real parser roots, with the semantic guard
# active.
#
# Every root is produced by Iyi::Parser from the source text below. Nothing is
# built by hand and no snapshot is mocked. The stream's own node walk runs the
# semantic guard on every node. The frames are decoded independently here, the
# decoded expansion is compared with the inventory snapshot, and the names it
# carries are checked against the source they came from.
#
# A `.iyi` filename selects the Iyi lexer and a `.cr` filename selects the
# Crystal lexer, which is what `--crystal-mode` builds read.
#
# This file needs the full compiler. It refuses to compile without it instead of
# checking less.
{% unless Iyi::Block.has_method?(:binder) %}
  {% raise "diagnostic_capture_real_full_spec requires the full compiler types (Block#binder)" %}
{% end %}

REAL_CAPTURE_CATALOG = <<-SRC
module Shop::Catalog
  class Item
    def initialize(name : String, price : Int32)
      @name = name
      @price = price
    end

    def label : String
      if @price > 0
        "\#{@name}: \#{@price}"
      else
        @name
      end
    end
  end

  macro price_of(item)
    {{ item }}.price
  end

  def self.sample : Array(Item)
    [Item.new("pen", 2), Item.new("book", 12)]
  end

  def self.index : Hash(String, Int32)
    {"pen" => 2, "book" => 12}
  end
end
SRC

REAL_CAPTURE_TOTALS = <<-SRC
total = Foo::Bar::Baz.size
values = [1, 2, 3]
table = {"alpha" => values}
picked = if total > 0
  values
else
  [0]
end
unless picked.empty?
  table.fetch("alpha")
end
SRC

REAL_CAPTURE_CATALOG_NAMES = ["Catalog", "Item", "initialize", "label", "price_of", "item", "sample", "index", "Array", "Hash", "Int32", "String", "new"]
REAL_CAPTURE_TOTALS_NAMES  = ["total", "values", "table", "picked", "Foo", "Bar", "Baz", "size", "fetch", "empty?"]

# Parses through a fresh parser that captures its own input before parsing.
private def real_capture_parser(source : String, filename : String) : Iyi::Parser
  parser = Iyi::Parser.new(source, nil, [Set(String).new], Iyi::WarningCollection.new)
  parser.filename = filename
  parser.diagnostic_source_file = filename
  parser.diagnostic_capture = true
  parser
end

private def real_capture_root(source : String, filename : String) : {Iyi::AcceptedCaptureInput, Iyi::ASTNode}
  parser = real_capture_parser(source, filename)
  input = parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile, nil,
    Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
  {input, parser.parse}
end

# Streams the frames into memory through the stream's own entry point.
private def real_capture_stream(root : Iyi::ASTNode) : {Bytes, String, Iyi::DiagnosticAstFrameStream}
  io = IO::Memory.new
  stream = Iyi::DiagnosticAstFrameStream.new(root)
  digest = stream.stream { |chunk| io.write(chunk) }
  {io.to_slice, digest, stream}
end

# The digest definition from C2, recomputed from the frame bytes alone.
private def real_capture_digest(bytes : Bytes) : String
  material = IO::Memory.new
  material << Iyi::DiagnosticAstFrameStream::DIGEST_TAG
  material.write(bytes)
  ::Crystal::Digest::SHA256.hexdigest(material.to_s)
end

private def real_capture_json(text : String) : JSON::Any
  parser = JSON::Parser.new(text)
  parser.max_nesting = 1024
  parser.parse
end

record RealCaptureFrame, tag : UInt8, payload : Bytes, owner : UInt64

private def real_capture_u64(bytes : Bytes, offset : Int32) : UInt64
  value = 0_u64
  8.times { |index| value = (value << 8) | bytes[offset + index].to_u64 }
  value
end

private def real_capture_decode(stream : Bytes) : Array(RealCaptureFrame)
  frames = [] of RealCaptureFrame
  offset = 0
  while offset < stream.size
    raise "truncated frame header" if offset + 9 > stream.size
    tag = stream[offset]
    value = real_capture_u64(stream, offset + 1)
    if tag == Iyi::DiagnosticAstFrameStream::TAG_ALIAS
      frames << RealCaptureFrame.new(tag, Bytes.empty, value)
      offset += 9
    elsif tag == Iyi::DiagnosticAstFrameStream::TAG_NODE || tag == Iyi::DiagnosticAstFrameStream::TAG_FILENAME
      raise "truncated frame payload" if value > (stream.size - offset - 9).to_u64
      length = value.to_i32
      frames << RealCaptureFrame.new(tag, stream[offset + 9, length], 0_u64)
      offset += 9 + length
    else
      raise "unknown frame tag"
    end
  end
  frames
end

# Rebuilds the expanded snapshot object from the frames alone. A filename
# reference resolves only through an F frame whose digest matches it. An A frame
# resolves only to a node already expanded. Trailing frames are refused.
private class RealCaptureExpander
  @position = 0
  @filenames = {} of String => Bytes
  @expanded = {} of UInt64 => JSON::Any

  def initialize(@frames : Array(RealCaptureFrame))
  end

  def run : JSON::Any
    read_filename_frames
    root = read_node(take)
    raise "trailing frames" unless @position == @frames.size
    root
  end

  private def take : RealCaptureFrame
    raise "frame stream ended early" if @position >= @frames.size
    frame = @frames[@position]
    @position += 1
    frame
  end

  private def read_filename_frames : Nil
    while @position < @frames.size && @frames[@position].tag == Iyi::DiagnosticAstFrameStream::TAG_FILENAME
      payload = @frames[@position].payload
      key = ::Crystal::Digest::SHA256.hexdigest(String.new(payload))
      if previous = @filenames[key]?
        raise "filename digest collision" unless previous == payload
      end
      @filenames[key] = payload
      @position += 1
    end
  end

  private def read_child(kind : String) : JSON::Any
    read_filename_frames
    frame = take
    if frame.tag == Iyi::DiagnosticAstFrameStream::TAG_ALIAS
      expanded = @expanded[frame.owner]? || raise "alias precedes its node"
      raise "alias kind mismatch" unless expanded.as_h["kind"].as_s == kind
      expanded
    else
      node = read_node(frame)
      raise "child kind mismatch" unless node.as_h["kind"].as_s == kind
      node
    end
  end

  private def read_node(frame : RealCaptureFrame) : JSON::Any
    raise "expected a node frame" unless frame.tag == Iyi::DiagnosticAstFrameStream::TAG_NODE
    parsed = real_capture_json(String.new(frame.payload)).as_h
    owner = parsed["owner_id"].as_i64.to_u64
    raise "duplicate owner id" if @expanded.has_key?(owner)
    node = fill_filenames(JSON::Any.new(parsed)).as_h
    children = node["children"].as_a.map do |entry|
      edge = entry.as_h.dup
      kind = edge["node"].as_h["kind"].as_s
      edge["node"] = read_child(kind)
      JSON::Any.new(edge)
    end
    node["children"] = JSON::Any.new(children)
    result = JSON::Any.new(node)
    @expanded[owner] = result
    result
  end

  private def fill_filenames(value : JSON::Any) : JSON::Any
    if hash = value.as_h?
      if reference = hash["filename_sha256"]?
        payload = @filenames[reference.as_s]? || raise "filename reference has no frame"
        filled = {} of String => JSON::Any
        hash.each { |key, item| filled[key] = item unless key == "filename_sha256" }
        filled["filename_snapshot"] = JSON::Any.new(String.new(payload))
        JSON::Any.new(filled)
      else
        filled = {} of String => JSON::Any
        hash.each { |key, item| filled[key] = fill_filenames(item) }
        JSON::Any.new(filled)
      end
    elsif array = value.as_a?
      JSON::Any.new(array.map { |item| fill_filenames(item) })
    else
      value
    end
  end
end

# Every direct name the expansion carries, in tree order.
private def real_capture_names(node : JSON::Any, into : Array(String)) : Array(String)
  fields = node.as_h
  fields["names"].as_a.each do |entry|
    into << String.new(Base64.decode(entry.as_h["value_base64"].as_s))
  end
  fields["children"].as_a.each { |edge| real_capture_names(edge.as_h["node"], into) }
  into
end

# The decoded segments of every Path node, in tree order.
private def real_capture_path_names(node : JSON::Any, into : Array(Array(String))) : Array(Array(String))
  fields = node.as_h
  if fields["kind"].as_s == "Iyi::Path"
    into << fields["names"].as_a.map { |entry| String.new(Base64.decode(entry.as_h["value_base64"].as_s)) }
  end
  fields["children"].as_a.each { |edge| real_capture_path_names(edge.as_h["node"], into) }
  into
end

# Every filename the expansion carries, wherever it appears.
private def real_capture_filenames(value : JSON::Any, into : Array(String)) : Nil
  if hash = value.as_h?
    hash.each do |key, item|
      if key == "filename_snapshot"
        into << item.as_s
      else
        real_capture_filenames(item, into)
      end
    end
  elsif array = value.as_a?
    array.each { |item| real_capture_filenames(item, into) }
  end
end

# The first node in tree order for which the block answers true.
private def real_capture_find(node : Iyi::ASTNode, &block : Iyi::ASTNode -> Bool) : Iyi::ASTNode?
  return node if block.call(node)
  Iyi::DiagnosticDirectChildFields.each(node) do |_field, _index, _key, child|
    found = real_capture_find(child, &block)
    return found if found
  end
  nil
end

private def real_capture_check_root(source : String, filename : String, lexical_mode : String,
                                    root_kind : String, expected_names : Array(String)) : JSON::Any
  input, root = real_capture_root(source, filename)
  input.input_sha256.should eq(::Crystal::Digest::SHA256.hexdigest(source))
  input.lexical_mode.should eq(lexical_mode)

  Iyi::DiagnosticSemanticDefaults.verify_tree!(root)

  bytes, digest, stream = real_capture_stream(root)
  stream.ast_sha256.should eq(digest)
  digest.should eq(real_capture_digest(bytes))

  frames = real_capture_decode(bytes)
  frames.count { |frame| frame.tag == Iyi::DiagnosticAstFrameStream::TAG_NODE }.should eq(stream.nodes)
  frames.count { |frame| frame.tag == Iyi::DiagnosticAstFrameStream::TAG_ALIAS }.should eq(stream.aliases)
  (stream.nodes > 0).should be_true

  expanded = RealCaptureExpander.new(frames).run
  expanded.should eq(real_capture_json(Iyi::DiagnosticAstInventorySnapshot.new(root).bytes))
  expanded.as_h["kind"].as_s.should eq(root_kind)

  names = real_capture_names(expanded, [] of String)
  expected_names.each do |name|
    names.includes?(name).should be_true
    source.should contain(name)
  end

  filenames = [] of String
  real_capture_filenames(expanded, filenames)
  filenames.any? { |item| item.includes?(filename) }.should be_true

  expanded
end

describe "diagnostic capture real parser roots" do
  describe "streams real parser roots with the semantic guard active" do
    it "streams a .iyi catalog of definitions, paths, a macro, collections, and a conditional" do
      real_capture_check_root(REAL_CAPTURE_CATALOG, "/spec/real/catalog.iyi", "Iyi", "Iyi::ModuleDef", REAL_CAPTURE_CATALOG_NAMES)
    end

    it "streams the same catalog as a --crystal-mode .cr root" do
      real_capture_check_root(REAL_CAPTURE_CATALOG, "/spec/real/catalog.cr", "Crystal", "Iyi::ModuleDef", REAL_CAPTURE_CATALOG_NAMES)
    end

    it "streams a .iyi totals script of paths, collections, and conditionals" do
      real_capture_check_root(REAL_CAPTURE_TOTALS, "/spec/real/totals.iyi", "Iyi", "Iyi::Expressions", REAL_CAPTURE_TOTALS_NAMES)
    end

    it "streams the same totals as a --crystal-mode .cr root" do
      real_capture_check_root(REAL_CAPTURE_TOTALS, "/spec/real/totals.cr", "Crystal", "Iyi::Expressions", REAL_CAPTURE_TOTALS_NAMES)
    end
  end

  describe "decoded evidence preserves source names" do
    it "decodes the module path segments of the catalog exactly" do
      _, root = real_capture_root(REAL_CAPTURE_CATALOG, "/spec/real/catalog.iyi")
      bytes, _, _ = real_capture_stream(root)
      expanded = RealCaptureExpander.new(real_capture_decode(bytes)).run
      paths = real_capture_path_names(expanded, [] of Array(String))
      paths.includes?(["Shop", "Catalog"]).should be_true
      paths.includes?(["Item"]).should be_true
      paths.includes?(["Hash"]).should be_true
    end

    it "decodes the three-segment path of the totals exactly" do
      _, root = real_capture_root(REAL_CAPTURE_TOTALS, "/spec/real/totals.iyi")
      bytes, _, _ = real_capture_stream(root)
      expanded = RealCaptureExpander.new(real_capture_decode(bytes)).run
      paths = real_capture_path_names(expanded, [] of Array(String))
      paths.includes?(["Foo", "Bar", "Baz"]).should be_true
    end

    it "decodes a def and a macro name from the source" do
      _, root = real_capture_root(REAL_CAPTURE_CATALOG, "/spec/real/catalog.iyi")
      bytes, _, _ = real_capture_stream(root)
      expanded = RealCaptureExpander.new(real_capture_decode(bytes)).run
      names = real_capture_names(expanded, [] of String)
      names.includes?("label").should be_true
      names.includes?("price_of").should be_true
    end

    it "accepts the real root under the recorded input's semantic and evidence checks" do
      input, root = real_capture_root(REAL_CAPTURE_CATALOG, "/spec/real/catalog.iyi")
      Iyi::DiagnosticRecordedEvidenceInputCheck.new(input).verify!(root)
    end

    it "accepts the real totals root under the recorded input's evidence checks" do
      input, root = real_capture_root(REAL_CAPTURE_TOTALS, "/spec/real/totals.iyi")
      Iyi::DiagnosticRecordedEvidenceInputCheck.new(input).verify!(root)
    end
  end

  describe "a real non-default semantic mutation is refused through the stream" do
    it "refuses a parsed call whose uses_with_scope flag is set" do
      _, root = real_capture_root(REAL_CAPTURE_CATALOG, "/spec/real/catalog.iyi")
      real_capture_stream(root)
      call = real_capture_find(root) { |node| node.is_a?(Iyi::Call) && node.name == "new" }.not_nil!.as(Iyi::Call)
      call.uses_with_scope = true
      expect_raises(ArgumentError, /Call\.uses_with_scope: raw value differs/) do
        real_capture_stream(root)
      end
    end

    it "refuses a parsed def whose abi_info flag is set" do
      _, root = real_capture_root(REAL_CAPTURE_CATALOG, "/spec/real/catalog.iyi")
      real_capture_stream(root)
      definition = real_capture_find(root) { |node| node.is_a?(Iyi::Def) && node.name == "label" }.not_nil!.as(Iyi::Def)
      definition.abi_info = true
      expect_raises(ArgumentError, /Def\.abi_info: raw value differs/) do
        real_capture_stream(root)
      end
    end
  end
end
