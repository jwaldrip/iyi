require "../support/syntax"

# Frame stream for the diagnostic AST capture (C2, slice A).
#
# The frames must reproduce the snapshot's expanded object exactly, so the shared
# node body is pinned by the snapshot. A changed filename byte, cycle, depth
# overflow or reuse must be rejected. The digest must move for every change to a
# name, child, alias or metadata field. None of these checks is skipped.

FRAME_SPEC_FIXTURE = "spec/frames/fixture.iyi"

private def frame_spec_parse(source : String, filename : String = FRAME_SPEC_FIXTURE) : Iyi::ASTNode
  parser = Iyi::Parser.new(source, nil, [Set(String).new], Iyi::WarningCollection.new)
  parser.filename = filename
  parser.diagnostic_source_file = filename
  parser.diagnostic_capture = true
  parser.parse
end

private def frame_spec_json(text : String) : JSON::Any
  parser = JSON::Parser.new(text)
  parser.max_nesting = 1024
  parser.parse
end

# Streams the frames into memory and returns the bytes, the digest and the stream.
private def frame_spec_stream(root : Iyi::ASTNode) : {Bytes, String, Iyi::DiagnosticAstFrameStream}
  io = IO::Memory.new
  stream = Iyi::DiagnosticAstFrameStream.new(root)
  digest = stream.stream { |chunk| io.write(chunk) }
  {io.to_slice, digest, stream}
end

# The digest definition from C2, recomputed from the frame bytes alone.
private def frame_spec_digest(bytes : Bytes) : String
  material = IO::Memory.new
  material << "iyi.capture.v1.ast\0"
  material.write(bytes)
  ::Crystal::Digest::SHA256.hexdigest(material.to_s)
end

private def frame_spec_u64(bytes : Bytes, offset : Int32) : UInt64
  value = 0_u64
  8.times { |index| value = (value << 8) | bytes[offset + index].to_u64 }
  value
end

record FrameSpecFrame, tag : UInt8, payload : Bytes, owner : UInt64

private def frame_spec_decode(stream : Bytes) : Array(FrameSpecFrame)
  frames = [] of FrameSpecFrame
  offset = 0
  while offset < stream.size
    raise "truncated frame header" if offset + 9 > stream.size
    tag = stream[offset]
    value = frame_spec_u64(stream, offset + 1)
    if tag == Iyi::DiagnosticAstFrameStream::TAG_ALIAS
      frames << FrameSpecFrame.new(tag, Bytes.empty, value)
      offset += 9
    elsif tag == Iyi::DiagnosticAstFrameStream::TAG_NODE || tag == Iyi::DiagnosticAstFrameStream::TAG_FILENAME
      raise "truncated frame payload" if value > (stream.size - offset - 9).to_u64
      length = value.to_i32
      frames << FrameSpecFrame.new(tag, stream[offset + 9, length], 0_u64)
      offset += 9 + length
    else
      raise "unknown frame tag"
    end
  end
  frames
end

# Offset of the first F frame's payload, found by walking the headers.
private def frame_spec_first_filename_offset(stream : Bytes) : Int32
  offset = 0
  while offset < stream.size
    tag = stream[offset]
    return offset + 9 if tag == Iyi::DiagnosticAstFrameStream::TAG_FILENAME
    offset += tag == Iyi::DiagnosticAstFrameStream::TAG_ALIAS ? 9 : 9 + frame_spec_u64(stream, offset + 1).to_i32
  end
  raise "no filename frame"
end

# Rebuilds the expanded snapshot object from the frames alone. A filename
# reference resolves only through an F frame whose own digest matches it. An A
# frame resolves only to a node already expanded. Trailing frames are refused.
private class FrameSpecExpander
  @position = 0
  @filenames = {} of String => Bytes
  @expanded = {} of UInt64 => JSON::Any

  def initialize(@frames : Array(FrameSpecFrame))
  end

  def run : JSON::Any
    read_filename_frames
    root = read_node(take)
    raise "trailing frames" unless @position == @frames.size
    root
  end

  private def take : FrameSpecFrame
    raise "frame stream ended early" if @position >= @frames.size
    frame = @frames[@position]
    @position += 1
    frame
  end

  private def read_filename_frames : Nil
    while @position < @frames.size && @frames[@position].tag == Iyi::DiagnosticAstFrameStream::TAG_FILENAME
      payload = @frames[@position].payload
      key = ::Crystal::Digest::SHA256.hexdigest(String.new(payload))
      raise "duplicate filename frame" if @filenames.has_key?(key)
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

  private def read_node(frame : FrameSpecFrame) : JSON::Any
    raise "expected a node frame" unless frame.tag == Iyi::DiagnosticAstFrameStream::TAG_NODE
    parsed = frame_spec_json(String.new(frame.payload)).as_h
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

describe "diagnostic capture frame stream" do
  it "reconstructs the snapshot object exactly from its frames" do
    root = frame_spec_parse("class Foo\n  def bar(x : Int32) : Int32\n    x + 1\n  end\nend\n")
    bytes, digest, _ = frame_spec_stream(root)
    expanded = FrameSpecExpander.new(frame_spec_decode(bytes)).run
    expanded.should eq(frame_spec_json(Iyi::DiagnosticAstInventorySnapshot.new(root).bytes))
    digest.should eq(frame_spec_digest(bytes))
  end

  it "reconstructs an aliased node the way the snapshot expands it" do
    shared = Iyi::Var.new("a")
    root = Iyi::Expressions.new([shared, shared] of Iyi::ASTNode)
    bytes, _, stream = frame_spec_stream(root)
    stream.aliases.should eq(1)
    expanded = FrameSpecExpander.new(frame_spec_decode(bytes)).run
    expanded.should eq(frame_spec_json(Iyi::DiagnosticAstInventorySnapshot.new(root).bytes))
  end

  it "keeps the snapshot bytes stable for the same tree" do
    root = frame_spec_parse("x = 1\ny = x + 2\n")
    first = Iyi::DiagnosticAstInventorySnapshot.new(root).bytes
    second = Iyi::DiagnosticAstInventorySnapshot.new(root).bytes
    second.should eq(first)
  end

  it "digests the frame bytes under the capture tag" do
    bytes, digest, _ = frame_spec_stream(frame_spec_parse("x = 1\n"))
    digest.should eq(frame_spec_digest(bytes))
  end

  it "is deterministic across fresh parses" do
    source = "def add(a, b)\n  a + b\nend\n"
    first_bytes, first_digest, _ = frame_spec_stream(frame_spec_parse(source))
    second_bytes, second_digest, _ = frame_spec_stream(frame_spec_parse(source))
    second_bytes.should eq(first_bytes)
    second_digest.should eq(first_digest)
  end

  it "emits each filename identity exactly once" do
    bytes, _, stream = frame_spec_stream(frame_spec_parse("a = 1\nb = 2\nc = 3\n"))
    filenames = frame_spec_decode(bytes).select { |frame| frame.tag == Iyi::DiagnosticAstFrameStream::TAG_FILENAME }
    stream.filename_frames.should eq(filenames.size)
    filenames.map { |frame| ::Crystal::Digest::SHA256.hexdigest(String.new(frame.payload)) }.uniq.size.should eq(filenames.size)
    (stream.filename_frames >= 1).should be_true
  end

  it "moves the digest when a name changes" do
    _, base_digest, _ = frame_spec_stream(Iyi::Expressions.new([Iyi::Var.new("a")] of Iyi::ASTNode))
    _, renamed_digest, _ = frame_spec_stream(Iyi::Expressions.new([Iyi::Var.new("b")] of Iyi::ASTNode))
    renamed_digest.should_not eq(base_digest)
  end

  it "moves the digest when a child is added" do
    _, base_digest, _ = frame_spec_stream(Iyi::Expressions.new([Iyi::Var.new("a")] of Iyi::ASTNode))
    _, extra_digest, _ = frame_spec_stream(Iyi::Expressions.new([Iyi::Var.new("a"), Iyi::Var.new("a")] of Iyi::ASTNode))
    extra_digest.should_not eq(base_digest)
  end

  it "moves the digest when a shared child becomes an alias" do
    _, separate_digest, _ = frame_spec_stream(Iyi::Expressions.new([Iyi::Var.new("a"), Iyi::Var.new("a")] of Iyi::ASTNode))
    shared = Iyi::Var.new("a")
    _, aliased_digest, _ = frame_spec_stream(Iyi::Expressions.new([shared, shared] of Iyi::ASTNode))
    aliased_digest.should_not eq(separate_digest)
  end

  it "moves the digest when only the filename metadata changes" do
    _, first_digest, _ = frame_spec_stream(frame_spec_parse("x = 1\n", "spec/frames/a.iyi"))
    _, second_digest, _ = frame_spec_stream(frame_spec_parse("x = 1\n", "spec/frames/b.iyi"))
    second_digest.should_not eq(first_digest)
  end

  it "rejects a filename frame whose bytes change" do
    bytes, digest, _ = frame_spec_stream(frame_spec_parse("x = 1\n"))
    tampered = bytes.dup
    offset = frame_spec_first_filename_offset(tampered)
    tampered[offset] = tampered[offset] ^ 0x01_u8
    frame_spec_digest(tampered).should_not eq(digest)
    expect_raises(Exception, "filename reference has no frame") do
      FrameSpecExpander.new(frame_spec_decode(tampered)).run
    end
  end

  it "rejects a cycle in the AST" do
    node = Iyi::Expressions.new([] of Iyi::ASTNode)
    node.expressions << node
    expect_raises(ArgumentError, "cyclic AST inventory") do
      Iyi::DiagnosticAstFrameStream.new(node).stream { |_chunk| }
    end
  end

  it "rejects a tree deeper than the absolute depth limit" do
    node = Iyi::Var.new("x").as(Iyi::ASTNode)
    200.times { node = Iyi::Expressions.new([node] of Iyi::ASTNode) }
    expect_raises(ArgumentError, "AST inventory exceeds depth limit") do
      Iyi::DiagnosticAstFrameStream.new(node).stream { |_chunk| }
    end
  end

  it "refuses a second walk" do
    stream = Iyi::DiagnosticAstFrameStream.new(Iyi::Var.new("a"))
    stream.stream { |_chunk| }
    expect_raises(ArgumentError, "frame stream is single-use") do
      stream.stream { |_chunk| }
    end
  end

  it "orders an alias after the first visit it refers to" do
    shared = Iyi::Var.new("a")
    root = Iyi::Expressions.new([shared, shared] of Iyi::ASTNode)
    bytes, _, _ = frame_spec_stream(root)
    frames = frame_spec_decode(bytes)
    frames.map(&.tag).should eq([Iyi::DiagnosticAstFrameStream::TAG_NODE,
                                 Iyi::DiagnosticAstFrameStream::TAG_NODE,
                                 Iyi::DiagnosticAstFrameStream::TAG_ALIAS])
    frames[2].owner.should eq(1_u64)
  end

  it "emits a filename frame before the node that first references it" do
    bytes, _, stream = frame_spec_stream(frame_spec_parse("x = 1\n"))
    frames = frame_spec_decode(bytes)
    frames.first.tag.should eq(Iyi::DiagnosticAstFrameStream::TAG_FILENAME)
    frames.count { |frame| frame.tag == Iyi::DiagnosticAstFrameStream::TAG_FILENAME }.should eq(stream.filename_frames)
    frames.none? { |frame| frame.tag == Iyi::DiagnosticAstFrameStream::TAG_ALIAS }.should be_true
  end

  it "retains one owner entry per first visit and one digest per filename identity" do
    bytes, _, stream = frame_spec_stream(frame_spec_parse("a = 1\n" * 200))
    stream.retained_owner_entries.should eq(stream.nodes)
    stream.retained_filename_entries.should eq(stream.filename_frames)
    stream.retained_filename_entries.should eq(1)
    stream.retained_filename_digest_bytes.should be < 200_i64
    (stream.stream_bytes > stream.retained_filename_digest_bytes * 100).should be_true
    bytes.size.should eq(stream.stream_bytes.to_i32)
  end

end
