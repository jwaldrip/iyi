module Iyi
  # Frame stream for one parsed AST (C2). The walk is pre-order over
  # DiagnosticDirectChildFields. The first visit of a node emits, in order:
  #
  # - one F frame for each filename identity the node references for the first
  #   time, in the order its node object references them;
  # - one N frame: the node object in the snapshot's own encoding, with each
  #   filename as a sha256 reference and each child as a bare kind stub;
  # - each child: its full subtree on a first visit, otherwise an A frame.
  #
  # N and F frames are a tag byte, a big-endian u64 length, then the payload.
  # An A frame is a tag byte, then the owner id as a big-endian u64. The digest
  # is sha256("iyi.capture.v1.ast\0" || frames), in stream order.
  #
  # Retained metadata is bounded by the number of first visits and of distinct
  # filename identities, each held as a fixed-size digest:
  #
  # - filename bytes are emitted once, at first reference, and not kept; only
  #   the identity-to-digest entry survives;
  # - no child edge is stored. Children are re-enumerated from the node after its
  #   N frame is out, so an ancestor holds only its node and its owner id;
  # - an N frame's JSON is released before its children are walked.
  #
  # Each N frame has its own output cap and evidence budget. The walk is
  # single-use and holds its root, so no object id is reused while it runs.
  class DiagnosticAstFrameStream
    DIGEST_TAG = "iyi.capture.v1.ast\0"
    TAG_NODE = 'N'.ord.to_u8
    TAG_FILENAME = 'F'.ord.to_u8
    TAG_ALIAS = 'A'.ord.to_u8
    HEADER_BYTES = 9
    MAX_DEPTH = DiagnosticAstNodeBody::MAX_DEPTH

    getter nodes : Int32 = 0
    getter aliases : Int32 = 0
    getter filename_frames : Int32 = 0
    getter stream_bytes : UInt64 = 0_u64
    getter max_node_bytes : Int32 = 0
    getter max_filename_bytes : Int32 = 0

    @consumed = false
    @active = Set(UInt64).new
    @owner_ids = {} of UInt64 => Int32
    @filename_digests = {} of String => String
    @digest : ::Crystal::Digest::SHA256? = nil
    @sink : Proc(Bytes, Nil)? = nil
    @ast_sha256 : String? = nil

    def initialize(@root : ASTNode)
    end

    # The digest of the complete stream, available once the stream has run.
    def ast_sha256 : String
      @ast_sha256 || raise ArgumentError.new("frame stream has not run")
    end

    # Retained metadata, for measurement. Entries are one per first visit and one
    # per distinct filename identity; the digest bytes are fixed-size per entry.
    def retained_owner_entries : Int32
      @owner_ids.size
    end

    def retained_filename_entries : Int32
      @filename_digests.size
    end

    def retained_filename_digest_bytes : Int64
      @filename_digests.sum { |entry| entry[0].bytesize.to_i64 + entry[1].bytesize.to_i64 }
    end

    # Streams every chunk to the block, in order, and returns the digest. Chunks
    # are frame headers and payloads; their concatenation is the stream.
    def stream(&block : Bytes -> Nil) : String
      raise ArgumentError.new("frame stream is single-use") if @consumed
      @consumed = true
      digest = ::Crystal::Digest::SHA256.new
      digest.update(DIGEST_TAG.to_slice)
      @digest = digest
      @sink = block
      visit(@root, 0)
      @ast_sha256 = digest.hexfinal
    end

    # Returns the sha256 of a filename snapshot, the value an N frame carries.
    # On first reference of an identity, its F frame is emitted now, before the
    # node that references it, and the snapshot is not kept. Identity is the
    # VirtualFile object or the String content. A nil filename is its own identity.
    def filename_digest(filename : String | VirtualFile | Nil) : String
      key = filename_identity(filename)
      if digest = @filename_digests[key]?
        return digest
      end
      snapshot = DiagnosticFilenameSnapshot.new(filename)
      digest = snapshot.sha256
      @filename_digests[key] = digest
      emit_filename(snapshot)
      digest
    end

    private def filename_identity(filename : String | VirtualFile | Nil) : String
      case filename
      when Nil         then "N"
      when String      then "S" + ::Crystal::Digest::SHA256.hexdigest(filename)
      when VirtualFile then "V#{filename.object_id}"
      else                  raise ArgumentError.new("unclassified filename binding")
      end
    end

    private def visit(node : ASTNode, depth : Int32) : Nil
      raise ArgumentError.new("AST inventory exceeds depth limit") if depth > MAX_DEPTH
      id = node.object_id
      raise ArgumentError.new("cyclic AST inventory") unless @active.add?(id)
      begin
        owner_id = @owner_ids.size
        @owner_ids[id] = owner_id
        emit_node_frame(node, depth, owner_id)
        visit_children(node, depth)
      ensure
        @active.delete(id)
      end
    end

    # The node's F frames go out during the body write, which precedes its N frame.
    # This method's locals end before any child is walked.
    private def emit_node_frame(node : ASTNode, depth : Int32, owner_id : Int32) : Nil
      output = DiagnosticCaptureOutput.new(DiagnosticAstNodeBody::MAX_BYTES)
      json = JSON::Builder.new(output)
      json.max_nesting = 1024
      json.start_document
      Body.new(self).write_object(json, node, depth, owner_id)
      json.end_document
      emit_node(output.snapshot)
    end

    # Children are enumerated again from the node, in the same order the body used.
    private def visit_children(node : ASTNode, depth : Int32) : Nil
      DiagnosticDirectChildFields.each(node) do |_field, _index, _key, child|
        visit_child(child, depth + 1)
      end
    end

    private def visit_child(child : ASTNode, depth : Int32) : Nil
      raise ArgumentError.new("AST inventory exceeds depth limit") if depth > MAX_DEPTH
      raise ArgumentError.new("cyclic AST inventory") if @active.includes?(child.object_id)
      if owner_id = @owner_ids[child.object_id]?
        emit_alias(owner_id)
      else
        visit(child, depth)
      end
    end

    private def emit_filename(snapshot : DiagnosticFilenameSnapshot) : Nil
      payload = snapshot.bytes_slice
      emit(frame_header(TAG_FILENAME, payload.size))
      emit(payload)
      @filename_frames += 1
      @max_filename_bytes = Math.max(@max_filename_bytes, payload.size)
    end

    private def emit_node(json : String) : Nil
      payload = json.to_slice
      emit(frame_header(TAG_NODE, payload.size))
      emit(payload)
      @nodes += 1
      @max_node_bytes = Math.max(@max_node_bytes, payload.size)
    end

    private def emit_alias(owner_id : Int32) : Nil
      header = Bytes.new(HEADER_BYTES)
      header[0] = TAG_ALIAS
      write_u64(header, 1, owner_id.to_u64)
      emit(header)
      @aliases += 1
    end

    private def frame_header(tag : UInt8, length : Int32) : Bytes
      header = Bytes.new(HEADER_BYTES)
      header[0] = tag
      write_u64(header, 1, length.to_u64)
      header
    end

    private def write_u64(buffer : Bytes, offset : Int32, value : UInt64) : Nil
      8.times { |index| buffer[offset + index] = ((value >> (56 - 8 * index)) & 0xff_u64).to_u8 }
    end

    private def emit(chunk : Bytes) : Nil
      @digest.not_nil!.update(chunk)
      @stream_bytes += chunk.size.to_u64
      @sink.not_nil!.call(chunk)
    end

    # Writes one node object. It keeps only the walker, so it holds no child edges
    # and no filename bytes after the node's frames are out.
    class Body < DiagnosticAstNodeBody
      def initialize(@walker : DiagnosticAstFrameStream)
        super(DiagnosticOrigin::MAX_UNFOLDED_BYTES)
      end

      def write_object(json : JSON::Builder, node : ASTNode, depth : Int32, owner_id : Int32) : Nil
        write_node_object(json, node, depth, owner_id)
      end

      def write_filename_field(json : JSON::Builder, filename : String | VirtualFile | Nil) : Nil
        json.field "filename_sha256", @walker.filename_digest(filename)
      end

      def write_child_node(json : JSON::Builder, child : ASTNode, depth : Int32) : Nil
        json.object { json.field "kind", child.class.name }
      end
    end
  end
end
