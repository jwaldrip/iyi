require "base64"
require "json"
require "set"
require "crystal/digest/sha256"
require "./diagnostic_origin"

module Iyi
  # Bounded canonical record and shard serialization ("iyi-msi/1") for a typed
  # node graph. It encodes and verifies bytes only. It is not an authority: no
  # parser acceptance, schema coverage, source binding or pin is established here.
  #
  # WIRE FORMAT (iyi-msi/1)
  #
  # Canonical text. Every record, shard, schema table and the root manifest is a
  # JSON object written with object keys sorted bytewise, no whitespace, no
  # escapes and no floats. Strings may contain only [A-Za-z0-9+/=_.:-], so no
  # escape can occur. Integers lie within +-(2^53 - 1). The verifier parses each
  # object, re-serializes it, and rejects any byte sequence that differs.
  #
  # Digests are lowercase hex SHA-256 over (domain ++ bytes):
  #   record  domain "iyi.msi.v1.record\0" ++ type ++ "\0"   bytes = canonical record
  #   shard   domain "iyi.msi.v1.shard\0"                    bytes = canonical shard
  #   root    domain "iyi.msi.v1.root\0"                     bytes = canonical root manifest
  #   schema  domain "iyi.msi.v1.schema\0"                   bytes = canonical schema table
  #   key     domain "iyi.capture.v1.key\0"                  bytes = tag ++ "\0" ++ canonical(envelope)
  #                                                                 ++ "\0" ++ input_sha256 ++ "\0" ++ decimal(input_bytes)
  #
  # Limits: shard 1 MiB (1048576), record 256 KiB (262144), inline value 4096
  # bytes, blob chunk 65536 bytes, list fanout 1024, list levels 3 (0..2),
  # AST depth: a root-to-leaf chain holds at most 129 nodes (MAX_DEPTH + 1),
  # matching the existing depth-0-based check in DiagnosticAstInventorySnapshot.
  # Unfolded evidence (names, keys, inline and blob values) totals at most
  # DiagnosticOrigin::MAX_UNFOLDED_BYTES (8 MiB). Input is at most 64 MiB.
  #
  # Records (type in field "t"), each canonical and at most 256 KiB:
  #   B  {"d":b64,"t":"B"}                  one blob chunk, 1..65536 bytes
  #   L  {"e":[ref...],"h":level,"n":count,"t":"L"}
  #        level 0: up to 1024 element refs (N/A for node lists, B for blobs)
  #        level h>0: up to 1024 refs of L records at level h-1
  #        n = leaf elements under this record; the tree is left-packed:
  #        every non-last child holds exactly 1024^(h) leaves
  #        owning children appear in strictly increasing ordinal order
  #   K  {"b":bytes,"l":Lref,"t":"K"}       blob root; chunks in order; all but last 65536
  #   N  {"f":[field...],"k":Kind,"t":"N"}  AST node
  #
  # Reference: [tag, digest, ordinal]. Tags: N owning node, A alias to a completed
  # node (not owning), L list, K blob root, B chunk. The tag names the target record
  # type (A names N). A reference must name an ordinal below the referencing record,
  # carry that record's digest, and each non-alias target has exactly one owner.
  #
  # Field entries, in schema order (names and order must equal the schema for Kind):
  #   [name,"a"]                            absent
  #   [name,"b",bool]                       flag
  #   [name,"i",int]                        number
  #   [name,"t",ident]                      identifier
  #   [name,"y",value]                      octets; value = inline b64 string (<= 4096 bytes) or K ref (> 4096)
  #   [name,"e",ref]                        one child, N or A ref
  #   [name,"l",count,Lref]                 child list, leaves N or A, count = elements
  #   [name,"m",[[i,keyb64,value]...]]      named octets; i = position
  #   [name,"M",[[i,keyb64,ref]...]]        keyed children, N or A refs, at most 1024 entries
  #
  # Root manifest (keys exactly these):
  #   count, envelope, input {blob: K ref, bytes, sha256}, key, root (N ref at ordinal count-1),
  #   schema "iyi-msi/1", schema_digest, shards [[first,count,digest,size]...], tag, tool (hex)
  # Shard: {"f":first,"n":count,"r":[record...]}; file name is its digest. The shard table is
  # contiguous from 0, and the shard set must equal the table exactly.
  #
  # Unsupported here (see report): ParseToDef and MacroExpansion envelopes, origin/
  # file/location typed records, content dedup of O/E/F/B records, streaming to disk,
  # the root self-check results, and any binding from ASTNode to this node model.
  module DiagnosticMsi
    SCHEMA_ID          = "iyi-msi/1"
    SHARD_BYTES        = 1_048_576
    RECORD_BYTES       = 262_144
    INLINE_VALUE_BYTES = 4_096
    BLOB_CHUNK_BYTES   = 65_536
    LIST_FANOUT        = 1_024
    LIST_MAX_LEVEL     = 2
    MAX_DEPTH          = 128
    MAX_INPUT_BYTES    = 64_i64 * 1024 * 1024
    MAX_SAFE_INTEGER   = 9_007_199_254_740_991_i64
    EVIDENCE_BYTES     = DiagnosticOrigin::MAX_UNFOLDED_BYTES.to_i64
    SHARD_OVERHEAD     = 64
    RECORD_TYPES       = %w(B L K N)
    SAFE_TEXT          = /\A[A-Za-z0-9+\/=_.:\-]*\z/
    IDENT              = /\A[A-Za-z][A-Za-z0-9_]{0,63}\z/
    HEX                = /\A[0-9a-f]{64}\z/

    # A value of one schema field.
    class Value
      enum Shape
        Absent
        Flag
        Number
        Identifier
        Octets
        Child
        Children
        Named
        Keyed
      end

      getter shape : Shape
      getter flag : Bool
      getter number : Int64
      getter text : String
      getter bytes : Bytes
      getter node : Node?
      getter nodes : Array(Node)
      getter entries : Array(Entry)

      def initialize(@shape : Shape, @flag : Bool = false, @number : Int64 = 0_i64, @text : String = "", @bytes : Bytes = Bytes.empty, @node : Node? = nil, @nodes : Array(Node) = [] of Node, @entries : Array(Entry) = [] of Entry)
      end

      def self.absent : Value
        new(Shape::Absent)
      end

      def self.flag(value : Bool) : Value
        new(Shape::Flag, flag: value)
      end

      def self.number(value : Int64) : Value
        new(Shape::Number, number: value)
      end

      def self.identifier(value : String) : Value
        new(Shape::Identifier, text: value)
      end

      def self.octets(value : Bytes) : Value
        new(Shape::Octets, bytes: value)
      end

      def self.child(value : Node) : Value
        new(Shape::Child, node: value)
      end

      def self.children(value : Array(Node)) : Value
        new(Shape::Children, nodes: value)
      end

      def self.named(value : Array(Entry)) : Value
        new(Shape::Named, entries: value)
      end

      def self.keyed(value : Array(Entry)) : Value
        new(Shape::Keyed, entries: value)
      end
    end

    # One keyed entry. A named entry carries bytes, a keyed entry carries a node.
    class Entry
      getter key : Bytes
      getter bytes : Bytes?
      getter node : Node?

      def initialize(@key : Bytes, @bytes : Bytes? = nil, @node : Node? = nil)
      end
    end

    class Field
      getter name : String
      getter value : Value

      def initialize(@name : String, @value : Value)
      end
    end

    class Node
      getter kind : String
      getter fields : Array(Field)

      def initialize(@kind : String, @fields : Array(Field) = [] of Field)
      end
    end

    struct Ref
      getter tag : String
      getter digest : String
      getter ordinal : Int64

      def initialize(@tag : String, @digest : String, @ordinal : Int64)
      end

      def json : JSON::Any
        DiagnosticMsi.arr([DiagnosticMsi.str(@tag), DiagnosticMsi.str(@digest), DiagnosticMsi.int(@ordinal)])
      end
    end

    struct ShardEntry
      getter first : Int64
      getter count : Int64
      getter digest : String
      getter size : Int64

      def initialize(@first : Int64, @count : Int64, @digest : String, @size : Int64)
      end
    end

    class Bundle
      getter root : Bytes
      getter root_digest : String
      getter shards : Hash(String, Bytes)

      def initialize(@root : Bytes, @root_digest : String, @shards : Hash(String, Bytes))
      end
    end

    class Verified
      getter input : Bytes
      getter record_count : Int64
      getter node_count : Int64
      getter shard_count : Int32
      getter root_digest : String

      def initialize(@input : Bytes, @record_count : Int64, @node_count : Int64, @shard_count : Int32, @root_digest : String)
      end
    end

    # Canonical JSON helpers. Constructors build values; the canonical writer is
    # the only serializer, so every record and shard has one byte form.
    def self.str(value : String) : JSON::Any
      JSON::Any.new(value)
    end

    def self.int(value : Int64) : JSON::Any
      JSON::Any.new(value)
    end

    def self.arr(items : Array(JSON::Any)) : JSON::Any
      JSON::Any.new(items)
    end

    def self.obj(pairs : Hash(String, JSON::Any)) : JSON::Any
      JSON::Any.new(pairs)
    end

    def self.canonical(value : JSON::Any) : String
      String.build { |io| write_canonical(io, value) }
    end

    def self.write_canonical(io : IO, value : JSON::Any) : Nil
      raw = value.raw
      case raw
      when Nil
        io << "null"
      when Bool
        io << (raw ? "true" : "false")
      when Int64
        raise ArgumentError.new("MSI integer is outside the safe range") if raw.abs > MAX_SAFE_INTEGER
        io << raw
      when String
        raise ArgumentError.new("MSI text is outside the canonical alphabet") unless SAFE_TEXT.matches?(raw)
        io << '"' << raw << '"'
      when Array(JSON::Any)
        io << '['
        raw.each_with_index do |item, position|
          io << ',' unless position == 0
          write_canonical(io, item)
        end
        io << ']'
      when Hash(String, JSON::Any)
        io << '{'
        raw.keys.sort.each_with_index do |key, position|
          raise ArgumentError.new("MSI key is outside the identifier alphabet") unless IDENT.matches?(key)
          io << ',' unless position == 0
          io << '"' << key << "\":"
          write_canonical(io, raw[key])
        end
        io << '}'
      else
        raise ArgumentError.new("MSI canonical form excludes floats")
      end
    end

    def self.digest(domain : String, bytes : Bytes) : String
      hasher = ::Crystal::Digest::SHA256.new
      hasher.update(domain.to_slice)
      hasher.update(bytes)
      hasher.hexfinal
    end

    def self.sha256_hex(bytes : Bytes) : String
      hasher = ::Crystal::Digest::SHA256.new
      hasher.update(bytes)
      hasher.hexfinal
    end

    def self.capture_key(tag : String, envelope_text : String, input_sha : String, input_bytes : Int64) : String
      material = "#{tag}\0#{envelope_text}\0#{input_sha}\0#{input_bytes}"
      digest("iyi.capture.v1.key\0", material.to_slice)
    end

    def self.schema_table(schema : Hash(String, Array(String))) : JSON::Any
      pairs = {} of String => JSON::Any
      schema.each do |kind, fields|
        pairs[kind] = arr(fields.map { |field| str(field) })
      end
      obj(pairs)
    end

    def self.schema_digest(schema : Hash(String, Array(String))) : String
      digest("iyi.msi.v1.schema\0", canonical(schema_table(schema)).to_slice)
    end

    def self.validate_schema(schema : Hash(String, Array(String))) : Nil
      raise ArgumentError.new("MSI schema is empty") if schema.empty?
      schema.each do |kind, fields|
        raise ArgumentError.new("MSI schema kind #{kind} is outside the identifier alphabet") unless IDENT.matches?(kind)
        fields.each do |field|
          raise ArgumentError.new("MSI schema field #{field} is outside the identifier alphabet") unless IDENT.matches?(field)
        end
        raise ArgumentError.new("MSI schema fields for #{kind} repeat") unless fields.uniq.size == fields.size
      end
    end

    # Crystal's stdlib has no strict decoder, so the alphabet and padding are
    # validated here before the lenient Base64.decode runs. The re-encode check
    # then rejects non-zero trailing bits and any other non-canonical spelling.
    BASE64_SHAPE = /\A(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?\z/

    def self.decode64(text : String, what : String) : Bytes
      raise ArgumentError.new("MSI #{what} is not valid base64") unless BASE64_SHAPE.matches?(text)
      decoded = begin
        Base64.decode(text)
      rescue error : Exception
        raise ArgumentError.new("MSI #{what} is not valid base64")
      end
      raise ArgumentError.new("MSI #{what} base64 is not canonical") unless Base64.strict_encode(decoded) == text
      decoded
    end

    def self.parse_canonical(text : String, what : String) : JSON::Any
      value = begin
        JSON.parse(text)
      rescue error : JSON::ParseException
        raise ArgumentError.new("MSI #{what} is not valid JSON")
      end
      raise ArgumentError.new("MSI #{what} is not canonical") unless canonical(value) == text
      value
    end

    def self.text_of(value : JSON::Any, what : String) : String
      value.as_s? || raise ArgumentError.new("MSI #{what} is not a string")
    end

    def self.int_of(value : JSON::Any, what : String) : Int64
      value.as_i64? || raise ArgumentError.new("MSI #{what} is not an integer")
    end

    def self.items_of(value : JSON::Any, what : String) : Array(JSON::Any)
      value.as_a? || raise ArgumentError.new("MSI #{what} is not an array")
    end

    def self.object_of(value : JSON::Any, what : String) : Hash(String, JSON::Any)
      value.as_h? || raise ArgumentError.new("MSI #{what} is not an object")
    end

    def self.keys_exactly!(hash : Hash(String, JSON::Any), keys : Array(String), what : String) : Nil
      raise ArgumentError.new("MSI #{what} keys differ from the canonical set") unless hash.keys.sort == keys.sort
    end

    def self.verify(root : Bytes, shards : Hash(String, Bytes), schema : Hash(String, Array(String))) : Verified
      validate_schema(schema)
      Verifier.new(root, shards, schema).run
    end

    # Writes one accepted input and one node graph into a bundle.
    class Writer
      def initialize(@schema : Hash(String, Array(String)))
        DiagnosticMsi.validate_schema(@schema)
        @ordinal = 0_i64
        @pending = [] of String
        @pending_bytes = 0_i64
        @pending_first = 0_i64
        @shard_table = [] of ShardEntry
        @shards = {} of String => Bytes
        @active = Set(UInt64).new
        @completed = {} of UInt64 => {Ref, Int32}
        @evidence = 0_i64
      end

      def write(root : Node, input : Bytes, tag : String, envelope : JSON::Any, tool : String) : Bundle
        raise ArgumentError.new("MSI input exceeds #{MAX_INPUT_BYTES} bytes") if input.size > MAX_INPUT_BYTES
        raise ArgumentError.new("MSI tag is outside the identifier alphabet") unless IDENT.matches?(tag)
        raise ArgumentError.new("MSI tool digest is not lowercase hex") unless HEX.matches?(tool)
        envelope_text = DiagnosticMsi.canonical(envelope)
        input_ref = write_blob(input)
        input_sha = DiagnosticMsi.sha256_hex(input)
        root_ref, _height = write_node(root, 0)
        raise ArgumentError.new("MSI root must be a first occurrence") unless root_ref.tag == "N"
        raise ArgumentError.new("MSI root must be the final record") unless root_ref.ordinal == @ordinal - 1
        flush_shard
        key = DiagnosticMsi.capture_key(tag, envelope_text, input_sha, input.size.to_i64)
        table = @shard_table.map do |entry|
          DiagnosticMsi.arr([DiagnosticMsi.int(entry.first), DiagnosticMsi.int(entry.count), DiagnosticMsi.str(entry.digest), DiagnosticMsi.int(entry.size)])
        end
        pairs = {} of String => JSON::Any
        pairs["count"] = DiagnosticMsi.int(@ordinal)
        pairs["envelope"] = envelope
        pairs["input"] = DiagnosticMsi.obj({
          "blob"   => input_ref.json,
          "bytes"  => DiagnosticMsi.int(input.size.to_i64),
          "sha256" => DiagnosticMsi.str(input_sha),
        })
        pairs["key"] = DiagnosticMsi.str(key)
        pairs["root"] = root_ref.json
        pairs["schema"] = DiagnosticMsi.str(SCHEMA_ID)
        pairs["schema_digest"] = DiagnosticMsi.str(DiagnosticMsi.schema_digest(@schema))
        pairs["shards"] = DiagnosticMsi.arr(table)
        pairs["tag"] = DiagnosticMsi.str(tag)
        pairs["tool"] = DiagnosticMsi.str(tool)
        root_text = DiagnosticMsi.canonical(DiagnosticMsi.obj(pairs))
        Bundle.new(root_text.to_slice, DiagnosticMsi.digest("iyi.msi.v1.root\0", root_text.to_slice), @shards)
      end

      private def charge(bytes : Int64) : Nil
        @evidence += bytes
        raise ArgumentError.new("MSI evidence exceeds #{EVIDENCE_BYTES} unfolded bytes") if @evidence > EVIDENCE_BYTES
      end

      private def write_node(node : Node, depth : Int32) : {Ref, Int32}
        raise ArgumentError.new("MSI AST depth exceeds #{MAX_DEPTH}") if depth > MAX_DEPTH
        id = node.object_id
        if done = @completed[id]?
          return {Ref.new("A", done[0].digest, done[0].ordinal), done[1]}
        end
        raise ArgumentError.new("MSI cycle through #{node.kind}") if @active.includes?(id)
        raise ArgumentError.new("MSI kind is outside the identifier alphabet") unless IDENT.matches?(node.kind)
        expected = @schema[node.kind]? || raise ArgumentError.new("MSI kind #{node.kind} is not in the schema")
        raise ArgumentError.new("MSI fields for #{node.kind} differ from the schema") unless node.fields.map(&.name) == expected
        @active.add(id)
        entries = [] of JSON::Any
        max_child = 0
        node.fields.each do |field|
          entry, child_height = write_field(field, depth)
          entries << entry
          max_child = child_height if child_height > max_child
        end
        height = max_child + 1
        raise ArgumentError.new("MSI AST depth exceeds #{MAX_DEPTH}") if height > MAX_DEPTH + 1
        ref = emit("N", DiagnosticMsi.obj({
          "f" => DiagnosticMsi.arr(entries),
          "k" => DiagnosticMsi.str(node.kind),
          "t" => DiagnosticMsi.str("N"),
        }))
        @active.delete(id)
        @completed[id] = {ref, height}
        {ref, height}
      end

      private def write_field(field : Field, depth : Int32) : {JSON::Any, Int32}
        name = field.name
        raise ArgumentError.new("MSI field name is outside the identifier alphabet") unless IDENT.matches?(name)
        value = field.value
        case value.shape
        when Value::Shape::Absent
          {DiagnosticMsi.arr([DiagnosticMsi.str(name), DiagnosticMsi.str("a")]), 0}
        when Value::Shape::Flag
          {DiagnosticMsi.arr([DiagnosticMsi.str(name), DiagnosticMsi.str("b"), JSON::Any.new(value.flag)]), 0}
        when Value::Shape::Number
          raise ArgumentError.new("MSI integer is outside the safe range") if value.number.abs > MAX_SAFE_INTEGER
          {DiagnosticMsi.arr([DiagnosticMsi.str(name), DiagnosticMsi.str("i"), DiagnosticMsi.int(value.number)]), 0}
        when Value::Shape::Identifier
          raise ArgumentError.new("MSI identifier is outside the identifier alphabet") unless IDENT.matches?(value.text)
          {DiagnosticMsi.arr([DiagnosticMsi.str(name), DiagnosticMsi.str("t"), DiagnosticMsi.str(value.text)]), 0}
        when Value::Shape::Octets
          {DiagnosticMsi.arr([DiagnosticMsi.str(name), DiagnosticMsi.str("y"), write_value(value.bytes)]), 0}
        when Value::Shape::Child
          child = value.node || raise ArgumentError.new("MSI child value has no node")
          ref, height = write_node(child, depth + 1)
          {DiagnosticMsi.arr([DiagnosticMsi.str(name), DiagnosticMsi.str("e"), ref.json]), height}
        when Value::Shape::Children
          refs = [] of Ref
          max_height = 0
          value.nodes.each do |child|
            ref, height = write_node(child, depth + 1)
            refs << ref
            max_height = height if height > max_height
          end
          list, count = write_list(refs)
          {DiagnosticMsi.arr([DiagnosticMsi.str(name), DiagnosticMsi.str("l"), DiagnosticMsi.int(count), list.json]), max_height}
        when Value::Shape::Named
          items = [] of JSON::Any
          value.entries.each_with_index do |entry, position|
            bytes = entry.bytes || raise ArgumentError.new("MSI named entry has no value")
            charge(entry.key.size.to_i64)
            items << DiagnosticMsi.arr([DiagnosticMsi.int(position.to_i64), DiagnosticMsi.str(Base64.strict_encode(entry.key)), write_value(bytes)])
          end
          {DiagnosticMsi.arr([DiagnosticMsi.str(name), DiagnosticMsi.str("m"), DiagnosticMsi.arr(items)]), 0}
        when Value::Shape::Keyed
          raise ArgumentError.new("MSI keyed field exceeds the list fanout") if value.entries.size > LIST_FANOUT
          items = [] of JSON::Any
          max_height = 0
          value.entries.each_with_index do |entry, position|
            child = entry.node || raise ArgumentError.new("MSI keyed entry has no node")
            ref, height = write_node(child, depth + 1)
            charge(entry.key.size.to_i64)
            max_height = height if height > max_height
            items << DiagnosticMsi.arr([DiagnosticMsi.int(position.to_i64), DiagnosticMsi.str(Base64.strict_encode(entry.key)), ref.json])
          end
          {DiagnosticMsi.arr([DiagnosticMsi.str(name), DiagnosticMsi.str("M"), DiagnosticMsi.arr(items)]), max_height}
        else
          raise ArgumentError.new("MSI unknown field shape")
        end
      end

      # Inline text when small enough, otherwise a blob root. Evidence is charged
      # for the full value in both cases.
      private def write_value(bytes : Bytes) : JSON::Any
        charge(bytes.size.to_i64)
        return DiagnosticMsi.str(Base64.strict_encode(bytes)) if bytes.size <= INLINE_VALUE_BYTES
        write_blob(bytes).json
      end

      private def write_blob(bytes : Bytes) : Ref
        chunks = [] of Ref
        offset = 0
        while offset < bytes.size
          length = Math.min(BLOB_CHUNK_BYTES, bytes.size - offset)
          chunk = bytes[offset, length]
          chunks << emit("B", DiagnosticMsi.obj({
            "d" => DiagnosticMsi.str(Base64.strict_encode(chunk)),
            "t" => DiagnosticMsi.str("B"),
          }))
          offset += length
        end
        list, _count = write_list(chunks)
        emit("K", DiagnosticMsi.obj({
          "b" => DiagnosticMsi.int(bytes.size.to_i64),
          "l" => list.json,
          "t" => DiagnosticMsi.str("K"),
        }))
      end

      # Left-packed list tree. Levels hold at most LIST_FANOUT children and the
      # tree has at most LIST_MAX_LEVEL + 1 levels.
      private def write_list(elements : Array(Ref)) : {Ref, Int64}
        if elements.empty?
          return {emit("L", DiagnosticMsi.obj({
            "e" => DiagnosticMsi.arr([] of JSON::Any),
            "h" => DiagnosticMsi.int(0_i64),
            "n" => DiagnosticMsi.int(0_i64),
            "t" => DiagnosticMsi.str("L"),
          })), 0_i64}
        end
        current = elements
        counts = Array(Int64).new(elements.size, 1_i64)
        level = 0_i64
        loop do
          next_refs = [] of Ref
          next_counts = [] of Int64
          start = 0
          while start < current.size
            stop = Math.min(start + LIST_FANOUT, current.size)
            group = current[start...stop]
            total = 0_i64
            (start...stop).each { |position| total += counts[position] }
            next_refs << emit("L", DiagnosticMsi.obj({
              "e" => DiagnosticMsi.arr(group.map(&.json)),
              "h" => DiagnosticMsi.int(level),
              "n" => DiagnosticMsi.int(total),
              "t" => DiagnosticMsi.str("L"),
            }))
            next_counts << total
            start = stop
          end
          return {next_refs[0], next_counts[0]} if next_refs.size == 1
          raise ArgumentError.new("MSI list exceeds the tree depth") if level >= LIST_MAX_LEVEL
          current = next_refs
          counts = next_counts
          level += 1
        end
      end

      private def emit(type : String, record : JSON::Any) : Ref
        text = DiagnosticMsi.canonical(record)
        raise ArgumentError.new("MSI record exceeds #{RECORD_BYTES} bytes") if text.bytesize > RECORD_BYTES
        digest = DiagnosticMsi.digest("iyi.msi.v1.record\0#{type}\0", text.to_slice)
        if !@pending.empty? && @pending_bytes + text.bytesize + 1 + SHARD_OVERHEAD > SHARD_BYTES
          flush_shard
        end
        @pending_first = @ordinal if @pending.empty?
        @pending << text
        @pending_bytes += text.bytesize + 1
        ref = Ref.new(type, digest, @ordinal)
        @ordinal += 1
        ref
      end

      private def flush_shard : Nil
        return if @pending.empty?
        body = String.build do |io|
          io << "{\"f\":" << @pending_first << ",\"n\":" << @pending.size << ",\"r\":["
          @pending.each_with_index do |record, position|
            io << ',' unless position == 0
            io << record
          end
          io << "]}"
        end
        raise ArgumentError.new("MSI shard exceeds #{SHARD_BYTES} bytes") if body.bytesize > SHARD_BYTES
        digest = DiagnosticMsi.digest("iyi.msi.v1.shard\0", body.to_slice)
        @shards[digest] = body.to_slice
        @shard_table << ShardEntry.new(@pending_first, @pending.size.to_i64, digest, body.bytesize.to_i64)
        @pending = [] of String
        @pending_bytes = 0_i64
      end
    end

    # Per-record state kept while verifying one bundle.
    class Stored
      property type : String = ""
      property digest : String = ""
      property owners : Int32 = 0
      property height : Int32 = 0
      property level : Int64 = 0_i64
      property count : Int64 = 0_i64
      property leaves : String = ""
      property children : Array(Int64) = [] of Int64
      property chunk : Bytes = Bytes.empty
      property blob_bytes : Int64 = 0_i64
    end

    class Verifier
      def initialize(@root_bytes : Bytes, @shards : Hash(String, Bytes), @schema : Hash(String, Array(String)))
        @records = [] of Stored
        @json = [] of Hash(String, JSON::Any)
        @evidence = 0_i64
      end

      def run : Verified
        raise ArgumentError.new("MSI root manifest exceeds the shard limit") if @root_bytes.size > SHARD_BYTES
        root = DiagnosticMsi.object_of(DiagnosticMsi.parse_canonical(String.new(@root_bytes), "root manifest"), "root manifest")
        DiagnosticMsi.keys_exactly!(root, %w(count envelope input key root schema schema_digest shards tag tool), "root manifest")
        raise ArgumentError.new("MSI schema identifier differs") unless DiagnosticMsi.text_of(root["schema"], "schema") == SCHEMA_ID
        raise ArgumentError.new("MSI schema table differs") unless DiagnosticMsi.text_of(root["schema_digest"], "schema digest") == DiagnosticMsi.schema_digest(@schema)
        count = DiagnosticMsi.int_of(root["count"], "count")
        tag = DiagnosticMsi.text_of(root["tag"], "tag")
        raise ArgumentError.new("MSI tag is outside the identifier alphabet") unless IDENT.matches?(tag)
        tool = DiagnosticMsi.text_of(root["tool"], "tool")
        raise ArgumentError.new("MSI tool digest is not lowercase hex") unless HEX.matches?(tool)
        envelope_text = DiagnosticMsi.canonical(root["envelope"])
        input = DiagnosticMsi.object_of(root["input"], "input")
        DiagnosticMsi.keys_exactly!(input, %w(blob bytes sha256), "input")
        input_bytes = DiagnosticMsi.int_of(input["bytes"], "input size")
        input_sha = DiagnosticMsi.text_of(input["sha256"], "input digest")
        raise ArgumentError.new("MSI capture key differs") unless DiagnosticMsi.text_of(root["key"], "key") == DiagnosticMsi.capture_key(tag, envelope_text, input_sha, input_bytes)

        table = DiagnosticMsi.items_of(root["shards"], "shard table")
        raise ArgumentError.new("MSI shard table does not match the shard set") unless table.size == @shards.size
        seen = Set(String).new
        first = 0_i64
        table.each do |row|
          items = DiagnosticMsi.items_of(row, "shard row")
          raise ArgumentError.new("MSI shard row arity") unless items.size == 4
          row_first = DiagnosticMsi.int_of(items[0], "shard first")
          row_count = DiagnosticMsi.int_of(items[1], "shard count")
          row_digest = DiagnosticMsi.text_of(items[2], "shard digest")
          row_size = DiagnosticMsi.int_of(items[3], "shard size")
          raise ArgumentError.new("MSI shard table is not contiguous") unless row_first == first && row_count > 0
          raise ArgumentError.new("MSI shard digest is not lowercase hex") unless HEX.matches?(row_digest)
          raise ArgumentError.new("MSI shard #{row_digest} is repeated") unless seen.add?(row_digest)
          bytes = @shards[row_digest]? || raise ArgumentError.new("MSI shard #{row_digest} is missing")
          raise ArgumentError.new("MSI shard size differs") unless bytes.size.to_i64 == row_size
          raise ArgumentError.new("MSI shard exceeds the shard limit") if bytes.size > SHARD_BYTES
          raise ArgumentError.new("MSI shard digest differs") unless DiagnosticMsi.digest("iyi.msi.v1.shard\0", bytes) == row_digest
          load_shard(bytes, row_first, row_count)
          first += row_count
        end
        raise ArgumentError.new("MSI record count differs") unless first == count && @records.size.to_i64 == count

        @records.size.times do |index|
          check_record(index.to_i64, @json[index])
        end

        input_tag, input_ordinal = resolve(input["blob"], count, ["K"])
        own(input_ordinal)
        blob = @records[input_ordinal.to_i]
        raise ArgumentError.new("MSI input size differs") unless blob.blob_bytes == input_bytes
        data = assemble(blob)
        raise ArgumentError.new("MSI input length differs") unless data.size.to_i64 == input_bytes
        raise ArgumentError.new("MSI input digest differs") unless DiagnosticMsi.sha256_hex(data) == input_sha

        _root_tag, root_ordinal = resolve(root["root"], count, ["N"])
        raise ArgumentError.new("MSI root must be the final record") unless root_ordinal == count - 1
        own(root_ordinal)

        @records.each do |stored|
          raise ArgumentError.new("MSI record is unreferenced or referenced twice") unless stored.owners == 1
        end
        nodes = @records.count { |stored| stored.type == "N" }
        Verified.new(data, count, nodes.to_i64, table.size, DiagnosticMsi.digest("iyi.msi.v1.root\0", @root_bytes))
      end

      private def load_shard(bytes : Bytes, first : Int64, count : Int64) : Nil
        shard = DiagnosticMsi.object_of(DiagnosticMsi.parse_canonical(String.new(bytes), "shard"), "shard")
        DiagnosticMsi.keys_exactly!(shard, %w(f n r), "shard")
        raise ArgumentError.new("MSI shard range differs") unless DiagnosticMsi.int_of(shard["f"], "shard first") == first
        raise ArgumentError.new("MSI shard count differs") unless DiagnosticMsi.int_of(shard["n"], "shard count") == count
        records = DiagnosticMsi.items_of(shard["r"], "shard records")
        raise ArgumentError.new("MSI shard record count differs") unless records.size.to_i64 == count
        records.each do |item|
          record = DiagnosticMsi.object_of(item, "record")
          type = DiagnosticMsi.text_of(record["t"]? || raise(ArgumentError.new("MSI record has no type")), "record type")
          raise ArgumentError.new("MSI record type #{type} is unknown") unless RECORD_TYPES.includes?(type)
          text = DiagnosticMsi.canonical(item)
          raise ArgumentError.new("MSI record exceeds #{RECORD_BYTES} bytes") if text.bytesize > RECORD_BYTES
          stored = Stored.new
          stored.type = type
          stored.digest = DiagnosticMsi.digest("iyi.msi.v1.record\0#{type}\0", text.to_slice)
          @records << stored
          @json << record
        end
      end

      private def check_record(index : Int64, record : Hash(String, JSON::Any)) : Nil
        case DiagnosticMsi.text_of(record["t"], "record type")
        when "B" then check_chunk(index, record)
        when "L" then check_list(index, record)
        when "K" then check_blob(index, record)
        when "N" then check_node(index, record)
        else         raise ArgumentError.new("MSI record type is unknown")
        end
      end

      private def check_chunk(index : Int64, record : Hash(String, JSON::Any)) : Nil
        DiagnosticMsi.keys_exactly!(record, %w(d t), "chunk")
        data = DiagnosticMsi.decode64(DiagnosticMsi.text_of(record["d"], "chunk"), "chunk")
        raise ArgumentError.new("MSI chunk size is outside the chunk limit") if data.empty? || data.size > BLOB_CHUNK_BYTES
        @records[index.to_i].chunk = data
      end

      private def check_list(index : Int64, record : Hash(String, JSON::Any)) : Nil
        DiagnosticMsi.keys_exactly!(record, %w(e h n t), "list")
        level = DiagnosticMsi.int_of(record["h"], "list level")
        raise ArgumentError.new("MSI list level is out of range") unless level >= 0 && level <= LIST_MAX_LEVEL
        total = DiagnosticMsi.int_of(record["n"], "list count")
        elements = DiagnosticMsi.items_of(record["e"], "list elements")
        raise ArgumentError.new("MSI list exceeds the fanout") if elements.size > LIST_FANOUT
        stored = @records[index.to_i]
        stored.level = level
        if level == 0
          if elements.empty?
            raise ArgumentError.new("MSI empty list must count zero") unless total == 0
            stored.leaves = "EMPTY"
          else
            leaf_class = peek_tag(elements[0]) == "B" ? "B" : "N"
            allowed = leaf_class == "B" ? ["B"] : ["N", "A"]
            previous = -1_i64
            elements.each do |element|
              element_tag, ordinal = resolve(element, index, allowed)
              if element_tag != "A"
                raise ArgumentError.new("MSI list elements are out of emission order") unless ordinal > previous
                previous = ordinal
              end
              claim(element_tag, ordinal)
              stored.children << ordinal
            end
            raise ArgumentError.new("MSI leaf count differs") unless total == elements.size
            stored.leaves = leaf_class
          end
        else
          leaf_class = ""
          sum = 0_i64
          previous = -1_i64
          elements.each do |element|
            _tag, ordinal = resolve(element, index, ["L"])
            raise ArgumentError.new("MSI list elements are out of emission order") unless ordinal > previous
            previous = ordinal
            child = @records[ordinal.to_i]
            raise ArgumentError.new("MSI list child has the wrong level") unless child.level == level - 1
            leaf_class = child.leaves if leaf_class.empty?
            raise ArgumentError.new("MSI list children disagree on leaves") unless child.leaves == leaf_class && leaf_class != "EMPTY"
            own(ordinal)
            sum += child.count
            stored.children << ordinal
          end
          raise ArgumentError.new("MSI interior count differs") unless total == sum
          stored.leaves = leaf_class
        end
        stored.count = total
      end

      private def check_blob(index : Int64, record : Hash(String, JSON::Any)) : Nil
        DiagnosticMsi.keys_exactly!(record, %w(b l t), "blob")
        total = DiagnosticMsi.int_of(record["b"], "blob size")
        raise ArgumentError.new("MSI blob size is out of range") if total < 0 || total > MAX_INPUT_BYTES
        list_tag, list = resolve(record["l"], index, ["L"])
        claim(list_tag, list)
        list_stored = @records[list.to_i]
        raise ArgumentError.new("MSI blob list holds non-chunk leaves") unless list_stored.leaves == "B" || (list_stored.leaves == "EMPTY" && total == 0)
        expected_chunks = (total + BLOB_CHUNK_BYTES - 1).tdiv(BLOB_CHUNK_BYTES)
        raise ArgumentError.new("MSI blob chunk count differs") unless list_stored.count == expected_chunks
        leaves = [] of Int64
        walk_tree(list, leaves)
        sum = 0_i64
        leaves.each_with_index do |chunk_ordinal, position|
          length = @records[chunk_ordinal.to_i].chunk.size.to_i64
          raise ArgumentError.new("MSI blob chunk is not full size") if position < leaves.size - 1 && length != BLOB_CHUNK_BYTES.to_i64
          sum += length
        end
        raise ArgumentError.new("MSI blob length differs") unless sum == total
        stored = @records[index.to_i]
        stored.blob_bytes = total
        stored.children = leaves
      end

      private def check_node(index : Int64, record : Hash(String, JSON::Any)) : Nil
        DiagnosticMsi.keys_exactly!(record, %w(f k t), "node")
        kind = DiagnosticMsi.text_of(record["k"], "kind")
        raise ArgumentError.new("MSI kind is outside the identifier alphabet") unless IDENT.matches?(kind)
        expected = @schema[kind]? || raise ArgumentError.new("MSI kind #{kind} is not in the schema")
        fields = DiagnosticMsi.items_of(record["f"], "fields")
        raise ArgumentError.new("MSI fields differ from the schema for #{kind}") unless fields.size == expected.size
        child_height = 0
        fields.each_with_index do |field, position|
          entry = DiagnosticMsi.items_of(field, "field entry")
          raise ArgumentError.new("MSI field entry has no shape") if entry.size < 2
          name = DiagnosticMsi.text_of(entry[0], "field name")
          raise ArgumentError.new("MSI field #{name} is out of schema order") unless name == expected[position]
          height = check_field(index, DiagnosticMsi.text_of(entry[1], "field shape"), entry)
          child_height = height if height > child_height
        end
        stored = @records[index.to_i]
        stored.height = child_height + 1
        raise ArgumentError.new("MSI AST depth exceeds #{MAX_DEPTH}") if stored.height > MAX_DEPTH + 1
      end

      # Returns the greatest child height this field contributes.
      private def check_field(index : Int64, shape : String, entry : Array(JSON::Any)) : Int32
        case shape
        when "a"
          expect_size(entry, 2)
          0
        when "b"
          expect_size(entry, 3)
          raise ArgumentError.new("MSI flag is not a boolean") if entry[2].as_bool?.nil?
          0
        when "i"
          expect_size(entry, 3)
          number = DiagnosticMsi.int_of(entry[2], "number")
          raise ArgumentError.new("MSI number is outside the safe range") if number.abs > MAX_SAFE_INTEGER
          0
        when "t"
          expect_size(entry, 3)
          raise ArgumentError.new("MSI identifier is outside the identifier alphabet") unless IDENT.matches?(DiagnosticMsi.text_of(entry[2], "identifier"))
          0
        when "y"
          expect_size(entry, 3)
          check_value(index, entry[2])
          0
        when "e"
          expect_size(entry, 3)
          child_tag, child = resolve(entry[2], index, ["N", "A"])
          claim(child_tag, child)
          @records[child.to_i].height
        when "l"
          expect_size(entry, 4)
          count = DiagnosticMsi.int_of(entry[2], "list count")
          list_tag, list = resolve(entry[3], index, ["L"])
          claim(list_tag, list)
          list_stored = @records[list.to_i]
          raise ArgumentError.new("MSI child list holds non-node leaves") unless list_stored.leaves == "N" || list_stored.leaves == "EMPTY"
          raise ArgumentError.new("MSI child list count differs") unless list_stored.count == count
          leaves = [] of Int64
          walk_tree(list, leaves)
          max_height = 0
          leaves.each do |leaf|
            leaf_height = @records[leaf.to_i].height
            max_height = leaf_height if leaf_height > max_height
          end
          max_height
        when "m"
          expect_size(entry, 3)
          named = DiagnosticMsi.items_of(entry[2], "named entries")
          named.each_with_index do |item, position|
            parts = DiagnosticMsi.items_of(item, "named entry")
            raise ArgumentError.new("MSI named entry arity") unless parts.size == 3
            raise ArgumentError.new("MSI named entry index differs") unless DiagnosticMsi.int_of(parts[0], "entry index") == position
            key = DiagnosticMsi.decode64(DiagnosticMsi.text_of(parts[1], "entry key"), "entry key")
            charge(key.size.to_i64)
            check_value(index, parts[2])
          end
          0
        when "M"
          expect_size(entry, 3)
          keyed = DiagnosticMsi.items_of(entry[2], "keyed entries")
          raise ArgumentError.new("MSI keyed field exceeds the fanout") if keyed.size > LIST_FANOUT
          max_height = 0
          keyed.each_with_index do |item, position|
            parts = DiagnosticMsi.items_of(item, "keyed entry")
            raise ArgumentError.new("MSI keyed entry arity") unless parts.size == 3
            raise ArgumentError.new("MSI keyed entry index differs") unless DiagnosticMsi.int_of(parts[0], "entry index") == position
            key = DiagnosticMsi.decode64(DiagnosticMsi.text_of(parts[1], "entry key"), "entry key")
            charge(key.size.to_i64)
            keyed_tag, keyed_ordinal = resolve(parts[2], index, ["N", "A"])
            claim(keyed_tag, keyed_ordinal)
            keyed_height = @records[keyed_ordinal.to_i].height
            max_height = keyed_height if keyed_height > max_height
          end
          max_height
        else
          raise ArgumentError.new("MSI unknown field shape")
        end
      end

      private def check_value(index : Int64, value : JSON::Any) : Nil
        if text = value.as_s?
          data = DiagnosticMsi.decode64(text, "inline value")
          raise ArgumentError.new("MSI inline value exceeds the inline limit") if data.size > INLINE_VALUE_BYTES
          charge(data.size.to_i64)
        else
          blob_tag, blob_ordinal = resolve(value, index, ["K"])
          claim(blob_tag, blob_ordinal)
          blob = @records[blob_ordinal.to_i]
          raise ArgumentError.new("MSI blob value fits the inline limit") unless blob.blob_bytes > INLINE_VALUE_BYTES
          charge(blob.blob_bytes)
        end
      end

      private def charge(bytes : Int64) : Nil
        @evidence += bytes
        raise ArgumentError.new("MSI evidence exceeds #{EVIDENCE_BYTES} unfolded bytes") if @evidence > EVIDENCE_BYTES
      end

      private def expect_size(entry : Array(JSON::Any), size : Int32) : Nil
        raise ArgumentError.new("MSI field entry arity differs") unless entry.size == size
      end

      private def peek_tag(value : JSON::Any) : String
        items = DiagnosticMsi.items_of(value, "reference")
        raise ArgumentError.new("MSI reference arity differs") unless items.size == 3
        DiagnosticMsi.text_of(items[0], "reference tag")
      end

      # Validates a reference against earlier records only and returns {tag, ordinal}.
      private def resolve(value : JSON::Any, limit : Int64, allowed : Array(String)) : {String, Int64}
        items = DiagnosticMsi.items_of(value, "reference")
        raise ArgumentError.new("MSI reference arity differs") unless items.size == 3
        ref_tag = DiagnosticMsi.text_of(items[0], "reference tag")
        digest = DiagnosticMsi.text_of(items[1], "reference digest")
        ordinal = DiagnosticMsi.int_of(items[2], "reference ordinal")
        raise ArgumentError.new("MSI reference tag #{ref_tag} is not allowed here") unless allowed.includes?(ref_tag)
        raise ArgumentError.new("MSI reference digest is not lowercase hex") unless HEX.matches?(digest)
        raise ArgumentError.new("MSI reference is not a backward reference") unless ordinal >= 0 && ordinal < limit
        stored = @records[ordinal.to_i]
        expected_type = ref_tag == "A" ? "N" : ref_tag
        raise ArgumentError.new("MSI reference names the wrong record type") unless stored.type == expected_type
        raise ArgumentError.new("MSI reference digest differs from its record") unless stored.digest == digest
        {ref_tag, ordinal}
      end

      private def claim(ref_tag : String, ordinal : Int64) : Nil
        own(ordinal) unless ref_tag == "A"
      end

      private def own(ordinal : Int64) : Nil
        stored = @records[ordinal.to_i]
        stored.owners += 1
        raise ArgumentError.new("MSI record #{ordinal} has more than one owner") if stored.owners > 1
      end

      # Checks that a list tree is left-packed: every non-last child holds the full
      # capacity of its level. Appends the leaf ordinals in order.
      private def walk_tree(ordinal : Int64, leaves : Array(Int64)) : Nil
        stored = @records[ordinal.to_i]
        if stored.level == 0
          leaves.concat(stored.children)
        else
          last = stored.children.size - 1
          stored.children.each_with_index do |child_ordinal, position|
            if position < last
              raise ArgumentError.new("MSI list is not left-packed") unless @records[child_ordinal.to_i].count == capacity(stored.level)
            end
            walk_tree(child_ordinal, leaves)
          end
        end
      end

      private def capacity(level : Int64) : Int64
        result = 1_i64
        level.times { result *= LIST_FANOUT }
        result
      end

      private def assemble(stored : Stored) : Bytes
        io = IO::Memory.new
        stored.children.each do |ordinal|
          io.write(@records[ordinal.to_i].chunk)
        end
        io.to_slice
      end
    end
  end
end
