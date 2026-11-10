require "json"

module Iyi
  # A coordinate in one accepted parser input, not an assertion that the
  # coordinate resolves. Only the frozen capture registry can establish that.
  class DiagnosticCaptureFieldRef
    getter capture_id : String
    getter owner_path_json : String
    getter field_tag : String
    getter index : Int32?
    getter map_key : String?

    def initialize(@capture_id : String, @owner_path_json : String, @field_tag : String,
                   @index : Int32? = nil, @map_key : String? = nil)
      unless @capture_id.bytesize == 64 && @capture_id.each_byte.all? { |b| (48_u8..57_u8).includes?(b) || (97_u8..102_u8).includes?(b) }
        raise ArgumentError.new("invalid capture input identity")
      end
      raise ArgumentError.new("empty capture field tag") if @field_tag.empty?
      raise ArgumentError.new("invalid capture field index") if @index.try { |i| i < 0 }
      raise ArgumentError.new("ambiguous capture field coordinate") if @index && @map_key
      raise ArgumentError.new("invalid capture owner path") unless JSON.parse(@owner_path_json).as_a?
    end

    def_equals_and_hash @capture_id, @owner_path_json, @field_tag, @index, @map_key
  end
end
