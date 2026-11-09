require "./diagnostic_provenance"
require "llvm"

module Iyi::DiagnosticProvenance
  # A definition can be the result of replacing several pre-optimization
  # definitions. Preserve all of their identities, including non-closures.
  class ObservedDefinition
    getter llvm_symbol : String
    getter linkage : String
    getter emissions : Array(Emission)
    property? unresolved_nonclosure : Bool

    def initialize(@llvm_symbol, @linkage, @emissions = [] of Emission, @unresolved_nonclosure = false)
    end
  end

  # Install after partition materialization and bitcode-cache generation. The
  # caller owns the module through finish and must not use this observation for
  # a previously cached native object. No instruction, linkage, or retention
  # attribute is changed.
  class Observer
    METADATA_NAME = "iyi.diagnostic.provenance.observer"

    @originals : Array(Array(Emission)?)

    def initialize(@mod : LLVM::Module, closures : Hash(String, Array(Emission)))
      @originals = [] of Array(Emission)?
      raise "diagnostic observer metadata already exists" unless LibLLVM.get_named_metadata_num_operands(@mod, METADATA_NAME) == 0
      seen = Set(String).new
      ctx = @mod.context
      @mod.functions.each do |fun|
        next if LibLLVM.is_declaration(fun) != 0
        name = fun.name
        raise "unnamed or duplicate LLVM definition" if name.empty? || !seen.add?(name)
        records = closures[name]?
        raise "empty closure observation set" if records && records.empty?
        records.try &.each { |record| DiagnosticProvenance.validate_emission!(record) }
        id = @originals.size.to_s
        @originals << records
        id_md = LibLLVM.md_string_in_context2(ctx, id, id.bytesize).as(LibLLVM::MetadataRef)
        fun_md = LibLLVM.value_as_metadata(fun.to_unsafe)
        operands = StaticArray[id_md, fun_md]
        node = LibLLVM.md_node_in_context2(ctx, operands.to_unsafe.as(LibLLVM::ValueRef*), 2).as(LibLLVM::MetadataRef)
        value = LibLLVM.metadata_as_value(ctx, node)
        LibLLVM.add_named_metadata_operand(@mod, METADATA_NAME, value)
      end
      closures.each_key do |name|
        raise "closure has no materialized LLVM definition: #{name}" unless seen.includes?(name)
      end
    end

    def finish : Array(ObservedDefinition)
      count = LibLLVM.get_named_metadata_num_operands(@mod, METADATA_NAME).to_i
      raise "diagnostic observer metadata lost entries" unless count == @originals.size
      nodes = Array(LibLLVM::ValueRef).new(count, Pointer(Void).null.as(LibLLVM::ValueRef))
      LibLLVM.get_named_metadata_operands(@mod, METADATA_NAME, nodes.to_unsafe) if count > 0
      found = Set(Int32).new
      by_value = {} of LibLLVM::ValueRef => ObservedDefinition
      nodes.each do |node|
        raise "invalid diagnostic observer node" unless LibLLVM.get_md_node_num_operands(node) == 2
        operands = StaticArray(LibLLVM::ValueRef, 2).new(Pointer(Void).null.as(LibLLVM::ValueRef))
        LibLLVM.get_md_node_operands(node, operands.to_unsafe)
        raise "invalid diagnostic observer ID" if operands[0].null?
        id_ptr = LibLLVM.get_md_string(operands[0], out id_length)
        raise "invalid diagnostic observer ID" if id_ptr.null?
        text = String.new(id_ptr, id_length)
        id = text.to_i32?
        raise "invalid diagnostic observer ID" unless id && id >= 0 && id < @originals.size && id.to_s == text && found.add?(id)
        value = operands[1]
        # Deletion clears a metadata operand. A non-function replacement is
        # unresolved rather than evidence of correspondence.
        next if value.null?
        raise "unsupported diagnostic observer replacement" if LibLLVM.is_a_function(value).null?
        fun = LLVM::Function.new(value)
        next if LibLLVM.is_declaration(fun) != 0
        definition = by_value[value] ||= ObservedDefinition.new(fun.name, fun.linkage.to_s)
        if originals = @originals[id]
          definition.emissions.concat(originals)
        else
          definition.unresolved_nonclosure = true
        end
      end
      raise "diagnostic observer IDs are incomplete" unless found.size == @originals.size
      @mod.functions.each do |fun|
        next if LibLLVM.is_declaration(fun) != 0
        by_value[fun.to_unsafe] ||= ObservedDefinition.new(fun.name, fun.linkage.to_s, unresolved_nonclosure: true)
      end
      by_value.values
    end
  end
end
