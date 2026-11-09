require "json"
require "set"

module Iyi::DiagnosticType
  # A diagnostic identity is available only for representations handled here.
  # There is deliberately no Type#to_s fallback for an unknown kind.
  def self.identity(type : Iyi::Type) : JSON::Any?
    identity(type, Set(UInt64).new)
  end

  private def self.identity(type : Iyi::Type, visiting : Set(UInt64)) : JSON::Any?
    id = type.object_id
    return nil unless visiting.add?(id)
    begin
      fields = {} of String => JSON::Any
      fields["kind"] = JSON::Any.new(type.class.name)
      case type
      when Iyi::Program
        # The global program is a single scope in a compilation.
        nil
      when Iyi::NilType, Iyi::VoidType, Iyi::BoolType, Iyi::CharType,
           Iyi::IntegerType, Iyi::FloatType, Iyi::SymbolType, Iyi::NoReturnType, Iyi::PrimitiveType
        fields["name"] = JSON::Any.new(type.name)
      when Iyi::UnionType
        members = [] of JSON::Any
        type.union_types.each do |member|
          item = identity(member, visiting) || return nil
          members << item
        end
        members.sort_by!(&.to_json)
        fields["members"] = JSON::Any.new(members)
      when Iyi::VirtualType
        fields["base"] = identity(type.base_type, visiting) || return nil
      when Iyi::MetaclassType, Iyi::VirtualMetaclassType, Iyi::GenericClassInstanceMetaclassType, Iyi::GenericModuleInstanceMetaclassType
        fields["instance"] = identity(type.instance_type, visiting) || return nil
      when Iyi::TupleInstanceType
        elements = [] of JSON::Any
        type.tuple_types.each do |element|
          elements << (identity(element, visiting) || return nil)
        end
        fields["elements"] = JSON::Any.new(elements)
      when Iyi::NamedTupleInstanceType
        entries = [] of JSON::Any
        type.entries.each do |entry|
          entry_type = identity(entry.type, visiting) || return nil
          entries << JSON::Any.new({"name" => JSON::Any.new(entry.name), "type" => entry_type})
        end
        fields["entries"] = JSON::Any.new(entries)
      when Iyi::ProcInstanceType
        args = [] of JSON::Any
        type.arg_types.each do |arg|
          args << (identity(arg, visiting) || return nil)
        end
        fields["arguments"] = JSON::Any.new(args)
        fields["return"] = identity(type.return_type, visiting) || return nil
      when Iyi::StaticArrayInstanceType
        size = type.size
        return nil unless size.is_a?(Iyi::NumberLiteral)
        fields["element"] = identity(type.element_type, visiting) || return nil
        fields["size_kind"] = JSON::Any.new(size.kind.to_s)
        fields["size_value"] = JSON::Any.new(size.value)
      when Iyi::PointerInstanceType
        fields["element"] = identity(type.element_type, visiting) || return nil
      when Iyi::GenericClassInstanceType, Iyi::GenericModuleInstanceType
        fields["owner"] = JSON::Any.new(type.generic_type.full_name)
        variables = [] of JSON::Any
        type.type_vars.to_a.sort_by!(&.[0]).each do |name, variable|
          return nil unless variable.is_a?(Iyi::Var)
          value = variable.type?
          return nil unless value
          value_identity = identity(value, visiting) || return nil
          variables << JSON::Any.new({"name" => JSON::Any.new(name), "type" => value_identity})
        end
        fields["parameters"] = JSON::Any.new(variables)
      when Iyi::TypeDefType
        fields["name"] = JSON::Any.new(type.name)
        fields["target"] = identity(type.typedef, visiting) || return nil
      when Iyi::AliasType, Iyi::ClassType, Iyi::ModuleType, Iyi::EnumType
        name = type.full_name
        return nil if name.empty?
        fields["name"] = JSON::Any.new(name)
      else
        return nil
      end
      JSON::Any.new(fields)
    ensure
      visiting.delete(id)
    end
  end
end
