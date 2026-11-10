require "./diagnostic_field_table"

module Iyi
  # Raw semantic state must be inert before an AST enters a capture census.
  # This checker does not itself establish capture authority.
  module DiagnosticSemanticDefaults
    def self.reflected_fields(kind : String) : Array(String)
      {% begin %}
      case kind
      {% for sub in Iyi::ASTNode.all_subclasses %}
        {% unless sub.abstract? %}
        when {{sub.name.split("::").last}}
          [{% for ivar in sub.instance_vars %}{{ivar.name.stringify}}, {% end %}] of String
        {% end %}
      {% end %}
      else
        raise ArgumentError.new("unclassified AST kind #{kind}")
      end
      {% end %}
    end

    def self.verify_coverage!(table = DiagnosticFieldTable::TABLE) : Nil
      pairs = DiagnosticAstFieldSchema.census_pairs
      missing = DiagnosticFieldTable.uncovered(table, pairs, DiagnosticFieldTable::Scope::Full)
      extra = DiagnosticFieldTable.unlisted(table, pairs, DiagnosticFieldTable::Scope::Full)
      unless missing.empty? && extra.empty?
        raise ArgumentError.new("semantic field coverage differs: uncovered=#{missing.join(",")} unlisted=#{extra.join(",")}")
      end
    end

    # Only actual inert raw values are accepted. The reflected type, rather
    # than initializer metadata, is used because the latter can disappear when
    # a class is reached through an ASTNode dispatch.
    private def self.check_concrete!(node : T, selected : String?, table : Hash(String, Array(DiagnosticFieldTable::Row))) : Nil forall T
      kind = {{T.name.split("::").last}}
      rows = table[kind]? || raise ArgumentError.new("#{kind}: no field table")
      if selected && !rows.any? { |row| row.field == selected && row.provenance.semantic? }
        raise ArgumentError.new("#{kind}.#{selected}: not a declared semantic field")
      end
      {% for ivar in T.instance_vars %}
        if (!selected || selected == {{ivar.name.stringify}}) && rows.any? { |row| row.field == {{ivar.name.stringify}} && row.provenance.semantic? }
          {% if ivar.type.nilable? %}
            raise ArgumentError.new("#{kind}.#{{{ivar.name.stringify}}}: raw value is not nil") unless node.@{{ivar.name.id}}.nil?
          {% elsif ivar.type == Bool %}
            raise ArgumentError.new("#{kind}.#{{{ivar.name.stringify}}}: raw value differs from its inert state") if node.@{{ivar.name.id}}
          {% elsif ivar.type == Int32 %}
            raise ArgumentError.new("#{kind}.#{{{ivar.name.stringify}}}: raw value differs from its inert state") unless node.@{{ivar.name.id}} == 0
          {% elsif ivar.type.stringify == "Iyi::SmallNodeList" %}
            value = node.@{{ivar.name.id}}
            unless value.@first.nil? && value.@second.nil? && value.@tail.nil?
              raise ArgumentError.new("#{kind}.#{{{ivar.name.stringify}}}: raw list is not empty")
            end
          {% else %}
            raise ArgumentError.new("#{kind}.#{{{ivar.name.stringify}}}: unclassified semantic field type")
          {% end %}
        end
      {% end %}
      nil
    end

    private def self.verify_selected!(node : ASTNode, selected : String?, table : Hash(String, Array(DiagnosticFieldTable::Row))) : Nil
      {% begin %}
      case node
      {% for name in DiagnosticAstFieldSchema::SUPPORTED %}
      when {{name.id}}
        check_concrete!(node.as({{name.id}}), selected, table)
      {% end %}
      else
        raise ArgumentError.new("unclassified AST node #{node.class}")
      end
      {% end %}
      nil
    end

    def self.check_field!(node : ASTNode, field : String, table = DiagnosticFieldTable::TABLE) : Nil
      verify_selected!(node, field, table)
    end

    def self.verify!(node : ASTNode, table = DiagnosticFieldTable::TABLE) : Nil
      verify_selected!(node, nil, table)
    end

    def self.verify_tree!(root : ASTNode, table = DiagnosticFieldTable::TABLE) : Nil
      verify_coverage!(table)
      active = Set(UInt64).new
      completed = Set(UInt64).new
      verify_visit!(root, table, active, completed, 0)
    end

    private def self.verify_visit!(node : ASTNode, table : Hash(String, Array(DiagnosticFieldTable::Row)), active : Set(UInt64), completed : Set(UInt64), depth : Int32) : Nil
      raise ArgumentError.new("semantic state exceeds depth limit") if depth > DiagnosticAstFrameStream::MAX_DEPTH
      id = node.object_id
      raise ArgumentError.new("cyclic semantic state tree") if active.includes?(id)
      return if completed.includes?(id)
      active.add(id)
      verify!(node, table)
      DiagnosticDirectChildFields.each(node) { |_field, _index, _key, child| verify_visit!(child, table, active, completed, depth + 1) }
      active.delete(id)
      completed.add(id)
      nil
    end
  end
end
