require "./diagnostic_field_table"
require "json"
require "crystal/digest/sha256"

module Iyi
  # Deterministic export of the actual field table. Unknown type-expression
  # classification remains null; this document is not an authority index.
  module DiagnosticFieldExport
    SCHEMA = "iyi-field-schema/1"

    def self.document(table = DiagnosticFieldTable::TABLE) : String
      DiagnosticFieldTable.verify!(table)
      String.build do |io|
        JSON.build(io) do |json|
          json.object do
            json.field "kinds" do
              json.object do
                table.keys.sort.each do |kind|
                  json.field kind do
                    json.array do
                      table[kind].each do |row|
                        json.object do
                          json.field "base", row.base
                          json.field "coordinate", row.coordinate.to_s
                          json.field "field", row.field
                          json.field "klass", row.klass.to_s
                          json.field "nilable", row.nilable
                          json.field "presence", row.presence.try(&.to_s)
                          json.field "provenance", row.provenance.to_s
                          json.field "role", row.role.to_s
                          json.field "scalar", row.scalar
                          json.field "type_expression", nil
                        end
                      end
                    end
                  end
                end
              end
            end
            json.field "schema", SCHEMA
          end
        end
      end
    end

    def self.digest(table = DiagnosticFieldTable::TABLE) : String
      ::Crystal::Digest::SHA256.hexdigest(document(table))
    end
  end
end
