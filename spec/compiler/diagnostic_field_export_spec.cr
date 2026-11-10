require "../support/syntax"
require "../../src/compiler/iyi/syntax/diagnostic_field_export"

describe Iyi::DiagnosticFieldExport do
  it "exports actual field types, ordering, and unknown type-expression status" do
    document = Iyi::DiagnosticFieldExport.document
    parsed = JSON.parse(document)
    parsed["schema"].as_s.should eq("iyi-field-schema/1")
    kinds = parsed["kinds"].as_h
    kinds.keys.should eq(kinds.keys.sort)
    rows = kinds["Call"].as_a
    rows.map { |row| row["field"].as_s }.should eq(Iyi::DiagnosticFieldTable::TABLE["Call"].map(&.field))
    name = rows.find { |row| row["field"].as_s == "name" }.not_nil!
    name["role"].as_s.should eq("Name")
    name["nilable"].as_bool.should be_false
    name["type_expression"].raw.should be_nil
    Iyi::DiagnosticFieldExport.digest.should eq(::Crystal::Digest::SHA256.hexdigest(document))
  end

  it "refuses a missing kind rather than exporting an incomplete table" do
    incomplete = Iyi::DiagnosticFieldTable::TABLE.dup
    incomplete.delete("Call")
    expect_raises(ArgumentError, /lacks kinds: Call/) do
      Iyi::DiagnosticFieldExport.document(incomplete)
    end
  end
end
