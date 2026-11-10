require "../support/syntax"

# Snapshot helpers. They read a real node through the same writers the
# snapshot uses, so the table is checked against what capture actually emits.
module DiagnosticFieldTableSpec
  alias Presences = Array({String, Iyi::DiagnosticFieldPresence})
  alias Scalars = Array({String, String, Iyi::DiagnosticScalarShape})
  alias Stubs = Array({String, Int32?, String?})

  def self.kind_of(node : Iyi::ASTNode) : String
    node.class.name.rpartition("::")[2]
  end

  def self.snapshot(node : Iyi::ASTNode)
    presences = Presences.new
    Iyi::DiagnosticDirectPresenceFields.each(node) { |field, state| presences << {field, state} }

    scalars = Scalars.new
    Iyi::DiagnosticDirectScalarFields.each(node) { |field, tag, value| scalars << {field, tag, value.shape} }

    children = Stubs.new
    child_kinds = [] of String
    Iyi::DiagnosticDirectChildFields.each(node) do |field, index, key, child|
      children << {field, index, key}
      child_kinds << kind_of(child)
    end

    names = Stubs.new
    Iyi::DiagnosticDirectNameFields.each(node) { |field, index, key, _value| names << {field, index, key} }

    {presences, scalars, children, names, child_kinds}
  end

  def self.check(node : Iyi::ASTNode) : Nil
    presences, scalars, children, names, child_kinds = snapshot(node)
    Iyi::DiagnosticFieldTable.check_node!(kind_of(node), presences, scalars, children, names, child_kinds)
  end

  # A copy of a row with its provenance changed.
  def self.with_provenance(row : Iyi::DiagnosticFieldTable::Row, provenance : Iyi::DiagnosticFieldTable::Provenance) : Iyi::DiagnosticFieldTable::Row
    Iyi::DiagnosticFieldTable::Row.new(row.field, row.klass, row.role, row.coordinate, row.presence, row.nilable, row.scalar, provenance, row.base)
  end
end

describe Iyi::DiagnosticFieldTable do
  table = Iyi::DiagnosticFieldTable::TABLE
  kinds = Iyi::DiagnosticAstFieldSchema::SUPPORTED
  pairs = Iyi::DiagnosticAstFieldSchema.census_pairs
  syntax = Iyi::DiagnosticFieldTable::Scope::Syntax
  full = Iyi::DiagnosticFieldTable::Scope::Full
  provenance_syntax = Iyi::DiagnosticFieldTable::Provenance::Syntax
  provenance_semantic = Iyi::DiagnosticFieldTable::Provenance::Semantic

  describe "coverage" do
    it "verifies the table against every supported kind" do
      Iyi::DiagnosticFieldTable.verify!
    end

    it "refuses a table that lacks a supported kind" do
      partial = table.reject { |kind, _rows| kind == "Call" }
      expect_raises(ArgumentError, /lacks kinds/) do
        Iyi::DiagnosticFieldTable.verify!(partial, kinds)
      end
    end

    it "refuses a table that carries an unsupported kind" do
      extended = table.dup
      extended["Bogus"] = [] of Iyi::DiagnosticFieldTable::Row
      expect_raises(ArgumentError, /unsupported kinds/) do
        Iyi::DiagnosticFieldTable.verify!(extended, kinds)
      end
    end

    it "gives field-less kinds no fields beyond their base rows" do
      kinds.each { |kind| table.has_key?(kind).should eq(true) }
      table["Nop"].reject(&.base).empty?.should eq(true)
      table["Self"].reject(&.base).empty?.should eq(true)
    end

    it "gives every kind one row for each base field" do
      kinds.each do |kind|
        table[kind].count(&.base).should eq(Iyi::DiagnosticFieldTable::BASE_FIELDS.size)
      end
    end

    it "refuses a kind whose base field is omitted" do
      holed = table.dup
      holed["Def"] = table["Def"].reject { |row| row.base && row.field == "location" }
      expect_raises(ArgumentError, /appears 0 times/) do
        Iyi::DiagnosticFieldTable.verify!(holed, kinds)
      end
    end
  end

  describe "census scopes" do
    {% if Iyi::Block.has_method?(:binder) %}
    # Full-compiler context. Every census pair must be covered by a full-scope
    # row, and every full-scope row must be in the census. Nothing is skipped.
    it "requires zero full-scope census pairs without a row" do
      Iyi::DiagnosticFieldTable.uncovered(table, pairs, full).should eq([] of String)
    end

    it "requires zero full-scope rows missing from the census" do
      Iyi::DiagnosticFieldTable.unlisted(table, pairs, full).should eq([] of String)
    end
    {% else %}
    # Syntax-only context. The census holds syntax fields alone.
    it "covers every syntax census pair with a syntax row, base fields included" do
      Iyi::DiagnosticFieldTable.uncovered(table, pairs, syntax).should eq([] of String)
    end

    it "lists no syntax-scope row that the syntax census does not contain" do
      Iyi::DiagnosticFieldTable.unlisted(table, pairs, syntax).should eq([] of String)
    end

    it "shows that a syntax-only census cannot satisfy the full scope" do
      Iyi::DiagnosticFieldTable.unlisted(table, pairs, full).includes?("Path.target_const").should eq(true)
    end

    it "reports a semantic field that the table marks syntax" do
      promoted = table.dup
      promoted["Path"] = table["Path"].map { |row| row.field == "target_const" ? DiagnosticFieldTableSpec.with_provenance(row, provenance_syntax) : row }
      Iyi::DiagnosticFieldTable.unlisted(promoted, pairs, syntax).includes?("Path.target_const").should eq(true)
    end
    {% end %}

    it "keeps semantic rows out of the syntax scope and in the full scope" do
      Iyi::DiagnosticFieldTable.rows_in_scope("Path", syntax).any? { |row| row.field == "target_const" }.should eq(false)
      Iyi::DiagnosticFieldTable.rows_in_scope("Path", full).any? { |row| row.field == "target_const" }.should eq(true)
    end

    it "reports a syntax field that the table marks semantic" do
      demoted = table.dup
      demoted["Def"] = table["Def"].map { |row| row.field == "doc" ? DiagnosticFieldTableSpec.with_provenance(row, provenance_semantic) : row }
      Iyi::DiagnosticFieldTable.uncovered(demoted, pairs, syntax).includes?("Def.doc").should eq(true)
    end

    it "reports a table that omits a census base field" do
      holed = table.dup
      holed["Def"] = table["Def"].reject { |row| row.base && row.field == "location" }
      Iyi::DiagnosticFieldTable.uncovered(holed, pairs, syntax).includes?("Def.location").should eq(true)
    end

    it "reports a table row for a field the census does not contain" do
      stale = table.dup
      stale["Def"] = table["Def"] + [Iyi::DiagnosticFieldTable::Row.new("stale_field", Iyi::DiagnosticAstFieldClass::Infrastructure, Iyi::DiagnosticFieldTable::Role::Infrastructure, Iyi::DiagnosticFieldTable::Coordinate::Single, nil, nil, nil)]
      Iyi::DiagnosticFieldTable.unlisted(stale, pairs, syntax).includes?("Def.stale_field").should eq(true)
    end
  end

  describe "classification" do
    it "classifies every table row, base rows included, the way the existing classifier does" do
      mismatches = [] of String
      table.each do |kind, rows|
        rows.each do |row|
          actual = Iyi::DiagnosticAstFieldSchema.classify(kind, row.field)
          mismatches << "#{kind}.#{row.field}" unless actual == row.klass
        end
      end
      mismatches.should eq([] of String)
    end

    it "classifies every base field of every kind as the table records" do
      mismatches = [] of String
      kinds.each do |kind|
        Iyi::DiagnosticFieldTable::BASE_FIELDS.each do |field|
          expected = Iyi::DiagnosticFieldTable.base_class(kind, field)
          mismatches << "#{kind}.#{field}" unless Iyi::DiagnosticAstFieldSchema.classify(kind, field) == expected
        end
      end
      mismatches.should eq([] of String)
    end
  end

  describe "row consistency" do
    it "refuses an always-present row that is nilable" do
      row = Iyi::DiagnosticFieldTable::Row.new("body", Iyi::DiagnosticAstFieldClass::Child, Iyi::DiagnosticFieldTable::Role::Child, Iyi::DiagnosticFieldTable::Coordinate::Single, Iyi::DiagnosticFieldTable::Presence::Always, true, nil)
      expect_raises(ArgumentError, /always-present/) do
        Iyi::DiagnosticFieldTable.verify_row!("Def", row)
      end
    end

    it "refuses a row whose role disagrees with its class" do
      row = Iyi::DiagnosticFieldTable::Row.new("doc", Iyi::DiagnosticAstFieldClass::SyntaxScalar, Iyi::DiagnosticFieldTable::Role::Child, Iyi::DiagnosticFieldTable::Coordinate::Single, Iyi::DiagnosticFieldTable::Presence::Optional, true, "bytes?")
      expect_raises(ArgumentError, /class and role/) do
        Iyi::DiagnosticFieldTable.verify_row!("Def", row)
      end
    end

    it "refuses a scalar whose nilable type tag disagrees with its nilability" do
      row = Iyi::DiagnosticFieldTable::Row.new("doc", Iyi::DiagnosticAstFieldClass::SyntaxScalar, Iyi::DiagnosticFieldTable::Role::Scalar, Iyi::DiagnosticFieldTable::Coordinate::Single, Iyi::DiagnosticFieldTable::Presence::Always, false, "bytes?")
      expect_raises(ArgumentError, /tag disagrees/) do
        Iyi::DiagnosticFieldTable.verify_row!("Def", row)
      end
    end

    it "refuses an infrastructure row that carries framing data" do
      row = Iyi::DiagnosticFieldTable::Row.new("annotations", Iyi::DiagnosticAstFieldClass::Infrastructure, Iyi::DiagnosticFieldTable::Role::Infrastructure, Iyi::DiagnosticFieldTable::Coordinate::Single, Iyi::DiagnosticFieldTable::Presence::Always, nil, nil)
      expect_raises(ArgumentError, /framing data/) do
        Iyi::DiagnosticFieldTable.verify_row!("Def", row)
      end
    end

    it "refuses a base row whose class differs from the classifier's" do
      row = Iyi::DiagnosticFieldTable::Row.new("location", Iyi::DiagnosticAstFieldClass::Infrastructure, Iyi::DiagnosticFieldTable::Role::Infrastructure, Iyi::DiagnosticFieldTable::Coordinate::Single, nil, true, nil, provenance_syntax, true)
      expect_raises(ArgumentError, /base class differs/) do
        Iyi::DiagnosticFieldTable.verify_row!("Def", row)
      end
    end

    it "refuses a base row whose nilability is not the declared one" do
      row = Iyi::DiagnosticFieldTable::Row.new("location", Iyi::DiagnosticAstFieldClass::OriginEvidence, Iyi::DiagnosticFieldTable::Role::Evidence, Iyi::DiagnosticFieldTable::Coordinate::Single, nil, false, nil, provenance_syntax, true)
      expect_raises(ArgumentError, /nilability differs/) do
        Iyi::DiagnosticFieldTable.verify_row!("Def", row)
      end
    end

    it "refuses a semantic row that is framed" do
      row = Iyi::DiagnosticFieldTable::Row.new("target_const", Iyi::DiagnosticAstFieldClass::Child, Iyi::DiagnosticFieldTable::Role::Child, Iyi::DiagnosticFieldTable::Coordinate::Single, Iyi::DiagnosticFieldTable::Presence::Always, false, nil, provenance_semantic)
      expect_raises(ArgumentError, /semantic row is framed/) do
        Iyi::DiagnosticFieldTable.verify_row!("Path", row)
      end
    end

    it "refuses an unknown kind" do
      expect_raises(ArgumentError, /unclassified AST kind/) do
        Iyi::DiagnosticFieldTable.rows("Nope")
      end
    end
  end

  describe "real node snapshots" do
    it "accepts a def with an argument and a body" do
      DiagnosticFieldTableSpec.check(Iyi::Def.new("f", [Iyi::Arg.new("x")] of Iyi::Arg, Iyi::NumberLiteral.new(1)))
    end

    it "accepts a call with an argument" do
      DiagnosticFieldTableSpec.check(Iyi::Call.new(nil, "puts", [Iyi::StringLiteral.new("hi")] of Iyi::ASTNode))
    end

    it "accepts a block with a parameter" do
      DiagnosticFieldTableSpec.check(Iyi::Block.new([Iyi::Var.new("x")] of Iyi::Var, Iyi::Nop.new))
    end

    it "accepts a path" do
      DiagnosticFieldTableSpec.check(Iyi::Path.new("Foo"))
    end

    it "accepts an is_a check" do
      DiagnosticFieldTableSpec.check(Iyi::IsA.new(Iyi::Var.new("x"), Iyi::Path.new("Int32")))
    end

    it "accepts a hash literal, whose entries are key and value pairs" do
      DiagnosticFieldTableSpec.check(Iyi::HashLiteral.new([Iyi::HashLiteral::Entry.new(Iyi::NumberLiteral.new(1), Iyi::NumberLiteral.new(2))] of Iyi::HashLiteral::Entry))
    end

    it "accepts a named tuple literal, whose key is a name and value a child" do
      DiagnosticFieldTableSpec.check(Iyi::NamedTupleLiteral.new([Iyi::NamedTupleLiteral::Entry.new("a", Iyi::NumberLiteral.new(1))] of Iyi::NamedTupleLiteral::Entry))
    end

    it "accepts an import with two path segments" do
      DiagnosticFieldTableSpec.check(Iyi::ImportDecl.new(["std", "json"]))
    end

    it "accepts a def whose free variable bound is keyed" do
      node = Iyi::Def.new("f", [] of Iyi::Arg, Iyi::NumberLiteral.new(1))
      node.free_var_bounds = {"T" => Iyi::Var.new("Show").as(Iyi::ASTNode)} of String => Iyi::ASTNode
      DiagnosticFieldTableSpec.check(node)
    end
  end

  describe "negative controls on a real def" do
    node = Iyi::Def.new("f", [Iyi::Arg.new("x")] of Iyi::Arg, Iyi::NumberLiteral.new(1))
    presences, scalars, children, names, child_kinds = DiagnosticFieldTableSpec.snapshot(node)

    it "rejects a presence list that omits a field" do
      expect_raises(ArgumentError, /differ/) do
        Iyi::DiagnosticFieldTable.check_presence!("Def", presences[0...-1])
      end
    end

    it "rejects a presence list that carries a stale field" do
      stale = DiagnosticFieldTableSpec::Presences.new
      presences.each { |field, state| stale << {field, state} }
      stale << {"bogus", Iyi::DiagnosticFieldPresence::Present}
      expect_raises(ArgumentError, /differ/) do
        Iyi::DiagnosticFieldTable.check_presence!("Def", stale)
      end
    end

    it "rejects an absent state on a field that is always present" do
      changed = DiagnosticFieldTableSpec::Presences.new
      presences.each { |field, state| changed << {field, (field == "name" ? Iyi::DiagnosticFieldPresence::Absent : state)} }
      expect_raises(ArgumentError, /not allowed/) do
        Iyi::DiagnosticFieldTable.check_presence!("Def", changed)
      end
    end

    it "rejects a scalar with the wrong type" do
      changed = DiagnosticFieldTableSpec::Scalars.new
      scalars.each { |field, tag, shape| changed << {field, (field == "visibility" ? "bool" : tag), shape} }
      expect_raises(ArgumentError, /differs/) do
        Iyi::DiagnosticFieldTable.check_scalars!("Def", changed)
      end
    end

    it "rejects a scalar that is omitted" do
      expect_raises(ArgumentError, /differ/) do
        Iyi::DiagnosticFieldTable.check_scalars!("Def", scalars[1..])
      end
    end

    it "rejects an indexed child whose index is dropped" do
      changed = DiagnosticFieldTableSpec::Stubs.new
      children.each { |field, index, key| changed << {field, (field == "args" ? nil : index), key} }
      expect_raises(ArgumentError, /indexed but lacks/) do
        Iyi::DiagnosticFieldTable.check_stubs!("Def", presences, changed, names)
      end
    end

    it "rejects a child kind that the table does not know" do
      expect_raises(ArgumentError, /not in the table/) do
        Iyi::DiagnosticFieldTable.check_node!("Def", presences, scalars, children, names, ["Bogus"])
      end
    end

    it "rejects keyed entries with a duplicate key" do
      keyed = Iyi::Def.new("g", [] of Iyi::Arg, Iyi::NumberLiteral.new(1))
      keyed.free_var_bounds = {"T" => Iyi::Var.new("Show").as(Iyi::ASTNode)} of String => Iyi::ASTNode
      keyed_presences, _, keyed_children, keyed_names, _ = DiagnosticFieldTableSpec.snapshot(keyed)
      doubled = DiagnosticFieldTableSpec::Stubs.new
      keyed_children.each { |field, index, key| doubled << {field, index, key} }
      doubled << {"free_var_bounds", nil, "T"}
      expect_raises(ArgumentError, /duplicate keys/) do
        Iyi::DiagnosticFieldTable.check_stubs!("Def", keyed_presences, doubled, keyed_names)
      end
    end
  end
end
