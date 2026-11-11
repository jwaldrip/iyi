require "../support/syntax"
require "../../src/compiler/iyi/syntax/diagnostic_bound_recipe"

# Spec-only issuance authority: every producer recomputes to itself, so the
# ledger issues whatever the recipe rendered.
class SpecBoundRecipeAuthority < Iyi::DiagnosticProjectionAuthority
  def recompute(request : Iyi::DiagnosticProjectionRequest) : Iyi::DiagnosticBoundProducer
    request.producer
  end
end

private def ledger_under_test : Iyi::DiagnosticProjectionLedger
  Iyi::DiagnosticProjectionLedger.new(SpecBoundRecipeAuthority.new)
end

# The declaration origin every signature site in these examples cites.
private def sig_origin : Iyi::DiagnosticOrigin
  Iyi::DiagnosticOrigin::Written.new("app", "/a.iyi", 1, "Def", "keyword")
end

# A signature site: ResolvedRestriction may render here (site tie), and finish needs a matching signature.
private def signature_recipe(ledger : Iyi::DiagnosticProjectionLedger = ledger_under_test,
                             container : String = "Owner") : Iyi::DiagnosticBoundRecipe
  Iyi::DiagnosticBoundRecipe.signature(ledger, "Iyi", container, sig_origin)
end

# The signature every signature site in these examples finishes with.
private def spec_signature : Iyi::IyiMod::Signature
  signature = Iyi::IyiMod::Signature.new("f", "", [] of String, "", "", [] of String, false)
  signature.diagnostic_origin = sig_origin
  signature
end

# A capture-on parse of one path, so its name tokens carry PathSegment evidence.
private def captured_path(text : String) : Iyi::ASTNode
  parser = Iyi::Parser.new(text)
  parser.filename = "/spec/bound_recipe.cr"
  parser.diagnostic_source_file = "/spec/bound_recipe.cr"
  parser.diagnostic_capture = true
  parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile,
    nil, Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
  parser.parse.as(Iyi::Path)
end

# A registered restriction at a signature site: the captured path, projected as a ResolvedRestriction.
private def restricted(recipe : Iyi::DiagnosticBoundRecipe, resolved : String,
                       add_global : Bool = false, root : String = "Root") : Iyi::DiagnosticBoundFragment
  source = recipe.printed(captured_path(resolved))
  recipe.project_whole(source, Iyi::DiagnosticBoundProducer::ResolvedRestriction.new(
    "Owner", resolved, resolved, root, add_global))
end

describe Iyi::DiagnosticBoundRecipe do
  it "strips the root from a rooted path and counts the projection it minted" do
    recipe = signature_recipe
    signature = spec_signature
    key = Iyi::IyiMod.signature_fragment_key("Owner", signature)
    stripped = recipe.strip_root(restricted(recipe, "Root::X"), "Root")
    stripped.text.should eq("X")
    fragment = recipe.finish(stripped, key, signature)
    fragment.key.should eq(key)
    recipe.counts.should eq({"ResolvedRestriction" => 1, "StripRoot" => 1})
  end

  it "leaves a global ::Root::X and an interior Other::Root::Z untouched" do
    recipe = signature_recipe
    recipe.strip_root(restricted(recipe, "Root::X", add_global: true), "Root").text.should eq("::Root::X")
    interior = restricted(recipe, "Other::Root::Z")
    recipe.strip_root(interior, "Root").text.should eq("Other::Root::Z")
    recipe.map_foreign(interior, "Json", "Root", "Json::Root").text.should eq("Other::Root::Z")
  end

  it "maps a bound name at a path head and skips identity mappings" do
    recipe = signature_recipe
    path = restricted(recipe, "JSON::Parser")
    recipe.map_foreign(path, "Json", "JSON", "Json::JSON").text.should eq("Json::JSON::Parser")
    recipe.map_foreign(path, "Json", "JSON", "JSON").text.should eq("JSON::Parser")
    recipe.map_foreign(restricted(recipe, "JSON", add_global: true), "Json", "JSON", "Json::JSON").text.should eq("::JSON")
  end

  it "aliases only a single-segment name with no :: neighbour" do
    recipe = signature_recipe
    recipe.replace_alias(restricted(recipe, "Name"), "Owner", "Name", "Int32").text.should eq("Int32")
    recipe.replace_alias(restricted(recipe, "Name::X"), "Owner", "Name", "Int32").text.should eq("Name::X")
    recipe.replace_alias(restricted(recipe, "Name", add_global: true), "Owner", "Name", "Int32").text.should eq("::Name")
  end

  it "projects a whole generic and a whole proc notation" do
    recipe = signature_recipe
    generic = recipe.plain("Array(Root::X)")
    recipe.project_whole(generic, Iyi::DiagnosticBoundProducer::ResolvedRestriction.new(
      "Owner", "Array(Root::X)", "Array(X)", "Root", false)).text.should eq("Array(X)")
    proc = recipe.plain("Root::X -> Int32")
    recipe.project_whole(proc, Iyi::DiagnosticBoundProducer::ResolvedRestriction.new(
      "Owner", "Root::X -> Int32", "X -> Int32", "Root", false)).text.should eq("X -> Int32")
  end

  it "joins and finishes a fragment that a section accepts, and verifies the section count" do
    recipe = signature_recipe
    signature = spec_signature
    key = Iyi::IyiMod.signature_fragment_key("Owner", signature)
    head = recipe.strip_root(restricted(recipe, "Root::X"), "Root")
    joined = recipe.join([head, recipe.plain(" -> Int32")], "")
    joined.text.should eq("X -> Int32")
    section = IyiMod::DiagnosticSection.new
    section.add_fragment(recipe.finish(joined, key, signature))
    recipe.verify_section!(section).should eq(1)
  end

  it "refuses a section holding projections this recipe did not finish" do
    minting = signature_recipe
    signature = spec_signature
    key = Iyi::IyiMod.signature_fragment_key("Owner", signature)
    section = IyiMod::DiagnosticSection.new
    section.add_fragment(minting.finish(restricted(minting, "Root::X"), key, signature))
    expect_raises(ArgumentError, "bound projection count differs from minted") do
      signature_recipe.verify_section!(section)
    end
  end

  it "keeps literal contents as written, since rewrites touch only name tokens (D1-B)" do
    recipe = Iyi::DiagnosticBoundRecipe.initialiser(ledger_under_test, "Iyi")
    literal = recipe.printed(Iyi::StringLiteral.new("Root::X"))
    literal.text.should eq("\"Root::X\"")
    recipe.strip_root(literal, "Root").text.should eq("\"Root::X\"")
    recipe.expect!(literal, "\"Root::X\"", "literal").text.should eq("\"Root::X\"")
  end

  it "refuses when the bytes differ from the ordinary binding" do
    recipe = signature_recipe
    expect_raises(ArgumentError, "bound provenance differs from ordinary binding at site") do
      recipe.expect!(restricted(recipe, "Root::X"), "Other::X", "site")
    end
  end

  it "refuses a touched event that carries a non-name anchor" do
    recipe = Iyi::DiagnosticBoundRecipe.initialiser(ledger_under_test, "Iyi")
    assign = Iyi::DiagnosticOrigin::Written.new("app", "/a.iyi", 2, "Assign", "constant")
    constant = Iyi::DiagnosticBoundRecipe.constant(recipe.ledger, "Iyi", assign, recipe)
    line = constant.constant_line(constant.printed(captured_path("Root")), constant.plain("1"))
    expect_raises(ArgumentError, "bound projection would drop a non-name anchor") do
      recipe.replace_alias(line, "Owner", "Root", "Other")
    end
  end

  it "refuses fragments the recipe's ledger did not register" do
    recipe = Iyi::DiagnosticBoundRecipe.initialiser(ledger_under_test, "Iyi")
    builder = Iyi::DiagnosticFragmentBuilder.new("Iyi")
    foreign = Iyi::DiagnosticBoundFragment.new(Iyi::DiagnosticRenderedFragment.new("X", builder.finish_data("X")))
    expect_raises(ArgumentError, /not registered/) do
      recipe.strip_root(foreign, "Root")
    end
  end

  it "composes constant lines from separate constant sites into one initialiser fragment" do
    ledger = ledger_under_test
    initialiser = Iyi::DiagnosticBoundRecipe.initialiser(ledger, "Iyi")
    first_assign = Iyi::DiagnosticOrigin::Written.new("app", "/a.iyi", 2, "Assign", "constant")
    second_assign = Iyi::DiagnosticOrigin::Written.new("app", "/a.iyi", 3, "Assign", "constant")
    first = Iyi::DiagnosticBoundRecipe.constant(ledger, "Iyi", first_assign, initialiser)
    second = Iyi::DiagnosticBoundRecipe.constant(ledger, "Iyi", second_assign, initialiser)
    line_one = first.constant_line(first.printed(captured_path("A")), first.plain("1"))
    line_two = second.constant_line(second.printed(captured_path("B")), second.plain("2"))
    joined = initialiser.join([line_one, line_two], "\n")
    joined.text.should eq("A = 1\nB = 2")
    section = IyiMod::DiagnosticSection.new
    section.add_fragment(initialiser.finish(joined, "initialiser"))
    initialiser.verify_section!(section).should eq(0)
  end

  it "refuses a join whose part belongs to a different site (R7)" do
    ledger = ledger_under_test
    owner = signature_recipe(ledger, "A")
    other = signature_recipe(ledger, "B")
    owned_part = owner.strip_root(restricted(owner, "Root::X"), "Root")
    expect_raises(ArgumentError, "bound fragment belongs to another site") do
      other.join([owned_part], "")
    end
  end

  it "refuses a finish whose key does not match the site (R15)" do
    recipe = Iyi::DiagnosticBoundRecipe.initialiser(ledger_under_test, "Iyi")
    joined = recipe.join([recipe.plain("X")], "")
    expect_raises(ArgumentError, "bound site key differs from its declaration") do
      recipe.finish(joined, "not-the-initialiser")
    end
  end
end
