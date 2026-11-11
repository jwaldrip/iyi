require "../support/syntax"
require "../../src/compiler/iyi/syntax/diagnostic_bound_recipe"

# Spec-only issuance authority: every projection replays as admitted.
class SpecBoundRecipeAuthority < Iyi::DiagnosticProjectionAuthority
  def replay!(producer : Iyi::DiagnosticBoundProducer, source_text : String) : Nil
  end
end

private def recipe_under_test(mode : String = "Iyi") : Iyi::DiagnosticBoundRecipe
  Iyi::DiagnosticBoundRecipe.new(SpecBoundRecipeAuthority.new, mode)
end

# A registered fragment whose path names come from a real restriction projection.
private def restricted(recipe : Iyi::DiagnosticBoundRecipe, resolved : String,
                       add_global : Bool = false, root : String = "Root") : Iyi::DiagnosticBoundFragment
  recipe.insert(Iyi::DiagnosticBoundProducer::ResolvedRestriction.new("Owner", resolved, resolved, root, add_global))
end

describe Iyi::DiagnosticBoundRecipe do
  it "strips the root from a rooted path and counts the projection it minted" do
    recipe = recipe_under_test
    stripped = recipe.strip_root(restricted(recipe, "Root::X"), "Root")
    stripped.text.should eq("X")
    fragment = recipe.finish(stripped, "signature")
    fragment.key.should eq("signature")
    recipe.counts.should eq({"StripRoot" => 1})
  end

  it "leaves a global ::Root::X and an interior Other::Root::Z untouched" do
    recipe = recipe_under_test
    recipe.strip_root(restricted(recipe, "Root::X", add_global: true), "Root").text.should eq("::Root::X")
    interior = restricted(recipe, "Other::Root::Z")
    recipe.strip_root(interior, "Root").text.should eq("Other::Root::Z")
    recipe.map_foreign(interior, "Json", "Root", "Json::Root").text.should eq("Other::Root::Z")
  end

  it "maps a bound name at a path head and skips identity mappings" do
    recipe = recipe_under_test
    path = restricted(recipe, "JSON::Parser")
    recipe.map_foreign(path, "Json", "JSON", "Json::JSON").text.should eq("Json::JSON::Parser")
    recipe.map_foreign(path, "Json", "JSON", "JSON").text.should eq("JSON::Parser")
    recipe.map_foreign(restricted(recipe, "JSON", add_global: true), "Json", "JSON", "Json::JSON").text.should eq("::JSON")
  end

  it "aliases only a single-segment name with no :: neighbour" do
    recipe = recipe_under_test
    recipe.replace_alias(restricted(recipe, "Name"), "Owner", "Name", "Int32").text.should eq("Int32")
    recipe.replace_alias(restricted(recipe, "Name::X"), "Owner", "Name", "Int32").text.should eq("Name::X")
    recipe.replace_alias(restricted(recipe, "Name", add_global: true), "Owner", "Name", "Int32").text.should eq("::Name")
  end

  it "projects a whole generic and a whole proc notation" do
    recipe = recipe_under_test
    generic = restricted(recipe, "Array(Root::X)")
    recipe.project_whole(generic, Iyi::DiagnosticBoundProducer::ResolvedRestriction.new(
      "Owner", "Array(Root::X)", "Array(X)", "Root", false)).text.should eq("Array(X)")
    proc = restricted(recipe, "Root::X -> Int32")
    recipe.project_whole(proc, Iyi::DiagnosticBoundProducer::ResolvedRestriction.new(
      "Owner", "Root::X -> Int32", "X -> Int32", "Root", false)).text.should eq("X -> Int32")
  end

  it "joins and finishes a fragment that a section accepts, and verifies the section count" do
    recipe = recipe_under_test
    head = recipe.strip_root(restricted(recipe, "Root::X"), "Root")
    joined = recipe.join([head, recipe.plain(" -> Int32")], "")
    joined.text.should eq("X -> Int32")
    section = IyiMod::DiagnosticSection.new
    section.add_fragment(recipe.finish(joined, "signature"))
    recipe.verify_section!(section).should eq(1)
  end

  it "refuses a section holding projections this recipe did not finish" do
    minting = recipe_under_test
    section = IyiMod::DiagnosticSection.new
    section.add_fragment(minting.finish(restricted(minting, "Root::X"), "foreign"))
    expect_raises(ArgumentError, "bound projection count differs from minted") do
      recipe_under_test.verify_section!(section)
    end
  end

  it "keeps literal contents as written, since rewrites touch only name tokens (D1-B)" do
    recipe = recipe_under_test
    literal = recipe.printed(Iyi::StringLiteral.new("Root::X"))
    literal.text.should eq("\"Root::X\"")
    recipe.strip_root(literal, "Root").text.should eq("\"Root::X\"")
    recipe.expect!(literal, "\"Root::X\"", "literal").text.should eq("\"Root::X\"")
  end

  it "refuses when the bytes differ from the ordinary binding" do
    recipe = recipe_under_test
    expect_raises(ArgumentError, "bound provenance differs from ordinary binding at site") do
      recipe.expect!(restricted(recipe, "Root::X"), "Other::X", "site")
    end
  end

  it "refuses a touched event that carries a non-name anchor" do
    recipe = recipe_under_test
    root = restricted(recipe, "Root")
    origin = root.rendered.data.anchors.first.origin.not_nil!
    line = recipe.constant_line(origin, root, recipe.plain("1"))
    expect_raises(ArgumentError, "bound projection would drop a non-name anchor") do
      recipe.replace_alias(line, "Owner", "Root", "Other")
    end
  end

  it "refuses fragments the recipe's authority did not register" do
    recipe = recipe_under_test
    builder = Iyi::DiagnosticFragmentBuilder.new("Iyi")
    foreign = Iyi::DiagnosticBoundFragment.new(Iyi::DiagnosticRenderedFragment.new("X", builder.finish_data("X")))
    expect_raises(ArgumentError, /not registered/) do
      recipe.strip_root(foreign, "Root")
    end
  end
end
