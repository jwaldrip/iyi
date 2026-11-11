require "../support/syntax"

class Iyi::DiagnosticRecordedEvidenceInputCheck
  # Exercise the derived guard separately after proving the full walk rejects
  # the same structural mutation at its earlier literal graph boundary.
  def spec_bind_derived!(node : Iyi::ASTNode, slot : Iyi::DiagnosticNameSlot) : Nil
    values = node.diagnostic_name_slots[slot]
    origin = values[0].as(Iyi::DiagnosticNameValue::Derived).origin
    bound_derived!(node, slot, values, origin)
  end

  # Binds a bare splat occurrence the way the walk does: its Arg is the traversal occurrence
  # of owner.args[index], then the bare-splat guard runs on it directly.
  def spec_bind_bare_splat!(arg : Iyi::ASTNode, owner : Iyi::ASTNode, index : Int32) : Nil
    @arg_occurrence = {owner.object_id, index, arg.object_id}
    slot = Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::Primary)
    values = arg.diagnostic_name_slots[slot]
    origin = values[0].as(Iyi::DiagnosticNameValue::Derived).origin
    bound_bare_splat!(arg, slot, values, origin)
  ensure
    @arg_occurrence = nil
  end
end


# Binds the source through the public bind! path in one lexical mode, selected by suffix.
private def derived_name_bind(source : String, suffix : String, & : Iyi::DiagnosticBoundCapture ->)
  path = File.tempname("derived-name-binding", suffix)
  File.write(path, source)
  begin
    parser = Iyi::Parser.new(source, nil, [Set(String).new], Iyi::WarningCollection.new)
    parser.filename = path
    ledger = Iyi::DiagnosticCaptureLedger.new
    _, claim, authority = Iyi::DiagnosticCaptureAuthority.record_source(ledger, parser)
    ledger.freeze!
    yield ledger.bind!(claim, authority)
  ensure
    File.delete(path) if File.file?(path)
  end
end

# Every positive must bind through bind! in both lexical modes.
private def derived_name_accept(source : String)
  [".cr", ".iyi"].each do |suffix|
    derived_name_bind(source, suffix) { |bound| bound.root.should_not be_nil }
  end
end

# Replays the source as bind! does, mutates the replayed tree, then runs the bundled walk.
private def derived_name_walk(source : String, suffix : String, mutate : Proc(Iyi::ASTNode, Nil), scope : String? = nil) : Nil
  path = File.tempname("derived-name-control", suffix)
  File.write(path, source)
  begin
    parser = Iyi::Parser.new(source, nil, [Set(String).new], Iyi::WarningCollection.new)
    parser.filename = path
    ledger = Iyi::DiagnosticCaptureLedger.new
    _, claim, authority = Iyi::DiagnosticCaptureAuthority.record_source(ledger, parser)
    ledger.freeze!
    replay = claim.replay_parser
    replay.enable_diagnostic_observations
    root = claim.replay_entry(replay)
    Iyi::DiagnosticCaptureRefs.stamp!(root, authority.capture_key)
    journal = Iyi::DiagnosticReplayJournal.new(replay.diagnostic_lexical_observations)
    identity = Iyi::DiagnosticModuleIdentity.from(root, claim, journal)
    structural = Iyi::DiagnosticUnnamedParamBinder.new(claim, journal).verify!(root)
    bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, replay, root)
    mutate.call(root)
    checker = Iyi::DiagnosticRecordedEvidenceInputCheck.new(claim, journal, identity, structural, bundle)
    if scope
      expect_raises(ArgumentError, "literal replay graph differs") { checker.verify!(root) }
      case scope
      when "sugar"
        arg = derived_name_nodes(root).find { |node| node.is_a?(Iyi::Arg) && node.name == "x" }.as(Iyi::Arg)
        checker.spec_bind_derived!(arg.restriction.not_nil!, derived_name_path_segment)
      when "regex_global"
        global = root.as(Iyi::Expressions).expressions.last
        checker.spec_bind_derived!(global, derived_name_primary)
      when "regex_lookup"
        calls = derived_name_nodes(root).select { |node| node.is_a?(Iyi::Call) && node.name == "[]" }
        checker.spec_bind_derived!(calls[1], derived_name_primary)
      else
        raise "unknown scoped derived-name control"
      end
    else
      checker.verify!(root)
    end
  ensure
    File.delete(path) if File.file?(path)
  end
end

# A mutated walk must refuse with exactly this message, in both lexical modes.
private def derived_name_reject(source : String, message : String, mutate : Proc(Iyi::ASTNode, Nil))
  [".cr", ".iyi"].each do |suffix|
    expect_raises(ArgumentError, message) { derived_name_walk(source, suffix, mutate) }
  end
end

private def derived_name_scoped_reject(source : String, message : String, scope : String, mutate : Proc(Iyi::ASTNode, Nil))
  [".cr", ".iyi"].each do |suffix|
    expect_raises(ArgumentError, message) { derived_name_walk(source, suffix, mutate, scope) }
  end
end

private def derived_name_nodes(node : Iyi::ASTNode, found : Array(Iyi::ASTNode) = [] of Iyi::ASTNode) : Array(Iyi::ASTNode)
  found << node
  Iyi::DiagnosticDirectChildFields.each(node) { |_, _, _, child| derived_name_nodes(child, found) }
  found
end

private def derived_name_primary : Iyi::DiagnosticNameSlot
  Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::Primary)
end

private def derived_name_path_segment : Iyi::DiagnosticNameSlot
  Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::PathSegment, 0)
end

# The derivation a node carries in one slot.
private def derived_name_origin(node : Iyi::ASTNode, slot : Iyi::DiagnosticNameSlot) : Iyi::DiagnosticOrigin::DerivedName
  value = node.diagnostic_name_slots[slot][0]
  value.as(Iyi::DiagnosticNameValue::Derived).origin
end

# The same token with a different input digest: its span, kind and text still match the replay,
# but source_token_ok? refuses it.
private def derived_name_unscanned(token : Iyi::DiagnosticSourceNameToken) : Iyi::DiagnosticSourceNameToken
  Iyi::DiagnosticSourceNameToken.new(lexical_origin: token.lexical_origin, binding_origin: token.binding_origin,
    context: token.context, input_sha256: "0" * 64, input_bytesize: token.input_bytesize,
    input_start: token.input_start, input_end: token.input_end, lexical_mode: token.lexical_mode,
    token_kind: token.token_kind, raw_text: token.raw_text)
end

describe "derived name binding positives" do
  it "binds operator names in both modes" do
    derived_name_accept("x = 1\nx += 1\n")
    derived_name_accept("a.x += 1\n")
    derived_name_accept("a = [1]\na[1] += 2\n")
    derived_name_accept("x = 1\ny = x -1\n")
    derived_name_accept("x = 1\ny = x -1-1\n")
    derived_name_accept("x = 1\ny = x -0x10\n")
    derived_name_accept("a = [1]\nb = a[1]\n")
    derived_name_accept("a = [1]\nb = a[[1][0]]\n")
    derived_name_accept("a = [1]\nb = a[\"[\"]\n")
    derived_name_accept("a = [1]\nb = a[\"]\"]\n")
    derived_name_accept("a = [1]\nb = a[%w[x]]\n")
    derived_name_accept("a = [1]\nb = a[1]?\n")
    derived_name_accept("a = [1]\na[1] = 2\n")
    derived_name_accept("a = [1]\na[1]=2\n")
    derived_name_accept("a = [1]\na[] = 2\n")
    derived_name_accept("a = [1]\na[1, 2] = 3\n")
    derived_name_accept("a.x = 1\n")
    derived_name_accept("a.x=1\n")
    derived_name_accept("a.x =\n  1\n")
    derived_name_accept("x = `ls`\n")
    derived_name_accept("x = 1\ny = `ls \#{x}`\n")
    derived_name_accept("y = %x(ls)\n")
  end

  it "binds type sugar in both modes" do
    derived_name_accept("def f(x : Int32*)\nend\n")
    derived_name_accept("def f(x : Int32**)\nend\n")
    derived_name_accept("def f(x : Int32?)\nend\n")
    derived_name_accept("class A\n  def f(x : self?)\n  end\nend\n")
    derived_name_accept("def f(x : Int32[4])\nend\n")
    derived_name_accept("def f(x : {Int32, String})\nend\n")
    derived_name_accept("def f(x : {a: Int32})\nend\n")
    derived_name_accept("x = \"\#{ {1, 2} }\"\n")
    derived_name_accept("x = 1\ny = x.nil?\n")
    derived_name_accept("a = %w()\n")
    derived_name_accept("a = %i()\n")
  end

  it "binds percent literal element paths in both modes" do
    derived_name_accept("a = %w(x y)\n")
    derived_name_accept("a = %W(x\#{1} y)\n")
    derived_name_accept("a = %i(one two)\n")
  end

  it "binds regex match indexes in both modes" do
    derived_name_accept("\"ab\" =~ /(a)/\nx = $0\n")
    derived_name_accept("\"ab\" =~ /(a)(b)/\nx = $2?\n")
    derived_name_accept("\"ab\" =~ /(a)/\nx = $1\n")
    derived_name_accept("\"ab\" =~ /(a)/\n$1\n$1\n")
  end

  it "binds parameter lowering forms in both modes" do
    derived_name_accept("def f(@x)\nend\n")
    derived_name_accept("def f(@x)\n  @x\nend\n")
    derived_name_accept("def f(@@x)\n  @@x\nend\n")
    derived_name_accept("def f(*, @x)\nend\n")
    derived_name_accept("def f(**@o)\nend\n")
    derived_name_accept("def f(&@b)\nend\n")
    derived_name_accept("def f(@end)\nend\n")
  end

  it "binds external-name lowering in both modes" do
    derived_name_accept("def f(@end)\n  @end\nend\n")
    derived_name_accept("def f(foo @end)\nend\n")
    derived_name_accept("def f(foo @x)\n  @x\nend\n")
  end
end

describe "derived name binding controls" do
  it "refuses an operator derivation placed on a node that is not its Call" do
    derived_name_reject("a = [1]\nb = a[1]\n", "derived name production does not fit field", ->(root : Iyi::ASTNode) {
      nodes = derived_name_nodes(root)
      call = nodes.find { |node| node.is_a?(Iyi::Call) && node.name == "[]" }.as(Iyi::Call)
      var = nodes.find { |node| node.is_a?(Iyi::Var) && node.name == "b" }.as(Iyi::Var)
      var.diagnostic_name_slots = {derived_name_primary => call.diagnostic_name_slots[derived_name_primary]}
      nil
    })
  end

  it "refuses an OpAssign derivation placed on a Call" do
    derived_name_reject("x = 1\nx += 1\ny = x.abs\n", "derived name production does not fit field", ->(root : Iyi::ASTNode) {
      nodes = derived_name_nodes(root)
      op = nodes.find { |node| node.is_a?(Iyi::OpAssign) }.as(Iyi::OpAssign)
      call = nodes.find { |node| node.is_a?(Iyi::Call) && node.name == "abs" }.as(Iyi::Call)
      call.diagnostic_origin = op.diagnostic_origin
      call.diagnostic_name_slots = {derived_name_primary => op.diagnostic_name_slots[derived_name_primary]}
      nil
    })
  end

  it "refuses an operator derivation that shares its slot with other evidence" do
    derived_name_reject("a = [1]\nb = a[1]\n", "derived name shares its slot with other evidence", ->(root : Iyi::ASTNode) {
      nodes = derived_name_nodes(root)
      call = nodes.find { |node| node.is_a?(Iyi::Call) && node.name == "[]" }.as(Iyi::Call)
      var = nodes.find { |node| node.is_a?(Iyi::Var) && node.name == "b" }.as(Iyi::Var)
      values = call.diagnostic_name_slots[derived_name_primary] + var.diagnostic_name_slots[derived_name_primary]
      call.diagnostic_name_slots = {derived_name_primary => values}
      nil
    })
  end

  it "refuses an operator derivation whose anchor is not the node origin" do
    derived_name_reject("a = [1]\nb = a[1]\n", "derived name anchor differs from node origin", ->(root : Iyi::ASTNode) {
      nodes = derived_name_nodes(root)
      call = nodes.find { |node| node.is_a?(Iyi::Call) && node.name == "[]" }.as(Iyi::Call)
      call.diagnostic_origin = nil
      nil
    })
  end

  it "refuses a second Call that reuses an operator witness" do
    derived_name_reject("a = [1]\nb = a[1]\nc = a[1]\n", "operator witness consumed twice", ->(root : Iyi::ASTNode) {
      nodes = derived_name_nodes(root)
      calls = nodes.select { |node| node.is_a?(Iyi::Call) && node.name == "[]" }
      first = calls[0].as(Iyi::Call)
      second = calls[1].as(Iyi::Call)
      second.diagnostic_origin = first.diagnostic_origin
      second.diagnostic_name_slots = first.diagnostic_name_slots
      nil
    })
  end

  it "refuses a signed split on a Call that is not its witnessed Call" do
    derived_name_reject("x = 1\nx.abs\ny = x -1\n", "signed operator split not witnessed", ->(root : Iyi::ASTNode) {
      nodes = derived_name_nodes(root)
      signed = nodes.find { |node| node.is_a?(Iyi::Call) && node.name == "-" }.as(Iyi::Call)
      earlier = nodes.find { |node| node.is_a?(Iyi::Call) && node.name == "abs" }.as(Iyi::Call)
      earlier.diagnostic_origin = signed.diagnostic_origin
      earlier.diagnostic_name_slots = signed.diagnostic_name_slots
      nil
    })
  end

  it "refuses a type sugar derivation outside its owner" do
    derived_name_scoped_reject("def f(x : Int32?)\nend\n", "type sugar outside its owner", "sugar", ->(root : Iyi::ASTNode) {
      nodes = derived_name_nodes(root)
      arg = nodes.find { |node| node.is_a?(Iyi::Arg) && node.name == "x" }.as(Iyi::Arg)
      union = arg.restriction.as(Iyi::Union)
      nil_path = union.types[-1].as(Iyi::Path)
      fresh = Iyi::Path.global(["Nil"])
      fresh.diagnostic_name_slots = {derived_name_path_segment => nil_path.diagnostic_name_slots[derived_name_path_segment]}
      arg.restriction = fresh
      nil
    })
  end

  it "refuses a percent array whose element path carries another array's opener" do
    derived_name_reject("a = %w(x)\nb = %w(y)\n", "type sugar opener differs from percent group", ->(root : Iyi::ASTNode) {
      arrays = derived_name_nodes(root).select { |node| node.is_a?(Iyi::ArrayLiteral) }
      first = arrays[0].as(Iyi::ArrayLiteral)
      second = arrays[1].as(Iyi::ArrayLiteral)
      second.of.as(Iyi::Path).diagnostic_name_slots = first.of.as(Iyi::Path).diagnostic_name_slots
      nil
    })
  end

  it "refuses a type sugar witness that is reused by a second owner" do
    derived_name_reject("def f(x : Int32*, y : Int32*)\nend\n", "type sugar witness consumed twice", ->(root : Iyi::ASTNode) {
      generics = derived_name_nodes(root).select { |node| node.is_a?(Iyi::Generic) && node.suffix.asterisk? }
      first = generics[0].as(Iyi::Generic)
      second = generics[1].as(Iyi::Generic)
      second.name.as(Iyi::Path).diagnostic_name_slots = first.name.as(Iyi::Path).diagnostic_name_slots
      nil
    })
  end

  it "refuses a type sugar witness that is not a source-written token" do
    derived_name_reject("def f(x : Int32*)\nend\n", "type-sugar witness is not a scanned token", ->(root : Iyi::ASTNode) {
      generic = derived_name_nodes(root).find { |node| node.is_a?(Iyi::Generic) && node.suffix.asterisk? }.as(Iyi::Generic)
      path = generic.name.as(Iyi::Path)
      witness = derived_name_origin(path, derived_name_path_segment).witnesses[0]
      wrong_identity = Iyi::DiagnosticOrigin::Written.new("elsewhere", "elsewhere.cr", witness.input_start, "TypeSyntax", "token")
      bad = Iyi::DiagnosticSourceSyntaxToken.new(wrong_identity, witness.input_sha256, witness.input_bytesize,
        witness.input_start, witness.input_end, witness.lexical_mode, witness.token_kind, witness.raw_text)
      origin = Iyi::DiagnosticOrigin::DerivedName.type_sugar(Iyi::DiagnosticTypeSugar::Pointer, [bad],
        Iyi::DiagnosticTypeSugarResult::Pointer, 0)
      path.diagnostic_name_slots = {derived_name_path_segment => [Iyi::DiagnosticNameValue::Derived.new(origin)] of Iyi::DiagnosticNameValue}
      nil
    })
  end

  it "refuses a regex match index whose token is not scanned" do
    derived_name_reject("\"ab\" =~ /(a)/\nx = $1\n", "regex match index is not a scanned token", ->(root : Iyi::ASTNode) {
      global = derived_name_nodes(root).find { |node| node.is_a?(Iyi::Global) && node.name == "$~" }.as(Iyi::Global)
      token = derived_name_origin(global, derived_name_primary).source_token.not_nil!
      origin = Iyi::DiagnosticOrigin::DerivedName.regex_match_index(derived_name_unscanned(token), "MatchData")
      global.diagnostic_name_slots = {derived_name_primary => [Iyi::DiagnosticNameValue::Derived.new(origin)] of Iyi::DiagnosticNameValue}
      nil
    })
  end

  it "refuses a regex match data that differs from its lookup" do
    derived_name_reject("\"ab\" =~ /(a)/\nx = $1\ny = $1\n", "regex match data differs from its lookup", ->(root : Iyi::ASTNode) {
      globals = derived_name_nodes(root).select { |node| node.is_a?(Iyi::Global) && node.name == "$~" }
      first = globals[0].as(Iyi::Global)
      second = globals[1].as(Iyi::Global)
      second.diagnostic_name_slots = first.diagnostic_name_slots
      nil
    })
  end

  it "refuses a regex match data outside any lookup" do
    derived_name_scoped_reject("\"ab\" =~ /(a)/\nx = $1\n", "regex match data outside its lookup", "regex_global", ->(root : Iyi::ASTNode) {
      global = derived_name_nodes(root).find { |node| node.is_a?(Iyi::Global) && node.name == "$~" }.as(Iyi::Global)
      extra = Iyi::Global.new("$~")
      extra.diagnostic_name_slots = global.diagnostic_name_slots
      root.as(Iyi::Expressions).expressions << extra
      nil
    })
  end

  it "refuses a regex lookup whose backreference is another Call's operand" do
    derived_name_scoped_reject("\"ab\" =~ /(a)/\nx = $1\ny = $1\n", "regex match index differs from backreference token", "regex_lookup", ->(root : Iyi::ASTNode) {
      calls = derived_name_nodes(root).select { |node| node.is_a?(Iyi::Call) && node.name == "[]" }
      first = calls[0].as(Iyi::Call)
      second = calls[1].as(Iyi::Call)
      second.args = [first.args[0]] of Iyi::ASTNode
      nil
    })
  end

  it "refuses a parameter lowering whose source token is not scanned" do
    derived_name_reject("def f(@x)\nend\n", "parameter lowering source is not a scanned token", ->(root : Iyi::ASTNode) {
      arg = derived_name_nodes(root).find { |node| node.is_a?(Iyi::Arg) }.as(Iyi::Arg)
      original = derived_name_origin(arg, derived_name_primary)
      origin = Iyi::DiagnosticOrigin::DerivedName.new(derived_name_unscanned(original.source_token.not_nil!),
        original.definition_origin.not_nil!, original.parameter_slot.not_nil!, original.parameter_index.not_nil!,
        "Argument", original.projection.not_nil!, original.fresh_index)
      arg.diagnostic_name_slots = {derived_name_primary => [Iyi::DiagnosticNameValue::Derived.new(origin)] of Iyi::DiagnosticNameValue}
      nil
    })
  end

  it "refuses a parameter lowering placed outside its definition's parameter" do
    derived_name_reject("def f(@x)\nend\n", "parameter lowering outside its definition", ->(root : Iyi::ASTNode) {
      nodes = derived_name_nodes(root)
      arg = nodes.find { |node| node.is_a?(Iyi::Arg) }.as(Iyi::Arg)
      var = nodes.find { |node| node.is_a?(Iyi::Var) && node.name == "x" }.as(Iyi::Var)
      var.diagnostic_name_slots = {derived_name_primary => arg.diagnostic_name_slots[derived_name_primary]}
      nil
    })
  end

  it "refuses a parameter lowering that is claimed twice" do
    derived_name_reject("def f(@x)\n  @x\nend\n", "parameter lowering consumed twice", ->(root : Iyi::ASTNode) {
      ivars = derived_name_nodes(root).select { |node| node.is_a?(Iyi::InstanceVar) && node.name == "@x" }
      lowered = ivars.find { |node| node.diagnostic_name_slots[derived_name_primary][0].is_a?(Iyi::DiagnosticNameValue::Derived) }.not_nil!
      reader = ivars.find { |node| !node.same?(lowered) }.not_nil!
      reader.diagnostic_name_slots = {derived_name_primary => lowered.diagnostic_name_slots[derived_name_primary]}
      nil
    })
  end

  it "refuses a macro fresh variable whose name token is not a fresh-variable token" do
    derived_name_reject("macro m\n  %v\nend\n", "macro variable name lacks its fresh-variable token", ->(root : Iyi::ASTNode) {
      nodes = derived_name_nodes(root)
      macro_var = nodes.find { |node| node.is_a?(Iyi::MacroVar) }.as(Iyi::MacroVar)
      macro_def = nodes.find { |node| node.is_a?(Iyi::Macro) }.as(Iyi::Macro)
      macro_var.diagnostic_name_slots = {derived_name_primary => macro_def.diagnostic_name_slots[derived_name_primary]}
      nil
    })
  end
end

# An unbound walk (no replay journal or identity) refuses every derivation before it is bound.
private def derived_name_legacy_reject(source : String, message : String)
  [".cr", ".iyi"].each do |suffix|
    path = File.tempname("derived-name-legacy", suffix)
    File.write(path, source)
    begin
      parser = Iyi::Parser.new(source, nil, [Set(String).new], Iyi::WarningCollection.new)
      parser.filename = path
      ledger = Iyi::DiagnosticCaptureLedger.new
      root, claim, _ = Iyi::DiagnosticCaptureAuthority.record_source(ledger, parser)
      expect_raises(ArgumentError, message) { Iyi::DiagnosticRecordedEvidenceInputCheck.new(claim).verify!(root) }
    ensure
      File.delete(path) if File.file?(path)
    end
  end
end

describe "derived name binding unchanged-message controls" do
  it "refuses a derivation in an unbound walk before it is bound" do
    derived_name_legacy_reject("x = 1\nx += 1\n", "derived name requires independently resolved ancestry")
  end

  it "refuses a derived name kind that has no journal binding" do
    derived_name_reject("x = 1\ny = x\n", "derived name QuotedName has no journal binding", ->(root : Iyi::ASTNode) {
      var = derived_name_nodes(root).find { |node| node.is_a?(Iyi::Var) && node.name == "y" }.as(Iyi::Var)
      quoted = Iyi::DiagnosticOrigin::DerivedName.quoted_name("method_name", "a" * 64, 16, "Iyi", 0, 5, "abc")
      var.diagnostic_name_slots = {derived_name_primary => [Iyi::DiagnosticNameValue::Derived.new(quoted)] of Iyi::DiagnosticNameValue}
      nil
    })
  end

  it "refuses a regex lookup origin whose node has no Primary derivation" do
    derived_name_reject("\"ab\" =~ /(a)/\nx = $1\n", "unclassified structural origin ancestry", ->(root : Iyi::ASTNode) {
      call = derived_name_nodes(root).find { |node| node.is_a?(Iyi::Call) && node.name == "[]" }.as(Iyi::Call)
      call.diagnostic_name_slots = {} of Iyi::DiagnosticNameSlot => Array(Iyi::DiagnosticNameValue)
      nil
    })
  end

  it "refuses a node origin from another input" do
    derived_name_reject("x = 1\ny = x\n", "structural origin input identity mismatch", ->(root : Iyi::ASTNode) {
      var = derived_name_nodes(root).find { |node| node.is_a?(Iyi::Var) && node.name == "y" }.as(Iyi::Var)
      var.diagnostic_origin = Iyi::DiagnosticOrigin::Written.new("elsewhere", "elsewhere.cr", 0, "Name", "local_reference")
      nil
    })
  end

  it "refuses a name field that differs from its source token" do
    derived_name_reject("x = 1\ny = x\n", "name field differs from source evidence", ->(root : Iyi::ASTNode) {
      var = derived_name_nodes(root).find { |node| node.is_a?(Iyi::Var) && node.name == "y" }.as(Iyi::Var)
      var.name = "zz"
      nil
    })
  end
end

# The index of a parameter within its owner, by identity.
private def derived_name_arg_index(owner : Iyi::ASTNode, arg : Iyi::ASTNode) : Int32
  args = owner.is_a?(Iyi::Def) ? owner.args : owner.as(Iyi::Macro).args
  args.index { |item| item.same?(arg) } || raise "argument is not a parameter of its owner"
end

# Replays the source, applies a graph-changing mutation, then proves the full walk refuses at
# its graph boundary before the bare-splat guard runs directly on the mutated occurrence.
private def derived_name_bare_splat_walk(source : String, suffix : String, mutate : Proc(Iyi::ASTNode, Array(Iyi::ASTNode))) : Nil
  path = File.tempname("derived-name-bare-splat", suffix)
  File.write(path, source)
  begin
    parser = Iyi::Parser.new(source, nil, [Set(String).new], Iyi::WarningCollection.new)
    parser.filename = path
    ledger = Iyi::DiagnosticCaptureLedger.new
    _, claim, authority = Iyi::DiagnosticCaptureAuthority.record_source(ledger, parser)
    ledger.freeze!
    replay = claim.replay_parser
    replay.enable_diagnostic_observations
    root = claim.replay_entry(replay)
    Iyi::DiagnosticCaptureRefs.stamp!(root, authority.capture_key)
    journal = Iyi::DiagnosticReplayJournal.new(replay.diagnostic_lexical_observations)
    identity = Iyi::DiagnosticModuleIdentity.from(root, claim, journal)
    structural = Iyi::DiagnosticUnnamedParamBinder.new(claim, journal).verify!(root)
    bundle = Iyi::DiagnosticLiteralReplayAssociations.new(claim, journal, replay, root)
    pair = mutate.call(root)
    arg = pair[0]
    owner = pair[1]
    checker = Iyi::DiagnosticRecordedEvidenceInputCheck.new(claim, journal, identity, structural, bundle)
    expect_raises(ArgumentError, "literal replay graph differs") { checker.verify!(root) }
    checker.spec_bind_bare_splat!(arg, owner, derived_name_arg_index(owner, arg))
  ensure
    File.delete(path) if File.file?(path)
  end
end

private def derived_name_bare_splat_reject(source : String, message : String, mutate : Proc(Iyi::ASTNode, Array(Iyi::ASTNode)))
  [".cr", ".iyi"].each do |suffix|
    expect_raises(ArgumentError, message) { derived_name_bare_splat_walk(source, suffix, mutate) }
  end
end

describe "bare splat binding positives" do
  it "binds a bare splat in a Def followed by another parameter in both modes" do
    derived_name_accept("def f(*, y)\nend\n")
    derived_name_accept("def f(x, *, y)\nend\n")
    derived_name_accept("def f(*, y : Int32)\nend\n")
    derived_name_accept("def f(*, foo @x)\n  @x\nend\n")
    derived_name_accept("def f(*, @x, y)\nend\n")
  end

  it "binds a bare splat in a Macro declaration in both modes" do
    derived_name_accept("macro f(*, y)\nend\n")
    derived_name_accept("macro f(x, *, y)\nend\n")
  end

  it "keeps a named splat on its own evidence in both modes" do
    derived_name_accept("def f(*xs, y)\nend\n")
  end
end

describe "bare splat binding controls" do
  it "refuses bare splat evidence copied onto another parameter" do
    derived_name_reject("def f(*, y)\nend\n", "bare splat requires parser replay association", ->(root : Iyi::ASTNode) {
      nodes = derived_name_nodes(root)
      star = nodes.find { |node| node.is_a?(Iyi::Arg) && node.name.empty? }.as(Iyi::Arg)
      other = nodes.find { |node| node.is_a?(Iyi::Arg) && node.name == "y" }.as(Iyi::Arg)
      other.diagnostic_name_slots = {derived_name_primary => star.diagnostic_name_slots[derived_name_primary]}
      nil
    })
  end

  it "refuses bare splat evidence on a parameter renamed to a named splat" do
    derived_name_reject("def f(*, y)\nend\n", "bare splat evidence outside its parameter", ->(root : Iyi::ASTNode) {
      star = derived_name_nodes(root).find { |node| node.is_a?(Iyi::Arg) && node.name.empty? }.as(Iyi::Arg)
      star.name = "xs"
      nil
    })
  end

  it "refuses an explicit external name on a bare splat" do
    derived_name_reject("def f(*, y)\nend\n", "bare splat evidence outside its parameter", ->(root : Iyi::ASTNode) {
      star = derived_name_nodes(root).find { |node| node.is_a?(Iyi::Arg) && node.name.empty? }.as(Iyi::Arg)
      star.diagnostic_external_explicit = true
      nil
    })
  end

  it "refuses a changed external name on a bare splat" do
    derived_name_reject("def f(*, y)\nend\n", "bare splat evidence outside its parameter", ->(root : Iyi::ASTNode) {
      star = derived_name_nodes(root).find { |node| node.is_a?(Iyi::Arg) && node.name.empty? }.as(Iyi::Arg)
      star.external_name = "x"
      nil
    })
  end

  it "refuses a bare splat whose declaration lost its splat index" do
    derived_name_reject("def f(*, y)\nend\n", "bare splat evidence outside its parameter", ->(root : Iyi::ASTNode) {
      definition = derived_name_nodes(root).find { |node| node.is_a?(Iyi::Def) }.as(Iyi::Def)
      definition.splat_index = nil
      nil
    })
  end

  it "refuses bare splat evidence reused by a second declaration" do
    derived_name_reject("def f(*, y)\nend\ndef g(*, z)\nend\n", "bare splat evidence outside its parameter", ->(root : Iyi::ASTNode) {
      stars = derived_name_nodes(root).select { |node| node.is_a?(Iyi::Arg) && node.name.empty? }
      second = stars[1].as(Iyi::Arg)
      second.diagnostic_name_slots = {derived_name_primary => stars[0].as(Iyi::Arg).diagnostic_name_slots[derived_name_primary]}
      nil
    })
  end

  it "refuses a bare splat moved into another declaration" do
    derived_name_bare_splat_reject("def f(*, y)\nend\ndef g(*, z)\nend\n", "bare splat evidence outside its parameter", ->(root : Iyi::ASTNode) {
      defs = derived_name_nodes(root).select { |node| node.is_a?(Iyi::Def) }.map(&.as(Iyi::Def))
      star = defs[0].args[0]
      defs[1].args = [star, defs[1].args[1]] of Iyi::Arg
      [star, defs[1]] of Iyi::ASTNode
    })
  end

  it "refuses a bare splat that gains a restriction" do
    derived_name_bare_splat_reject("def f(*, y)\nend\n", "bare splat evidence outside its parameter", ->(root : Iyi::ASTNode) {
      definition = derived_name_nodes(root).find { |node| node.is_a?(Iyi::Def) }.as(Iyi::Def)
      star = definition.args[0]
      star.restriction = Iyi::Path.global(["Int32"])
      [star, definition] of Iyi::ASTNode
    })
  end

  it "refuses a bare splat with no following parameter" do
    derived_name_bare_splat_reject("def f(*, y)\nend\n", "bare splat evidence outside its parameter", ->(root : Iyi::ASTNode) {
      definition = derived_name_nodes(root).find { |node| node.is_a?(Iyi::Def) }.as(Iyi::Def)
      star = definition.args[0]
      definition.args = [star] of Iyi::Arg
      [star, definition] of Iyi::ASTNode
    })
  end
end

# ---- Guard-level mutation controls (ReviewBareSplat F3-F5) ----
#
# Every control first proves the unmutated walk binds, then changes one piece of
# evidence. Forged association lists and origin slots leave the replayed tree
# unchanged, so the named guard is the first refusal. Tree edits change the frozen
# graph, so those controls assert the graph refusal first, then call the guard
# directly on the mutated occurrence, as the scoped controls above do.

record BareSplatMutantContext,
  claim : Iyi::AcceptedCaptureInput,
  root : Iyi::ASTNode,
  journal : Iyi::DiagnosticReplayJournal,
  identity : Iyi::DiagnosticModuleIdentity,
  structural : Set(UInt64),
  replay : Iyi::Parser,
  observations : Array(Iyi::DiagnosticBareSplatObservation)

# One replayed source, built as the recorder builds it. The file is needed only while recording.
private def bare_splat_mutant_context(source : String, suffix : String) : BareSplatMutantContext
  path = File.tempname("bare-splat-mutant", suffix)
  File.write(path, source)
  begin
    parser = Iyi::Parser.new(source, nil, [Set(String).new], Iyi::WarningCollection.new)
    parser.filename = path
    ledger = Iyi::DiagnosticCaptureLedger.new
    _, claim, authority = Iyi::DiagnosticCaptureAuthority.record_source(ledger, parser)
    ledger.freeze!
    replay = claim.replay_parser
    replay.enable_diagnostic_observations
    root = claim.replay_entry(replay)
    Iyi::DiagnosticCaptureRefs.stamp!(root, authority.capture_key)
    journal = Iyi::DiagnosticReplayJournal.new(replay.diagnostic_lexical_observations)
    identity = Iyi::DiagnosticModuleIdentity.from(root, claim, journal)
    structural = Iyi::DiagnosticUnnamedParamBinder.new(claim, journal).verify!(root)
    BareSplatMutantContext.new(claim, root, journal, identity, structural, replay, replay.diagnostic_bare_splat_observations)
  ensure
    File.delete(path) if File.file?(path)
  end
end

# Spec-only hook. Production takes the association list from the parser alone. A control
# replaces that list on a bundle it built itself, so the binder meets forged evidence while
# the production constructor, its API and its callers stay as they are.
class Iyi::DiagnosticLiteralReplayAssociations
  def spec_replace_bare_splats!(observations : Array(Iyi::DiagnosticBareSplatObservation)) : Nil
    @bare_splats = observations.dup
    nil
  end
end

# The checker for one context. A list of observations replaces the parser's own list.
private def bare_splat_mutant_checker(context : BareSplatMutantContext,
                                      observations : Array(Iyi::DiagnosticBareSplatObservation)? = nil) : Iyi::DiagnosticRecordedEvidenceInputCheck
  bundle = Iyi::DiagnosticLiteralReplayAssociations.new(context.claim, context.journal, context.replay, context.root)
  bundle.spec_replace_bare_splats!(observations) if observations
  Iyi::DiagnosticRecordedEvidenceInputCheck.new(context.claim, context.journal, context.identity, context.structural, bundle)
end

# A checker with no association evidence at all.
private def bare_splat_bundleless_checker(context : BareSplatMutantContext) : Iyi::DiagnosticRecordedEvidenceInputCheck
  Iyi::DiagnosticRecordedEvidenceInputCheck.new(context.claim, context.journal, context.identity, context.structural)
end

private def bare_splat_def(root : Iyi::ASTNode) : Iyi::Def
  derived_name_nodes(root).find { |node| node.is_a?(Iyi::Def) }.as(Iyi::Def)
end

private def bare_splat_macro(root : Iyi::ASTNode) : Iyi::Macro
  derived_name_nodes(root).find { |node| node.is_a?(Iyi::Macro) }.as(Iyi::Macro)
end

private def bare_splat_star(root : Iyi::ASTNode) : Iyi::Arg
  derived_name_nodes(root).find { |node| node.is_a?(Iyi::Arg) && node.name.empty? }.as(Iyi::Arg)
end

private def bare_splat_star_origin(star : Iyi::Arg) : Iyi::DiagnosticOrigin::DerivedName
  derived_name_origin(star, derived_name_primary)
end

# A structural origin built through the constructor, which runs the anchor, witness and input checks.
private def bare_splat_rebuilt(context : BareSplatMutantContext, production : Iyi::DiagnosticStructuralProduction,
                               anchor : Iyi::DiagnosticOrigin, digest : String, bytesize : Int32,
                               witnesses : Array(Iyi::DiagnosticOperatorWitness),
                               fresh_index : Int32? = nil) : Iyi::DiagnosticOrigin::DerivedName
  Iyi::DiagnosticOrigin::DerivedName.structural_name(production, anchor, digest, bytesize, context.claim.lexical_mode, witnesses, fresh_index)
end

private def bare_splat_assign(node : Iyi::ASTNode, origin : Iyi::DiagnosticOrigin::DerivedName) : Nil
  node.diagnostic_name_slots = {derived_name_primary => [Iyi::DiagnosticNameValue::Derived.new(origin)] of Iyi::DiagnosticNameValue}
end

# A generated token event, as the expansion records it.
private def bare_splat_event(mode : String, start : Int32, finish : Int32, kind : String, raw : String) : Iyi::DiagnosticTokenEvent
  parts = [Iyi::DiagnosticEmissionPart::Generated.new(start, finish, nil, Iyi::DiagnosticMacroProducer::MacroTemplate)] of Iyi::DiagnosticEmissionPart
  Iyi::DiagnosticTokenEvent.new(start, finish, kind, raw, mode, Iyi::DiagnosticTokenSelection::Whole, parts)
end

# Baseline: the unmutated walk binds. The forged association list must make the full walk
# refuse with `message`. The tree is untouched, so no graph check can preempt the guard.
private def bare_splat_forged_refusal(source : String, message : String,
                                      &forge : BareSplatMutantContext -> Array(Iyi::DiagnosticBareSplatObservation)) : Nil
  [".cr", ".iyi"].each do |suffix|
    context = bare_splat_mutant_context(source, suffix)
    bare_splat_mutant_checker(context).verify!(context.root)
    forged = forge.call(context)
    expect_raises(ArgumentError, message) { bare_splat_mutant_checker(context, forged).verify!(context.root) }
  end
end

# Baseline, then one origin or slot edit that leaves the graph unchanged. The full walk must refuse.
private def bare_splat_slot_refusal(source : String, message : String, &mutate : BareSplatMutantContext -> Nil) : Nil
  [".cr", ".iyi"].each do |suffix|
    context = bare_splat_mutant_context(source, suffix)
    bare_splat_mutant_checker(context).verify!(context.root)
    mutate.call(context)
    expect_raises(ArgumentError, message) { bare_splat_mutant_checker(context).verify!(context.root) }
  end
end

# Baseline, then a tree edit to the star. The graph refusal must come first, and the guard
# must then refuse the mutated occurrence on its own.
private def bare_splat_scoped_refusal(source : String, message : String, &mutate : Iyi::Arg -> Nil) : Nil
  [".cr", ".iyi"].each do |suffix|
    context = bare_splat_mutant_context(source, suffix)
    checker = bare_splat_mutant_checker(context)
    checker.verify!(context.root)
    star = bare_splat_star(context.root)
    owner = bare_splat_def(context.root)
    mutate.call(star)
    expect_raises(ArgumentError, "literal replay graph differs") { checker.verify!(context.root) }
    expect_raises(ArgumentError, message) { checker.spec_bind_bare_splat!(star, owner, derived_name_arg_index(owner, star)) }
  end
end

describe "bare splat forged association controls" do
  it "refuses a bare splat with no parser association" do
    bare_splat_forged_refusal("def f(*, y)\nend\n", "bare splat requires parser replay association") do |context|
      [] of Iyi::DiagnosticBareSplatObservation
    end
  end

  it "refuses a bare splat whose association is duplicated" do
    bare_splat_forged_refusal("def f(*, y)\nend\n", "bare splat association is duplicated") do |context|
      original = context.observations[0]
      [original, original]
    end
  end

  it "refuses an association that no walk claims" do
    bare_splat_forged_refusal("def f(*, y)\nend\n", "bare splat association unclaimed") do |context|
      original = context.observations[0]
      orphan = Iyi::DiagnosticBareSplatObservation.new(original.owner.as(Iyi::Def), Iyi::Arg.new(""), 0, original.keyword, original.star, original.comma)
      [original, orphan]
    end
  end

  it "refuses an association whose owner is outside the frozen replay graph" do
    bare_splat_forged_refusal("def f(*, y)\nend\n", "bare splat evidence outside its parameter") do |context|
      original = context.observations[0]
      unfrozen = Iyi::DiagnosticBareSplatObservation.new(Iyi::Def.new("f"), original.argument, original.index, original.keyword, original.star, original.comma)
      [unfrozen]
    end
  end

  it "refuses a def parameter whose association names a macro owner" do
    bare_splat_forged_refusal("def f(*, y)\nend\nmacro g(z)\nend\n", "bare splat evidence outside its parameter") do |context|
      original = context.observations[0]
      macro_owner = bare_splat_macro(context.root)
      [Iyi::DiagnosticBareSplatObservation.new(macro_owner, original.argument, original.index, original.keyword, original.star, original.comma)]
    end
  end

  it "refuses a macro parameter whose association names a def owner" do
    bare_splat_forged_refusal("macro g(*, y)\nend\ndef f(z)\nend\n", "bare splat evidence outside its parameter") do |context|
      original = context.observations[0]
      def_owner = bare_splat_def(context.root)
      [Iyi::DiagnosticBareSplatObservation.new(def_owner, original.argument, original.index, original.keyword, original.star, original.comma)]
    end
  end

  it "refuses an association whose index is not the parameter's position" do
    bare_splat_forged_refusal("def f(x, *, y)\nend\n", "bare splat evidence outside its parameter") do |context|
      original = context.observations[0]
      [Iyi::DiagnosticBareSplatObservation.new(original.owner.as(Iyi::Def), original.argument, 0, original.keyword, original.star, original.comma)]
    end
  end

  it "refuses an association with a negative index" do
    bare_splat_forged_refusal("def f(x, *, y)\nend\n", "bare splat evidence outside its parameter") do |context|
      original = context.observations[0]
      [Iyi::DiagnosticBareSplatObservation.new(original.owner.as(Iyi::Def), original.argument, -1, original.keyword, original.star, original.comma)]
    end
  end

  it "refuses an association whose keyword is not the declaration keyword" do
    bare_splat_forged_refusal("def f(*, y)\nend\n", "bare splat witness differs from replay") do |context|
      original = context.observations[0]
      [Iyi::DiagnosticBareSplatObservation.new(original.owner.as(Iyi::Def), original.argument, original.index, original.star, original.star, original.comma)]
    end
  end

  it "refuses an association whose star is not the star token" do
    bare_splat_forged_refusal("def f(*, y)\nend\n", "bare splat witness differs from replay") do |context|
      original = context.observations[0]
      [Iyi::DiagnosticBareSplatObservation.new(original.owner.as(Iyi::Def), original.argument, original.index, original.keyword, original.comma, original.comma)]
    end
  end

  it "refuses an association whose comma is not the comma token" do
    bare_splat_forged_refusal("def f(*, y)\nend\n", "bare splat witness differs from replay") do |context|
      original = context.observations[0]
      [Iyi::DiagnosticBareSplatObservation.new(original.owner.as(Iyi::Def), original.argument, original.index, original.keyword, original.star, original.star)]
    end
  end

  it "refuses bare splat evidence when the association list is absent from the walk" do
    [".cr", ".iyi"].each do |suffix|
      context = bare_splat_mutant_context("def f(*, y)\nend\n", suffix)
      bare_splat_mutant_checker(context).verify!(context.root)
      expect_raises(ArgumentError, "bare splat requires parser replay association") do
        bare_splat_bundleless_checker(context).verify!(context.root)
      end
    end
  end
end

describe "bare splat origin and anchor controls" do
  it "refuses a bare splat origin that names another input digest" do
    bare_splat_slot_refusal("def f(*, y)\nend\n", "structural witnesses use different inputs") do |context|
      star = bare_splat_star(context.root)
      origin = bare_splat_star_origin(star)
      rebuilt = bare_splat_rebuilt(context, Iyi::DiagnosticStructuralProduction::BareSplatParameter,
        origin.structural_anchor.as(Iyi::DiagnosticOrigin), "0" * 64, context.claim.input_bytesize, origin.structural_witnesses)
      bare_splat_assign(star, rebuilt)
      nil
    end
  end

  it "refuses a bare splat origin that names another input length" do
    bare_splat_slot_refusal("def f(*, y)\nend\n", "structural witnesses use different inputs") do |context|
      star = bare_splat_star(context.root)
      origin = bare_splat_star_origin(star)
      rebuilt = bare_splat_rebuilt(context, Iyi::DiagnosticStructuralProduction::BareSplatParameter,
        origin.structural_anchor.as(Iyi::DiagnosticOrigin), context.claim.input_sha256, context.claim.input_bytesize + 1, origin.structural_witnesses)
      bare_splat_assign(star, rebuilt)
      nil
    end
  end

  it "refuses a bare splat anchor from another source module" do
    bare_splat_slot_refusal("def f(*, y)\nend\n", "invalid structural anchor") do |context|
      star = bare_splat_star(context.root)
      origin = bare_splat_star_origin(star)
      anchor = origin.structural_anchor.as(Iyi::DiagnosticOrigin::Written)
      foreign = Iyi::DiagnosticOrigin::Written.new("elsewhere", "elsewhere.cr", anchor.input_byte_offset, "Def", "keyword")
      rebuilt = bare_splat_rebuilt(context, Iyi::DiagnosticStructuralProduction::BareSplatParameter,
        foreign, context.claim.input_sha256, context.claim.input_bytesize, origin.structural_witnesses)
      bare_splat_assign(star, rebuilt)
      nil
    end
  end

  it "refuses a bare splat anchor that is not the declaration keyword" do
    bare_splat_slot_refusal("def f(*, y)\nend\n", "invalid structural anchor") do |context|
      star = bare_splat_star(context.root)
      origin = bare_splat_star_origin(star)
      anchor = origin.structural_anchor.as(Iyi::DiagnosticOrigin::Written)
      call_role = Iyi::DiagnosticOrigin::Written.new(anchor.source_module, anchor.source_file, anchor.input_byte_offset, "Call", "method")
      rebuilt = bare_splat_rebuilt(context, Iyi::DiagnosticStructuralProduction::BareSplatParameter,
        call_role, context.claim.input_sha256, context.claim.input_bytesize, origin.structural_witnesses)
      bare_splat_assign(star, rebuilt)
      nil
    end
  end

  it "refuses a bare splat whose declaration origin is not its anchor" do
    bare_splat_slot_refusal("def f(*, y)\nend\n", "bare splat evidence outside its parameter") do |context|
      owner = bare_splat_def(context.root)
      anchor = owner.diagnostic_origin.as(Iyi::DiagnosticOrigin::Written)
      owner.diagnostic_origin = Iyi::DiagnosticOrigin::Written.new(anchor.source_module, anchor.source_file, anchor.input_byte_offset + 1, "Def", "keyword")
      nil
    end
  end

  it "refuses an expanded bare splat until its expansion authority is integrated" do
    bare_splat_slot_refusal("def f(*, y)\nend\n", "expanded bare splat requires resolved expansion ancestry (contract X)") do |context|
      star = bare_splat_star(context.root)
      origin = bare_splat_star_origin(star)
      mode = context.claim.lexical_mode
      invocation = Iyi::DiagnosticOrigin::Written.new("expanded", "expanded.cr", 0, "Macro", "keyword")
      keyword = Iyi::DiagnosticOrigin::Expanded.new(invocation, invocation, "sha256:#{context.claim.input_sha256}", "Def", "keyword",
        nil, bare_splat_event(mode, 0, 3, "IDENT", "def"), Iyi::DiagnosticAnchorUse::Direct.new)
      witnesses = origin.structural_witnesses.map do |witness|
        event = bare_splat_event(mode, witness.input_start, witness.input_end, witness.token_kind, witness.raw_text)
        Iyi::DiagnosticOperatorWitness.new(witness.input_start, witness.input_end, witness.token_kind, witness.raw_text, Iyi::DiagnosticTokenSelection::Whole, event)
      end
      rebuilt = bare_splat_rebuilt(context, Iyi::DiagnosticStructuralProduction::BareSplatParameter,
        keyword, context.claim.input_sha256, context.claim.input_bytesize, witnesses)
      bare_splat_assign(star, rebuilt)
      nil
    end
  end

  it "refuses a bare splat origin whose anchor does not precede its star at construction" do
    [".cr", ".iyi"].each do |suffix|
      context = bare_splat_mutant_context("def f(*, y)\nend\n", suffix)
      origin = bare_splat_star_origin(bare_splat_star(context.root))
      anchor = origin.structural_anchor.as(Iyi::DiagnosticOrigin::Written)
      late = Iyi::DiagnosticOrigin::Written.new(anchor.source_module, anchor.source_file, origin.structural_witnesses[0].input_start, "Def", "keyword")
      expect_raises(ArgumentError, "anchor does not precede witnesses") do
        bare_splat_rebuilt(context, Iyi::DiagnosticStructuralProduction::BareSplatParameter,
          late, context.claim.input_sha256, context.claim.input_bytesize, origin.structural_witnesses)
      end
    end
  end

  it "refuses a bare splat origin that carries a fresh index at construction" do
    [".cr", ".iyi"].each do |suffix|
      context = bare_splat_mutant_context("def f(*, y)\nend\n", suffix)
      origin = bare_splat_star_origin(bare_splat_star(context.root))
      expect_raises(ArgumentError, "structural witness differs") do
        bare_splat_rebuilt(context, Iyi::DiagnosticStructuralProduction::BareSplatParameter,
          origin.structural_anchor.as(Iyi::DiagnosticOrigin), context.claim.input_sha256, context.claim.input_bytesize,
          origin.structural_witnesses, 0)
      end
    end
  end

  it "refuses a bare splat origin whose witnesses are out of order at construction" do
    [".cr", ".iyi"].each do |suffix|
      context = bare_splat_mutant_context("def f(*, y)\nend\n", suffix)
      origin = bare_splat_star_origin(bare_splat_star(context.root))
      expect_raises(ArgumentError, "structural witness differs") do
        bare_splat_rebuilt(context, Iyi::DiagnosticStructuralProduction::BareSplatParameter,
          origin.structural_anchor.as(Iyi::DiagnosticOrigin), context.claim.input_sha256, context.claim.input_bytesize,
          origin.structural_witnesses.reverse)
      end
    end
  end
end

describe "bare splat parameter guard controls" do
  it "refuses a bare splat that gains a default value" do
    bare_splat_scoped_refusal("def f(*, y)\nend\n", "bare splat evidence outside its parameter") do |star|
      star.default_value = Iyi::Path.global(["Int32"])
      nil
    end
  end

  it "refuses bare splat evidence on a node that is not a parameter" do
    [".cr", ".iyi"].each do |suffix|
      context = bare_splat_mutant_context("def f(*, y)\nend\n", suffix)
      checker = bare_splat_mutant_checker(context)
      checker.verify!(context.root)
      star = bare_splat_star(context.root)
      owner = bare_splat_def(context.root)
      var = Iyi::Var.new("z")
      var.diagnostic_name_slots = {derived_name_primary => star.diagnostic_name_slots[derived_name_primary]}
      expect_raises(ArgumentError, "bare splat evidence outside its parameter") do
        checker.spec_bind_bare_splat!(var, owner, derived_name_arg_index(owner, star))
      end
    end
  end

  it "refuses bare splat evidence that also carries an ExternalName slot" do
    [".cr", ".iyi"].each do |suffix|
      context = bare_splat_mutant_context("def f(*, y)\nend\n", suffix)
      checker = bare_splat_mutant_checker(context)
      checker.verify!(context.root)
      star = bare_splat_star(context.root)
      owner = bare_splat_def(context.root)
      values = star.diagnostic_name_slots[derived_name_primary]
      star.diagnostic_name_slots = {derived_name_primary => values,
                                    Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::ExternalName) => values}
      expect_raises(ArgumentError, "bare splat evidence outside its parameter") do
        checker.spec_bind_bare_splat!(star, owner, derived_name_arg_index(owner, star))
      end
    end
  end

  it "refuses a second claim of the same bare splat association" do
    [".cr", ".iyi"].each do |suffix|
      context = bare_splat_mutant_context("def f(*, y)\nend\n", suffix)
      checker = bare_splat_mutant_checker(context)
      checker.verify!(context.root)
      star = bare_splat_star(context.root)
      owner = bare_splat_def(context.root)
      index = derived_name_arg_index(owner, star)
      checker.spec_bind_bare_splat!(star, owner, index)
      expect_raises(ArgumentError, "bare splat association consumed twice") do
        checker.spec_bind_bare_splat!(star, owner, index)
      end
    end
  end

  it "refuses a bare splat whose star and comma are separated by a newline" do
    [".cr", ".iyi"].each do |suffix|
      expect_raises(ArgumentError, "unwitnessed grammar gap") do
        derived_name_bind("def f(*\n, y)\nend\n", suffix) { |_| nil }
      end
    end
  end
end

describe "bare splat binding positives, F5 shapes" do
  it "binds a spaced bare splat in both modes" do
    derived_name_accept("def f(* , y)\nend\n")
  end

  it "binds an escaped newline between the star and comma in both modes" do
    derived_name_accept("def f(*\\\n, y)\nend\n")
  end

  it "binds a bare splat with downstream positional arguments in both modes" do
    derived_name_accept("def f(*, y, z)\nend\n")
  end

  it "binds a bare splat before a double splat and a block argument in both modes" do
    derived_name_accept("def f(*, y, **o)\nend\n")
    derived_name_accept("def f(*, y, &b)\nend\n")
  end

  it "binds an annotated bare splat in both modes" do
    derived_name_accept("def f(@[Foo] *, y)\nend\n")
    derived_name_accept("macro f(x, @[Foo] *, y)\nend\n")
  end

  it "binds the macro fixture shapes in both modes" do
    derived_name_accept("macro foo(*, __var var)\nend\n")
    derived_name_accept("macro foo(*, var)\nend\n")
  end
end
