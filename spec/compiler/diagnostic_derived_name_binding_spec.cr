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
