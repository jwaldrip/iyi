# Call census oracle for bench/selfhost_semantic_calls_census_exercise.sh.
#
#   selfhost_semantic_calls_census_oracle <file.iyi> [--prelude-only]
#
# Compiles the file the way the typed oracle does (the prelude, then the file,
# through the top-level pass and the main pass), then prints one line for each
# call site of the file the hosted pass reached, in tree order. Each line is tab
# separated:
#
#   <line>:<col> T <name> <receiver> <argument types> <named> <block> <result>
#   <line>:<col> U <reason>
#
# A T line is a call whose receiver, arguments and named arguments the hosted pass
# typed. <receiver> is the hosted receiver type (`PROGRAM` for the program, `-`
# never appears), <argument types> are joined by `;` or `-`, <named> is `name=type`
# joined by `;` or `-`, and <block> is 1 when the call has a block literal. <result>
# is the hosted lookup (`Type#lookup_matches`, analyze_all off) in the same form as
# bench/selfhost_semantic_calls_oracle.cr: `<owner>::<name>(<restrictions>) -> <ret>`
# joined by `; `, `none`, with ` [cover all]` when the list covers every argument
# combination, or `error: <first line>`.
#
# A U line is a call the census does not measure, with the reason: the hosted pass
# did not type its receiver or an argument (`receiver-untyped`, `argument-untyped`),
# or the call is one the hosted pass answers outside lookup: a macro expansion
# (`macro`), `super` and `previous_def` (`special:<name>`), a call with a scope
# (`with-scope`), a block argument (`block-arg`), or a splat (`splat`).
#
# The port's driver (bench/selfhost_semantic_calls_census_exercise.iyi) reads these
# lines and prints the same result for each T line, from the receiver and argument
# types alone. Only lookup and matching are compared; the bodies slice, which types
# the arguments, is not involved.
require "compiler/requires"

class Iyi::Compiler
  # iyi: the compile's own sequence (parse and prelude, top-level pass, main pass),
  # as bench/selfhost_typed_oracle.cr runs it.
  def census_program(source : Iyi::Compiler::Source, prelude_only : Bool) : {Program, ASTNode}
    program = new_program([source])
    node = if prelude_only
             location = Iyi::Location.new(program.filename, 1, 1)
             program.normalize(Iyi::Expressions.new([Iyi::Require.new(prelude).tap(&.iyi_prelude=(true)).at(location)] of Iyi::ASTNode))
           else
             parse(program, [source])
           end
    node, processor = program.top_level_semantic(node)
    node = program.semantic_after_top_level(node, processor, cleanup: false)
    {program, node}
  end
end

RECEIVER_PROGRAM = "PROGRAM"

# The type text the port reads back: the name as the hosted compile prints it,
# without a leading `::`.
def type_text(t : Iyi::Type) : String
  text = t.is_a?(Iyi::NamedType) ? t.full_name : t.to_s
  text.sub(/^::/, "")
end

# The matches of a receiver for a signature, and whether they cover every
# argument combination. A union receiver is one lookup per member, in member order.
def dispatch_matches(receiver : Iyi::Type, signature : Iyi::CallSignature) : {Array(Iyi::Match), Bool}
  if receiver.is_a?(Iyi::UnionType)
    all = [] of Iyi::Match
    cover = true
    receiver.as(Iyi::UnionType).union_types.each do |member|
      found, member_cover = dispatch_matches(member, signature)
      all.concat(found)
      cover = false unless member_cover
    end
    return {all, cover}
  end
  # A trait receiver is looked up over the types that implement it, as the hosted
  # call pass dispatches it (NonGenericModuleType#including_types).
  if receiver.is_a?(Iyi::TraitType)
    including = receiver.as(Iyi::TraitType).including_types
    return {[] of Iyi::Match, false} if including.nil?
    return dispatch_matches(including.as(Iyi::Type), signature)
  end
  matches = receiver.lookup_matches(signature)
  {matches.matches || [] of Iyi::Match, matches.cover_all? == true}
end

def restriction_text(owner : Iyi::Type, restriction : Iyi::ASTNode?) : String
  return "_" if restriction.nil?
  owner.lookup_type(restriction).to_s
end

def match_text(m : Iyi::Match) : String
  scope = m.context.defining_type
  restrictions = m.def.args.map { |arg| restriction_text(scope, arg.restriction) }
  ret = m.def.return_type
  ret_text = ret.nil? ? "needs body typing" : scope.lookup_type(ret).to_s
  "#{m.context.instantiated_type.to_s}::#{m.def.name}(#{restrictions.join(", ")}) -> #{ret_text}"
end

# The hosted lookup result of a T line, as bench/selfhost_semantic_calls_oracle.cr
# writes it.
def lookup_text(recv : Iyi::Type, call : Iyi::Call, arg_types : Array(Iyi::Type), named_types : Array(Iyi::NamedArgumentType)?) : String
  signature = Iyi::CallSignature.new(call.name, arg_types, call.block, named_types)
  found, cover = dispatch_matches(recv, signature)
  return "none" if found.empty?
  text = found.map { |m| match_text(m) }.join("; ")
  text += " [cover all]" if cover
  text
rescue ex : Exception
  "error: #{ex.message.to_s.lines.first? || ""}"
end

# The census line of one hosted call site, keyed by its location.
def census_line(call : Iyi::Call, key : String) : String
  return "#{key}\tU\tmacro" if call.expanded || call.expanded_macro
  return "#{key}\tU\tspecial:#{call.name}" if call.name == "super" || call.name == "previous_def"
  return "#{key}\tU\twith-scope" if call.with_scope
  return "#{key}\tU\tblock-arg" if call.block_arg
  return "#{key}\tU\tsplat" if call.args.any? { |arg| arg.is_a?(Iyi::Splat) || arg.is_a?(Iyi::DoubleSplat) }

  arg_types = [] of Iyi::Type
  call.args.each do |arg|
    t = arg.type?
    return "#{key}\tU\targument-untyped" if t.nil?
    arg_types << t.as(Iyi::Type)
  end

  named_types = nil
  if named = call.named_args
    named_types = [] of Iyi::NamedArgumentType
    named.each do |na|
      t = na.value.type?
      return "#{key}\tU\targument-untyped" if t.nil?
      named_types << Iyi::NamedArgumentType.new(na.name, t.as(Iyi::Type))
    end
  end

  recv = if obj = call.obj
           obj.type?
         else
           call.scope?
         end
  return "#{key}\tU\treceiver-untyped" if recv.nil?
  recv_type = recv.as(Iyi::Type)

  recv_text = recv_type.is_a?(Iyi::Program) ? RECEIVER_PROGRAM : type_text(recv_type)
  args_text = arg_types.empty? ? "-" : arg_types.map { |t| type_text(t) }.join(";")
  named_text = named_types.nil? || named_types.empty? ? "-" : named_types.map { |n| "#{n.name}=#{type_text(n.type)}" }.join(";")
  block_text = call.block ? "1" : "0"
  result = lookup_text(recv_type, call, arg_types, named_types)
  "#{key}\tT\t#{call.name}\t#{recv_text}\t#{args_text}\t#{named_text}\t#{block_text}\t#{result}"
end

# Walks the tree and records every call site located in the file, entering each
# required file's expansion as the typed oracle does.
class CallCensusWalk < Iyi::Visitor
  getter lines = [] of String

  def initialize(@file : String, @root : Iyi::ASTNode)
    @absolute = File.expand_path(@file)
  end

  def visit_any(node)
    return true if node.object_id == @root.object_id
    if node.is_a?(Iyi::Require)
      if expanded = node.expanded
        expanded.accept(self)
      end
      return true if node.iyi_prelude?
    end
    if node.is_a?(Iyi::Call) && (loc = node.location) && (name = loc.filename).is_a?(String) && File.expand_path(name) == @absolute
      @lines << census_line(node.as(Iyi::Call), "#{loc.line_number}:#{loc.column_number}")
    end
    true
  end

  def visit(node)
    true
  end
end

path = ARGV.find { |arg| !arg.starts_with?("--") } || abort("usage: selfhost_semantic_calls_census_oracle <file.iyi> [--prelude-only]")
prelude_only = ARGV.includes?("--prelude-only")

begin
  compiler = Iyi::Compiler.new
  compiler.prelude = "iyi/prelude"
  compiler.no_codegen = true
  compiler.stdout = IO::Memory.new
  compiler.stderr = IO::Memory.new
  source = Iyi::Compiler::Source.new(path, File.read(path))
  _, node = compiler.census_program(source, prelude_only)
  walk = CallCensusWalk.new(path, node)
  node.accept(walk)
  walk.lines.each { |line| puts line }
rescue ex : Exception
  STDERR.puts "ERROR: #{ex.message.to_s.lines.first? || ""}"
  exit 2
end
