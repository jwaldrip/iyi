require "../syntax/transformer"

# iyi: the `repl` command, the first slice of an interpreter for the language
# itself. This reopens what SPEC.md Appendix B #11 settled (V.11 removed
# Crystal's interpreter), and the reopened call is Appendix B #25, on the terms
# III.11 states: the owner asked for a REPL with Elixir's `iex` as the
# reference, and the base is the macro interpreter that stayed, not the runtime
# interpreter that left.
#
# Why that base: the removed interpreter was 11,377 lines with 380 more of
# libffi bindings, interpreted Crystal rather than iyi, and died on an iyi
# module header, so reverting it buys a second implementation of the wrong
# language and reintroduces C interop, which is the one dependency a session
# must never grow back. The macro interpreter (`macros/interpreter.cr`, 781
# lines) is already a complete AST evaluator that resolves types, so most of
# the distance from a line to an answer is printing the result. Both are a
# second implementation of the semantics, the thing V.11 objected to; this one
# starts 10,596 lines smaller and already runs iyi's macros.
#
# No path below calls C. A line that declares a lib or an extern reaches the
# interpreter's refusal visit, raises, and the loop catches it: interpreted
# code has no route out to C, which is why libffi never comes back. The gate
# is bench/dependency_floor.sh, proven to fire, so this is enforced rather
# than trusted.
#
# The slice is a walking skeleton on purpose: banner, prompt, one line in,
# value or error out, loop, `.exit` or Ctrl-D. Session state is the macro
# interpreter's own variable table, so `x = 1` then `x + 1` answers 2.
# Nothing wider is built until this much runs end to end.
class Iyi::Command
  private def repl
    program = Program.new

    # A line is evaluated the way a macro body is: the program is both scope
    # and path lookup, so `Int32` in a line resolves the way `{{ Int32 }}`
    # already does. One interpreter per session, because its variable table
    # is the session's memory.
    interpreter = MacroInterpreter.new(program, program, program, nil)
    interactive = STDIN.tty? && STDOUT.tty?

    if interactive
      puts "#{Command.program_name} repl, on the macro evaluator (SPEC.md III.11)"
      puts "A line of iyi at a time; .exit or Ctrl-D leaves."
    end

    loop do
      print "#{Command.program_name}> " if interactive
      STDOUT.flush if interactive

      line = STDIN.gets
      break unless line

      # `.exit` is checked before the parser because a leading dot is not iyi
      # syntax: it is the session's own vocabulary, not the language's.
      stripped = line.strip
      next if stripped.empty?
      break if stripped == ".exit"

      begin
        parser = program.new_parser(line)
        parser.filename = "(repl)"
        # Each line is a fresh parse unit, so Crystal reads a bare `x` as
        # a Call, not a Var. The session already knows the name: rewrite
        # it before evaluation so `x = 6` then `x * 7` answers 42.
        ast = parser.parse
        names = Set.new(interpreter.var_names)
        ast = ast.transform(SessionVars.new(names))
        result = interpreter.accept(ast)
        unless result.is_a?(Nop) || (result.is_a?(Expressions) && result.expressions.empty?)
          puts result
        end
      rescue ex : Iyi::CodeError
        # A bad line prints and the prompt comes back. An interpreter that
        # dies on the first typo is worse than one that admits the line.
        ex.color = @color
        ex.error_trace = @error_trace
        STDERR.puts ex
      rescue ex
        # Anything else (a plain ::Exception out of the evaluator) still must
        # not take the session down with it.
        STDERR.puts "repl: #{ex.message || ex.class.name}"
      end
    end
  end

  # A parse-unit rewrite, not a second evaluator: only the names the
  # session already holds (plus assigns in this same line) become Vars.
  class SessionVars < Transformer
    def initialize(@names : Set(String))
    end

    def transform(node : Call)
      node = super
      return node unless node.is_a?(Call)
      return node if node.obj || !node.args.empty? || node.named_args || node.block || node.block_arg
      return node unless @names.includes?(node.name)
      Var.new(node.name).at(node)
    end

    def transform(node : Assign)
      node = super
      if node.is_a?(Assign) && (target = node.target).is_a?(Var)
        @names.add(target.name)
      end
      node
    end
  end
end
