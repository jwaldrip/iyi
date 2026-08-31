# iyi: `iyi check` — the front end's verdict, with the blind spot closed.
#
# The cheapest question an agent can ask the compiler is "is this
# program well-typed?", and until now the CLI only answered it as a side
# effect of producing a binary. `check` is `build --no-codegen` with its
# name said plainly — no object files, no linker, no artifact; the
# verdict is the exit code, and under `-f json` every error arrives as
# data, `suggested_edit` included.
#
# A build's answer has a hole: a def nobody calls is typed when somebody
# calls it — the lazy typing inherited from Crystal — so a build says
# "clean" about a body it never visited, and an agent that edits a def,
# checks, and ships finds the bug when the first caller lands. R-2 is
# what closes it: a fully declared signature is exactly enough to type
# the body without a caller. So `check` runs a second front-end pass
# with a synthetic probe appended — for every def whose parameters and
# return are all written, one call with `uninitialized` values of the
# declared types, under `if false` so nothing could ever run — and the
# compiler types the body against the declaration. Crystal cannot offer
# this; here it falls out of the rule that signatures are written down.
#
# What the probe does not reach, stated rather than hidden: defs with
# generic free vars or block parameters (there is no one type to probe
# with), defs whose parameters are unannotated (nothing declared to
# check against — the build's lazy answer is all there is), generic and
# abstract types. `--shallow` skips the probe pass entirely and gives
# the build's exact answer.
require "../mod/installer"

class Iyi::Command
  private def check
    if options.first?.in?("--help", "-h")
      puts <<-USAGE
        Usage: #{Command.program_name} check [switches] [program file]

        Type-check the program and produce nothing: no codegen, no
        binary. Exit 0 means well-typed; errors print like a build's,
        and `-f json` makes each one data — file, line, column, size,
        message, the SPEC sections it cites, and, when the compiler
        knows the fix, a `suggested_edit` with the exact replacement.

        Beyond a build's answer, every def with a fully written
        signature is typed even if nothing calls it — R-2's declared
        types stand in for the missing caller. `--shallow` gives the
        build's exact (lazy) answer instead.
        USAGE
      exit
    end

    deep = !options.delete("--shallow")
    entry = options.find { |option| !option.starts_with?('-') && option.ends_with?(".iyi") }

    compile_no_codegen "check"
    report_warnings
    exit 1 if warnings_fail_on_exit?

    return unless deep && entry && File.file?(entry)
    probe = check_probe_source(entry)
    return unless probe

    # The probe pass: the same front end, the entry's own text plus the
    # probe block. Errors raise through to the one rescue that serves
    # every verb, so `-f json` and `suggested_edit` work here unchanged.
    # A trace frame can land on a probe line (past the file's end); the
    # anchor error lands in the body it names, which is the answer.
    entry_path = File.expand_path(entry)
    compiler = Compiler.new
    compiler.prelude = "iyi/prelude"
    compiler.no_codegen = true
    compiler.iyi_mod_table = Mod::Installer.table_for(File.dirname(entry_path))
    compiler.compile(
      Compiler::Source.new(entry_path, File.read(entry_path) + probe),
      File.tempname("iyi-check", nil))
  end

  # The probe block for every fully declared def in the file, or nil when
  # nothing qualifies. Eligibility is "the declaration says enough", not
  # "the def is pub": R-2 only *forces* the writing on exports, but any
  # def that wrote its types down has bought the same right to be checked
  # without a caller.
  private def check_probe_source(filename : String, text : String = File.read(filename)) : String?
    parser = Parser.new(text)
    parser.filename = filename
    nodes = parser.parse

    lines = [] of String
    serial = 0
    fresh = -> { serial += 1; "__iyi_check_#{serial}" }

    probe_def = ->(a_def : Def, receiver_type : String?) do
      return unless check_probable?(a_def)
      args = a_def.args.map do |arg|
        name = fresh.call
        lines << "  #{name} = uninitialized #{arg.restriction}"
        name
      end
      call =
        if receiver_type
          holder = fresh.call
          lines << "  #{holder} = uninitialized #{receiver_type}"
          "#{holder}.#{a_def.name}(#{args.join(", ")})"
        elsif (receiver = a_def.receiver) && receiver.to_s == "self"
          return # class methods need the type's name in scope; not from here
        else
          "#{a_def.name}(#{args.join(", ")})"
        end
      returns = a_def.return_type.to_s
      if returns == "Nil"
        lines << "  #{call}"
      else
        lines << "  #{fresh.call} : #{returns} = #{call}"
      end
    end

    walk = uninitialized Proc(ASTNode, Nil)
    walk = ->(node : ASTNode) do
      case node
      when Expressions
        node.expressions.each { |child| walk.call(child) }
      when ModuleDef
        walk.call(node.body)
      when Def
        probe_def.call(node, nil)
      when ClassDef
        # A concrete, monomorphic type: its methods can be probed on an
        # `uninitialized` receiver. Generic or abstract types have no one
        # receiver to make, so their bodies stay caller-typed.
        return if node.type_vars || node.abstract?
        type_name = node.name.to_s
        body = node.body
        members = body.is_a?(Expressions) ? body.expressions : [body]
        members.each do |member|
          next unless member.is_a?(Def)
          next if member.name == "initialize"
          next if member.receiver
          probe_def.call(member, type_name)
        end
      else
        # Nothing else declares a probable body at this level.
      end
    end
    walk.call(nodes)

    return nil if lines.empty?
    "\nif false\n#{lines.join('\n')}\nend\n"
  end

  # A def the probe can honestly call: every parameter carries a written
  # type, the return is written, and there is no shape the probe cannot
  # synthesise — no block, no splats, no free vars, a plainly callable
  # name.
  private def check_probable?(a_def : Def) : Bool
    return false if a_def.block_arity || a_def.block_arg
    return false if a_def.splat_index || a_def.double_splat
    return false if (free_vars = a_def.free_vars) && !free_vars.empty?
    return false unless a_def.return_type
    return false if a_def.abstract?
    return false unless a_def.name.each_char.all? { |ch| ch.alphanumeric? || ch == '_' || ch.in?('?', '!') }
    return false unless a_def.name[0].lowercase? || a_def.name[0] == '_'
    a_def.args.all? do |arg|
      restriction = arg.restriction
      restriction && !restriction.to_s.includes?("self") &&
        !arg.default_value && arg.external_name == arg.name
    end
  end
end
