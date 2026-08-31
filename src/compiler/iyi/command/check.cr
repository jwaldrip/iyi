# iyi: `iyi check` — the front end's verdict and nothing else.
#
# The cheapest question an agent can ask the compiler is "is this
# program well-typed?", and until now the CLI only answered it as a side
# effect of producing a binary. `check` is `build --no-codegen` with its
# name said plainly: parse, expand, type, then stop. No object files, no
# linker, no artifact — the verdict is the exit code, and under
# `-f json` every error arrives as data, `suggested_edit` included.
#
# It checks exactly what a build checks — no more. A def nobody calls is
# typed when somebody calls it — the lazy typing inherited from Crystal —
# so a clean `check` means "this program compiles", not "every body in
# this file has been visited". Saying that plainly beats a verb that
# quietly promises more than the compiler does.
#
# This is the same compile the language server runs on every keystroke
# (SPEC.md III.8 #2): ~tens of milliseconds on a module-local unit. The
# verb exists for everything that is not an LSP client — CI steps,
# scripts, and agents that want one process, one answer.
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
        USAGE
      exit
    end

    compile_no_codegen "check"

    # Nothing to print on success: the verdict is the exit code, the
    # same contract `test` and `vet` keep. Errors never reach this line —
    # they raise out to the one rescue that serves every verb.
    report_warnings
    exit 1 if warnings_fail_on_exit?
  end
end
