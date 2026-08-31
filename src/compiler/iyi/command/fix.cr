# iyi: `iyi fix` — apply the compiler's own suggestions to the file.
#
# The division of labour is deliberate. `check -f json` *shows* the edit
# (`suggested_edit`: file, line, column, size, replacement); `fix`
# *performs* it. Nothing here invents a repair: the only edits applied
# are the ones the semantic pass computed at the raise site — the
# Levenshtein did-you-mean, the `and`→`&&` operator hint, the III.1.7a
# participle. If the compiler did not say it, `fix` does not do it.
#
# The loop is compile → apply the one edit the error carries → compile
# again, because the front end stops at the first error and every edit
# moves the ground under later spans. One edit per round is not a
# compromise; it is the only ordering that is always right. The round
# cap exists so two suggestions that undo each other cannot ping-pong
# forever.
require "../lsp/analysis"

class Iyi::Command
  private def fix
    json_mode = false
    while option = options.first?
      case option
      when "--json"
        json_mode = true
        options.shift
      when "--help", "-h"
        puts <<-USAGE
          Usage: #{Command.program_name} fix [--json] <file>

          Apply the compiler's did-you-mean edits to <file>, recompiling
          after each one, until the file is clean or carries an error the
          compiler has no edit for. Exit 0 when the file ends clean.

          To see the edits without applying them, use
          `#{Command.program_name} check -f json`: the same edits travel
          there as `suggested_edit`, and the file is not touched.
          USAGE
        exit
      else
        break
      end
    end

    file = options.first?
    abort "fix: which file? Usage: #{Command.program_name} fix [--json] <file>" unless file
    abort "fix: file '#{file}' does not exist" unless File.file?(file)
    path = File.expand_path(file)

    analysis = Lsp::Analysis.new
    applied = [] of {Int32, Int32, String, String}
    remaining = nil

    # 32 rounds is not a tuning knob: a file that genuinely carries more
    # consecutive fixable typos than that is not being fixed, it is being
    # generated, and a loop that long deserves a look rather than a run.
    32.times do
      text = File.read(path)
      # The probe rides along (see check.cr): fix must converge to the
      # same verdict `check` gives, uncalled bodies included — a fix
      # that says clean where check says broken is two tools lying to
      # each other. Probe-line diagnostics (past the file's end) carry
      # no applicable edit and fall out as `remaining` below.
      probe = check_probe_source(path, text) || ""
      _, diags = analysis.check(path, text + probe, {} of String => String)
      if diags.empty?
        remaining = nil
        break
      end

      diag = diags.first
      replacement = diag.suggestion
      unless replacement && diag.size > 0
        remaining = diag
        break
      end

      lines = text.split('\n')
      line_text = lines[diag.line - 1]?
      unless line_text
        remaining = diag
        break
      end
      chars = line_text.chars
      from = chars[diag.column - 1, diag.size].join
      if from == replacement
        # The suggestion equals what is already written: applying it
        # would change nothing and loop forever. Report and stop.
        remaining = diag
        break
      end

      lines[diag.line - 1] = chars[0, diag.column - 1].join + replacement +
                             ((chars[diag.column - 1 + diag.size..]? || [] of Char).join)
      File.write(path, lines.join('\n'))
      applied << {diag.line, diag.column, from, replacement}
    end

    if json_mode
      JSON.build(STDOUT) do |json|
        json.object do
          json.field "file", path
          json.field "applied" do
            json.array do
              applied.each do |(line, column, from, to)|
                json.object do
                  json.field "line", line
                  json.field "column", column
                  json.field "from", from
                  json.field "to", to
                end
              end
            end
          end
          json.field "clean", remaining.nil?
          if remaining
            json.field "remaining", remaining.message
          end
        end
      end
      STDOUT.puts
    else
      applied.each do |(line, column, from, to)|
        puts "fixed #{file}:#{line}:#{column}: '#{from}' -> '#{to}'"
      end
      if remaining
        STDERR.puts "#{file}:#{remaining.line}:#{remaining.column}: #{remaining.message}"
      elsif applied.empty?
        puts "#{file}: already clean"
      end
    end

    exit remaining ? 1 : 0
  end
end
