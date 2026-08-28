# iyi: `iyi doc` — III.8's doc verb, a renderer over data that exists.
#
# What it prints is `IyiMod.surface`: the caller's view of a module —
# exported functions and types with their doc comments, no bodies, no
# private anything. The same document `iyi mod context` grounds an edit
# with, served for one module at a time, because "what can I call here"
# is a question a person asks too.
#
#     iyi doc lib/thing.iyimod    # from an artifact, source not needed
#     iyi doc src/thing.iyi       # from source: the module is compiled
#                                 # alone, front end only, and read back
#
# No HTML, no site, no theme. The document is text because the consumers
# are a terminal and a model, and III.7's registry index — `Exports`
# served as data — is where anything richer belongs.
require "file_utils"

class Iyi::Command
  private def doc
    filename = options.shift?
    case
    when filename.nil? || filename == "--help" || filename == "-h"
      puts doc_usage
      exit
    when filename.ends_with?(".iyimod")
      abort! "no such file: #{filename}", :USAGE_ERROR unless File.file?(filename)
      artifact =
        begin
          IyiMod.read(filename)
        rescue ex : IyiMod::Error
          abort! ex.message.to_s, :USAGE_ERROR
        end
      IyiMod.surface artifact, STDOUT
    when filename.ends_with?(".iyi")
      abort! "no such file: #{filename}", :USAGE_ERROR unless File.file?(filename)
      doc_from_source(File.expand_path(filename))
    else
      abort! "expected a .iyi module or a .iyimod artifact", :USAGE_ERROR
    end
  end

  # The module compiled alone — R-1's promise worn as a verb, the same way
  # `mod context` wears it: a synthetic entry imports the module, the
  # front end runs, and the artifact it emits is the answer.
  private def doc_from_source(filename : String) : Nil
    module_name = File.basename(filename, ".iyi")
    module_root = File.dirname(filename)

    emit_dir = File.tempname("iyi-doc", nil)
    Dir.mkdir_p(emit_dir)
    begin
      entry = File.join(emit_dir, "doc_entry.iyi")
      File.write(entry, "import #{module_name}\n")

      compiler = Compiler.new
      compiler.prelude = "iyi/prelude"
      compiler.no_codegen = true
      compiler.iyi_mod_table = Mod::Installer.table_for(module_root)
      compiler.emit_iyimod = emit_dir
      compiler.stdout = IO::Memory.new
      compiler.stderr = IO::Memory.new
      previous_path = ENV["IYI_PATH"]?
      begin
        ENV["IYI_PATH"] = ([module_root] + (previous_path ? [previous_path] : IyiPath.default_paths)).join(':')
        compiler.compile(
          Compiler::Source.new(entry, File.read(entry)),
          File.join(emit_dir, "unused"))
      rescue ex : Iyi::Error | Iyi::CodeError
        abort! "#{filename} does not compile alone: #{ex.message.to_s.lines.first?}", :USAGE_ERROR
      ensure
        previous_path ? (ENV["IYI_PATH"] = previous_path) : ENV.delete("IYI_PATH")
      end

      Dir.glob(File.join(emit_dir, "**", "*.iyimod")) do |candidate|
        begin
          artifact = IyiMod.read(candidate)
          if artifact.module_name == module_name
            IyiMod.surface artifact, STDOUT
            return
          end
        rescue IyiMod::Error
          next
        end
      end
      abort! "compiled, but no artifact carries module '#{module_name}'", :USAGE_ERROR
    ensure
      FileUtils.rm_rf(emit_dir)
    end
  end

  private def doc_usage
    <<-USAGE
    Usage: #{Command.program_name} doc FILE

    Prints a module's exported surface with its doc comments — functions,
    types, methods, impls; no bodies, nothing private. FILE is a `.iyimod`
    artifact (read directly, source not needed) or a `.iyi` module (compiled
    alone, front end only).
    USAGE
  end
end
