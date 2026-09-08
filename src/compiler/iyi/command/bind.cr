# iyi: `iyi bind` — every shard under `lib/`, behind a boundary, in one
# command (SPEC.md III.6).
#
# The boundary has existed for a while as two commands per shard, run in
# dependency order by a person who knows the order and each shard's root
# namespace: `tool bind -e Root --emit-bind mods --use-iyimod mods
# lib/x/src/x.cr`, then a build of the keep file it wrote, with
# `--iyi-keep Root --emit-bind .` so the object code lands in the
# artifact. Kemal is four shards and eight commands, and
# `samples/crystal/kemal/README.md` is the loop written out by hand. The
# loop is what this verb is: it reads `lib/` the way `shards install`
# left it, orders the shards by their own `shard.yml` dependencies, reads
# each root off its entry file, and runs the two steps as itself. What
# comes out is `mods/<shard>.iyimod` per shard, and a program that wrote
# `require "kemal"` writes `import kemal` and builds against the
# artifacts instead of the source.
#
# Nothing here is new analysis: the steps are the ones the gate
# (`bench/kemal_serves.sh`) runs, in the order it runs them, as
# subprocesses of this binary — the way `mcp` and the daemon re-run the
# verbs — so a failure is the step's own message and the artifacts of the
# shards before it stand.
class Iyi::Command
  private def bind
    mods = "mods"
    lib_dir = "lib"
    while option = options.first?
      case option
      when "--mods"
        options.shift
        mods = options.shift? || abort!("--mods takes a directory", :USAGE_ERROR)
      when "--lib"
        options.shift
        lib_dir = options.shift? || abort!("--lib takes a directory", :USAGE_ERROR)
      when "--help", "-h"
        puts <<-USAGE
          Usage: #{Command.program_name} bind [--lib DIR] [--mods DIR] [SHARD ...]

          Bind the shards shard.yml depends on (what `shards install` put
          under lib/, development dependencies aside) as a .iyimod each
          under mods/, in dependency order, each against the ones before
          it. Name shards to bind those and what they depend on instead.
          Then `import <name>` in a program built with --crystal --use-iyimod mods;
          the name is the root namespace spelled for import (`Kemal` is
          `kemal`, `DB` is `d_b`), and the output says it.
          USAGE
        exit
      else
        break
      end
    end

    unless Dir.exists?(lib_dir)
      abort! "bind: no #{lib_dir}/ here; run `shards install` first, or --lib DIR", :USAGE_ERROR
    end

    shards = {} of String => Shard
    Dir.each_child(lib_dir) do |name|
      dir = File.join(lib_dir, name)
      next unless Dir.exists?(dir)
      entry = File.join(dir, "src", "#{name}.cr")
      unless File.file?(entry)
        STDERR.puts "bind: #{name}: no src/#{name}.cr, skipped"
        next
      end
      shards[name] = Shard.new(name, entry, shard_root(entry), shard_dependencies(dir, shards_available: lib_dir))
    end
    abort! "bind: nothing under #{lib_dir}/ has a src/<name>.cr", :USAGE_ERROR if shards.empty?

    # What to bind: the shards named, or the project's own `shard.yml`
    # dependencies — not its development ones, which are the tests' (a
    # spec framework under lib/ is not a boundary anybody's program
    # crosses) — or, with no manifest to read, everything under lib/.
    wanted =
      if !options.empty?
        options.dup
      elsif File.file?("shard.yml")
        listed = shard_dependencies(".", shards_available: lib_dir)
        abort! "bind: shard.yml lists no dependency that is under #{lib_dir}/", :USAGE_ERROR if listed.empty?
        listed
      else
        shards.keys
      end
    wanted.each do |name|
      abort! "bind: no shard named #{name} under #{lib_dir}/", :USAGE_ERROR unless shards[name]?
    end

    ordered = [] of Shard
    visiting = Set(String).new
    visit = uninitialized Proc(String, Nil)
    visit = ->(name : String) : Nil do
      return if ordered.any? { |s| s.name == name }
      abort! "bind: #{name} depends on itself through its dependencies", :USAGE_ERROR unless visiting.add?(name)
      shards[name].dependencies.each { |dependency| visit.call(dependency) }
      ordered << shards[name]
    end
    wanted.each { |name| visit.call(name) }

    executable = Process.executable_path || abort!("bind: cannot find the compiler's own executable", :USAGE_ERROR)
    Dir.mkdir_p(mods)
    mods_path = File.expand_path(mods)

    # The fill build runs inside mods/, where a relative `lib` on the path
    # would resolve under it; so the paths the subprocesses get are this
    # directory's, absolute, with lib/ where the default has it.
    lib_path = File.expand_path(lib_dir)
    search = IyiPath.default_paths.map { |path| path == "lib" ? lib_path : File.expand_path(path) }
    search.unshift(lib_path) unless search.includes?(lib_path)
    env = {"IYI_PATH" => search.join(Process::PATH_DELIMITER), "CRYSTAL_PATH" => search.join(Process::PATH_DELIMITER)}

    # A shard that fails is named and the rest go on: the ones before it
    # stand, and a shard that does not depend on it binds regardless.
    # The exit code says whether everything asked for was bound.
    failed = [] of String
    puts "binding #{ordered.size} shard#{ordered.size == 1 ? "" : "s"} into #{mods}/, in dependency order:"
    ordered.each do |shard|
      print "  #{shard.name}"
      STDOUT.flush
      unless root = shard.root
        puts " — no top-level module, class or struct in #{shard.entry}; bind it by hand with `#{Command.program_name} tool bind --crystal -e Root ...`"
        failed << shard.name
        next
      end
      if (missing = shard.dependencies.find { |dependency| failed.includes?(dependency) })
        puts " (#{root}) — skipped: depends on #{missing}, which did not bind"
        failed << shard.name
        next
      end
      print " (#{root})"
      STDOUT.flush

      step = run_step(executable, env, ["tool", "bind", "--crystal", "-e", root, "--emit-bind", mods_path, "--use-iyimod", mods_path, shard.entry], chdir: nil, log: File.join(mods_path, "#{shard.name}.bind.log"))
      unless step
        puts " — binding failed; #{mods}/#{shard.name}.bind.log has the compiler's answer"
        failed << shard.name
        next
      end
      # The artifact is named for the root, spelled so `import` reads it
      # back (`DB` is `d_b`, `Kemal` is `kemal`: `Iyi.iyi_module_name`),
      # and the keep file beside it; that is where the fill build finds it.
      # A shard whose surface is macros - `prop`, say - has nothing R-2 can
      # write and `tool bind` writes no file; III.6 rule 4 says macros do
      # not cross, and this is where a person learns that about the shard.
      artifact = Iyi.iyi_module_name(root)
      unless File.file?(File.join(mods_path, "#{artifact}_keep.cr"))
        puts " — nothing to bind: no method R-2 can write a signature for (a surface that is macros does not cross, SPEC.md III.6); #{mods}/#{shard.name}.bind.log has the count"
        failed << shard.name
        next
      end
      step = run_step(executable, env, ["build", "--crystal", "--iyi-keep", root, "--emit-bind", ".", "-o", "keep_#{shard.name}", "#{artifact}_keep.cr"], chdir: mods_path, log: File.join(mods_path, "#{shard.name}.fill.log"))
      unless step
        # The declarations without their object code would be found by
        # the next build's `--use-iyimod` and fail there, further from the
        # cause; the log stays, the half-artifact does not.
        File.delete?(File.join(mods_path, "#{artifact}.iyimod"))
        puts " — filling the object code failed; #{mods}/#{shard.name}.fill.log has the compiler's answer"
        failed << shard.name
        next
      end
      puts " — #{mods}/#{artifact}.iyimod"
    end
    if failed.empty?
      puts "import any of them by that name from a program built with --crystal --use-iyimod #{mods}"
    else
      puts "#{ordered.size - failed.size} of #{ordered.size} bound; not bound: #{failed.join(", ")}"
      exit 1
    end
  end

  record Shard, name : String, entry : String, root : String?, dependencies : Array(String)

  # The shard's root namespace: the first top-level `module`, `class` or
  # `struct` its entry file declares, which is what `-e` selects. A shard
  # whose entry only requires its parts declares nothing there, and then
  # the first part in require order that does is read instead.
  private def shard_root(entry : String) : String?
    seen = Set(String).new
    queue = [entry]
    while file = queue.shift?
      next unless seen.add?(file)
      next unless File.file?(file)
      File.each_line(file) do |line|
        if match = line.match(/^(?:abstract\s+)?(?:module|class|struct)\s+([A-Z][A-Za-z0-9_]*)/)
          return match[1]
        end
        if match = line.match(/^require\s+"(\.[^"]+)"/)
          required = File.expand_path(match[1], File.dirname(file))
          if required.ends_with?("/*") || required.ends_with?("/**")
            Dir.glob(File.join(required.rchop("*").rchop("*"), "**", "*.cr")).sort.each { |part| queue << part }
          else
            queue << (required.ends_with?(".cr") ? required : required + ".cr")
          end
        end
      end
    end
    nil
  end

  # The shard's own `shard.yml` dependencies, by name, restricted to what
  # is installed: a dependency that is not under lib/ is not one this
  # verb can bind, and the compiler will say so when the shard's own
  # `require` misses it. `development_dependencies` are not read; they
  # are the shard's tests', not its consumers'.
  private def shard_dependencies(dir : String, shards_available : String) : Array(String)
    manifest = File.join(dir, "shard.yml")
    return [] of String unless File.file?(manifest)
    names = [] of String
    in_dependencies = false
    File.each_line(manifest) do |line|
      if line.match(/^\S/)
        in_dependencies = line.starts_with?("dependencies:")
        next
      end
      next unless in_dependencies
      if match = line.match(/^  ([A-Za-z0-9_]+):/)
        names << match[1] if Dir.exists?(File.join(shards_available, match[1]))
      end
    end
    names
  end

  private def run_step(executable : String, env : Hash(String, String), args : Array(String), chdir : String?, log : String) : Bool
    File.open(log, "w") do |sink|
      status = Process.run(executable, args, env: env, chdir: chdir, output: sink, error: sink)
      status.success?
    end
  end
end
