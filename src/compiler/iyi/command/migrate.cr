# iyi: `iyi migrate SRC --out DIR` — a Crystal source tree written out as
# iyi modules (SPEC.md III.6, "What a migration would need, measured").
#
# Every rule here was found by migrating a real application rather than
# designed, and each is mechanical:
#
#   1. **A Crystal namespace is an iyi path.** `module A::B` wrapping a
#      file, or `class A::B::C` declared at its top, places the file at
#      `a/b/c` — segments spelled the way `Iyi.iyi_module_name` spells
#      them, so `DB` is `d_b` and comes back `DB` — and the wrapper comes
#      off, because the path *is* the namespace.
#   2. **A type's qualified name changes with it.** Every constant path
#      the tree declares is resolved the way Crystal resolves one —
#      innermost namespace outwards, through `include` — and rewritten to
#      the bare name the declaring module exports, under a `using` line.
#      Two modules offering one name: the second stays qualified, and the
#      note says which.
#   3. **What other files reach is `pub`.** A Crystal file cannot say
#      otherwise, and the compiler refuses an unexported name at its use.
#   4. **`require "./x"` is `import`; `require "shard"` stays.** Shard
#      requires are global in Crystal and a module's own here, so every
#      module gets the tree's set.
#   5. **A cycle is one module.** R-1 refuses an import cycle (III.5 rule
#      1) and Crystal's global namespace never had one to refuse, so each
#      strongly connected set of modules is written as one, its members in
#      require order, and named.
#   6. **A reopening of a type the tree does not own stays Crystal.** R-3
#      is the one rule no rewrite satisfies, and it has a mechanical home:
#      a `.cr` file beside the module, `require`d from it, where open
#      classes are Crystal's rule.
#   7. **`!` is III.1.7a's.** `x.not_nil!` becomes `(x || raise …)`, and
#      any other `foo!` its non-bang spelling, each site named in a note
#      because the copy and the mutation are not the same program.
#
# Everything else stays as written — `getter`, `include` into a type,
# `rescue`, macros, an untyped `def` nobody exports — because the
# measurement said it compiles as it is under `--crystal`. What does not
# is reported rather than guessed at: `--check` compiles every module
# written and prints the first refusal of each, which is the list a
# person works through.
#
# Text, not syntax, and the reason it can be: II.3 rule 4 makes the
# header block line-shaped, a Crystal file's namespace wrappers and
# top-level declarations are line-shaped too, and constant paths are
# lexically distinctive. String contents are skipped; a `# comment` is
# left alone. `--check` is what says whether that was enough.
class Iyi::Command
  private def migrate
    out_dir = nil
    check = false
    verbose = false
    src = nil
    while option = options.first?
      case option
      when "--out"
        options.shift
        out_dir = options.shift? || abort!("--out takes a directory", :USAGE_ERROR)
      when "--check"
        options.shift
        check = true
      when "--verbose", "-v"
        options.shift
        verbose = true
      when "--help", "-h"
        puts <<-USAGE
          Usage: #{Command.program_name} migrate SRC --out DIR [--check] [--verbose]

          Write every .cr under SRC as an iyi module under DIR: the
          namespace as the path, the wrapper off, `pub` on the top level,
          relative requires as imports, and every constant path this tree
          declares as the bare name its module exports, under a `using`
          line. Import cycles are written as one module; a reopening of a
          type the tree does not own is kept as Crystal in a `.cr` file
          beside its module.

          --check   compile every module written (`check --crystal`) and
                    print the first refusal of each
          --verbose every note, rather than the first few of each kind

          The modules build with `--crystal`, which is the library the
          tree was written against; `#{Command.program_name} bind` puts its
          shards behind a boundary after that.
          USAGE
        exit
      else
        if src
          abort! "migrate: one tree at a time; unexpected '#{option}'", :USAGE_ERROR
        end
        src = options.shift
      end
    end

    src ||= abort!("migrate: which tree? Usage: #{Command.program_name} migrate SRC --out DIR", :USAGE_ERROR)
    abort! "migrate: no such directory: #{src}", :USAGE_ERROR unless Dir.exists?(src)
    out_dir ||= abort!("migrate: --out DIR is where the modules go", :USAGE_ERROR)
    src = File.expand_path(src)
    out_dir = File.expand_path(out_dir)
    abort! "migrate: --out #{out_dir} is inside #{src}; the modules would be migrated again", :USAGE_ERROR if out_dir.starts_with?(src + "/")

    files = Dir.glob(File.join(src, "**", "*.cr")).sort
    abort! "migrate: no .cr under #{src}", :USAGE_ERROR if files.empty?

    # Which root namespaces are the tree's own, and which belong to the
    # library it is written against. A declaration under a name the
    # library already owns is a reopening (rule 6) whether it is written
    # `struct Int32` or `class Log::Metadata`, and the only authority on
    # that is the library: the compiler is asked, once, by analysing a
    # program that is nothing but the prelude.
    library = Compiler.new
    library.no_codegen = true
    library.stdout = IO::Memory.new
    library.stderr = IO::Memory.new
    library_names = begin
      result = library.compile(
        Compiler::Source.new(File.join(Dir.tempdir, "iyi-migrate-probe.cr"), ""),
        File.tempname("iyi-migrate", nil))
      (result.program.types?.try(&.keys) || [] of String).to_set
    rescue ex : CodeError | Iyi::Error
      abort! "migrate: could not read Crystal's library to see which names it owns: #{ex.message}", :CODE_ERROR
    end

    tree_roots = Set(String).new
    files.each { |file| MigrateUnit.collect_roots(file, tree_roots) }
    tree_roots.reject! { |name| library_names.includes?(name) }

    notes = Notes.new
    units = files.map { |file| MigrateUnit.read(file, src, tree_roots, notes) }
    by_source = units.to_h { |unit| {unit.source, unit} }
    by_namespace = {} of String => MigrateUnit
    units.each { |unit| by_namespace[unit.namespace.join("::")] ||= unit unless unit.namespace.empty? }

    shard_requires = [] of String
    units.each do |unit|
      unit.shard_requires.each { |name| shard_requires << name unless shard_requires.includes?(name) }
    end

    # The symbol table: every constant path the tree declares, and the
    # aliases `include` gives it. `module AcikTurkiye; include Logging`
    # makes `AcikTurkiye::Log` another spelling of `AcikTurkiye::Logging::Log`,
    # which is the lookup Crystal performs and the one reference in this
    # application that nothing else explains.
    exports = {} of String => Export
    units.each do |unit|
      unit.exports.each { |name| exports[unit.qualified(name)] ||= Export.new(unit, name) }
    end
    units.each do |unit|
      unit.includes.each do |included|
        target = resolve_namespace(included, unit, by_namespace)
        next unless target
        prefix = unit.namespace.join("::")
        target.exports.each do |name|
          key = prefix.empty? ? name : "#{prefix}::#{name}"
          exports[key] ||= Export.new(target, name)
        end
      end
    end

    project_root = Dir.current
    units.each { |unit| unit.render(by_source, by_namespace, exports, notes, project_root) }

    # Everything under the tree that is not Crystal travels with it: a
    # view, a fixture, a JSON file the program reads. A *template* is
    # code — a macro splices it into whichever module renders it — so its
    # constant paths are rewritten too, inside its `<% %>` regions, and
    # the names it ends up using are handed to every module that names a
    # template, since which module renders which is a shard's macro's
    # business rather than something this text can see.
    template_names = MigrateUnit.new(src, "", [] of String, "", [] of String,
      [] of String, [] of String, 0, [] of String, [] of String)
    assets = 0
    Dir.glob(File.join(src, "**", "*")).sort.each do |file|
      next unless File.file?(file)
      next if file.ends_with?(".cr")
      relative_asset = file.lchop(project_root).lchop('/')
      target = File.join(out_dir, relative_asset)
      Dir.mkdir_p(File.dirname(target))
      if TEMPLATE_EXTENSIONS.any? { |extension| file.ends_with?(extension) }
        File.write(target, template_names.rewrite_template(File.read(file), exports, notes))
        notes.add "embed", "#{relative_asset} travelled with the tree, its constant paths rewritten"
      else
        File.copy(file, target)
      end
      assets += 1
    end
    used_by_templates = template_names.usings
    unless used_by_templates.empty?
      units.each do |unit|
        next unless unit.body.any? do |line|
                      TEMPLATE_EXTENSIONS.any? { |extension| line.includes?("#{extension}\"") }
                    end
        used_by_templates.each do |imported, names|
          unit.imports << imported
          (unit.usings[imported] ||= Set(String).new).concat(names)
        end
      end
    end

    # A cycle is one unit of compilation whatever its files were.
    components = strongly_connected(units)
    remap = {} of String => String
    merged = {} of String => Array(String)
    components.each do |members|
      next if members.size == 1
      path = merged_path(members)
      members.each { |member| remap[member.path] = path }
      merged[path] = members.map(&.path)
      notes.add "cycle", "#{path} is #{members.size} files R-1 cannot separate (#{members.map(&.path).join(", ")}); split it by moving what the later ones reach for into one module they can all import"
    end

    written = {} of String => String
    modules = {} of String => Array(MigrateUnit)
    units.each { |unit| (modules[remap[unit.path]? || unit.path] ||= [] of MigrateUnit) << unit }
    modules.each do |module_path, members|
      members = required_first(members, by_source) if members.size > 1
      imports = Set(String).new
      usings = {} of String => Set(String)
      members.each do |member|
        member.imports.each do |imported|
          target = remap[imported]? || imported
          imports << target unless target == module_path
        end
        member.usings.each do |imported, names|
          target = remap[imported]? || imported
          next if target == module_path
          (usings[target] ||= Set(String).new).concat(names)
        end
      end

      sidecars = members.reject(&.sidecar.empty?)
      sidecars.each do |member|
        sidecar_path = File.join(out_dir, File.dirname(module_path), "#{File.basename(member.path)}_crystal.cr")
        Dir.mkdir_p(File.dirname(sidecar_path))
        File.write(sidecar_path,
          "# Reopenings of types this tree does not own, kept as Crystal: R-3 closes\n" \
          "# a type where it is written, and these are somebody else's (SPEC.md III.6).\n" +
          member.sidecar.join('\n').strip + "\n")
      end

      written[module_path] = String.build do |io|
        io << "module " << module_path << "\n\n"
        shard_requires.each { |name| io << "require \"" << name << "\"\n" }
        # A shard's top-level code runs once, in whichever module the
        # compiler required it from first — and `pg` registering its
        # driver there is a program that opens a connection before the
        # registration when that module is not the first initialised.
        # III.5 makes an import's initialiser run before its importer's,
        # so one module requires the shards and every other imports it:
        # the effects land in a module that is initialised first, by rule
        # rather than by the order files happened to compile in.
        io << "import " << SHARDS_MODULE << '\n' if !shard_requires.empty? && module_path != SHARDS_MODULE
        sidecars.each { |member| io << "require \"./" << File.basename(member.path) << "_crystal.cr\"\n" }
        io << '\n' unless shard_requires.empty? && sidecars.empty?
        imports.to_a.sort.each { |imported| io << "import " << imported << '\n' }
        usings.to_a.sort_by(&.[0]).each do |(imported, names)|
          io << "using " << imported << "::{" << names.to_a.sort.join(", ") << "}\n"
        end
        io << '\n' unless imports.empty?
        members.each do |member|
          io << "# ── " << member.relative << " ──\n\n" if members.size > 1
          text = MigrateUnit.resolve_marks(member.body.join('\n').strip, remap, module_path)
          io << text << '\n'
          io << '\n' if members.size > 1
        end
      end
    end

    unless shard_requires.empty?
      written[SHARDS_MODULE] = String.build do |io|
        io << "# The shards this tree was written against, required once and\n"
        io << "# imported by every module: III.5 initialises an import before\n"
        io << "# its importer, so a shard's top-level code — `pg` registering\n"
        io << "# its driver — runs before anything that uses it.\n"
        io << "module " << SHARDS_MODULE << "\n\n"
        shard_requires.each { |name| io << "require \"" << name << "\"\n" }
      end
    end

    written.each do |module_path, text|
      target = File.join(out_dir, "#{module_path}.iyi")
      Dir.mkdir_p(File.dirname(target))
      File.write(target, text)
    end

    puts "#{units.size} files → #{written.size} modules under #{out_dir}/"
    if verbose
      units.each do |unit|
        target = remap[unit.path]? || unit.path
        also = target == unit.path ? "" : " (one of #{merged[target].size})"
        puts "  #{unit.relative} → #{target}.iyi#{also}"
      end
    end
    notes.print(verbose)

    if check
      puts
      puts "checking every module against Crystal's library:"
      executable = Process.executable_path || abort!("migrate: cannot find the compiler's own executable", :USAGE_ERROR)
      clean = [] of String
      broke = [] of {String, String}
      written.keys.sort.each do |module_path|
        output = IO::Memory.new
        # From the migrated tree, which is a project of its own: the
        # templates a macro embeds were copied into it at the paths their
        # `embed` names, and their constant paths were rewritten with the
        # module that embeds them.
        status = Process.run(executable,
          ["check", "--crystal", "--no-color", File.join(out_dir, "#{module_path}.iyi")],
          chdir: out_dir, output: output, error: output)
        if status.success?
          clean << module_path
        else
          text = output.to_s
          at = text.lines.index { |line| line.starts_with?("Error:") }
          message = (at ? text.lines[at] : text.lines.last?) || "(no message)"
          where = at ? text.lines[0...at].reverse.find(&.starts_with?("In ")).try(&.lchop("In ").strip) : nil
          via = where && !where.starts_with?("#{module_path}.iyi") ? " (in #{where})" : ""
          broke << {module_path, message.lchop("Error: ").strip + via}
        end
      end
      broke.each { |(module_path, message)| puts "  #{module_path}: #{message}" }
      puts "#{clean.size} of #{written.size} modules compile; #{broke.size} carry what is listed above"
      exit 1 unless broke.empty?
    else
      puts
      puts "next: #{Command.program_name} migrate #{src} --out #{out_dir} --check"
    end
  end

  # One name a module exports, and the module.
  record Export, unit : MigrateUnit, name : String

  # The module that owns the tree's shard requires.
  SHARDS_MODULE = "crystal_shards"

  # What counts as code a macro splices rather than data a program reads.
  TEMPLATE_EXTENSIONS = %w(.ecr .slang .slim .mustache .cr.erb)

  # Notes, grouped by kind so a hundred files do not print a hundred
  # variations of one finding.
  class Notes
    getter groups = {} of String => Array(String)

    def add(kind : String, note : String) : Nil
      list = @groups[kind] ||= [] of String
      list << note unless list.includes?(note)
    end

    HEADINGS = {
      "cycle"   => "import cycles, written as one module each",
      "reopen"  => "reopenings of types this tree does not own, kept as Crystal",
      "collide" => "one name offered by two modules, the second left qualified",
      "bang"    => "`!` is III.1.7a's: rewritten, and worth reading",
      "include" => "`include` of a namespace, which is a `using` line here",
      "nested"  => "modules left nested, which nothing outside can reach",
      "untyped" => "exports whose types the compiler still has to be told",
      "embed"   => "templates embedded at compile time, named from the project root",
    }

    def print(verbose : Bool) : Nil
      return if @groups.empty?
      HEADINGS.each do |kind, heading|
        list = @groups[kind]?
        next unless list
        puts
        puts "#{heading} (#{list.size}):"
        shown = verbose ? list : list.first(6)
        shown.each { |note| puts "  #{note}" }
        puts "  … and #{list.size - shown.size} more (--verbose)" if list.size > shown.size
      end
    end
  end

  # A cycle's members in require order: what a member required comes
  # first, so an `include` follows the module it names.
  private def required_first(members : Array(MigrateUnit), by_source : Hash(String, MigrateUnit)) : Array(MigrateUnit)
    member_set = members.to_set
    ordered = [] of MigrateUnit
    seen = Set(MigrateUnit).new
    visit = uninitialized Proc(MigrateUnit, Nil)
    visit = ->(unit : MigrateUnit) : Nil do
      return unless seen.add?(unit)
      unit.required_units(by_source).each { |required| visit.call(required) if member_set.includes?(required) }
      ordered << unit
    end
    members.each { |member| visit.call(member) }
    ordered
  end

  # `include Logging` inside `module AcikTurkiye`: the namespace it names,
  # resolved outwards the way Crystal resolves a constant.
  private def resolve_namespace(name : String, from : MigrateUnit, by_namespace : Hash(String, MigrateUnit)) : MigrateUnit?
    name = name.lchop("::")
    from.namespace.size.downto(0) do |depth|
      prefix = from.namespace[0, depth]
      candidate = (prefix + name.split("::")).join("::")
      if unit = by_namespace[candidate]?
        return unit unless unit == from
      end
    end
    nil
  end

  # Tarjan's strongly connected components over the import graph.
  private def strongly_connected(units : Array(MigrateUnit)) : Array(Array(MigrateUnit))
    by_path = units.to_h { |unit| {unit.path, unit} }
    index = 0
    indices = {} of String => Int32
    lowlink = {} of String => Int32
    on_stack = Set(String).new
    stack = [] of String
    components = [] of Array(MigrateUnit)
    visit = uninitialized Proc(String, Nil)
    visit = ->(path : String) : Nil do
      indices[path] = lowlink[path] = index
      index += 1
      stack << path
      on_stack << path
      (by_path[path]?.try(&.imports) || Set(String).new).each do |next_path|
        next unless by_path.has_key?(next_path)
        if !indices.has_key?(next_path)
          visit.call(next_path)
          lowlink[path] = Math.min(lowlink[path], lowlink[next_path])
        elsif on_stack.includes?(next_path)
          lowlink[path] = Math.min(lowlink[path], indices[next_path])
        end
      end
      if lowlink[path] == indices[path]
        component = [] of MigrateUnit
        loop do
          popped = stack.pop
          on_stack.delete(popped)
          component << by_path[popped]
          break if popped == path
        end
        components << component.sort_by { |unit| units.index(unit) || 0 }
      end
    end
    units.each { |unit| visit.call(unit.path) unless indices.has_key?(unit.path) }
    components
  end

  # One path for a cycle's modules: their common directory, then their own
  # names joined, or the first and "and_others" when that runs long.
  private def merged_path(members : Array(MigrateUnit)) : String
    dirs = members.map { |member| member.path.includes?('/') ? File.dirname(member.path) : "" }
    common = dirs.first.split('/')
    dirs.each do |dir|
      parts = dir.split('/')
      common = common.zip?(parts).take_while { |(a, b)| a == b }.map(&.[0])
    end
    stems = members.map { |member| File.basename(member.path) }.sort
    name = stems.join('_')
    name = "#{stems.first}_and_others" if name.size > 40
    prefix = common.reject(&.empty?).join('/')
    prefix.empty? ? name : "#{prefix}/#{name}"
  end

  # One Crystal file, read for what places it, what it declares, and what
  # it reaches for.
  class MigrateUnit
    getter source : String
    getter relative : String
    getter namespace : Array(String)
    getter path : String
    getter exports : Array(String)
    getter includes : Array(String)
    getter lines : Array(String)
    getter wrappers : Int32
    getter shard_requires : Array(String)
    # Reopenings of types the tree does not own, kept as Crystal.
    getter sidecar : Array(String)
    getter imports = Set(String).new
    getter usings = {} of String => Set(String)
    getter body = [] of String

    DECL    = /^(\s*)(?:(private|protected)\s+)?(?:abstract\s+)?(class|struct|module|enum|alias|annotation|lib)\s+([A-Z][\w:]*)/
    DEF     = /^(\s*)(?:(private|protected)\s+)?(def|macro)\s+(?:self\.)?([\w?!=<>+\-*\/%\[\]]+)/
    CONST   = /^(\s*)([A-Z]\w*)\s*=[^=]/
    REQUIRE = /^\s*require\s+"([^"]+)"/
    INCLUDE = /^(\s*)(?:include|extend)\s+(::)?([A-Z][\w:]*)\s*$/
    PATH    = /(::)?[A-Z]\w*(?:::[A-Z]\w*)+/
    # `Shop::Names.title(x)` and `Shop.banner`: a namespace and a method
    # of it, which is how a Crystal module function is called and is not a
    # constant path.
    PATH_CALL = /(::)?[A-Z]\w*(?:::[A-Z]\w*)*\.[a-z_]\w*[?!]?/

    def initialize(@source, @relative, @namespace, @path, @exports, @includes,
                   @lines, @wrappers, @shard_requires, @sidecar)
    end

    # Every root namespace a file declares unqualified: the tree's own.
    def self.collect_roots(file : String, into : Set(String)) : Nil
      File.each_line(file) do |line|
        next unless (match = line.match(DECL)) && match[1].empty?
        name = match[4]
        into << name unless name.includes?("::")
      end
    end

    def self.read(file : String, root : String, tree_roots : Set(String), notes : Notes) : MigrateUnit
      all = File.read(file).split('\n')
      relative = file.lchop(root).lchop('/')
      stem = File.basename(file, ".cr")

      # Rule 6 first, because a reopening at the end of a file is what
      # stops the module before it from being read as the file's wrapper.
      lines = [] of String
      sidecar = [] of String
      inside = nil
      all.each do |line|
        if indent = inside
          sidecar << line
          inside = nil if line.strip == "end" && (line.size - line.lstrip.size) == indent
          next
        end
        if (match = line.match(DECL)) && match[1].empty? &&
           !tree_roots.includes?(match[4].split("::").first)
          inside = 0
          sidecar << line
          notes.add "reopen", "#{relative}: `#{match[3]} #{match[4]}`"
          next
        end
        lines << line
      end

      wrappers = [] of String
      index = 0
      while index < lines.size
        line = lines[index]
        stripped = line.strip
        if stripped.empty? || stripped.starts_with?('#') || stripped.starts_with?("require ")
          index += 1
          next
        end
        # A wrapper is a `module` whose `end` closes what encloses it:
        # peeled one at a time, so `module Shop` around `module Counter`
        # around the code is the path `shop/counter` and neither line
        # stays in the file. A module left nested cannot be `pub` —
        # nothing outside could reach into it — so peeling is what makes
        # the namespace addressable.
        if (match = line.match(/^\s*module\s+([A-Z][\w:]*)\s*$/)) && closes_block?(lines, index, wrappers.size)
          wrappers << match[1]
          index += 1
          next
        end
        break
      end
      namespace = wrappers.flat_map(&.split("::"))

      declared_name = nil
      lines[index..].each do |line|
        next if line.strip.empty? || line.strip.starts_with?('#')
        if (match = line.match(DECL)) && match[1].empty?
          declared_name = match[4]
        end
        break
      end
      if declared_name && declared_name.includes?("::") && namespace.empty?
        parts = declared_name.split("::")
        namespace = parts[0..-2]
        declared_name = parts.last
      end

      depth = wrappers.size * 2
      exports = [] of String
      includes = [] of String
      lines[index..].each do |line|
        next unless (line.size - line.lstrip.size) == depth
        if match = line.match(DECL)
          next if match[2]? == "private"
          exports << match[4].split("::").last
        elsif match = line.match(DEF)
          next if match[2]? == "private" || match[2]? == "protected"
          exports << match[4]
        elsif match = line.match(CONST)
          exports << match[2]
        elsif match = line.match(INCLUDE)
          includes << match[3]
        end
      end
      exports.uniq!

      segments = namespace.map { |segment| Iyi.iyi_module_name(segment) }
      own =
        if declared_name && !declared_name.includes?("::") && exports.size == 1 && exports.first == declared_name
          Iyi.iyi_module_name(declared_name)
        elsif !wrappers.empty? && Iyi.iyi_module_name(namespace.last).delete('_') == stem.delete('_').downcase
          nil
        else
          stem
        end
      path = (own ? segments + [own] : segments).join("/")
      path = stem if path.empty?

      shard_requires = lines.compact_map do |line|
        (match = line.match(REQUIRE)) && !match[1].starts_with?('.') ? match[1] : nil
      end.uniq

      new(file, relative, namespace, path, exports, includes, lines,
        wrappers.size, shard_requires, sidecar)
    end

    # Whether the block opened at `index` closes the region `peeled`
    # wrappers deep: its `end` is the last line before those wrappers'
    # own `end`s, and everything between sits deeper. That makes it the
    # region's only construct — a wrapper, as opposed to a declaration
    # among siblings.
    private def self.closes_block?(lines : Array(String), index : Int32, peeled : Int32) : Bool
      opener_indent = lines[index].size - lines[index].lstrip.size
      rest = lines[(index + 1)..].reject { |line| line.strip.empty? || line.strip.starts_with?('#') }
      # The wrappers already peeled each contribute a closing `end` at the
      # tail; this block's own `end` is the one before them.
      return false if rest.size <= peeled
      closing = rest[rest.size - 1 - peeled]
      return false unless closing.strip == "end" && (closing.size - closing.lstrip.size) == opener_indent
      rest[0, rest.size - 1 - peeled].all? { |line| (line.size - line.lstrip.size) > opener_indent }
    end

    def qualified(name : String) : String
      (namespace + [name]).join("::")
    end

    # The module's own name for a constant path it declares, spelled the
    # way a consumer writes it when the bare name is taken: `d_b/tag` and
    # `Tag` is `AcikTurkiye::DB::Tag::Tag`.
    # A name whose module is not known until import cycles have been
    # merged rides through the body between these, and the driver
    # resolves it: `MARK path MARK Name MARK`. A private-use codepoint,
    # because it cannot occur in Crystal source.
    MARK = '\ue000'

    def self.resolve_marks(text : String, remap : Hash(String, String), module_path : String) : String
      return text unless text.includes?(MARK)
      String.build do |io|
        rest = text
        while (at = rest.index(MARK))
          io << rest[0, at]
          rest = rest[(at + 1)..]
          owner_end = rest.index(MARK) || break
          owner = rest[0, owner_end]
          rest = rest[(owner_end + 1)..]
          name_end = rest.index(MARK) || break
          name = rest[0, name_end]
          rest = rest[(name_end + 1)..]
          target = remap[owner]? || owner
          if name.empty?
            io << namespace_of(target)
          else
            io << (target == module_path ? name : spelled(target, name))
          end
        end
        io << rest
      end
    end

    # Whether this module's own namespace plus the exported name *is*
    # another module's namespace, in which case the bare name reaches the
    # module rather than what it exports.
    private def shadowed?(export : Export) : Bool
      MigrateUnit.namespace_of(path) + "::" + export.name == MigrateUnit.namespace_of(export.unit.path)
    end

    # `d_b/tag` is the namespace `AcikTurkiye::DB::Tag`.
    def self.namespace_of(module_path : String) : String
      module_path.split('/').map { |segment| segment.split('_').map(&.capitalize).join }.join("::")
    end

    def self.spelled(module_path : String, name : String) : String
      namespace_of(module_path) + "::" + name
    end

    @by_namespace = {} of String => MigrateUnit

    def render(by_source : Hash(String, MigrateUnit), by_namespace : Hash(String, MigrateUnit),
               exports : Hash(String, Export), notes : Notes, project_root : String) : Nil
      @by_namespace = by_namespace
      claimed = {} of String => String
      @exports.each { |name| claimed[name] = path }
      depth = wrappers * 2
      opened = 0

      lines.each do |line|
        stripped = line.strip
        if match = line.match(REQUIRE)
          target = match[1]
          if target.starts_with?('.')
            resolve_require(target, by_source).each { |unit| imports << unit.path unless unit.path == path }
          end
          next # a shard require rides in the header
        end
        if opened < wrappers && stripped.starts_with?("module ") && line.match(/^\s*module\s+[A-Z][\w:]*\s*$/)
          opened += 1
          next
        end
        if wrappers > 0 && stripped == "end" && (line.size - line.lstrip.size) < depth
          next
        end
        line = line[depth..]? || "" if depth > 0 && line.size >= depth && line[0, depth].strip.empty?

        # Rule: `include Logging` at the namespace's own level is Crystal's
        # way of saying "and these names are mine too"; here the names come
        # through `using`, which the rewrite below writes.
        if (match = line.match(INCLUDE)) && match[1].empty?
          if target = Command.resolve_namespace_for(match[3], self, by_namespace)
            notes.add "include", "#{path}: `include #{match[3]}` is #{target.path}'s names; they arrive by `using`"
            next
          end
        end

        if (match = line.match(DECL)) && match[1].empty? && match[4].includes?("::")
          line = line.sub(match[4], match[4].split("::").last)
        end
        if (match = line.match(DECL)) && match[1].empty? && match[2]?.nil?
          if match[3] == "module"
            notes.add "nested", "#{path}: `module #{match[4]}` stays nested, and `pub` does not apply to a module — nothing outside can reach into it"
          else
            line = "pub " + line
          end
        elsif (match = line.match(DEF)) && match[1].empty? && match[2]?.nil?
          # `def self.banner` at a module's top level is Crystal saying
          # "a module function"; an iyi module extends itself, so the
          # module function is the plain spelling and `def self.` would
          # put it on the metaclass — reachable from source and *not*
          # through an artifact, which is where the difference shows.
          line = line.sub(/\bdef\s+self\./, "def ")
          line = "pub " + line
        elsif (match = line.match(CONST)) && match[1].empty?
          line = "pub " + line
        end

        line = rewrite_paths(line, exports, claimed, notes)
        line = rewrite_bangs(line, notes)
        body << line
      end

      # A bare name resolves outwards, the way Crystal resolves one: this
      # file's namespace first, then the one above it, to the top. So
      # `ENVIRONMENT` inside `AcikTurkiye::Logging` is `AcikTurkiye`'s and
      # arrives by `using` rather than by having been in scope.
      bare_lookup = {} of String => Export
      namespace.size.downto(0) do |depth|
        prefix = namespace[0, depth].join("::")
        exports.each do |qualified_name, export|
          parts = qualified_name.split("::")
          next unless parts.size - 1 == depth
          next unless depth.zero? || qualified_name.starts_with?(prefix + "::")
          bare_lookup[export.name] ||= export
        end
      end
      bare_lookup.each do |bare, export|
        next if export.unit == self
        next if shadowed?(export)
        next if (owner = claimed[bare]?) && owner != export.unit.path
        next unless body.any? do |line|
                      !line.strip.starts_with?('#') &&
                      line.matches?(/(?<![\w:@.])#{Regex.escape(bare)}\b/)
                    end
        imports << export.unit.path
        (usings[export.unit.path] ||= Set(String).new) << bare
        claimed[bare] = export.unit.path
      end
      imports.delete(path)

      text = body.join('\n')
      untyped = text.scan(/^pub def\s+([\w?!]+)\(([^)]*)\)/m).count do |match|
        params = match[2]
        !params.strip.empty? && params.split(',').any? { |param| !param.includes?(':') }
      end
      notes.add "untyped", "#{path}: #{untyped} exported def#{untyped == 1 ? "" : "s"} whose parameters carry no type — R-2 wants them written; `crystal tool bind -e <Root>` prints what the compiler inferred" if untyped > 0
    end

    # A template is code inside `<% %>`; the rest is text a rewrite must
    # not touch, since HTML is full of quotes and capital letters.
    def rewrite_template(text : String, exports : Hash(String, Export), notes : Notes) : String
      claimed = {} of String => String
      String.build do |io|
        rest = text
        while (open_at = rest.index("<%"))
          io << rest[0, open_at]
          rest = rest[open_at..]
          close_at = rest.index("%>")
          unless close_at
            io << rest
            return io.to_s
          end
          code = rest[0, close_at + 2]
          io << rewrite_paths(code, exports, claimed, notes)
          rest = rest[(close_at + 2)..]
        end
        io << rest
      end
    end

    # Every unit this file's relative requires name, in order.
    def required_units(by_source : Hash(String, MigrateUnit)) : Array(MigrateUnit)
      lines.compact_map do |line|
        (match = line.match(REQUIRE)) && match[1].starts_with?('.') ? resolve_require(match[1], by_source) : nil
      end.flatten
    end

    private def resolve_require(target : String, by_source : Hash(String, MigrateUnit)) : Array(MigrateUnit)
      base = File.expand_path(target, File.dirname(source))
      if base.ends_with?("/**") || base.ends_with?("/*")
        dir = base.rchop("*").rchop("*").rchop("/")
        pattern = base.ends_with?("/**") ? File.join(dir, "**", "*.cr") : File.join(dir, "*.cr")
        Dir.glob(pattern).sort.compact_map { |file| by_source[file]? }
      else
        file = base.ends_with?(".cr") ? base : base + ".cr"
        (unit = by_source[file]?) ? [unit] : [] of MigrateUnit
      end
    end

    # `!` is error propagation here (III.1.7a), so a Crystal bang cannot
    # be written at all. `not_nil!` becomes the narrowing it stands for;
    # every other bang becomes the spelling without it, which is the copy
    # where Crystal's was the mutation — hence the note.
    private def rewrite_bangs(line : String, notes : Notes) : String
      return line if line.strip.starts_with?('#')
      while (at = line.index(".not_nil!"))
        start = receiver_start(line, at)
        receiver = line[start...at]
        line = line[0, start] + "(#{receiver} || raise \"nil where a value was expected\")" + line[(at + ".not_nil!".size)..]
        notes.add "bang", "#{path}: `not_nil!` became `(x || raise …)`"
      end
      line.gsub(/\.([a-z_]+)!(?![=~\w])/) do |_, match|
        name = match[1]
        notes.add "bang", "#{path}: `#{name}!` became `#{name}` — Crystal's mutated in place, this answers a copy; check the callers"
        ".#{name}"
      end
    end

    # Where the primary expression ending at `at` begins: identifiers,
    # dots, instance variables and balanced brackets, walking left.
    private def receiver_start(line : String, at : Int32) : Int32
      index = at
      depth = 0
      while index > 0
        char = line[index - 1]
        case char
        when ')', ']', '}'
          depth += 1
        when '(', '[', '{'
          break if depth == 0
          depth -= 1
        when '.', '@', '_', '?', ':'
          # part of the chain: a name, a call, a constant path
        else
          break unless char.alphanumeric? || depth > 0
        end
        index -= 1
      end
      index
    end

    # Every constant path this tree declares, rewritten to the bare name
    # its module exports. Resolved outwards from this file's namespace,
    # the way Crystal resolves a constant; string contents are skipped.
    private def rewrite_paths(line : String, exports : Hash(String, Export),
                              claimed : Hash(String, String), notes : Notes) : String
      return line if line.strip.starts_with?('#')
      String.build do |io|
        index = 0
        in_string = false
        # `"a #{Foo::BAR} b"` is a string with code in it, and the code is
        # a constant path like any other — found by hand rather than by
        # skipping every quoted span, which is how the first version
        # missed `"#{AcikTurkiye::NAME}.*"`.
        interpolation = 0
        while index < line.size
          char = line[index]
          escaped = index > 0 && line[index - 1] == '\\'
          if in_string && interpolation.zero? && char == '#' && line[index + 1]? == '{' && !escaped
            interpolation = 1
            io << '#' << '{'
            index += 2
            next
          end
          if interpolation > 0
            case char
            when '{' then interpolation += 1
            when '}' then interpolation -= 1
            end
            if interpolation.zero?
              io << char
              index += 1
              next
            end
          elsif char == '"' && !escaped
            in_string = !in_string
            io << char
            index += 1
            next
          end
          previous = index > 0 ? line[index - 1] : ' '
          if (in_string && interpolation.zero?) || !char.ascii_uppercase? ||
             previous.alphanumeric? || previous == '_' || previous == ':'
            io << char
            index += 1
            next
          end
          match = PATH_CALL.match_at_byte_index(line, index)
          match = nil unless match && match.begin(0) == index
          unless match
            match = PATH.match_at_byte_index(line, index)
            match = nil unless match && match.begin(0) == index
          end
          unless match
            io << char
            index += 1
            next
          end
          token = match[0]
          io << rewrite_path(token, exports, claimed, notes)
          index += token.size
        end
      end
    end

    private def rewrite_path(token : String, exports : Hash(String, Export),
                             claimed : Hash(String, String), notes : Notes) : String
      # `Shop::Names.title` is a namespace and a method: the method is one
      # module's export, and naming it bare under a `using` is what R-2b
      # says a consumer writes.
      if at = token.index('.')
        head = token[0, at]
        method = token[(at + 1)..]
        if unit = Command.resolve_namespace_for(head, self, @by_namespace)
          # Qualified rather than bare under a `using`: a module function
          # called from inside a type's body does not resolve as a bare
          # name, and `Module::Path.method` is what R-2b names as the
          # other spelling. It reads the same as the Crystal it came from.
          return method if unit == self
          imports << unit.path
          return "#{MARK}#{unit.path}#{MARK}#{MARK}.#{method}"
        end
        return rewrite_path(head, exports, claimed, notes) + "." + method
      end

      absolute = token.starts_with?("::")
      parts = token.lchop("::").split("::")
      # The longest prefix of the path that names something the tree
      # declares, resolved from this namespace outwards.
      (parts.size).downto(1) do |take|
        head = parts[0, take]
        tail = parts[take..]
        depths = absolute ? [0] : (0..namespace.size).to_a.reverse
        depths.each do |depth|
          candidate = (namespace[0, depth] + head).join("::")
          export = exports[candidate]?
          next unless export
          suffix = tail.empty? ? "" : "::" + tail.join("::")
          if export.unit == self
            return export.name + suffix
          end
          imports << export.unit.path
          # Shadowed: inside module `shop`, the name `Report` is the
          # namespace of the module `shop/report` before it is that
          # module's export, so the bare name reaches a module and not the
          # class. The qualified spelling is what a consumer writes then.
          if shadowed?(export)
            return "#{MARK}#{export.unit.path}#{MARK}#{export.name}#{MARK}" + suffix
          end
          if (owner = claimed[export.name]?) && owner != export.unit.path
            notes.add "collide", "#{path}: `#{export.name}` is #{owner}'s here, so #{export.unit.path}'s stays qualified"
            # The qualified spelling is the *final* module's, and modules
            # that form an import cycle are merged after this runs — so a
            # marker rides through and the driver resolves it.
            return "#{MigrateUnit::MARK}#{export.unit.path}#{MigrateUnit::MARK}#{export.name}#{MigrateUnit::MARK}" + suffix
          end
          (usings[export.unit.path] ||= Set(String).new) << export.name
          claimed[export.name] = export.unit.path
          return export.name + suffix
        end
      end
      # Not a declaration: perhaps the namespace itself, which a module
      # function is called on and a nested name is reached through.
      if unit = Command.resolve_namespace_for(token, self, @by_namespace)
        return "" if unit == self
        imports << unit.path
        return "#{MARK}#{unit.path}#{MARK}#{MARK}"
      end
      token
    end
  end

  # `resolve_namespace` reached from a unit while it renders.
  def self.resolve_namespace_for(name : String, from : MigrateUnit, by_namespace : Hash(String, MigrateUnit)) : MigrateUnit?
    name = name.lchop("::")
    from.namespace.size.downto(0) do |depth|
      candidate = (from.namespace[0, depth] + name.split("::")).join("::")
      if unit = by_namespace[candidate]?
        return unit unless unit == from
      end
    end
    nil
  end
end
