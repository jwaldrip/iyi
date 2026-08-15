# Base visitor for semantic analysis. It traverses the whole
# ASTNode tree, keeping a `current_type` in context, which corresponds
# to the type being visited according to class/module/lib definitions.
abstract class Crystal::SemanticVisitor < Crystal::Visitor
  getter program : Program

  # At every point there's a current type.
  # In the beginning this is the `Program` (top-level), but when
  # a class definition is visited this changes to that type, and so on.
  property current_type : ModuleType

  property! scope : Type
  setter scope

  property vars : MetaVars

  @path_lookup : Type?
  @untyped_def : Def?
  @typed_def : Def?
  @block : Block?

  # iyi: the files `import` is part way through loading, entry file first. A
  # file that appears twice in it is an import cycle — see `check_import_cycle`.
  @iyi_importing = [] of String

  def initialize(@program, @vars = MetaVars.new)
    @current_type = @program
    @exp_nest = 0
    @in_lib = false
    @in_c_struct_or_union = false
    @in_is_a = false
  end

  # Transform require to its source code.
  # The source code can be a Nop if the file was already required.
  def visit(node : Require)
    if expanded = node.expanded
      expanded.accept self
      return false
    end

    if inside_exp?
      node.raise "can't require dynamically"
    end

    location = node.location
    filename = node.string
    relative_to = location.try &.original_filename

    # Remember that the program depends on this require
    @program.record_require(filename, relative_to)

    filenames = begin
      @program.find_in_path(filename, relative_to)
    rescue ex : CrystalPath::NotFoundError
      message = "can't find file '#{ex.filename}'"
      notes = [] of String

      if ex.filename.starts_with? '.'
        if relative_to
          message += " relative to '#{relative_to}'"
        end
      else
        notes << <<-NOTE
          If you're trying to require a shard:
          - Did you remember to run `shards install`?
          - Did you make sure you're running the compiler in the same directory as your shard.yml?
          NOTE
      end

      node.raise "#{message}\n\n#{notes.join("\n")}"
    end

    if filenames
      nodes = Array(ASTNode).new(filenames.size)

      @program.run_requires(node, filenames) do |filename|
        nodes << require_file(node, filename)
      end

      expanded = Expressions.from(nodes)
    else
      expanded = Nop.new
    end

    node.expanded = expanded
    node.bind_to(expanded)
    false
  end

  # iyi: `import app/user` (R-1)
  #
  # Resolves a module path to a file and loads it at most once, so the import
  # graph is a DAG rather than textual inclusion.
  #
  # The loaded module IS namespaced: `Parser#apply_module_header` turns the
  # file's `module a/b` header into a `ModuleDef` for `A::B` before this ever
  # sees it, so `import a/b` brings in `A::B::Thing`, not a global `Thing`.
  #
  # The module's nodes do NOT land here. `import` leaves a `Nop` where it was
  # written and hands the loaded file to `Program#iyi_module_inits`, which
  # `top_level_semantic` splices ahead of the program's own code. Loading is
  # depth-first, and a module is appended only once the modules it imports
  # already are, so that list is in topological order: III.5 rule 1 — a module
  # initialises after every module it imports — holds by construction rather
  # than by the accident of an `import` preceding the body that needs it.
  #
  # That accident was observable. An `import` written below other top-level
  # code used to splice there, so the importing module ran part of its own
  # initialiser before the imported module ran any of its.
  def visit(node : ImportDecl)
    if expanded = node.expanded
      expanded.accept self
      return false
    end

    if inside_exp?
      node.raise "can't import dynamically"
    end

    path = node.path.join('/')
    location = node.location
    relative_to = location.try &.original_filename

    # iyi: the artifact, if there is one (SPEC.md IV.1). This is R-1's contract
    # arriving: a module that has a `.iyimod` is compiled against it, and its
    # source is not opened — not read, not parsed, not analysed. The source
    # need not even be there.
    artifact_path = iyi_artifact_path(node, path)

    filename = artifact_path || resolve_import(path)
    unless filename
      node.raise "can't find module '#{path}'"
    end

    @program.record_require(path, relative_to)

    check_import_cycle(node, filename)

    # Only a module read from source: `iyi_module_paths` is the list
    # `--emit-iyimod` writes from, and a module that arrived as an artifact
    # already has one.
    #
    # The way back from a filename to a module path is still needed for both
    # kinds, because the DAG edges below are keyed on filenames — so an
    # artifact's goes in a hash of its own rather than in the emit list.
    if artifact_path
      @program.iyi_artifact_modules[artifact_path] ||= path
    else
      @program.iyi_module_paths[filename] ||= path
    end

    # One edge of the import DAG. Recorded even when the module is already
    # loaded: the second importer adds no initialiser, but it does constrain
    # where that initialiser may be moved to (rule 2).
    (@program.iyi_module_imports[@iyi_importing.last] ||= [] of String) << filename

    # Load-once. A module imported by several others is compiled once, and so
    # is initialised once — the second importer adds no entry to the list.
    if @program.requires.add?(filename)
      @program.iyi_module_inits <<
        if artifact_path
          import_artifact(node, artifact_path)
        else
          import_file(node, filename)
        end
    end

    expanded = Nop.new
    node.expanded = expanded
    node.bind_to expanded
    false
  end

  # Resolves `a/b` to a file.
  #
  # Module paths are ABSOLUTE, resolved from the project root — never relative
  # to the importing file. That is what makes `import app/greeter` mean the
  # same module no matter which file writes it; a relative reading would make
  # a path's meaning depend on its location, and two files could disagree
  # about what `app/greeter` is. Go takes the same position.
  #
  # The project root is the directory of the entry file until iyi has a
  # manifest to declare one.
  #
  # `.iyi` wins over `.cr` so an iyi module can shadow a Crystal file of the
  # same name during the transition.
  private def resolve_import(path : String) : String?
    candidates = [] of String

    if root = project_root
      candidates << File.join(root, "#{path}.iyi")
      candidates << File.join(root, "#{path}.cr")
    end

    @program.crystal_path.entries.each do |entry|
      candidates << File.join(entry, "#{path}.iyi")
      candidates << File.join(entry, "#{path}.cr")
    end

    candidates.find { |candidate| File.file?(candidate) }
  end

  private def project_root : String?
    filename = @program.filename
    filename ? File.dirname(filename) : nil
  end

  # iyi: refuses an import cycle (R-1, SPEC.md III.5 rule 1).
  #
  # A cycle used to compile. It was refused only where a module needed one of
  # the other's names at *declaration* time — the second module of the pair is
  # loaded from inside the first's `import`, before the first's own body has
  # been seen, so its declarations are not there yet. Everything that resolves
  # later got through: a cycle whose only crossing use is inside a `def` built
  # and ran, and so did one that closed through the entry module.
  #
  # That is the accident rule 1 no longer relies on, and it is the one IV.4's
  # coherence proof rests on. Reported as a cycle, so the author reads the
  # cause rather than an undefined constant somewhere along it.
  private def check_import_cycle(node : ImportDecl, filename : String) : Nil
    # The entry file is the root of the walk and never reaches `import_file`,
    # so seed it here — a cycle that closes through it is still a cycle.
    if @iyi_importing.empty?
      @iyi_importing << @program.filename.to_s
    end

    index = @iyi_importing.index(filename)
    return unless index

    chain = @iyi_importing[index..].map { |file| iyi_module_name(file) }
    chain << iyi_module_name(filename)

    node.raise <<-MSG
      import cycle

          #{chain.join(" -> ")}

      `import` forms a DAG (R-1). A cycle has no initialisation order — a \
      module initialises after every module it imports (SPEC.md III.5 rule 1), \
      and here each would have to go after the other — and it is what makes at \
      most one module able to define any given impl (SPEC.md IV.4). Move what \
      the modules in the cycle share into a module they both import.
      MSG
  end

  # The module path a file would be imported by, for diagnostics. Files outside
  # the project root have none, so they keep their name.
  private def iyi_module_name(filename : String) : String
    root = project_root
    if root && filename.starts_with?("#{root}/")
      filename[(root.size + 1)..].sub(/\.(iyi|cr)$/, "")
    else
      filename
    end
  end

  # iyi: an imported module is declared at the top level (R-1).
  #
  # Wherever the `import` is written. `apply_module_header` lifts the ones at
  # the head of a file out of the module they would otherwise be nested in, and
  # that covered every import until one was written lower down: `import
  # boot/registry` below `samples/init_order`'s own code declared
  # `Samples::InitOrder::Boot::Registry`, a module nobody else could name.
  #
  # It compiled, which is why it lasted. The importing file finds the nested
  # module under the same name it would have found the real one under, so the
  # only visible effect was on anyone looking from outside — and the first to
  # look was `--emit-iyimod`, which wrote `boot/registry.iyimod` with no
  # exports at all, because there was no `Boot::Registry` at the top level to
  # read them off. III.5 had already made a module's initialiser independent of
  # where its `import` is written; this is its namespace catching up.
  private def iyi_at_top_level(&)
    old_type = @current_type
    @current_type = @program
    begin
      yield
    ensure
      @current_type = old_type
    end
  end

  # iyi: where `import a/b` would find `a/b.iyimod` (SPEC.md IV.1).
  #
  # Nowhere at all unless `--use-iyimod` named a directory, so an ordinary
  # build is the one that was there before this existed.
  private def iyi_artifact_path(node : ImportDecl, path : String) : String?
    dir = @program.iyi_module_dir
    return unless dir

    candidate = File.join(dir, "#{path}.iyimod")
    return unless File.file?(candidate)

    reason = iyi_artifact_stale(path, dir)
    return candidate unless reason

    # The artifact is no longer the module. A build that also writes artifacts
    # is the incremental loop, and recompiling this module from its source —
    # and rewriting the artifact on the way out — is what it asked for.
    return nil if @program.iyi_rewrites_artifacts && resolve_import(path)

    node.raise <<-MESSAGE
      #{candidate} is not "#{path}" any more: #{reason}

      An artifact is read only while it still describes its module, or a build
      would compile against a surface nobody has and link code nobody wrote
      (SPEC.md IV.3). Rebuild it with --emit-iyimod, or pass --emit-iyimod to
      this build and let it rewrite what has moved.
      MESSAGE
  end

  # iyi: why *module_path*'s artifact is no longer the module, or nil if it
  # still is (SPEC.md IV.3).
  #
  # Two questions, and the second is the one that makes this a graph. Does the
  # artifact still describe the source it was written from — which is what the
  # source hash answers, and which is unasked when there is no source, since
  # then the artifact is all there is. And is every module it was compiled
  # against still the module it was compiled against: an edge records what the
  # far end hashed to, so a dependency whose *interface* moved invalidates this
  # one even though its own file has not been touched.
  #
  # Memoised on the program, because one module's answer is part of the answer
  # for everything that imports it and the graph is walked from every entry.
  private def iyi_artifact_stale(module_path : String, dir : String) : String?
    staleness = @program.iyi_artifact_staleness
    return staleness[module_path] if staleness.has_key?(module_path)

    # Provisionally stale, so a cycle among the artifacts terminates. R-1
    # forbids one in the source; a directory of stale artifacts is not the
    # source and cannot be trusted to have kept the rule.
    staleness[module_path] = "its imports form a cycle"
    staleness[module_path] = iyi_compute_artifact_stale(module_path, dir)
  end

  private def iyi_compute_artifact_stale(module_path : String, dir : String) : String?
    candidate = File.join(dir, "#{module_path}.iyimod")
    return "there is no artifact for it" unless File.file?(candidate)

    summary =
      begin
        IyiMod.read_summary(candidate)
      rescue ex : IyiMod::Error
        return ex.message.to_s
      end

    # An artifact from before the hashes existed cannot answer, and IV.5's
    # equality on the header is checked where the artifact is read rather than
    # here: this is about whether the file still describes its module, not
    # about whether this compiler may adopt it at all.
    return nil if summary.hashes.source.empty?

    if source = resolve_import(module_path)
      unless IyiMod.digest(File.read(source)) == summary.hashes.source
        return "#{source} has changed since it was written"
      end
    end

    summary.imports.each do |edge|
      if reason = iyi_artifact_stale(edge.module_name, dir)
        return "\"#{edge.module_name}\", which it imports, has: #{reason}"
      end

      dependency = IyiMod.read_summary(File.join(dir, "#{edge.module_name}.iyimod"))
      unless dependency.hashes.interface == edge.interface
        return "the surface of \"#{edge.module_name}\", which it imports, has changed"
      end
      unless dependency.hashes.implementation == edge.implementation
        return "the bodies \"#{edge.module_name}\" ships for it to compile have changed"
      end
    end

    nil
  end

  # iyi: compiles an imported module from its `.iyimod` (SPEC.md IV.1).
  #
  # The artifact is read, rendered back to the declarations it was built from,
  # and those are parsed and analysed in place of the module's source. What
  # that removes is the module's *bodies* — the part of a dependency that is
  # not a consumer's business (IV.2) and the part there is most of.
  #
  # The module contributes **no initialiser**. Its top-level code is not a
  # declaration and is not in the file, so III.5's ordering has nothing of it
  # to order. That is the honest edge of what an artifact buys today: enough to
  # typecheck against, not enough to run, which is why a build that reads them
  # is a front-end-only build until `ObjectCode` exists (IV.1a).
  private def import_artifact(node : ImportDecl, artifact_path : String) : ASTNode
    artifact =
      begin
        IyiMod.read(artifact_path, want_object_code: @program.iyi_wants_object_code)
      rescue ex : IyiMod::Error
        node.raise ex.message.to_s
      end

    check_artifact_matches node, artifact, artifact_path

    # A module's own top-level code travels and is compiled here. What does not
    # is runnable code inside a *type* body — a class variable's initialiser,
    # which belongs to the type — and a build given a module with one would
    # link and run with that part silently missing. Refused here, where the
    # module and the reason are both nameable.
    if artifact.has_initialiser && @program.iyi_wants_object_code
      node.raise <<-MESSAGE
        "#{artifact.module_name}" has code inside a type body that has to run,
        and a .iyimod carries a module's own top level and no more (SPEC.md
        III.5, IV.1g).

        A program built against this artifact would link and run with that part
        never having happened. Build it from source, or pass --no-codegen to
        typecheck against the artifact.
        MESSAGE
    end

    unless artifact.object_code.empty?
      @program.iyi_artifact_objects[artifact.module_name] = artifact.object_code
    end

    # What this module hashed to, for the artifacts this build writes: an edge
    # records the far end's hashes whichever way the far end arrived (IV.3).
    @program.iyi_artifact_hashes[artifact.module_name] = artifact.hashes

    source = String.build { |io| IyiMod.declarations(artifact, io) }
    parser = @program.new_parser(source)
    parser.filename = artifact_path
    # The path is where these declarations came from and not a file anyone can
    # read them out of, so the text goes where an error will look for it.
    Crystal.register_iyi_declarations artifact_path, source
    @iyi_importing << artifact_path
    begin
      parsed_nodes = parser.parse
      parsed_nodes = @program.normalize(parsed_nodes, inside_exp: false)
      read_iyi_artifact_constants artifact, parsed_nodes
      parsed_nodes.accept IyiMod::DeclarationMarker.new
      iyi_at_top_level { parsed_nodes.accept self }
    rescue ex : CodeError
      node.raise "while importing \"#{node.path.join('/')}\" from its .iyimod", ex
    rescue ex
      raise Error.new "while importing \"#{node.path.join('/')}\" from its .iyimod", ex
    ensure
      @iyi_importing.pop
    end

    # The declarations join the tree, exactly as a module read from source
    # does. Accepting them here is enough for name lookup and no more: an
    # instance variable's type is settled by `TypeDeclarationVisitor`, a
    # separate pass over the *tree*, so `@items : Array(T)` read from an
    # artifact and never spliced in was a declaration the compiler had parsed,
    # accepted, and could not see — "can't infer the type of instance variable
    # `@items`" on the line that assigns it.
    #
    # It is still not an initialiser. There is nothing here to run, which is
    # what makes this safe: III.5 orders what modules *do*, and a file of
    # declarations does nothing.
    mark_iyi_artifact_types artifact
    number_iyi_artifact_types node, artifact

    FileNode.new(parsed_nodes, artifact_path)
  end

  # iyi: creates the types the artifact's object code refers to a type id of,
  # so that this program numbers them (SPEC.md IV.1g).
  #
  # A type id is an external reference — the module's unit refers to
  # `Array(Item):type_id` and the linker resolves it from a definition in this
  # program's `_main`. This program defines one for every type it has, and
  # `Array(Item)` is not among them: it exists in the producing build because
  # of a body that stayed behind, and nothing in the declarations read here
  # would ever create it. Naming it is enough — the type has to be numbered,
  # not used, and creating it is what puts it in the numbering.
  #
  # Nothing to do for a build that generates no code: it links nothing, so it
  # numbers nothing.
  private def number_iyi_artifact_types(node : ImportDecl, artifact : IyiMod::Artifact) : Nil
    return if artifact.object_code.empty?

    artifact.type_ids.each do |name|
      parser = @program.new_parser(name)
      parser.next_token
      type_node = parser.parse_bare_proc_type
      parser.check :EOF
      # Reaching what the module keeps to itself, which is what these names are
      # made of: `Array(Router::RouteDefinition)` names a `private record` and
      # the artifact carries it as one. R-2b is not weakened by that — the type
      # arrives declared and unreachable, exactly as it is when the module is
      # read from source, and this is the compiler restoring the module's own
      # instantiation rather than anybody naming it.
      @program.lookup_type(type_node, include_private: true)
    rescue CodeError
      # A name this build cannot resolve. The module's own types travel with
      # the artifact, unexported ones included, so what is left is an
      # instantiation at somebody *else's* unexported type — reachable from
      # neither module. Refused with both names rather than left to the linker,
      # which would report the mangled symbol and no module at all.
      node.raise <<-MESSAGE
        "#{artifact.module_name}" numbers `#{name}`, and this build cannot name it

        Its object code refers to that type's id, which is resolved from a
        definition in this program — so this program has to have the type. This
        module's own types travel with its artifact, so the one it cannot name
        belongs to a module that does not export it (SPEC.md IV.1g).

        Build the module from source, or export the type it names.
        MESSAGE
    end
  end

  # iyi: reads the constants the artifact's object code reads, on its behalf
  # (SPEC.md IV.1g).
  #
  # A constant is typed and initialised where it is *read* — `visit(Path)` types
  # its value the first time, and `codegen_assign` initialises it only if
  # `const.used?`. On the far side of an artifact the only reader is machine
  # code this build did not compile, so `kemal/dsl`'s `APP` was declared,
  # assigned in the initialiser that travelled, and never given a type or a
  # symbol — every exported method in the unit called through a global nothing
  # defined.
  #
  # Marking it used is not enough and was tried first: without a read its value
  # has no type, and the next pass says it cannot infer one. So the compiler
  # reads it, by appending the paths to the declarations before they are
  # analysed. That costs one load in the consuming program and puts the
  # constant back on the ordinary path — initialisation stays lazy and stays in
  # III.5's order, because reading a constant is what initialises it.
  private def read_iyi_artifact_constants(artifact : IyiMod::Artifact, nodes : ASTNode) : Nil
    return if artifact.object_code.empty? || artifact.constants.empty?
    return unless nodes.is_a?(Expressions)

    artifact.constants.each do |name|
      nodes.expressions << Path.new(name.split("::"), global: true)
    end
  end

  # iyi: marks the types an artifact declares, so codegen declares their
  # methods rather than defining them (SPEC.md IV.1g).
  #
  # Marked whether or not the object code was read, because the mark answers a
  # front-end question too: a type carried without `pub` arrives with fields
  # and no `initialize` to assign them in, and the check that would call them
  # nilable has to know where the declaration came from. Guarding this on the
  # object code left that check firing on a `--no-codegen` build alone.
  #
  # Done here, from the artifact's own list of exported types, rather than by
  # threading a flag through the type-creation path: this is the one place that
  # knows both which module was read from a `.iyimod` and which names it
  # exported, and it is a walk over a handful of names rather than a check on
  # every type a build makes.
  private def mark_iyi_artifact_types(artifact : IyiMod::Artifact) : Nil
    return unless scope = @program.iyi_module_type(artifact.module_name)

    mark_iyi_artifact_types scope, artifact.exports.types
  end

  # Recursive, because a type's declarations are types. A nested one is as much
  # the artifact's as its container is — the object code carries the container's
  # unit, and what a `private record` inside it declares is in that unit too.
  private def mark_iyi_artifact_types(scope : Type, declarations : Array(IyiMod::TypeDecl)) : Nil
    declarations.each do |declaration|
      type = scope.types?.try &.[]?(declaration.name)
      next unless type

      type.iyi_from_artifact = true
      mark_iyi_artifact_types type, declaration.types
    end
  end

  # iyi: IV.5 — an artifact from another compiler, target or set of flags is
  # refused, never migrated.
  #
  # Refused rather than quietly ignored in favour of the source. A build that
  # asked to be compiled against artifacts and was silently given the source
  # instead is slower than it looks and proves nothing, which for the one
  # measurement this project exists for is the worst answer available.
  private def check_artifact_matches(node : ImportDecl, artifact : IyiMod::Artifact,
                                     artifact_path : String) : Nil
    expected = IyiMod.compiler_version
    unless artifact.compiler_version == expected
      node.raise "#{artifact_path} was written by compiler #{artifact.compiler_version}, this is #{expected}. A .iyimod is rejected and rebuilt, never migrated (SPEC.md IV.5) — rebuild it with --emit-iyimod"
    end

    target = @program.codegen_target.to_s
    unless artifact.target_triple == target
      node.raise "#{artifact_path} was built for #{artifact.target_triple}, this build targets #{target} — rebuild it with --emit-iyimod"
    end

    flags = @program.flags.to_a.sort!
    unless artifact.flags == flags
      node.raise "#{artifact_path} was built with flags #{artifact.flags.join(", ")}, this build has #{flags.join(", ")}. Macros branch on flags, so an artifact built under one set cannot be adopted by a build under another — rebuild it with --emit-iyimod"
    end
  end

  private def import_file(node : ImportDecl, filename : String)
    parser = @program.new_parser(File.read(filename))
    parser.filename = filename
    parser.wants_doc = @program.wants_doc?
    @iyi_importing << filename
    begin
      parsed_nodes = parser.parse
      parsed_nodes = @program.normalize(parsed_nodes, inside_exp: false)
      iyi_at_top_level { parsed_nodes.accept self }
    rescue ex : CodeError
      node.raise "while importing \"#{node.path.join('/')}\"", ex
    rescue ex
      raise Error.new "while importing \"#{node.path.join('/')}\"", ex
    ensure
      @iyi_importing.pop
    end

    # The module's own top-level code, so the artifact can carry it, and
    # separately whether any runnable code is somewhere this cannot reach —
    # which is what a consumer has to be refused over rather than given a
    # module that half sets itself up.
    source = iyi_initialiser_source(parsed_nodes)
    @program.iyi_module_initialiser_source[filename] = source unless source.empty?
    @program.iyi_module_initialisers << filename if iyi_uncarried_initialiser?(parsed_nodes)

    FileNode.new(parsed_nodes, filename)
  end

  # iyi: whether a module's file has top-level code that has to *run* — a
  # module initialiser in III.5's sense, as opposed to declarations.
  #
  # Deliberately conservative: anything this does not recognise as a
  # declaration counts as an initialiser. Answering "no" wrongly gives a build
  # that links and silently omits the module's setup, which is the worst
  # outcome available here; answering "yes" wrongly gives a refusal that says
  # why. A `.iyimod` carries declarations only, so this is what a codegen build
  # reading one has to be told (SPEC.md IV.1g).
  # A type's body is walked rather than taken as a declaration, and that is
  # where the first version of this was wrong. `Parser#apply_module_header`
  # wraps a whole module file in a `ModuleDef` for `A::B`, so treating a
  # `ModuleDef` as a declaration made *every* module answer "no initialiser" —
  # the flag was written, and always false. A body is also where a class
  # variable's initialiser lives, which has to run for the same reason.
  private def iyi_initialiser?(node : ASTNode) : Bool
    case node
    when Expressions
      node.expressions.any? { |child| iyi_initialiser?(child) }
    when ModuleDef, ClassDef, TraitDef, ImplDef, LibDef
      iyi_initialiser?(node.body)
    when EnumDef
      node.members.any? { |member| iyi_initialiser?(member) }
    when VisibilityModifier
      # `pub struct List(T)` is a `VisibilityModifier` around the declaration,
      # not a declaration — which made every module with a `pub` type read as
      # having an initialiser, and refused three samples that were fine.
      iyi_initialiser?(node.exp)
    when Nop, ModuleHeader, ImportDecl, UsingDecl, Def, Macro, AnnotationDef,
         Alias, TypeDeclaration, AssocTypeDecl, Annotation, Include, Extend
      false
    else
      if expansion = iyi_expansion(node)
        iyi_initialiser?(expansion)
      else
        true
      end
    end
  end

  # iyi: what a macro call turned into, or nil if this is not one.
  #
  # A macro call is not code until it is expanded, and what a module's macros
  # expand to is mostly declarations: `getter name : String` is a `def` and a
  # `record Route, method : String` is a struct. Reading the call itself made
  # every module that writes one read as having runnable code in a type body,
  # which refused the module — and `getter` is the shape of every real
  # library, so the conservative answer was wrong on the ordinary case rather
  # than on a corner of one.
  #
  # Asking is possible because the top-level pass has already run over these
  # nodes by the time this does: the expansion is on the node. A call with
  # none is what it looks like — `puts "hello"` in a type body is code that
  # has to run, and a module with one is still refused.
  private def iyi_expansion(node : ASTNode) : ASTNode?
    case node
    when Call
      node.expanded
    when ExpandableNode
      node.expanded
    end
  end

  # iyi: the module's initialiser as source text, for the artifact (IV.1g).
  #
  # Only the module's *own* top level — this walks `Expressions` and the
  # `ModuleDef` the file is wrapped in, and no further. Runnable code inside a
  # type body is a class variable's initialiser, which belongs to that type and
  # is not this; `iyi_initialiser?` still sees it, which is what leaves such a
  # module refused rather than carried with a piece missing.
  #
  # In text order, because that is the order III.5 gives a module's own code.
  private def iyi_initialiser_source(node : ASTNode) : String
    statements = [] of ASTNode
    iyi_collect_initialiser node, statements
    statements.join('\n', &.to_s)
  end

  private def iyi_collect_initialiser(node : ASTNode, statements : Array(ASTNode)) : Nil
    case node
    when Expressions
      node.expressions.each { |child| iyi_collect_initialiser child, statements }
    when ModuleDef
      iyi_collect_initialiser node.body, statements
    when ClassDef, TraitDef, ImplDef, LibDef, EnumDef, Nop, ModuleHeader,
         ImportDecl, UsingDecl, Def, Macro, AnnotationDef, Alias,
         TypeDeclaration, AssocTypeDecl, Annotation, Include, Extend
      # A declaration, or a body this does not reach into.
    when VisibilityModifier
      # Whole, not unwrapped. The modifier here is Crystal's `private` — `pub`
      # is a flag on the declaration rather than a wrapper, and it does not take
      # a constant at all (SPEC.md IV.2) — and a `private CONST = compute` is
      # still the module's own code to run. Dropping the modifier on the way
      # through would carry the value and change what it is.
      statements << node if iyi_initialiser?(node.exp)
    else
      # A macro call contributes what it expanded to rather than itself. The
      # call would carry its declarations across as well, and those already
      # travel in `Exports` — a consumer that re-expanded it would declare
      # them twice.
      if expansion = iyi_expansion(node)
        iyi_collect_initialiser expansion, statements
      else
        statements << node
      end
    end
  end

  # iyi: whether the module has runnable code `iyi_initialiser_source` leaves
  # behind — which is the thing a consumer has to be refused over.
  #
  # A class variable's initialiser is the case: it belongs to the type rather
  # than to the module's own top level, so it is not in the initialiser and a
  # build given one would run with it missing.
  private def iyi_uncarried_initialiser?(node : ASTNode) : Bool
    case node
    when Expressions
      node.expressions.any? { |child| iyi_uncarried_initialiser?(child) }
    when ModuleDef
      iyi_uncarried_initialiser?(node.body)
    when VisibilityModifier
      iyi_uncarried_initialiser?(node.exp)
    when ClassDef, TraitDef, ImplDef, LibDef
      iyi_initialiser?(node.body)
    when EnumDef
      node.members.any? { |member| iyi_initialiser?(member) }
    else
      false
    end
  end

  private def require_file(node : Require, filename : String)
    # These spans are additive: a require is parsed and normalized before any
    # nested require inside it is expanded, so they never nest. The visit is
    # deliberately not timed here — `accept` recurses into nested requires, so
    # a span around it would count inner files once per enclosing file. Take
    # it as the "Semantic (top level)" stage total minus these.
    source = Prof.span("require: read") { File.read(filename) }
    if Prof.enabled?
      Prof.count("require: files")
      Prof.count("require: lines", source.count('\n'))
    end
    parser = @program.new_parser(source)
    parser.filename = filename
    parser.wants_doc = @program.wants_doc?
    begin
      parsed_nodes = Prof.span("require: parse") { parser.parse }
      parsed_nodes = Prof.span("require: normalize") { @program.normalize(parsed_nodes, inside_exp: inside_exp?) }
      # We must type the node immediately, in case a file requires another
      # *before* one of the files in `filenames`
      parsed_nodes.accept self
    rescue ex : CodeError
      node.raise "while requiring \"#{node.string}\"", ex
    rescue ex
      raise Error.new "while requiring \"#{node.string}\"", ex
    end

    FileNode.new(parsed_nodes, filename)
  end

  def visit(node : ClassDef)
    check_outside_exp node, "declare class"
    pushing_type(node.resolved_type) do
      node.hook_expansions.try &.each &.accept self
      node.body.accept self
    end
    node.set_type(@program.nil)
    false
  end

  def visit(node : ModuleDef)
    check_outside_exp node, "declare module"
    pushing_type(node.resolved_type) do
      node.body.accept self
    end
    node.set_type(@program.nil)
    false
  end

  # iyi: the top-level visitor already reopened the target and defined the
  # methods on it; this walks the body in the target's scope, the way
  # `ModuleDef` does.
  #
  # Without it the default walk visits `node.target` as an expression, and for
  # `impl Greet for Box(T) forall T` that means resolving `T` as a constant —
  # which it is not.
  def visit(node : ImplDef)
    check_outside_exp node, "declare impl"
    pushing_type(node.resolved_type) do
      node.body.accept self
    end
    node.set_type(@program.nil)
    false
  end

  # iyi: likewise, and for the same reason.
  def visit(node : TraitDef)
    check_outside_exp node, "declare trait"
    pushing_type(node.resolved_type) do
      node.body.accept self
    end
    node.set_type(@program.nil)
    false
  end

  # iyi: the trait and impl visitors above already read what this declares, so
  # by now it carries nothing left to do.
  def visit(node : AssocTypeDecl)
    node.set_type(@program.nil)
    false
  end

  def visit(node : AnnotationDef)
    check_outside_exp node, "declare annotation"
    node.set_type(@program.nil)
    false
  end

  def visit(node : EnumDef)
    check_outside_exp node, "declare enum"
    pushing_type(node.resolved_type) do
      node.members.each &.accept self
    end
    node.set_type(@program.nil)
    false
  end

  def visit(node : LibDef)
    check_outside_exp node, "declare lib"
    node.set_type(@program.nil)
    false
  end

  def visit(node : Include)
    check_outside_exp node, "include"
    node.hook_expansions.try &.each &.accept self
    node.set_type(@program.nil)
    false
  end

  # iyi: already resolved into an `include` by the top-level visitor.
  def visit(node : UsingDecl)
    check_outside_exp node, "use `using`"
    node.set_type(@program.nil)
    false
  end

  def visit(node : Extend)
    check_outside_exp node, "extend"
    node.hook_expansions.try &.each &.accept self
    node.set_type(@program.nil)
    false
  end

  def visit(node : Alias)
    check_outside_exp node, "declare alias"
    node.set_type(@program.nil)
    false
  end

  def visit(node : Def)
    check_outside_exp node, "declare def"
    node.hook_expansions.try &.each &.accept self
    node.set_type(@program.nil)
    false
  end

  def visit(node : Macro)
    check_outside_exp node, "declare macro"
    node.set_type(@program.nil)
    false
  end

  def visit(node : Annotation)
    annotations = @annotations ||= [] of Annotation
    annotations << node
    false
  end

  def visit(node : Call)
    !expand_macro(node, raise_on_missing_const: false)
  end

  def visit(node : MacroExpression)
    expand_inline_macro node
    false
  end

  def visit(node : MacroIf)
    expand_inline_macro node
    false
  end

  def visit(node : MacroFor)
    expand_inline_macro node
    false
  end

  def visit(node : MacroVerbatim)
    expansion = MacroIf.new(BoolLiteral.new(true), node)
    expand_inline_macro expansion

    node.expanded = expansion
    node.bind_to expansion

    false
  end

  def visit(node : ExternalVar | Path | Generic | ProcNotation | Union | Metaclass | Self | TypeOf)
    false
  end

  def visit(node : ASTNode)
    true
  end

  def visit_any(node)
    @exp_nest += 1 if nesting_exp?(node)

    true
  end

  def end_visit_any(node)
    @exp_nest -= 1 if nesting_exp?(node)

    if @annotations
      case node
      when Expressions
        # Nothing, will be taken care in individual expressions
      when Annotation
        # Nothing
      when Nop
        # Nothing (might happen as a result of an evaluated macro if)
      when Call
        # Don't clear annotations if these were generated by a macro
        unless node.expanded
          @annotations = nil
        end
      when MacroExpression, MacroIf, MacroFor
        # Don't clear annotations if these were generated by a macro
      else
        @annotations = nil
      end
    end
  end

  # Returns free variables
  def free_vars : Hash(String, TypeVar)?
    nil
  end

  def nesting_exp?(node)
    case node
    when Expressions, LibDef, CStructOrUnionDef, ClassDef, ModuleDef, FunDef, Def, Macro,
         Alias, Include, Extend, EnumDef, VisibilityModifier, MacroFor, MacroIf, MacroExpression,
         FileNode, TypeDeclaration, Require, AnnotationDef,
         # iyi declarations — like the above, these declare rather than compute,
         # so they must not count as being inside an expression.
         TraitDef, ImplDef, ModuleHeader, ImportDecl, UsingDecl, AssocTypeDecl
      false
    else
      true
    end
  end

  def lookup_type(node : ASTNode,
                  free_vars = nil,
                  find_root_generic_type_parameters = true)
    current_type.lookup_type(
      node,
      free_vars: free_vars,
      allow_typeof: false,
      find_root_generic_type_parameters: find_root_generic_type_parameters
    )
  end

  def check_outside_exp(node, op)
    node.raise "can't #{op} dynamically" if inside_exp?
  end

  def expand_macro(node, raise_on_missing_const = true, first_pass = false, accept = true)
    if expanded = node.expanded
      @exp_nest -= 1
      eval_macro(node) do
        expanded.accept self if accept
      end
      @exp_nest += 1
      return true
    end

    obj = node.obj
    case obj
    when Path
      base_type = @path_lookup || @scope || @current_type
      macro_scope = base_type.lookup_type_var?(obj, free_vars: free_vars, raise: raise_on_missing_const)
      return false unless macro_scope.is_a?(Type)

      macro_scope = macro_scope.remove_alias

      the_macro = macro_scope.metaclass.lookup_macro(node.name, node.args, node.named_args)
      node.raise "private macro '#{node.name}' called for #{obj}" if the_macro.is_a?(Macro) && the_macro.visibility.private?
    when Nil
      return false if node.super? || node.previous_def?
      the_macro = node.lookup_macro
    else
      return false
    end

    return false unless the_macro.is_a?(Macro)

    # If we find a macro outside a def/block and this is not the first pass it means that the
    # macro was defined before we first found this call, so it's an error
    # (we must analyze the macro expansion in all passes)
    if !@typed_def && !@block && !first_pass
      node.raise "macro '#{node.name}' must be defined before this point but is defined later"
    end

    expansion_scope = (macro_scope || @scope || current_type)

    args, named_args = expand_macro_arguments(node, expansion_scope)

    @exp_nest -= 1
    generated_nodes = expand_macro(the_macro, node, visibility: node.visibility, accept: accept) do
      old_args, old_named_args = node.args, node.named_args
      node.args, node.named_args = args, named_args
      expanded_macro, macro_expansion_pragmas = @program.expand_macro the_macro, node, expansion_scope, expansion_scope, @untyped_def
      node.args, node.named_args = old_args, old_named_args
      {expanded_macro, macro_expansion_pragmas}
    end
    @exp_nest += 1

    node.expanded = generated_nodes
    node.expanded_macro = the_macro
    node.bind_to generated_nodes

    true
  end

  def expand_macro(the_macro, node, mode = nil, *, visibility : Visibility, accept = true, &)
    expanded_macro, macro_expansion_pragmas =
      eval_macro(node) do
        yield
      end

    mode ||= if @in_c_struct_or_union
               Parser::ParseMode::LibStructOrUnion
             elsif @in_lib
               Parser::ParseMode::Lib
             else
               Parser::ParseMode::Normal
             end

    # We could do Set.new(@vars.keys) but that creates an intermediate array
    local_vars = Set(String).new(initial_capacity: @vars.size)
    @vars.each_key { |key| local_vars << key }

    generated_nodes = @program.parse_macro_source(expanded_macro, macro_expansion_pragmas, the_macro, node, local_vars,
      current_def: @typed_def,
      inside_type: !current_type.is_a?(Program),
      inside_exp: @exp_nest > 0,
      mode: mode,
      visibility: visibility,
    )

    node.doc ||= annotations_doc @annotations

    if node_doc = node.doc
      generated_nodes.accept PropagateDocVisitor.new(node_doc)
    end

    generated_nodes.accept self if accept
    generated_nodes
  end

  class PropagateDocVisitor < Visitor
    @doc : String

    def initialize(@doc)
    end

    def visit(node : ClassDef | ModuleDef | EnumDef | Def | FunDef | Macro | AnnotationDef | Alias | Assign | Call)
      node.doc ||= @doc
      false
    end

    def visit(node : ASTNode)
      true
    end
  end

  def expand_macro_arguments(call, expansion_scope)
    # If any argument is a MacroExpression, solve it first and
    # replace Path with Const/TypeNode if it denotes such thing
    args = call.args
    named_args = call.named_args

    if args.any?(MacroExpression) || named_args.try &.any? &.value.is_a?(MacroExpression)
      @exp_nest -= 1
      args = args.map do |arg|
        expand_macro_argument(arg, expansion_scope)
      end
      named_args = named_args.try &.map do |named_arg|
        value = expand_macro_argument(named_arg.value, expansion_scope)
        NamedArgument.new(named_arg.name, value)
      end
      @exp_nest += 1
    end

    {args, named_args}
  end

  def expand_macro_argument(node, expansion_scope)
    if node.is_a?(MacroExpression)
      node.accept self
      expanded = node.expanded.not_nil!
      if expanded.is_a?(Path)
        expanded_type = expansion_scope.lookup_path(expanded)
        case expanded_type
        when Const
          expanded = expanded_type.value
        when Type
          expanded = TypeNode.new(expanded_type)
        end
      end
      expanded
    else
      node
    end
  end

  def expand_inline_macro(node, mode = nil, accept = true)
    if expanded = node.expanded
      eval_macro(node) do
        expanded.accept self if accept
      end
      return expanded
    end

    the_macro = Macro.new("macro_#{node.object_id}", [] of Arg, node).at(node)

    skip_macro_exception = nil

    generated_nodes = expand_macro(the_macro, node, mode: mode, visibility: :public, accept: accept) do
      @program.expand_macro node, (@scope || current_type), @path_lookup, free_vars, @untyped_def
    rescue ex : SkipMacroException
      skip_macro_exception = ex
      {ex.expanded_before_skip, ex.macro_expansion_pragmas}
    end

    node.expanded = generated_nodes
    node.bind_to generated_nodes

    raise skip_macro_exception if skip_macro_exception

    generated_nodes
  end

  def eval_macro(node, &)
    yield
  rescue ex : TopLevelMacroRaiseException
    # If the node that caused a top level macro raise is a `Call`, it denotes it happened within the context of a macro.
    # In this case, we want the inner most exception to be the call of the macro itself so that it's the last frame in the trace.
    # This will make the actual `#raise` method call be the first frame.
    if node.is_a? Call
      ex.inner = Crystal::MacroRaiseException.for_node node, ex.message
    end

    # Otherwise, if the current node is _NOT_ a `Call`, it denotes a top level raise within a method.
    # In this case, we want the same behavior as if it were a `Call`, but do not want to set the inner exception here since that will be handled via `Call#bubbling_exception`.
    # So just re-raise the exception to keep the original location intact.
    raise ex
  rescue ex : MacroRaiseException
    # Raise another exception on this node, keeping the original as the inner exception.
    # This will retain the location of the node specific raise as the last frame, while also adding in this node into the trace.
    #
    # If the original exception does not have a location, it'll essentially be dropped and this node will take its place as the last frame.
    node.raise ex.message, ex, exception_type: Crystal::MacroRaiseException
  rescue ex : Crystal::CodeError
    node.raise "expanding macro", ex
  end

  def process_annotations(annotations, &)
    annotations.try &.each do |ann|
      annotation_type = lookup_annotation(ann)
      validate_annotation(annotation_type, ann)
      yield annotation_type, ann
    end
  end

  def lookup_annotation(ann)
    # TODO: Since there's `Int::Primitive`, and now we'll have
    # `::Primitive`, but there's no way to specify ::Primitive
    # just yet in annotations, we temporarily hardcode
    # that `Primitive` inside annotations means the top
    # level primitive.
    # We also have the same problem with File::Flags, which
    # is an enum marked with Flags annotation.
    if ann.path.single?("Primitive")
      type = @program.primitive_annotation
    elsif ann.path.single?("Flags")
      type = @program.flags_annotation
    else
      type = lookup_type(ann.path)
    end

    unless type.is_a?(AnnotationType)
      ann.raise "#{ann.path} is not an annotation, it's a #{type.type_desc}"
    end

    type
  end

  def validate_annotation(annotation_type, ann)
    case annotation_type
    when @program.deprecated_annotation
      # Check whether a DeprecatedAnnotation can be built.
      # There is no need to store it, but enforcing
      # arguments makes sense here.
      DeprecatedAnnotation.from(ann)
    when @program.experimental_annotation
      # ditto DeprecatedAnnotation
      ExperimentalAnnotation.from(ann)
    end
  end

  private def annotations_doc(annotations)
    annotations.try(&.first?).try &.doc
  end

  def check_class_var_annotations
    thread_local = false
    process_annotations(@annotations) do |annotation_type, ann|
      if annotation_type == @program.thread_local_annotation
        thread_local = true
      else
        ann.raise "class variables can only be annotated with ThreadLocal"
      end
    end
    thread_local
  end

  def check_allowed_in_lib(node, type = node.type.instance_type)
    unless type.allowed_in_lib?
      msg = String.build do |msg|
        msg << "only primitive types, pointers, structs, unions, enums and tuples are allowed in lib declarations, not #{type}"
        msg << " (did you mean LibC::Int?)" if type == @program.int
        msg << " (did you mean LibC::Float?)" if type == @program.float
      end
      node.raise msg
    end

    type
  end

  def check_declare_var_type(node, declared_type, variable_kind)
    type = declared_type.instance_type

    if type.is_a?(GenericClassType)
      node.raise "can't declare variable of generic non-instantiated type #{type}"
    end

    unless type.can_be_stored?
      node.raise "can't use #{type} as the type of #{variable_kind} yet, use a more specific type"
    end

    declared_type
  end

  def class_var_owner(node)
    scope = (@scope || current_type).class_var_owner

    if scope.is_a?(Program)
      node.raise "can't use class variables at the top level"
    end

    scope.as(ClassVarContainer)
  end

  def interpret_enum_value(node : ASTNode, target_type : IntegerType? = nil)
    MathInterpreter
      .new(current_type, self, target_type)
      .interpret(node)
  end

  def inside_exp?
    @exp_nest > 0
  end

  def pushing_type(type : ModuleType, &)
    old_type = @current_type
    @current_type = type
    read_annotations
    yield
    @current_type = old_type
  end

  # Returns the current annotations and clears them for subsequent readers.
  def read_annotations
    annotations = @annotations
    @annotations = nil
    annotations
  end
end
