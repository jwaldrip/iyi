# iyi: minimal version selection — SPEC.md III.7's whole algorithm, quoted:
# "for each module in the graph, take the highest of the minimum versions
# anything asked for." No solver, no lockfile to fight over in a merge, and
# adding a dependency cannot silently upgrade an unrelated one.
#
# The resolver walks a worklist: the root manifest's requirements seed it,
# every visited module's own manifest feeds it, and a path's answer only
# ever goes up. Termination is the usual MVS argument — versions per path
# form a finite set the walk only climbs.
#
# Fetching is a seam (`&fetch`), so the algorithm is a pure function the
# specs can drive with a table and the build drives with git.
require "./modfile"

module Iyi::Mod
  record Selection, path : String, version : SemanticVersion do
    def to_s(io : IO) : Nil
      io << path << " v" << version
    end
  end

  module Resolver
    # *root* is the program's own manifest. *fetch* answers a module's
    # manifest at an exact version — from a checkout, a fixture, or a test
    # table — and its cost is why visited pairs are asked exactly once.
    def self.resolve(root : ModFile, &fetch : String, SemanticVersion -> ModFile) : Array(Selection)
      chosen = {} of String => SemanticVersion
      queue = root.requirements.dup
      visited = Set({String, SemanticVersion}).new

      while requirement = queue.shift?
        if requirement.path == root.path
          raise ModError.new("#{root.path} requires itself; a module's own version is whatever is checked out")
        end

        current = chosen[requirement.path]?
        chosen[requirement.path] = requirement.version if current.nil? || requirement.version > current

        # The manifest of the exact version asked for, even when a higher
        # one is already chosen: its requirements are still minimums the
        # graph stated, and MVS honours every stated minimum.
        next unless visited.add?({requirement.path, requirement.version})
        manifest = fetch.call(requirement.path, requirement.version)
        unless manifest.path == requirement.path
          raise ModError.new(
            "#{requirement.path} v#{requirement.version} says it is '#{manifest.path}'; " \
            "identity is the path, and these disagree")
        end
        queue.concat(manifest.requirements)
      end

      chosen.map { |path, version| Selection.new(path, version) }.sort_by!(&.path)
    end
  end
end
