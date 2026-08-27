# iyi: the piece that turns a manifest into search roots. `iyi build` calls
# this once, before semantic: if the entry file's directory has an
# `iyi.mod`, its requirements are resolved (MVS, resolver.cr), every
# selection is checked out (fetcher.cr), and the program gets a prefix
# table the import resolver consults — longest prefix first, so
# `github.com/user/lib/v2` wins over `github.com/user/lib` when both are
# required, which is how a major version is a different module (III.7).
#
# No manifest, no table, no behaviour change: the manifest is the opt-in.
require "./resolver"
require "./fetcher"

module Iyi::Mod
  module Installer
    MANIFEST = "iyi.mod"

    # The prefix table for the program whose entry file sits in
    # *entry_dir*, or an empty one when there is no manifest to serve.
    def self.table_for(entry_dir : String) : Array({String, String})
      manifest_path = File.join(entry_dir, MANIFEST)
      return [] of {String, String} unless File.file?(manifest_path)

      root = ModFile.parse(File.read(manifest_path), manifest_path)
      selections = Resolver.resolve(root) do |path, version|
        Fetcher.manifest(path, version)
      end

      table = selections.map do |selection|
        {selection.path, Fetcher.checkout(selection.path, selection.version)}
      end
      # Longest prefix first, so the most specific module answers an import.
      table.sort_by! { |(prefix, _)| -prefix.size }
      table
    end
  end
end
