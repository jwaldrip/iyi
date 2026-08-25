module Iyi
  # Manages cache files in the ".iyi" directory.
  #
  # For each compiled program a directory is created in the cache
  # that stores .bc and .o files that could possibly be reused
  # from a previous compilation.
  #
  # To keep the cache dir small, only the 10 most recently used
  # directories are kept. We use the directory's modification
  # time for this.
  class CacheDir
    def self.instance
      @@instance ||= new
    end

    @dir : String?

    private def initialize
    end

    # Returns the directory where cache files related to the
    # given sources will be stored. The directory will be
    # created if it doesn't exist.
    def directory_for(sources : Array(Compiler::Source))
      directory_for(sources.first.filename)
    end

    # Returns the directory where cache files related to the
    # given filenames will be stored. The directory will be
    # created if it doesn't exist.
    def directory_for(filename : String)
      dir = compute_dir

      filename = ::Path[filename]
      name = String.build do |io|
        filename.each_part do |part|
          if io.empty?
            if part == "#{filename.anchor}"
              part = "#{filename.drive}"[..0]
            end
          else
            io << '-'
          end
          io << part
        end
      end
      output_dir = File.join(dir, name)
      Dir.mkdir_p(output_dir)
      output_dir
    end

    # Keeps the 10 most recently used directories in the cache,
    # and removes all others. Directories a compiler is working in right now
    # are kept whatever their age (see `#directory_in_use?`).
    def cleanup(dir = compute_dir)
      entries = gather_cache_entries(dir)
      cleanup_dirs(entries)
    end

    # Returns a filename that has prepended the cache directory.
    def join(filename)
      dir = compute_dir
      File.join(dir, filename)
    end

    # Returns the cache directory, without creating it.
    #
    # iyi: naming a cache directory is not the same as needing one, and this
    # method has only ever been asked the first question: its one caller is
    # `Crystal::CACHE_DIR` in `program.cr`, a constant every analysed program
    # gets whether or not it reads it, and whose documented meaning is what
    # `IYI_CACHE_DIR` is configured to. It used to answer by creating a
    # directory and calling `exit 1` when it could not, which made the front end
    # — a binary that generates no code and writes no cache — refuse to analyse
    # anything on a filesystem with nowhere writable:
    #
    #     Error: can't create cache directory.
    #     crystal needs a cache directory. These directories were candidates for it:
    #      - /.iyi
    #     but none of them are writable.
    #
    # That is a wasm module reading source out of a host's virtual filesystem,
    # and it is also any sandbox, any read-only root, and any CI container
    # running `--no-codegen`. The paths that actually write a cache — `#join`,
    # `#directory_for`, `#cleanup` — still create it, which is where creating it
    # belongs.
    def dir
      compute_dir(create: false)
    end

    private def compute_dir(create : Bool = true)
      dir = @dir
      return dir if dir

      # Try to use one of these as a cache directory, in order
      candidates = {% begin %}
        [
          Config.env("CACHE_DIR"),
          {% if flag?(:windows) %}
            ENV["LOCALAPPDATA"]?.try { |dir| "#{dir}/iyi/cache" },
            ENV["USERPROFILE"]?.try { |home| "#{home}/.cache/iyi" },
            ENV["USERPROFILE"]?.try { |home| "#{home}/.iyi" },
          {% else %}
            ENV["XDG_CACHE_HOME"]?.try { |home| "#{home}/iyi" },
            ENV["HOME"]?.try { |home| "#{home}/.cache/iyi" },
            ENV["HOME"]?.try { |home| "#{home}/.iyi" },
          {% end %}
          ".iyi",
        ]
      {% end %}
      candidates = candidates
        .compact
        .map! { |file| File.expand_path(file) }
        .uniq!

      # Asked only for the name: the first candidate that is already a
      # directory, and otherwise the first candidate, which is what would be
      # created if anything ever needed to. Nothing is written and the answer is
      # not memoised, so a later caller that does need the directory still
      # creates it.
      unless create
        return candidates.find { |candidate| Dir.exists?(candidate) } || candidates.first
      end

      # Return the first one for which we could create a directory
      candidates.each do |candidate|
        Dir.mkdir_p(candidate)
        return @dir = candidate
      rescue File::Error
        # Try next one
      end

      msg = String.build do |io|
        io.puts "Error: can't create cache directory."
        io.puts
        io.puts "#{Iyi::Command.program_name} needs a cache directory. These directories were candidates for it:"
        io.puts
        candidates.each do |candidate|
          io << " - " << candidate << '\n'
        end
        io.puts
        io.puts "but none of them are writable."
        io.puts
        io.puts "Please specify a writable cache directory by setting the IYI_CACHE_DIR environment variable."
      end

      puts msg
      exit 1
    end

    private def cleanup_dirs(entries)
      entries
        .select { |dir| Dir.exists?(dir) }
        .sort_by! { |dir| File.info?(dir).try(&.modification_time) || Time.unix(0) }
        .reverse!
        .skip(10)
        .each { |name| FileUtils.rm_rf(name) unless directory_in_use?(name) }
    end

    # iyi: whether a compiler is working in this directory right now.
    #
    # The rule above is "keep the ten most recently used", and a directory's
    # last use is read from its modification time — which stops moving while a
    # build sits in an optimization pass, writing nothing. Ten other builds in
    # that window and this one's directory was deleted underneath it, from
    # another process, mid-codegen. What came out was an object file that could
    # not be written, or a linker asking for object files nobody had written.
    #
    # A build already says it is using its directory: it holds `compiler.lock`
    # there for the whole of codegen and linking. This asks.
    def directory_in_use?(dir : String) : Bool
      lock = File.join(dir, "compiler.lock")
      return false unless File.exists?(lock)

      File.open(lock, "r") do |file|
        begin
          file.flock_exclusive(blocking: false)
        rescue IO::Error
          return true
        end
        file.flock_unlock
      end
      false
    rescue File::Error
      # The directory answered nothing we can read. Deleting it is the one
      # thing that can lose someone else's work, so don't.
      true
    end

    private def gather_cache_entries(dir)
      Dir.children(dir).map! { |name| File.join(dir, name) }
    end
  end
end
