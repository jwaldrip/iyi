# Implementation of the `crystal clear_cache` command

class Iyi::Command
  private def clear_cache
    verbose = false
    OptionParser.parse(@options) do |opts|
      # iyi: unquoted, because a quoted heredoc does not interpolate and this
      # banner printed the literal text `#{Command.program_name}` at a user.
      opts.banner = <<-BANNER
        Usage: #{Command.program_name} clear_cache

        Clears the compiler cache

        Options:
        BANNER

      opts.on("-h", "--help", "Show this message") do
        puts opts
        exit
      end

      opts.on("-v", "--verbose", "Display detailed information") do
        verbose = true
      end
    end
    puts "Clearing compiler cache at #{CacheDir.instance.dir.inspect}" if verbose
    FileUtils.rm_rf(CacheDir.instance.dir)
  end
end
