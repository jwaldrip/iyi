# Implementation of the `crystal clear_cache` command

class Crystal::Command
  private def clear_cache
    verbose = false
    OptionParser.parse(@options) do |opts|
      # iyi: an interpolating heredoc. It was `<<-'BANNER'`, which interpolates
      # nothing, so `clear_cache --help` printed the interpolation as source
      # text under both names.
      opts.banner = <<-BANNER
        Usage: #{Crystal.program_name} clear_cache

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
