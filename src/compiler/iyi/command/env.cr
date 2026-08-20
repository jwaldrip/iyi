# Implementation of the `crystal env` command

class Iyi::Command
  private def env
    var_names = [] of String

    OptionParser.parse(@options) do |opts|
      opts.banner = env_usage

      opts.on("-h", "--help", "Show this message") do
        puts opts
        exit
      end

      opts.unknown_args do |before, after|
        var_names = before
      end
    end

    # iyi: the same compiler ships under two names. `iyi env` prints `IYI_*`;
    # `crystal env` prints `CRYSTAL_*`, because Crystal's own specs and anyone
    # invoking the compatibility binary ask for Crystal's names. `CRYSTAL_VERSION`
    # is Crystal's version under both, which is what `--version` reports as the
    # upstream number.
    prefix = Command.program_name.upcase
    vars = {
      "#{prefix}_CACHE_DIR"    => CacheDir.instance.dir,
      "#{prefix}_EXEC_PATH"    => Iyi::Config.exec_path || "",
      "#{prefix}_PATH"         => IyiPath.default_path,
      "CRYSTAL_VERSION"        => Config.version || "",
      "#{prefix}_LIBRARY_PATH" => IyiLibraryPath.default_path,
      "#{prefix}_OPTS"         => Config.env("OPTS") || "",
    }

    if var_names.empty?
      vars.each do |key, value|
        puts "#{key}=#{Process.quote(value)}"
      end
    else
      var_names.each do |key|
        puts vars[key]?
      end
    end
  end

  private def env_usage
    <<-USAGE
    Usage: #{Command.program_name} env [var ...]

    Prints #{Command.program_name} environment information.

    By default it prints information as a shell script.
    If one or more variable names is given as arguments,
    it prints the value of each named variable on its own line.

    Options:
    USAGE
  end
end
