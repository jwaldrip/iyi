require "option_parser"
require "colorize"

# This file is included in the compiler to add usage instructions for the
# spec runner on `crystal spec --help`.

module Spec
  # :nodoc:
  #
  # Configuration for a spec runner. More global state is defined in `./dsl.cr`.
  class CLI
    # iyi: was `Regex?`. `-e` only ever held an escaped literal, so this is a
    # substring, and a `String` is what every consumer wanted (Appendix B #22).
    getter pattern : String?
    getter line : Int32?
    getter slowest : Int32?
    getter? fail_fast = false
    property? focus = false
    getter? dry_run = false
    getter? list_tags = false
    getter? color : Bool

    getter stdout : IO
    getter stderr : IO

    def initialize(@stdout : IO = STDOUT, @stderr : IO = STDERR)
      @color = Colorize.default_enabled?(@stdout, @stderr)
    end

    def add_location(file, line)
      locations = @locations ||= {} of String => Array(Int32)
      locations.put_if_absent(File.expand_path(file)) { [] of Int32 } << line
    end

    def add_tag(tag)
      if anti_tag = tag.lchop?('~')
        (@anti_tags ||= Set(String).new) << anti_tag
      else
        (@tags ||= Set(String).new) << tag
      end
    end

    getter randomizer_seed : UInt64?
    getter randomizer : Random::PCG32?

    def order=(mode)
      seed =
        case mode
        when "default"
          nil
        when "random"
          Random::Secure.rand(1..99999).to_u64 # 5 digits or less for simplicity
        when UInt64
          mode
        else
          raise ArgumentError.new("Order must be either 'default', 'random', or a numeric seed value")
        end

      @randomizer_seed = seed
      @randomizer = seed ? Random::PCG32.new(seed) : nil
    end

    getter option_parser : OptionParser { build_option_parser(without_p: false) }

    def build_option_parser(*, without_p) : OptionParser
      OptionParser.new do |opts|
        opts.banner = "crystal spec runner"
        # iyi: was `Regex.new(Regex.escape(pattern))`, which is a regex engine
        # hired to answer `String#includes?`: `Regex.escape` strips every
        # metacharacter on the way in, so the compiled pattern could only ever
        # match itself literally, and the flag is documented as "include
        # STRING". Dropping it takes pcre2 off the compiler binary, which
        # requires this file only so `crystal spec --help` can print these
        # flags (Appendix B #22).
        opts.on("-e", "--example STRING", "run examples whose full nested names include STRING") do |pattern|
          @pattern = pattern
        end
        opts.on("-l", "--line LINE", "run examples whose line matches LINE") do |line|
          @line = line.to_i
        end
        opts.on((without_p ? "" : "-p"), "--profile", "Print the 10 slowest specs") do
          @slowest = 10
        end
        opts.on("--fail-fast", "abort the run on first failure") do
          @fail_fast = true
        end
        opts.on("--location file:line", "run example at line 'line' in file 'file', multiple allowed") do |location|
          if parsed = parse_location(location)
            add_location parsed[0], parsed[1]
          else
            abort "location #{location} must be file:line"
          end
        end
        opts.on("--tag TAG", "run examples with the specified TAG, or exclude examples by adding ~ before the TAG.") do |tag|
          add_tag tag
        end
        opts.on("--list-tags", "lists all the tags used.") do
          @list_tags = true
        end
        opts.on("--order MODE", "run examples in random order by passing MODE as 'random' or to a specific seed by passing MODE as the seed value") do |mode|
          if mode.in?("default", "random")
            self.order = mode
          elsif seed = mode.to_u64?
            self.order = seed
          else
            abort("order must be either 'default', 'random', or a numeric seed value")
          end
        end
        opts.on("--junit_output OUTPUT_PATH", "generate JUnit XML output within the given OUTPUT_PATH") do |output_path|
          configure_formatter("junit", output_path)
        end
        opts.on("-h", "--help", "show this help") do |pattern|
          @stdout.puts opts
          exit
        end
        opts.on("-v", "--verbose", "verbose output") do
          configure_formatter("verbose")
        end
        opts.on("--tap", "Generate TAP output (Test Anything Protocol)") do
          configure_formatter("tap")
        end
        opts.on("--color", "Enabled ANSI colored output") do
          @color = true
        end
        opts.on("--no-color", "Disable ANSI colored output") do
          @color = false
        end
        opts.on("--dry-run", "Pass all tests without execution") do
          @dry_run = true
        end
        opts.unknown_args do |args|
        end
      end
    end

    # Blank implementation to reduce the interface of spec's option parser for
    # inclusion in the compiler. This avoids depending on more of `Spec`
    # module.
    # The real implementation in `../spec.cr` overrides this for actual use.
    def configure_formatter(formatter, output_path = nil)
    end

    # iyi: `location =~ /\A(.+?)\:(\d+)\Z/` written out, so `--location` does
    # not link pcre2 into the compiler (Appendix B #22).
    #
    # `(.+?)` is lazy, which reads as "shortest prefix", but that is not what
    # the pattern does: `(\d+)\Z` has to reach the end and `:` is not a digit,
    # so the engine backtracks until only the LAST colon is left as the split.
    # "a:1:2" is file "a:1" line 2, not file "a", so `split(':')` and every
    # leftmost scan are wrong. That is the only reason this scans backwards.
    #
    # Byte-wise because ':', '\n' and the digits are ASCII and UTF-8 is
    # self-synchronizing, so no multi-byte character can hide one of them;
    # `String#[]` would be quadratic on a non-ASCII path to learn nothing.
    private def parse_location(location : String) : {String, Int32}?
      bytes = location.to_slice

      # `\Z`, not `\z`: one final newline is tolerated and sits outside the
      # match, so "f.cr:3\n" is line 3. Exactly one of them, because
      # "f.cr:3\n\n" never matched. LF only, which is PCRE2's newline
      # convention here: '\r' and the Unicode separators are ordinary
      # characters to this pattern.
      size = bytes.size
      size -= 1 if size > 0 && bytes[size - 1] == '\n'.ord

      colon = size - 1
      while colon >= 0 && bytes[colon] != ':'.ord
        colon -= 1
      end

      # `(.+?)` needs at least one character, so a leading colon never matched.
      return nil if colon <= 0

      # `.` matches anything except a newline, so a newline left of the colon
      # failed the whole match rather than just the prefix.
      return nil if bytes[0, colon].includes?('\n'.ord.to_u8)

      # `(\d+)`: one or more, and ASCII only. pcre2 is compiled with UCP here
      # (`src/regex/pcre2.cr`), so `\d` was `\p{Nd}` and "f.cr:١" matched, then
      # died in `$2.to_i` with `Invalid Int32` and a backtrace. Rejecting it
      # here prints the documented message instead; the only inputs whose
      # behaviour changes are ones that could never have produced a line.
      digits = bytes[(colon + 1)...size]
      return nil if digits.empty?
      digits.each do |byte|
        return nil unless '0'.ord <= byte <= '9'.ord
      end

      # `to_i`, not `to_i?`: an out-of-range line number still raises, exactly
      # as `$2.to_i` did.
      {String.new(bytes[0, colon]), String.new(digits).to_i}
    end

    private def abort(msg)
      @stderr.puts msg
      exit 1
    end
  end

  @[Deprecated("This is an internal API.")]
  def self.randomizer : Random::PCG32?
    @@cli.randomizer
  end
end
