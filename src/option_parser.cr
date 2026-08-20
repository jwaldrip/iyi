# `OptionParser` is a class for command-line options processing. It supports:
#
# * Short and long modifier style options (example: `-h`, `--help`)
# * Passing arguments to the flags (example: `-f filename.txt`)
# * Subcommands
# * Automatic help message generation
#
# Run `crystal` for an example of a CLI built with `OptionParser`.
#
# NOTE: To use `OptionParser`, you must explicitly import it with `require "option_parser"`
#
# Short example:
#
# ```
# require "option_parser"
#
# upcase = false
# destination = "World"
#
# OptionParser.parse do |parser|
#   parser.banner = "Usage: salute [arguments]"
#   parser.on("-u", "--upcase", "Upcases the salute") { upcase = true }
#   parser.on("-t NAME", "--to=NAME", "Specifies the name to salute") { |name| destination = name }
#   parser.on("-h", "--help", "Show this help") do
#     puts parser
#     exit
#   end
#   parser.invalid_option do |flag|
#     STDERR.puts "ERROR: #{flag} is not a valid option."
#     STDERR.puts parser
#     exit(1)
#   end
#   parser.missing_option do |flag|
#     STDERR.puts "ERROR: #{flag} is missing an argument."
#     STDERR.puts parser
#     exit(1)
#   end
# end
#
# destination = destination.upcase if upcase
# puts "Hello #{destination}!"
# ```
#
# # Subcommands
#
# `OptionParser` also supports subcommands.
#
# Short example:
#
# ```
# require "option_parser"
#
# verbose = false
# salute = false
# welcome = false
# name = "World"
# parser = OptionParser.new do |parser|
#   parser.banner = "Usage: example [subcommand] [arguments]"
#   parser.on("salute", "Salute a name") do
#     salute = true
#     parser.banner = "Usage: example salute [arguments]"
#     parser.on("-t NAME", "--to=NAME", "Specify the name to salute") { |_name| name = _name }
#   end
#   parser.on("welcome", "Print a greeting message") do
#     welcome = true
#     parser.banner = "Usage: example welcome"
#   end
#   parser.on("-v", "--verbose", "Enabled verbose output") { verbose = true }
#   parser.on("-h", "--help", "Show this help") do
#     puts parser
#     exit
#   end
# end
#
# parser.parse
#
# if salute
#   STDERR.puts "Saluting #{name}" if verbose
#   puts "Hello #{name}"
# elsif welcome
#   STDERR.puts "Welcoming #{name}" if verbose
#   puts "Welcome!"
# else
#   puts parser
#   exit(1)
# end
# ```
class OptionParser
  class Exception < ::Exception
  end

  class InvalidOption < Exception
    def initialize(option)
      super("Invalid option: #{option}")
    end
  end

  class MissingOption < Exception
    def initialize(option)
      super("Missing option: #{option}")
    end
  end

  # :nodoc:
  enum FlagValue
    Required
    Optional
    None
  end

  # :nodoc:
  record Handler,
    value_type : FlagValue,
    block : String ->

  # Creates a new parser, with its configuration specified in the block,
  # and uses it to parse the passed *args* (defaults to `ARGV`).
  #
  # Refer to `#gnu_optional_args?` for the behaviour of the named parameter.
  def self.parse(args = ARGV, *, gnu_optional_args : Bool = false, &) : self
    parser = OptionParser.new(gnu_optional_args: gnu_optional_args)
    yield parser
    parser.parse(args)
    parser
  end

  # Creates a new parser.
  #
  # Refer to `#gnu_optional_args?` for the behaviour of the named parameter.
  def initialize(*, @gnu_optional_args : Bool = false)
    @flags = [] of String
    @handlers = Hash(String, Handler).new
    @stop = false
    @missing_option = ->(option : String) { raise MissingOption.new(option) }
    @invalid_option = ->(option : String) { raise InvalidOption.new(option) }
  end

  # Creates a new parser, with its configuration specified in the block.
  #
  # Refer to `#gnu_optional_args?` for the behaviour of the named parameter.
  def self.new(*, gnu_optional_args : Bool = false, &)
    new(gnu_optional_args: gnu_optional_args).tap { |parser| yield parser }
  end

  # Returns whether the GNU convention is followed for optional arguments.
  #
  # If true, any optional argument must follow the preceding flag in the same
  # token immediately, without any space inbetween:
  #
  # ```
  # require "option_parser"
  #
  # OptionParser.parse(%w(-a1 -a 2 -a --b=3 --b 4), gnu_optional_args: true) do |parser|
  #   parser.on("-a", "--b [x]", "optional") { |x| p x }
  #   parser.unknown_args { |args, _| puts "Remaining: #{args}" }
  # end
  # ```
  #
  # Prints:
  #
  # ```text
  # "1"
  # ""
  # ""
  # "3"
  # ""
  # Remaining: ["2", "4"]
  # ```
  #
  # Without `gnu_optional_args: true`, prints the following instead:
  #
  # ```text
  # "1"
  # "2"
  # "--b=3"
  # "4"
  # Remaining: []
  # ```
  property? gnu_optional_args : Bool

  # Establishes the initial message for the help printout.
  # Typically, you want to write here the name of your program,
  # and a one-line template of its invocation.
  #
  # Example:
  #
  # ```
  # require "option_parser"
  #
  # parser = OptionParser.new
  # parser.banner = "Usage: crystal [command] [switches] [program file] [--] [arguments]"
  # ```
  setter banner : String?

  # Establishes a handler for a *flag* or subcommand.
  #
  # Flags must start with a dash or double dash. They can also have
  # an optional argument, which will get passed to the block.
  # Each flag has a description, which will be used for the help message.
  #
  # Subcommands are any *flag* passed which does not start with a dash. They
  # cannot take arguments. When a subcommand is parsed, all subcommands are
  # removed from the OptionParser, simulating a "tree" of subcommands. All flags
  # remain valid. For a longer example, see the examples at the top of the page.
  #
  # Examples of valid flags:
  #
  # * `-a`, `-B`
  # * `--something-longer`
  # * `-f FILE`, `--file FILE`, `--file=FILE` (these will yield the passed value to the block as a string)
  #
  # Examples of valid subcommands:
  #
  # * `foo`, `run`
  def on(flag : String, description : String, &block : String ->)
    append_flag flag, description

    flag, value_type = parse_flag_definition(flag)
    @handlers[flag] = Handler.new(value_type, block)
  end

  # Establishes a handler for a pair of short and long flags.
  #
  # See the other definition of `on` for examples. This method does not support
  # subcommands.
  def on(short_flag : String, long_flag : String, description : String, &block : String ->)
    check_starts_with_dash short_flag, "short_flag", allow_empty: true
    check_starts_with_dash long_flag, "long_flag"

    if short_flag.empty?
      # Long-only option.
      append_flag long_flag, description
    else
      append_flag "#{short_flag}, #{long_flag}", description
    end

    short_flag, short_value_type = parse_flag_definition(short_flag)
    long_flag, long_value_type = parse_flag_definition(long_flag)

    # Pick the "most required" argument type between both flags
    if short_value_type.required? || long_value_type.required?
      value_type = FlagValue::Required
    elsif short_value_type.optional? || long_value_type.optional?
      value_type = FlagValue::Optional
    else
      value_type = FlagValue::None
    end

    handler = Handler.new(value_type, block)
    @handlers[short_flag] = @handlers[long_flag] = handler
  end

  # iyi: the ordered `case` over seven regex literals, written out (Appendix B
  # #22, III.10 item 3: pcre2 comes off the compiler, and this file is compiled
  # into it). `Crystal::Rx` was not an option: it is compiler-private, and the
  # stdlib does not get to depend on compiler internals.
  #
  # `case` took the first match, so the order is load-bearing and is kept:
  #
  #   1. /\A--(\S+)\s+\[\S+\]\z/         long, bracketed argument  -> Optional
  #   2. /\A--(\S+)(\s+|\=)(\S+)?\z/     long, spaced or `=`       -> Required
  #   3. /\A--\S+\z/                     long, bare                -> None
  #   4. /\A-(.)\s*\[\S+\]\z/            short, bracketed argument -> Optional
  #   5. /\A-(.)\s+\S+\z/, /\A-(.)\s+\z/, /\A-(.)\S+\z/  short     -> Required
  #   else                                                         -> None
  #
  # Rule 1 is a strict subset of rule 2 and rule 2's `=` case is a subset of
  # rule 3, which is what the order was buying; a rule 4 or 5 match on a `--`
  # definition registers `flag[0..1]`, i.e. `"--"`, which is what the old
  # `# /-(.)/ matches` note was warning about and is reproduced verbatim.
  #
  # There is no backtracking to model. Every `\S+`, `\s+` and `\s*` here is
  # followed by something it cannot itself match, so each is pinned to its
  # maximal run and one left-to-right scan decides every rule. The single place
  # greediness is observable is rule 2's `=`, below.
  #
  # `\A`/`\z` anchor the whole string with no newline tolerance, unlike `\Z`,
  # so nothing here trims a trailing "\n".
  private def parse_flag_definition(flag : String)
    if flag.starts_with?("--")
      # `(\S+)`, the flag name: it cannot cross whitespace, so it is exactly the
      # run from index 2 to the first whitespace.
      name_end = whitespace_index(flag, 2)

      if name_end.nil?
        # No whitespace, so rule 2 can only match through its `\=` branch. `(\S+)`
        # is greedy and gives ground from the right, so the split lands on the
        # LAST `=`, not the first: `--a=b=c` registers `--a=b` taking `c`. The
        # `=` may not be the name's first character, hence `> 2`.
        eq = flag.rindex('=')
        return {"--#{flag[2...eq]}", FlagValue::Required} if eq && eq > 2
        # Rule 3, which returns *flag* rather than `"--#{$1}"`.
        return {flag, FlagValue::None} if flag.size > 2
      elsif name_end > 2
        arg_start = non_whitespace_index(flag, name_end)
        # A second whitespace run leaves nothing that can reach `\z`: rules 1 and
        # 2 both fail and `--a b c` falls through to the short rules, then None.
        unless arg_start && whitespace_index(flag, arg_start)
          name = flag[2...name_end]
          return {"--#{name}", FlagValue::Optional} if arg_start && bracketed_argument?(flag, arg_start)
          # `arg_start.nil?` is rule 2's empty `(\S+)?`: `--flag ` with nothing
          # after the space still declares a required argument.
          return {"--#{name}", FlagValue::Required}
        end
      end
    end

    # Rules 4 and 5 open with `-(.)`, and `.` matches every character except a
    # newline (the engine ran with the LF newline convention and without DOTALL,
    # so CR is a `.` and LF is not; measured, not assumed). The capture is
    # unused: `flag[0..1]` is what gets registered.
    if flag.size > 2 && flag.starts_with?('-') && flag[1] != '\n'
      arg_start = non_whitespace_index(flag, 2)
      if arg_start.nil?
        # Rule 5's `/\A-(.)\s+\z/`: everything past the flag letter is whitespace.
        {flag[0..1], FlagValue::Required}
      elsif whitespace_index(flag, arg_start).nil?
        # Rule 4's `\s*` allows zero, so `-f[X]` and `-f [X]` land here alike.
        return {flag[0..1], FlagValue::Optional} if bracketed_argument?(flag, arg_start)
        # Rule 5's `/\A-(.)\s+\S+\z/` when spaced, `/\A-(.)\S+\z/` when not.
        {flag[0..1], FlagValue::Required}
      else
        {flag, FlagValue::None}
      end
    else
      # `-f` without an argument, and every definition no rule claimed.
      {flag, FlagValue::None}
    end
  end

  # iyi: `\[\S+\]\z`, given a *start* that opens the run and no whitespace from
  # there on. `\S+` is greedy, so the closing bracket is the string's last
  # character and the name between the brackets may itself contain `]`.
  private def bracketed_argument?(flag : String, start : Int32) : Bool
    flag[start] == '[' && flag.ends_with?(']') && flag.size >= start + 3
  end

  # iyi: `\s` as the compiled patterns saw it. The engine ran with PCRE2's UCP
  # flag, where `\s` is `\p{Z}` plus `\h` plus `\v`, while `Char#whitespace?` is
  # `\p{Z}` plus the ASCII controls. Those agree on every character but one:
  # U+0085 NEL, which `\v` covers and no `Z` category does. Named here rather
  # than dropped, so a definition separated by a NEL classifies as it always did.
  private def flag_whitespace?(char : Char) : Bool
    char.whitespace? || char == '\u0085'
  end

  private def whitespace_index(flag : String, start : Int32) : Int32?
    start.upto(flag.size - 1) { |i| return i if flag_whitespace?(flag[i]) }
    nil
  end

  private def non_whitespace_index(flag : String, start : Int32) : Int32?
    start.upto(flag.size - 1) { |i| return i unless flag_whitespace?(flag[i]) }
    nil
  end

  # Adds a separator, with an optional header message, that will be used to
  # print the help. The separator is placed between the flags registered (`#on`)
  # before, and the flags registered after the call.
  #
  # This way, you can group the different options in an easier to read way.
  def separator(message = "") : Nil
    @flags << message.to_s
  end

  # Sets a handler for regular arguments that didn't match any of the setup options.
  #
  # You typically use this to get the main arguments (not modifiers)
  # that your program expects (for example, filenames). The default behaviour
  # is to do nothing. The arguments can also be extracted from the *args* array
  # passed to `#parse` after parsing.
  def unknown_args(&@unknown_args : Array(String), Array(String) ->)
  end

  # Sets a handler for when a option that expects an argument wasn't given any.
  #
  # You typically use this to display a help message.
  # The default behaviour is to raise `MissingOption`.
  def missing_option(&@missing_option : String ->)
  end

  # Sets a handler for option arguments that didn't match any of the setup options.
  #
  # You typically use this to display a help message.
  # The default behaviour is to raise `InvalidOption`.
  def invalid_option(&@invalid_option : String ->)
  end

  # Sets a handler which runs before each argument is parsed. This callback is
  # not passed flag arguments. For example, `--foo=foo_arg --bar bar_arg` would
  # pass `--foo=foo_arg` and `--bar` to the callback only.
  #
  # You typically use this to implement advanced option parsing behaviour such
  # as treating all options after a filename differently (along with `#stop`).
  def before_each(&@before_each : String ->)
  end

  # Stops the current parse and returns immediately, leaving the remaining flags
  # unparsed. This is treated identically to `--` being inserted *behind* the
  # current parsed flag.
  def stop : Nil
    @stop = true
  end

  # Returns all the setup options, formatted in a help message.
  def to_s(io : IO) : Nil
    if banner = @banner
      io << banner
      io << '\n'
    end
    @flags.join io, '\n'
  end

  # Width for option list portion of summary.
  property summary_width : Int32 = 32

  def summary_width=(width : Int32)
    raise ArgumentError.new("Negative summary width: #{width}") if width < 0
    @summary_width = width
  end

  # Indentation for summary.
  property summary_indent : String = "    "

  private def append_flag(flag, description)
    # Add indent for long-only options to align with those following a short option
    flag = "    #{flag}" if flag.starts_with?("--")
    description_indent = "#{summary_indent}#{" " * summary_width} "
    description = description.gsub("\n", "\n#{description_indent}")

    if flag.size > summary_width
      @flags << "#{summary_indent}#{flag}\n#{description_indent}#{description}"
    else
      @flags << "#{summary_indent}#{flag}#{" " * (summary_width - flag.size)} #{description}"
    end
  end

  private def check_starts_with_dash(arg, name, allow_empty = false)
    return if allow_empty && arg.empty?

    unless arg.starts_with?('-')
      raise ArgumentError.new("Argument '#{name}' (#{arg.inspect}) must start with a dash (-)")
    end
  end

  private def with_preserved_state(&)
    old_flags = @flags.clone
    old_handlers = @handlers.clone
    old_banner = @banner
    old_unknown_args = @unknown_args
    old_missing_option = @missing_option
    old_invalid_option = @invalid_option
    old_before_each = @before_each
    old_summary_width = @summary_width
    old_summary_indent = @summary_indent

    begin
      yield
    ensure
      @flags = old_flags
      @handlers = old_handlers
      @stop = false
      @banner = old_banner
      @unknown_args = old_unknown_args
      @missing_option = old_missing_option
      @invalid_option = old_invalid_option
      @before_each = old_before_each
      @summary_width = old_summary_width
      @summary_indent = old_summary_indent
    end
  end

  # Parses the passed *args* (defaults to `ARGV`), running the handlers associated to each option.
  def parse(args = ARGV) : Nil
    with_preserved_state do
      # List of indexes in `args` which have been handled and must be deleted
      handled_args = [] of Int32
      double_dash_index = nil

      arg_index = 0
      while arg_index < args.size
        arg = args[arg_index]

        if @stop
          double_dash_index = arg_index - 1
          @stop = false
          break
        end

        if before_each = @before_each
          before_each.call(arg)
        end

        # -- means to stop parsing arguments
        if arg == "--"
          double_dash_index = arg_index
          handled_args << arg_index
          break
        end

        if bundle = validate_bundle(arg)
          arg_index = handle_bundled_short_options(arg, bundle, arg_index, args, handled_args)
        else
          flag, value = parse_arg_to_flag_and_value(arg)
          arg_index = handle_flag(flag, value, arg_index, args, handled_args)
        end

        arg_index += 1
      end

      # We're about to delete all the unhandled arguments in args so double_dash_index
      # is about to change. Arguments are only handled before "--", so we're deleting
      # nothing after "--", which means it's index is decremented by handled_args.size.
      # But actually we also added "--" itself to handled_args so we change it's index
      # by one less.
      if double_dash_index
        double_dash_index -= handled_args.size - 1
      end

      # After argument parsing, delete handled arguments from args.
      remove_handled_args(args, handled_args)

      # Since we've deleted all handled arguments, `args` is all unknown arguments
      # which we split by the index of any double dash argument
      if unknown_args = @unknown_args
        if double_dash_index
          before_dash = args[0...double_dash_index]
          after_dash = args[double_dash_index..-1]
        else
          before_dash = args
          after_dash = [] of String
        end
        unknown_args.call(before_dash, after_dash)
      end

      # We consider any remaining arguments which start with '-' to be invalid
      args.each_with_index do |arg, index|
        break if double_dash_index && index >= double_dash_index

        if arg.starts_with?('-') && arg != "-"
          @invalid_option.call(arg)
        end
      end
    end
  end

  private def short_arg?(arg : String) : Bool
    arg.starts_with?('-') && !arg.starts_with?("--") && arg.size > 2
  end

  # Validates all flags in a bundle before executing any handlers.
  # Returns the array of validated handlers if all flags are recognized, or nil
  # if any flag is unrecognized, so the entire bundle can be treated as a single
  # unhandled argument. Stops collecting handlers at the first value-consuming flag
  # since remaining chars become its value rather than separate flags.
  private def validate_bundle(arg : String) : Array(Handler)?
    return nil unless short_arg?(arg)
    handlers = [] of Handler
    rest = arg[1..]
    rest.each_char do |char|
      handler = @handlers["-#{char}"]?
      return nil unless handler
      handlers << handler
      # If this flag consumes a value, remaining chars become its value — stop validating
      break if handler.value_type.required? || handler.value_type.optional?
    end
    handlers
  end

  # Parses a command-line argument into a flag and optional inline value.
  private def parse_arg_to_flag_and_value(arg : String) : {String, String?}
    if arg.starts_with?("--")
      name, separator, value = arg.partition("=")
      if separator == "="
        return {name, value}
      end
    elsif short_arg?(arg)
      return {arg[0..1], arg[2..]}
    end
    {arg, nil}
  end

  private def handle_bundled_short_options(arg : String, bundle : Array(Handler), arg_index : Int32, args : Array(String), handled_args : Array(Int32)) : Int32
    bundle.each_with_index do |handler, index|
      value = arg[(index + 2)..] unless handler.value_type.none?
      handler.block.call value || ""
    end

    handled_args << arg_index
    arg_index
  end

  # Processes a single flag/subcommand. Matches original behaviour exactly.
  private def handle_flag(flag : String, value : String?, arg_index : Int32, args : Array(String), handled_args : Array(Int32)) : Int32
    return arg_index unless handler = @handlers[flag]?
    return arg_index if handler.value_type.none? && value

    handled_args << arg_index

    if !value
      case handler.value_type
      in FlagValue::Required
        value = args[arg_index + 1]?
        if value
          handled_args << arg_index + 1
          arg_index += 1
        else
          @missing_option.call(flag)
        end
      in FlagValue::Optional
        unless gnu_optional_args?
          value = args[arg_index + 1]?
          if value && !@handlers.has_key?(value)
            handled_args << arg_index + 1
            arg_index += 1
          else
            value = nil
          end
        end
      in FlagValue::None
        # do nothing
      end
    end

    # If this is a subcommand (flag not starting with -), delete all
    # subcommands since they are no longer valid.
    unless flag.starts_with?('-')
      @handlers.select! { |k, _| k.starts_with?('-') }
      @flags.select! { |entry| summary_flag?(entry) }
    end

    handler.block.call(value || "")

    arg_index
  end

  # Removes handled arguments from the args array based on handled_args indexes.
  private def remove_handled_args(args : Array(String), handled_args : Array(Int32)) : Nil
    # After argument parsing, delete handled arguments from args.
    # We reverse so that we delete args from the end
    handled_args.reverse!
    i = 0
    args.reject! do
      # handled_args is sorted in reverse so we know that i <= handled_args.last
      handled = i == handled_args.last?

      # Maintain the i <= handled_args.last invariant
      handled_args.pop if handled

      i += 1

      handled
    end
  end

  private def summary_flag?(entry : String) : Bool
    # Long-only options have extra spaces after summary_indent.
    entry.starts_with?(summary_indent) &&
      entry[summary_indent.size..].lstrip.starts_with?('-')
  end
end
