# iyi: the types a Crystal `def` never wrote down, read off the program.
#
# R-2 asks an exported signature for full types, and Crystal code does not
# have them: `def call(env)` is idiomatic, and what `env` is lives in the
# whole-program inference R-1 refuses to do. The types are not *missing*,
# though — the compiler computed them to compile the program. This reads
# them back, for `iyi migrate --annotate`.
#
# Two readings, and which one wins is the whole design:
#
#   * **A parameter** is read off the *instantiated def*, where the
#     compiler bound it to compile the body. That is the type the body was
#     compiled against, so it is the one a declaration must state.
#     `initialize` is only reachable this way, since a call names `new`.
#   * **The answer** is read off the *call*, because a boundary is about
#     what a caller is handed — `def discards(io) : Nil` has a body
#     producing an `IO` and a caller receiving `Nil`, and it is the caller
#     the symbol has to agree with. This is the lesson III.6 rule 1
#     records for `tool bind`, applied to the same question one level out.
#
# A parameter two instantiations bound differently, or an answer two calls
# were handed differently, is reported as both and written as neither: a
# `pub def` cannot be two defs, and choosing for the author would be
# inventing a program.
require "./typed_def_processor"

module Iyi
  class ParamTypes < Visitor
    include TypedDefProcessor

    # `{filename, line} => {parameter name => the types seen}`
    @from_instances = {} of {String, Int32} => Hash(String, Set(String))
    @from_calls = {} of {String, Int32} => Hash(String, Set(String))
    # `{filename, line} => the types callers were handed / bodies produced`
    @call_answers = {} of {String, Int32} => Set(String)
    @body_answers = {} of {String, Int32} => Set(String)
    # `{filename, line, name} => where the bang def it calls was written.
    # A `!` cannot be part of a name in iyi (III.1.7), so a migration has
    # to rewrite these, and the rewrite depends on whose method it is: one
    # the tree defines lost its bang too, where Crystal's mutating member
    # needs the copy put back. Textually the two are the same call.
    @bang_targets = {} of {String, Int32, String} => Set(String)

    @target_location = Location.new(nil, 0, 0)

    def self.read(result : Compiler::Result) : ParamTypes
      types = new
      types.process(result)
      types
    end

    # A project has as many programs as it has entry files — an app, a
    # migration runner, a seeder — and a def only one of them calls is
    # typed only in that one. Reading each and merging is what makes the
    # answer the *project's* rather than one target's.
    def merge!(other : ParamTypes) : Nil
      {% for field in %w(from_instances from_calls) %}
        other.@{{field.id}}.each do |key, names|
          bucket = (@{{field.id}}[key] ||= {} of String => Set(String))
          names.each { |name, types| (bucket[name] ||= Set(String).new).concat(types) }
        end
      {% end %}
      other.@bang_targets.each do |key, files|
        (@bang_targets[key] ||= Set(String).new).concat(files)
      end
      {% for field in %w(call_answers body_answers) %}
        other.@{{field.id}}.each do |key, types|
          (@{{field.id}}[key] ||= Set(String).new).concat(types)
        end
      {% end %}
    end

    def process(result : Compiler::Result) : Nil
      process_result result
      result.node.accept self
    end

    # What one def's parameters were bound to: the instantiations, and
    # what only the calls saw filled in after them.
    def params(key : {String, Int32}) : Hash(String, Set(String))?
      instances = @from_instances[key]?
      calls = @from_calls[key]?
      return calls unless instances
      return instances unless calls
      merged = instances.dup
      calls.each { |name, types| merged[name] ||= types }
      merged
    end

    # What a caller is handed, and the body's own answer where no call
    # said otherwise.
    def answer(key : {String, Int32}) : Set(String)?
      @call_answers[key]? || @body_answers[key]?
    end

    # Where the bang method called at this position was written, or nil
    # if the program has no such call - a macro wrote it, or nothing was
    # instantiated.
    def bang_targets(key : {String, Int32, String}) : Set(String)?
      @bang_targets[key]?
    end

    def process_typed_def(typed_def : Def) : Nil
      if (location = typed_def.location) && (filename = location.filename).is_a?(String)
        key = {filename, location.line_number}
        record_args typed_def, key, @from_instances
        if type = typed_def.type?
          (@body_answers[key] ||= Set(String).new) << type.devirtualize.to_s
        end
      end
      typed_def.accept self
    end

    def visit(node : Call)
      record_call node
      true
    end

    def visit(node)
      true
    end

    private def record_args(a_def : Def, key : {String, Int32}, into) : Nil
      # A splat, a double splat and a block parameter have no one type to
      # read from one binding, so only the positional run before a splat
      # is recorded.
      limit = a_def.splat_index || a_def.args.size
      a_def.args.each_with_index do |arg, index|
        break if index >= limit
        next if arg.restriction
        type = arg.type?
        next unless type
        bucket = (into[key] ||= {} of String => Set(String))
        (bucket[arg.name] ||= Set(String).new) << type.devirtualize.to_s
      end
    end

    private def record_call(node : Call) : Nil
      targets = node.target_defs
      return unless targets
      if node.name.ends_with?('!') && (at = node.location) && (called_in = at.filename).is_a?(String)
        bucket = (@bang_targets[{called_in, at.line_number, node.name.rchop}] ||= Set(String).new)
        targets.each do |target|
          written_in = target.location.try(&.filename)
          bucket << (written_in.is_a?(String) ? written_in : "?")
        end
      end
      arguments = node.args
      targets.each do |target|
        location = target.location
        next unless location
        filename = location.filename
        next unless filename.is_a?(String)
        key = {filename, location.line_number}

        if type = node.type?
          (@call_answers[key] ||= Set(String).new) << type.devirtualize.to_s
        end

        limit = target.splat_index || target.args.size
        target.args.each_with_index do |arg, index|
          break if index >= limit
          next if arg.restriction
          argument = arguments[index]?
          next unless argument
          type = argument.type?
          next unless type
          bucket = (@from_calls[key] ||= {} of String => Set(String))
          (bucket[arg.name] ||= Set(String).new) << type.devirtualize.to_s
        end
      end
    end
  end

  def self.param_types(result : Compiler::Result) : ParamTypes
    ParamTypes.read(result)
  end
end
