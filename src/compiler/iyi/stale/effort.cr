require "json"
require "./fast_record"

module Iyi::Stale
  # One test's last known check, build and run, in seconds. A missing file,
  # or one of another format or version, is absent: nothing is written in its
  # place. Machine-local, under `tests-v1/effort/`, and never exported.
  class EffortRecord
    FORMAT  = "iyi-stale-effort"
    VERSION = 1

    # The three costs. Nil is unknown, not zero: a build not yet measured is
    # the nil that `Effort.decide` counts as 0, while a nil check or run means
    # the timing is not known.
    record Costs, check : Float64?, build : Float64?, run : Float64?

    # The check a run without a check still owes. `seen` is the fast record of
    # the inputs at that run, in the fast record's own store form, or nil when
    # there was nothing to stamp.
    record Owed, cause : String, seen : FastRecord?

    getter test : TestId
    getter costs : Costs
    getter? unservable : Bool
    getter owed : Owed?

    def initialize(@test : TestId, @costs : Costs, @unservable : Bool, @owed : Owed? = nil)
    end

    # The record of *test*, or nil. Takes no lock and writes nothing.
    def self.read(store : Store, test : TestId) : EffortRecord?
      found = parse(File.read(store.effort_path(test)))
      found if found && found.test == test
    rescue File::Error
      nil
    end

    # The record in *content*, or nil when it is corrupt, or of another format
    # or version. A `seen` that is not itself a fast record is corrupt too:
    # a later settle compares that record, and a guessed one would pay the
    # owed check on the wrong inputs.
    def self.parse(content : String) : EffortRecord?
      json = JSON.parse(content)
      return nil unless json["format"]?.try(&.as_s?) == FORMAT
      return nil unless json["version"]?.try(&.as_i?) == VERSION

      costs = json["costs"]
      owed = owed_from(json["owed"])
      new(TestId.new(json["test"]["root"].as_s, json["test"]["path"].as_s),
        Costs.new(seconds(costs["check"]), seconds(costs["build"]), seconds(costs["run"])),
        json["unservable"].as_bool, owed)
    rescue
      nil
    end

    # The record as the store keeps it.
    def to_store_json : String
      JSON.build do |json|
        json.object do
          json.field "format", FORMAT
          json.field "version", VERSION
          json.field "test" do
            json.object do
              json.field "root", test.root
              json.field "path", test.path
            end
          end
          json.field "costs" do
            json.object do
              write_seconds(json, "check", costs.check)
              write_seconds(json, "build", costs.build)
              write_seconds(json, "run", costs.run)
            end
          end
          json.field "unservable", unservable?
          json.field "owed" do
            if owed = self.owed
              json.object do
                json.field "cause", owed.cause
                json.field "seen" do
                  if seen = owed.seen
                    json.raw seen.to_store_json
                  else
                    json.null
                  end
                end
              end
            else
              json.null
            end
          end
        end
      end
    end

    private def write_seconds(json : JSON::Builder, name : String, value : Float64?) : Nil
      json.field name do
        if value
          json.number(value)
        else
          json.null
        end
      end
    end

    # Nil is unknown. A number that is not a number is corrupt, which `parse`
    # reports as absent.
    private def self.seconds(value : JSON::Any) : Float64?
      return nil if value.raw.nil?
      value.as_f? || raise ArgumentError.new("cost is not a number")
    end

    private def self.owed_from(value : JSON::Any) : Owed?
      return nil if value.raw.nil?
      seen_value = value["seen"]
      seen = if seen_value.raw.nil?
               nil
             else
               FastRecord.parse(seen_value.to_json) || raise ArgumentError.new("owed.seen is not a fast record")
             end
      Owed.new(value["cause"].as_s, seen)
    end
  end

  # The effort rule: a cheap test the fast path cannot serve is built and run
  # with no compiler check, and owes that check until a later run has settled.
  module Effort
    # The compiler path is today's check. The run path builds and runs the
    # test and starts no compiler.
    enum Path
      Compiler
      Run
    end

    # Which path a test takes from the record as it stood before this run, and
    # the label that path reports. Cheap is `(build or 0) + run <= check / 2`:
    # the owed check on a lone edit then costs at most half a check more than
    # today, and a build not yet measured counts as 0 so a short run is tried
    # once. *settled* is the caller's: `owed.seen` is nil, or nothing that
    # record stamped has changed.
    def self.decide(record : EffortRecord?, settled : Bool) : {path: Path, label: String}
      check = record.try(&.costs.check)
      run = record.try(&.costs.run)
      unless check && run
        return {path: Path::Compiler, label: "unknown"}
      end

      build = record.try(&.costs.build) || 0.0
      unless build + run <= check / 2
        return {path: Path::Compiler, label: "dear"}
      end

      if record.try(&.owed) && settled
        {path: Path::Compiler, label: "owed"}
      else
        {path: Path::Run, label: "cheap"}
      end
    end

    # A passing run without a check owes that check, except when a fast record
    # that is not refused matched and the test is unservable: the last compiler
    # run, on these same inputs, already passed without leaving anything to serve.
    def self.owes?(matched_unrefused : Bool, unservable : Bool) : Bool
      !(matched_unrefused && unservable)
    end

    # Whether the effort rule is on. Unset is on. `IYI_STALE_EFFORT=off`
    # restores today's paths. Any other value is refused; the runner turns
    # that into its usage error, as it does for `IYI_STALE_FAST_DROP`.
    def self.mode(env) : Bool
      case env["IYI_STALE_EFFORT"]?
      when nil, "on"
        true
      when "off"
        false
      else
        raise ArgumentError.new("IYI_STALE_EFFORT takes on or off")
      end
    end
  end
end
