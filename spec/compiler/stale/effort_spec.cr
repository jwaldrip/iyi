require "../../spec_helper"
require "../spec_helper"
require "compiler/iyi/stale/effort"
require "file_utils"

# Directories the examples below made, removed once each has ended.
EFFORT_SPEC_DIRS = [] of String

Spec.after_each do
  EFFORT_SPEC_DIRS.each { |dir| FileUtils.rm_rf(dir) }
  EFFORT_SPEC_DIRS.clear
end

private def effort_dir : String
  dir = File.tempname("iyi-effort")
  Dir.mkdir_p(dir)
  EFFORT_SPEC_DIRS << dir
  dir
end

private def effort_test : Iyi::Stale::TestId
  Iyi::Stale::TestId.new("src", "a_test.iyi")
end

private def effort_costs(check : Float64?, build : Float64?, run : Float64?) : Iyi::Stale::EffortRecord::Costs
  Iyi::Stale::EffortRecord::Costs.new(check, build, run)
end

private def effort_record(check : Float64?, build : Float64?, run : Float64?, *, owed : Bool = false) : Iyi::Stale::EffortRecord
  owed_value = Iyi::Stale::EffortRecord::Owed.new("lib/util.iyi changed", nil) if owed
  Iyi::Stale::EffortRecord.new(effort_test, effort_costs(check, build, run), false, owed_value)
end

private def effort_fast(dir : String) : Iyi::Stale::FastRecord
  Iyi::Stale::FastRecord.new(effort_test, "src/a_test.iyi", dir, "local-build", "portable-build",
    "x86_64-linux-gnu", 4, [] of Iyi::Stale::FastEntry, {} of String => String?, false,
    [] of Iyi::Stale::FastEntry, {} of String => Array(String)?, [] of Iyi::Stale::FastPkgConfig)
end

private def compiler_unknown
  {path: Iyi::Stale::Effort::Path::Compiler, label: "unknown"}
end

private def compiler_dear
  {path: Iyi::Stale::Effort::Path::Compiler, label: "dear"}
end

private def compiler_owed
  {path: Iyi::Stale::Effort::Path::Compiler, label: "owed"}
end

private def run_cheap
  {path: Iyi::Stale::Effort::Path::Run, label: "cheap"}
end

describe Iyi::Stale::Effort do
  it "takes the compiler path when no timing is known" do
    Iyi::Stale::Effort.decide(nil, false).should eq compiler_unknown
    Iyi::Stale::Effort.decide(nil, true).should eq compiler_unknown
    Iyi::Stale::Effort.decide(effort_record(nil, 0.1, 0.1), false).should eq compiler_unknown
    Iyi::Stale::Effort.decide(effort_record(1.92, 0.1, nil), false).should eq compiler_unknown
    Iyi::Stale::Effort.decide(effort_record(nil, nil, nil), true).should eq compiler_unknown
  end

  it "takes the compiler path when the test is dear" do
    Iyi::Stale::Effort.decide(effort_record(1.0, 0.0, 1.0), false).should eq compiler_dear
    Iyi::Stale::Effort.decide(effort_record(1.0, 0.0, 1.0, owed: true), true).should eq compiler_dear
  end

  it "pays an owed check when a cheap test has settled" do
    Iyi::Stale::Effort.decide(effort_record(2.0, 0.1, 0.1, owed: true), true).should eq compiler_owed
  end

  it "runs a cheap test without a check otherwise" do
    Iyi::Stale::Effort.decide(effort_record(2.0, 0.1, 0.1), false).should eq run_cheap
    Iyi::Stale::Effort.decide(effort_record(2.0, 0.1, 0.1), true).should eq run_cheap
    Iyi::Stale::Effort.decide(effort_record(2.0, 0.1, 0.1, owed: true), false).should eq run_cheap
  end

  it "treats a cost equal to half a check as cheap, and a hair over as dear" do
    Iyi::Stale::Effort.decide(effort_record(2.0, 0.25, 0.75), false).should eq run_cheap
    Iyi::Stale::Effort.decide(effort_record(2.0, 0.0, 1.0), false).should eq run_cheap
    Iyi::Stale::Effort.decide(effort_record(2.0, 0.25, 0.75 + 1e-9), false).should eq compiler_dear
  end

  it "counts a nil build as 0" do
    Iyi::Stale::Effort.decide(effort_record(2.0, nil, 1.0), false).should eq run_cheap
    Iyi::Stale::Effort.decide(effort_record(2.0, nil, 1.0 + 1e-9), false).should eq compiler_dear
  end

  it "owes a check after a pass unless a matching unrefused record was unservable" do
    Iyi::Stale::Effort.owes?(false, false).should be_true
    Iyi::Stale::Effort.owes?(false, true).should be_true
    Iyi::Stale::Effort.owes?(true, false).should be_true
    Iyi::Stale::Effort.owes?(true, true).should be_false
  end
end

describe "IYI_STALE_EFFORT" do
  it "is on unless set to off, and refuses any other value" do
    Iyi::Stale::Effort.mode({} of String => String).should be_true
    Iyi::Stale::Effort.mode({"IYI_STALE_EFFORT" => "on"}).should be_true
    Iyi::Stale::Effort.mode({"IYI_STALE_EFFORT" => "off"}).should be_false
    expect_raises(ArgumentError, "IYI_STALE_EFFORT takes on or off") do
      Iyi::Stale::Effort.mode({"IYI_STALE_EFFORT" => "bogus"})
    end
  end

  it "reads the process environment" do
    saved = ENV["IYI_STALE_EFFORT"]?
    begin
      ENV.delete("IYI_STALE_EFFORT")
      Iyi::Stale::Effort.mode(ENV).should be_true
      ENV["IYI_STALE_EFFORT"] = "off"
      Iyi::Stale::Effort.mode(ENV).should be_false
      ENV["IYI_STALE_EFFORT"] = "on"
      Iyi::Stale::Effort.mode(ENV).should be_true
    ensure
      if saved
        ENV["IYI_STALE_EFFORT"] = saved
      else
        ENV.delete("IYI_STALE_EFFORT")
      end
    end
  end
end

describe Iyi::Stale::EffortRecord do
  it "reads a missing record as absent" do
    dir = effort_dir
    store = Iyi::Stale::Store.new(dir)
    Iyi::Stale::EffortRecord.read(store, effort_test).should be_nil
  end

  it "takes corrupt, other-format and other-version records as absent" do
    dir = effort_dir
    fast = effort_fast(dir)
    record = Iyi::Stale::EffortRecord.new(effort_test, effort_costs(1.92, 0.41, 0.02), false,
      Iyi::Stale::EffortRecord::Owed.new("lib/util.iyi changed", fast))
    body = record.to_store_json

    Iyi::Stale::EffortRecord.parse("{").should be_nil
    Iyi::Stale::EffortRecord.parse("").should be_nil
    Iyi::Stale::EffortRecord.parse(body.sub("iyi-stale-effort", "iyi-stale-fast")).should be_nil
    Iyi::Stale::EffortRecord.parse(body.sub("\"version\":1", "\"version\":2")).should be_nil
    Iyi::Stale::EffortRecord.parse(body.sub("iyi-stale-fast", "not-a-fast-record")).should be_nil
  end

  it "round trips, including an owed fast record and a null seen" do
    dir = effort_dir
    fast = effort_fast(dir)
    owed = Iyi::Stale::EffortRecord::Owed.new("lib/util.iyi changed", fast)
    record = Iyi::Stale::EffortRecord.new(effort_test, effort_costs(1.92, nil, 0.02), true, owed)

    parsed = Iyi::Stale::EffortRecord.parse(record.to_store_json).not_nil!
    parsed.test.should eq record.test
    parsed.costs.check.should eq record.costs.check
    parsed.costs.build.should be_nil
    parsed.costs.run.should eq record.costs.run
    parsed.unservable?.should be_true
    parsed.owed.not_nil!.cause.should eq "lib/util.iyi changed"
    parsed.owed.not_nil!.seen.not_nil!.to_store_json.should eq fast.to_store_json

    absent = Iyi::Stale::EffortRecord.new(effort_test, effort_costs(nil, nil, nil), false,
      Iyi::Stale::EffortRecord::Owed.new("lib/util.iyi changed", nil))
    reread = Iyi::Stale::EffortRecord.parse(absent.to_store_json).not_nil!
    reread.costs.check.should be_nil
    reread.owed.not_nil!.seen.should be_nil

    none = Iyi::Stale::EffortRecord.new(effort_test, effort_costs(2.0, 0.0, 0.25), false, nil)
    Iyi::Stale::EffortRecord.parse(none.to_store_json).not_nil!.owed.should be_nil
  end

  it "reads and writes the record of a test through the store" do
    dir = effort_dir
    store = Iyi::Stale::Store.new(dir)
    test = effort_test
    record = effort_record(1.92, 0.41, 0.02)

    store.write_effort(test, record.to_store_json)
    Iyi::Stale::EffortRecord.read(store, test).not_nil!.costs.check.should eq 1.92

    File.write(store.effort_path(test), "{")
    Iyi::Stale::EffortRecord.read(store, test).should be_nil
  end
end
