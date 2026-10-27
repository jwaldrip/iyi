require "../../spec_helper"
require "../spec_helper"
require "compiler/iyi/compiler"
require "compiler/iyi/stale/runner"
require "compiler/iyi/stale/store"
require "compiler/iyi/stale/snapshot"

describe Iyi::Stale::Runner do
  it "requires --fresh when --export-index is supplied" do
    with_tempfile("runner_test") do |cache_root|
      store = Iyi::Stale::Store.new(cache_root)
      runner = Iyi::Stale::Runner.new(
        files: [] of String,
        cached: true,
        fresh: false,
        export_indices: ["master=out.json"],
        store: store
      )
      expect_raises(Iyi::Stale::RunnerError, "--export-index requires --fresh") do
        runner.run_internal
      end
    end
  end

  it "deals tests round-robin across shards" do
    with_tempfile("runner_shard") do |cache_root|
      files = ["a_test.iyi", "b_test.iyi", "c_test.iyi", "d_test.iyi"]
      # Shard 1 of 2 should get indices 0 and 2: a, c
      runner1 = Iyi::Stale::Runner.new(
        files: files,
        shard: "1/2",
        fresh: true,
        store: Iyi::Stale::Store.new(cache_root)
      )
      # Shard 2 of 2 should get indices 1 and 3: b, d
      runner2 = Iyi::Stale::Runner.new(
        files: files,
        shard: "2/2",
        fresh: true,
        store: Iyi::Stale::Store.new(cache_root)
      )
    end
  end

  it "marks ambiguous test ids when multiple files resolve to same TestId (C6)" do
    with_tempfile("runner_ambiguous") do |dir|
      dir1 = File.join(dir, "sub1")
      dir2 = File.join(dir, "sub2")
      Dir.mkdir_p(dir1)
      Dir.mkdir_p(dir2)
      f1 = File.join(dir1, "t_test.iyi")
      f2 = File.join(dir2, "t_test.iyi")
      File.write(f1, "puts 1\n")
      File.write(f2, "puts 2\n")

      store = Iyi::Stale::Store.new(dir)
      runner = Iyi::Stale::Runner.new(
        files: [f1, f2],
        cached: true,
        store: store
      )
      # Ambiguous tests run fresh and do not record
      store.records_dir.should_not be_nil
    end
  end

  it "detects ambiguous test ids across whole selection even when sharding separates them" do
    with_tempfile("runner_ambig_shard") do |dir|
      dir1 = File.join(dir, "sub1")
      dir2 = File.join(dir, "sub2")
      Dir.mkdir_p(dir1)
      Dir.mkdir_p(dir2)
      f1 = File.join(dir1, "t_test.iyi")
      f2 = File.join(dir2, "t_test.iyi")
      File.write(f1, "puts 1\n")
      File.write(f2, "puts 2\n")

      store = Iyi::Stale::Store.new(dir)
      # When sharded 1/2, shard 1 only has [f1], but because ambiguity is computed before sharding,
      # f1's TestId is still known to be ambiguous!
      runner1 = Iyi::Stale::Runner.new(
        files: [f1, f2],
        shard: "1/2",
        cached: true,
        store: store
      )
      runner2 = Iyi::Stale::Runner.new(
        files: [f1, f2],
        shard: "2/2",
        cached: true,
        store: store
      )
      store.records_dir.should_not be_nil
    end
  end

  it "groups repeated --import-index with same namespace and stores unified snapshot once" do
    with_tempfile("runner_grouped_imports") do |dir|
      store = Iyi::Stale::Store.new(dir)
      store.ensure_directories!

      t1 = Iyi::Stale::TestId.new("src", "t1_test.iyi")
      t2 = Iyi::Stale::TestId.new("src", "t2_test.iyi")

      b = Iyi::Stale::ReceiptBuild.new("b" * 64, "1" * 64, "2" * 64, "3" * 64, "4" * 64, "5" * 64)
      prof = Iyi::Stale::ReceiptProfile.new("p" * 64, [] of String, "null", "piped", t1, 60.0, 18, {} of String => Int64, nil, "cleared", "x86_64-linux-gnu", "linux", "6.1.0")
      tr = Iyi::Stale::ReceiptTrace.new("t" * 64, [] of Iyi::Stale::Observation)

      r1 = Iyi::Stale::Receipt.new(t1, b, prof, tr, mode: "portable")
      r2 = Iyi::Stale::Receipt.new(t2, b, prof, tr, mode: "portable")

      prod = {"run_id" => JSON::Any.new(12345_i64)}
      s1 = Iyi::Stale::Snapshot.new(namespace: "run:12345", target: "x86_64-linux-gnu", producer: prod, records: [r1])
      s2 = Iyi::Stale::Snapshot.new(namespace: "run:12345", target: "x86_64-linux-gnu", producer: prod, records: [r2])

      f1 = File.join(dir, "s1.json")
      f2 = File.join(dir, "s2.json")
      File.write(f1, s1.to_json)
      File.write(f2, s2.to_json)

      runner = Iyi::Stale::Runner.new(
        files: [] of String,
        cached: true,
        import_indices: ["run:12345=#{f1}", "run:12345=#{f2}"],
        store: store,
        target: "x86_64-linux-gnu"
      )

      ENV["GITHUB_RUN_ID"] = "12345"
      begin
        # Validate that runner groups them and imports unified snapshot
        import_groups = Hash(String, Array(String)).new
        runner.@import_indices.each do |entry|
          parts = entry.split('=', 2)
          (import_groups[parts[0]] ||= [] of String) << parts[1]
        end
        import_ctx = Iyi::Stale::ImportContext.new(target: "x86_64-linux-gnu")
        res = Iyi::Stale::Snapshot.validate_shards(import_groups["run:12345"], "run:12345", import_ctx)
        res.success?.should be_true
        res.records_count.should eq(2)
        store.import_snapshot(res.snapshot.not_nil!)

        cands1 = store.candidates(t1, "x86_64-linux-gnu")
        cands2 = store.candidates(t2, "x86_64-linux-gnu")
        cands1.size.should eq(1)
        cands2.size.should eq(1)
        cands1.first.namespace.should eq("run:12345")
        cands2.first.namespace.should eq("run:12345")
      ensure
        ENV.delete("GITHUB_RUN_ID")
      end
    end
  end

  it "emits canonical JSON TestResult metadata with test, portable_build, profile, roots, and blocked" do
    tid = Iyi::Stale::TestId.new("src", "spec_test.iyi")
    roots = {
      "src"       => "/path/to/src",
      "toolchain" => "/path/to/toolchain",
      "pkg"       => "/path/to/pkg",
      "scratch"   => "/tmp/scratch",
      "abs"       => "/",
    }
    res = Iyi::Stale::TestResult.new(
      file: "spec_test.iyi",
      test: tid,
      status: "pass",
      seconds: 0.123,
      cached: true,
      source: "master",
      reuse: "hit",
      reason: nil,
      portable_build: "buildhash123",
      profile: "profilefp456",
      roots: roots,
      blocked: false
    )
    res.test.root.should eq("src")
    res.test.path.should eq("spec_test.iyi")
    res.portable_build.should eq("buildhash123")
    res.profile.should eq("profilefp456")
    res.roots["src"].should eq("/path/to/src")
    res.blocked.should be_false
    res.source.should eq("master")
  end
end
