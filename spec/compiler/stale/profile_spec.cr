require "../../spec_helper"
require "../spec_helper"
require "compiler/iyi/stale/profile"

describe Iyi::Stale::Profile do
  it "keys a test's profile by the same inputs its fingerprint has always used" do
    host = Iyi::Stale::Profile.host("aarch64-apple-darwin")
    argv = ["/scratch/one"]
    cwd = Iyi::Stale::RootPath.new("src", "pkg")

    profile = Iyi::Stale::Profile.current(host: host, argv: argv, cwd: cwd, timeout: 60.0)

    # The argument list the per-test profile was built from before the host
    # was read once per run, with the same machine values.
    digest = Iyi::Stale::ReceiptProfile.compute_fp(
      argv: argv,
      stdin: "null",
      stdio: "piped",
      cwd: Iyi::Stale::TestId.new("src", "pkg"),
      timeout: 60.0,
      umask: host.umask,
      rlimits: host.rlimits,
      cgroup_mem: host.cgroup_mem,
      loader_vars: "cleared",
      target: "aarch64-apple-darwin",
      os: host.os,
      kernel: host.kernel
    )
    profile.fp.should eq Iyi::Stale.hex(digest)
    profile.cwd.should eq Iyi::Stale::TestId.new("src", "pkg")
    profile.target.should eq "aarch64-apple-darwin"
    profile.umask.should eq host.umask
    profile.rlimits.should eq host.rlimits
    profile.cgroup_mem.should eq host.cgroup_mem
    profile.os.should eq host.os
    profile.kernel.should eq host.kernel
  end

  it "gives every test of one run the same host values" do
    host = Iyi::Stale::Profile.host
    first = Iyi::Stale::Profile.current(host: host, argv: ["/scratch/a"], cwd: Iyi::Stale::RootPath.new("src", "."), timeout: 60.0)
    second = Iyi::Stale::Profile.current(host: host, argv: ["/scratch/b"], cwd: Iyi::Stale::RootPath.new("src", "."), timeout: 60.0)

    first.umask.should eq second.umask
    first.rlimits.should eq second.rlimits
    first.kernel.should eq second.kernel
    first.fp.should_not eq second.fp
  end

  {% if flag?(:unix) %}
    it "reads the umask and leaves it as it was" do
      old = LibC.umask(0o027)
      begin
        Iyi::Stale::Profile.host.umask.should eq 0o027
        LibC.umask(0o027).should eq 0o027
      ensure
        LibC.umask(old)
      end
    end
  {% end %}
end
