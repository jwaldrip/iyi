# iyi: `iyi test` — the verify loop, with no framework to learn
# (AI_FIRST.md §2 #4).
#
# A test is a plain iyi program named `*_test.iyi`: it asserts by exiting
# non-zero, exactly the contract every gate in `bench/` already runs on,
# because this repository's own culture is the framework. No DSL, no
# matchers, no registry — a program that prints what failed and exits 1 is
# a failing test, and one that exits 0 passed.
#
#     iyi test              # every *_test.iyi under the current directory
#     iyi test dir file.iyi # these, recursing into directories
#     iyi test --json       # the run as data, for a harness
#
# Each test builds and runs alone: one file, one process, one verdict — a
# crash, a panic and a deadlock are all failures that name their file. A
# test that neither exits nor fails is killed at the deadline (`--timeout`,
# 60 s default), because a harness that can hang is not a harness.
class Iyi::Command
  private def test
    as_json = false
    timeout = 60.0
    paths = [] of String

    while option = options.shift?
      case option
      when "--json"
        as_json = true
      when "--timeout"
        value = options.shift?
        abort! "--timeout takes seconds", :USAGE_ERROR unless value
        timeout = value.to_f? || abort! "--timeout takes seconds, not '#{value}'", :USAGE_ERROR
      when "--help", "-h"
        puts test_usage
        exit
      else
        paths << option
      end
    end
    paths << "." if paths.empty?

    files = [] of String
    paths.each do |path|
      if File.directory?(path)
        Dir.glob(File.join(path, "**", "*_test.iyi")) { |file| files << file }
      elsif File.file?(path)
        files << path
      else
        abort! "no such file or directory: #{path}", :USAGE_ERROR
      end
    end
    files.uniq!.sort!

    if files.empty?
      abort! "no *_test.iyi found. A test is a plain iyi program that exits non-zero to fail", :USAGE_ERROR
    end

    results = files.map { |file| run_one_test(file, timeout) }
    failed = results.count { |result| result[:status] != "pass" }

    if as_json
      JSON.build(STDOUT) do |json|
        json.object do
          json.field "tests" do
            json.array do
              results.each do |result|
                json.object do
                  json.field "file", result[:file]
                  json.field "status", result[:status]
                  json.field "seconds", result[:seconds]
                  json.field "output", result[:output] unless result[:output].empty?
                end
              end
            end
          end
          json.field "passed", results.size - failed
          json.field "failed", failed
        end
      end
      STDOUT.puts
    else
      results.each do |result|
        next if result[:status] == "pass"
        STDOUT << result[:file] << ": " << result[:status] << '\n'
        result[:output].each_line { |line| STDOUT << "  " << line << '\n' }
      end
      puts "#{results.size - failed} passed, #{failed} failed" + (failed.zero? ? "" : " — a failing test prints above")
    end

    exit 1 unless failed.zero?
  end

  private def run_one_test(file : String, deadline : Float64) : {file: String, status: String, seconds: Float64, output: String}
    started = Time.monotonic
    output = IO::Memory.new

    binary = File.tempname("iyi-test", nil)
    begin
      build_status = Process.run(
        Process.executable_path.not_nil!,
        ["build", file, "-o", binary],
        output: output, error: output,
      )
      unless build_status.success?
        return {file: file, status: "does not build", seconds: elapsed(started), output: output.to_s}
      end

      process = Process.new(binary, output: output, error: output)
      done = ::Channel(Process::Status).new
      spawn { done.send(process.wait) }
      select
      when status = done.receive
        verdict = status.success? ? "pass" : "fail"
        {file: file, status: verdict, seconds: elapsed(started), output: status.success? ? "" : output.to_s}
      when timeout(deadline.seconds)
        process.terminate(graceful: false)
        done.receive
        {file: file, status: "hung: killed at #{deadline}s", seconds: elapsed(started), output: output.to_s}
      end
    ensure
      File.delete?(binary)
    end
  end

  private def elapsed(started : Time::Span) : Float64
    (Time.monotonic - started).total_seconds.round(3)
  end

  private def test_usage
    <<-USAGE
    Usage: #{Command.program_name} test [--json] [--timeout SECONDS] [paths]

    Runs every `*_test.iyi` under the given paths (default: `.`). A test is
    a plain iyi program: exit 0 is a pass, anything else is a failure that
    prints its own evidence. `--json` reports the run as data.
    USAGE
  end
end
