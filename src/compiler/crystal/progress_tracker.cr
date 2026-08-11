module Crystal
  # Fine-grained profiling, gated behind IYI_PROF=1.
  # Temporary instrumentation for the compile-speed investigation.
  module Prof
    @@enabled = !ENV["IYI_PROF"]?.nil?
    @@spans = {} of String => Time::Span
    @@order = [] of String

    def self.enabled?
      @@enabled
    end

    # Times a block and accumulates it under `name`.
    def self.span(name : String, &)
      return yield unless @@enabled
      start = Time.instant
      retval = yield
      taken = start.elapsed
      if existing = @@spans[name]?
        @@spans[name] = existing + taken
      else
        @@spans[name] = taken
        @@order << name
      end
      retval
    end

    @@counts = {} of String => Int64
    @@samples = {} of String => Array({String, Time::Span})

    # Times a block and records it as an individual labelled sample under
    # `group`, so the slowest items can be reported.
    def self.sample(group : String, label : String, &)
      return yield unless @@enabled
      start = Time.instant
      retval = yield
      (@@samples[group] ||= [] of {String, Time::Span}) << {label, start.elapsed}
      retval
    end

    def self.count(name : String, by : Int32 = 1)
      return unless @@enabled
      @@counts[name] = (@@counts[name]? || 0_i64) + by
    end

    def self.report(io = STDERR)
      return unless @@enabled
      return if @@order.empty? && @@counts.empty?
      io.puts
      io.puts "=== IYI_PROF ==="
      @@order.each do |name|
        io.puts "#{name.ljust(38)} #{@@spans[name]}"
      end
      @@counts.each do |name, n|
        io.puts "#{name.ljust(38)} #{n}"
      end
      @@samples.each do |group, list|
        total = list.sum(&.[1])
        sorted = list.sort_by { |(_, span)| -span.total_nanoseconds }
        io.puts
        io.puts "--- #{group}: #{list.size} samples, total #{total} ---"
        sorted.first(15).each_with_index do |(label, span), i|
          pct = total.total_nanoseconds.zero? ? 0.0 : span.total_nanoseconds / total.total_nanoseconds * 100
          io.puts "  %2d. %-52s %s (%5.1f%%)" % {i + 1, label[0, 52], span, pct}
        end
        top15 = sorted.first(15).sum(&.[1])
        io.puts "  top 15 = #{top15} of #{total}"
      end
      io.flush
    end
  end

  class ProgressTracker
    # FIXME: This assumption is not always true
    STAGES        = 14
    STAGE_PADDING = 34

    property? stats = false
    property? progress = false

    getter current_stage = 1
    getter current_stage_name : String?
    getter stage_progress = 0
    getter stage_progress_total : Int32?

    def stage(name, &)
      @current_stage_name = name

      print_stats
      print_progress

      time_start = Time.instant
      retval = yield
      time_taken = time_start.elapsed

      print_stats(time_taken)
      print_progress

      @current_stage += 1
      @stage_progress = 0
      @stage_progress_total = nil

      retval
    end

    def clear
      return unless @progress
      print " " * (STAGE_PADDING + 5)
      print "\r"
    end

    def print_stats(time_taken = nil)
      return unless @stats

      justified_name = "#{current_stage_name}:".ljust(STAGE_PADDING)
      if time_taken
        memory_usage_mb = GC.stats.heap_size / 1024.0 / 1024.0
        memory_usage_str = " (%7.2fMB)" % {memory_usage_mb}
        puts "#{justified_name} #{time_taken}#{memory_usage_str}"
      else
        print "#{justified_name}\r" unless @progress
      end
    end

    def print_progress
      return unless @progress

      if stage_progress_total = @stage_progress_total
        progress = " [#{@stage_progress}/#{stage_progress_total}]"
      end

      stage_name = @current_stage_name.try(&.ljust(STAGE_PADDING))
      print "[#{@current_stage}/#{STAGES}]#{progress} #{stage_name}\r"
    end

    def stage_progress=(@stage_progress)
      print_progress
    end

    def stage_progress_total=(@stage_progress_total)
      print_progress
    end
  end
end
