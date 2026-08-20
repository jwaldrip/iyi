require "socket"

{% if flag?(:without_mt) %}
  require "c/poll"

  # `poll(2)`, for the build daemon's single-fiber server loop. Declared here
  # because reopening `lib LibC` inside a class would define a nested lib of the
  # same name rather than extending the real one.
  lib LibC
    struct PollFd
      fd : Int
      events : Short
      revents : Short
    end

    fun poll(fds : PollFd*, nfds : ULong, timeout : Int) : Int
  end
{% end %}

# A build daemon: analyse the prelude once, then fork a child per build so each
# build starts from a `Program` that already has it.
#
# The measurements behind this are in SPEC.md IV.1a/IV.1b. The prelude is ~87% of
# a small build's front end, and a fork restores it in about a millisecond, which
# is a floor no serialised artifact can beat. So the daemon is not a substitute
# for `.iyimod` — it cannot cross machines or sessions, and it is not the basis
# of separate compilation — but it delivers the same front-end win today.
#
# The output of a build has to reach the client as it happens, with `stdout` and
# `stderr` still distinguishable and the exit status intact. The child therefore
# writes to a pair of pipes rather than to the connection, and the daemon frames
# what it reads:
#
#     1 byte kind, 0 = exit, 1 = stdout, 2 = stderr
#     4 bytes little-endian length (or the exit code, for kind 0)
#     that many bytes
#
# Requests are a little-endian length followed by that many bytes of JSON,
# `{"cwd": ..., "args": [...], "version": ...}`. The version is checked, along
# with the server's own executable, so that a rebuilt compiler cannot be served
# from silently.
class Iyi::Command
  DAEMON_FRAME_EXIT   = 0_u8
  DAEMON_FRAME_STDOUT = 1_u8
  DAEMON_FRAME_STDERR = 2_u8

  private def daemon
    subcommand = options.first?

    case subcommand
    when nil, "start"
      options.shift?
      daemon_start
    when "build"
      options.shift
      daemon_build
    when "--help", "-h"
      puts <<-USAGE
        Usage: #{Command.program_name} daemon [start|build] [switches]

        Analyses the prelude once and forks a child per build, so a build does
        not re-analyse it. Start a daemon in one terminal and send builds to it
        from another:

            #{Command.program_name} daemon start
            #{Command.program_name} daemon build hello.iyi

        Command:
            start (default)      run the daemon in the foreground
            build                send a build to a running daemon

        Switches:
            --socket PATH        socket to listen on / connect to

        Set CRYSTAL_DAEMON_SOCKET and an ordinary `#{Command.program_name} build`
        is served by that daemon too, falling back to a normal build if it is
        not there.
        USAGE
      exit
    else
      abort! "unknown daemon subcommand: #{subcommand}", :USAGE_ERROR
    end
  end

  # Hands the server over to the single-threaded daemon binary.
  #
  # The daemon forks a child per build, and only the forking thread survives a
  # fork — a multi-threaded runtime would give the child a broken one, which is
  # why Crystal refuses `fork` in such a build at compile time. So the server
  # half lives in its own binary. The client half does not fork and runs
  # anywhere, which is why only `start` is redirected.
  private def daemon_exec_server : NoReturn
    # An explicit override is authoritative. Falling back to some other binary
    # because the named one is missing would run a build against a compiler the
    # user did not ask for, and say nothing about it.
    if (override = ENV["CRYSTAL_DAEMON"]?) && !override.empty?
      unless File.info?(override).try(&.file?)
        STDERR.puts "CRYSTAL_DAEMON points at #{override}, which is not a file"
        exit 1
      end
      Process.exec(override, ["daemon", "start"] + options)
    end

    candidates = [] of String
    if executable = Process.executable_path
      candidates << File.join(File.dirname(executable), "crystal-daemon")
    end
    candidates << File.join(".build", "crystal-daemon")

    if server = candidates.find { |candidate| File.info?(candidate).try(&.file?) }
      Process.exec(server, ["daemon", "start"] + options)
    end

    STDERR.puts <<-MSG
      The build daemon needs a single-threaded compiler, and none was found.

      Build one with:
          make crystal-daemon

      Looked in:
      #{candidates.join('\n') { |candidate| "    #{candidate}" }}

      Set CRYSTAL_DAEMON to point at it directly.
      MSG
    exit 1
  end

  # Lets `crystal build` go through a daemon without the user retyping the
  # command: set CRYSTAL_DAEMON_SOCKET and ordinary builds are served by it.
  #
  # Opt-in, and it falls back to building normally when nothing is listening —
  # with a line saying so, because a daemon that quietly died should not look
  # like a daemon that is working.
  private def daemon_socket_from_env : String?
    socket = ENV["CRYSTAL_DAEMON_SOCKET"]?
    return nil if socket.nil? || socket.empty?

    unless File.exists?(socket)
      STDERR.puts "crystal: no daemon at #{socket}, building without it"
      return nil
    end

    socket
  end

  private def daemon_socket_path : String
    path = nil
    options.each_with_index do |opt, i|
      if opt == "--socket"
        path = options[i + 1]?
        options.delete_at(i, 2)
        break
      end
    end
    path || File.join(CacheDir.instance.dir, "daemon.sock")
  end

  private def daemon_start
    {% unless flag?(:without_mt) %}
      daemon_exec_server
    {% else %}
      # Before the socket exists, so that what is recorded is the compiler this
      # daemon actually started from. A client can appear the instant the socket
      # does, and anything sampled after that races with it.
      identity = daemon_identity

      path = daemon_socket_path
      Dir.mkdir_p(File.dirname(path))
      File.delete?(path)
      server = UNIXServer.new(path)

      # The whole point: pay for the prelude once, here, rather than in every
      # build. Children adopt this and start from it.
      elapsed = Time.instant
      preanalysed = Compiler.new.preanalyse_prelude
      Compiler.preanalysed[preanalysed.key] = preanalysed

      STDERR.puts "#{Command.program_name} daemon listening on #{path}"
      STDERR.puts "prelude analysed in #{elapsed.elapsed.total_seconds.round(3)}s"
      STDERR.flush

      daemon_loop(server, identity) do
        if preanalysed.stale?
          elapsed = Time.instant
          # Every cached prelude came from the same sources, so they are all
          # stale together.
          Compiler.preanalysed.clear
          preanalysed = Compiler.new.preanalyse_prelude
          Compiler.preanalysed[preanalysed.key] = preanalysed
          STDERR.puts "prelude changed, re-analysed in #{elapsed.elapsed.total_seconds.round(3)}s"
          STDERR.flush
        end
      end
    {% end %}
  end

  {% if flag?(:without_mt) %}
    # `poll(2)`, because the server has to wait on many descriptors from a single
    # fiber. Crystal has no `IO.select`, and a fiber per stream is what broke the
    # first attempt at concurrency: a forked child inherits the parent's live
    # fibers, and the scheduler runs them as soon as the child blocks on IO, so
    # another build's relay writes to descriptors this child has closed.
    #
    # One fiber, one `poll`, no inherited relays.
    # A build in flight: the connection to report to, the child's two output
    # pipes, and how many of them are still open.
    private class DaemonBuild
      getter client : UNIXSocket
      getter out_r : IO::FileDescriptor
      getter err_r : IO::FileDescriptor
      getter pid : LibC::PidT
      getter args : Array(String)
      property open : Int32

      def initialize(@client, @out_r, @err_r, @pid, @args)
        @open = 2
      end

      def stream(kind : UInt8) : IO::FileDescriptor
        kind == DAEMON_FRAME_STDOUT ? @out_r : @err_r
      end
    end

    private def daemon_loop(server, identity : String, &refresh) : Nil
      builds = [] of DaemonBuild
      warm = [] of Array(String)
      buffer = Bytes.new(16384)

      loop do
        # Rebuilt each round: which descriptors matter changes as builds start
        # and finish, and the set is small enough that this is not worth caching.
        fds = [] of LibC::PollFd
        owners = [] of {DaemonBuild?, UInt8}

        fds << LibC::PollFd.new(fd: server.fd, events: LibC::POLLIN.to_i16, revents: 0)
        owners << {nil, 0_u8}

        builds.each do |build|
          {DAEMON_FRAME_STDOUT, DAEMON_FRAME_STDERR}.each do |kind|
            stream = build.stream(kind)
            next if stream.closed?
            fds << LibC::PollFd.new(fd: stream.fd, events: LibC::POLLIN.to_i16, revents: 0)
            owners << {build, kind}
          end
        end

        ready = LibC.poll(fds.to_unsafe, fds.size.to_u64, -1)
        next if ready < 0 # interrupted; rebuild the set and wait again

        finished = [] of DaemonBuild

        fds.each_with_index do |pollfd, index|
          next if pollfd.revents == 0

          build, kind = owners[index]

          unless build
            daemon_accept(server, identity, builds) { refresh.call }
            next
          end

          # `poll` said readable, so this does not block: it returns data, or 0
          # at end of stream once the child has exited and closed its end.
          stream = build.stream(kind)
          read = begin
            stream.read(buffer)
          rescue IO::Error
            0
          end

          if read == 0
            stream.close rescue nil
            build.open -= 1
            finished << build if build.open == 0
          else
            daemon_frame(build.client, kind, buffer[0, read]) rescue nil
          end
        end

        finished.each do |build|
          warm << build.args if daemon_finish(build)
          builds.delete(build)
        end

        # Only while nothing is in flight: analysing a prelude takes about a
        # second, and this loop is the only thing relaying output.
        if builds.empty? && !warm.empty?
          daemon_warm(warm.shift)
        end
      end
    end

    # Accepts one connection and starts its build, or refuses it. Returns
    # without starting anything if the request is rejected.
    private def daemon_accept(server, identity : String, builds : Array(DaemonBuild), &refresh) : Nil
      client = server.accept

      request = daemon_read_request(client)
      cwd = request["cwd"].as_s
      args = request["args"].as_a.map(&.as_s)

      # A daemon holds an analysed prelude *and* the compiler that analysed it.
      # Rebuild the compiler and it would keep serving builds from the old one,
      # silently, with output that looks like a normal build's.
      if daemon_identity != identity
        daemon_refuse(client, <<-MSG)
          The build daemon started before #{Process.executable_path || "the compiler"} was rebuilt,
          so it would compile this with the old one. Restart the daemon.
          MSG
        client.close rescue nil
        return
      end

      if (client_version = request["version"]?.try(&.as_s)) && client_version != Iyi::Config.description
        daemon_refuse(client, <<-MSG)
          The build daemon and this client are different compilers.
          Daemon: #{Iyi::Config.description}
          Client: #{client_version}
          MSG
        client.close rescue nil
        return
      end

      refresh.call

      out_r, out_w = IO.pipe(read_blocking: false, write_blocking: true)
      err_r, err_w = IO.pipe(read_blocking: false, write_blocking: true)

      pid = Crystal::System::Process.fork do
        # Nothing of the daemon's, and nothing of any *other* build's: an
        # inherited connection or pipe read-end left open here outlives this
        # build. Note `delete: false` — `UNIXServer#close` unlinks the socket
        # file, which would take the daemon's address away from every later
        # client while the daemon went on listening, apparently healthy.
        server.close(delete: false) rescue nil
        client.close rescue nil
        out_r.close rescue nil
        err_r.close rescue nil
        builds.each do |other|
          other.client.close rescue nil
          other.out_r.close rescue nil
          other.err_r.close rescue nil
        end

        LibC.dup2(out_w.fd, 1)
        LibC.dup2(err_w.fd, 2)

        Dir.cd(cwd)
        Iyi::Command.run(args)
        LibC._exit 0
      end

      out_w.close
      err_w.close

      builds << DaemonBuild.new(client, out_r, err_r, pid.not_nil!, args)
    end

    private def daemon_finish(build : DaemonBuild) : Bool
      status = ::Process.new(Crystal::System::Process.new(build.pid)).wait

      begin
        build.client.write_byte(DAEMON_FRAME_EXIT)
        build.client.write_bytes(status.exit_code, IO::ByteFormat::LittleEndian)
        build.client.flush
      rescue IO::Error
        # The client hung up before its build finished; nothing left to tell it.
      end

      build.client.close rescue nil
      status.success?
    end

    # Analyses the prelude for a flag set some build actually used, so the next
    # build with those flags is fast too. Macros branch on flags, so `--release`
    # and `-Dfoo` each need their own.
    #
    # Driven by builds that already *succeeded*, which is what makes it safe:
    # turning arguments into a compiler means running the option parser, and the
    # option parser exits the process on bad input. Doing that here on arguments
    # a client made up would take the daemon down on a typo.
    private def daemon_warm(args : Array(String)) : Nil
      limit = (ENV["CRYSTAL_DAEMON_PRELUDES"]?.try(&.to_i?) || 3)
      return if Compiler.preanalysed.size >= limit

      compiler = Iyi::Command.new(args.dup).prelude_compiler_for_build
      return if Compiler.preanalysed.has_key?(compiler.prelude_cache_key)

      elapsed = Time.instant
      preanalysed = compiler.preanalyse_prelude
      Compiler.preanalysed[preanalysed.key] = preanalysed

      switches = args.select(&.starts_with?("-")).join(' ')
      switches = "(default flags)" if switches.empty?
      STDERR.puts "prelude for #{switches} analysed in #{elapsed.elapsed.total_seconds.round(3)}s (#{Compiler.preanalysed.size}/#{limit} cached)"
      STDERR.flush
    rescue ex
      # A flag set we cannot pre-analyse just stays slow.
      STDERR.puts "daemon: could not pre-analyse a prelude: #{ex.message}"
      STDERR.flush
    end
  {% end %}

  private def daemon_frame(io : IO, kind : UInt8, bytes : Bytes) : Nil
    io.write_byte(kind)
    io.write_bytes(bytes.size.to_u32, IO::ByteFormat::LittleEndian)
    io.write(bytes)
    io.flush
  end

  # Identifies the running server's own executable, so a rebuild is noticed.
  # The version string alone cannot see it: two builds of the same commit
  # describe themselves identically, and during development that is the normal
  # case rather than the exception.
  private def daemon_identity : String
    executable = Process.executable_path
    return "an unknown build" unless executable

    info = File.info?(executable)
    return "a deleted build" unless info

    # Nanoseconds, not seconds: a rebuild that lands in the same second as the
    # daemon's start is exactly the case this has to catch.
    "#{info.size}:#{info.modification_time.to_unix_ns}"
  end

  private def daemon_refuse(client, message : String) : Nil
    message.each_line do |line|
      daemon_frame(client, DAEMON_FRAME_STDERR, "#{line}\n".to_slice)
    end
    client.write_byte(DAEMON_FRAME_EXIT)
    client.write_bytes(1, IO::ByteFormat::LittleEndian)
    client.flush
  end

  private def daemon_read_request(client) : JSON::Any
    size = client.read_bytes(UInt32, IO::ByteFormat::LittleEndian)
    bytes = Bytes.new(size)
    client.read_fully(bytes)
    JSON.parse(String.new(bytes))
  end

  # Returns only when *fallback* is set and no daemon answered; otherwise it
  # runs the build to completion and exits with the daemon's status.
  private def daemon_build(path : String? = nil, fallback : Bool = false)
    path ||= daemon_socket_path

    begin
      client = UNIXSocket.new(path)
    rescue ex : Socket::Error | File::Error
      if fallback
        STDERR.puts "crystal: daemon at #{path} did not answer, building without it"
        return
      end
      abort! "no daemon listening on #{path} (start one with `#{Command.program_name} daemon start`)", :FAILURE
    end

    # The child runs a full command line, so put back the subcommand this one
    # consumed: `crystal daemon build -o x y.cr` is `crystal build -o x y.cr`.
    request = {cwd: Dir.current, args: ["build"] + options, version: Iyi::Config.description}.to_json
    client.write_bytes(request.bytesize.to_u32, IO::ByteFormat::LittleEndian)
    client.write(request.to_slice)
    client.flush

    loop do
      kind = client.read_byte
      break unless kind

      case kind
      when DAEMON_FRAME_EXIT
        exit client.read_bytes(Int32, IO::ByteFormat::LittleEndian)
      when DAEMON_FRAME_STDOUT, DAEMON_FRAME_STDERR
        size = client.read_bytes(UInt32, IO::ByteFormat::LittleEndian)
        bytes = Bytes.new(size)
        client.read_fully(bytes)
        io = kind == DAEMON_FRAME_STDOUT ? STDOUT : STDERR
        io.write(bytes)
        io.flush
      else
        abort! "daemon sent an unknown frame #{kind}", :SOFTWARE_ERROR
      end
    end

    # End of stream without an exit frame means the daemon died mid-build.
    abort! "daemon closed the connection without reporting a result", :SOFTWARE_ERROR
  end
end
