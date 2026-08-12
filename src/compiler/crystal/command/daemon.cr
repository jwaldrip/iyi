require "socket"

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
class Crystal::Command
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
        Usage: crystal daemon [start|build] [switches]

        Analyses the prelude once and forks a child per build, so a build does
        not re-analyse it. Start a daemon in one terminal and send builds to it
        from another:

            crystal daemon start
            crystal daemon build hello.cr

        Command:
            start (default)      run the daemon in the foreground
            build                send a build to a running daemon

        Switches:
            --socket PATH        socket to listen on / connect to
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
      Compiler.preanalysed = preanalysed

      STDERR.puts "crystal daemon listening on #{path}"
      STDERR.puts "prelude analysed in #{elapsed.elapsed.total_seconds.round(3)}s"
      STDERR.flush

      # One build at a time, and not for lack of trying: see the note on
      # `daemon_serve` about why a fiber per connection cannot work here.
      loop do
        client = server.accept
        begin
          if preanalysed.stale?
            elapsed = Time.instant
            preanalysed = Compiler.new.preanalyse_prelude
            Compiler.preanalysed = preanalysed
            STDERR.puts "prelude changed, re-analysed in #{elapsed.elapsed.total_seconds.round(3)}s"
            STDERR.flush
          end

          daemon_serve(server, client, identity)
        rescue ex
          STDERR.puts "daemon: #{ex.message}"
          STDERR.flush
        ensure
          client.close rescue nil
        end
      end
    {% end %}
  end

  {% if flag?(:without_mt) %}
    # Serves one build.
    #
    # Sequential, and this is not a placeholder. Serving connections from a fiber
    # each — the obvious way — breaks, because a forked child inherits the
    # parent's live fibers and the scheduler runs them the moment the child
    # blocks on IO. Another build's relay fiber then writes to descriptors this
    # child has closed, and the daemon dies of a broken pipe mid-build.
    #
    # Concurrency here needs a parent with exactly one fiber: a single `IO.select`
    # loop over the listener and every in-flight build's pipes, so that a fork
    # never happens with another fiber alive. That is a different server, not a
    # flag.
    private def daemon_serve(server, client, identity : String)
      request = daemon_read_request(client)
      cwd = request["cwd"].as_s
      args = request["args"].as_a.map(&.as_s)

      # A daemon holds an analysed prelude *and* the compiler that analysed it.
      # Rebuild the compiler and the daemon keeps serving builds from the old
      # one, silently — the worst kind of stale cache, because the output looks
      # like a normal build. Refuse instead, and say why.
      if daemon_identity != identity
        daemon_refuse(client, <<-MSG)
          The build daemon started before #{Process.executable_path || "the compiler"} was rebuilt,
          so it would compile this with the old one. Restart the daemon.
          MSG
        return
      end

      if (client_version = request["version"]?.try(&.as_s)) && client_version != Crystal::Config.description
        daemon_refuse(client, <<-MSG)
          The build daemon and this client are different compilers.
          Daemon: #{Crystal::Config.description}
          Client: #{client_version}
          MSG
        return
      end

      out_r, out_w = IO.pipe(read_blocking: false, write_blocking: true)
      err_r, err_w = IO.pipe(read_blocking: false, write_blocking: true)

      pid = Crystal::System::Process.fork do
        # The child must not keep the listening socket or the connection alive:
        # the client waits for end-of-stream, and an inherited copy would hold
        # it open past the build. Note `delete: false` — `UNIXServer#close`
        # unlinks the socket file by default, so a plain `close` here would take
        # the daemon's address away from every later client while the daemon
        # itself went on listening, apparently healthy.
        server.close(delete: false) rescue nil
        client.close rescue nil
        out_r.close rescue nil
        err_r.close rescue nil

        LibC.dup2(out_w.fd, 1)
        LibC.dup2(err_w.fd, 2)

        Dir.cd(cwd)
        Crystal::Command.run(args)
        LibC._exit 0
      end

      out_w.close
      err_w.close

      # One fiber per stream, and a lock so two frames never interleave.
      lock = Mutex.new
      done = Channel(Nil).new
      spawn { daemon_relay(out_r, DAEMON_FRAME_STDOUT, client, lock); done.send(nil) }
      spawn { daemon_relay(err_r, DAEMON_FRAME_STDERR, client, lock); done.send(nil) }
      2.times { done.receive }

      status = ::Process.new(Crystal::System::Process.new(pid.not_nil!)).wait

      lock.synchronize do
        client.write_byte(DAEMON_FRAME_EXIT)
        client.write_bytes(status.exit_code, IO::ByteFormat::LittleEndian)
        client.flush
      end
    end

    private def daemon_relay(src : IO, kind : UInt8, dst : IO, lock : Mutex)
      buffer = Bytes.new(16384)
      while (read = src.read(buffer)) > 0
        lock.synchronize do
          dst.write_byte(kind)
          dst.write_bytes(read.to_u32, IO::ByteFormat::LittleEndian)
          dst.write(buffer[0, read])
          dst.flush
        end
      end
    rescue IO::Error
      # Client hung up mid-build; the exit frame will fail too and the daemon
      # simply moves on to the next request.
    ensure
      src.close rescue nil
    end
  {% end %}

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
      bytes = "#{line}\n".to_slice
      client.write_byte(DAEMON_FRAME_STDERR)
      client.write_bytes(bytes.size.to_u32, IO::ByteFormat::LittleEndian)
      client.write(bytes)
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

  private def daemon_build
    path = daemon_socket_path

    begin
      client = UNIXSocket.new(path)
    rescue ex : Socket::Error | File::Error
      abort! "no daemon listening on #{path} (start one with `crystal daemon start`)", :FAILURE
    end

    # The child runs a full command line, so put back the subcommand this one
    # consumed: `crystal daemon build -o x y.cr` is `crystal build -o x y.cr`.
    request = {cwd: Dir.current, args: ["build"] + options, version: Crystal::Config.description}.to_json
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
