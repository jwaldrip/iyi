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
# `{"cwd": ..., "args": [...]}`.
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
      STDERR.puts "The build daemon needs a single-threaded compiler: make crystal sequential_codegen=1"
      STDERR.puts "(`Crystal::System::Process.fork` is unavailable in a multi-threaded build.)"
      exit 1
    {% else %}
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

      loop do
        client = server.accept
        begin
          daemon_serve(server, client)
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
    # Serves one build. Sequential on purpose: one build at a time is enough to
    # show what the preserved prelude is worth, and concurrent builds would need
    # a separate `Program` per child anyway.
    private def daemon_serve(server, client)
      request = daemon_read_request(client)
      cwd = request["cwd"].as_s
      args = request["args"].as_a.map(&.as_s)

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
    request = {cwd: Dir.current, args: ["build"] + options}.to_json
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
