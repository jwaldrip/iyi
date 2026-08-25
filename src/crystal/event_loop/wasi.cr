# :nodoc:
class Crystal::EventLoop::Wasi < Crystal::EventLoop
  def self.default_file_blocking?
    false
  end

  def self.default_socket_blocking?
    false
  end

  def initialize(parallelism : Int32)
  end

  # Runs the event loop.
  def run(blocking : Bool) : Bool
    raise NotImplementedError.new("Crystal::EventLoop::Wasi#run")
  end

  # iyi: the execution-context surface, which this class never grew.
  #
  # `Crystal::EventLoop` gained `run(blocking, &)`, `lock?(&)` and `interrupt?`
  # behind the same flags that select execution contexts, and the Wasi
  # implementation was not updated with it, so the whole standard library
  # stopped cross-compiling to `wasm32-wasi`: the error is that the abstract
  # `run(blocking : Bool, & : (Fiber ->))` is unimplemented, and it fires while
  # type-checking any Crystal program for that target.
  #
  # Raising rather than working, because none of the loop works on wasm32 yet:
  # every wait here already raises, `poll_oneoff` is a TODO throughout the file,
  # and a body that silently returned would claim an event loop that is not
  # there. What this restores is the ability to compile for the target at all,
  # which is what an out-of-the-box platform claim needs first.
  {% if !flag?(:without_mt) && !flag?(:preview_mt) || flag?(:execution_context) %}
    def run(blocking : Bool, & : Fiber ->) : Nil
      raise NotImplementedError.new("Crystal::EventLoop::Wasi#run(blocking, &)")
    end

    def lock?(&) : Bool
      raise NotImplementedError.new("Crystal::EventLoop::Wasi#lock?")
    end

    def interrupt? : Bool
      raise NotImplementedError.new("Crystal::EventLoop::Wasi#interrupt?")
    end
  {% end %}

  def interrupt : Nil
    raise NotImplementedError.new("Crystal::Wasi::EventLoop.interrupt")
  end

  def sleep(duration : ::Time::Span) : Nil
    raise NotImplementedError.new("Crystal::Wasi::EventLoop.sleep")
  end

  # Creates a timeout_event.
  def create_timeout_event(fiber) : Crystal::EventLoop::Event
    raise NotImplementedError.new("Crystal::Wasi::EventLoop.create_timeout_event")
  end

  def pipe(read_blocking : Bool?, write_blocking : Bool?) : {IO::FileDescriptor, IO::FileDescriptor}
    raise NotImplementedError.new("Crystal::EventLoop::Wasi#pipe")
  end

  # iyi: `read` and `write` on this event loop were already implemented against
  # `LibC.read` and `LibC.write`, and `LibC.open` is bound for the target
  # (`src/lib_c/wasm32-wasi/c/fcntl.cr:24`), so opening was the one step of
  # reading a file that raised. A compiler is a program that reads files, so on
  # this target it could not read its own prelude.
  #
  # It reports the errno rather than raising, which is this method's contract;
  # `File.open` turns that into `File::Error`. Two differences from the
  # libevent version above, both because of what wasi is: no `O_CLOEXEC`, since
  # there is no exec to close across (wasi-libc defines it as 0 anyway), and
  # the descriptor is always blocking, since `set_blocking` has no
  # implementation here and there is no event loop to hand a non-blocking fd
  # to. wasi's own `path_open` is the richer call underneath, and `LibC.open`
  # in wasi-libc is a wrapper over it that resolves the path against the
  # preopened directories, which is what makes a bare path work at all.
  def open(path : String, flags : Int32, permissions : File::Permissions, blocking : Bool?) : {System::FileDescriptor::Handle, Bool} | Errno | WinError
    path.check_no_null_byte

    fd = LibC.open(path, flags, permissions)
    return Errno.value if fd == -1

    {fd, true}
  end

  # TODO: LibWasi.fd_read
  def read(file_descriptor : Crystal::System::FileDescriptor, slice : Bytes) : Int32
    evented_read(file_descriptor, "Error reading file_descriptor") do
      LibC.read(file_descriptor.fd, slice, slice.size).tap do |return_code|
        if return_code == -1 && Errno.value == Errno::EBADF
          raise IO::Error.new "File not open for reading", target: file_descriptor
        end
      end
    end
  end

  def pread(file_descriptor : System::FileDescriptor, slice : Bytes, offset : Int64) : Int32
    evented_read(file_descriptor, "Error reading file_descriptor") do
      LibC.pread(file_descriptor.fd, slice, slice.size, offset)
    end
  end

  def wait_readable(file_descriptor : Crystal::System::FileDescriptor) : Nil
    evented_wait_readable(file_descriptor) do
      raise IO::TimeoutError.new("Read timed out")
    end
  end

  # TODO: LibWasi.fd_write
  def write(file_descriptor : Crystal::System::FileDescriptor, slice : Bytes) : Int32
    evented_write(file_descriptor, "Error writing file_descriptor") do
      LibC.write(file_descriptor.fd, slice, slice.size).tap do |return_code|
        if return_code == -1 && Errno.value == Errno::EBADF
          raise IO::Error.new "File not open for writing", target: file_descriptor
        end
      end
    end
  end

  def wait_writable(file_descriptor : Crystal::System::FileDescriptor) : Nil
    evented_wait_writable(file_descriptor) do
      raise IO::TimeoutError.new("Write timed out")
    end
  end

  def reopened(file_descriptor : Crystal::System::FileDescriptor) : Nil
    raise NotImplementedError.new("Crystal::EventLoop#reopened(FileDescriptor)")
  end

  # TODO: LibWasi.sock_shutdown
  def shutdown(file_descriptor : Crystal::System::FileDescriptor) : Nil
    evented_close(file_descriptor)
  end

  def close(file_descriptor : Crystal::System::FileDescriptor) : Nil
    file_descriptor.file_descriptor_close
  end

  def socket(family : ::Socket::Family, type : ::Socket::Type, protocol : ::Socket::Protocol) : {::Socket::Handle, Bool}
    raise NotImplementedError.new("Crystal::EventLoop::Wasi#socket")
  end

  def socketpair(type : ::Socket::Type, protocol : ::Socket::Protocol, blocking : Bool) : {Handle, Handle}
    raise NotImplementedError.new("Crystal::EventLoop::Wasi#socketpair")
  end

  # TODO: LibWasi.sock_recv
  def read(socket : ::Socket, slice : Bytes) : Int32
    evented_read(socket, "Error reading socket") do
      LibC.recv(socket.fd, slice, slice.size, 0).to_i32
    end
  end

  def wait_readable(socket : ::Socket) : Nil
    evented_wait_readable(socket) do
      raise IO::TimeoutError.new("Read timed out")
    end
  end

  # TODO: LibWasi.sock_send
  def write(socket : ::Socket, slice : Bytes) : Int32
    evented_write(socket, "Error writing to socket") do
      LibC.send(socket.fd, slice, slice.size, 0)
    end
  end

  def wait_writable(socket : ::Socket) : Nil
    evented_wait_writable(socket) do
      raise IO::TimeoutError.new("Write timed out")
    end
  end

  def receive_from(socket : ::Socket, slice : Bytes) : Tuple(Int32, ::Socket::Address)
    raise NotImplementedError.new "Crystal::Wasi::EventLoop#receive_from"
  end

  def send_to(socket : ::Socket, slice : Bytes, address : ::Socket::Address) : Int32
    raise NotImplementedError.new "Crystal::Wasi::EventLoop#send_to"
  end

  def connect(socket : ::Socket, address : ::Socket::Addrinfo | ::Socket::Address, timeout : ::Time::Span | ::Nil) : IO::Error?
    raise NotImplementedError.new "Crystal::Wasi::EventLoop#connect"
  end

  # TODO: LibWasi.sock_accept
  def accept(socket : ::Socket) : ::Socket::Handle?
    raise NotImplementedError.new "Crystal::Wasi::EventLoop#accept"
  end

  def shutdown(socket : ::Socket) : Nil
    evented_close(socket)
  end

  def close(socket : ::Socket) : Nil
    socket.socket_close
  end

  def evented_read(target, errno_msg : String, &) : Int32
    loop do
      bytes_read = yield
      if bytes_read != -1
        # `to_i32` is acceptable because `Slice#size` is an Int32
        return bytes_read.to_i32
      end

      if Errno.value == Errno::EAGAIN
        evented_wait_readable(target) do
          raise IO::TimeoutError.new("Read timed out")
        end
      else
        raise IO::Error.from_errno(errno_msg, target: target)
      end
    end
  end

  def evented_write(target, errno_msg : String, &) : Int32
    loop do
      bytes_written = yield
      if bytes_written != -1
        return bytes_written.to_i32
      end

      if Errno.value == Errno::EAGAIN
        evented_wait_writable(target) do
          raise IO::TimeoutError.new("Write timed out")
        end
      else
        raise IO::Error.from_errno(errno_msg, target: target)
      end
    end
  end

  # TODO: LibWasi.poll_oneoff
  private def evented_wait_readable(io, &)
    raise NotImplementedError.new("Crystal::EventLoop::Wasi#evented_wait_readable")
  end

  # TODO: LibWasi.poll_oneoff
  private def evented_wait_writable(io, &)
    raise NotImplementedError.new("Crystal::EventLoop::Wasi#evented_wait_writable")
  end

  private def evented_close(io)
    # nothing to do (yet)
  end
end

struct Crystal::EventLoop::Wasi::Event
  include Crystal::EventLoop::Event

  def add(timeout : Time::Span) : Nil
  end

  def add(timeout : Nil) : Nil
  end

  def free : Nil
  end

  def delete
  end
end
