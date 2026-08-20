module Crystal::System::Thread
  alias Handle = Nil

  def self.init : Nil
  end

  def self.new_handle(thread_obj : ::Thread) : Handle
    raise NotImplementedError.new("Crystal::System::Thread.new_handle")
  end

  # iyi: `Thread#initialize` in the shared code calls this to spawn the system
  # thread. wasm32-wasi has no threads, so creating one is unsupported at
  # runtime; the method exists only so the shared `Thread` type-checks (same
  # treatment as `.new_handle` above).
  private def init_handle
    raise NotImplementedError.new("Crystal::System::Thread#init_handle")
  end

  def self.current_handle : Handle
    nil
  end

  def self.yield_current : Nil
    raise NotImplementedError.new("Crystal::System::Thread.yield_current")
  end

  def self.current_thread : ::Thread
    @@current_thread ||= ::Thread.new
  end

  def self.current_thread? : ::Thread?
    @@current_thread
  end

  def self.current_thread=(@@current_thread : ::Thread)
  end

  def self.sleep(time : ::Time::Span) : Nil
    req = uninitialized LibC::Timespec
    req.tv_sec = typeof(req.tv_sec).new(time.@seconds)
    req.tv_nsec = typeof(req.tv_nsec).new(time.@nanoseconds)

    loop do
      return if LibC.nanosleep(pointerof(req), out rem) == 0
      raise RuntimeError.from_errno("nanosleep() failed") unless Errno.value == Errno::EINTR
      req = rem
    end
  end

  private def system_join : Exception?
    NotImplementedError.new("Crystal::System::Thread#system_join")
  end

  private def system_close
  end

  private def stack_address : Void*
    # TODO: Implement
    Pointer(Void).null
  end

  # iyi: wasm32-wasi has no thread-naming syscall (there are no threads to
  # name), so setting the name stops at the Crystal-side `@name` property.
  # This stub exists only to satisfy `Thread#name=`; it returns *name* to match
  # the pthread/win32 signatures.
  private def system_name=(name : String) : String
    name
  end

  def self.init_suspend_resume : Nil
  end

  private def system_suspend : Nil
    raise NotImplementedError.new("Crystal::System::Thread.system_suspend")
  end

  private def system_wait_suspended : Nil
    raise NotImplementedError.new("Crystal::System::Thread.system_wait_suspended")
  end

  private def system_resume : Nil
    raise NotImplementedError.new("Crystal::System::Thread.system_resume")
  end
end
