require "../../spec_helper"
require "../spec_helper"
require "compiler/iyi/compiler"
require "compiler/iyi/stale/reach"
require "json"

private def compile_class_var_reach(source : Iyi::Compiler::Source, name : String, owners : Array(String)) : String
  with_tempfile("reach_class_var.key") do |key_path|
    with_tempfile("reach_class_var.bin") do |bin_path|
      compiler = create_spec_compiler
      compiler.prelude = "iyi/prelude"
      compiler.stale_key = key_path

      begin
        compiler.compile(source, bin_path)
      rescue ex : Iyi::Error
        details = String.build do |io|
          io << ex.class << ": " << ex.to_s << "\nClassVar diagnostics for " << name << '\n'
          if program = compiler.program?
            if reach = program.stale_reach
              io << "reach mismatch: " << reach.mismatch << '\n'
              io << "matching elements:\n"
              reach.elements.each do |element|
                next unless element.kind.class_var? && element.key.ends_with?("::#{name}")
                io << "  key=" << element.key << " initializer_class=" << element.node.try(&.class)
                io << " initializer_type=" << element.node.try(&.type?) << " variable_type=" << element.type << '\n'
              end
              io << "comparison set:\n"
              reach.class_vars.each do |cv|
                next unless cv.name == name
                init = cv.initializer.try(&.node)
                io << "  owner=" << cv.owner << " name=" << cv.name
                io << " initializer_class=" << init.try(&.class) << " initializer_type=" << init.try(&.type?)
                io << " variable_type=" << cv.type << '\n'
              end
            else
              io << "reach unavailable\n"
            end
            if recorder = program.stale_recorder
              io << "emitted set:\n"
              recorder.emitted_class_vars.each do |cv|
                next unless cv.name == name
                init = cv.initializer.try(&.node)
                io << "  owner=" << cv.owner << " name=" << cv.name
                io << " initializer_class=" << init.try(&.class) << " initializer_type=" << init.try(&.type?)
                io << " variable_type=" << cv.type << '\n'
              end
            else
              io << "recorder unavailable\n"
            end
          else
            io << "program unavailable\n"
          end
        end
        raise Iyi::Error.new(details, cause: ex)
      end

      reach = compiler.program.stale_reach.not_nil!
      owners.each do |owner|
        reach.elements.any? { |element| element.kind.class_var? && element.key == "#{owner}::#{name}" }.should be_true
      end
      File.exists?(key_path).should be_true
      key = File.read(key_path)
      key.should contain(%("mismatch": []))
      JSON.parse(key)["local"]["callpath"].as_s
    end
  end
end

private def atomic_class_var_source(seed : Int32) : Iyi::Compiler::Source
  Iyi::Compiler::Source.new("reach_atomic.iyi", <<-IYI
    module spec/reach_atomic
    import std/atomic
    class FirstHolder
      def self.reach_seed : UInt64
        #{seed}_u64
      end
      @@waiting = Atomic(UInt64).new(self.reach_seed)
      def self.value
        @@waiting.get
      end
    end
    class SecondHolder
      @@waiting = Atomic(UInt64).new(0_u64)
      def self.value
        @@waiting.get
      end
    end
    puts FirstHolder.value
    puts SecondHolder.value
    IYI
  )
end

describe "Iyi::Stale S3e: Reach walk, cross-check, drop per EdgeKind (row 42)" do
  {% unless flag?(:win32) %}
    it "reaches Signal.wait class variable initializers without a mismatch" do
      source = Iyi::Compiler::Source.new("reach_signal.iyi", <<-IYI
        module spec/reach_signal
        import std/signal::{Signal}
        group do |g|
          g.spawn { Signal.wait(Signal::INT); 0 }
        end
        IYI
      )
      compile_class_var_reach(source, "@@waiting", ["Std::Signal::SignalWaiter"])
    end
  {% end %}

  it "reaches Atomic class variables with dependent initializers under distinct owners" do
    owners = ["Spec::ReachAtomic::FirstHolder", "Spec::ReachAtomic::SecondHolder"]
    first = compile_class_var_reach(atomic_class_var_source(1), "@@waiting", owners)
    changed = compile_class_var_reach(atomic_class_var_source(2), "@@waiting", owners)
    changed.should_not eq(first)
  end

  it "rejects a dropped Atomic class variable edge" do
    with_tempfile("reach_atomic_drop.key") do |key_path|
      with_tempfile("reach_atomic_drop.bin") do |bin_path|
        compiler = create_spec_compiler
        compiler.prelude = "iyi/prelude"
        compiler.stale_key = key_path
        compiler.stale_drop = Iyi::Stale::EdgeKind::ClassVar

        error = expect_raises(Iyi::Error, /reach mismatch/) do
          compiler.compile(atomic_class_var_source(1), bin_path)
        end
        error.message.to_s.should contain("Spec::ReachAtomic::FirstHolder::@@waiting")
      end
    end
  end

  it "compiles without error when no edge is dropped" do
    with_tempfile("reach_ok.key") do |key_path|
      with_tempfile("reach_ok.bin") do |bin_path|
        compiler = create_spec_compiler
        compiler.prelude = "iyi/prelude"
        compiler.stale_key = key_path

        source = Iyi::Compiler::Source.new("reach_ok.iyi", <<-IYI
          module spec/reach_ok
          def add(a : Int32, b : Int32) : Int32
            a + b
          end
          puts add(1, 2)
          IYI
        )

        compiler.compile(source, bin_path)
        File.exists?(key_path).should be_true
        key = File.read(key_path)
        key.should contain(%("mismatch": []))
      end
    end
  end

  it "refuses with reach mismatch when Call edge is dropped" do
    with_tempfile("reach_call.key") do |key_path|
      with_tempfile("reach_call.bin") do |bin_path|
        compiler = create_spec_compiler
        compiler.prelude = "iyi/prelude"
        compiler.stale_key = key_path
        compiler.stale_drop = Iyi::Stale::EdgeKind::Call

        source = Iyi::Compiler::Source.new("reach_call.iyi", <<-IYI
          module spec/reach_call
          def unique_callee_func : Int32
            42
          end
          puts unique_callee_func
          IYI
        )

        expect_raises(Iyi::Error, /reach mismatch/) do
          compiler.compile(source, bin_path)
        end
      end
    end
  end

  it "refuses with reach mismatch when BlockInline edge is dropped" do
    with_tempfile("reach_block.key") do |key_path|
      with_tempfile("reach_block.bin") do |bin_path|
        compiler = create_spec_compiler
        compiler.prelude = "iyi/prelude"
        compiler.stale_key = key_path
        compiler.stale_drop = Iyi::Stale::EdgeKind::BlockInline

        source = Iyi::Compiler::Source.new("reach_block.iyi", <<-IYI
          module spec/reach_block
          def my_inlined(&block : Int32 -> Int32) : Int32
            yield 42
          end
          puts my_inlined { |x| x + 100 }
          IYI
        )

        expect_raises(Iyi::Error, /reach mismatch/) do
          compiler.compile(source, bin_path)
        end
      end
    end
  end

  it "refuses with reach mismatch when ProcLiteral edge is dropped" do
    with_tempfile("reach_proc.key") do |key_path|
      with_tempfile("reach_proc.bin") do |bin_path|
        compiler = create_spec_compiler
        compiler.prelude = "iyi/prelude"
        compiler.stale_key = key_path
        compiler.stale_drop = Iyi::Stale::EdgeKind::ProcLiteral

        source = Iyi::Compiler::Source.new("reach_proc.iyi", <<-IYI
          module spec/reach_proc
          fn = -> { 42 }
          puts fn.call
          IYI
        )

        expect_raises(Iyi::Error, /reach mismatch/) do
          compiler.compile(source, bin_path)
        end
      end
    end
  end

  it "refuses with reach mismatch when Const edge is dropped" do
    with_tempfile("reach_const.key") do |key_path|
      with_tempfile("reach_const.bin") do |bin_path|
        compiler = create_spec_compiler
        compiler.prelude = "iyi/prelude"
        compiler.stale_key = key_path
        compiler.stale_drop = Iyi::Stale::EdgeKind::Const

        source = Iyi::Compiler::Source.new("reach_const.iyi", <<-IYI
          module spec/reach_const
          COMPLEX_CONST = [10, 20, 30]
          puts COMPLEX_CONST.size
          IYI
        )

        expect_raises(Iyi::Error, /reach mismatch/) do
          compiler.compile(source, bin_path)
        end
      end
    end
  end

  it "refuses with reach mismatch when ClassVar edge is dropped" do
    with_tempfile("reach_cvar.key") do |key_path|
      with_tempfile("reach_cvar.bin") do |bin_path|
        compiler = create_spec_compiler
        compiler.prelude = "iyi/prelude"
        compiler.stale_key = key_path
        compiler.stale_drop = Iyi::Stale::EdgeKind::ClassVar

        source = Iyi::Compiler::Source.new("reach_cvar.iyi", <<-IYI
          module spec/reach_cvar
          class CVarHolder
            @@list = [100, 200]
            def self.list
              @@list
            end
          end
          puts CVarHolder.list.size
          IYI
        )

        expect_raises(Iyi::Error, /reach mismatch/) do
          compiler.compile(source, bin_path)
        end
      end
    end
  end

  it "refuses with reach mismatch when IvarInit edge is dropped" do
    with_tempfile("reach_ivar.key") do |key_path|
      with_tempfile("reach_ivar.bin") do |bin_path|
        compiler = create_spec_compiler
        compiler.prelude = "iyi/prelude"
        compiler.stale_key = key_path
        compiler.stale_drop = Iyi::Stale::EdgeKind::IvarInit

        source = Iyi::Compiler::Source.new("reach_ivar.iyi", <<-IYI
          module spec/reach_ivar
          class Box
            @items = [1, 2, 3, 4]
            def items
              @items
            end
          end
          puts Box.new.items.size
          IYI
        )

        expect_raises(Iyi::Error, /reach mismatch/) do
          compiler.compile(source, bin_path)
        end
      end
    end
  end

  it "observed program with real prelude reaching raise and puts has empty mismatch and no __iyi_effect_ elements" do
    with_tempfile("reach_obs.key") do |key_path|
      with_tempfile("reach_obs.elements.jsonl") do |elements_path|
        with_tempfile("reach_obs.bin") do |bin_path|
          compiler = create_spec_compiler
          compiler.prelude = "iyi/prelude"
          compiler.flags << "iyi_observe"
          compiler.stale_key = key_path
          compiler.stale_dump_elements = elements_path

          source = Iyi::Compiler::Source.new("reach_obs.iyi", <<-IYI
            module spec/reach_obs
            def check_raise(x : Int32) : Int32
              raise "panicked" if x == 0
              x + 1
            end
            puts check_raise(1)
            IYI
          )

          compiler.compile(source, bin_path)
          File.exists?(key_path).should be_true
          key = File.read(key_path)
          key.should contain(%("mismatch": []))
          File.exists?(elements_path).should be_true
          elements = File.read(elements_path)
          elements.should_not contain("__iyi_effect_")
        end
      end
    end
  end
end
