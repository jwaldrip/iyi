require "../../spec_helper"

describe "Code gen: sizeof" do
  it "gets sizeof int" do
    run("sizeof(Int32)").to_i.should eq(4)
  end

  it "gets sizeof struct" do
    run(<<-CODE).to_i.should eq(12)
      struct Foo
        def initialize(@x : Int32, @y : Int32, @z : Int32)
        end
      end

      Foo.new(1, 2, 3)

      sizeof(Foo)
      CODE
  end

  it "gets sizeof class" do
    # A class is represented as a pointer to its data
    run(<<-CODE).to_i.should eq(sizeof(Void*))
      class Foo
        def initialize(@x : Int32, @y : Int32, @z : Int32)
        end
      end

      Foo.new(1, 2, 3)

      sizeof(Foo)
      CODE
  end

  it "gets sizeof union" do
    size = run(<<-CODE).to_i
      sizeof(Int32 | Float64)
      CODE

    # This union is represented as:
    #
    #   struct {
    #      4 bytes, # for the type id
    #      8 bytes, # for the largest size between Int32 and Float64
    #   }
    #
    # But in 64 bits structs are aligned to 8 bytes, so it'll actually
    # be struct { 8 bytes, 8 bytes }.
    #
    # In 32 bits structs are aligned to 4 bytes, so it remains the same.
    {% if flag?(:bits64) %}
      size.should eq(16)
    {% else %}
      size.should eq(12)
    {% end %}
  end

  it "gets instance_sizeof class" do
    run(<<-CODE).to_i.should eq(16)
      class Foo
        def initialize(@x : Int32, @y : Int32, @z : Int32)
        end
      end

      Foo.new(1, 2, 3)

      instance_sizeof(Foo)
      CODE
  end

  it "gets instance_sizeof a generic type with type vars" do
    run(<<-CODE).to_i.should eq(8)
      class Foo(T)
        def initialize(@x : T)
        end
      end

      instance_sizeof(Foo(Int32))
      CODE
  end

  it "gets sizeof Void" do
    # Same as the size of a byte, because doing
    # `Pointer(Void).malloc` must work like `Pointer(UInt8).malloc`
    run("sizeof(Void)").to_i.should eq(1)
  end

  it "gets sizeof NoReturn" do
    # NoReturn can't hold anything
    run("sizeof(NoReturn)").to_i.should eq(0)
  end

  it "gets sizeof Nil (#7644)" do
    # Nil can't hold anything
    run("sizeof(Nil)").to_i.should eq(0)
  end

  it "gets sizeof Bool (#8272)" do
    run("sizeof(Bool)").to_i.should eq(1)
  end

  it "can use sizeof in type argument (1)" do
    run(<<-CODE).to_i.should eq(4)
      struct StaticArray
        def size
          N
        end
      end

      x = uninitialized UInt8[sizeof(Int32)]
      x.size
      CODE
  end

  it "can use sizeof in type argument (2)" do
    run(<<-CODE).to_i.should eq(8)
      struct StaticArray
        def size
          N
        end
      end

      x = uninitialized UInt8[sizeof(Float64)]
      x.size
      CODE
  end

  it "can use sizeof of virtual type" do
    size = run(<<-CODE).to_i
      class Foo
        @x = 1
      end

      class Bar < Foo
        @y = 2
      end

      foo = Bar.new.as(Foo)
      sizeof(typeof(foo))
      CODE

    {% if flag?(:bits64) %}
      size.should eq(8)
    {% else %}
      size.should eq(4)
    {% end %}
  end

  it "can use instance_sizeof of virtual type" do
    run(<<-CODE).to_i.should eq(12)
      class Foo
        @x = 1
      end

      class Bar < Foo
        @y = 2
      end

      class Baz < Bar
        @z = 2
      end

      bar = Baz.new.as(Bar)
      instance_sizeof(typeof(bar))
      CODE
  end

  it "can use instance_sizeof in type argument" do
    run(<<-CODE).to_i.should eq(12)
      struct StaticArray
        def size
          N
        end
      end

      class Foo
        def initialize
          @x = 1
          @y = 1
        end
      end

      x = uninitialized UInt8[instance_sizeof(Foo)]
      x.size
      CODE
  end

  it "returns correct sizeof for abstract struct (#4319)" do
    size = run(<<-CODE).to_i
        abstract struct Entry
        end

        struct FooEntry < Entry
          def initialize
            @uid = ""
          end
        end

        struct BarEntry < Entry
          def initialize
            @uid = ""
          end
        end

        sizeof(Entry)
        CODE

    size.should eq(16)
  end

  it "doesn't precompute sizeof of abstract struct (#7741)" do
    run(<<-CODE).to_i.should eq(16)
      abstract struct Base
      end

      struct Foo(T) < Base
        def initialize(@x : T)
        end
      end

      z = sizeof(Base)

      Foo({Int32, Int32, Int32, Int32})

      z
      CODE
  end

  it "doesn't precompute sizeof of module (#7741)" do
    run(<<-CODE).to_i.should eq(16)
      module Base
      end

      struct Foo(T)
        include Base

        def initialize(@x : T)
        end
      end

      z = sizeof(Base)

      Foo({Int32, Int32, Int32, Int32})

      z
      CODE
  end

  describe "folded sizeof matches the codegen stride" do
    it "doesn't fold sizeof of a tuple holding a module" do
      both_modes_true?(folded_sizeof_program("{Int32, Base}", "", "early.to_u64 == stride")).should be_true
    end

    it "keeps copied array elements of a tuple holding a module" do
      both_modes_true?(folded_sizeof_program("{Int32, Base}", "copy = [{1, bar.as(Base)}].dup", "copy[0][1].is_a?(Bar) && copy[0][1].same?(bar) && early.to_u64 == stride")).should be_true
    end

    it "doesn't fold sizeof of a named tuple holding a module" do
      both_modes_true?(folded_sizeof_program("NamedTuple(x: Int32, b: Base)", "", "early.to_u64 == stride")).should be_true
    end

    it "doesn't fold sizeof of a union holding a module" do
      both_modes_true?(folded_sizeof_program("Base | Int32", "", "early.to_u64 == stride")).should be_true
    end

    it "doesn't fold sizeof of a static array of a module" do
      both_modes_true?(folded_sizeof_program("StaticArray(Base, 2)", "", "early.to_u64 == stride")).should be_true
    end

    it "doesn't fold sizeof of a struct with a module field" do
      extra = <<-EXTRA
        struct Holder
          def initialize(@b : Base)
          end
        end

        holder = Holder.new(bar.as(Base))
        EXTRA
      both_modes_true?(folded_sizeof_program("Holder", extra, "holder.b.is_a?(Bar) && early.to_u64 == stride")).should be_true
    end

    it "doesn't fold sizeof of an alias of a tuple holding a module" do
      both_modes_true?(folded_sizeof_program("Pair", "alias Pair = {Int32, Base}", "early.to_u64 == stride")).should be_true
    end

    it "still folds sizeof of a recursive struct held through a pointer" do
      extra = <<-EXTRA
        struct Node
          def initialize(@next : Pointer(Node))
          end
        end

        node = Node.new(Pointer(Node).null)
        EXTRA
      both_modes_true?(folded_sizeof_program("Node", extra, "early.to_u64 == stride")).should be_true
    end

    it "still folds sizeof of a class holding a module, which is a pointer" do
      both_modes_true?(folded_sizeof_program("Bar", "", "early.to_u64 == stride")).should be_true
    end

    it "takes offsetof of a field whose preceding fields are settled" do
      run(<<-CODE).to_i.should eq(0)
        module Base
        end

        class Bar
          include Base
        end

        struct Pair
          def initialize(@a : Int32, @b : Base)
          end
        end

        Pair.new(1, Bar.new.as(Base))
        offsetof(Pair, @a)
        CODE
    end

    it "refuses offsetof of a field after an unsettled module field" do
      expect_raises(Iyi::TypeException, /layout is not settled yet/) do
        run(<<-CODE)
          module Base
          end

          class Bar
            include Base
          end

          struct Pair
            def initialize(@a : Int32, @b : Base)
            end
          end

          Pair.new(1, Bar.new.as(Base))
          offsetof(Pair, @b)
          CODE
      end
    end
  end

  describe "instance_sizeof with an unsettled field" do
    it "compiles and runs a class holding a module field" do
      run(<<-CODE).to_b.should be_true
        module Base
        end

        class Bar
          include Base
        end

        class Holder
          def initialize(@b : Base)
          end
        end

        holder = Holder.new(Bar.new.as(Base))
        instance_sizeof(Holder) > 0
        CODE
    end
  end

  describe "alignof" do
    it "gets alignof primitive types" do
      run("alignof(Int32)").to_i.should eq(4)
      run("alignof(Void)").to_i.should eq(1)
      run("alignof(NoReturn)").to_i.should eq(1)
      run("alignof(Nil)").to_i.should eq(1)
      run("alignof(Bool)").to_i.should eq(1)
    end

    it "gets alignof struct" do
      run(<<-CODE).to_i.should eq(4)
        struct Foo
          def initialize(@x : Int8, @y : Int32, @z : Int16)
          end
        end

        Foo.new(1, 2, 3)

        alignof(Foo)
        CODE
    end

    it "gets alignof class" do
      # pointer size and alignment should be identical
      run(<<-CODE).to_i.should eq(sizeof(Void*))
        class Foo
          def initialize(@x : Int8, @y : Int32, @z : Int16)
          end
        end

        Foo.new(1, 2, 3)

        alignof(Foo)
        CODE
    end

    it "gets alignof union" do
      run("alignof(Int32 | Int8)").to_i.should eq(8)
      run("alignof(Int32 | Int64)").to_i.should eq(8)
    end

    it "alignof mixed union is not less than alignof its variant types" do
      # NOTE: `alignof(Int128) == 16` is not guaranteed
      run("alignof(Int32 | Int128) >= alignof(Int128)").to_b.should be_true
    end
  end

  describe "instance_alignof" do
    it "gets instance_alignof class" do
      run(<<-CODE).to_i.should eq(4)
        class Foo
          def initialize(@x : Int8, @y : Int32, @z : Int16)
          end
        end

        Foo.new(1, 2, 3)

        instance_alignof(Foo)
        CODE

      run(<<-CODE).to_i.should eq(8)
        class Foo
          def initialize(@x : Int8, @y : Int64, @z : Int16)
          end
        end

        Foo.new(1, 2, 3)

        instance_alignof(Foo)
        CODE

      run(<<-CODE).to_i.should eq(4)
        class Foo
        end

        Foo.new

        instance_alignof(Foo)
        CODE
    end

    it "gets instance_alignof a generic type with type vars" do
      run(<<-CODE).to_i.should eq(4)
        class Foo(T)
          def initialize(@x : T)
          end
        end

        instance_alignof(Foo(Int32))
        CODE

      run(<<-CODE).to_i.should eq(8)
        class Foo(T)
          def initialize(@x : T)
          end
        end

        instance_alignof(Foo(Int64))
        CODE

      run(<<-CODE).to_i.should eq(4)
        class Foo(T)
          def initialize(@x : T)
          end
        end

        instance_alignof(Foo(Int8))
        CODE
    end
  end
end

private def folded_sizeof_program(type : String, extra : String, check : String) : String
  <<-CODE
    module Base
    end

    class Bar
      include Base
    end

    struct Foo(T)
      include Base

      def initialize(@x : T)
      end
    end

    bar = Bar.new
    #{extra}
    early = sizeof(#{type})
    Foo({Int32, Int32, Int32, Int32}).new({1, 2, 3, 4})
    stride = (Pointer(#{type}).null + 1).address
    #{check}
    CODE
end

# Runs the program through the JIT and through the prelude-compiled executable.
private def both_modes_true?(code : String) : Bool
  run(code).to_b && run(%(require "prelude"\n#{code})).to_b
end

