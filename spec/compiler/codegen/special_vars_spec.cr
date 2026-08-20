require "../../spec_helper"

describe "Codegen: special vars" do
  ["$~", "$?"].each do |name|
    it "codegens #{name}" do
      run(<<-CODE).to_string.should eq("hey")
        class Object; def not_nil!; self; end; end

        def foo(z)
          #{name} = "hey"
        end

        foo(2)
        #{name}
        CODE
    end

    it "codegens #{name} with nilable (1)" do
      run(<<-CODE).to_string.should eq("ouch")
        require "prelude"

        def foo
          if 1 == 2
            #{name} = "foo"
          end
        end

        foo

        begin
          #{name}
        rescue ex
          "ouch"
        end
        CODE
    end

    it "codegens #{name} with nilable (2)" do
      run(<<-CODE).to_string.should eq("foo")
        require "prelude"

        def foo
          if 1 == 1
            #{name} = "foo"
          end
        end

        foo

        begin
          #{name}
        rescue ex
          "ouch"
        end
        CODE
    end
  end

  it "codegens $~ two levels" do
    run(<<-CODE).to_string.should eq("hey")
      class Object; def not_nil!; self; end; end

      def foo
        $? = "hey"
      end

      def bar
        $? = foo
        $?
      end

      bar
      $?
      CODE
  end

  it "works lazily" do
    run(<<-CODE).to_string.should eq("bar")
      require "prelude"

      class Foo
        getter string

        def initialize(@string : String)
        end
      end

      def bar(&block : Foo -> _)
        block
      end

      block = bar do |foo|
        case foo.string
        when /foo-(.+)/
          $1
        else
          "baz"
        end
      end
      block.call(Foo.new("foo-bar"))
      CODE
  end

  it "codegens in block" do
    run(<<-CODE).to_string.should eq("hey")
      require "prelude"

      class Object; def not_nil!; self; end; end

      def foo
        $~ = "hey"
        yield
      end

      a = nil
      foo do
        a = $~
      end
      a.not_nil!
      CODE
  end

  it "codegens in block with nested block" do
    run(<<-CODE).to_string.should eq("hey")
      require "prelude"

      class Object; def not_nil!; self; end; end

      def bar
        yield
      end

      def foo
        bar do
          $~ = "hey"
          yield
        end
      end

      a = nil
      foo do
        a = $~
      end
      a.not_nil!
      CODE
  end

  it "codegens after block" do
    run(<<-CODE).to_string.should eq("hey")
      require "prelude"

      class Object; def not_nil!; self; end; end

      def foo
        $~ = "hey"
        yield
      end

      a = nil
      foo {}
      $~
      CODE
  end

  it "codegens after block 2" do
    run(<<-CODE).to_string.should eq("bye")
      class Object; def not_nil!; self; end; end

      def baz
        $~ = "bye"
      end

      def foo
        baz
        yield
        $~
      end

      foo do
      end
      CODE
  end

  it "codegens with default argument" do
    run(<<-CODE).to_string.should eq("bye")
      class Object; def not_nil!; self; end; end

      def baz(x = 1)
        $~ = "bye"
      end

      baz
      $~
      CODE
  end

  it "preserves special vars in macro expansion with call with default arguments (#824)" do
    run(<<-CODE).to_string.should eq("yes")
      class Object; def not_nil!; self; end; end

      def bar(x = 0)
        $~ = "yes"
      end

      macro foo
        bar
        $~
      end

      foo
      CODE
  end

  it "allows with primitive" do
    run(<<-CODE).to_i.should eq(123)
      class Object; def not_nil!; self; end; end

      def foo
        $~ = 123
      end

      foo

      v = $~
      v || 456
      CODE
  end

  it "allows with struct" do
    run(<<-CODE).to_i.should eq(123)
      class Object; def not_nil!; self; end; end

      struct Foo
        def initialize(@x : Int32)
        end

        def x
          @x
        end
      end

      def foo
        $~ = Foo.new(123)
      end

      foo

      v = $~
      if v
        v.x
      else
        456
      end
      CODE
  end

  it "preserves special vars if initialized inside block (#2194)" do
    run(<<-CODE).to_string.should eq("foo")
      class Object; def not_nil!; self; end; end

      def foo
        $~ = "foo"
      end

      def bar
        yield
      end

      bar do
        foo
      end

      v = $~
      if v
        v
      else
        "bar"
      end
      CODE
  end
end
