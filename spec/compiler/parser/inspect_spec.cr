require "../../support/syntax"

private def expect_inspect(source, expected = source, file = __FILE__, line = __LINE__)
  it "inspects #{source.inspect}", file, line do
    node = Parser.new(source).parse
    node.inspect.should eq(expected), file: file, line: line
  end
end

describe "ASTNode#inspect" do
  expect_inspect %q{[] of T}, %(ArrayLiteral[of: Path["T"]])
  expect_inspect %q{([] of T).foo}, %(Call[Expressions.paren(ArrayLiteral[of: Path["T"]]), "foo"])
  expect_inspect %q{({} of K => V).foo}, <<-CODE
  Call[
    Expressions.paren(HashLiteral[of: HashLiteral::Entry[Path["K"], Path["V"]]]),
    "foo"
  ]
  CODE
  expect_inspect %q{foo(bar)}, %(Call["foo", [Call["bar"]]])
  expect_inspect %q{(~1).foo}, %(Call[Expressions.paren(Call[NumberLiteral["1", :i32], "~"]), "foo"])
  expect_inspect %q{1 && (a = 2)}, <<-CODE
  And[
    NumberLiteral["1", :i32],
    Expressions.paren(Assign[Var["a"], NumberLiteral["2", :i32]])
  ]
  CODE
  expect_inspect %q{(a = 2) && 1}, <<-CODE
  And[
    Expressions.paren(Assign[Var["a"], NumberLiteral["2", :i32]]),
    NumberLiteral["1", :i32]
  ]
  CODE
  expect_inspect %q{foo(a.as(Int32))}, %(Call["foo", [Cast[Call["a"], Path["Int32"]]]])
  expect_inspect %q{(1 + 2).as(Int32)}, <<-CODE
  Cast[
    Expressions.paren(
      Call[NumberLiteral["1", :i32], "+", [NumberLiteral["2", :i32]]]
    ),
    Path["Int32"]
  ]
  CODE
  expect_inspect %q{a.as?(Int32)}, %(NilableCast[Call["a"], Path["Int32"]])
  expect_inspect %q{(1 + 2).as?(Int32)}, <<-CODE
  NilableCast[
    Expressions.paren(
      Call[NumberLiteral["1", :i32], "+", [NumberLiteral["2", :i32]]]
    ),
    Path["Int32"]
  ]
  CODE
  expect_inspect %q{@foo.bar}, %(Call[InstanceVar["@foo"], "bar"])
  expect_inspect %(:foo), %(SymbolLiteral["foo"])
  expect_inspect %(:"{"), %(SymbolLiteral["{"])
  expect_inspect %(%r()), %(RegexLiteral[StringLiteral[""]])
  expect_inspect %(%r()imx), <<-CODE
  RegexLiteral[
    StringLiteral[""],
    options: Iyi::RegexOptions[IGNORE_CASE, MULTILINE, EXTENDED]
  ]
  CODE
  expect_inspect %(/hello world/), %(RegexLiteral[StringLiteral["hello world"]])
  expect_inspect %(/hello world/imx), <<-CODE
  RegexLiteral[
    StringLiteral["hello world"],
    options: Iyi::RegexOptions[IGNORE_CASE, MULTILINE, EXTENDED]
  ]
  CODE
  expect_inspect %(/\\s/), %(RegexLiteral[StringLiteral["\\\\s"]])
  expect_inspect %(/\\?/), %(RegexLiteral[StringLiteral["\\\\?"]])
  expect_inspect %(/\\(group\\)/), %(RegexLiteral[StringLiteral["\\\\(group\\\\)"]])
  expect_inspect %(/\\//), %(RegexLiteral[StringLiteral["/"]])
  expect_inspect %(/\#{1 / 2}/), <<-CODE
    RegexLiteral[
      StringInterpolation[
        Call[NumberLiteral["1", :i32], "/", [NumberLiteral["2", :i32]]]
      ]
    ]
    CODE
  expect_inspect %<%r(/)>, %(RegexLiteral[StringLiteral["/"]])
  expect_inspect %(/ /), %(RegexLiteral[StringLiteral[" "]])
  expect_inspect %(%r( )), %(RegexLiteral[StringLiteral[" "]])
  expect_inspect %(foo &.bar), %(Call["foo", block: Block[Var["__arg0"], body: Call[Var["__arg0"], "bar"]]])
  expect_inspect %(foo &.bar(1, 2, 3)), <<-CODE
    Call[
      "foo",
      block: Block[
        Var["__arg0"],
        body: Call[
          Var["__arg0"],
          "bar",
          [NumberLiteral["1", :i32],
           NumberLiteral["2", :i32],
           NumberLiteral["3", :i32]]
        ]
      ]
    ]
    CODE
  expect_inspect %(foo { |i| i.bar { i } }), <<-CODE
    Call[
      "foo",
      block: Block[
        Var["i"],
        body: Call[Var["i"], "bar", block: Block[body: Var["i"]]]
      ]
    ]
    CODE
  expect_inspect %(foo do |k, v|\n  k.bar(1, 2, 3)\nend), <<-CODE
    Call[
      "foo",
      block: Block[
        Var["k"], Var["v"],
        body: Call[
          Var["k"],
          "bar",
          [NumberLiteral["1", :i32],
           NumberLiteral["2", :i32],
           NumberLiteral["3", :i32]]
        ]
      ]
    ]
    CODE
  expect_inspect %(foo(3, &.*(2))), <<-CODE
    Call[
      "foo",
      [NumberLiteral["3", :i32]],
      block: Block[
        Var["__arg0"],
        body: Call[Var["__arg0"], "*", [NumberLiteral["2", :i32]]]
      ]
    ]
    CODE
  expect_inspect %(return begin\n  1\n  2\nend), %(Return[Expressions.begin(NumberLiteral["1", :i32], NumberLiteral["2", :i32])])
  expect_inspect %(macro foo\n  %bar = 1\nend), <<-CODE
    Macro[
      "foo",
      [],
      Expressions[MacroLiteral["  "], MacroVar["bar"], MacroLiteral[" = 1\\n"]]
    ]
    CODE
  expect_inspect %(macro foo\n  %bar = 1; end), <<-CODE
    Macro[
      "foo",
      [],
      Expressions[MacroLiteral["  "], MacroVar["bar"], MacroLiteral[" = 1; "]]
    ]
    CODE
  expect_inspect %(macro foo\n  %bar{1, x} = 1\nend), <<-CODE
    Macro[
      "foo",
      [],
      Expressions[
        MacroLiteral["  "],
        MacroVar["bar", exps: [NumberLiteral["1", :i32], Var["x"]]],
        MacroLiteral[" = 1\\n"]
      ]
    ]
    CODE
  expect_inspect %({% foo %}), %(MacroExpression[Var["foo"], output: false])
  expect_inspect %({{ foo }}), %(MacroExpression[Var["foo"]])
  expect_inspect %({% if foo %}\n  foo_then\n{% end %}), %(MacroIf[Var["foo"], MacroLiteral["\\n" + "  foo_then\\n"]])
  expect_inspect %({% if foo %}\n  foo_then\n{% else %}\n  foo_else\n{% end %}), <<-CODE
    MacroIf[
      Var["foo"],
      MacroLiteral["\\n" + "  foo_then\\n"],
      MacroLiteral["\\n" + "  foo_else\\n"]
    ]
    CODE
  expect_inspect %({% for foo in bar %}\n  {{ foo }}\n{% end %}), <<-CODE
    MacroFor[
      [Var["foo"]],
      Var["bar"],
      Expressions[
        MacroLiteral["\\n" + "  "],
        MacroExpression[Var["foo"]],
        MacroLiteral["\\n"]
      ]
    ]
    CODE
  expect_inspect %(macro foo\n  {% for foo in bar %}\n    {{ foo }}\n  {% end %}\nend), <<-CODE
    Macro[
      "foo",
      [],
      Expressions[
        MacroLiteral["  "],
        MacroFor[
          [Var["foo"]],
          Var["bar"],
          Expressions[
            MacroLiteral["\\n" + "    "],
            MacroExpression[Var["foo"]],
            MacroLiteral["\\n" + "  "]
          ]
        ],
        MacroLiteral["\\n"]
      ]
    ]
    CODE
  expect_inspect %[1.as(Int32)], %(Cast[NumberLiteral["1", :i32], Path["Int32"]])
  expect_inspect %[(1 || 1.1).as(Int32)], <<-CODE
    Cast[
      Expressions.paren(Or[NumberLiteral["1", :i32], NumberLiteral["1.1", :f64]]),
      Path["Int32"]
    ]
    CODE
  expect_inspect %[1 & 2 & (3 | 4)], <<-CODE
    Call[
      Call[NumberLiteral["1", :i32], "&", [NumberLiteral["2", :i32]]],
      "&",
      [Expressions.paren(
         Call[NumberLiteral["3", :i32], "|", [NumberLiteral["4", :i32]]]
       )]
    ]
    CODE
  expect_inspect %[(1 & 2) & (3 | 4)], <<-CODE
    Call[
      Expressions.paren(
        Call[NumberLiteral["1", :i32], "&", [NumberLiteral["2", :i32]]]
      ),
      "&",
      [Expressions.paren(
         Call[NumberLiteral["3", :i32], "|", [NumberLiteral["4", :i32]]]
       )]
    ]
    CODE
  expect_inspect %Q{def foo(x : T = 1)\nend}, <<-CODE
    Def[
      "foo",
      [Arg["x", default_value: NumberLiteral["1", :i32], restriction: Path["T"]]],
      Nop.new
    ]
    CODE
  expect_inspect %Q{def foo(x : X, y : Y) forall X, Y\nend}, <<-CODE
    Def[
      "foo",
      [Arg["x", restriction: Path["X"]], Arg["y", restriction: Path["Y"]]],
      Nop.new
    ]
    CODE
  expect_inspect %(foo : A | (B -> C)), <<-CODE
      TypeDeclaration[
        Var["foo"],
        Union[Path["A"], Union.parens(ProcNotation[Path["B"], Path["C"]])]
      ]
      CODE
  expect_inspect %(x : (A | B)), <<-CODE
      TypeDeclaration[Var["x"], Union.parens(Path["A"], Path["B"])]
      CODE
  expect_inspect %(foo : Int32 = 1), <<-CODE
      TypeDeclaration[Var["foo"], Path["Int32"], value: NumberLiteral["1", :i32]]
      CODE

  # Typed constant declarations (#13443)
  expect_inspect %(FOO : Int64 = 1), <<-CODE
      TypeDeclaration[Path["FOO"], Path["Int64"], value: NumberLiteral["1", :i32]]
      CODE
  expect_inspect %(::FOO : Int64 = 1), <<-CODE
      TypeDeclaration[
        Path.global("FOO"),
        Path["Int64"],
        value: NumberLiteral["1", :i32]
      ]
      CODE
  expect_inspect %(Foo::BAR : Int64 = 1), <<-CODE
      TypeDeclaration[
        Path["Foo", "BAR"],
        Path["Int64"],
        value: NumberLiteral["1", :i32]
      ]
      CODE
  expect_inspect %(::Foo::BAR : Int64 = 1), <<-CODE
      TypeDeclaration[
        Path.global("Foo", "BAR"),
        Path["Int64"],
        value: NumberLiteral["1", :i32]
      ]
      CODE
  expect_inspect %(FOO : String = "hey"), <<-CODE
      TypeDeclaration[Path["FOO"], Path["String"], value: StringLiteral["hey"]]
      CODE
  expect_inspect %(FOO : ::Int32 = -5), <<-CODE
      TypeDeclaration[
        Path["FOO"],
        Path.global("Int32"),
        value: NumberLiteral["-5", :i32]
      ]
      CODE
  expect_inspect %(PAIR : Tuple(Int32, String) = {1, "x"}), <<-CODE
      TypeDeclaration[
        Path["PAIR"],
        Generic[Path["Tuple"], [Path["Int32"], Path["String"]]],
        value: TupleLiteral[NumberLiteral["1", :i32], StringLiteral["x"]]
      ]
      CODE

  expect_inspect %(foo = uninitialized Int32), <<-CODE
      UninitializedVar[Var["foo"], Path["Int32"]]
      CODE
  expect_inspect %[%("\#{foo}")], <<-CODE
    StringInterpolation[StringLiteral["\\""], Call["foo"], StringLiteral["\\""]]
    CODE
  expect_inspect %Q{class Foo\n  private def bar\n  end\nend}, <<-CODE
      ClassDef[
        Path["Foo"],
        body: VisibilityModifier[Iyi::Visibility::Private, Def["bar", [], Nop.new]]
      ]
      CODE
  expect_inspect %q{abstract class Foo(T) < Bar; end}, <<-CODE
      ClassDef[
        Path["Foo"],
        superclass: Path["Bar"],
        type_vars: ["T"],
        abstract: true,
        body: Nop.new
      ]
      CODE
  expect_inspect %q{struct Foo; end}, %q{ClassDef[Path["Foo"], struct: true, body: Nop.new]}
  expect_inspect %q{module Foo(T); end}, %q{ModuleDef[Path["Foo"], type_vars: ["T"], body: Nop.new]}
  expect_inspect %q{annotation Foo; end}, %q(AnnotationDef[Path["Foo"]])
  expect_inspect %q{foo(&.==(2))}, <<-CODE
      Call[
        "foo",
        block: Block[
          Var["__arg0"],
          body: Call[Var["__arg0"], "==", [NumberLiteral["2", :i32]]]
        ]
      ]
      CODE
  expect_inspect %q{foo.nil?}, %(IsA[Call["foo"], Path.global("Nil"), nil_check: true])
  expect_inspect %q{foo._bar}, %(Call[Call["foo"], "_bar"])
  expect_inspect %q{foo._bar(1)}, %(Call[Call["foo"], "_bar", [NumberLiteral["1", :i32]]])
  expect_inspect %q{_foo.bar}, %(Call[Call["_foo"], "bar"])
  expect_inspect %q{1.responds_to?(:inspect)}, %(RespondsTo[NumberLiteral["1", :i32], "inspect"])
  expect_inspect %q{1.responds_to?(:"&&")}, %(RespondsTo[NumberLiteral["1", :i32], "&&"])
  expect_inspect %Q{macro foo(x, *y)\nend}, %(Macro["foo", [Arg["x"], Arg["y"]], Expressions[], splat_index: 1])

  expect_inspect %q{{ {1, 2, 3} }}, <<-CODE
    TupleLiteral[
      TupleLiteral[
        NumberLiteral["1", :i32],
        NumberLiteral["2", :i32],
        NumberLiteral["3", :i32]
      ]
    ]
    CODE
  expect_inspect %q{{ {1 => 2} }}, <<-CODE
    TupleLiteral[
      HashLiteral[
        HashLiteral::Entry[NumberLiteral["1", :i32], NumberLiteral["2", :i32]]
      ]
    ]
    CODE
  expect_inspect %q{{ {1, 2, 3} => 4 }}, <<-CODE
    HashLiteral[
      HashLiteral::Entry[
        TupleLiteral[
          NumberLiteral["1", :i32],
          NumberLiteral["2", :i32],
          NumberLiteral["3", :i32]
        ],
        NumberLiteral["4", :i32]
      ]
    ]
    CODE
  expect_inspect %q{{ {foo: 2} }}, %(TupleLiteral[NamedTupleLiteral["foo": NumberLiteral["2", :i32]]])
  expect_inspect %Q{def foo(*args)\nend}, %(Def["foo", [Arg["args"]], Nop.new, splat_index: 0])
  expect_inspect %Q{def foo(*args : _)\nend}, %(Def["foo", [Arg["args", restriction: Underscore.new]], Nop.new, splat_index: 0])
  expect_inspect %Q{def foo(**args)\nend}, %(Def["foo", [], Nop.new, double_splat: Arg["args"]])
  expect_inspect %Q{def foo(**args : T)\nend}, %(Def["foo", [], Nop.new, double_splat: Arg["args", restriction: Path["T"]]])
  expect_inspect %Q{def foo(x, **args)\nend}, %(Def["foo", [Arg["x"]], Nop.new, double_splat: Arg["args"]])
  expect_inspect %Q{def foo(x, **args, &block)\nend}, <<-CODE
    Def[
      "foo",
      [Arg["x"]],
      Nop.new,
      block_arg: Arg["block"],
      block_arity: 0,
      double_splat: Arg["args"]
    ]
    CODE
  expect_inspect %Q{def foo(x, **args, &block : (_ -> _))\nend}, <<-CODE
    Def[
      "foo",
      [Arg["x"]],
      Nop.new,
      block_arg: Arg[
        "block",
        restriction: Union.parens(ProcNotation[Underscore.new, Underscore.new])
      ],
      block_arity: 1,
      double_splat: Arg["args"]
    ]
    CODE
  expect_inspect %Q{def foo(& : (->))\nend}, <<-CODE
    Def[
      "foo",
      [],
      Nop.new,
      block_arg: Arg["", restriction: Union.parens(ProcNotation[])],
      block_arity: 0
    ]
    CODE
  expect_inspect %Q{macro foo(**args)\nend}, %(Macro["foo", [], Expressions[], double_splat: Arg["args"]])
  expect_inspect %Q{macro foo(x, **args)\nend}, %(Macro["foo", [Arg["x"]], Expressions[], double_splat: Arg["args"]])
  expect_inspect %Q{def foo(x y)\nend}, %(Def["foo", [Arg["y", external_name: "x"]], Nop.new])
  expect_inspect %(foo("bar baz": 2)), %(Call["foo", named_args: [NamedArgument["bar baz", NumberLiteral["2", :i32]]]])
  expect_inspect %(Foo("bar baz": Int32)), %(Generic[Path["Foo"], [], named_args: [NamedArgument["bar baz", Path["Int32"]]]])
  expect_inspect %({"foo bar": 1}), %(NamedTupleLiteral["foo bar": NumberLiteral["1", :i32]])
  expect_inspect %(def foo("bar baz" qux)\nend), %(Def["foo", [Arg["qux", external_name: "bar baz"]], Nop.new])
  expect_inspect %q{foo()}, %(Call["foo"])
  expect_inspect %q{/a/x}, %(RegexLiteral[StringLiteral["a"], options: Iyi::RegexOptions::EXTENDED])
  expect_inspect %q{1_f32}, %(NumberLiteral["1", :f32])
  expect_inspect %q{1_f64}, %(NumberLiteral["1", :f64])
  expect_inspect %q{1.0}, %(NumberLiteral["1.0", :f64])
  expect_inspect %q{1e10_f64}, %(NumberLiteral["1e10", :f64])
  expect_inspect %q{!a}, %(Not[Call["a"]])
  expect_inspect %q{!(1 < 2)}, <<-CODE
    Not[
      Expressions.paren(
        Call[NumberLiteral["1", :i32], "<", [NumberLiteral["2", :i32]]]
      )
    ]
    CODE
  expect_inspect %q{(1 + 2)..3}, <<-CODE
    RangeLiteral[
      Expressions.paren(
        Call[NumberLiteral["1", :i32], "+", [NumberLiteral["2", :i32]]]
      ),
      NumberLiteral["3", :i32]
    ]
    CODE
  expect_inspect %Q{macro foo\n{{ @type }}\nend}, <<-CODE
    Macro[
      "foo",
      [],
      Expressions[MacroExpression[InstanceVar["@type"]], MacroLiteral["\\n"]]
    ]
    CODE
  expect_inspect %Q{macro foo\n\\{{ @type }}\nend}, %(Macro["foo", [], Expressions[MacroLiteral["{"], MacroLiteral["{ @type }}\\n"]]])
  expect_inspect %Q{macro foo\n{% @type %}\nend}, <<-CODE
    Macro[
      "foo",
      [],
      Expressions[
        MacroExpression[InstanceVar["@type"], output: false],
        MacroLiteral["\\n"]
      ]
    ]
    CODE
  expect_inspect %Q{macro foo\n{{ @type }}\nend}, <<-CODE
    Macro[
      "foo",
      [],
      Expressions[MacroExpression[InstanceVar["@type"]], MacroLiteral["\\n"]]
    ]
    CODE
  expect_inspect %Q{macro foo\n\\{{ @type }}\nend}, %(Macro["foo", [], Expressions[MacroLiteral["{"], MacroLiteral["{ @type }}\\n"]]])
  expect_inspect %Q{macro foo\n{% @type %}\nend}, <<-CODE
    Macro[
      "foo",
      [],
      Expressions[
        MacroExpression[InstanceVar["@type"], output: false],
        MacroLiteral["\\n"]
      ]
    ]
    CODE
  expect_inspect %Q{macro foo\n\\{%@type %}\nend}, %(Macro["foo", [], Expressions[MacroLiteral["{%"], MacroLiteral["@type %}\\n"]]])
  expect_inspect %Q{enum A : B\nend}, %(EnumDef[Path["A"], base_type: Path["B"]])
  expect_inspect %Q{# doc\ndef foo\nend}, %(Def["foo", [], Nop.new])
  expect_inspect %q{foo[x, y, a: 1, b: 2]}, <<-CODE
    Call[
      Call["foo"],
      "[]",
      [Call["x"], Call["y"]],
      named_args: [NamedArgument["a", NumberLiteral["1", :i32]],
       NamedArgument["b", NumberLiteral["2", :i32]]]
    ]
    CODE
  expect_inspect %q{foo[x, y, a: 1, b: 2] = z}, <<-CODE
    Call[
      Call["foo"],
      "[]=",
      [Call["x"], Call["y"], Call["z"]],
      named_args: [NamedArgument["a", NumberLiteral["1", :i32]],
       NamedArgument["b", NumberLiteral["2", :i32]]]
    ]
    CODE
  expect_inspect %(@[Foo(1, 2, a: 1, b: 2)]), <<-CODE
    Annotation[
      Path["Foo"],
      named_args: [NamedArgument["a", NumberLiteral["1", :i32]],
       NamedArgument["b", NumberLiteral["2", :i32]]]
    ]
    CODE
  expect_inspect %(lib Foo\nend), %(LibDef[Path["Foo"], Nop.new])
  expect_inspect %(fun foo(a : Void, b : Void, ...) : Void\n\nend), <<-CODE
    FunDef[
      "foo",
      Arg["a", restriction: Path["Void"]], Arg["b", restriction: Path["Void"]],
      return_type: Path["Void"],
      varargs: true,
      real_name: "foo",
      body: Nop.new
    ]
    CODE
  expect_inspect %(lib Foo\n  struct Foo\n    a : Void\n    b : Void\n  end\nend), <<-CODE
    LibDef[
      Path["Foo"],
      CStructOrUnionDef[
        "Foo",
        Expressions[
          TypeDeclaration[Var["a"], Path["Void"]],
          TypeDeclaration[Var["b"], Path["Void"]]
        ]
      ]
    ]
    CODE
  expect_inspect %(lib Foo\n  union Foo\n    a : Int\n    b : Int32\n  end\nend), <<-CODE
    LibDef[
      Path["Foo"],
      CStructOrUnionDef[
        "Foo",
        Expressions[
          TypeDeclaration[Var["a"], Path["Int"]],
          TypeDeclaration[Var["b"], Path["Int32"]]
        ],
        union: true
      ]
    ]
    CODE
  expect_inspect %(lib Foo\n  FOO = 0\nend), %(LibDef[Path["Foo"], Assign[Path["FOO"], NumberLiteral["0", :i32]]])
  expect_inspect %(lib LibC\n  fun getch = "get.char"\nend), %(LibDef[Path["LibC"], FunDef["getch", real_name: "get.char"]])
  expect_inspect %(enum Foo\n  A = 0\n  B\nend), <<-CODE
    EnumDef[
      Path["Foo"],
      Arg["A", default_value: NumberLiteral["0", :i32]], Arg["B"]
    ]
    CODE
  expect_inspect %(alias Foo = Void), %(Alias[Path["Foo"], Path["Void"]])
  expect_inspect %(alias Foo::Bar = Void), %(Alias[Path["Foo", "Bar"], Path["Void"]])
  expect_inspect %(type(Foo = Void)), %(Call["type", [Assign[Path["Foo"], Path["Void"]]]])
  expect_inspect %(return true ? 1 : 2), <<-CODE
    Return[
      If[
        BoolLiteral[true],
        NumberLiteral["1", :i32],
        NumberLiteral["2", :i32],
        ternary: true
      ]
    ]
    CODE
  expect_inspect %(1 <= 2 <= 3), <<-CODE
    Call[
      Call[NumberLiteral["1", :i32], "<=", [NumberLiteral["2", :i32]]],
      "<=",
      [NumberLiteral["3", :i32]]
    ]
    CODE
  expect_inspect %((1 <= 2) <= 3), <<-CODE
    Call[
      Expressions.paren(
        Call[NumberLiteral["1", :i32], "<=", [NumberLiteral["2", :i32]]]
      ),
      "<=",
      [NumberLiteral["3", :i32]]
    ]
    CODE
  expect_inspect %(1 <= (2 <= 3)), <<-CODE
    Call[
      NumberLiteral["1", :i32],
      "<=",
      [Expressions.paren(
         Call[NumberLiteral["2", :i32], "<=", [NumberLiteral["3", :i32]]]
       )]
    ]
    CODE
  expect_inspect %(case 1; when .foo?; 2; end), <<-CODE
    Case[
      When[Call[ImplicitObj.new, "foo?"], NumberLiteral["2", :i32]],
      cond: NumberLiteral["1", :i32]
    ]
    CODE
  expect_inspect %(select; when foo.bar; 2; end), <<-CODE
    Select[When[Call[Call["foo"], "bar"], NumberLiteral["2", :i32]]]
    CODE
  expect_inspect %(select; when foo.bar; 2; else 3; end), <<-CODE
    Select[
      When[Call[Call["foo"], "bar"], NumberLiteral["2", :i32]],
      else: NumberLiteral["3", :i32]
    ]
    CODE
  expect_inspect %(case 1; in .foo?; 2; end), <<-CODE
    Case[
      When[
        Call[ImplicitObj.new, "foo?"],
        NumberLiteral["2", :i32],
        exhaustive: true
      ],
      cond: NumberLiteral["1", :i32],
      exhaustive: true
    ]
    CODE
  expect_inspect %(case 1; when .!; 2; when .< 0; 3; end), <<-CODE
    Case[
      When[Not[ImplicitObj.new], NumberLiteral["2", :i32]],
      When[
        Call[ImplicitObj.new, "<", [NumberLiteral["0", :i32]]],
        NumberLiteral["3", :i32]
      ],
      cond: NumberLiteral["1", :i32]
    ]
    CODE
  expect_inspect %(case 1\nwhen .[](2)\n  3\nwhen .[]=(4)\n  5\nend), <<-CODE
    Case[
      When[
        Call[ImplicitObj.new, "[]", [NumberLiteral["2", :i32]]],
        NumberLiteral["3", :i32]
      ],
      When[
        Call[ImplicitObj.new, "[]=", [NumberLiteral["4", :i32]]],
        NumberLiteral["5", :i32]
      ],
      cond: NumberLiteral["1", :i32]
    ]
    CODE
  expect_inspect %({(1 + 2)}), <<-CODE
    TupleLiteral[
      Expressions.paren(
        Call[NumberLiteral["1", :i32], "+", [NumberLiteral["2", :i32]]]
      )
    ]
    CODE
  expect_inspect %({foo: (1 + 2)}), <<-CODE
    NamedTupleLiteral[
      "foo": Expressions.paren(
        Call[NumberLiteral["1", :i32], "+", [NumberLiteral["2", :i32]]]
      )
    ]
    CODE
  expect_inspect %q("#{(1 + 2)}"), <<-CODE
    StringInterpolation[
      Expressions.paren(
        Call[NumberLiteral["1", :i32], "+", [NumberLiteral["2", :i32]]]
      )
    ]
    CODE
  expect_inspect %({(1 + 2) => (3 + 4)}), <<-CODE
    HashLiteral[
      HashLiteral::Entry[
        Expressions.paren(
          Call[NumberLiteral["1", :i32], "+", [NumberLiteral["2", :i32]]]
        ),
        Expressions.paren(
          Call[NumberLiteral["3", :i32], "+", [NumberLiteral["4", :i32]]]
        )
      ]
    ]
    CODE
  expect_inspect %([(1 + 2)] of Int32), <<-CODE
    ArrayLiteral[
      Expressions.paren(
        Call[NumberLiteral["1", :i32], "+", [NumberLiteral["2", :i32]]]
      ),
      of: Path["Int32"]
    ]
    CODE
  expect_inspect %(foo(1, (2 + 3), bar: (4 + 5))), <<-CODE
    Call[
      "foo",
      [NumberLiteral["1", :i32],
       Expressions.paren(
         Call[NumberLiteral["2", :i32], "+", [NumberLiteral["3", :i32]]]
       )],
      named_args: [NamedArgument[
         "bar",
         Expressions.paren(
           Call[NumberLiteral["4", :i32], "+", [NumberLiteral["5", :i32]]]
         )
       ]]
    ]
    CODE
  expect_inspect %(if (1 + 2\n3)\n  4\nend), <<-CODE
    If[
      Expressions.paren(
        Call[NumberLiteral["1", :i32], "+", [NumberLiteral["2", :i32]]],
        NumberLiteral["3", :i32]
      ),
      NumberLiteral["4", :i32],
      Nop.new
    ]
    CODE
  expect_inspect %q(while foo; bar; end), %(While[Call["foo"], body: Call["bar"]])
  expect_inspect %q(until foo; bar; end), %(Until[Call["foo"], body: Call["bar"]])
  expect_inspect %q{%x(whoami)}, %(Call["`", [StringLiteral["whoami"]]])
  expect_inspect %(begin\n  ()\nend), %(Expressions.begin(Expressions.paren(Nop.new)))
  expect_inspect %q("\e\0\""), %q(StringLiteral["\e\u0000\""])
  expect_inspect %q("#{1}\0"), <<-CODE
    StringInterpolation[NumberLiteral["1", :i32], StringLiteral["\\u0000"]]
    CODE
  expect_inspect %q(%r{\/\0}), %(RegexLiteral[StringLiteral["/\\\\0"]])
  expect_inspect %q(%r{#{1}\/\0}), <<-CODE
    RegexLiteral[
      StringInterpolation[
        NumberLiteral["1", :i32], StringLiteral["/"], StringLiteral["\\\\0"]
      ]
    ]
    CODE
  expect_inspect %q(`\n\0`), %(Call["`", [StringLiteral["\\n" + "\\u0000"]]])
  expect_inspect %q(`#{1}\n\0`), <<-CODE
    Call[
      "`",
      [StringInterpolation[
         NumberLiteral["1", :i32], StringLiteral["\\n"], StringLiteral["\\u0000"]
       ]]
    ]
    CODE
  expect_inspect %Q{macro foo\n{% verbatim do %}1{% end %}\nend}, <<-CODE
    Macro[
      "foo",
      [],
      Expressions[MacroVerbatim[MacroLiteral["1"]], MacroLiteral["\\n"]]
    ]
    CODE
  expect_inspect %q{foo.*}, %(Call[Call["foo"], "*"])
  expect_inspect %q{foo.%}, %(Call[Call["foo"], "%"])
  expect_inspect %q{&+1}, %(Call[NumberLiteral["1", :i32], "&+"])
  expect_inspect %q{&-1}, %(Call[NumberLiteral["1", :i32], "&-"])
  expect_inspect %q{1.&*}, %(Call[NumberLiteral["1", :i32], "&*"])
  expect_inspect %q{1.&**}, %(Call[NumberLiteral["1", :i32], "&**"])
  expect_inspect %q{1.~(2)}, %(Call[NumberLiteral["1", :i32], "~", [NumberLiteral["2", :i32]]])
  expect_inspect %Q{1.~(2) do\nend}, <<-CODE
    Call[
      NumberLiteral["1", :i32],
      "~",
      [NumberLiteral["2", :i32]],
      block: Block[body: Nop.new]
    ]
    CODE
  expect_inspect %Q{1.+ do\nend}, %(Call[NumberLiteral["1", :i32], "+", block: Block[body: Nop.new]])
  expect_inspect %Q{1.[](2) do\nend}, <<-CODE
    Call[
      NumberLiteral["1", :i32],
      "[]",
      [NumberLiteral["2", :i32]],
      block: Block[body: Nop.new]
    ]
    CODE
  expect_inspect %q{1.[]=}, %(Call[NumberLiteral["1", :i32], "[]="])
  expect_inspect %q{1.+(a: 2)}, <<-CODE
    Call[
      NumberLiteral["1", :i32],
      "+",
      named_args: [NamedArgument["a", NumberLiteral["2", :i32]]]
    ]
    CODE
  expect_inspect %q{1.+(&block)}, %(Call[NumberLiteral["1", :i32], "+", block_arg: Call["block"]])
  expect_inspect %q{1.//(2, a: 3)}, <<-CODE
    Call[
      NumberLiteral["1", :i32],
      "//",
      [NumberLiteral["2", :i32]],
      named_args: [NamedArgument["a", NumberLiteral["3", :i32]]]
    ]
    CODE
  expect_inspect %q{1.//(2, &block)}, <<-CODE
    Call[
      NumberLiteral["1", :i32],
      "//",
      [NumberLiteral["2", :i32]],
      block_arg: Call["block"]
    ]
    CODE
  expect_inspect %({% verbatim do %}\n  1{{ 2 }}\n  3{{ 4 }}\n{% end %}), <<-CODE
    MacroVerbatim[
      Expressions[
        MacroLiteral["\\n" + "  1"],
        MacroExpression[NumberLiteral["2", :i32]],
        MacroLiteral["\\n" + "  3"],
        MacroExpression[NumberLiteral["4", :i32]],
        MacroLiteral["\\n"]
      ]
    ]
    CODE
  expect_inspect %({% for foo in bar %}\n  {{ if true\n  foo\n  bar\nend }}\n{% end %}), <<-CODE
    MacroFor[
      [Var["foo"]],
      Var["bar"],
      Expressions[
        MacroLiteral["\\n" + "  "],
        MacroExpression[
          If[BoolLiteral[true], Expressions[Var["foo"], Var["bar"]], Nop.new]
        ],
        MacroLiteral["\\n"]
      ]
    ]
    CODE
  expect_inspect %(asm("nop" ::::)), %(Asm["nop"])
  expect_inspect %(asm("nop" : "a"(1), "b"(2) : "c"(3), "d"(4) : "e", "f" : "volatile", "alignstack", "intel")), <<-CODE
    Asm[
      "nop",
      outputs: [AsmOperand["a", NumberLiteral["1", :i32]],
       AsmOperand["b", NumberLiteral["2", :i32]]],
      inputs: [AsmOperand["c", NumberLiteral["3", :i32]],
       AsmOperand["d", NumberLiteral["4", :i32]]],
      clobbers: ["e", "f"],
      volatile: true,
      alignstack: true,
      intel: true
    ]
    CODE
  expect_inspect %(asm("nop" :: "c"(3), "d"(4) ::)), <<-CODE
    Asm[
      "nop",
      inputs: [AsmOperand["c", NumberLiteral["3", :i32]],
       AsmOperand["d", NumberLiteral["4", :i32]]]
    ]
    CODE
  expect_inspect %(asm("nop" :::: "volatile")), %(Asm["nop", volatile: true])
  expect_inspect %(asm("nop" :: "a"(1) :: "volatile")), %(Asm["nop", inputs: [AsmOperand["a", NumberLiteral["1", :i32]]], volatile: true])
  expect_inspect %(asm("nop" ::: "e" : "volatile")), %(Asm["nop", clobbers: ["e"], volatile: true])
  expect_inspect %[(1..)], %(Expressions.paren(RangeLiteral[NumberLiteral["1", :i32], Nop.new]))
  expect_inspect %[..3], %(RangeLiteral[Nop.new, NumberLiteral["3", :i32]])
  expect_inspect %q{offsetof(Foo, @bar)}, %(OffsetOf[Path["Foo"], InstanceVar["@bar"]])
  expect_inspect %Q{def foo(**options, &block)\nend}, <<-CODE
    Def[
      "foo",
      [],
      Nop.new,
      block_arg: Arg["block"],
      block_arity: 0,
      double_splat: Arg["options"]
    ]
    CODE
  expect_inspect %Q{macro foo\n  123\nend}, %(Macro["foo", [], MacroLiteral["  123\\n"]])
  expect_inspect %Q{if true\n(  1)\nend}, %(If[BoolLiteral[true], Expressions.paren(NumberLiteral["1", :i32]), Nop.new])
  expect_inspect %Q{unless true\n(  1)\nend}, %(Unless[BoolLiteral[true], Expressions.paren(NumberLiteral["1", :i32]), Nop.new])
  expect_inspect %Q{begin\n(  1)\nrescue\nend}, <<-CODE
    ExceptionHandler[
      rescues: [Rescue[]],
      body: Expressions.paren(NumberLiteral["1", :i32])
    ]
    CODE
  expect_inspect %q{begin; rescue exc; end}, <<-CODE
    ExceptionHandler[rescues: [Rescue[name: "exc"]]]
    CODE
  expect_inspect %q{begin; rescue exc : Foo; end}, <<-CODE
    ExceptionHandler[rescues: [Rescue[types: [Path["Foo"]], name: "exc"]]]
    CODE
  expect_inspect %q{begin; rescue Foo | Bar; end}, <<-CODE
    ExceptionHandler[rescues: [Rescue[types: [Path["Foo"], Path["Bar"]]]]]
    CODE
  expect_inspect %q{begin; 2; ensure; 1; end}, <<-CODE
    ExceptionHandler[
      ensure: NumberLiteral["1", :i32],
      body: NumberLiteral["2", :i32]
    ]
    CODE
  expect_inspect %[他.说("你好")], %(Call[Call["他"], "说", [StringLiteral["你好"]]])
  expect_inspect %[他.说 = "你好"], %(Call[Call["他"], "说=", [StringLiteral["你好"]]])
  expect_inspect %[あ.い, う.え.お = 1, 2], <<-CODE
    MultiAssign[
      [Call[Call["あ"], "い"], Call[Call[Call["う"], "え"], "お"]],
      [NumberLiteral["1", :i32], NumberLiteral["2", :i32]]
    ]
    CODE
  expect_inspect %q(Foo(Bar)), %(Generic[Path["Foo"], [Path["Bar"]]])
  expect_inspect %q(Foo?), <<-CODE
    Generic.question(Path.global("Union"), [Path["Foo"], Path.global("Nil")])
    CODE
  expect_inspect %q(Foo(Bar*)), %q(Generic[Path["Foo"], [Generic.asterisk(Path.global("Pointer"), [Path["Bar"]])]])
  expect_inspect %q(Foo(Bar[12])), <<-CODE
    Generic[
      Path["Foo"],
      [Generic.bracket(
         Path.global("StaticArray"),
         [Path["Bar"], NumberLiteral["12", :i32]]
       )]
    ]
    CODE
  expect_inspect %q(nil), %(NilLiteral.new)
  expect_inspect %q('c'), %(CharLiteral['c'])
  expect_inspect %q(Set(String){"foo", "bar"}), <<-CODE
    ArrayLiteral[
      StringLiteral["foo"], StringLiteral["bar"],
      name: Generic[Path["Set"], [Path["String"]]]
    ]
    CODE
  expect_inspect %q(1...2), <<-CODE
    RangeLiteral[
      NumberLiteral["1", :i32],
      NumberLiteral["2", :i32],
      exclusive: true
    ]
    CODE
  expect_inspect %q(/foo/ix), <<-CODE
    RegexLiteral[
      StringLiteral["foo"],
      options: Iyi::RegexOptions[IGNORE_CASE, EXTENDED]
    ]
    CODE
  expect_inspect %q(foo = 1; foo += 2), <<-CODE
    Expressions[
      Assign[Var["foo"], NumberLiteral["1", :i32]],
      OpAssign[Var["foo"], "+", NumberLiteral["2", :i32]]
    ]
    CODE
  expect_inspect %q(foo.@bar), %(ReadInstanceVar[Call["foo"], "@bar"])
  expect_inspect %q(@@bar), %(ClassVar["@@bar"])
  expect_inspect %q($?), %(Global["$?"])
  expect_inspect %q(def Foo.bar; end), <<-CODE
    Def["bar", [], Nop.new, receiver: Path["Foo"]]
    CODE
  expect_inspect %q(abstract def foo : _), %q(Def["foo", [], Nop.new, return_type: Underscore.new, abstract: true])
  expect_inspect %q(pointerof(foo)), %(PointerOf[Call["foo"]])
  expect_inspect %q(sizeof(Int32)), %(SizeOf[Path["Int32"]])
  expect_inspect %q(instance_sizeof(Int32)), %(InstanceSizeOf[Path["Int32"]])
  expect_inspect %q(alignof(Int32)), %(AlignOf[Path["Int32"]])
  expect_inspect %q(instance_alignof(Int32)), %(InstanceAlignOf[Path["Int32"]])
  expect_inspect %q(LibFoo.bar(out baz)), <<-CODE
    Call[Path["LibFoo"], "bar", [Out[Var["baz"]]]]
    CODE
  expect_inspect %q(private def foo; end), %(VisibilityModifier[Iyi::Visibility::Private, Def["foo", [], Nop.new]])
  expect_inspect %q(require "foo"), %(Require["foo"])
  expect_inspect %q(->(i : Int32) { i * 2 }), <<-CODE
    ProcLiteral[
      Def[
        "->",
        [Arg["i", restriction: Path["Int32"]]],
        Call[Var["i"], "*", [NumberLiteral["2", :i32]]]
      ]
    ]
    CODE
  expect_inspect %q(->add(Int32, Int32)), <<-CODE
    ProcPointer["add", [Path["Int32"], Path["Int32"]]]
    CODE
  expect_inspect %q(->Foo.add), <<-CODE
    ProcPointer[Path["Foo"], "add"]
    CODE
  expect_inspect %q(yield), %(Yield[])
  expect_inspect %q(with foo yield), %(Yield[scope: Call["foo"]])
  expect_inspect %q(yield 1), %(Yield[NumberLiteral["1", :i32]])
  expect_inspect %q(yield(1, 2)), <<-CODE
    Yield[
      NumberLiteral["1", :i32], NumberLiteral["2", :i32],
      has_parentheses: true
    ]
    CODE
  expect_inspect %q(include Foo), %(Include[Path["Foo"]])
  expect_inspect %q(extend Foo), %(Extend[Path["Foo"]])
  expect_inspect %q(lib Foo; type Bar = Baz; end), <<-CODE
    LibDef[Path["Foo"], TypeDef["Bar", Path["Baz"]]]
    CODE
  expect_inspect %q(typeof(1)), %q(TypeOf[NumberLiteral["1", :i32]])
  expect_inspect %q(foo(*x)), %q(Call["foo", [Splat[Call["x"]]]])
  expect_inspect %q(foo(**x)), %q(Call["foo", [DoubleSplat[Call["x"]]]])
end
