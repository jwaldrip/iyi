require "../support/syntax"

# The bound parameter writer's bytes and its builder record, read back from parsed source.
# The byte cases are the parameter texts 1052cd561 pins. The builder cases pin what a fragment
# records: names and annotation paths as anchors, a bare star as one StructuredSyntax event,
# and a string-literal external name with no event. Ordinary printing is held alongside, so the
# writer cannot change it.

private def bound_plain_def(source : String) : Iyi::Def
  Iyi::Parser.new(source).parse.as(Iyi::Def)
end

private def bound_capture_def(source : String) : Iyi::Def
  parser = Iyi::Parser.new(source)
  parser.diagnostic_source_file = "/spec/bound_parameter_writer.cr"
  parser.enable_diagnostic_observations
  parser.diagnostic_capture = true
  parser.parse.as(Iyi::Def)
end

private def bound_text(node : Iyi::Arg, prefix : String) : String
  Iyi::ToSVisitor.bound_parameter_name(node, prefix)
end

# The bound text written through a builder, with the builder that recorded it.
private def bound_recorded(node : Iyi::Arg, prefix : String) : {String, Iyi::DiagnosticFragmentBuilder}
  io = IO::Memory.new
  builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
  Iyi::ToSVisitor.write_bound_parameter_name(io, node, prefix, builder)
  {io.to_s, builder}
end

private def bound_roles(builder : Iyi::DiagnosticFragmentBuilder) : Array(String)
  (0...builder.anchor_count).map { |index| builder.anchor_at(index).role }
end

private def bound_event_texts(builder : Iyi::DiagnosticFragmentBuilder) : Array(String)
  (0...builder.event_count).map { |index| builder.event_at(index).selected_text }
end

describe "ToSVisitor.bound_parameter_name" do
  it "writes an identifier external name as the source spelled it, under the splat prefix" do
    bound_text(Iyi::Arg.new("xs", external_name: "ext"), "*").should eq "*ext xs"
  end

  it "writes an annotated splat and an annotated block with their annotations first" do
    splat = bound_plain_def("def f(@[Foo] *xs)\nend").args.first
    Iyi::ToSVisitor.bound_annotation_prefix(splat).should eq "@[Foo] "
    bound_text(splat, "*").should eq "@[Foo] *xs"

    block = bound_plain_def("def f(@[Foo] &b)\nend").block_arg.not_nil!
    bound_text(block, "&").should eq "@[Foo] &b"
  end

  it "keeps an external name's spelling, where the printer would quote it" do
    bound_text(Iyi::Arg.new("x", external_name: "_"), "").should eq "_ x"
    bound_text(Iyi::Arg.new("x", external_name: "é"), "").should eq "é x"
    Iyi::ToSVisitor.parameter_text(Iyi::Arg.new("x", external_name: "_"), "").should eq %("_" x)
  end

  it "writes a bare star as the star alone and prefixes named splats" do
    bound_text(Iyi::Arg.new(""), "*").should eq "*"
    bound_text(Iyi::Arg.new("xs"), "*").should eq "*xs"
    bound_text(Iyi::Arg.new("opts"), "**").should eq "**opts"
    bound_text(Iyi::Arg.new("x"), "").should eq "x"
    bound_text(Iyi::Arg.new("b"), "&").should eq "&b"
  end

  it "writes an anonymous block as its ampersand alone" do
    block = bound_plain_def("def f(&)\nend").block_arg.not_nil!
    bound_text(block, "&").should eq "&"
  end

  it "refuses a prefix the bound parameter path never writes" do
    expect_raises(ArgumentError, /invalid bound parameter prefix/) do
      bound_text(Iyi::Arg.new("b"), "@")
    end
  end

  it "writes an annotated external name with a builder exactly as without one" do
    node = bound_capture_def("def f(@[Foo] from xs)\nend").args.first
    text, _builder = bound_recorded(node, "")
    text.should eq "@[Foo] from xs"
    text.should eq bound_text(node, "")
  end
end

describe "ToSVisitor.write_bound_parameter_name with a fragment builder" do
  it "records the external name and the name as anchors, in written order" do
    node = bound_capture_def("def f(from xs)\nend").args.first
    text, builder = bound_recorded(node, "")
    text.should eq "from xs"
    bound_event_texts(builder).should eq ["from", "xs"]
    bound_roles(builder).should eq ["named_entry", "parameter"]
  end

  it "records a bare star as one StructuredSyntax event and no anchor" do
    node = bound_capture_def("def hold(*, y)\nend").args.first
    text, builder = bound_recorded(node, "*")
    text.should eq "*"
    bound_event_texts(builder).should eq ["*"]
    builder.anchor_count.should eq 0
  end

  it "records an annotation's path as an anchor, through the printer" do
    node = bound_capture_def("def f(@[Foo] xs)\nend").args.first
    text, builder = bound_recorded(node, "")
    text.should eq "@[Foo] xs"
    bound_event_texts(builder).should eq ["Foo", "xs"]
    bound_roles(builder).should eq ["path_segment", "parameter"]
  end

  it "writes a string-literal external name as plain bytes with no event" do
    node = bound_capture_def(%(def f("ext" xs)\nend)).args.first
    text, builder = bound_recorded(node, "")
    text.should eq "ext xs"
    bound_event_texts(builder).should eq ["xs"]
    bound_roles(builder).should eq ["parameter"]
  end

  it "writes an anonymous block without a name anchor" do
    node = bound_capture_def("def f(&)\nend").block_arg.not_nil!
    text, builder = bound_recorded(node, "&")
    text.should eq "&"
    builder.anchor_count.should eq 0
  end
end
