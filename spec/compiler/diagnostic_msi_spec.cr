require "../support/syntax"
require "../../src/compiler/iyi/syntax/diagnostic_msi"

alias Msi = Iyi::DiagnosticMsi

def msi_schema : Hash(String, Array(String))
  {
    "Leaf"    => ["value"],
    "Pair"    => ["left", "right"],
    "Chain"   => ["next"],
    "Bag"     => ["items"],
    "Table"   => ["names"],
    "Index"   => ["children"],
    "Scalars" => ["flag", "number", "text", "nothing"],
  }
end

def msi_envelope : JSON::Any
  Msi.obj({"tool" => Msi.str("spec")})
end

def msi_write(root : Msi::Node, input : Bytes = Bytes.empty) : Msi::Bundle
  Msi::Writer.new(msi_schema).write(root, input, "Probe", msi_envelope, "a" * 64)
end

def msi_verify(bundle : Msi::Bundle) : Msi::Verified
  Msi.verify(bundle.root, bundle.shards, msi_schema)
end

def msi_leaf(text : String) : Msi::Node
  Msi::Node.new("Leaf", [Msi::Field.new("value", Msi::Value.octets(text.to_slice))])
end

def msi_pair(left : Msi::Node, right : Msi::Node) : Msi::Node
  Msi::Node.new("Pair", [
    Msi::Field.new("left", Msi::Value.child(left)),
    Msi::Field.new("right", Msi::Value.child(right)),
  ])
end

def msi_chain(length : Int32) : Msi::Node
  node = Msi::Node.new("Chain", [Msi::Field.new("next", Msi::Value.absent)])
  (length - 1).times do
    node = Msi::Node.new("Chain", [Msi::Field.new("next", Msi::Value.child(node))])
  end
  node
end

def msi_ref?(value : JSON::Any) : Bool
  items = value.as_a?
  return false unless items && items.size == 3
  tag = items[0].as_s?
  digest = items[1].as_s?
  return false unless tag && digest && items[2].as_i64?
  %w(N A L K B).includes?(tag) && digest.size == 64
end

# Rewrites every reference digest from the digest of its target ordinal.
def msi_rewrite(value : JSON::Any, digests : Array(String)) : Nil
  if msi_ref?(value)
    items = value.as_a
    ordinal = items[2].as_i64.to_i
    items[1] = JSON::Any.new(digests[ordinal]? || ("0" * 64))
  elsif (array = value.as_a?)
    array.each { |item| msi_rewrite(item, digests) }
  elsif (hash = value.as_h?)
    hash.each_value { |item| msi_rewrite(item, digests) }
  end
end

# Test-only forger for single-shard bundles. Yields the record array, then
# recomputes every digest, the shard, the shard table and the root, so the
# result is internally consistent and only the verifier's own checks can refuse it.
def msi_reseal(bundle : Msi::Bundle, &) : Msi::Bundle
  root = JSON.parse(String.new(bundle.root)).as_h
  shard_digest = root["shards"].as_a[0].as_a[2].as_s
  shard = JSON.parse(String.new(bundle.shards[shard_digest])).as_h
  records = shard["r"].as_a
  yield records
  digests = [] of String
  records.each do |record|
    msi_rewrite(record, digests)
    digests << Msi.digest("iyi.msi.v1.record\0#{record.as_h["t"].as_s}\0", Msi.canonical(record).to_slice)
  end
  shard_text = "{\"f\":0,\"n\":#{records.size},\"r\":[#{records.map { |record| Msi.canonical(record) }.join(",")}]}"
  new_shard_digest = Msi.digest("iyi.msi.v1.shard\0", shard_text.to_slice)
  root["shards"] = Msi.arr([Msi.arr([
    Msi.int(0_i64),
    Msi.int(records.size.to_i64),
    Msi.str(new_shard_digest),
    Msi.int(shard_text.bytesize.to_i64),
  ])])
  root_any = JSON::Any.new(root)
  msi_rewrite(root_any, digests)
  root_text = Msi.canonical(root_any)
  Msi::Bundle.new(root_text.to_slice, Msi.digest("iyi.msi.v1.root\0", root_text.to_slice), {new_shard_digest => shard_text.to_slice})
end

describe Iyi::DiagnosticMsi do
  it "round-trips a shared subgraph, counting the shared node once" do
    shared = msi_leaf("alpha")
    bundle = msi_write(msi_pair(shared, shared), "abc".to_slice)
    verified = msi_verify(bundle)
    verified.input.should eq("abc".to_slice)
    # input: chunk, list, blob root = 3; leaf = 1; pair = 1
    verified.record_count.should eq(5_i64)
    verified.node_count.should eq(2_i64)
  end

  it "is deterministic for identical input" do
    a = msi_write(msi_pair(msi_leaf("a"), msi_leaf("b")), "x".to_slice)
    b = msi_write(msi_pair(msi_leaf("a"), msi_leaf("b")), "x".to_slice)
    a.root_digest.should eq(b.root_digest)
  end

  it "reproduces arbitrary bytes in the input and in values" do
    all = Bytes.new(256 * 40) { |i| (i % 256).to_u8 }
    values = Bytes.new(256) { |i| i.to_u8 }
    bundle = msi_write(Msi::Node.new("Leaf", [Msi::Field.new("value", Msi::Value.octets(values))]), all)
    msi_verify(bundle).input.should eq(all)
  end

  it "splits a large input into bounded shards and verifies all of them" do
    input = Bytes.new(3 * 1024 * 1024) { |i| ((i * 131) % 256).to_u8 }
    bundle = msi_write(msi_leaf("root"), input)
    bundle.shards.size.should be > 1
    bundle.shards.values.all? { |bytes| bytes.size <= 1_048_576 }.should eq(true)
    msi_verify(bundle).input.should eq(input)
  end

  it "pins the root digest to the exact tree" do
    full = msi_write(msi_pair(msi_leaf("a"), msi_leaf("b")))
    child_removed = msi_write(msi_leaf("a"))
    full.root_digest.should_not eq(child_removed.root_digest)
  end

  it "refuses a shard whose bytes were flipped" do
    bundle = msi_write(msi_leaf("root"), Bytes.new(200_000, 7_u8))
    key = bundle.shards.keys.first
    bytes = Bytes.new(bundle.shards[key].size)
    bytes.copy_from(bundle.shards[key])
    bytes[20] = bytes[20] ^ 1_u8
    bundle.shards[key] = bytes
    expect_raises(ArgumentError) { msi_verify(bundle) }
  end

  it "refuses a missing shard" do
    bundle = msi_write(msi_leaf("root"), Bytes.new(3 * 1024 * 1024, 9_u8))
    bundle.shards.delete(bundle.shards.keys.first)
    expect_raises(ArgumentError) { msi_verify(bundle) }
  end

  it "refuses an extra shard the table does not name" do
    bundle = msi_write(msi_leaf("root"))
    bundle.shards["b" * 64] = Bytes.new(2, 0_u8)
    expect_raises(ArgumentError) { msi_verify(bundle) }
  end

  it "refuses a root manifest that is valid JSON but not canonical" do
    bundle = msi_write(msi_leaf("root"))
    root_text = String.new(bundle.root).gsub(",", ", ")
    expect_raises(ArgumentError) do
      msi_verify(Msi::Bundle.new(root_text.to_slice, bundle.root_digest, bundle.shards))
    end
  end

  it "refuses a child removed from a list even when every digest is recomputed" do
    bundle = msi_write(Msi::Node.new("Bag", [Msi::Field.new("items", Msi::Value.children([msi_leaf("a"), msi_leaf("b"), msi_leaf("c")]))]))
    forged = msi_reseal(bundle) do |records|
      list = records.find { |record| record.as_h["t"].as_s == "L" && record.as_h["e"].as_a.size == 3 }.not_nil!.as_h
      list["e"].as_a.pop
      list["n"] = Msi.int(2_i64)
    end
    expect_raises(ArgumentError) { msi_verify(forged) }
  end

  it "refuses reordered owning children even when every digest is recomputed" do
    bundle = msi_write(Msi::Node.new("Bag", [Msi::Field.new("items", Msi::Value.children([msi_leaf("a"), msi_leaf("b"), msi_leaf("c")]))]))
    forged = msi_reseal(bundle) do |records|
      list = records.find { |record| record.as_h["t"].as_s == "L" && record.as_h["e"].as_a.size == 3 }.not_nil!.as_h
      list["e"].as_a.reverse!
    end
    expect_raises(ArgumentError) { msi_verify(forged) }
  end

  it "refuses a dropped child: a record left with no owner" do
    bundle = msi_write(msi_pair(msi_leaf("a"), msi_leaf("b")))
    forged = msi_reseal(bundle) do |records|
      pair = records.last.as_h
      entries = pair["f"].as_a
      left_ref = entries[0].as_a[2]
      entries[1].as_a[2] = Msi.arr([Msi.str("A"), Msi.str("0" * 64), left_ref.as_a[2]])
    end
    expect_raises(ArgumentError) { msi_verify(forged) }
  end

  it "refuses a duplicated owner" do
    bundle = msi_write(msi_pair(msi_leaf("a"), msi_leaf("b")))
    forged = msi_reseal(bundle) do |records|
      entries = records.last.as_h["f"].as_a
      entries[1].as_a[2] = entries[0].as_a[2]
    end
    expect_raises(ArgumentError) { msi_verify(forged) }
  end

  it "refuses a self alias" do
    bundle = msi_write(msi_pair(msi_leaf("a"), msi_leaf("b")))
    forged = msi_reseal(bundle) do |records|
      entries = records.last.as_h["f"].as_a
      entries[1].as_a[2] = Msi.arr([Msi.str("A"), Msi.str("0" * 64), Msi.int((records.size - 1).to_i64)])
    end
    expect_raises(ArgumentError) { msi_verify(forged) }
  end

  it "refuses a field dropped from a node" do
    bundle = msi_write(Msi::Node.new("Scalars", [
      Msi::Field.new("flag", Msi::Value.flag(true)),
      Msi::Field.new("number", Msi::Value.number(-42_i64)),
      Msi::Field.new("text", Msi::Value.identifier("Alpha")),
      Msi::Field.new("nothing", Msi::Value.absent),
    ]))
    forged = msi_reseal(bundle) { |records| records.last.as_h["f"].as_a.pop }
    expect_raises(ArgumentError) { msi_verify(forged) }
  end

  it "refuses keyed entries whose indices no longer match their positions" do
    index = Msi::Node.new("Index", [Msi::Field.new("children", Msi::Value.keyed([
      Msi::Entry.new("x".to_slice, nil, msi_leaf("a")),
      Msi::Entry.new("y".to_slice, nil, msi_leaf("b")),
    ]))])
    bundle = msi_write(index)
    forged = msi_reseal(bundle) do |records|
      entries = records.last.as_h["f"].as_a[0].as_a[2].as_a
      entries.reverse!
    end
    expect_raises(ArgumentError) { msi_verify(forged) }
  end

  it "refuses an inline value over the inline limit" do
    bundle = msi_write(msi_leaf("short"))
    forged = msi_reseal(bundle) do |records|
      leaf = records.find { |record| record.as_h["t"].as_s == "N" && record.as_h["k"].as_s == "Leaf" }.not_nil!
      leaf.as_h["f"].as_a[0].as_a[2] = Msi.str(Base64.strict_encode(Bytes.new(4097, 0_u8)))
    end
    expect_raises(ArgumentError) { msi_verify(forged) }
  end

  it "accepts a chain of exactly the depth limit and refuses one deeper" do
    msi_verify(msi_write(msi_chain(129))).node_count.should eq(129_i64)
    expect_raises(ArgumentError) { msi_write(msi_chain(130)) }
  end

  it "refuses a cycle" do
    fields = [] of Msi::Field
    looped = Msi::Node.new("Chain", fields)
    fields << Msi::Field.new("next", Msi::Value.child(looped))
    expect_raises(ArgumentError) { msi_write(looped) }
  end

  it "refuses an unknown kind and a field outside the schema" do
    expect_raises(ArgumentError) { msi_write(Msi::Node.new("Nope", [] of Msi::Field)) }
    expect_raises(ArgumentError) do
      msi_write(Msi::Node.new("Leaf", [
        Msi::Field.new("value", Msi::Value.octets("x".to_slice)),
        Msi::Field.new("extra", Msi::Value.absent),
      ]))
    end
  end

  it "refuses a record over the record limit" do
    entries = (0...60).map { |i| Msi::Entry.new(i.to_s.to_slice, Bytes.new(4000, 65_u8)) }
    expect_raises(ArgumentError) do
      msi_write(Msi::Node.new("Table", [Msi::Field.new("names", Msi::Value.named(entries))]))
    end
  end

  it "refuses evidence over the unfolded byte limit" do
    tables = (0...2100).map do
      Msi::Node.new("Table", [Msi::Field.new("names", Msi::Value.named([Msi::Entry.new("k".to_slice, Bytes.new(4000, 66_u8))]))])
    end
    expect_raises(ArgumentError) do
      msi_write(Msi::Node.new("Bag", [Msi::Field.new("items", Msi::Value.children(tables))]))
    end
  end
end
