# The restored chop algorithm, exercised for real.
#
# Why this is a .cr file: in iyi, String#byte_slice is private, callable only
# from the module that reopens String. std/text is that module and it cannot be
# built on upstream master yet (it imports std/slice, which needs enumerable and
# indexable, none merged). So the behaviour is demonstrated here through the
# compatibility compiler, on the same bytes, with the same two implementations.
# The bodies are copied verbatim from src/std/text.iyi.

def chop_restored(s : String) : String
  return "" if s.empty?
  if s.bytesize >= 2 && s.to_unsafe[s.bytesize - 2] == 13_u8 && s.to_unsafe[s.bytesize - 1] == 10_u8
    return s.byte_slice(0, s.bytesize - 2)
  end
  cut = s.bytesize - 1
  while cut > 0 && (s.to_unsafe[cut] & 0xC0_u8) == 0x80_u8
    cut = cut - 1
  end
  s.byte_slice(0, cut)
end

def chop_bytewise(s : String) : String
  return "" if s.empty?
  if s.bytesize >= 2 && s.to_unsafe[s.bytesize - 2] == 13_u8 && s.to_unsafe[s.bytesize - 1] == 10_u8
    return s.byte_slice(0, s.bytesize - 2)
  end
  s.byte_slice(0, s.bytesize - 1)
end

def show(label, got)
  puts "#{label} => #{got.inspect} bytes=#{got.bytesize} chars=#{got.size} valid=#{got.valid_encoding?}"
end

puts "== 1. ascii"
show("chop_restored(\"abc\") ", chop_restored("abc"))

puts "== 2. multi-byte: the case the rewind exists for"
show("chop_restored(\"hé\")  ", chop_restored("hé"))
show("chop_bytewise(\"hé\")  ", chop_bytewise("hé"))

puts "== 3. crlf"
show("chop_restored(\"ab\\r\\n\")", chop_restored("ab\r\n"))

puts "== 4. empty"
show("chop_restored(\"\")    ", chop_restored(""))

good = chop_restored("hé")
bad = chop_bytewise("hé")

ok = good == "h" &&
     good.valid_encoding? &&
     chop_restored("abc") == "ab" &&
     chop_restored("ab\r\n") == "ab" &&
     chop_restored("") == "" &&
     !bad.valid_encoding?

puts
if ok
  puts "PASS: restored chop answers #{good.inspect}, a valid string."
  puts "      the bytewise form answers #{bad.bytes.inspect}, valid_encoding?=#{bad.valid_encoding?}"
  exit 0
else
  puts "FAIL"
  exit 1
end
