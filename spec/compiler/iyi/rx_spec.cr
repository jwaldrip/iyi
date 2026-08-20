# iyi: differential spec for the owned regex engine (SPEC.md III.10, Appendix B
# decision 17). A regex engine can pass a page of hand written expectations and
# still be wrong, so the core of this file asserts almost nothing by hand: it
# compares the engine against a second one. The spec binary still links pcre2
# for the stdlib `Regex` even though the compiler binary must not, and that is
# what makes an oracle available here at all. Every corpus case runs through
# `rx_should_agree`, which requires agreement on whether it matched, on byte
# begin and end, on group count, and on each group's begin, end and text, and
# prints both engines' results side by side when they differ.
#
# Offsets are bytes because `Rx::Match#begin` and `#end` are byte offsets; the
# stdlib oracle offers the same numbers only through `MatchData#byte_begin` and
# `#byte_end` (its `#begin` and `#end` count chars). The reference also compiles
# with PCRE2_UTF | PCRE2_UCP (src/regex/pcre2.cr pins both), so agreement means
# agreement with Unicode aware classes, case and word boundaries. That is
# deliberate: the compiler's real patterns always ran under UCP, and the zero
# dependency replacements of them preserved exactly that (see the `# iyi:` notes
# in compiler.cr and exception.cr), so anything weaker here would test a
# different engine than the one the compiler had.

require "spec"
require "compiler/iyi/rx"

# Renders an owned match the way the failure message shows it: no match, or the
# whole match span and then every group's span and text. Groups that did not
# participate render as absent; both views below produce identical strings for
# identical outcomes, so plain string equality is the comparison.
private def rx_owned_view(owned_match : Iyi::Rx::Match?) : String
  return "no match" unless owned_match
  String.build do |io|
    io << "match " << owned_match.begin(0) << ".." << owned_match.end(0) << ' ' << owned_match[0].inspect
    io << " groups=" << owned_match.group_count
    1.upto(owned_match.group_count) do |group|
      io << ' ' << group << ':'
      if text = owned_match[group]
        io << owned_match.begin(group) << ".." << owned_match.end(group) << ' ' << text.inspect
      else
        io << "absent"
      end
    end
  end
end

private def rx_reference_view(reference_match : Regex::MatchData?) : String
  return "no match" unless reference_match
  String.build do |io|
    io << "match " << reference_match.byte_begin(0) << ".." << reference_match.byte_end(0) << ' ' << reference_match[0].inspect
    io << " groups=" << reference_match.group_size
    1.upto(reference_match.group_size) do |group|
      io << ' ' << group << ':'
      if text = reference_match[group]?
        io << reference_match.byte_begin(group) << ".." << reference_match.byte_end(group) << ' ' << text.inspect
      else
        io << "absent"
      end
    end
  end
end

private def rx_reference(source : String, ignore_case : Bool) : Regex
  Regex.new(source, ignore_case ? Regex::Options::IGNORE_CASE : Regex::Options::None)
end

# The one helper every corpus case goes through. Compiling both engines from
# the same source string (and the same ignore_case) keeps the comparison honest;
# a mismatch fails the example naming the pattern, the subject and both results.
private def rx_should_agree(source : String, subject : String, ignore_case : Bool = false, start : Int32 = 0) : Nil
  owned = Iyi::Rx::Pattern.compile(source, ignore_case).match(subject, start)
  reference = rx_reference(source, ignore_case).match_at_byte_index(subject, start)
  owned_view = rx_owned_view(owned)
  reference_view = rx_reference_view(reference)
  return if owned_view == reference_view

  message = String.build do |io|
    io << "iyi's Rx disagrees with pcre2 on /" << source << '/'
    io << 'i' if ignore_case
    io << " against " << subject.inspect
    io << " from byte " << start if start > 0
    io << '\n'
    io << "     iyi:   " << owned_view << '\n'
    io << "     pcre2: " << reference_view
  end
  fail message
end

private def rx_gsub_should_agree(source : String, subject : String, replacement : String, ignore_case : Bool = false) : Nil
  owned = Iyi::Rx.gsub(subject, Iyi::Rx::Pattern.compile(source, ignore_case), replacement)
  reference = subject.gsub(rx_reference(source, ignore_case), replacement)
  return if owned == reference

  fail("iyi's Rx.gsub disagrees with pcre2 on /#{source}/ against #{subject.inspect} with replacement #{replacement.inspect}\n" +
       "     iyi:   #{owned.inspect}\n" +
       "     pcre2: #{reference.inspect}")
end

private def rx_sub_should_agree(source : String, subject : String, replacement : String) : Nil
  owned = Iyi::Rx.sub(subject, Iyi::Rx::Pattern.compile(source), replacement)
  reference = subject.sub(rx_reference(source, false), replacement)
  return if owned == reference

  fail("iyi's Rx.sub disagrees with pcre2 on /#{source}/ against #{subject.inspect} with replacement #{replacement.inspect}\n" +
       "     iyi:   #{owned.inspect}\n" +
       "     pcre2: #{reference.inspect}")
end

private def rx_scan_should_agree(source : String, subject : String) : Nil
  owned = Iyi::Rx.scan(subject, Iyi::Rx::Pattern.compile(source)).map { |match| "#{match.begin(0)}..#{match.end(0)} #{match[0].inspect}" }
  reference = subject.scan(rx_reference(source, false)).map { |match| "#{match.byte_begin(0)}..#{match.byte_end(0)} #{match[0].inspect}" }
  return if owned == reference

  fail("iyi's Rx.scan disagrees with pcre2 on /#{source}/ against #{subject.inspect}\n" +
       "     iyi:   #{owned.inspect}\n" +
       "     pcre2: #{reference.inspect}")
end

private def rx_split_should_agree(source : String, subject : String) : Nil
  owned = Iyi::Rx.split(subject, Iyi::Rx::Pattern.compile(source))
  reference = subject.split(rx_reference(source, false))
  return if owned == reference

  fail("iyi's Rx.split disagrees with pcre2 on /#{source}/ against #{subject.inspect}\n" +
       "     iyi:   #{owned.inspect}\n" +
       "     pcre2: #{reference.inspect}")
end

describe Iyi::Rx do
  describe "differential against pcre2" do
    it "agrees on every pattern the compiler itself runs" do
      # iyi: lifted verbatim from the sources named on each row, no
      # approximations. Subjects are the strings each site really sees: triples
      # for the ABI dispatch, linker stderr for the hint, api set names for the
      # mingw loader. The empty subject is appended by the driver below.
      compiler_patterns = {
        # src/compiler/iyi/compiler.cr, expand_lib_flags: a backticked
        # command inside lib flags. Lazy, so "a `b` c `d` e" stops at the first
        # closing backtick; a greedy pair would run to the last one.
        {"`(.*?)`", false, ["gcc `pkg-config --libs openssl` -lssl", "`echo hi`", "``", "a `b` c `d` e", "plain flags, no command"]},
        # compiler.cr, safe_object_name: everything outside [A-Za-z0-9_] becomes
        # -<ord>. Ω exercises the complement class over a multi byte character:
        # under PCRE2_UTF a negated class matches one whole character, never a
        # stray lead byte.
        {"[^A-Za-z0-9_]", false, ["List(Int32)", "app/greeter", "Ωmega", "foo_1"]},
        # compiler.cr, the three linker error shapes. (\S+)\b is greedy then
        # backtracks to a word boundary: -lssl: hints about ssl, -lfoo! about
        # foo, -lcafé! about café under UCP, and an all punctuation run like !!!
        # never lands on one, so the line passes through unmatched.
        {"cannot find -l(\\S+)\\b", false, ["ld: cannot find -lssl: No such file or directory", "cannot find -lfoo!", "cannot find -lcafé!", "cannot find -l!!!", "cannot find -la and cannot find -lb", "undefined symbol: main"]},
        {"unable to find library -l(\\S+)\\b", false, ["ld: unable to find library -lz", "unable to find library -lstdc++.so", "linked fine"]},
        {"library not found for -l(\\S+)\\b", false, ["clang: error: library not found for -lcurl", "library not found for -lpthread"]},
        # src/compiler/iyi/exception.cr, leading_white_space. ^ anchors at
        # the subject start only (no multiline flag anywhere in the compiler),
        # so an indented second line does not match, and an all blank line has
        # no \S after the run.
        {"^(\\s+)\\S", false, ["    puts 1", "\t\tfoo bar", "   ", "no leading space", "a\n  b"]},
        # src/compiler/iyi/codegen/abi.cr, initialize and the from dispatch.
        {"apple", false, ["aarch64-apple-darwin24.5.0", "x86_64-apple-macosx", "x86_64-unknown-linux-gnu", "applesauce"]},
        {"windows", false, ["x86_64-w64-windows-gnu", "i686-pc-windows-msvc", "wasm32-unknown-unknown"]},
        {"x86_64.+windows-(?:msvc|gnu)", false, ["x86_64-w64-windows-gnu", "x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu", "amd64-w64-windows-gnu"]},
        {"x86_64|amd64", false, ["amd64-linux-gnu", "x86_64-unknown-linux-gnu", "aarch64-apple-darwin24.5.0"]},
        {"i386|i486|i586|i686", false, ["i686-pc-linux-gnu", "i386", "arm-linux-gnueabihf"]},
        {"aarch64|arm64", false, ["aarch64-apple-darwin24.5.0", "arm64-apple-darwin", "x86_64-pc-linux"]},
        {"arm", false, ["arm-unknown-linux-gnueabihf", "armv7-none-eabi", "aarch64-apple-darwin24.5.0"]},
        {"avr", false, ["avr-unknown-unknown", "atmega"]},
        {"wasm32", false, ["wasm32-unknown-wasi", "wasm64-unknown-unknown"]},
        # src/compiler/iyi/codegen/target.cr, freebsd_version. Unanchored,
        # so gnufreebsd13.2 reads 13 too; freebsdx.y has no digit run and must
        # not match anywhere later either.
        {"freebsd(\\d+)\\.\\d+", false, ["x86_64-unknown-freebsd13.2", "gnufreebsd13.2", "aarch64-unknown-freebsd14.0", "freebsdx.y", "x86_64-unknown-linux-gnu"]},
        # src/compiler/iyi/semantic/semantic_visitor.cr, strip_source_suffix.
        # A pcre2 $ also matches just before one final newline, which is why
        # "src/foo.cr\n" strips and foo.crs does not.
        {"\\.(iyi|cr)$", false, ["src/foo.cr", "lib/bar.iyi", "src/foo.cr\n", "src/foo.txt", "foo.crs"]},
        # src/compiler/iyi/semantic/suggestions.cr, SuggestableDefName. \A,
        # not ^ and not unanchored: a lowercase name past a newline still fails
        # because only position 0 can match.
        {"\\A[a-z_]", false, ["size", "_foo", "Foo", "1abc", "\nfoo"]},
        # src/compiler/iyi/loader/mingw.cr, api_set?. The only anchored
        # pattern in the compiler. kernel32.dll and a trailing .txt fail the
        # anchor or the $, uppercase API- fails the literal prefix, and a final
        # newline is fine before $.
        {"^(?:api-|ext-)[a-zA-Z0-9-]*l\\d+-\\d+-\\d+\\.dll$", false, ["api-ms-win-crt-runtime-l1-1-0.dll", "ext-ms-win-shell32-l1-2-0.dll", "api-l1-1-0.dll", "kernel32.dll", "api-ms-win-crt-stdio-l1-1-0.dll.txt", "API-MS-WIN-crt-l1-1-0.dll", "api-ms-win-crt-runtime-l1-1-0.dll\n"]},
        # src/compiler/iyi/tools/init.cr, the only ignore_case pattern in
        # the compiler. Case folding reaches into the negated class: foo-BAR
        # does not match because B is a letter under /i, while digits do.
        {"[-_]([^a-z])", true, ["foo-2bar", "html_5", "foo-BAR", "foo-bar", "x_y"]},
      }

      compiler_patterns.each do |source, ignore_case, subjects|
        subjects.each { |subject| rx_should_agree(source, subject, ignore_case) }
        rx_should_agree(source, "", ignore_case)
      end
    end

    it "agrees on every supported construct" do
      # One row per construct from the contract's syntax list, with a subject
      # that matches, one that does not, and the empty subject appended by the
      # driver. For a* style rows the second subject still matches (empty at
      # byte 0); what the row pins is that both engines agree on that span.
      constructs = {
        {"abc", "xxabcxx", "abd"},
        {"a\\.b", "za.bz", "aXb"},
        {"\\+", "a+b", "ab"},
        {"\\(\\)", "()", "("},
        {"\\{2\\}", "x{2}y", "x22"},
        {"\\*\\?\\.", "*?.", "*?"},
        {"a\\|b", "a|b", "ab"},
        {"\\\\", "a\\b", "ab"},
        {"\\/", "a/b", "ab"},
        {"\\n", "a\nb", "ab"},
        {"\\t", "\t", " "},
        {"\\r", "\r", "\n"},
        {"\\f", "\f", "x"},
        {"\\v", "\v", "x"},
        {"\\0", "a\u{0}b", "ab"},
        {"\\x41", "xAy", "xBy"},
        {"\\x2B", "+", "-"},
        {".", "abc", "\n"},
        {"a.c", "abc", "a\nc"},
        {"[abc]", "xbx", "ddd"},
        {"[a-z]+", "abc123", "123"},
        {"[^abc]", "d", "b"},
        {"[]]", "a]b", "ab"},
        {"[a-]", "-", "b"},
        {"[]-]", "]", "a"},
        {"[\\d]+", "ab12", "ab"},
        {"[\\w]+", "_a1", "!!"},
        {"[a-cx-z]+", "xyz", "mnp"},
        {"[^^]", "a", "^"},
        {"\\d+", "x42y", "xy"},
        {"\\D+", "42x", "42"},
        {"\\w+", " a_1", " !!! "},
        {"\\W+", "ab!cd", "abcd"},
        {"\\s+", "a \tb", "ab"},
        {"\\S+", " ", "a"},
        {"\\h+", "x1F", "xG"},
        {"\\H+", "1g", "1F"},
        {"^ab", "abc", "xabc"},
        {"c$", "abc", "acb"},
        {"\\Aab", "ab", "xab"},
        {"c\\z", "abc", "abc\n"},
        {"c\\Z", "abc\n", "abc\n\n"},
        {"\\bab", "ab cd", "xab"},
        {"\\Bcd", "abcd", "cd"},
        {"a*", "aaa", "b"},
        {"a+", "baaab", "bbb"},
        {"a?b", "ab", "b"},
        {"a{3}", "aaab", "aab"},
        {"a{2,}", "aaaa", "ba"},
        {"a{2,4}", "aaaaab", "ab"},
        {"(ab)+", "ababab", "a"},
        {"a+?", "aaa", "b"},
        {"a*?b", "aab", "aa"},
        {"a??", "a", "b"},
        {"a{2,3}?b", "aaab", "ab"},
        {"a{3}?b", "aaab", "aab"},
        {"ab|cd", "xcdx", "ad"},
        {"(a)(b)", "ab", "ba"},
        {"(?:ab)+c", "ababc", "abab"},
        {"(?i)abc", "ABC", "ABD"},
        {"(?i)abc", "xAbCy", "abd"},
        {"(?i:ab)c", "ABc", "ABC"},
        {"a(?i)bc", "aBC", "Abc"},
      }

      constructs.each do |source, hit, miss|
        rx_should_agree(source, hit)
        rx_should_agree(source, miss)
        rx_should_agree(source, "")
      end
    end

    it "agrees on the inputs that break naive engines" do
      adversarial = {
        # leftmost-first, not longest
        {"a|ab", ["ab"]},
        # order decides, and here ab wins
        {"ab|a", ["ab"]},
        # greedy runs to the last b
        {"a.*b", ["aXbXb"]},
        # lazy stops at the first b
        {"a.*?b", ["aXbXb"]},
        # dot never crosses a newline
        {".*", ["ab\ncd", "\n"]},
        {"((a)(b))", ["ab"]},
        # absent group must render absent
        {"((a)(b)?c)", ["ac", "abc", "axc"]},
        {"a(b(c)d)e", ["abcde"]},
        # group 2 absent after the last round
        {"((a(x)?)+)", ["axax", "a"]},
        # alternation under a quantifier
        {"(a|b)+", ["abba", "a"]},
        # preference order, not longest: a then bc
        {"(a|ab)(c|bc)", ["abc"]},
        {"(ab|a)*", ["aba", ""]},
        # empty body rounds; both engines state theirs
        {"(a*)*", ["aaa", ""]},
        # exponential bait, small enough that pcre2's own match limit is never the outcome
        {"(a+)+b", ["aaab", "aaac", "aaaaaaaac"]},
        {"(a|)b?", ["b", ""]},
        {"(a|)", ["b", "a", ""]},
        # empty branch is tried first
        {"(|a)b", ["ab", "b"]},
        {"^a", ["a\nb", "xa"]},
        # $ also sits before one final newline
        {"b$", ["a\nb", "a\nb\n"]},
        {"a$", ["a\n", "a\nb"]},
        {"^$", ["\n", "a"]},
        {"\\bfoo\\b", ["foo", "foo bar", "xfoox", "foo!", "(foo)"]},
        # ] first and - last in one class, quantified over a run of both
        {"[]-]+", ["-]-a", "b"]},
        {"a{0,3}", ["b", "a", "aa", "aaa", "aaaa", "bab"]},
        {"a{0,3}b", ["aaab", "b"]},
      }

      adversarial.each do |source, subjects|
        subjects.each { |subject| rx_should_agree(source, subject) }
        rx_should_agree(source, "")
      end
    end

    it "agrees on utf-8 subjects" do
      # iyi: byte offsets out, whole characters in. The reference runs UTF mode
      # with UCP, so é counts as a word character and é|b is not a word
      # boundary; the engine has to say the same, because the compiler's own
      # patterns made exactly those distinctions (compiler.cr word_boundary?
      # documents the UCP reading).
      utf8 = {
        {".", ["é", "日", "aé b", "é\n"]},
        {"[éû]+", ["éûxé", "x"]},
        # codepoint range: ā (U+0101) is outside
        {"[à-ÿ]", ["û", "a", "ā"]},
        # negated class takes the whole character
        {"[^a]", ["é"]},
        # UCP word chars
        {"\\w+", ["café au lait", "!!"]},
        {"\\S+", ["héllo!"]},
        # é|b is no boundary under UCP
        {"\\bb", ["éb", "ab", " b"]},
        {"café\\b", ["café!", "café", "cafés"]},
        # offsets after multi byte prefixes
        {"b", ["ééb"]},
        {"(b)(c)", ["éébc"]},
        {".*x", ["ééx"]},
      }

      utf8.each do |source, subjects|
        subjects.each { |subject| rx_should_agree(source, subject) }
      end
    end

    it "agrees when matching from a start offset" do
      pattern = Iyi::Rx::Pattern.compile("b+")
      match = pattern.match("abbc", 1).not_nil!
      match.begin(0).should eq(1)
      match.end(0).should eq(3)
      match[0].should eq("bb")
      pattern.match("abbc", 3).should be_nil
      # past the end is nil, not a raise
      pattern.match("abbc", 5).should be_nil

      # iyi: start offsets run on ASCII subjects only, where byte and char
      # offsets coincide. The contract pins bytes for begin and end; it does not
      # spell out a unit for start, so nothing here forces a reading either way.
      {
        {"b+", "abbc", 0},
        {"b+", "abbc", 1},
        {"b+", "abbc", 2},
        {"b+", "abbc", 3},
        {"b+", "abbc", 4},
        {"b+", "abbc", 5},
        # empty match from an offset
        {"a*", "bb", 1},
        {"c", "abc", 2},
      }.each do |source, subject, start|
        rx_should_agree(source, subject, start: start)
      end
    end
  end

  describe "refused syntax" do
    it "raises SyntaxError for every construct outside the supported set" do
      # iyi: SPEC.md III.10 takes Go's trade: linear time means no backreferences
      # or lookaround, ever. Refusing loudly beats silently matching wrong, so
      # each of these must raise at compile and carry a position. None of them
      # is compiled against pcre2; the oracle has nothing to say about
      # constructs the engine must not accept.
      refused = {
        {"backreference \\1", "(a)\\1"},
        {"named backreference \\k", "(?<n>a)\\k<n>"},
        {"lookahead (?=)", "a(?=b)"},
        {"negative lookahead (?!)", "a(?!b)"},
        {"lookbehind (?<=)", "(?<=a)b"},
        {"negative lookbehind (?<!)", "(?<!a)b"},
        {"named group (?<name>)", "(?<name>a)"},
        {"named group (?P<name>)", "(?P<name>a)"},
        {"atomic group (?>)", "(?>ab)"},
        {"possessive *+", "a*+"},
        {"possessive ++", "a++"},
        {"possessive ?+", "a?+"},
        {"possessive {n,m}+", "a{1,2}+"},
        {"conditional (?(1))", "(?(1)a|b)"},
        {"recursion (?R)", "a(?R)b"},
        {"subroutine (?1)", "(a)(?1)"},
        {"anchor \\G", "\\G"},
        {"keep \\K", "a\\Kb"},
        {"property \\p{...}", "\\p{L}"},
        {"negated property \\P{...}", "\\P{L}"},
        {"property \\pL", "\\pL"},
      }

      refused.each do |label, source|
        begin
          Iyi::Rx::Pattern.compile(source)
        rescue ex : Iyi::Rx::SyntaxError
          ex.position.should be >= 0
          ex.position.should be <= source.size
          next
        end
        fail("iyi's Rx accepted #{label} (#{source.inspect}); the contract refuses it (SPEC.md III.10)")
      end
    end
  end

  describe "helpers" do
    it "exposes the pattern source and the match subject" do
      pattern = Iyi::Rx::Pattern.compile("a+b", true)
      pattern.source.should eq("a+b")
      match = pattern.match("xaaab").not_nil!
      match.subject.should eq("xaaab")
      match[0].should eq("aaab")
      match.group_count.should eq(0)
    end

    it "answers matches? and the module level match (subject first)" do
      pattern = Iyi::Rx::Pattern.compile("b+")
      pattern.matches?("abbc").should be_true
      pattern.matches?("aaa").should be_false
      Iyi::Rx.matches?("abbc", pattern).should be_true
      Iyi::Rx.matches?("aaa", pattern).should be_false
      found = Iyi::Rx.match("abbc", pattern)
      found.should_not be_nil
      found.not_nil![0].should eq("bb")
      Iyi::Rx.match("aaa", pattern).should be_nil
    end

    it "gsubs with backreferences like pcre2" do
      pattern = Iyi::Rx::Pattern.compile("(\\w+) (\\w+)")
      Iyi::Rx.gsub("hello world", pattern, "\\2 \\1").should eq("world hello")
      Iyi::Rx.gsub("foo bar", Iyi::Rx::Pattern.compile("\\w+"), "[\\0]").should eq("[foo] [bar]")
      # a reference to a group that did not participate is empty, per contract.
      # In "ab abxb" the second match is "ab" at bytes 3..5 with the group
      # absent: the greedy (x)? faces a b, matches empty, and the match closes
      # before the x ever arrives, so "xb" copies through. pcre2 says "<> <>xb"
      # for that subject; "ab axb" is where the group does participate.
      Iyi::Rx.gsub("ab abxb", Iyi::Rx::Pattern.compile("a(x)?b"), "<\\1>").should eq("<> <>xb")
      Iyi::Rx.gsub("ab axb", Iyi::Rx::Pattern.compile("a(x)?b"), "<\\1>").should eq("<> <x>")

      rx_gsub_should_agree("(\\w+) (\\w+)", "hello world", "\\2 \\1")
      rx_gsub_should_agree("\\w+", "foo bar", "[\\0]")
      rx_gsub_should_agree("a(x)?b", "ab abxb", "<\\1>")
      rx_gsub_should_agree("a(x)?b", "ab axb", "<\\1>")
    end

    it "gsubs with a block like pcre2" do
      digits = Iyi::Rx::Pattern.compile("[0-9]+")
      Iyi::Rx.gsub("a1b22c", digits) { |match| "*#{match[0]}*" }.should eq("a*1*b*22*c")

      # compiler.cr safe_object_name, the map the zero-dep code reproduces:
      # anything outside [A-Za-z0-9_] becomes -<ord>. not_nil! because Rx#[]
      # returns String? even for group 0.
      owned = Iyi::Rx.gsub("List(Int32)", Iyi::Rx::Pattern.compile("[^A-Za-z0-9_]")) { |match| "-#{match[0].not_nil![0].ord}" }
      owned.should eq("List-40Int32-41")
      # the stdlib block yields the matched String first, not the MatchData
      owned.should eq("List(Int32)".gsub(/[^A-Za-z0-9_]/) { |matched| "-#{matched[0].ord}" })
    end

    it "subs only the first match like pcre2" do
      Iyi::Rx.sub("aaa", Iyi::Rx::Pattern.compile("a"), "b").should eq("baa")
      Iyi::Rx.sub("a1a2", Iyi::Rx::Pattern.compile("1|2")) { |match| "<#{match[0]}>" }.should eq("a<1>a2")

      rx_sub_should_agree("o", "foo", "0")
      # semantic_visitor.cr strip_source_suffix, the real call
      rx_sub_should_agree("\\.(iyi|cr)$", "src/foo.cr", "")
    end

    it "replaces with the compiler's own patterns like pcre2 does" do
      # init.cr valid_name?, the only /i replacement in the compiler
      rx_gsub_should_agree("[-_]([^a-z])", "foo-2bar html_5", "\\1", ignore_case: true)
      # compiler.cr, one of the three linker hint lines
      rx_gsub_should_agree("cannot find -l(\\S+)\\b", "ld: cannot find -lssl: No such file or directory", "cannot find -l\\1 (hint)")
    end

    it "scans every match like pcre2" do
      rx_scan_should_agree("[a-z][0-9]", "a1b2c3")
      rx_scan_should_agree("(a)(b)", "ab_ab")
      rx_scan_should_agree("", "abc")
      # byte offsets across a multi byte char
      rx_scan_should_agree("a", "aéa")

      second = Iyi::Rx.scan("aéa", Iyi::Rx::Pattern.compile("a"))[1]
      second.begin(0).should eq(3)
      second.end(0).should eq(4)
    end

    it "splits like pcre2" do
      Iyi::Rx.split("a,b,c", Iyi::Rx::Pattern.compile(",")).should eq(["a", "b", "c"])

      rx_split_should_agree(",", "a,b,c")
      rx_split_should_agree("\\d", "a1b2c3")
      # the trailing empty field stays
      rx_split_should_agree(",", "a,b,")
      # empty subject yields [""], like the stdlib
      rx_split_should_agree(",", "")
      # empty matches adjacent to fields
      rx_split_should_agree("a*", "bab")
      # the stdlib interleaves captured groups
      rx_split_should_agree("(\\d)", "a1b")
    end

    it "terminates on a pattern that matches empty, in gsub and scan" do
      # iyi: the contract's own rule, advance one character, is the only thing
      # standing between these calls and an infinite loop. A hang here is a
      # failure; the spec runner reports it as a timeout.
      rx_gsub_should_agree("a*", "bab", "<\\0>")
      rx_gsub_should_agree("", "ab", "-")
      rx_scan_should_agree("a*", "bab")
      rx_scan_should_agree("", "abc")
    end
  end
end
