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

# iyi: what the engine itself must answer, for a pattern pcre2 refuses to
# compile at all. A variable length lookbehind is the case: the engine supports
# it and the oracle does not, so there is nothing to compare against and the
# expectation has to be stated. Where the oracle does compile the pattern the
# differential still runs, so this never becomes a way around it.
private def rx_should_span(source : String, subject : String, from : Int32, to : Int32) : Nil
  match = Iyi::Rx::Pattern.compile(source).match(subject)
  if match.nil? || match.begin(0) != from || match.end(0) != to
    fail("iyi's Rx on /#{source}/ against #{subject.inspect}\n" +
         "     got:      #{rx_owned_view(match)}\n" +
         "     expected: match #{from}..#{to}")
  end
  rx_should_agree(source, subject) if rx_reference_compiles?(source)
end

private def rx_should_not_match(source : String, subject : String) : Nil
  match = Iyi::Rx::Pattern.compile(source).match(subject)
  fail("iyi's Rx matched /#{source}/ against #{subject.inspect}: #{rx_owned_view(match)}") if match
  rx_should_agree(source, subject) if rx_reference_compiles?(source)
end

private def rx_reference_compiles?(source : String) : Bool
  Regex.new(source)
  true
rescue ArgumentError
  false
end

# Whether an assertion-only pattern holds exactly at byte *at*. Such a pattern
# matches empty, so an unanchored search from *at* answers the question only
# when the match it finds begins there rather than further along.
private def rx_holds_at?(pattern : Iyi::Rx::Pattern, subject : String, at : Int32) : Bool
  match = pattern.match(subject, at)
  !match.nil? && match.begin(0) == at
end

private def rx_reference_holds_at?(pattern : Regex, subject : String, at : Int32) : Bool
  match = pattern.match_at_byte_index(subject, at)
  !match.nil? && match.byte_begin(0) == at
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
        {"\\V", "a\nb", "\n"},
        {"\\x{41}", "xAy", "xBy"},
        {"\\x{2B}", "+", "-"},
        {"\\x{1F600}", "a\u{1F600}b", "ab"},
        {"\\p{L}", "1a", "12"},
        {"\\pL", "1a", "12"},
        {"\\P{L}", "a1", "ab"},
        {"\\PL", "a1", "ab"},
        {"\\p{Lu}", "aA", "ab"},
        {"\\p{Ll}", "Aa", "AB"},
        {"\\p{N}", "a1", "ab"},
        {"\\p{M}", "a\u{0301}", "ab"},
        {"[\\p{L}]+", "12ab", "12"},
        {"[\\P{L}]+", "ab12", "ab"},
        {"[\\v]", "\r", "x"},
        {"[\\V]", "x", "\r"},
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

    it "agrees on caseless matching past ascii" do
      # iyi: `(?i)` folds through `Char#downcase(Unicode::CaseOptions::Fold)`,
      # the stdlib's simple case folding, which is what pcre2 compares under
      # PCRE2_CASELESS. Folding rather than trying one side's other case is what
      # makes the classes larger than a pair work: all three sigmas fold to one
      # character, and so do s, S and the long s, and so do k, K and the Kelvin
      # sign. Each row's pattern is matched caselessly against every subject,
      # including one the pair must NOT reach.
      caseless = {
        {"é", ["É", "é", "e"]},
        {"É", ["é", "É", "E"]},
        {"École", ["ÉCOLE", "école", "École", "ecole"]},
        {"σ", ["ς", "Σ", "σ", "s"]},
        {"ς", ["σ", "Σ", "ς"]},
        {"Σ", ["σ", "ς", "Σ"]},
        {"ſ", ["s", "S", "ſ"]},
        {"s", ["ſ", "s", "S"]},
        # KELVIN SIGN, whose fold is a plain k
        {"\u{212A}", ["k", "K", "\u{212A}"]},
        {"k", ["\u{212A}", "k", "K"]},
        # İ (U+0130) folds to itself, so neither engine pairs it with i
        {"İ", ["i", "I", "İ", "ı"]},
        {"i", ["İ", "ı", "I", "i"]},
        # no case to invent
        {"日", ["日", "本"]},
        {"à", ["À", "à"]},
        {"þ", ["Þ", "þ"]},
      }

      caseless.each do |source, subjects|
        subjects.each { |subject| rx_should_agree(source, subject, ignore_case: true) }
        rx_should_agree(source, "", ignore_case: true)
      end

      # iyi: a class folds the SUBJECT, never the class, because a folded range
      # is not a range: [À-Þ] has to reach à, and [à-þ] has to reach À, and no
      # folding of the endpoints produces a set either question can be asked of.
      # The ranges below are the two directions, and [a-z] against the Kelvin
      # sign is the case that needs the fold rather than a case mapping.
      classes = {
        {"[éû]", ["É", "Û", "é", "a"]},
        {"[É]", ["é", "É", "e"]},
        {"[à-þ]", ["À", "Þ", "à", "þ", "a"]},
        {"[À-Þ]", ["à", "þ", "À", "Þ", "a"]},
        {"[^é]", ["É", "é", "a"]},
        {"[a-zÀ-Þ]", ["É", "à", "A", "1"]},
        {"[a-z]", ["É", "A", "a", "\u{212A}", "ſ"]},
        {"[A-Z]", ["é", "a", "Z", "\u{212A}", "ſ"]},
        {"[ſ]", ["s", "S", "ſ"]},
        # the OHM SIGN reaches Ω the way the KELVIN SIGN reaches K above: it is
        # already uppercase, so only the upcase of its fold lands in the range
        {"[Α-Ω]", ["α", "ω", "Α", "Ω", "\u{2126}"]},
        {"[α-ω]", ["Α", "Ω", "α", "ω", "\u{2126}"]},
        # a property inside a caseless class: é is not Lu, but its upcase is
        {"[\\p{Lu}]", ["é", "É", "日", "5"]},
        {"[éû]+", ["ÉÛéû", "aa"]},
      }

      classes.each do |source, subjects|
        subjects.each { |subject| rx_should_agree(source, subject, ignore_case: true) }
        rx_should_agree(source, "", ignore_case: true)
      end
    end

    it "agrees on the unicode properties it accepts" do
      # iyi: five general categories, exactly the ones a public stdlib predicate
      # answers exactly: L is `Char#letter?`, Lu is `uppercase?`, Ll is
      # `lowercase?`, N is `number?`, M is `mark?`. Both spellings, both senses,
      # inside a class and outside one. Every subject here is a character whose
      # category has been settled since Unicode 3, so the comparison cannot turn
      # into a disagreement between the stdlib's tables and the linked pcre2's.
      properties = {
        {"\\p{L}", ["a", "é", "日", "5", "!", "\u{0301}"]},
        {"\\pL", ["a", "é", "5"]},
        {"\\P{L}", ["a", "5", "!", "é"]},
        {"\\PL", ["a", "5"]},
        {"\\p{Lu}", ["A", "a", "É", "é", "日"]},
        {"\\p{Ll}", ["a", "A", "é", "É", "日"]},
        {"\\P{Lu}", ["A", "a", "É"]},
        {"\\P{Ll}", ["a", "A", "é"]},
        {"\\p{N}", ["5", "٣", "½", "Ⅴ", "a"]},
        {"\\pN", ["5", "½", "a"]},
        {"\\P{N}", ["5", "a"]},
        {"\\p{M}", ["\u{0301}", "a", "é"]},
        {"\\P{M}", ["\u{0301}", "a"]},
        {"\\pM", ["\u{0301}", "a"]},
        # inside a class, alone and unioned, and under the class level negation
        {"[\\p{L}]+", ["café", "12", "aé1"]},
        {"[\\P{L}]+", ["12!", "ab", "a1"]},
        {"[^\\p{L}]", ["a", "1"]},
        {"[^\\P{L}]", ["a", "1"]},
        {"[\\p{Lu}\\p{N}]+", ["AB12", "ab", "A1b"]},
        {"[\\p{L}\\p{M}]+", ["e\u{0301}x", "!!"]},
        {"[\\pL0-9]+", ["a1!", "!!"]},
        # quantified, and after a literal, so the class is not the whole pattern
        {"a\\p{M}", ["a\u{0301}", "ab"]},
        {"\\p{L}\\p{N}", ["a1", "1a"]},
        {"\\p{Lu}+", ["xABy", "xy"]},
      }

      properties.each do |source, subjects|
        subjects.each { |subject| rx_should_agree(source, subject) }
        rx_should_agree(source, "")
      end
    end

    it "agrees on the vertical whitespace class" do
      # iyi: pcre2 and Perl read `\v` as a class, not as the vertical tab
      # character it used to be here: VT, LF, FF, CR, NEL, LINE SEPARATOR and
      # PARAGRAPH SEPARATOR. Every member gets a row, and tab and space are the
      # two neighbours that have to stay outside it.
      members = ["\u{000B}", "\n", "\u{000C}", "\r", "\u{0085}", "\u{2028}", "\u{2029}"]
      outside = ["\t", " ", "a", "\u{00A0}"]

      (members + outside).each do |subject|
        {"\\v", "\\V", "[\\v]", "[\\V]", "[^\\v]", "[^\\V]", "[\\v\\t]", "[\\V\\n]"}.each do |source|
          rx_should_agree(source, subject)
        end
      end

      {"\\v", "\\V", "[\\v]", "[\\V]"}.each { |source| rx_should_agree(source, "") }
      rx_should_agree("\\v+", "a\r\n\u{2028}b")
      rx_should_agree("\\V+", "ab\ncd")
      rx_should_agree("\\v\\V", "\nx")
    end

    it "agrees on \\x{...} at every width" do
      # iyi: pcre2 takes any number of hex digits between the braces, so leading
      # zeroes are free and one form names every codepoint. `\xHH` keeps its old
      # two digit reading, which is why both spellings of A appear here.
      hex = {
        {"\\x{a}", ["\n", "a"]},
        {"\\x{41}", ["A", "B"]},
        {"\\x{e9}", ["é", "e"]},
        {"\\x{E9}", ["é", "e"]},
        {"\\x{0041}", ["A", "a"]},
        {"\\x{00041}", ["A"]},
        {"\\x{000041}", ["A"]},
        {"\\x{10FFFF}", ["\u{10FFFF}", "a"]},
        {"\\x{1F600}", ["\u{1F600}", "a"]},
        # as range endpoints, which is where a codepoint escape earns its keep
        {"[\\x{41}-\\x{5A}]+", ["ABZ", "abz"]},
        {"[\\x{e9}\\x{fb}]+", ["éû", "ab"]},
        {"[\\x{2028}-\\x{2029}]", ["\u{2028}", "a"]},
        {"\\x{41}\\x41", ["AA", "A"]},
        {"\\x{41}+", ["xAAy", "xy"]},
      }

      hex.each do |source, subjects|
        subjects.each { |subject| rx_should_agree(source, subject) }
        rx_should_agree(source, "")
      end
    end

    it "states the two readings pcre2 cannot be met on" do
      # iyi: two answers stated rather than inherited, both forced by what the
      # stdlib exposes publicly rather than by a preference.
      #
      # `\d` is Nd plus Nl plus No, where pcre2 under UCP means \p{Nd} exactly.
      # Every public predicate the stdlib has for numbers answers the wider set:
      # `Char#number?` and `Unicode.number?` are both Nd|Nl|No,
      # `Char#ascii_number?` is ASCII only, and the rest of
      # src/unicode/unicode.cr is :nodoc:. Narrowing `\d` to ASCII instead would
      # miss the Arabic-Indic digits pcre2 does match, which is the worse miss
      # for a class whose whole point is digits. So the wider reading stands and
      # \p{Nd} is refused rather than approximated.
      #   pcre2: /\d/ matches neither ½ (U+00BD, No) nor Ⅴ (U+2164, Nl).
      digits = Iyi::Rx::Pattern.compile("\\d")
      digits.matches?("½").should be_true
      digits.matches?("Ⅴ").should be_true
      # and wherever pcre2 agrees, the differential still holds us to it
      rx_should_agree("\\d+", "٣٤")
      rx_should_agree("\\d+", "x42y")
      rx_should_agree("\\d", "a")
      rx_should_agree("\\D+", "٣a")

      # ẞ (U+1E9E) full-folds to "ss", and `Unicode::CaseOptions::Fold`
      # documents that a character whose full folding is several characters is
      # returned unchanged. So ẞ does not fold to ß here, while pcre2's simple
      # folding pairs the two. Reaching it with an extra simple downcase
      # comparison would close this one pair and open others, because simple
      # lowercase is not symmetric: it would also pair İ (U+0130) with i, and
      # the caseless example above asserts that pcre2 refuses exactly that.
      #   pcre2: /ß/i matches ẞ, and /ẞ/i matches ß.
      Iyi::Rx::Pattern.compile("ß", true).matches?("\u{1E9E}").should be_false
      Iyi::Rx::Pattern.compile("\u{1E9E}", true).matches?("ß").should be_false
      # each still matches itself, so the gap is the cross pairing and nothing
      # wider than it
      rx_should_agree("ß", "ß", ignore_case: true)
      rx_should_agree("\u{1E9E}", "\u{1E9E}", ignore_case: true)
      rx_should_agree("ß", "ss", ignore_case: true)
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

    it "agrees on lookaround, all four forms" do
      # iyi: one row per shape, with two subjects and the empty one appended by
      # the driver. The empty subject is the case that catches a pre-pass
      # indexing off the end of its own bitmap, which is why every row gets it.
      lookaround = {
        # positive lookahead: the text after the match is checked and not
        # consumed, so the match ends before it
        {"a(?=b)", "xaby", "xacy"},
        {"a(?=bc)", "abcd", "abdc"},
        {"\\w+(?=,)", "one,two", "one two"},
        {"(?=\\d)\\w+", "1abc", "abc"},
        # an inner pattern that looks further than the match reaches
        {"(?=.*z)\\w+", "abz", "abc"},
        # negative lookahead
        {"a(?!b)", "ac", "ab"},
        {"a(?!bc)", "abd", "abc"},
        {"foo(?![0-9])", "foo!", "foo9"},
        {"(?!\\d)\\w", "a1", "1"},
        # positive lookbehind
        {"(?<=a)b", "abc", "xbc"},
        {"(?<=ab)c", "abc", "axc"},
        {"(?<=,)\\w+", "one,two", "one two"},
        {"(?<=\\d)[a-z]", "1a", "aa"},
        # negative lookbehind
        {"(?<!a)b", "xb", "ab"},
        {"(?<!ab)c", "axc", "abc"},
        {"(?<![0-9])[a-z]", "!a", "1a"},
        {"\\w+(?<!s)", "cat", "s"},
        # one either side of the same atom, and two at the same position
        {"(?<=\\s)\\w+(?=\\s)", "a bb c", "abb"},
        {"(?=\\w)(?=[a-z])\\w+", "abc", "ABC"},
        # under a quantifier, where the loop's empty round has to carry the
        # assertion too or the quantified form answers differently from the bare
        # one, and inside a capturing group, which is allowed: it is a capturing
        # group INSIDE an assertion that is refused, not one around it
        {"(?:(?<=a)b)+", "abb", "xb"},
        {"((?<=a)b)", "ab", "xb"},
        {"(?=a)*a", "a", "b"},
        {"(?=a)+a", "xa", "xb"},
        {"(?=a){2}a", "a", "b"},
        {"(?=a)*?a", "a", "b"},
        {"((?=a))a", "a", "b"},
        # the fold flag reaches an assertion's own program, and stops at the
        # group that set it
        {"(?i)(?=A)a", "A", "b"},
        {"(?=(?i:A))a", "xa", "A"},
        # nested: an inner assertion is a property of a position too, so it is
        # one bitmap read from inside another bitmap's automaton
        {"(?=a(?=b))\\w\\w", "xab", "xac"},
        {"(?=a(?!b))\\w", "ac", "ab"},
        {"(?<=(?<=a)b)c", "abc", "xbc"},
        # three deep, both ways round
        {"(?=a(?=b(?=c)))\\w\\w\\w", "abc", "abd"},
        {"(?<=(?<=(?<=a)b)c)d", "abcd", "xbcd"},
      }

      lookaround.each do |source, hit, miss|
        rx_should_agree(source, hit)
        rx_should_agree(source, miss)
        rx_should_agree(source, "")
      end
    end

    it "agrees on lookaround at the subject's edges" do
      # iyi: an assertion is a question about a position, and the two ends are
      # the positions a bitmap is easiest to get wrong at. Rows whose whole
      # pattern is an assertion match empty, so the only thing the two engines
      # can disagree about is where.
      edges = {
        {"(?<=^a)b", "ab", "xab"},
        {"(?<=\\Aa)b", "ab", "aab"},
        {"(?<=^)a", "ab", "\na"},
        {"a(?=$)", "a", "ab"},
        {"a(?=$)", "ba\n", "a\nb"},
        {"a(?=\\z)", "ba", "a\n"},
        {"^(?=.*b)\\w+", "axb", "axc"},
        {"\\w+(?<=^\\w)", "ab", " ab"},
        {"(?=b)", "ab", "aa"},
        {"(?<=b)", "ba", "aa"},
        {"(?!b)", "b", "a"},
        {"(?<!b)", "ba", "b"},
        # an inner pattern that matches empty, so the assertion always holds
        {"(?=)a", "a", "b"},
        {"(?<=)a", "a", "b"},
        {"(?=a*)b", "b", "c"},
      }

      edges.each do |source, first, second|
        rx_should_agree(source, first)
        rx_should_agree(source, second)
        rx_should_agree(source, "")
      end
    end

    it "agrees on the boundary lookaround the bind tool needs" do
      # iyi: src/compiler/iyi/tools/bind.cr renames a bound identifier only where
      # it stands alone, which is a negative lookbehind and a negative lookahead
      # around an escaped name. That pair is the reason this work exists, so the
      # subjects are the shapes bind really meets. The second pattern is bind's
      # own boundary rule exactly: `:` blocks a match before the name, because
      # otherwise `Other::MyLib::Entry` reads as a `MyLib::` of its own, and does
      # not block one after it, because `Entry::Foo` really does start with the
      # name.
      standalone = "(?<![A-Za-z0-9_])Entry(?![A-Za-z0-9_])"
      qualified = "(?<![A-Za-z0-9_:])Entry(?![A-Za-z0-9_])"
      subjects = [
        "Entry",         # the whole subject
        "Entry rest",    # at the start
        "rest Entry",    # at the end
        "(Entry)",       # punctuation either side
        "_Entry",        # an underscore before makes it a longer name
        "Entry_",        # and after
        "1Entry",        # so does a digit
        "Entry9",
        "_Entry_",
        "9Entry9",
        "MyEntry",       # buried inside a longer identifier
        "Entrys",
        "Entry, Entry",  # twice in one subject
        "Entry Entry",
        "Foo::Entry",    # qualified
        "Entry::Foo",
        "Other::MyEntry",
        "Array(Entry)",
        "entry",         # a name is case sensitive
        "",
      ]

      {standalone, qualified}.each do |source|
        subjects.each do |subject|
          rx_should_agree(source, subject)
          # gsub is the call bind actually makes
          rx_gsub_should_agree(source, subject, "Renamed")
          rx_scan_should_agree(source, subject)
        end
      end
    end

    it "matches a variable length lookbehind, which pcre2 will not compile" do
      # iyi: pcre2 matches a lookbehind by stepping back a known number of
      # characters and trying from there, so it has to know that number, and
      # refuses the pattern when it cannot: "length of lookbehind assertion is
      # not limited". There is no number to know here. `(?<=L)` is answered by
      # simulating `Σ*L` forward over the subject once and reading the bit at the
      # position, so an unbounded L costs exactly what a fixed one costs. Being
      # more capable than the oracle is deliberate, and rx_should_span still
      # holds us to the oracle wherever it does compile the pattern.
      rx_should_span("(?<=ab+)c", "abbbc", 4, 5)
      rx_should_span("(?<=ab+)c", "abc", 2, 3)
      rx_should_not_match("(?<=ab+)c", "ac")
      rx_should_not_match("(?<=ab+)c", "bc")
      rx_should_not_match("(?<=ab+)c", "")
      rx_should_span("(?<=a.*)z", "a123z", 4, 5)
      rx_should_not_match("(?<=a.*)z", "z")
      rx_should_span("(?<=\\w+,)\\d+", "key,42", 4, 6)
      rx_should_span("(?<!ab+)c", "axc", 2, 3)
      rx_should_not_match("(?<!ab+)c", "abbc")

      # The bounded forms pcre2 does compile, where the oracle can still speak.
      {
        {"(?<=a{1,3})c", "aac"},
        {"(?<=a{1,3})c", "c"},
        {"(?<=a?b)c", "bc"},
        {"(?<=a?b)c", "abc"},
        {"(?<=(?:ab|c))d", "abd"},
        {"(?<=(?:ab|c))d", "cd"},
        {"(?<=(?:ab|c))d", "xd"},
      }.each { |source, subject| rx_should_agree(source, subject) }
    end

    it "agrees on named groups, which are numbered groups that also have a name" do
      named = {
        {"(?<word>\\w+)", "hi there", "!!"},
        {"(?<a>x)(?<b>y)", "xy", "yx"},
        {"(?'q'\\d+)", "a42", "abc"},
        {"(?P<p>[a-z]+)", "ABc", "AB"},
        # named and unnamed groups share one numbering, in source order
        {"(?<lead>\\w)(\\w)(?<tail>\\w)", "abc", "ab"},
        {"(\\w)(?<mid>\\w)(\\w)", "abc", "ab"},
        {"(?<opt>x)?y", "xy", "y"},
        {"(?<alt>a)|(?<other>b)", "b", "c"},
        {"(?<outer>(?<inner>a)b)", "ab", "ba"},
      }

      named.each do |source, hit, miss|
        rx_should_agree(source, hit)
        rx_should_agree(source, miss)
        rx_should_agree(source, "")
      end

      match = Iyi::Rx::Pattern.compile("(?<year>\\d{4})-(?<month>\\d{2})").match("on 2026-08 ok").not_nil!
      match["year"].should eq("2026")
      match["month"].should eq("08")
      # a name reaches exactly what its number reaches
      match["year"].should eq(match[1])
      match["month"].should eq(match[2])
      match.begin("year").should eq(3)
      match.end("year").should eq(7)
      match.begin("month").should eq(8)
      match.end("month").should eq(10)
      # and the oracle numbers them the same way round
      reference = Regex.new("(?<year>\\d{4})-(?<month>\\d{2})").match("on 2026-08 ok").not_nil!
      match["year"].should eq(reference["year"])
      match[1].should eq(reference[1])
      match[2].should eq(reference[2])

      expect_raises(KeyError, /no capture group named "day"/) { match["day"] }
      expect_raises(KeyError, /no capture group named "day"/) { match.begin("day") }

      # a named group that did not participate is absent, not empty, which is
      # the same distinction the numeric index draws
      optional = Iyi::Rx::Pattern.compile("a(?<mid>x)?b").match("ab").not_nil!
      optional["mid"].should be_nil
      optional[1].should be_nil
    end

    it "keeps an assertion linear in the subject" do
      # iyi: the reason lookaround is built out of bitmaps rather than out of a
      # sub-match. Answering `(?<!\w)needle(?!\w)` by running a sub-VM at each
      # start position over this subject is on the order of 10^9 character steps;
      # one pass per assertion is on the order of 10^5. The gsub below is the
      # same point for a sweep: the bitmaps are computed for the whole sweep
      # rather than for each of its 20_000 start offsets, so a scan stays linear
      # in the subject too.
      elapsed = Time.measure do
        haystack = ("ab " * 20_000) + "needle"
        found = Iyi::Rx::Pattern.compile("(?<![A-Za-z0-9_])needle(?![A-Za-z0-9_])").match(haystack).not_nil!
        found.begin(0).should eq(60_000)
        found.end(0).should eq(60_006)

        every = Iyi::Rx.gsub("ab " * 20_000, Iyi::Rx::Pattern.compile("(?<![A-Za-z0-9_])ab(?![A-Za-z0-9_])"), "xy")
        every.should eq("xy " * 20_000)
      end
      # Loose enough not to flake on a loaded machine, and still orders of
      # magnitude below what a per-position sub-VM would need.
      elapsed.should be < 5.seconds
    end

    it "agrees on lookaround when matching from a start offset" do
      # iyi: the bitmaps cover the whole subject and are computed once per match
      # call, so a start offset moves only where the machine begins. A lookbehind
      # still sees the text before the offset, which is text the machine itself
      # never visits, and that is the property a pre-pass starting at the offset
      # would quietly get wrong.
      {
        {"(?<=a)b", "abab", 0},
        {"(?<=a)b", "abab", 1},
        {"(?<=a)b", "abab", 2},
        {"(?<=a)b", "abab", 3},
        {"(?<=a)b", "abab", 4},
        {"(?<!a)b", "abcb", 0},
        {"(?<!a)b", "abcb", 2},
        {"a(?=b)", "abab", 1},
        {"a(?=b)", "abab", 2},
        {"a(?!b)", "abac", 1},
        {"(?<![A-Za-z0-9_])Entry(?![A-Za-z0-9_])", "Entry Entry", 0},
        {"(?<![A-Za-z0-9_])Entry(?![A-Za-z0-9_])", "Entry Entry", 1},
        {"(?<![A-Za-z0-9_])Entry(?![A-Za-z0-9_])", "Entry Entry", 6},
        # ^ inside a lookbehind still means byte 0, never the start offset
        {"(?<=^a)b", "abab", 0},
        {"(?<=^a)b", "abab", 2},
        {"(?=$)", "ab", 1},
      }.each { |source, subject, start| rx_should_agree(source, subject, start: start) }

      pattern = Iyi::Rx::Pattern.compile("(?<=a)b")
      pattern.match("ab", 1).not_nil!.begin(0).should eq(1)
      pattern.match("abab", 2).not_nil!.begin(0).should eq(3)
      pattern.match("abab", 4).should be_nil
      # past the end is still nil rather than a raise, bitmaps or not
      pattern.match("abab", 9).should be_nil
    end

    it "is right where pcre2 contradicts itself on a mixed length lookbehind" do
      # iyi: the one place the oracle cannot be followed. `(?<=A|B)` is the union
      # of `(?<=A)` and `(?<=B)`, because an alternation matches exactly when one
      # of its branches does. pcre2 matches a lookbehind by stepping back a fixed
      # number of characters, and where the branches differ in length and one is
      # zero width it reports the group as holding at positions where neither
      # branch holds. That is not a semantics to defer to, it is pcre2
      # disagreeing with itself, so what is asserted here is pcre2's own answers
      # for the branches, never its answer for the pair.
      left = Iyi::Rx::Pattern.compile("(?<=a)")
      right = Iyi::Rx::Pattern.compile("(?<=$)")
      pair = Iyi::Rx::Pattern.compile("(?<=(?:a|$))")
      reference_left = Regex.new("(?<=a)")
      reference_right = Regex.new("(?<=$)")
      reference_pair = Regex.new("(?<=(?:a|$))")

      # At byte 0 of "a", pcre2 says neither branch holds, and then says the pair
      # does. Both cannot be true.
      rx_reference_holds_at?(reference_left, "a", 0).should be_false
      rx_reference_holds_at?(reference_right, "a", 0).should be_false
      rx_reference_holds_at?(reference_pair, "a", 0).should be_true
      # the engine matches pcre2 branch by branch, and stays consistent on the pair
      rx_holds_at?(left, "a", 0).should be_false
      rx_holds_at?(right, "a", 0).should be_false
      rx_holds_at?(pair, "a", 0).should be_false

      # The law itself, over a corpus. Each branch is still held to pcre2, so the
      # engine only leaves the oracle where the oracle stops being coherent, and
      # a lookahead is held to it whole because pcre2 has no such trouble there.
      {"a", "b", ".", "\\w", "$", "\\b", "^", "c{1,2}"}.each do |first|
        {"a", ".", "$", "\\b", "x"}.each do |second|
          only_first = Iyi::Rx::Pattern.compile("(?<=(?:#{first}))")
          only_second = Iyi::Rx::Pattern.compile("(?<=(?:#{second}))")
          behind = Iyi::Rx::Pattern.compile("(?<=(?:#{first}|#{second}))")
          ahead = Iyi::Rx::Pattern.compile("(?=(?:#{first}|#{second}))")
          reference_ahead = Regex.new("(?=(?:#{first}|#{second}))")
          {"", "a", "ab", "baa", "a b"}.each do |subject|
            rx_should_agree("(?<=(?:#{first}))", subject)
            rx_should_agree("(?<=(?:#{second}))", subject)
            (0..subject.bytesize).each do |at|
              union = rx_holds_at?(only_first, subject, at) || rx_holds_at?(only_second, subject, at)
              rx_holds_at?(behind, subject, at).should eq(union)
              rx_holds_at?(ahead, subject, at).should eq(rx_reference_holds_at?(reference_ahead, subject, at))
            end
          end
        end
      end
    end
  end

  describe "refused syntax" do
    it "raises SyntaxError for every construct outside the supported set" do
      # iyi: SPEC.md III.10 takes Go's trade, and the line it draws is regular
      # languages. A backreference, a recursion, a subroutine call and a
      # conditional are not regular, so no simulation answers them and no amount
      # of care makes them linear. An atomic group and a possessive quantifier
      # are the other kind of refusal: controls for a backtracker, and there is
      # no backtracker here to control. Lookaround has left this list, because a
      # lookaround over a regular inner pattern is itself regular and is now
      # answered by a pre-pass; what remains of it here is the capturing group
      # inside one, which would need the sub-match that pre-pass never performs.
      # `\p{...}` has left it for the five categories a public stdlib predicate
      # answers exactly, and the rows below are what is left of it: a category
      # the stdlib cannot answer without approximating, and a script name.
      # Refusing loudly beats silently matching wrong, so each of these must
      # raise at compile and carry a position. None is compiled against pcre2;
      # the oracle has nothing to say about constructs the engine must not
      # accept, and it accepts several of these itself.
      refused = {
        {"backreference \\1", "(a)\\1"},
        {"named backreference \\k", "(?<n>a)\\k<n>"},
        {"capturing group inside a lookahead", "(?=(a))"},
        {"capturing group inside a negative lookahead", "a(?!(b))"},
        {"capturing group inside a lookbehind", "(?<=(a))b"},
        {"capturing group nested two assertions deep", "(?=x(?<=(a)))"},
        {"named group inside a lookahead", "(?=(?<n>a))"},
        {"duplicate group name", "(?<n>a)(?<n>b)"},
        {"duplicate group name across syntaxes", "(?<n>a)(?P<n>b)"},
        {"group name starting with a digit", "(?<1n>a)"},
        {"empty group name", "(?<>a)"},
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
        {"property \\p{Nd}, which the stdlib cannot answer exactly", "\\p{Nd}"},
        {"negated property \\P{Nd}", "\\P{Nd}"},
        {"property \\p{Nl}", "\\p{Nl}"},
        {"property \\p{Lt}", "\\p{Lt}"},
        {"property \\p{Z}", "\\p{Z}"},
        {"short property \\pZ", "\\pZ"},
        {"script name \\p{Greek}", "\\p{Greek}"},
        {"script name in a class", "[\\p{Latin}]"},
        {"pcre2's own \\p{^L} negation spelling", "\\p{^L}"},
        {"empty property name", "\\p{}"},
        {"unterminated property name", "\\p{L"},
        {"bare \\p", "\\p"},
        {"short property with no letter", "[\\p]"},
        {"empty \\x{}", "\\x{}"},
        {"unterminated \\x{", "\\x{41"},
        {"\\x{} above U+10FFFF", "\\x{110000}"},
        {"\\x{} with a digit run that would overflow", "\\x{FFFFFFFFFFFF}"},
        {"\\x{} naming a surrogate", "\\x{D800}"},
        {"\\x{} naming the last surrogate", "\\x{DFFF}"},
        {"\\x{} in a class with no digits", "[\\x{}]"},
        {"\\x with no digits at all", "\\x"},
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

    it "names what is wrong in a \\x{...} or \\p{...} refusal, and where" do
      # iyi: the table above proves each of these raises with a position. What
      # it cannot prove is that the four \x{...} refusals are four DIFFERENT
      # refusals, which matters because they are the four ways pcre2 refuses one
      # too: no digits, no closing brace, past the last codepoint, and a
      # surrogate, which pcre2 in UTF mode will not compile either. Both engines
      # refusing the same shapes is what keeps them from disagreeing about a
      # codepoint no UTF-8 subject can carry.
      cases = {
        {"\\x{}", /no digits in/},
        {"[\\x{}]", /no digits in/},
        {"\\x{41", /missing closing brace/},
        {"\\x{4G}", /missing closing brace/},
        {"\\x{110000}", /above U\+10FFFF/},
        {"\\x{FFFFFFFFFFFF}", /above U\+10FFFF/},
        {"\\x{D800}", /surrogate/},
        {"\\x{DFFF}", /surrogate/},
        {"\\x", /malformed \\x escape/},
        {"\\p{Nd}", /unsupported unicode property/},
        {"\\p{Greek}", /unsupported unicode property/},
        {"\\p{}", /unsupported unicode property/},
        {"\\p{L", /missing closing brace/},
        {"\\p", /malformed \\p escape/},
        {"[\\p]", /malformed \\p escape/},
      }

      cases.each do |source, message|
        error = expect_raises(Iyi::Rx::SyntaxError, message) do
          Iyi::Rx::Pattern.compile(source)
        end
        error.position.should be >= 0
        error.position.should be <= source.bytesize
      end

      # the position points at the escape that failed, not at the end of the
      # pattern, so a long pattern still says where to look
      error = expect_raises(Iyi::Rx::SyntaxError, /above U\+10FFFF/) do
        Iyi::Rx::Pattern.compile("abc\\x{110000}def")
      end
      error.position.should eq(5)
    end

    it "counts an assertion's program against the same instruction cap" do
      # iyi: the cap is one budget for the whole pattern, the main program and
      # every assertion's program together. Two budgets would let a pattern buy
      # twice the ceiling by moving the expansion inside an assertion.
      expect_raises(Iyi::Rx::SyntaxError, /exceeds 200000 instructions/) do
        Iyi::Rx::Pattern.compile("(?=(?:a{1000}){1000})")
      end
      # the same expansion outside an assertion is refused identically
      expect_raises(Iyi::Rx::SyntaxError, /exceeds 200000 instructions/) do
        Iyi::Rx::Pattern.compile("(?:a{1000}){1000}")
      end
      # and one that fits still compiles and runs
      fits = Iyi::Rx::Pattern.compile("(?=(?:a{50}){50})a")
      fits.matches?("a" * 20).should be_false
      fits.matches?("a" * 2_500).should be_true
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

    it "does not copy the tail twice for an empty match at the end of the subject" do
      # iyi: a real defect, found by the lookaround work and older than it.
      # `gsub_impl` finished on an empty match at the very end without moving its
      # cursor to it, then appended everything from the cursor to the end a
      # second time: `Iyi::Rx.gsub("abc", /$/, "<>")` answered "abc<>abc" where
      # pcre2 answers "abc<>". Nothing about the match was wrong, and `scan`
      # agreed with pcre2 throughout, which is why nothing caught it: only the
      # rebuilt string was wrong. Lookaround makes it easy to reach because an
      # assertion is the ordinary way to write a pattern that matches empty at
      # the end and nowhere before it.
      Iyi::Rx.gsub("abc", Iyi::Rx::Pattern.compile("$"), "<>").should eq("abc<>")

      {"$", "\\z", "\\Z", "b*$", "(?=$)", "(?=\\z)", "(?!a)", "(?<=c)", "c(?=$)"}.each do |source|
        {"", "a", "abc", "aa", "abc\n", "a b c"}.each do |subject|
          rx_gsub_should_agree(source, subject, "<\\0>")
          rx_scan_should_agree(source, subject)
          rx_sub_should_agree(source, subject, "<\\0>")
        end
      end
    end
  end
end
