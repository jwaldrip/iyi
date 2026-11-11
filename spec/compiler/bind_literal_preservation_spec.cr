require "../spec_helper"
require "./spec_helper"
require "../../src/compiler/iyi/tools/bind"

module Iyi
  describe "Literal preservation in bind text rewrites" do
    describe "strip_root" do
      it "leaves plain string literals as written" do
        strip_root(%("Root::X"), "Root").should eq(%("Root::X"))
        strip_root(%("before Root::X after"), "Root").should eq(%("before Root::X after"))
      end

      it "leaves percent string literals as written" do
        strip_root(%(%q(Root::X)), "Root").should eq(%(%q(Root::X)))
        strip_root(%(%Q(Root::X)), "Root").should eq(%(%Q(Root::X)))
        strip_root(%(%(Root::X)), "Root").should eq(%(%(Root::X)))
      end

      it "leaves array literals as written" do
        strip_root(%(%w(Root::X Other)), "Root").should eq(%(%w(Root::X Other)))
        strip_root(%(%i(Root::X Other)), "Root").should eq(%(%i(Root::X Other)))
      end

      it "leaves regex literals as written" do
        strip_root(%(/Root::X/), "Root").should eq(%(/Root::X/))
        strip_root(%(%r(Root::X)), "Root").should eq(%(%r(Root::X)))
      end

      it "leaves comments as written" do
        strip_root("# Root::X\n", "Root").should eq("# Root::X\n")
      end

      it "leaves character literals as written" do
        strip_root(%('R'), "Root").should eq(%('R'))
      end

      it "leaves heredoc bodies as written" do
        heredoc = "<<-EOF\nRoot::X\nEOF"
        strip_root(heredoc, "Root").should eq(heredoc)
      end

      it "rewrites code inside string interpolation while preserving the literal surrounding it" do
        source = %("before \#{Root::X} after")
        strip_root(source, "Root").should eq(%("before \#{X} after"))
      end

      it "handles escaped interpolation characters in literals" do
        source = %("before \\\#{Root::X} after")
        strip_root(source, "Root").should eq(source)
      end

      it "rewrites code in nested interpolation while preserving all literal segments" do
        source = %("outer \#{"inner \#{Root::X} more"} end")
        strip_root(source, "Root").should eq(%("outer \#{"inner \#{X} more"} end"))
      end

      it "preserves surrounding literal text when interpolation contains a hash" do
        source = %("before \#{ {x: Root::X}; Root::Y } after Root::X")
        strip_root(source, "Root").should eq(%("before \#{ {x: X}; Y } after Root::X"))
      end

      it "handles escaped quotes inside nested interpolation" do
        source = %("a \#{"b \\"nested\\" \#{Root::X}"} c")
        strip_root(source, "Root").should eq(%("a \#{"b \\"nested\\" \#{X}"} c"))
      end
    end

    describe "replace_word" do
      it "replaces identifiers in code while preserving occurrences in string literals" do
        source = %(old = "old \#{old} old")
        replace_word(source, "old", "new").should eq(%(new = "old \#{new} old"))
      end

      it "preserves percent literals, heredocs and regexes" do
        replace_word(%(%q(old)), "old", "new").should eq(%(%q(old)))
        replace_word(%(/old/), "old", "new").should eq(%(/old/))
        heredoc = "<<-EOF\nold\nEOF"
        replace_word(heredoc, "old", "new").should eq(heredoc)
      end

      it "replaces identifiers inside nested interpolations" do
        source = %("a \#{"b \#{old} c"} d")
        replace_word(source, "old", "new").should eq(%("a \#{"b \#{new} c"} d"))
      end
    end
  end
end
