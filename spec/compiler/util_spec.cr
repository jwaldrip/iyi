require "spec"
require "../support/tempfile"
require "compiler/crystal/util"

describe Crystal do
  # iyi: a name that is a prefix of another name is not a directory that
  # contains it. Working in `/tmp/x/crystal` with a cache directory next to it
  # at `/tmp/x/crystal-cache`, this used to answer `-cache/…`, and the compiler
  # wrote its object files to a relative path that does not exist. What came
  # out was "No such file or directory" from LLVM, naming nothing.
  describe "relative_filename" do
    it "makes a path under the working directory relative to it" do
      Dir.cd(Dir.tempdir) do
        here = Dir.current
        Iyi.relative_filename(File.join(here, "a", "b")).should eq File.join("a", "b")
      end
    end

    it "leaves a sibling whose name starts the same alone" do
      with_tempfile("relative-filename") do |base|
        inside = File.join(base, "crystal")
        Dir.mkdir_p(inside)
        Dir.cd(inside) do
          sibling = File.join(base, "crystal-cache", "unit.o")
          Iyi.relative_filename(sibling).should eq sibling
        end
      end
    end
  end

  describe "normalize_path" do
    sep = {{ flag?(:win32) ? "\\" : "/" }}

    it { Iyi.normalize_path("a").should eq ".#{sep}a" }
    it { Iyi.normalize_path("./a/b").should eq ".#{sep}a#{sep}b" }
    it { Iyi.normalize_path("../a/b").should eq ".#{sep}..#{sep}a#{sep}b" }
    it { Iyi.normalize_path("/foo/bar").should eq "#{sep}foo#{sep}bar" }

    {% if flag?(:win32) %}
      it { Iyi.normalize_path("C:\\foo\\bar").should eq "C:\\foo\\bar" }
      it { Iyi.normalize_path("C:foo\\bar").should eq "C:foo\\bar" }
      it { Iyi.normalize_path("\\foo\\bar").should eq "\\foo\\bar" }
      it { Iyi.normalize_path("foo\\bar").should eq ".\\foo\\bar" }
    {% end %}
  end
end
