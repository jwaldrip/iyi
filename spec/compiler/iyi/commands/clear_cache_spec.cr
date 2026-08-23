require "../../../spec_helper"

class Iyi::CacheDir
  class_setter instance

  def initialize(@dir)
    Dir.mkdir_p(dir)
  end
end

describe Iyi::Command do
  describe "clear_cache" do
    around_each do |example|
      old_cache_dir = CacheDir.instance
      temp_dir_name = File.tempname
      begin
        CacheDir.instance = CacheDir.new(temp_dir_name)
        example.run
      ensure
        FileUtils.rm_rf(temp_dir_name)
        CacheDir.instance = old_cache_dir
      end
    end

    it "clears any cached compiler files" do
      file_path = File.tempname(dir: CacheDir.instance.dir)
      Dir.mkdir_p(File.dirname(file_path))
      File.touch(file_path)
      File.exists?(file_path).should be_true

      Iyi::Command.run(["clear_cache"])

      File.exists?(file_path).should be_false
      File.exists?(CacheDir.instance.dir).should be_false
    end
  end
end
