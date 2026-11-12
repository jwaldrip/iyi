require "json"
require "crystal/digest/md5"
require "../build_inputs"
require "./compiler_env"

module Iyi::Stale
  # What a file was when the stale build child looked at it, as the inputs
  # record keeps it: one `stat` (kind, size, modification and change times in
  # nanoseconds, device and inode), and the content's MD5 when the times cannot
  # vouch for it (`BuildInputs.racy?`, taken over the later of the two times).
  #
  # POSIX only. Elsewhere the stamp is the recorder's own, without a change time
  # or an inode, and no record is written (`Check.run`).
  module FileStamp
    # The stamp of *path*, from a single stat. A caller takes it before the
    # compiler reads the file, so an edit between the two reaches the compiler
    # and not the record.
    def self.of(path : String) : BuildInputs::Stamp
      {% if flag?(:unix) %}
        if LibC.stat(path, out stat) == 0
          {% if flag?(:darwin) %}
            mtime = stat.st_mtimespec.tv_sec.to_i64 * 1_000_000_000_i64 + stat.st_mtimespec.tv_nsec.to_i64
            ctime = stat.st_ctimespec.tv_sec.to_i64 * 1_000_000_000_i64 + stat.st_ctimespec.tv_nsec.to_i64
          {% else %}
            mtime = stat.st_mtim.tv_sec.to_i64 * 1_000_000_000_i64 + stat.st_mtim.tv_nsec.to_i64
            ctime = stat.st_ctim.tv_sec.to_i64 * 1_000_000_000_i64 + stat.st_ctim.tv_nsec.to_i64
          {% end %}
          mode = stat.st_mode.to_u32 & 0o170000_u32
          kind =
            if mode == 0o100000_u32
              BuildInputs::Kind::File
            elsif mode == 0o040000_u32
              BuildInputs::Kind::Directory
            else
              BuildInputs::Kind::Other
            end
          size = kind.file? ? stat.st_size.to_i64 : 0_i64
          digest = nil
          if kind.file? && BuildInputs.racy?(Math.max(mtime, ctime), BuildInputs.now)
            digest = fingerprint(path)
          end
          BuildInputs::Stamp.new(kind, size, mtime, digest, ctime, stat.st_dev.to_u64, stat.st_ino.to_u64)
        else
          BuildInputs::ABSENT
        end
      {% else %}
        BuildInputs.stamp(path)
      {% end %}
    end

    # The MD5 of the content of *path*, read with the recorder paused so the
    # read is not itself an input. Nil when it cannot be read.
    def self.fingerprint(path : String) : String?
      content = BuildInputs.paused { ::File.read(path) }
      Crystal::Digest::MD5.hexdigest(content)
    rescue IO::Error
      nil
    end
  end

  # The inputs record a stale build writes for `--stale-inputs`: what the build
  # read, what it found, and the environment it saw, for the fast path. Written
  # by `Check.run` for a reusable build whose recorder heard every input, and
  # removed by the build verb when something after the check says otherwise.
  module InputsFile
    FORMAT  = "iyi-stale-inputs"
    VERSION = 1

    # The environment names a build reads whether or not its recorder sees
    # them: some before the recorder starts, some in child processes. They are
    # recorded in every record, so a change to any of them is seen.
    def self.forced_env : Array(String)
      (CompilerEnv::LOCATOR_VARS.to_a + BuildInputs::CHILD_ENV + BuildInputs::LINK_ONLY_ENV +
        BuildInputs::CODEGEN_ONLY_ENV +
        %w(CRYSTAL_WORKERS IYI_FORK_PROBE IYI_LIBRARY_PATH CRYSTAL_LIBRARY_PATH IYI_EXEC_PATH CRYSTAL_EXEC_PATH)).uniq
    end

    # Writes the record for *inputs* to *path*, through a temporary file and a
    # rename, so a reader sees the old record or the new one and never half of
    # either.
    def self.write(path : String, inputs : BuildInputs, local_build : String, portable_build : String) : Nil
      BuildInputs.paused do
        observed = inputs.observed_env.dup
        forced_env.each do |name|
          observed[name] = Crystal::System::Env.get(name) unless observed.has_key?(name)
        end

        dir = File.dirname(path)
        Dir.mkdir_p(dir) unless dir.empty? || Dir.exists?(dir)
        tmp = "#{path}.tmp.#{Process.pid}"
        File.open(tmp, "w") do |io|
          JSON.build(io) do |json|
            json.object do
              json.field "format", FORMAT
              json.field "version", VERSION
              json.field "local_build", local_build
              json.field "portable_build", portable_build
              json.field "observed_env" do
                json.object do
                  observed.keys.sort!.each do |name|
                    value = observed[name]
                    json.field name do
                      if value
                        json.string value
                      else
                        json.null
                      end
                    end
                  end
                end
              end
              json.field "env_enumerated", inputs.observed_enumerated?
              json.field "files" do
                json.array do
                  inputs.files.keys.sort!.each do |file|
                    stamp = inputs.files[file]
                    json.array do
                      json.string file
                      json.string stamp.kind.to_s.downcase
                      json.number stamp.size
                      json.number stamp.mtime
                      json.number stamp.ctime
                      json.number stamp.dev
                      json.number stamp.ino
                      if digest = stamp.digest
                        json.string digest
                      else
                        json.null
                      end
                    end
                  end
                end
              end
              json.field "listings" do
                json.object do
                  inputs.listings.keys.sort!.each do |dir_path|
                    names = inputs.listings[dir_path]
                    json.field dir_path do
                      if names
                        json.array do
                          names.each { |entry| json.string entry }
                        end
                      else
                        json.null
                      end
                    end
                  end
                end
              end
              json.field "pkg_config" do
                json.array do
                  inputs.pkg_config.each do |module_name, static_link, flags|
                    json.array do
                      json.string module_name
                      json.bool static_link
                      if flags
                        json.string flags
                      else
                        json.null
                      end
                    end
                  end
                end
              end
            end
          end
        end
        File.rename(tmp, path)
      end
    end
  end
end
