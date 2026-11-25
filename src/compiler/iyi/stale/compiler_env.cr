require "crystal/digest/sha256"
require "./encoding"
require "../build_inputs"

module Iyi::Stale
  module CompilerEnv
    enum VariableClass
      Locator
      Display
      Excluded
      Value
    end

    LOCATOR_VARS = Set{
      "IYI_OPTS",
      "CRYSTAL_OPTS",
      "IYI_PATH",
      "CRYSTAL_PATH",
      "IYI_CACHE_DIR",
      "CRYSTAL_CACHE_DIR",
      "HOME",
      "XDG_CACHE_HOME",
      "LOCALAPPDATA",
      "USERPROFILE",
    }

    DISPLAY_VARS = Set{
      "DUMP",
      "IYI_DUMP_TYPE_INFO",
      "IYI_DUMP_TYPE_ID",
      "IYI_TDF",
      "IYI_SYM",
      "IYI_HEADER_CENSUS",
      "IYI_DEBUG_CODEGEN",
      "IYI_PROF",
      "IYI_WARM",
      "IYI_FORK_TRACE",
      "NO_COLOR",
      "TERM",
    }

    def self.variable_class(name : String) : VariableClass
      return VariableClass::Locator if LOCATOR_VARS.includes?(name)
      return VariableClass::Display if DISPLAY_VARS.includes?(name)
      return VariableClass::Excluded if BuildInputs::CHILD_ENV.includes?(name)
      VariableClass::Value
    end

    def self.value_class?(name : String) : Bool
      variable_class(name).value?
    end

    def self.display_class?(name : String) : Bool
      variable_class(name).display?
    end

    def self.locator_class?(name : String) : Bool
      variable_class(name).locator?
    end

    def self.excluded_class?(name : String) : Bool
      variable_class(name).excluded?
    end

    # Computes CompilerEnvFp = D("cenv", sorted (name, value | absent) of value-class reads).
    # An enumeration during the check adds every variable that is not display or locator.
    def self.fp(inputs : BuildInputs) : Digest
      if inputs.env_enumerated?
        inputs.env_enumerated
      end
      fp(inputs.env, inputs.env_enumerated?)
    end

    # Whether a variable the build read is one of the entries the fingerprint
    # is made of.
    def self.counted?(name : String, enumerated : Bool) : Bool
      if enumerated
        v_class = variable_class(name)
        !v_class.display? && !v_class.locator?
      else
        variable_class(name).value?
      end
    end

    def self.fp(env : Hash(String, String?), enumerated : Bool = false) : Digest
      entries = [] of {String, String?}
      env.each do |name, val|
        entries << {name, val} if counted?(name, enumerated)
      end

      entries.sort_by! { |name, _| name }

      Stale.d("cenv") do |encoder|
        encoder.list(entries.size) do |enc|
          entries.each do |name, val|
            enc.str(name)
            if val
              enc.str(val)
            else
              enc.absent
            end
          end
        end
      end
    end

    def self.fp : Digest
      if inputs = BuildInputs.current
        fp(inputs)
      else
        fp({} of String => String?)
      end
    end

    # iyi: `IYI_STALE_CENV_DUMP=FILE` appends to FILE what this build's
    # fingerprint was made of: a header with the file being built, then a line
    # for each variable the build read, `*` when it counts. A test that misses
    # with "compiler environment changed" does not say which variable differs,
    # and the blocks of two runs of one test do. Read with
    # `Crystal::System::Env`, which the recorder does not see, so asking for
    # the dump changes nothing it records.
    def self.dump(filename : String) : Nil
      path = Crystal::System::Env.get("IYI_STALE_CENV_DUMP")
      return unless path && !path.empty?
      return unless inputs = BuildInputs.current
      BuildInputs.paused do
        ::File.open(path, "a") do |io|
          io << "build file=" << filename << " pid=" << Process.pid << " enumerated=" << inputs.env_enumerated? << '\n'
          inputs.env.to_a.sort_by { |name, _| name }.each do |name, val|
            io << (counted?(name, inputs.env_enumerated?) ? '*' : ' ') << ' ' << name << '=' << (val || "(absent)") << '\n'
          end
          inputs.observed_env.to_a.sort_by { |name, _| name }.each do |name, val|
            next if inputs.env.has_key?(name)
            io << "~ " << name << '=' << (val || "(absent)") << '\n'
          end
        end
      end
    rescue ::File::Error | IO::Error
    end
  end
end
