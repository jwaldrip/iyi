# iyi: `Compiler::OptimizationMode` on its own, so that a front end can name it
# without linking a code generator.
#
# It is a plain enum and it always was — nothing in it is LLVM's. It lived in
# `compiler.cr` because that is who reads it, and `compiler.cr` speaks LLVM on
# every other line, so a binary that wanted the enum got the library with it.
# See `llvm_shim.cr`.
class Crystal::Compiler
  # Optimization mode
  enum OptimizationMode
    # [default] no optimization, fastest compilation, slowest runtime
    O0 = 0

    # low, compilation slower than O0, runtime faster than O0
    O1 = 1

    # middle, compilation slower than O1, runtime faster than O1
    O2 = 2

    # high, slowest compilation, fastest runtime
    # enables with --release flag
    O3 = 3

    # optimize for size, enables most O2 optimizations but aims for smaller
    # code size
    Os

    # optimize aggressively for size rather than speed
    Oz

    def suffix
      ".#{to_s.downcase}"
    end

    def self.from_level?(level : String) : self?
      case level
      when "0" then O0
      when "1" then O1
      when "2" then O2
      when "3" then O3
      when "s" then Os
      when "z" then Oz
      end
    end
  end
end
