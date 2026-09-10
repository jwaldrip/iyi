# The shape an artifact cannot carry, in forty lines and no shard.
#
# `Chainy::Link` is a module used as a *type*: `@next : Link | Nil` holds
# whatever includes it, and a call on that field is compiled as a test per
# includer. The includers are whatever the *producing* build had — `First`
# and `Last` — so the machine code in the artifact answers a question only
# the whole program can answer.
#
# A consumer that writes its own `Link` joins the set and the artifact's copy
# cannot know:
#
#     iyi tool bind --crystal -e Chainy --emit-bind mods shard.cr
#     iyi build --crystal --iyi-keep Chainy --emit-bind mods --use-iyimod mods \
#       -o keep mods/chainy_keep.cr
#     iyi run --crystal --use-iyimod mods app.iyi
#
# prints `first ` and stops, where the same two files built from source print
# `first mine end`. This is the miniature of the defect an application hits:
# kemal's handler chain is `@next : HTTP::Handler | Nil`, every middleware a
# person writes joins that set, and `Kemal::InitHandler@HTTP::Handler#call_next`
# matched none of its cases, fell through to the `Proc` arm of the union and
# jumped through a pointer that was never a function — a segfault on the
# first request, behind a front end that compiled clean.
#
# Not a gate: it fails, and it fails for a reason SPEC.md III.6 now names.
module Chainy
  module Link
    abstract def run(io : IO) : Nil

    def run_next(io : IO) : Nil
      if link = @next
        link.run(io)
      else
        io << "end"
      end
    end
  end

  class First
    include Link

    @next : Link | Nil = nil

    def next=(link : Link)
      @next = link
    end

    def run(io : IO) : Nil
      io << "first "
      run_next(io)
    end
  end

  class Last
    include Link

    @next : Link | Nil = nil

    def run(io : IO) : Nil
      io << "last "
      run_next(io)
    end
  end
end
