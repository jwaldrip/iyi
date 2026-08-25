# This file is the entry point for WebAssembly programs compliant with the WASI
# spec. See https://github.com/WebAssembly/WASI/blob/snapshot-01/design/application-abi.md.
#
# iyi: it used to define `_start` too, and that made a program impossible to
# link with the command the compiler itself prints:
#
#     wasm-ld: error: duplicate symbol: _start
#     >>> defined in .../share/wasi-sysroot/lib/wasm32-wasi/crt1-command.o
#     >>> defined in /tmp/iyiwasm/hi.wasm
#
# `crt1-command.o` is what a WASI command program links, and it is already the
# whole of that sequence: it exports `_start`, calls `__wasm_call_ctors`, calls
# `__main_void`, calls `__wasm_call_dtors` and exits. So the entry the stdlib
# defined was a second copy of the linker's, and what wasi-libc actually wants
# from a program is one symbol lower down: clang renames a C `main` to
# `__main_argc_argv` or `__main_void` by its parameters, and `__main_void` in
# the sysroot forwards to `__main_argc_argv` with the real arguments.
#
# This is the same choice iyi's own prelude made (`src/iyi/prelude.iyi`, the
# note above `__iyi_start`), and the reason CI did not catch the collision is
# that its wasm32-wasi job type-checks `.cr` and only links the `.iyi` sample.

# `__main_argc_argv` is called by wasi-libc's `__main_void` with the program
# arguments.
fun __main_argc_argv(argc : Int32, argv : UInt8**) : Int32
  main(argc, argv)
end
