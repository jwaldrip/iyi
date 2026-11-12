# iyi: a self-hosting compiler with no LLVM and no external linker

Dispatch-ready specification. Grounded at line B `9a2a08173` (`/Users/jwaldrip/checkouts/iyi-selfhost-b`, branch `reintegrate/upstream-master-into-selfhost`) and upstream `iyilang/iyi` master `140375a3b`. Anything not verified in the tree is marked **[UNVERIFIED: how to verify]**. Phases are dependency-ordered; nothing here carries a duration.

---

## 0. The goal, observably

On each compiler host (aarch64-darwin, x86_64-linux-gnu, aarch64-linux-gnu, x86_64-windows), from a clean checkout:

1. `stage1` (the iyi-written compiler, built once by the Crystal-hosted compiler) builds `stage2` from `src/compiler/**/*.iyi`; `stage2` builds `stage3`; `cmp stage2 stage3` exits 0, and so do their debug companions.
2. `stage2` links only the platform's own contract: `otool -L` shows `/usr/lib/libSystem.B.dylib` alone on darwin; `readelf -d` shows no `NEEDED` and `readelf -l` no `INTERP` on Linux; `dumpbin /dependents` shows `kernel32.dll` (plus `advapi32`, `ws2_32`, `crypt32` only where std modules the compiler uses need them) on Windows. `nm stage2 | grep -c LLVM` is 0.
3. Both builds ran with a `PATH` whose `cc clang gcc ld ld64 ld.lld lld mold link.exe lld-link wasm-ld codesign dsymutil llc llvm-*` are tripwires that log and exit 97; the tripwire log is empty.
4. `stage2` builds every program in the sample, prelude and std corpora for all five targets (aarch64-darwin, x86_64-linux-gnu, aarch64-linux-gnu, x86_64-windows, wasm32-wasi); each program, run on its target's runner, matches the same program built by the Crystal-hosted compiler through LLVM in exit status, stdout and stderr.
5. `bench/panics.sh` (including step 9a, named frames through `std/debug`) passes on native outputs.
6. Stale testing (`iyi test --cached`, PR #147) runs on the self-hosted compiler; `src/compiler/iyi/**/*.cr` and `src/llvm/**` are deleted.

Each upstream PR along the way merges green on `iyilang/iyi` CI by itself, with a merge commit.

---

## 1. Corrections to the brief

1. **#147 does not use LLVM's JIT.** `STALE_TESTS_DESIGN.md` at the PR head says "No JIT anywhere"; the JIT code in `src/compiler/iyi/codegen/codegen.cr` 29-155 has no production caller. LLVM enters #147 in three places only: the fresh/recording build, RG8 (normalised LLVM IR printed under `DUMP=1` at `codegen.cr` 755-779, normalised by `bench/stale_ir_normalize.py`), and toolchain identity (LLVM version plus a digest of the LLVM shared library). Re-homing stale testing therefore needs an IR-text oracle and a new toolchain identity, not a JIT replacement.
2. **#147 does touch files line B's gates compile.** It changes no file under `selfhost/` or `src/compiler/**/*.iyi` (confirmed), but it edits `src/iyi/{concurrency,file,float,prelude,thread}.iyi` and about fifteen `src/std/*.iyi` files: `@[Effect(...)]` annotations, observer hooks under `{% if flag?(:iyi_observe) %}`, two raise functions appended to `concurrency.iyi`, and `std/debug.iyi`'s `struct DlInfo` becoming an alias. Line B's prelude gates parse and compile those files, so #147's merge can turn line B red unless the front end accepts them first (slice A8).
3. **Line B against upstream master is not only the port.** `git diff --stat 140375a3b HEAD` (316 files, +73,410) includes about 7,800 lines of unrelated std features (`quic.iyi` 3,706, `qpack.iyi` 1,004, `http3.iyi` 745, `webtransport.iyi` 691, `oauth.iyi` 674, `oauth2.iyi` 665, edits to `base64`, `crypto`, `digest`, `http`, `option_parser`) and about 480 lines of Crystal-hosted compiler edits. Five of those edited files are also edited by #147 (`codegen/call.cr`, `command.cr`, `macros/methods.cr`, `semantic/semantic_visitor.cr`, `src/compiler/requires.cr`), as are `bench/dependency_floor.sh`, `bench/doc_numbers.py`, `bench/identity_floor.py`, `bench/arena_exercise.sh`, `bench/runtime_exercise.sh`. Line B also changes prelude semantics in `src/iyi/atomic.iyi` (Bool atomics, with matching `codegen/primitives.cr` changes).
4. **The codegen gap is a rewrite, not an extension.** `codegen/codegen.iyi` never reads semantic results (`@main_visitor` is stored at 349 and 386 and never read); it types from syntax strings with a silent `Int32` fallback (`llvm_type_from_name` 729-769, `infer_var_type` 883-1064); `LocalVarCollector` keeps the first assignment (176-212). The pipeline gives `MainVisitor` only function return types (`compiler.iyi` 158-167), so no body is type-checked. And it does not implement the prelude's runtime contract: the entry chain `main -> __iyi_enter -> __iyi_program -> __iyi_main` (`prelude.iyi` 10707-10742, 11516-11519), `__iyi_new` and the write barrier, `@[Primitive]` atomics (which compile to nothing: a silent miscompile), `@[ThreadLocal]`, `@[Naked]`, preemption checks, and the defer-registry panic. It lowers `raise` and `rescue` through `_Unwind_RaiseException` and an Iyi-source personality (`codegen.iyi` 2165-2486, `compiler.iyi` 424-574), which iyi's model forbids: a panic "unwinds without an unwinder" (`prelude.iyi` 10829-10833, SPEC III.1.4), and upstream refuses `rescue` (`semantic/main_visitor.cr` 3356-3375). Line B's parser and normalizer do not refuse it.
5. **Line B's documents overstate.** `src/compiler/iyi.iyi` does not exist (the entry is `src/compiler/stage1.iyi`); there are 23 selfhost gates, not 14 or 18; `STAGE_TWO.md` section 6 criterion 2 requires libLLVM linked, which contradicts decision 5; `bench/fixtures/compile_raise.iyi` defines its own `__crystal_raise`, so the gate's raise mutations patch the fixture, not the injected runtime (`STAGE_TWO.md` 332-336 is wrong); `BOOTSTRAP.md` says its figures are measured by `bench/doc_numbers.py`, which reads only README, SPEC, CHANGELOG, INSTALL, Makefile and `samples/iyi/calc.iyi`.
6. **Upstream CI runs no selfhost gate, and line B's gates cannot run there as written.** They hard-code `/opt/homebrew` and use `otool`; upstream's Linux jobs run in `crystallang/crystal:1.21.0-build`. `selfhost_compile_exercise.sh` compares exit codes only, despite its header. Its mutation helpers restore a mutated source only on the normal path, not on interrupt.
7. **Debug information is part of parity.** `bench/panics.sh` step 9a (run by the `samples` job) requires named frames with `file:line` through `std/debug`, which reads `<exe>.dwarf` on darwin (written today by `dsymutil --flat`, an external tool: `compiler.cr` 3552-3581, `std/debug.iyi` 1786-1827), `.symtab`, `.eh_frame`, `.debug_line`, `.debug_info`, `.debug_abbrev`, `.debug_str` on Linux (`std/debug.iyi` 1554-1561), and a PDB on Windows (MSF 7.00: PDB info GUID matched to the PE's RSDS record, DBI module info and section contributions, `/names`, module streams with `S_GPROC32`/`S_LPROC32` and C13 `DEBUG_S_LINES`: `std/debug.iyi` 279-970).
8. **Linux programs are dynamically linked today.** The object asks libc for nothing (#147's SPEC text: the only undefined names are `__data_start`, `__ehdr_start`, `_end`), but the link adds `Scrt1.o crti.o crtbeginS.o -lgcc -lc` and `ld-linux` (SPEC V.9 item 9; `bench/floor_base.sh` `FLOOR_BASE_LINUX`). An own linker makes them static-PIE with no libc and no interpreter, so the floor moves.
9. **aarch64-linux has no native CI runner** (QEMU in `cross-run`). Upstream is a public repository (`gh repo view`), so GitHub's `ubuntu-24.04-arm` hosted runner is available to propose.
10. **SPEC V.9 item 9 (c) already costed an own linker and recommended against it** ("iyi owns none of the three while it emits LLVM objects and links against libc"; "The recommendation is (a), then (b) if the number survives it, and (c) for no reason this section can find"). The amendment must answer that paragraph, not only B.2 and III.9 rule 2.
11. **Upstream requires one check:** the ruleset "master: every selected job passed" requires the `result` job; `scripts/ci_plan.py` runs a new `bench/*.sh` only if some job's step names it (or names a script that globs it), so every new gate must be reachable from `iyi.yml`.
12. **Size of what is left.** The Crystal sources stage 1 needs (`semantic/`, `semantic.cr`, `types.cr`, `program.cr`, `macros.cr`, `macros/`, `codegen/`, `compiler.cr`, `preempt_checks.cr`, `wasm_roots.cr`) total 72,294 lines by `wc -l` at line B; line B has ported part of that. The commands, LSP, tools and `mod` that F2 must port or drop total 34,997 more.

---

## 2. Decisions

### 2.1 The seam

**Decision.** LLVM is cut out at the builder boundary. Code generation emits **iyi IR** (`src/compiler/ir/**`), an SSA IR deliberately shaped like LLVM IR at O0 (typed values, basic blocks, phi, alloca/load/store, GEP, LLVM's integer and float ops, casts, first-class aggregates, atomics, inline asm, a closed set of intrinsics), plus explicit ops for iyi's runtime contract (`ThreadLocalAddr`, `ThreadPointer`). The IR's builder, type table, module, function, block and value classes keep the method names that `codegen.iyi` calls on `compiler/llvm/{builder,context,module,values}.iyi`, so moving `codegen.iyi` (and later the port of `codegen/*.cr`) onto it is a type and import rename.

**The LLVM path stays selectable behind the same IR** during the transition (decision 4): `backend/llvm/translate.iyi` replays iyi IR into LLVM through the existing bindings. The inverse, `backend/llvm/import.iyi`, reads any LLVM module (the Crystal-hosted compiler's `--emit llvm-ir`) into iyi IR. Import then translate must reproduce the oracle's module exactly; that round trip over the whole sample, prelude and std corpus on all five targets is the proof that the IR is complete before anything consumes it.

**Rejected:** (a) cutting LLVM out of `codegen.iyi`'s builder call sites straight into a native backend: it couples the backend to a syntax-typed emitter that has to be replaced anyway (correction 4); (b) a Go-style abstract SSA with no LLVM shape: it makes the translator, the importer and the mechanical port of `codegen/*.cr` harder for no gain, since the native backend legalises LLVM-shaped IR anyway; (c) a companion `iyi-llvm` process for the fallback: the compiler built from the transitional entry point links LLVM in process, and that entry point is deleted at E2, which is simpler.

**The bridge.** Because the importer exists, the native backend is proven on the full language (the Crystal-hosted compiler's IR for every corpus program) without waiting for stage 1. This is what lets phases C and D run in parallel with the stage-1 port, the long pole.

**Backend selection.** `--backend native|llvm` on `build` and `run`; the default per target comes from `NATIVE_TARGETS` in `src/compiler/backend/backend.iyi` (empty at first; each target's landing PR adds its triple after that target's corpus gate is green). Two entry points: `src/compiler/stage1.iyi` (native only; links no LLVM) and `src/compiler/stage1_llvm.iyi` (native and LLVM; transitional, deleted at E2). A compiler built without the LLVM backend refuses `--backend llvm`, or a target whose default is still LLVM, with `iyi: this compiler has no LLVM backend; <triple> has no native backend yet` and exit 1. `iyi build --print-backend --target <triple>` prints the chosen backend. Tested by `bench/native_backend_select_exercise.sh` (B3).

### 2.2 Backend architecture

Pipeline per function, `IR -> legalize -> optimize -> select -> regalloc -> frame -> encode`, functions compiled in parallel and merged in module order.

1. **Legalize** (`native/lower.iyi`, target-parameterised): drop unwind edges (`invoke` becomes `call` plus `br`; blocks reachable only through unwind edges are deleted; a reachable EH pad is a named error); scalarise first-class aggregates (SSA aggregates become per-field values; aggregate loads, stores and phis split); lower `i128` arithmetic to 64-bit pairs, with division, remainder, float conversion and overflow-checked multiply as calls to native runtime helpers; expand intrinsics (overflow arithmetic to flag sequences; `memcpy`/`memmove`/`memset` to inline sequences for small constant sizes and otherwise to calls to the runtime helpers `__iyi_native_memcpy`/`memmove`/`memset`, never to the prelude's or a libc's, so no collector flag or platform changes the floor); `switch` to compare chains or jump tables; GEP to address arithmetic from `DataLayout`; `ThreadLocalAddr` per object format; `C`-convention calls per platform ABI.
2. **Optimize** (`ir/passes/*`), Go-class, on by default for native (`-O0` disables it, for debugging the backend):
   - **In:** mem2reg for scalar and small-aggregate allocas whose address does not escape and that have no volatile access; SCCP (constant folding and propagation); dead code elimination; dominator-based CSE that never merges volatile, atomic, `ThreadLocalAddr`, `ThreadPointer` or inline-asm values and never moves them across a call or a back-edge (a fiber can change threads at either); CFG simplification (merge straight-line blocks, fold constant branches, delete unreachable blocks); inlining of small non-recursive functions and `alwaysinline`, never `noinline`, `naked` or functions with inline asm; block layout for fallthrough.
   - **Out:** vectorisation, unrolling, LTO, interprocedural analysis beyond inlining, alias-analysis-driven load/store elimination beyond a block, instruction scheduling, fast-math or FMA contraction (no fused multiply-add unless the IR calls the `fma` intrinsic), strength reduction or any rewrite that leaves only a derived pointer outside an object while its base is dead (the collector scans conservatively).
3. **Select** (`native/<arch>/isel.iyi`): per-block pattern matching from IR to MIR with addressing-mode folding, immediate folding, compare-and-branch fusion. Conversions, divisions, shifts and atomics use the instruction LLVM picks at O0 (`cvttsd2si`, `fcvtzs`, LLVM's `fptoui` sequence on x86_64, hardware shift masking, the orderings' instruction mapping below), so cases LLVM leaves undefined behave as today's binaries do.
4. **Register allocation** (`native/regalloc.iyi`): linear scan over SSA live intervals with splitting at block boundaries, fixed-register constraints for calls, shifts, divisions and inline asm, spill slots in the frame.
5. **Frame** (`native/frame.iyi`): frame pointer always (`x29`/`x30` record, `rbp` chain; darwin's `backtrace()` walks it); callee-saved saves; 16-byte stack alignment; no red zone; Win64 32-byte shadow space; `x18` never allocated on aarch64; **stack probes** for any frame over 4096 bytes, touching each page from the top before use, inline on every target including Windows (no `__chkstk`; SPEC III.1.4 and `bench/panics.sh`'s 64 KiB frame require the touch); `naked` functions get no prologue or epilogue.
6. **Encode** (`native/<arch>/encode.iyi`): machine code into an in-memory object (section 3.4) through a `SectionWriter` (bytes, relocations and symbols appended to one section), plus a format-neutral frame description and line table per function, which the linker turns into `.eh_frame`, `.pdata`/`.xdata`, DWARF or PDB.

**Calling conventions.** IR has two: `C` (platform C ABI; the producer has already done C ABI lowering exactly as `codegen/abi/*.cr` does, so signatures carry LLVM-style `byval`/`sret`/`zeroext`/`signext` attributes and LLVM-style coerced aggregates such as `[2 x i64]`, `{i64, i64}`, `[4 x float]`; the native backend assigns those exactly as LLVM's backend does) and `Iyi` (internal: the native backend uses the platform C convention for scalars and splits aggregates into scalar leaves; the translator emits LLVM's default C convention so oracle parity holds). A program is all-native or all-LLVM; objects record their producer and the linker refuses a mix.

**Per-target ABI rules.**
- **aarch64-darwin (Apple AAPCS64 variant):** variadic arguments always on the stack in 8-byte slots; caller extends `i8`/`i16` arguments to 32 bits; stack-passed arguments packed by natural alignment; `x18` reserved; frame records mandatory; `x8` indirect result.
- **aarch64-linux (AAPCS64):** variadic in registers then stack; HFAs in `v0-v7`; `x8` indirect result.
- **x86_64-linux (SysV):** six integer and eight SSE argument registers; `al` holds the vector-register count for variadic calls; `rdi` indirect result; callee-saved `rbx rbp r12-r15`.
- **x86_64-windows (Win64):** `rcx rdx r8 r9` and `xmm0-3` by position; 32-byte shadow space; aggregates over 8 bytes by reference; variadic floats in both register files; callee-saved adds `rsi rdi xmm6-xmm15`; `rcx` indirect result.
- **wasm32-wasi:** wasm signatures from IR types (`i32` pointers); aggregates by pointer as LLVM's wasm32 ABI does (`codegen/abi/wasm32.cr`).

**The collector's constraints on code generation** (GC_DESIGN.md 2537-2560: stacks scanned conservatively, statepoints "Measured, and Not Taken"; heap precise through layout tables). No stack maps are needed. The backend must guarantee: the callee-saved set is within what `IyiRoots.spill_registers` spills (`prelude.iyi` 4403-4429: SysV `rbx rbp r12-r15`, Win64 adds `rsi rdi`, aarch64 `x19-x30`), so the platform C set is used unchanged; no pointer lives in a floating-point or vector register across a call; frames are contiguous on the thread's or fiber's stack; on wasm, every `ptr` value live across a call is also stored to the linear-memory shadow stack (the semantics of `src/compiler/iyi/wasm_roots.cr`).

**Exceptions: none.** iyi refuses `rescue`, panics unwind by the defer registry, a panicking task dies alone, and the stack-overflow panic does not unwind (SPEC III.1.4; `prelude.iyi` 10829-10910). No LSDA, no personality, no landing pads in native code. Unwind *tables* are still written where something walks the stack: `.eh_frame` on Linux (`std/debug` walks it), `.pdata`/`.xdata` on Windows (`RtlCaptureStackBackTrace`, `prelude.iyi` 793-797, and the OS). darwin needs none (frame pointers).

**Fibers and stack switching** stay runtime-owned: `__iyi_ctx_swap` is a `@[Naked] @[NoInline]` function whose body is inline asm per target (`concurrency.iyi` 66-177). The backend supports naked functions and those templates. No split stacks.

**TLS** (`@[ThreadLocal]`, `class_var.cr` 9-34; every access goes through a fresh thread-pointer read, `codegen.cr` 1621-1716, so `ThreadLocalAddr` is never CSE'd or hoisted across a call or back-edge, and the IR verifier enforces it):
- darwin: Mach-O TLV descriptors in `__DATA,__thread_vars` bound to `_tlv_bootstrap`, template in `__thread_data`/`__thread_bss`, `MH_HAS_TLV_DESCRIPTORS`, access through the descriptor's thunk.
- Linux: local-exec, `PT_TLS`; x86_64 variant II (`%fs`-relative negative offsets, TCB self-pointer at `%fs:0`), aarch64 variant I (`tpidr_el0 + 16 + offset`), matching `IyiTlsImage` (`thread.iyi` 234-238). rt sets up the main thread's block, which glibc does today.
- Windows: `_tls_index`, `gs:[0x58]`, `SECREL` offsets, a TLS directory the linker synthesises.
- wasm32: plain globals (no threads; the prelude refuses concurrency there).

**Preemption checks** are IR, emitted by the ported `PreemptChecks` pass (`src/compiler/iyi/preempt_checks.cr`, 639 lines) using `ThreadPointer` reads: x86_64 Linux `cmpq $0, %fs:off`; aarch64 Linux `mrs tpidr_el0` plus offset; Windows a TEB slot (`gs:`) whose offset is read at function entry (`concurrency.iyi` 5209-5226); darwin `tpidrro_el0` pthread slots; the cold path calls `__iyi_preempt`; `@[NoPreempt]` skips.

**Atomics** map as LLVM maps them: x86_64 seq_cst store is `xchg`, RMW is `lock xadd`/`xchg`/`cmpxchg` loops, seq_cst fence is `mfence`, acquire and release fences are compiler barriers; aarch64 acquire and release loads and stores are `ldar`/`stlr`, RMW is an `ldaxr`/`stlxr` loop (ARMv8.0 baseline on both aarch64 targets; LSE on darwin is a later optimisation), fences are `dmb ish`/`dmb ishld`; singlethread scope is a compiler barrier; wasm32 atomics are plain operations (`prelude.iyi` 35-37).

**Inline asm.** Every `asm(...)` template in the tree is assembled by the backend's own assemblers (x86_64 AT&T, aarch64), with LLVM's constraint semantics (`=r`, `={rax}`, `{rdi}`, `r`, `x`, `=x`, tied `0`, `~{memory}` and register clobbers, `$N`, `$$`) and relocation operators (`sym(%rip)`, `sym@PAGE`, `sym@PAGEOFF`, `:lo12:sym`). The assemblers implement exactly the instructions the inventory finds (raw syscalls, `pause`/`yield`/`isb`, `cpuid`, `xgetbv`, `vfmadd213sd`/`ss`, `roundsd`, `push`/`pop`/`mov`/`lea`/`stp`/`ldp`/`adrp`/`add`/`mrs`/`svc`/`ret`, register spills, `gs:` loads) and refuse anything else by name, including the Intel dialect unless the inventory finds a use. wasm32 refuses inline asm.

**LLVM intrinsics bound by name** from `lib` blocks (`float.iyi` 31-37: `llvm.copysign.f64`, `llvm.floor.f64`, `llvm.ceil.f64`; `std/math.iyi` 16-24: `llvm.sqrt`, `llvm.copysign`, `llvm.fma`; wasm: `llvm.wasm.memory.grow.i32`, `llvm.stacksave.p0`, `llvm.frameaddress.p0`) become IR `Intrinsic` ops with a closed `IntrinsicId` enum whose members are exactly what the importer's coverage report finds.

**What each target needs that the others do not.**

| target | only this target |
|---|---|
| aarch64-darwin | Mach-O and dyld binding and rebase; `LC_MAIN` (dyld calls `main`, so no start code); ad-hoc code signature (mandatory on arm64); TLV descriptors; Apple AAPCS64 variant; `x18` reserved; an export trie of every global symbol (the oracle links with `-rdynamic`, and `dladdr` names frames) [UNVERIFIED: whether `dladdr` reads the export trie or the symbol table; verify by running `bench/panics.sh` 9a against a native binary with and without the trie]; `<exe>.dwarf` companion; `LC_BUILD_VERSION` minos 14.4 (SPEC III.9: `os_sync_wait_on_address`); symbol prefix `_`; `tpidrro_el0` preempt reads |
| x86_64-linux-gnu, aarch64-linux-gnu | ELF static-PIE with a self-relocating rt (`_start`, `environ`, main-thread TLS block and thread pointer, RELRO `mprotect`, `exit_group`); linker-defined `__ehdr_start`, `__data_start`, `__bss_start`, `_end` (root discovery and `IyiTlsImage`); `PT_TLS`, `PT_GNU_STACK`; `.eh_frame`, `.symtab`, `.debug_*` in the executable; `%fs` (address space 257) or `tpidr_el0` thread-pointer reads |
| x86_64-windows | PE32+ with an import directory per DLL, TLS directory and `_tls_index`, `.pdata`/`.xdata` for every function, `.reloc` (`DYNAMIC_BASE`, `HIGH_ENTROPY_VA`, `NX_COMPAT`), 8 MiB stack reserve (link.exe gets `/STACK:0x800000` today); rt entry with no CRT (calls `main`, then `ExitProcess`); Win64 ABI; `gs:` TEB reads; PDB plus RSDS debug directory; `Iyi.safe_mangling` names |
| wasm32-wasi | stack-machine code generation with no register allocator; structured control flow (stackify over the dominator tree; an irreducible CFG is a named error, which iyi source cannot produce); linear-memory shadow stack (`__stack_pointer`) for allocas and GC roots; function table for indirect calls; `__wasi_<name>` declarations become `wasi_snapshot_preview1.<name>` imports (the naming wasi-libc uses, `prelude.iyi` 1475-1486); `_start` export calling `args_sizes_get`/`args_get`, `__main_argc_argv`, `proc_exit`; `memory.grow`; `__heap_base`/`__data_end`; bulk-memory `memory.copy`/`memory.fill`; no threads, TLS, atomics, asm, stack probes or debug info |

### 2.3 Objects and the linker

The native backend writes an in-memory object (`native/obj/object.iyi`). Writers and readers for the platform relocatable formats (Mach-O `MH_OBJECT`, ELF `ET_REL`, COFF) exist for three reasons only: differential testing (our objects linked by the system linker; LLVM's objects linked by our linker), the object cache, and `--emit obj`. The linker consumes in-memory objects and writes the executable directly; the wasm "linker" assembles the final module.

**The native runtime (rt)** is toolchain code, not library code: hand-written iyi IR text (`src/compiler/native/rt/*.ir`), parsed by `compiler/ir/parser` and linked into every native program. It holds the start code (Linux, Windows, wasm), `environ`, and the `__iyi_native_*` helpers the legaliser calls (memory copy, move and fill; 128-bit division and remainder; 128-bit float conversion; overflow-checked 128-bit multiply). Writing it in IR keeps it independent of every front end (the syntax-directed `codegen.iyi`, the bridge, the typed lowering), and B2's translator compiles the same files through LLVM for a differential test. The prelude is never edited.

- **Mach-O executable:** `__PAGEZERO`, `__TEXT` (`__text`, `__stubs`, `__const`, `__cstring`), `__DATA` (`__got`, `__data`, `__bss`, `__thread_vars`, `__thread_data`, `__thread_bss`), `__LINKEDIT`. The collector walks `__DATA` (required) and `__DATA_CONST` (optional) of image 0 (`prelude.iyi` 4742-4779), so those names are a contract; this linker writes no `__DATA_CONST`. Load commands: segments, `LC_DYLD_INFO_ONLY` (rebase opcodes; every import bound eagerly through `__got`; no lazy binding, no `__stub_helper`), `LC_SYMTAB` with every function symbol (names are how darwin's panic frames are named), `LC_DYSYMTAB`, `LC_LOAD_DYLINKER /usr/lib/dyld`, `LC_UUID` (content hash), `LC_BUILD_VERSION` (macOS, minos 14.4, no tools), `LC_SOURCE_VERSION`, `LC_MAIN`, `LC_LOAD_DYLIB` for `/usr/lib/libSystem.B.dylib` and `/System/Library/Frameworks/{Security,CoreFoundation}.framework/Versions/A/{Security,CoreFoundation}` when used, `LC_FUNCTION_STARTS`, `LC_DATA_IN_CODE`, `LC_CODE_SIGNATURE`. Flags `MH_PIE MH_TWOLEVEL MH_DYLDLINK MH_NOUNDEFS` (+`MH_HAS_TLV_DESCRIPTORS`). **Ad-hoc signature:** a SuperBlob with one CodeDirectory (version `0x20400`, SHA-256, 4096-byte pages, identifier = output basename, flags `CS_ADHOC | CS_LINKER_SIGNED`, exec-segment fields for `__TEXT` with `CS_EXECSEG_MAIN_BINARY`), hashed with `std/digest`'s SHA-256. If dyld refuses `LC_DYLD_INFO_ONLY` on a current macOS, the fallback is `LC_DYLD_CHAINED_FIXUPS` (risk R3). The debug companion `<exe>.dwarf` is an `MH_DSYM` file with the same `LC_UUID` and a `__DWARF` segment (`__debug_line`, `__debug_info`, `__debug_abbrev`, `__debug_str`), replacing `dsymutil --flat`.
- **ELF executable (both Linux targets):** static-PIE: `ET_DYN`, no `PT_INTERP`, no `PT_DYNAMIC`; `PT_PHDR`, `PT_LOAD` (R+X, ELF header included so `__ehdr_start` is mapped), `PT_LOAD` (R), `PT_LOAD` (RW), `PT_TLS`, `PT_GNU_STACK` (RW), `PT_GNU_RELRO` over relocated read-only data, made read-only by rt after relocating (today `ld.so` does this). Relative relocations go in a table rt applies before any relocated data is read (load base from `__ehdr_start`). LLVM objects' GOT relocations get GOT entries; `TPOFF`/`TLSLE` relocations use our `PT_TLS` layout. `.symtab`, `.strtab`, `.eh_frame`, `.debug_*` kept (debug sections non-alloc). No `.comment` linker string.
- **PE executable:** `.text`, `.rdata` (import directory, ILT and IAT, hint/name table, TLS directory, `.pdata`, `.xdata`, debug directory with RSDS), `.data`, `.bss`, `.tls`, `.reloc`. No Rich header. Subsystem console. Entry is rt's `__iyi_win_start`. `__chkstk`, `_fltused`, the CRT entry and CRT imports are not used. PDB written beside the executable with the RSDS GUID.
- **wasm module:** type, import, function, table, memory (exported `memory`), global (`__stack_pointer`), export (`_start`, `memory`), element, code, data, and a `name` section.

**Debug information stance.** The backend emits a format-neutral line table and frame description per function (section 3.4); the linker writes exactly what `std/debug` reads (correction 7): DWARF (`.debug_line`, a compile unit with subprograms in `.debug_info`, `.debug_abbrev`, `.debug_str`) in the ELF executable and in the darwin companion, `.eh_frame` on ELF, a PDB on Windows. Variables and types (`--debug`, `Debug::All`, held by `bench/debug_info.py` for the LLVM path) are out of scope until after E. Default builds carry line tables, as today (`compiler.cr` 33-37: `LineNumbers`). Debug and unwind sections inside LLVM-produced objects (used only by linker tests) are dropped, except `.eh_frame` (ELF) and `.pdata`/`.xdata` (COFF), which are relocated and passed through.

**`lib`/`fun`, `@[Link]` under the native backend.**
- `lib` functions are `C`-convention calls; their imports resolve by the declaring `lib`'s `@[Link]` library (`import_library` in IR); on darwin a `lib` with no `@[Link]` is libSystem.
- Allowed libraries per target (the native floor): darwin `libSystem`, `Security`, `CoreFoundation`; Windows `kernel32`, `advapi32`, `ws2_32`, `crypt32`; wasm `wasi_snapshot_preview1` through `__wasi_*`; Linux none (any undefined symbol is a link error naming it). Anything else is refused by name.
- `@[Link(ldflags:)]`, `pkg_config:`, static archives and `dll: "gc.dll"` are refused natively, with one recorded exception: `prelude.iyi` 655's `@[Link(ldflags: "msvcrt.lib ucrt.lib vcruntime.lib")]` is satisfied by native rt (it exists only to give link.exe a CRT entry and intrinsics). `-Dgc_boehm` and `--crystal` stay LLVM-only and are refused natively; after E2 they need an upstream decision (keep on the Crystal-hosted compiler until F4, or drop).
- For bridged oracle IR (which carries no `@[Link]`), `iyi-native` takes a sidecar `<prog>.imports` that the line B front end produces by parsing the program's `lib` blocks for the target.

**Toolchain floor per target, after its native backend lands** (SPEC III.9 rule 3: every tool recorded with a reason):

| target | build-time host files and tools | run-time | reason |
|---|---|---|---|
| aarch64-darwin | none (no SDK, ld64, codesign, dsymutil) | `/usr/lib/dyld`, `libSystem.B.dylib`; Security and CoreFoundation only with `std/system_roots` | Apple's syscall ABI is private; libSystem is the contract (III.9 rule 1) |
| x86_64-linux-gnu, aarch64-linux-gnu | none | the kernel | the prelude issues raw syscalls; the object already asks libc for nothing |
| x86_64-windows | none (no link.exe, Windows SDK `.lib`, vcruntime, ucrt) | `kernel32.dll`, and `advapi32`, `ws2_32`, `crypt32` per std module | the Win32 API is the contract |
| wasm32-wasi | none (no wasi-sdk, wasm-ld) | a WASI preview1 host | WASI is the contract |

Test-time only, never invoked by the compiler: `otool`, `readelf`, `nm`, `dumpbin`, `codesign -v`, `wasmtime`, QEMU, `llvm-mc` (optional), the Crystal-hosted compiler as oracle until F4. Temporary toolchain entries with exit conditions (III.9 rule 4): LLVM and libstdc++ in the iyi compiler (exit at E2); `cc`, `link.exe`, wasi-sdk and `dsymutil` for the LLVM path (exit with it); LLVM and libgc in the Crystal-hosted compiler and `crystal` itself (exit at F4, per the existing rule).

---

## 3. Shared contracts

All new modules follow the tree's conventions: `module compiler/<dir>/<file>` header, `import compiler/x::{A, B}`, `@[Unsafe("why")]` above any module that touches raw memory (SPEC III.13), errors as union members (SPEC III.1), no reopening of another module's types, no `rescue`.

### 3.1 Directory and ownership map

| path | contents | owner slice |
|---|---|---|
| `src/compiler/ir/{types,values,inst,intrinsics,function,module,builder,printer,parser,verifier,layout}.iyi` | IR core | B1 |
| `src/compiler/ir/passes/{mem2reg,sccp,dce,cse,simplify_cfg,inline,pipeline}.iyi` | optimisation | D7 |
| `src/compiler/ir/passes/{preempt_checks,wasm_roots}.iyi` | runtime-contract passes | S2f |
| `src/compiler/backend/backend.iyi` | `Backend`, selection, `NATIVE_TARGETS` | B3 |
| `src/compiler/backend/llvm/{translate,import,emit}.iyi`, additions to `src/compiler/llvm/*.iyi` | LLVM path | B2 |
| `src/compiler/native/obj/{object,macho}.iyi`; `.../elf.iyi`; `.../coff.iyi` | object model and relocatable formats | C1; D3; D4 |
| `src/compiler/native/link/{link,imports,macho_exe,codesign}.iyi`; `.../dwarf.iyi` | linker core and darwin; DWARF | C2; D6 |
| `src/compiler/native/link/{elf_exe,eh_frame}.iyi`; `.../{pe_exe,pdb,win64_unwind}.iyi` | ELF; PE | D3; D4 |
| `src/compiler/native/{mir,target,lower,regalloc,frame,emit,driver}.iyi` | native core | C3 |
| `src/compiler/native/asm/{constraints,inventory}.iyi` | inline-asm constraint parser, template inventory | C4 |
| `src/compiler/native/aarch64/{regs,abi,isel,encode}.iyi`; `.../asm.iyi` | aarch64 | C3 (then D1 after C3 merges); C4 |
| `src/compiler/native/x86_64/{regs,abi,isel,encode,asm}.iyi` | x86_64 | D2 |
| `src/compiler/native/wasm/{codegen,stackify,module,leb}.iyi` | wasm32 | D5 |
| `src/compiler/native/rt/builtins.ir`; `start_linux_x86_64.ir`, `start_linux_aarch64.ir`; `start_windows_x86_64.ir`; `start_wasm32.ir` | native runtime | C5; D3; D4; D5 |
| `src/compiler/tools/ir.iyi`; `src/compiler/tools/compile_native.iyi`; `src/compiler/tools/native.iyi` | `iyi-ir`; `iyi-compile-native`; `iyi-native` (the bridge) | B2; B3; D1 |
| `src/compiler/semantic/typed.iyi`, `src/compiler/lower/CONTRACT.md` | the analysed-program contract | S0 |
| `src/compiler/lower/**` | typed lowering (port of `codegen/*.cr`) | S2 slices |
| shared: `.github/workflows/iyi.yml`, `Makefile`, `Makefile.win`, `scripts/ci_plan.py`, `bench/ci_plan_exercise.py`, `SPEC.md`, `README.md`, `CHANGELOG.md`, `bench/doc_numbers.py` | | **INT**, the integrator (the parent). Slices hand INT the exact lines they need (job steps, plan rules, CHANGELOG entry, CLAIMS tuples); no slice edits these files |

### 3.2 iyi IR

```iyi
module compiler/ir/types

pub enum TypeKind
  Void
  Int
  Float
  Ptr
  Struct
  Array
  Func
end

# Interned by TypeTable: equal types are the same object.
pub class IrType
  getter kind : TypeKind
  getter bits : Int32               # Int: 1, 8, 16, 32, 64, 128. Float: 32, 64
  getter address_space : Int32      # Ptr: 0; 256 (%gs) and 257 (%fs) on x86_64
  getter fields : Array(IrType)     # Struct
  getter packed : Bool              # Struct
  getter name : String?             # Struct, named; opaque until TypeTable#set_body
  getter element : IrType?          # Array
  getter count : Int64              # Array
  getter params : Array(IrType)     # Func
  getter ret : IrType?              # Func
  getter varargs : Bool             # Func
end

pub class TypeTable
  def void : IrType
  def int(bits : Int32) : IrType
  def float(bits : Int32) : IrType
  def ptr(address_space : Int32 = 0) : IrType
  def struct_of(fields : Array(IrType), packed : Bool = false) : IrType
  def named_struct(name : String) : IrType
  def set_body(named : IrType, fields : Array(IrType), packed : Bool = false) : Nil
  def array_of(element : IrType, count : Int64) : IrType
  def func(params : Array(IrType), ret : IrType, varargs : Bool = false) : IrType
end
```

```iyi
module compiler/ir/layout

# LLVM's DataLayout semantics for exactly the five targets; anything else is refused.
pub class DataLayout
  def self.for(target : ::Compiler::Platform::Target::Target) : DataLayout | LayoutError
  def llvm_string : String          # byte-identical to the oracle's `target datalayout`
  def pointer_bytes : Int32
  def store_size(t : IrType) : Int64
  def alloc_size(t : IrType) : Int64
  def abi_align(t : IrType) : Int32
  def offset_of(t : IrType, field : Int32) : Int64
  def stack_align : Int32
end
```

```iyi
module compiler/ir/inst

pub enum Op
  # constants and module-level references
  ConstInt
  ConstFloat
  ConstNull
  ConstUndef
  ConstPoison
  ConstZero
  ConstAggregate
  ConstBytes
  ConstExpr          # Gep / PtrToInt / IntToPtr / BitCast / Add / Sub over constants
  GlobalAddr
  FunctionAddr
  # memory
  Alloca
  Load
  Store
  Gep
  Fence
  CmpXchg
  AtomicRmw
  VaArg
  # arithmetic
  Add
  Sub
  Mul
  SDiv
  UDiv
  SRem
  URem
  Shl
  LShr
  AShr
  And
  Or
  Xor
  FAdd
  FSub
  FMul
  FDiv
  FRem
  FNeg
  ICmp
  FCmp
  # conversions
  Trunc
  ZExt
  SExt
  FPTrunc
  FPExt
  FPToSI
  FPToUI
  SIToFP
  UIToFP
  PtrToInt
  IntToPtr
  BitCast
  AddrSpaceCast
  # values
  ExtractValue
  InsertValue
  Select
  Phi
  Freeze
  # calls
  Call
  Intrinsic
  # iyi's runtime contract: never folded, merged, or moved across a call or back-edge
  ThreadLocalAddr
  ThreadPointer
  # terminators
  Ret
  Br
  CondBr
  Switch
  Unreachable
  # oracle round trip only; the native backend deletes what only unwinding reaches
  Invoke
  LandingPad
  Resume
  CatchSwitch
  CatchPad
  CatchRet
  CleanupPad
  CleanupRet
end

pub enum CallConv
  C      # platform C ABI; the signature is already ABI-lowered by its producer
  Iyi    # internal; the native backend chooses, the LLVM translator emits C
end

pub enum Ordering
  NotAtomic
  Unordered
  Monotonic
  Acquire
  Release
  AcqRel
  SeqCst
end

pub enum AsmDialect
  Att
  Intel
end

pub enum ThreadPointerKind
  Fs          # x86_64 Linux
  Gs          # x86_64 Windows
  TpidrEl0    # aarch64 Linux
  TpidrroEl0  # aarch64 darwin
end

pub struct Attribute
  getter name : String          # LLVM's name: "noinline", "naked", "byval", "sret", "zeroext", "frame-pointer" ...
  getter int_value : UInt64
  getter string_value : String?
  getter type_value : IrType?
end

pub struct DebugLoc
  getter file : Int32           # index into Module#files
  getter line : Int32
  getter column : Int32
end

pub struct GepAux
  getter source_type : IrType
  getter inbounds : Bool
end

pub struct MemAux                # Load, Store, CmpXchg, AtomicRmw, Fence
  getter align : Int32
  getter volatile : Bool
  getter ordering : Ordering
  getter failure_ordering : Ordering
  getter single_thread : Bool
  getter rmw_op : String         # LLVM's atomicrmw operation name
  getter weak : Bool
end

pub struct CallAux
  getter fn_type : IrType
  getter cc : CallConv
  getter tail : Bool
  getter fn_attrs : Array(Attribute)
  getter param_attrs : Array(Array(Attribute))
  getter ret_attrs : Array(Attribute)
end

pub struct AsmAux                # the callee of a Call that is inline asm
  getter template : String
  getter constraints : String
  getter side_effects : Bool
  getter align_stack : Bool
  getter dialect : AsmDialect
end

pub struct IntrinsicAux
  getter id : IntrinsicId         # closed enum in compiler/ir/intrinsics.iyi; members = the importer's coverage
  getter overload : Array(IrType)
end

alias InstAux = GepAux | MemAux | CallAux | AsmAux | IntrinsicAux | Nil

# Value (compiler/ir/values.iyi) is the base of Inst, Param, the constants, Global and Function.
pub class Inst < Value
  getter op : Op
  getter type : IrType
  getter args : Array(Value)
  getter aux_int : Int64          # predicate, index, flags (nsw/nuw/exact/inbounds), constant payload
  getter aux : InstAux
  getter targets : Array(Block)   # successors; Phi incoming blocks; Switch default then case blocks
  getter cases : Array(Int64)     # Switch case values, aligned with targets[1..]
  property loc : DebugLoc?
  property name : String          # builder-supplied; printing is deterministic regardless
end
```

```iyi
module compiler/ir/function

pub enum Linkage
  External
  Internal
  Private
  LinkOnceOdr
  Weak
  ExternalWeak
end

pub enum TlsModel
  None
  LocalExec
  InitialExec
  LocalDynamic
  GeneralDynamic
end

pub struct DebugSubprogram
  getter display_name : String    # what a PDB S_GPROC32 carries ("inner")
  getter linkage_name : String    # the mangled symbol ("*Named^Named::inner<Int32>:Int32")
  getter file : Int32
  getter line : Int32
end

pub class Block
  getter name : String
  getter insts : Array(Inst)      # phis first, exactly one terminator last
  getter preds : Array(Block)
  property no_vectorize : Bool    # the oracle's llvm.loop hint (codegen.cr 3096); native ignores it
  def terminator : Inst
end

pub class Function < Value
  getter name : String
  getter type : IrType
  property cc : CallConv
  property linkage : Linkage
  property attrs : Array(Attribute)
  property param_attrs : Array(Array(Attribute))
  property ret_attrs : Array(Attribute)
  property import_library : String?   # declarations: the declaring lib's @[Link] library
  property personality : Value?       # oracle round trip only
  property section : String?
  property alignment : Int32
  property subprogram : DebugSubprogram?
  getter params : Array(Param)
  getter blocks : Array(Block)
  def declaration? : Bool
end

pub class Global < Value
  getter name : String
  getter value_type : IrType
  property initializer : Value?
  property linkage : Linkage
  property constant : Bool
  property tls : TlsModel
  property alignment : Int32
  property section : String?
  property unnamed_addr : Bool
  property import_library : String?
end
```

```iyi
module compiler/ir/module

pub class Module
  getter name : String
  getter target : ::Compiler::Platform::Target::Target
  getter layout : DataLayout
  getter types : TypeTable
  getter files : Array(String)            # DebugLoc#file indexes this
  getter flags : Hash(String, Int64)      # module flags (branch-target-enforcement, cf-protection)
  getter globals : Array(Global)          # emission order is part of determinism
  getter functions : Array(Function)
  def function?(name : String) : Function?
  def global?(name : String) : Global?
  def add_function(name : String, type : IrType, cc : CallConv = CallConv::Iyi) : Function
  def add_global(name : String, type : IrType) : Global
end
```

```iyi
module compiler/ir/builder

# Method names and argument order are those of compiler/llvm/builder.iyi.
pub class Builder
  def initialize(@module : Module)
  def position_at_end(block : Block) : Nil
  def position_before(inst : Inst) : Nil
  def insert_block : Block?
  def append_block(fn : Function, name : String) : Block
  def ret(value : Value) : Inst
  def ret_void : Inst
  def br(dest : Block) : Inst
  def cond_br(cond : Value, then_block : Block, else_block : Block) : Inst
  def switch(value : Value, else_block : Block, cases : Array({Value, Block})) : Inst
  def unreachable : Inst
  # add, sub, mul, sdiv, exact_sdiv, udiv, srem, urem, shl, lshr, ashr, and, or, xor,
  # fadd, fsub, fmul, fdiv, frem: all of this shape
  def add(lhs : Value, rhs : Value, name : String = "") : Inst
  def fneg(value : Value, name : String = "") : Inst
  def icmp(predicate : IntPredicate, lhs : Value, rhs : Value, name : String = "") : Inst
  def fcmp(predicate : RealPredicate, lhs : Value, rhs : Value, name : String = "") : Inst
  def alloca(type : IrType, name : String = "") : Inst
  def load(type : IrType, pointer : Value, name : String = "") : Inst
  def store(value : Value, pointer : Value) : Inst
  def gep(type : IrType, pointer : Value, indices : Array(Value), name : String = "") : Inst
  def inbounds_gep(type : IrType, pointer : Value, indices : Array(Value), name : String = "") : Inst
  # trunc, zext, sext, fptrunc, fpext, fp2si, fp2ui, si2fp, ui2fp, ptr2int, int2ptr, bit_cast: all of this shape
  def trunc(value : Value, type : IrType, name : String = "") : Inst
  def select(cond : Value, then_value : Value, else_value : Value, name : String = "") : Inst
  def phi(type : IrType, incoming : Array({Value, Block}), name : String = "") : Inst
  def call(fn_type : IrType, callee : Value, args : Array(Value), name : String = "") : Inst
  def invoke(fn_type : IrType, callee : Value, args : Array(Value), normal : Block, unwind : Block, name : String = "") : Inst
  def extract_value(aggregate : Value, index : Int32, name : String = "") : Inst
  def insert_value(aggregate : Value, value : Value, index : Int32, name : String = "") : Inst
  def intrinsic(id : IntrinsicId, overload : Array(IrType), args : Array(Value), name : String = "") : Inst
  def inline_asm(fn_type : IrType, template : String, constraints : String, side_effects : Bool, align_stack : Bool, dialect : AsmDialect) : Value
  def fence(ordering : Ordering, single_thread : Bool) : Inst
  def cmpxchg(pointer : Value, compare : Value, replacement : Value, success : Ordering, failure : Ordering) : Inst
  def atomicrmw(operation : String, pointer : Value, value : Value, ordering : Ordering, single_thread : Bool) : Inst
  def thread_local_addr(global : Global) : Inst
  def thread_pointer(kind : ThreadPointerKind) : Inst
  def set_debug_loc(loc : DebugLoc?) : Nil
end
```

`TypeTable`, `Module`, `Function`, `Block` and `Value` likewise provide the methods `codegen.iyi` calls on `Context`, `Module`, `LLVMType`, `LLVMValue`, `Function` and `BasicBlock` (`int32`, `pointer`, `struct`, `struct_named`, `struct_set_body`, `array`, `get_function?`, `append_basic_block`, `type`, and the rest); B4 lists them by `grep` and B1 provides each under the same name.

```iyi
module compiler/ir/printer
pub def print(m : Module) : String                 # deterministic; identical across runs, hosts and thread counts

module compiler/ir/parser
pub def parse(text : String) : Module | IrParseError

module compiler/ir/verifier
# Types; SSA dominance; phi/pred agreement; one terminator per block; Call operands against fn_type;
# CallConv::C only with lowered signatures; and `tls-fresh`: no ThreadLocalAddr or ThreadPointer result
# is used after a call or a back-edge that follows it.
pub def verify(m : Module) : Array(IrError)
```

**Determinism (contract for every producer, pass and writer):** no output depends on hash iteration order, object addresses, thread count or wall clock; parallel results merge in module order; timestamps are zero; Mach-O `LC_UUID`, the PE RSDS GUID and build ids are a hash of the output with the field zeroed; `SOURCE_DATE_EPOCH` is honoured; source paths are normalised as the oracle normalises them.

### 3.3 Backends

```iyi
module compiler/backend/backend

pub enum BackendKind
  Native
  Llvm
end

pub enum OptLevel
  O0
  O1          # native default and --release; the LLVM path keeps 0..3
end

pub enum DebugLevel
  None
  LineTables  # default, as the Crystal-hosted compiler's LineNumbers
  Full
end

pub struct LinkLibrary
  getter name : String          # "libSystem", "Security", "kernel32", "wasi_snapshot_preview1"
  getter kind : String          # "dylib" | "framework" | "dll" | "wasi"
end

pub struct LinkInputs
  getter libraries : Array(LinkLibrary)
  getter entry : String?        # nil: the target's default (darwin LC_MAIN "main"; Linux and wasm "_start"; Windows "__iyi_win_start")
  getter stack_reserve : Int64  # Windows: 0x800000
  getter min_os : String?       # darwin: "14.4"
end

pub struct BuildRequest
  getter module : ::Compiler::Ir::Module::Module
  getter opt : OptLevel
  getter debug : DebugLevel
  getter link : LinkInputs
  getter output : String
  getter emit_ir : Bool         # also write <output>.ir (printer output)
  getter emit_obj : Bool        # also write the platform relocatable object
end

pub trait Backend
  abstract def kind : BackendKind
  abstract def supports?(target : ::Compiler::Platform::Target::Target) : Bool
  abstract def build(request : BuildRequest) : BuildResult | BuildError
end

NATIVE_TARGETS = [] of String   # a target's landing PR appends its normalised triple

pub def default_kind(target : ::Compiler::Platform::Target::Target) : BackendKind
pub def choose(requested : BackendKind?, target : ::Compiler::Platform::Target::Target, available : Array(Backend)) : Backend | BackendRefusal
```

### 3.4 Objects and the linker

```iyi
module compiler/native/obj/object

pub enum ObjFormat
  MachO
  Elf
  Coff
  Wasm
end

pub enum SectionKind
  Text
  ReadOnly
  Data
  ZeroFill
  TlsData
  TlsZeroFill
  TlsVars          # Mach-O TLV descriptors
  Unwind           # .eh_frame / .pdata / .xdata passed through from LLVM objects
  Other
end

pub enum SymbolBinding
  Local
  Global
  Weak
end

pub enum SymbolKind
  Func
  Object
  Tls
  Section
  Undefined
  Absolute
end

pub enum RelocKind
  Abs64
  Abs32
  PcRel32                 # x86_64 rip-relative data; ELF PREL32 (eh_frame)
  X86Branch32             # call/jmp rel32 (ELF PLT32, COFF REL32 on calls)
  X86GotPcRel             # GOTPCREL(X): a GOT entry or relaxation
  X86TpOff32              # local-exec %fs offset
  A64Call26
  A64Jump26
  A64AdrpPage21
  A64AddLo12
  A64Ldst8Lo12
  A64Ldst16Lo12
  A64Ldst32Lo12
  A64Ldst64Lo12
  A64Ldst128Lo12
  A64GotPage21
  A64GotLo12
  A64TlvpPage21           # Mach-O TLV descriptor
  A64TlvpLo12
  A64TprelHi12            # ELF local-exec
  A64TprelLo12Nc
  CoffAddr32Nb            # image-relative (.pdata)
  CoffSecRel32            # TLS offset in .tls
  CoffSection
  Sub64                   # Mach-O SUBTRACTOR pairs and differences
  WasmFuncIndexLeb
  WasmTableIndexSleb
  WasmTableIndexI32
  WasmMemAddrLeb
  WasmMemAddrSleb
  WasmMemAddrI32
  WasmTypeIndexLeb
  WasmGlobalIndexLeb
end

pub struct Reloc
  getter offset : Int64
  getter kind : RelocKind
  getter symbol : Int32
  getter addend : Int64
end

pub class Section
  property name : String          # canonical: ".text" ".rodata" ".data" ".bss" ".tdata" ".tbss" ".tlv"; writers map per format
  property kind : SectionKind
  property align : Int32
  property bytes : ::Std::Slice::Bytes
  property size : Int64           # for zero-fill
  property relocs : Array(Reloc)
end

pub class Symbol
  property name : String          # undecorated; the Mach-O writer adds "_"
  property kind : SymbolKind
  property binding : SymbolBinding
  property section : Int32        # -1 when undefined or absolute
  property value : Int64
  property size : Int64
  property import_library : String?
end

pub struct LineRow
  getter offset : Int32           # from the function's start
  getter file : Int32
  getter line : Int32
  getter column : Int32
end

pub struct DebugFunc               # format-neutral; the linker writes DWARF or PDB from it
  getter symbol : Int32
  getter display_name : String
  getter rows : Array(LineRow)
end

pub enum FrameOp
  PushFrameRecord                 # stp x29, x30 / push rbp
  SetFramePointer
  SaveReg
  AllocStack
end

pub struct FrameEvent
  getter offset : Int32           # code offset after which the event holds
  getter op : FrameOp
  getter reg : Int32
  getter value : Int64
end

pub struct FrameDesc               # format-neutral; the linker writes .eh_frame or .pdata/.xdata from it
  getter symbol : Int32
  getter size : Int32
  getter events : Array(FrameEvent)
end

pub class ObjectFile
  property format : ObjFormat
  property target : ::Compiler::Platform::Target::Target
  property producer : String      # "iyi-native" or "llvm"; the linker refuses a mix
  property sections : Array(Section)
  property symbols : Array(Symbol)
  property debug_funcs : Array(DebugFunc)
  property frame_descs : Array(FrameDesc)
  property files : Array(String)
end
```

```iyi
module compiler/native/obj/macho      # likewise elf, coff
pub def write_object(obj : ObjectFile) : ::Std::Slice::Bytes
pub def read_object(bytes : ::Std::Slice::Bytes, target : ::Compiler::Platform::Target::Target) : ObjectFile | ObjError

module compiler/native/link/link
pub struct LinkedImage
  getter executable : ::Std::Slice::Bytes
  getter companions : Hash(String, ::Std::Slice::Bytes)   # ".dwarf" (darwin), ".pdb" (Windows)
end

# Deterministic. Errors name the symbol and the object that referenced it.
pub def link(objects : Array(::Compiler::Native::Obj::Object::ObjectFile), inputs : ::Compiler::Backend::Backend::LinkInputs) : LinkedImage | LinkError
```

**Linker-defined symbols** (a contract with the prelude and rt): ELF `__ehdr_start`, `__data_start`, `__bss_start`, `_end`, `__iyi_rela_start`/`__iyi_rela_end` (the relative relocations), `__iyi_tdata_start`/`__iyi_tdata_end`, `__iyi_tls_memsz`, `__iyi_tls_align` (absolute), `__iyi_relro_start`/`__iyi_relro_end`; PE `_tls_index`, `_tls_used`; wasm `__heap_base`, `__data_end`, `__stack_pointer`.

### 3.5 Machine IR

```iyi
module compiler/native/mir

pub enum RegClass
  Gpr
  Fpr
end

pub struct VReg
  getter id : Int32
  getter cls : RegClass
end

pub struct PReg
  getter id : Int32
  getter cls : RegClass
end

pub enum OperandKind
  Virtual
  Physical
  Imm
  Symbol            # symbol index, addend, RelocKind
  Block
  FrameSlot
  OutgoingArg
end

pub struct Operand
  getter kind : OperandKind
  getter reg : Int32
  getter imm : Int64
  getter reloc : ::Compiler::Native::Obj::Object::RelocKind?
end

pub class MInst
  property opcode : Int32         # the target's opcode enum value
  property defs : Array(Operand)
  property uses : Array(Operand)
  property clobbers : Array(PReg)
  property call : Bool
  property terminator : Bool
  property side_effects : Bool
  property loc : ::Compiler::Ir::Inst::DebugLoc?
end

pub class MBlock
  property insts : Array(MInst)
  property succs : Array(Int32)
end

pub class FrameInfo
  property slots : Array({Int64, Int32})   # size, align (allocas and spills)
  property outgoing_bytes : Int64
  property callee_saved : Array(PReg)
  property has_calls : Bool
  property naked : Bool
end

pub class MFunction
  property name : String
  property blocks : Array(MBlock)
  property frame : FrameInfo
  property vreg_count : Int32
end

# SectionWriter (compiler/native/emit.iyi) appends bytes, relocations and symbols to one Section of an ObjectFile.
pub trait TargetIsa
  abstract def select(fn : ::Compiler::Ir::Function::Function, layout : ::Compiler::Ir::Layout::DataLayout) : MFunction
  abstract def allocatable(cls : RegClass) : Array(PReg)
  abstract def callee_saved : Array(PReg)
  abstract def finish_frame(fn : MFunction) : Nil              # prologue, epilogue, probes, FrameDesc events
  abstract def encode(fn : MFunction, out : SectionWriter) : Nil
  abstract def assemble(template : String, operands : Array(Operand), out : SectionWriter) : Nil | AsmError
end
```

### 3.6 The analysed-program contract (S1 to S2)

`src/compiler/semantic/typed.iyi` declares a trait with exactly the members `src/compiler/iyi/codegen/*.cr`, `preempt_checks.cr` and `wasm_roots.cr` read from `Program`, `Type`, `ASTNode#type`, `Call#target_defs`, `Def` (instances, vars, closure flags, the annotations `@[Primitive]`, `@[Naked]`, `@[NoInline]`, `@[AlwaysInline]`, `@[NoPreempt]`, `@[Raises]`), class variables (`@[ThreadLocal]`, initialisers, once flags), constants, `lib` funs (real name, convention, varargs, `@[Link]` library), type ids (union member order as `program.cr` 1601-1604), layouts (type id in the header word's high half, GC_DESIGN Stage 5), `ARGC_UNSAFE`/`ARGV_UNSAFE`, and flags. S0 extracts the list by reading every member access in those files; the semantic port implements the trait and the lowering consumes only it. Names follow the Crystal originals so the port stays a mechanical translation.

### 3.7 The runtime contract every producer and backend honours

1. Entry: darwin dyld calls `main(argc, argv)`; on Linux, Windows and wasm, rt calls `main` (wasm: `__main_argc_argv`) and exits with its result. `main` is the prelude's (`prelude.iyi` 11688), which calls `__iyi_enter`.
2. Allocation through `__iyi_new(size, type_id, flags)`, `__iyi_malloc64`, `__iyi_malloc_atomic64`, `__iyi_realloc64`; pointer-bearing stores bracketed by `__iyi_write_barrier_begin`/`__iyi_write_barrier(address, words)` when the `__iyi_marking` byte is set; `__iyi_gc_layouts` tables emitted by the lowering.
3. Back-edge preemption checks per 2.2; `__iyi_preempt` on the cold path.
4. TLS per 2.2; `ThreadLocalAddr` re-evaluated after every call and back-edge (verifier rule `tls-fresh`).
5. Stack probes, frame pointers, callee-saved set per 2.2.
6. No unwinding; `raise` is the prelude's panic.
7. Linker-defined symbols per 3.4.

### 3.8 Gate conventions

- `bench/lib/mutation.sh` (A1): `prove_mutation <label> <file> <old> <new> -- <check command...>` copies the file aside, replaces the first occurrence (exit 3 if absent: "PATCH CHANGED NOTHING: this proves nothing" fails the gate), runs the check, requires it to fail ("caught"), and restores through `trap ... EXIT INT TERM` so an interrupt never leaves a mutated source.
- Output: `== N. <step>` lines, final `== ALL <NAME> CHECKS PASSED` or `== SOME <NAME> CHECKS FAILED`, exit status 0 or 1. No gate skips silently: a gate that cannot run its target here says which job runs it, and `bench/gates_reachable.py` proves some job does.
- Drivers: `bench/selfhost_gates.sh` runs every `bench/selfhost_*_exercise.sh` it globs; `bench/native_gates.sh <triple>` runs every `bench/native_*_exercise.sh` for that triple. `ci_plan.py`'s reach follows the globs, so later PRs add gates without touching `iyi.yml`.
- Oracle for machine code: LLVM's integrated assembler through the Crystal-hosted compiler. The gate writes the instruction or template into a naked `fun` with explicit-register constraints, builds it with `bin/iyi build --cross-compile --target <triple> --emit obj`, and reads the function's bytes and relocations with our own object readers. No new tool is required; `llvm-mc` may be used where present.
- Tripwire: `bench/lib/tripwire.sh` (C6) builds a directory of shims for every external tool named in section 0 item 3 and prepends it to `PATH`.

### 3.9 Proof inventory at the grounded revisions, and blind spots

| proof | where | blind spot |
|---|---|---|
| 23 `bench/selfhost_*_exercise.sh` | line B 9a2a08173 | darwin-only paths; not run upstream; four red after the merge; `selfhost_compile` compares exit codes only; mutation restore not interrupt-safe; the codegen IR normaliser hides type ids |
| `bench/dependency_floor.sh`, `bench/floor_base.sh` | upstream 140375a3b | LLVM path only; transitive libraries unmeasured; modified by #147 |
| `bench/panics.sh` (incl. 9a named frames), `bench/debug_info.py` | upstream, `samples` job | LLVM path only |
| `cross-objects`, `cross-run` (QEMU aarch64), `wasi-run` (wasmtime and wasi-sdk), `windows-*`, `darwin*` jobs | upstream iyi.yml | LLVM path only |
| `bench/doc_numbers.py` | upstream | does not read BOOTSTRAP.md or the STAGE documents |

---

## 4. Phases and slices

| phase | reaches | depends on | proven first |
|---|---|---|---|
| A | (a) line B green on current upstream | nothing | A1 |
| B | the seam | B1: nothing; B4: A3 | B1 |
| C | (c) first native program, aarch64-darwin | B1; C6 also B3, B4 | C2 (its first increment) |
| D | (d) the full language native on five targets | C, B2 | D1 |
| S | (b) stage 1 | S0: nothing; S2: B1 | S0 |
| E | (e) stage 2 == stage 3, zero LLVM | S, D | E1 |
| F | (f) stale testing moved, Crystal-hosted compiler deleted | E, #147 merged upstream | F1 |

[IR] marks slices that need independent review (consequential architecture, security posture, destructive operations). Every slice reports to INT the exact shared-file lines it needs. Branches are cut from the fork's integration branch (`reintegrate/upstream-master-into-selfhost` until #72 merges, then `integrate/selfhost`) and merged back with merge commits.

### Phase A: line B green on current upstream (reaches (a))

Exit: fork PR #72 has every check green; all selfhost gates green on the Linux container and on macos-15; upstream PR #104 (line A, with #71 folded in) green.

**A1 (first) Portable gates and the selfhost CI rail.**
- Files: `bench/selfhost_*_exercise.sh` (all 23), `bench/lib/mutation.sh` (new), `bench/selfhost_gates.sh` (new). Requests to INT: a `selfhost` job in `iyi.yml` (ubuntu-24.04, `crystallang/crystal:1.21.0-build`, provisions `llvm-config` as line B already does, runs `bash bench/selfhost_gates.sh`) and a `selfhost-darwin` job (macos-15), both in `result.needs`, replacing line B's 23 individual steps in the `iyi` job; a `ci_plan.py` rule selecting both when a PR changes `src/compiler/**/*.iyi`, `bench/selfhost_*` or `bench/fixtures/**`, with the matching case in `bench/ci_plan_exercise.py` [UNVERIFIED: `ci_plan.py`'s handling of non-bench source paths; the slice reads the whole script first].
- Change: replace `/opt/homebrew` paths with `command -v` lookups; `otool -L` on darwin and `readelf -d` on Linux; move every mutation proof onto `prove_mutation`; make `selfhost_compile` compare stdout as its header says.
- Non-goals: fixing the four red gates.
- Acceptance: `bash bench/selfhost_gates.sh` runs all 23 gates on both runners and prints each verdict; every mutation proof prints "caught"; a scripted SIGINT during a mutation leaves `git diff --exit-code` clean; `selfhost_compile` fails when a fixture's stdout differs (a new mutation proof).
- Gate: the driver; jobs `selfhost` (ubuntu-24.04 container) and `selfhost-darwin` (macos-15).
- Review: a portability edit must not weaken a comparison; evidence: the per-gate mutation list before and after is identical or larger.

**A2 Lexer and parser: `float.iyi`'s `(self / scale)`.**
- Files: `src/compiler/syntax/lexer.iyi`, `src/compiler/syntax/parser.iyi`, a fixture in `bench/fixtures/`.
- Change: find why `(self / scale)` (`src/iyi/float.iyi` 236) is rejected and fix it. Reading the code, a slash followed by whitespace lexes as `OP_SLASH` (`lexer.iyi` 552-553), so the cause is elsewhere [UNVERIFIED: the probe log names the failing phase and token].
- Acceptance: `selfhost_lexer` and `selfhost_parser` green with a new fixture containing `(self / scale)`; `float.iyi` reaches its floor in `selfhost_prelude` (A4 integrates floors).
- Mutation: revert the fix; the new fixture fails.

**A3 `codegen.iyi` repairs, and its exception lowering retired.**
- Files: `src/compiler/codegen/codegen.iyi`, `bench/fixtures/cg_*.iyi`, `bench/selfhost_codegen_exercise.sh`.
- Change: (1) `alloca void` for `Array#delete`'s `found = nil` then `found = element` (`array.iyi` 585-589): a `Nil` first assignment must not fix the local's type (`LocalVarCollector` 184-189, `infer_var_type` 913-914, `llvm_type_from_name` 750-751); take the first non-`Nil` assignment and make the slot nilable. (2) Close the IR divergence against the Crystal oracle on `cg_closures` (closure struct naming, 1661-1679), `cg_generics` (unknown generic arguments falling back to `i32` at 765-766 and 1050-1064; mangling duplicated at 2770/2776 and 3989/3995) and `cg_virtual_dispatch` (hierarchy range at 4151-4154). Causes are [INFERENCE] from reading; the gate's diff is the ground truth. (3) Delete the `ExceptionHandler` and `raise` lowering (2165-2486) and refuse `rescue` with the oracle's message (`semantic/main_visitor.cr` 3356-3375); `cg_exceptions.iyi` and `cg_raise.iyi` become refusal fixtures whose message must equal the oracle's.
- Non-goals: semantic typing (stage-1 work); this file is replaced by S2.
- Acceptance: `selfhost_codegen` identical on every remaining fixture, refusal fixtures identical, all mutations caught; `array.iyi` and `prelude.iyi` no longer emit `alloca void` (the `selfhost_ir_valid` gate).
- Mutation: restore first-assignment-wins; a `cg_` fixture with a `nil`-first local diverges.

**A4 Pipeline, loader and prelude gates.**
- Files: `src/compiler/loader.iyi`, `src/compiler/compiler.iyi`, `src/compiler/tools/compile.iyi`, `bench/selfhost_compile_exercise.sh`, `bench/selfhost_prelude_exercise.sh`, `bench/selfhost_prelude_whole_exercise.sh`, `bench/fixtures/compile_*.iyi`.
- Change: (1) `concurrency.iyi` cannot see `Atomic` in single-file mode because `resolve_single` reads only the root file (`loader.iyi` 159-162) and `Atomic` comes from `atomic.iyi`, required by `prelude.iyi` 37: make the single-file probe load a prelude file's own requires, or record the floor with that reason; (2) find the one uncaught mutation in `selfhost_compile` (candidates [INFERENCE]: the resolver-order mutation at `loader.iyi` 280 and the missing-import mutation at 273, each caught only if `compile_diamond`'s exit depends on it; and the `"\${@}"` quoting at gate lines 277-279) and make it caught; (3) delete `Compiler.append_raise_runtime` (`compiler.iyi` 424-574) and its mutations; `compile_raise.iyi` and `compile_implicit_raise.iyi` become refusal fixtures; (4) reconcile `selfhost_prelude` (floor `link` for `prelude.iyi`) with `selfhost_prelude_whole` (floor `codegen`, line 39); integrate A2's and A3's floors.
- Depends: A1; floors after A2 and A3.
- Acceptance: all three gates green on both runners; every mutation caught.

**A5 #72's other red checks.**
- Files: as triage finds; expected `src/std/{quic,qpack,http3,webtransport,oauth,oauth2}.iyi` and their `bench/std_*_exercise.*`.
- Change: classify each failing check at #72's head as (i) caused by line B's std additions, (ii) caused by gate portability (A1), (iii) caused by the reintegrate merge, or (iv) failing on upstream master too (prove with the same job on master); fix (iii); handle (i) per the decision below; record (iv) with the upstream run's link.
- **[JASON] decision needed before A5 is dispatched:** the ~7,800 lines of std features in line B (correction 3) are not self-hosting work. Recommendation: move them to their own fork branch and upstream PRs, out of the self-hosting line.
- Acceptance: #72's checks all green.

**A6 Truthful line B documents.**
- Files: `BOOTSTRAP.md`, `STAGE_ONE.md`, `STAGE_TWO.md` (the latter two may fold into `BOOTSTRAP.md`); figure requests to INT for `bench/doc_numbers.py`.
- Change: correct every item in correction 5; replace `STAGE_TWO.md` section 6 with this plan's section 0; register each stated figure in `doc_numbers.py` CLAIMS or delete the "measured by doc_numbers.py" sentence; record that the Itanium raise path is retired.
- Acceptance: `python3 bench/doc_numbers.py` green with the new claims; `grep -n 'iyi\.iyi' BOOTSTRAP.md STAGE_*.md` empty.

**A7 Line A green (decision 2).**
- Files: `selfhost/**` on fork branch `selfhost/port` (upstream #104), `src/iyi/string.iyi` (from #71).
- Change: merge `selfhost/imports` (#71) into `selfhost/port` (#104) with a merge commit, update against current upstream master, fix #104's failing check ("iyi, built and run on Windows") or prove it fails on master too.
- Acceptance: #104 every check green; #71 closed with a pointer to the merge.

**A8 #147 forward compatibility.**
- Files: line B front-end files the probe shows need it (`syntax/*.iyi`, `macros/*.iyi`); a fixture set copied from #147's head versions of `src/iyi/*.iyi` and the touched `src/std/*.iyi`.
- Change: in an ovnfs checkout of line B, overlay #147's versions of those files (read with `gh api ...?ref=<head sha>`) and run `selfhost_lexer`, `selfhost_parser`, `selfhost_prelude`; fix the front-end gaps found (`@[Effect(...)]`, `flag?(:iyi_observe)`, the appended `fun __iyi_raise_cast_failed` and `__iyi_raise_closure_to_c`).
- Non-goals: touching any file #147 owns.
- Acceptance: the three gates give identical results with and without #147's files overlaid.

### Phase B: the seam (prerequisite for (b), (c), (d))

Exit: `selfhost_codegen`, `selfhost_compile` and `selfhost_ir_valid` green with `codegen.iyi` emitting IR and the translator producing LLVM; the round-trip gate green over the full corpus for all five targets.

**B1 (first) IR core [IR].**
- Files: `src/compiler/ir/{types,values,inst,intrinsics,function,module,builder,printer,parser,verifier,layout}.iyi`, `bench/native_ir_exercise.sh`, `bench/fixtures/ir/**`.
- Change: section 3.2 exactly. `layout.iyi` reproduces LLVM's DataLayout for aarch64-darwin, aarch64-linux, x86_64-linux, x86_64-windows-msvc and wasm32-wasi (`i128` aligned to 16 on both 64-bit architectures).
- Non-goals: passes, backends.
- Acceptance: `print(parse(text)) == text` for every fixture; modules the builder fixtures construct print identically after a parse; each malformed fixture is refused by the verifier with its named error, `tls-fresh` included; `DataLayout#llvm_string` per target equals the oracle's `target datalayout` line.
- Gate: `bench/native_ir_exercise.sh`; jobs `native-linux` (ubuntu-24.04 container; added by INT with B1's PR) and `native-darwin`.
- Mutation: break `offset_of`'s alignment rounding; the layout fixture fails. Swap two printer cases; the round trip fails.
- Review: an IR that cannot express something the oracle emits; the evidence is B2's coverage report, so B1 merges after B2's report has run once against B1's branch.

**B2 LLVM translator and importer, and the round trip [IR].**
- Files: `src/compiler/backend/llvm/{translate,import,emit}.iyi`; additions to `src/compiler/llvm/{lib_llvm,values,module,builder,target}.iyi` (introspection: functions, blocks, instructions, operands, predicates, orderings, alignment, GEP source types, address spaces, TLS modes, inline asm strings, intrinsic ids, attributes, debug locations); `src/compiler/tools/ir.iyi` (`iyi-ir import|print|verify|translate|roundtrip|coverage`); `bench/native_llvm_roundtrip_exercise.sh`.
- Change: `translate(m : Ir::Module)` to an LLVM module and `import(llvm module) : Ir::Module | ImportError`, refusing any opcode, intrinsic or attribute outside the closed sets, by name. `roundtrip` strips debug info on both sides (`LLVMStripModuleDebugInfo`), prints both with LLVM's printer and compares; line locations are compared separately as (function, instruction index, file, line).
- Depends: B1.
- Acceptance: for every program in `samples/iyi/*.iyi`, every `bench/std_*_exercise.iyi`, every `bench/fixtures/cg_*.iyi` and `compile_*.iyi`, and the line B tools, on each of the five targets (`bin/iyi build --emit llvm-ir --cross-compile --target <triple>`), `iyi-ir roundtrip` prints `identical`; `iyi-ir coverage` writes the op, intrinsic and attribute inventory, which becomes `IntrinsicId`'s members; the rt `.ir` files translate and verify.
- Gate: `bench/native_llvm_roundtrip_exercise.sh`; job `native-linux`.
- Mutation: drop `nsw` in `translate`; the round trip differs. Drop one member of `IntrinsicId`; import refuses by name.
- Experiment it carries: [UNVERIFIED: that `--emit llvm-ir` is the whole program when std modules come from `.iyimod` artifacts (`compiler.cr` 3502-3504), and that it cross-compiles every target from Linux]. Verify by compiling one emitted `.ll` per target to an object, linking with the target's linker, and running it; if artifacts are excluded, use the oracle's flag that forces source builds.

**B3 Backend interface, selection, entry points.**
- Files: `src/compiler/backend/backend.iyi`, `src/compiler/compiler.iyi` (the emit and link stages call `Backend#build`; the LLVM backend wraps today's path), `src/compiler/command/driver.iyi` (`--backend`, `--print-backend`, `--emit ir`), `src/compiler/stage1.iyi`, `src/compiler/stage1_llvm.iyi` (new), `src/compiler/tools/compile.iyi`, `src/compiler/tools/compile_native.iyi` (new), `bench/native_backend_select_exercise.sh`. Requests to INT: Makefile targets `iyi-compile-native`, `iyi-stage1-llvm`.
- Depends: B1; after A4 (which owns `compiler.iyi` and `tools/compile.iyi` until it merges).
- Acceptance: section 2.1's selection behaviour, each case asserted with exact output; `.build/iyi-compile-native` links no LLVM (`otool -L`, `readelf -d`) and refuses `--backend llvm` with the exact message.
- Mutation: add a triple to `NATIVE_TARGETS`; the `--print-backend` assertions fail.

**B4 `codegen.iyi` on IR.**
- Files: `src/compiler/codegen/codegen.iyi`, `src/compiler/compiler.iyi` (B3 hands it over), `bench/selfhost_codegen_exercise.sh` (dump path).
- Change: imports move from `compiler/llvm/*` to `compiler/ir/*`; `compile_declarations_to_module` returns `Ir::Module`; the LLVM path translates.
- Depends: A3, B1, B2, B3.
- Acceptance: `selfhost_codegen` (LLVM IR identical to the Crystal oracle after the existing normalisation), `selfhost_compile` and `selfhost_ir_valid` green with unchanged expectations.
- Mutation: the existing codegen mutations, unchanged, still caught.

### Phase C: first native program on aarch64-darwin, no LLVM, no system linker (reaches (c))

Exit: every remaining `bench/fixtures/compile_*.iyi` built by `.build/iyi-compile-native --backend native` on macos-15 runs with the oracle's exit status and stdout; the tripwire log is empty; the binary passes `codesign -v --strict`; `otool -L` shows libSystem alone; `LC_BUILD_VERSION` lists no tools.

**C1 Object model and Mach-O relocatable objects.**
- Files: `src/compiler/native/obj/object.iyi`, `src/compiler/native/obj/macho.iyi`, `bench/native_obj_exercise.sh`, `bench/fixtures/native_obj/**`.
- Change: section 3.4's model, landed first as its own commit so C2 and C3 build on it; Mach-O `MH_OBJECT` writer and reader for arm64 (every ARM64 relocation type LLVM emits, `SUBTRACTOR`/`ADDEND` pairs included).
- Acceptance: for every object the oracle emits for the corpus (`--cross-compile --target aarch64-apple-darwin --emit obj`), `read`, `write`, `read` gives an equal `ObjectFile`, and the rewritten object linked by `cc` on macos-15 runs identically to the original.
- Gate: `bench/native_obj_exercise.sh`; jobs `native-linux` (read/write equality) and `native-darwin` (link and run).
- Mutation: shift `A64AdrpPage21`'s encoding by one bit; the relinked program crashes.

**C2 (first in C) Mach-O executables and ad-hoc signing [IR].**
- Files: `src/compiler/native/link/{link,imports,macho_exe,codesign}.iyi`, `bench/native_link_exercise.sh`.
- First increment, which proves the platform before anything else is built: link a hand-built `ObjectFile` that calls `_write` and `_exit` into a signed executable that runs on macos-15 and on the newest macOS available locally. If dyld or the kernel refuses `LC_DYLD_INFO_ONLY` or the signature, switch this slice to chained fixups before continuing (risk R3).
- Then: link the oracle's darwin objects for every corpus program (through C1's reader) with our linker: TLV descriptors, rebase opcodes, export trie, `LC_SYMTAB`; unwind and debug sections from LLVM objects dropped (nothing unwinds on darwin; named frames come from D6).
- Depends: C1.
- Acceptance: every corpus program linked by our linker from oracle objects runs on macos-15 with the oracle binary's exit status, stdout and stderr; `codesign -v --strict` passes; no `__stub_helper` section; `nm -u` lists no `dyld_stub_binder`.
- Gate: `bench/native_link_exercise.sh aarch64-apple-darwin`; job `native-darwin`.
- Mutation: hash one page wrong in the CodeDirectory; the run dies with SIGKILL. Bind one import to the wrong library ordinal; dyld refuses to launch.

**C3 Native core and the aarch64 code generator [IR].**
- Files: `src/compiler/native/{mir,target,lower,regalloc,frame,emit,driver}.iyi`, `src/compiler/native/aarch64/{regs,abi,isel,encode}.iyi`, `bench/native_encode_exercise.sh`, `bench/native_codegen_exercise.sh`.
- Change: sections 2.2 and 3.5 for aarch64, both the darwin and Linux variants of AAPCS64, `-O0` only (D7 adds passes).
- Depends: B1, C1; B2 for acceptance (2).
- Acceptance: (1) every MIR opcode form encodes to the oracle's bytes (section 3.8's method); (2) for every IR module the importer produces from the `cg_*` and `compile_*` fixtures, the native object linked by `cc` on macos-15 runs with the oracle's exit status and stdout; (3) a function with a 64 KiB frame contains the page-by-page probe (checked on the MIR dump).
- Gates: both scripts; jobs `native-linux` (encoding) and `native-darwin` (run).
- Mutation: swap the operands of `sub` in isel; the arithmetic fixtures differ. Stop saving callee-saved registers in the prologue; the recursive fixture holding values across calls differs. Drop the probe; check (3) fails.

**C4 Inline asm: inventory, constraints, aarch64 assembler.**
- Files: `src/compiler/native/asm/{constraints,inventory}.iyi`, `src/compiler/native/aarch64/asm.iyi`, `bench/native_asm_exercise.sh`.
- Change: `inventory` parses every `.iyi` under `src/` with the line B parser and macro interpreter per target and lists `(file:line, template, constraints, dialect)`; `constraints` implements LLVM's constraint grammar for what the inventory finds; the aarch64 assembler encodes every aarch64 template in it.
- Depends: C1 (the reader for the oracle's bytes).
- Acceptance: every aarch64 template, darwin and Linux, assembles to the oracle's bytes and relocations; a template outside the supported set is refused by name.
- Gate: `bench/native_asm_exercise.sh aarch64`; job `native-linux`.
- Mutation: swap the `@PAGE` and `@PAGEOFF` relocation kinds; the comparison fails.

**C5 Native runtime helpers.**
- Files: `src/compiler/native/rt/builtins.ir`.
- Change: the `__iyi_native_*` helpers in IR text: memory copy, move and fill; 128-bit division and remainder (signed and unsigned); 128-bit float conversions; overflow-checked 128-bit multiply. Linked into every native program by the driver.
- Acceptance: a fixture calling every helper over boundary values (signed minimum, powers of two, maximum values) prints the same output built natively and built through B2's translator with LLVM.
- Gate: part of `bench/native_codegen_exercise.sh`.

**C6 First light.**
- Files: `src/compiler/native/driver.iyi` (from C3, handed over), `src/compiler/tools/compile_native.iyi` (from B3), `bench/lib/tripwire.sh`, `bench/native_first_light_exercise.sh`. Requests to INT: `native-darwin` (macos-15) in `result.needs`; a `ci_plan.py` rule for `src/compiler/native/**`, `src/compiler/ir/**`, `src/compiler/backend/**`, `bench/native_*`.
- Depends: B3, B4, C1 to C5.
- Acceptance: section C's exit criteria, asserted by the gate.
- Mutation: make the driver call `cc` for linking; the tripwire log is non-empty and the gate fails. Link one object marked `producer = "llvm"`; the mix refusal fires.

### Phase D: the full language native on all five targets (reaches (d))

The bridge: `iyi-native build-ll <prog.ll> --imports <prog.imports> --target <triple> -o <prog>` imports the oracle's IR (B2), compiles it natively and links it with our linker and rt. Its front-end half uses the Crystal-hosted compiler; the backend half has no LLVM. D's acceptance is behavioural parity on the corpus per target; zero LLVM end to end for the full language arrives with S4 and E.

The corpus every D gate uses: `samples/iyi/*.iyi` with their stdin cases (`calc`), every `bench/std_*_exercise.iyi`, the runtime gates' programs (`bench/panics.sh`, `concurrency_exercise.sh`, `parallel_exercise.sh`, `collect_trigger.sh`, `defer_cost.sh`, `spawn_fuzz.sh`, `chaos_exercise.sh`), the line B tools.

**D1 (first) aarch64 runtime contract, and darwin on the full corpus.**
- Files: `src/compiler/native/aarch64/{isel,encode,abi}.iyi` (after C3 merges), `src/compiler/tools/native.iyi` (the bridge tool and the `.imports` sidecar writer), `bench/native_corpus_exercise.sh`, `bench/native_atomics_exercise.sh`.
- Change: TLV access and descriptors; LL/SC atomics and orderings; naked functions; `ThreadPointer` reads (`tpidr_el0`, `tpidrro_el0`); preemption-check lowering; Apple variadic rules.
- Depends: C (all), B2.
- Acceptance: every corpus program, bridged and built natively on macos-15, matches the oracle binary's exit status, stdout and stderr, including `panics.sh` except 9a (D6); `collect_trigger.sh` and `parallel_exercise.sh` pass ten consecutive runs; `native_atomics_exercise.sh`: for every (operation, ordering, width) the oracle's corpus uses, our instruction sequence equals the oracle's object code.
- Gates: `bench/native_corpus_exercise.sh aarch64-apple-darwin`, `bench/native_atomics_exercise.sh aarch64`; job `native-darwin`.
- Mutation: emit `ldr` for an acquire load; the atomics comparison fails. Reuse one `ThreadLocalAddr` across a call; the verifier's `tls-fresh` rule fires.

**D2 x86_64 code generator and assembler.**
- Files: `src/compiler/native/x86_64/{regs,abi,isel,encode,asm}.iyi`.
- Change: SysV and Win64; SSE2 baseline (no POPCNT, LZCNT or BMI unless `--mattr` says so; LLVM's generic lowering for `ctpop`/`ctlz`); `%fs`/`%gs` segment loads; `lock` atomics; the AT&T assembler for every x86_64 template in the inventory (syscalls, `cpuid`, `xgetbv`, VEX `vfmadd213sd`/`ss`, `roundsd`, `pause`, register spills, `gs:` reads).
- Depends: C3 (MIR, regalloc, frame), C4 (constraints, inventory).
- Acceptance: encoder, asm and atomics gates for x86_64 equal to the oracle; the `cg_*`/`compile_*` IR compiled natively, linked by `cc` in the Linux container, matches the oracle.
- Gates: `bench/native_encode_exercise.sh x86_64`, `bench/native_asm_exercise.sh x86_64`, `bench/native_atomics_exercise.sh x86_64`, `bench/native_codegen_exercise.sh x86_64-linux-gnu`; job `native-linux`.
- Mutation: use `cvtsd2si` instead of `cvttsd2si`; a float-conversion fixture differs.

**D3 ELF, static-PIE linking, Linux rt [IR].**
- Files: `src/compiler/native/obj/elf.iyi`, `src/compiler/native/link/{elf_exe,eh_frame}.iyi`, `src/compiler/native/rt/{start_linux_x86_64,start_linux_aarch64}.ir`.
- Change: `ET_REL` reader and writer (the x86_64 and aarch64 relocations LLVM emits, `REX_GOTPCRELX` and local-exec TLS included); the static-PIE writer of section 2.3; rt per architecture: `_start` reads `argc`, `argv` and `envp` from the initial stack, sets `environ`, applies the relative relocations, makes RELRO read-only, maps the main thread's TLS block from the TLS linker symbols in the variant `IyiTlsImage` uses and sets the thread pointer (`arch_prctl(ARCH_SET_FS)`, `msr tpidr_el0`), calls `main`, and `exit_group`s with its result; `.eh_frame` from `FrameDesc` (and passed through from LLVM objects).
- Depends: C1. The linker half proves itself on oracle objects (with rt translated by B2) before D1 and D2 finish; the full-corpus half needs D1 and D2.
- Acceptance: (1) oracle objects for the corpus, linked by our linker for x86_64-linux-gnu, run in the container identically to the oracle binaries, and the same for aarch64-linux-gnu on the arm job; (2) the same corpus bridged and built natively on both architectures; (3) `readelf -lW` shows no `INTERP` and no `DYNAMIC`, `PT_TLS` when TLS is used, `GNU_STACK` RW; `nm` shows none of `_init _fini frame_dummy __do_global_dtors_aux register_tm_clones deregister_tm_clones`; a fixture printing `main`'s address prints different values on two runs (ASLR).
- Gates: `bench/native_link_exercise.sh <triple>`, `bench/native_corpus_exercise.sh <triple>`; jobs `native-linux` (x86_64) and `native-arm64-linux` (INT proposes `ubuntu-24.04-arm`; the fallback is the `cross-run` pattern under QEMU).
- Mutation: skip the relative relocations in rt; every corpus program crashes. Set up the TLS block with the other variant; `thread_exercise.sh`'s program fails.

**D4 PE linking, Windows rt, unwind and PDB [IR].**
- Files: `src/compiler/native/obj/coff.iyi`, `src/compiler/native/link/{pe_exe,pdb,win64_unwind}.iyi`, `src/compiler/native/rt/start_windows_x86_64.ir`.
- Change: COFF reader and writer; the PE writer of section 2.3; TLS directory and `_tls_index`; `.pdata`/`.xdata` from `FrameDesc` (and passed through from LLVM objects); a PDB writer for exactly what `std/debug` reads (PDB info stream with GUID and `/names` in its named-stream map, empty valid TPI and IPI headers, DBI with module info and section contributions, `/names`, one module stream per object with `S_GPROC32`/`S_END` records named by `DebugSubprogram#display_name` and C13 `DEBUG_S_LINES` plus `DEBUG_S_FILECHKSMS`), the RSDS debug directory; rt `__iyi_win_start` calls `main` and `ExitProcess`.
- [UNVERIFIED: whether any Windows path reads `ARGC_UNSAFE`/`ARGV_UNSAFE`; the prelude's `Program.args` uses `GetCommandLineW` (`prelude.iyi` 11319-11336). rt passes `argc = 0` and an `argv` holding one null pointer unless the args differential below fails, in which case rt splits `GetCommandLineW` into UTF-8 by Microsoft's rules.]
- Depends: C1, D2.
- Acceptance: oracle objects linked by our linker, then the bridged native corpus, run on windows-2025 identically to the oracle binaries; `dumpbin /dependents` lists only allowed DLLs; `dumpbin /imports` names no `vcruntime140`, `ucrtbase` or `api-ms-win-crt-*`; no Rich header; `panics.sh` 9a passes on Windows (frames named `inner at ...named.iyi:6`); the args differential (ASCII and non-ASCII arguments, `Program.args`, program name) matches.
- Gates: `bench/native_link_exercise.sh x86_64-windows-msvc`, `bench/native_corpus_exercise.sh x86_64-windows-msvc`; job `native-windows` (windows-2025).
- Mutation: omit one function's `.pdata` entry; 9a's recursion frames are lost and the gate fails. Corrupt the PDB GUID; `std/debug` refuses the PDB and 9a fails.

**D5 wasm32-wasi.**
- Files: `src/compiler/native/wasm/{codegen,stackify,module,leb}.iyi`, `src/compiler/native/rt/start_wasm32.ir`.
- Change: section 2.2's wasm row; `__wasi_*` imports; `_start`.
- [UNVERIFIED: the full set of WASI imports the prelude and std use beyond `fd_write`, `fd_read`, `proc_exit`; verify by reading the module the `wasi-run` job builds today with this slice's own wasm reader.]
- Depends: B1, B2 (bridge input); independent of C3.
- Acceptance: the corpus subset the `wasi-run` and `wasm32-collector` jobs run today, bridged and built natively, runs under wasmtime identically; the module's imports are only `wasi_snapshot_preview1.*`; no `producers` section naming clang or LLD.
- Gate: `bench/native_corpus_exercise.sh wasm32-wasi`; job `native-wasi` (ubuntu-24.04, wasmtime from `scripts/install-wasm-toolchain.sh`).
- Mutation: keep a `ptr` live across a call out of the shadow stack; the `wasm32-collector` driver's forced-collection case fails.

**D6 Debug information for `std/debug`.**
- Files: `src/compiler/native/link/dwarf.iyi`; line-table emission in `src/compiler/native/emit.iyi` (C3 hands it over); companion writing in `macho_exe.iyi` (C2 hands it over).
- Change: DWARF from `DebugFunc` for ELF (in the executable) and darwin (`<exe>.dwarf`, `MH_DSYM`, matching `LC_UUID`).
- Depends: D1, D3.
- Acceptance: `bench/panics.sh` 9a passes on native outputs on macos-15 and on both Linux architectures; `llvm-dwarfdump --verify` (test-time, where present) reports no errors.
- Gate: `bench/native_corpus_exercise.sh` includes 9a; jobs `native-darwin`, `native-linux`, `native-arm64-linux`.
- Mutation: shift every line row by one; 9a's `named.iyi:6` check fails.

**D7 Optimisation passes.**
- Files: `src/compiler/ir/passes/{mem2reg,sccp,dce,cse,simplify_cfg,inline,pipeline}.iyi`, `bench/native_opt_exercise.sh`, `bench/native_perf.py`.
- Change: section 2.2's "In" list.
- Depends: C3.
- Acceptance: each pass has before and after IR fixtures; the corpus gates pass with `-O1` on every target; `bench/native_perf.py` records against the oracle the compile wall time of the corpus and the run time of `bench/`'s timed programs. Proposed bar (Go-class) **[JASON and SERDAR to confirm the numbers]**: native `-O1` compiles faster than the oracle's default `-O0` on every corpus program; native `-O1` runs no slower than the oracle's `-O0` on every timed program and within 2x of the oracle's `--release` geometric mean.
- Mutation: let CSE merge two `ThreadLocalAddr` across a call; `tls-fresh` fires after the pipeline. Let mem2reg promote an alloca with a volatile access; the volatile-slot `mem2reg` fixture fails and the wasm collector case fails.

**D8 Native floors and linker fingerprints.**
- Files: `bench/native_floor.sh` (sources `bench/floor_base.sh` read-only; does not edit it while #147 is open).
- Change: per target, the native program floor of section 2.3's table, read with `nm -u`/`otool -L`, `readelf`, `dumpbin` and our wasm reader; the fingerprint checks (no `LC_BUILD_VERSION` tools, no `__stub_helper`, no ELF `.comment` linker string, no crt symbols, no PE Rich header, no wasm `producers` from clang or LLD); it fails when the floor moves either way.
- Depends: D1 to D5.
- Gate: jobs `native-darwin`, `native-linux`, `native-arm64-linux`, `native-windows`, `native-wasi`.

**Per-target default flips.** When a target's D gates are green, a PR adds its triple to `NATIVE_TARGETS`, which makes `--backend native` its default in the iyi compiler.

### Phase S: stage 1 (reaches (b)); runs in parallel with C and D

Stage 1: the Crystal-hosted compiler builds `src/compiler/stage1_llvm.iyi` into `.build/iyi-stage1`, which builds the corpus with behavioural parity on both backends and builds `src/compiler/stage1.iyi` into a working `stage2`. The scope is the iyi language only: Crystal-mode-only code (`--crystal`, rescue typing beyond refusing it, interpreter remnants) is not ported. Commands other than `build` and `run` move in F2.

Every S slice ships a differential gate named `bench/selfhost_semantic_<area>_exercise.sh` or `bench/selfhost_lower_<area>_exercise.sh` in the existing pattern (typed dumps, error messages, or IR against the Crystal oracle), run by the `selfhost` and `selfhost-darwin` jobs, and owns distinct files. Ported visitor methods that Crystal spreads across files by reopening a class become module functions taking the visitor as their first argument [UNVERIFIED: whether iyi permits reopening a module's own class from another module; verify with a two-file fixture under `bin/iyi`].

**S0 (first) Measure, and fix the contract.**
- Files: `bench/selfhost_typed_parity_exercise.sh` (new), `src/compiler/semantic/typed.iyi`, `src/compiler/lower/CONTRACT.md`; line A's corpora added to `selfhost_lexer`, `selfhost_parser` and `selfhost_semantic` (samples, `src/iyi`, `src/std`, the port's own source, line A's fixtures).
- Change: (1) a gate that typechecks every file of the prelude, std and `src/compiler/**/*.iyi` with the iyi semantic port and reports per file the fraction of expression nodes whose type equals the Crystal oracle's: the burn-down every S1 slice must move; (2) section 3.6's contract, extracted mechanically from `codegen/*.cr`; (3) line A parity.
- Acceptance: the parity gate prints per-file numbers against a committed floor that may only rise; `typed.iyi` compiles; when line B's lexer, parser and declaration gates meet or exceed line A's measured results (from #104: parser 27/27 samples, 17/17 prelude, 67/67 std, self-source identical; lexer 6 agree on samples; declarations 23 agree on samples, 14 of 15 on the prelude, 31 of 35 on std), INT closes #104 with a pointer (decision 2).

**S1 Semantic analysis completion** (Crystal sources to `src/compiler/semantic/` and `src/compiler/types/`, in dependency order; each slice owns its new files and, where named, one existing file):
- S1a Type model: `types.cr` remainder, `type_merge.cr`, `type_intersect.cr`, `type_lookup.cr`, `type_to_restriction.cr`, `filters.cr`, `conversions.cr`, `path_lookup.cr` to `types/{merge,intersect,lookup,to_restriction,filters}.iyi`; owns `types/types.iyi`.
- S1b Program and declarations: `program.cr`, `top_level_visitor.cr` remainder, `type_declaration_visitor.cr`, `type_declaration_processor.cr`, `type_guess_visitor.cr`, `instance_vars_initializer_visitor.cr`, `class_vars_initializer_visitor.cr`, `new.cr`, `lib.cr`, `hooks.cr`, `flags.cr` to `semantic/{program,declarations,type_guess,initializers,new,lib,hooks}.iyi`; owns `semantic/top_level.iyi`. After S1a.
- S1c Lookup and calls: `method_lookup.cr`, `restrictions.cr`, `restrictions_augmenter.cr`, `call.cr`, `call_error.cr`, `default_arguments.cr`, `match.cr`, `suggestions.cr` to `semantic/{method_lookup,restrictions,call,call_error,default_arguments,match}.iyi`. After S1b.
- S1d Bodies: `main_visitor.cr`, `bindings.cr`, `semantic_visitor.cr`, `definition_typing.cr`, `fix_missing_types.cr`, `exception.cr` (refusing `rescue` only) to `semantic/{bindings,semantic_visitor,definition_typing}.iyi`; owns `semantic/main_visitor.iyi`. After S1c.
- S1e Transformers: `literal_expander.cr`, `cleanup_transformer.cr`, `math_interpreter.cr`, `normalizer.cr` remainder to `semantic/{literal_expander,cleanup}.iyi`; owns `semantic/normalizer.iyi`. Parallel with S1c.
- S1f iyi's rule checks: `unsafe_check.cr`, `share.cr`, `share_reach.cr`, `reach_proof.cr`, `exhaustiveness_checker.cr`, `abstract_def_checker.cr`, `warnings.cr`, `cover.cr` to `semantic/checks/*.iyi`; owns `semantic/recursive_struct_checker.iyi`. After S1d.
- S1g Macros: `macros.cr`, `macros/methods.cr`, `macros/interpreter.cr`, `macros/macros.cr`, `macros/types.cr` (TypeNode, `run`, hooks) to `src/compiler/macros/*.iyi`. After S1b.
- Acceptance per slice: its fixtures' typed dumps and error messages identical to the oracle's; the S0 burn-down rises on the files its area governs; mutation proofs per slice.

**S2 Typed lowering** (port of `codegen/*.cr` to `src/compiler/lower/` onto the IR builder; one function per Crystal visitor method; the `Lowerer` context in `lower/context.iyi`, owned by S2a):
- S2a Core: `codegen.cr`, `context.cr`, `phi.cr`, `cond.cr`, `llvm_builder_helper.cr`, `iyi_llvm_builder.cr`, `ast.cr`, `symbol.cr`, `llvm_id.cr` to `lower/{lower,context,phi,cond,helpers,symbols}.iyi`.
- S2b Types and layouts: `llvm_typer.cr`, `types.cr`, `type_layouts.cr`, `gc_layouts.cr`, `type_id.cr`, `unions.cr` to `lower/{typer,layouts,gc_layouts,type_id,unions}.iyi`.
- S2c Functions and calls: `fun.cr`, `call.cr`, `match.cr`, `abi.cr`, `abi/{aarch64,x86_64,x86_win64,wasm32}.cr` to `lower/{fun,call,match}.iyi` and `lower/abi/*.iyi` (C ABI lowering lives here, so IR `C` signatures arrive lowered).
- S2d Primitives and casts: `primitives.cr`, `cast.cr`, `asm.cr` to `lower/{primitives,cast,asm}.iyi`.
- S2e Globals: `class_var.cr`, `const.cr`, `once.cr` to `lower/{class_var,const,once}.iyi` (TLS per section 2.2; `ARGC_UNSAFE`/`ARGV_UNSAFE`).
- S2f Runtime-contract passes and ensure: `preempt_checks.cr` to `ir/passes/preempt_checks.iyi`; `wasm_roots.cr` to `ir/passes/wasm_roots.iyi`; `exception.cr` to `lower/ensure.iyi` (ensure bodies on normal exits only; no landing pads); `debug.cr`'s line locations to `lower/debug.iyi`.
- S2g Program assembly: the codegen orchestration in `compiler.cr` (units, entry, `import_library` from `@[Link]`) to `lower/program.iyi`.
- S2h Retire `codegen/codegen.iyi`: delete it when `lower/` passes the `cg_*` and `compile_*` corpora; repoint those gates.
- Depends: S0's contract, B1, and the S1 slice each depends on for its fixtures.
- Acceptance per slice: for its fixtures, IR from `lower/` equals IR imported from the oracle's `.ll` after normalisation (names, debug locations and the oracle's dead EH skeletons removed), and the programs built through both backends match the oracle at run time.

**S3 Pipeline and driver.** Files: `src/compiler/command/driver.iyi` (`build` and `run` call the compiler; today they only assign options, `driver.iyi` 941-949), `src/compiler/compiler.iyi` (the typed pipeline, whole-program from source, macro `run` helpers built by this compiler, target flags), `src/compiler/loader.iyi` (`IYI_PATH`, the share path). Depends: S1, S2, B3.

**S4 Stage-1 gate.** Files: `bench/selfhost_stage_one_exercise.sh` (extended). Acceptance: `.build/iyi-stage1`, built from `stage1_llvm.iyi` by `bin/iyi --release`, builds the corpus with oracle parity through `--backend llvm` on every target and through `--backend native` on every target in `NATIVE_TARGETS`; it builds `src/compiler/stage1.iyi`, and that `stage2` answers `--version` and `--help` and builds `samples/iyi/hello.iyi`. Jobs `selfhost`, `selfhost-darwin`.

### Phase E: the fixed point, zero LLVM (reaches (e))

**E1 (first) Stage two and three [IR].**
- Files: `bench/selfhost_stage_two_exercise.sh`.
- Steps: clean cache, `SOURCE_DATE_EPOCH` set, paths normalised; `stage1` builds `stage2` with `--backend native`; `stage2` builds `stage3`; `cmp` the executables and their companions (`.dwarf`, `.pdb`); the zero-LLVM, floor and tripwire checks of section 0 items 2 and 3; `stage2` builds the corpus with oracle parity on all five targets; cross-host identity: `stage2` for each target built on every host is byte-identical (artifacts compared across jobs); on aarch64-linux, a `stage2` cross-built on x86_64 runs on the arm runner and builds a `stage3` identical to the x86_64-built one.
- Depends: S4, and D complete (all five triples in `NATIVE_TARGETS`).
- Gate jobs: `stage-two-darwin` (macos-15), `stage-two-linux` (container), `stage-two-arm64` (the arm runner or QEMU), `stage-two-windows` (windows-2025).
- Mutation: seed one hash-ordered iteration in the lowering with the process id; `cmp` fails. Compile a probe build with an `@[Link("LLVM")]` module; the floor check fails.

**E2 LLVM leaves the iyi compiler [IR].**
- Files deleted: `src/compiler/stage1_llvm.iyi`, `src/compiler/backend/llvm/**`, `src/compiler/llvm/**`, `src/compiler/llvm.iyi`, `src/compiler/platform/linker.iyi`, the LLVM subcommands of `src/compiler/tools/ir.iyi`, the IR-level oracle comparisons (behavioural comparisons against the Crystal-hosted compiler's binaries remain until F4).
- Requests to INT: SPEC status for the native backend and own linker from PROPOSED to BUILT, with the measured figures registered in `doc_numbers.py`.
- Acceptance: E1 green after the deletion; `grep -rn 'compiler/llvm' src/compiler --include=*.iyi` empty.

### Phase F: stale testing re-homed, the Crystal-hosted compiler deleted (reaches (f))

**F1 (first) Stale testing on the iyi compiler.** After #147 merges upstream, and after E2. Port `src/compiler/iyi/stale/*.cr` (about 7,300 lines in #147), `semantic/effects.cr`, `semantic/observers.cr`, `build_inputs.cr`, `up_to_date.cr` and `command/test.cr`'s changes. The call-path walk mirrors `lower/` (its roots and call edges) instead of `codegen.cr` 373-383 and `call.cr` 4-39; toolchain identity becomes the compiler binary's digest plus backend and target; RG8 compares normalised iyi IR text from `ir/printer.iyi` instead of `DUMP=1` LLVM IR. Acceptance: #147's gates (`bench/stale_*.sh`, and `spec/compiler/stale/*` rewritten as iyi gates) pass against the self-hosted compiler.

**F2 Command parity.** Each remaining command of the Crystal-hosted compiler (`lsp`, `mod` and its subcommands, `doc`, `migrate`, `fix`, `mcp`, `check`, `spec`, `eval`, `sandbox`, `env`, `init`, `get`, `cursor`, `clear_cache`, the tools under `tools/`) is either ported with a differential gate or dropped by an upstream decision recorded in SPEC. **[SERDAR] decision per command.**

**F3 Release and bootstrap.** A release publishes `stage2` binaries for the four hosts; `make` bootstraps from the previous release (III.9 rule 4's exit for `crystal`).

**F4 Delete the Crystal-hosted compiler [IR].** Delete `src/compiler/iyi/**/*.cr`, `src/compiler/*.cr`, `src/llvm/**`, the Crystal oracle gates (converted to behavioural or golden gates first) and `selfhost/` if line A merged; SPEC III.9 then says the compiler links the platform libc and nothing else.

---

## 5. Upstream PR series (`iyilang/iyi` master, merge commits)

Every PR: adds files where possible; carries its own gate, reachable from `iyi.yml` through the drivers; adds one CHANGELOG entry (upstream practice: recent commits such as `fee79da5d` edit CHANGELOG with the change); states no figure that `doc_numbers.py` does not check; is green alone.

| # | contents | depends | shared files |
|---|---|---|---|
| P1 | **SPEC proposal, docs only:** a new Appendix entry "B.2a: Reversing B.2: PROPOSED" plus one-line status pointers (below) | none | SPEC.md, CHANGELOG.md |
| P2 | Oracle fixes the port found, on files #147 does not touch: Bool atomics (`codegen/primitives.cr`, `src/iyi/atomic.iyi`), the sibling-unit path rule (`semantic/path_lookup.cr`), each with a spec | none | CHANGELOG.md |
| P3 | Oracle fixes on files #147 touches (`codegen/call.cr`, `macros/methods.cr`, `semantic/semantic_visitor.cr`, `src/compiler/requires.cr`) | #147 merged, or its owner agrees | CHANGELOG.md |
| P4 | The selfhost rail plus foundation and lexer: `bench/lib/mutation.sh`, `bench/selfhost_gates.sh`, the `selfhost` job, the `ci_plan.py` rule, `src/compiler/foundation/*.iyi`, `syntax/{token,lexer}.iyi`, the lexer gate and fixtures, `BOOTSTRAP.md` with registered figures | P1 accepted | iyi.yml, ci_plan.py, ci_plan_exercise.py, doc_numbers.py, CHANGELOG.md |
| P5 | AST, visitor, transformer, gate | P4 | CHANGELOG.md |
| P6 | Parser, gate, line A's corpora (#104 closes once S0's parity holds) | P5 | CHANGELOG.md |
| P7 | Normalizer, gate | P6 | CHANGELOG.md |
| P8 | Types, gate | P6 | CHANGELOG.md |
| P9 | Semantic (current extent), gate | P7, P8 | CHANGELOG.md |
| P10 | Macro engine, gate | P9 | CHANGELOG.md |
| P11 | Platform target and flags (and the LLVM path's link commands), gate | P4 | CHANGELOG.md |
| P12 | Artifact format, gate | P9 | CHANGELOG.md |
| P13 | Formatter and bind tools, gates (no CLI wiring) | P9 | CHANGELOG.md |
| P14 | Command driver and daemon, gates (no CLI wiring) | P11 | CHANGELOG.md |
| P15 | IR core, gate, the `native-linux` job | P4 | iyi.yml, CHANGELOG.md |
| P16 | LLVM bindings, translator, importer, `iyi-ir`, the round-trip gate | P15 | Makefile, CHANGELOG.md |
| P17 | Loader, pipeline, codegen on IR, backend interface, compile tools, their gates | P10, P14, P16 | Makefile, CHANGELOG.md |
| P18 | `--selfhost` companion wiring (`mod`, `format`, `parse`) | #147 merged (it touches `command.cr`) | CHANGELOG.md |
| P19 to P22 | C1; C2; C3 with C4 and C5; C6 (adds `native-darwin`) | P17 | iyi.yml (P22), Makefile, CHANGELOG.md |
| P23 onward | D1 to D8, one PR each; then one PR per target adding it to `NATIVE_TARGETS` with its floor | P22 | iyi.yml (jobs `native-arm64-linux`, `native-windows`, `native-wasi` in their first PRs), CHANGELOG.md |
| S series | S0; S1a to S1g; S2a to S2h; S3; S4; one PR each | P17 | CHANGELOG.md |
| E series | E1 (adds the `stage-two-*` jobs); E2 (deletions, SPEC status BUILT) | S4, D complete | iyi.yml, SPEC.md, doc_numbers.py, CHANGELOG.md |
| F series | F1 to F4 | E2, #147 merged | everything F4 deletes |

**P1's SPEC text points.** #147's SPEC hunks rewrite III.9's floor listing ("What a plain own-prelude program depends on") and its "At the object layer" paragraph; P1 touches only the headings and sentences named here and adds new text elsewhere, so the two do not conflict.
1. **New Appendix entry "B.2a: Reversing B.2: PROPOSED"** (the substance), written to say plainly that it reverses B.2 rather than routing around it:
   - What changed since B.2: the port B.2 declined has been started and measured. Line B is this compiler ported to iyi layer by layer, each layer differentially gated against the Crystal front end with mutation proofs (its size registered in `doc_numbers.py`). III.9 already separated "a bootstrap chain ... requires *a* compiler for iyi written in iyi, which is a much smaller target than the fork" from porting; the proposal is the port, restricted to that smaller target: one language, no `--crystal`.
   - B.2's cost argument ("291k, against rules that forbid the style most of those lines are written in") is answered by method: each ported layer is rewritten in iyi's style (R-3, III.1 and III.13 gated as for any iyi code) and proven equal to the layer it replaces before the next starts.
   - Staging and exits: the Crystal-hosted compiler stays the shipped compiler until stage 2 == stage 3 holds and stale testing has moved; LLVM leaves the iyi-written compiler first.
2. **III.9 rule 2, proposed amendment:** "The compiler may link the platform libc. LLVM and `cc` remain permitted toolchain requirements for a target until that target's native backend lands; each is recorded under rule 4 as temporary, with that exit condition." Rule 3 gains the per-target table of section 2.3; rule 4 gains LLVM, libstdc++, `cc`, `link.exe`, wasi-sdk and `dsymutil` as temporary entries with exits.
3. **V.9 item 9 (c), answered:** with a native backend iyi owns the three things (c) says it does not: its object format, its calling convention (the platform C convention with an internal aggregate rule), and its runtime (it already does: its own prelude, raw syscalls on Linux). The "system part" (`Scrt1.o`, `crti.o`, `crtbeginS.o`, `libgcc`, `libc.so.6`, the dynamic linker) disappears on Linux because programs become static and libc-free; on darwin it is libSystem binding and an ad-hoc signature; on Windows import tables and a TLS directory; on wasm module assembly. The correctness burden is scoped by the floor: no dynamic ELF, no archives, no LTO, no foreign objects.
4. **Appendix B row 10:** "PROPOSED: yes, as a bootstrap chain (B.2a)."
5. **III.10 inventory, the LLVM row:** "compiler only; temporary per target until its native backend lands (B.2a, III.9 rule 4)."
6. **B.2's heading** gains "(reversal PROPOSED in B.2a)"; its body stays as the record. The 0.1.0 statement (line 84) and line 1106 stay as history.

---

## 6. Protecting #147

While #147 is open, **no slice edits these files** (from its file list): `src/compiler/iyi/{build_inputs,command,compiler,config,program,semantic,types}.cr`, `src/compiler/iyi/codegen/{cache_dir,call,class_var,codegen,const,context,fun,link,types}.cr`, `src/compiler/iyi/command/{mcp,test}.cr`, `src/compiler/iyi/macros/{macros,methods}.cr`, `src/compiler/iyi/semantic/{ast,main_visitor,new,semantic_visitor,top_level_visitor,type_lookup}.cr`, `src/compiler/iyi/syntax/ast.cr`, `src/compiler/requires.cr`, `src/crystal/system/unix/spawn.cr`, `src/crystal/system/win32/process.cr`, `src/process.cr`, `src/iyi/{concurrency,file,float,prelude,thread}.iyi`, `src/std/{debug,dir,env,file,gc,mutex,path,process,random,signal,socket,system,system_roots,term,time,udp,user}.iyi`, `samples/iyi/{calc,files,socket}.iyi`, `bench/{dependency_floor.sh,floor_base.sh,arena_exercise.sh,collect_trigger.sh,concurrency_exercise.sh,mark_exercise.sh,parallel_exercise.sh,runtime_exercise.sh,thread_exercise.sh,thread_floor.sh,panics.sh,identity_floor.py}` and the `bench/std_*` files it lists, `spec/compiler-cli/crystal-{build,daemon}_spec.cr`, `spec/compiler/{codegen/const,config,iyimod,semantic/union}_spec.cr`, `spec/std/socket/*`, `Makefile.win`, `INSTALL.md`. The shared files it edits (`.github/workflows/iyi.yml`, `Makefile`, `README.md`, `SPEC.md`, `CHANGELOG.md`, `bench/doc_numbers.py`) take only append-style edits in regions #147 does not touch, through INT.

**Behaviours the plan must not change** (#147 keys on them): the Crystal-hosted `CodeGenVisitor`'s walk and call edges; magic-constant default expansions (`call.cr` 173-191) and cast-failure locations (`codegen.cr` 1954-1980); the `__iyi_raise_cast_failed` and `__iyi_raise_closure_to_c` messages byte for byte; union member order (`program.cr` 1601-1604); `DUMP=1` IR printing (`codegen.cr` 755-779); `Program#lib_flags` and link flags; `BuildInputs` recording; toolchain identity (LLVM version and library digest); the refused modes (`--emit`, `--no-cleanup`, `--iyi-keep`). The plan changes nothing in the Crystal-hosted compiler except P2 (files #147 does not touch) and P3 (held). Native work never edits the prelude: toolchain code lives in `src/compiler/native/rt/`.

**When stale testing moves:** F1, after #147 has merged upstream (its design and files are final) and after E2 (the compiler it will run on exists, without LLVM). A8 keeps line B green across #147's merge in the meantime.

---

## 7. Risks that would falsify the plan

| # | risk | cheapest early experiment | if it fires |
|---|---|---|---|
| R1 | **Stage 1 does not converge** (the largest): the remaining semantic, macro and lowering port (correction 12: 72,294 Crystal lines in scope, part ported) cannot reach parity, given that the Crystal sources are written in the style R-3 forbids and must be restructured as they are ported | S0's typed-parity gate over the prelude, std and the compiler's own source, which gives the denominator and the per-file gap; the first S1 slice's movement of it shows whether hand-porting converges | switch S1 and S2 to a Crystal-to-iyi mechanical translator (Go 1.5's c2go path) under the same gates |
| R2 | Upstream refuses the reversal | open P1 first, docs only, before any port PR | the series stays on the fork; nothing in phases A to E depends on upstream acceptance |
| R3 | dyld or the kernel refuses an `LC_DYLD_INFO_ONLY`, ad-hoc-signed executable written without ld64, on macOS 14.4 through current | C2's first increment on macos-15 and on the newest local macOS | chained fixups (`LC_DYLD_CHAINED_FIXUPS`) |
| R4 | `--emit llvm-ir` is not the whole program (artifact objects), or does not cross-compile every target from Linux | B2's built-in experiment | force source builds for the bridge, or run the bridge per host |
| R5 | The IR cannot express an oracle construct without an LLVM escape hatch | B2's round trip on the full corpus before B1 merges | revise B1's contract before C3 commits to it |
| R6 | Conservative scanning misses roots under native code (a pointer in a vector register, a derived pointer, a wasm local) | `collect_trigger.sh`, `parallel_exercise.sh` and the `wasm32-collector` driver on bridged native builds at D1 and D5, ten runs each | tighten 2.2's register-allocation and pass constraints |
| R7 | `std/debug`'s PDB reader needs more than the minimal PDB (types, publics) | D4's first increment: a PDB with one module, one `S_GPROC32` and its lines, read by `std/debug` in a panicking program on windows-2025 | add the streams it needs; never change `std/debug` while #147 is open |
| R8 | The iyi-built compiler is too slow or too large in memory to build itself under CI limits | time and peak RSS of `.build/iyi-parse` and the semantic gate over all of `src/` today, then native-built versus LLVM-built once D1 lands | profile the collector and the backend before E |
| R9 | Non-determinism blocks the fixed point | build each corpus program twice natively in D1 and compare bytes | fix the producer that diverges |
| R10 | #147's merge turns line B red | A8 | front-end fixes in A8 |
| R11 | Inline asm in the tree uses forms the assemblers do not cover (operand modifiers, the Intel dialect) | C4's inventory, run before the assemblers grow | extend the assembler, or refuse and ask upstream to rewrite the template |
| R12 | darwin's frame names come from the export trie, which the linker must then mirror | D1 with and without the trie | write the trie (already in C2's scope) |

**What to do first about R1:** dispatch S0 now. It costs one gate and one contract file, and it turns the stage-1 question from an estimate into a measured, per-file burn-down that every later S slice must move.

---

## 8. Dispatch order

- **Wave 1, now, in parallel (disjoint files):** A1, A6, A7, A8, B1, C1 (`object.iyi` first), S0; INT opens P1.
- **Wave 2:** A2, A3, A4, A5 (after the [JASON] decision); B2 (after B1's contract files land); C2 (after `object.iyi`); C3 and C4 (after B1 and C1).
- **Wave 3:** B3 (after A4), B4 (after A3, B2, B3); C5; D2, D3's linker half and D5 (after their contracts); S1a, S1e, S1g, S2a, S2b.
- **Then:** C6; D1, D4, D6, D7, D8; the rest of S by dependency; E; F.

## 9. The end-to-end check, and what proves this wrong

**The check:** section 0, run by `bench/selfhost_stage_two_exercise.sh` (E1) on all four hosts plus `bench/native_corpus_exercise.sh wasm32-wasi`, with F1's stale gates and F4's deletion on top.

**This specification is wrong if:** S0's burn-down shows the hand port does not converge (R1); dyld rejects both binding forms (R3); the IR needs an LLVM escape hatch the round trip cannot remove (R5); the conservative collector cannot be made safe under native code without stack maps (R6), which would reopen GC_DESIGN's "not taken" decision; or upstream refuses B.2a (R2), which ends the upstream half but not the work.
