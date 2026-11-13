# The typed pipeline: status and refusal table

The typed pipeline takes one program from source to a native executable through the typed analysis
and the typed lowering, with no LLVM and no host tool. It is `compile_typed` in `compiler/compiler.iyi`
and the program assembly in `compiler/lower/program.iyi`, reached from `iyi-compile-native <program.iyi>
-o <exe> --pipeline typed [--prelude] [--probe-phase] [--keep-going] [--emit ir]`. The default pipeline is
still the codegen path; the integrator flips it.

Phases, in order: `parse`, `declarations`, `bodies`, `lower`, `verify`, `native`, `link`. With
`--probe-phase` each phase prints `[phase] X: start`, then `[phase] X: pass` when it passes. A refusal
prints `X: fail: <message>` and `reached: <last pass>` and writes no output.

`--keep-going` (probe only) switches the body typer to total mode before the bodies phase: a construct it
cannot type is recorded on its node with its reason, and typing goes on. After the bodies phase the tool prints
the refusal table below: the body refusals, then the lowering column, one `table:` line per row. Lowering of the
whole program still stops at its first refusal; the lowering column lowers each reached def alone.

The integration merge changes the hello root-driven floor from 810 reached, 737 typed clean, and 328 lowered clean
to 814, 742, and 243. The lowering count falls because a probe now counts as clean only when its own body finishes
and its function verifies. This one floor reduction is authorized for the integration merge. These are not census counts.

## What the table counts

- `defs-reached`: distinct instantiations the body typer started. The label is the receiver, the name and
  the argument types. A call clones the def, and the clone's node id is new every time; counting those ids
  counted one instantiation once per call site. The same instantiation reached again does not add a count.
- `defs-typed-clean`: those instantiations whose every clone has no refusal node under it.
- `root-refusals`: refusals on top-level code, outside any def.
- `refusal-sites`: distinct (node, reason) pairs. A node refused once per instantiation counts once.
- One row per refusal reason, largest count first: its count, the slice that owns it (`owner`, from
  `typed_owner` in `lower/program.iyi`), the reason's first line, and one example with its file and line
  and the def that holds it. `owner=unassigned` means no rule names the reason yet and the rule belongs in
  `typed_owner`.
 
Lowering per instantiation runs `lower_def_probe` (lower/lower.iyi) on each reached clone, alone, into one
 module. Its refusals are ranked as the body rows are, with the lowering's owner. An instantiation is lowered
 clean when every probe of that label succeeds. `defs-lowered-clean` counts those labels, not clones and not
 the lines of `.names`. A lowering refusal names its def, not a node, since the lowering carries no location
 yet. `.names` lists each clean function name once (`names.uniq` at the write). It used to repeat a name once
 per clean instance; the coverage comparison is on the set of names either way.

## Gate

`bench/selfhost_pipeline_exercise.sh` runs the tool with `--keep-going` on the three prelude roots and the
compiler's own tools, regenerates the block below (`SELFHOST_PIPELINE_RAISE=1`), fails when it is stale, and
holds `defs-reached`, `defs-typed-clean` and `defs-lowered-clean` per root against `bench/selfhost_pipeline_table.floor`.
All three may only rise, and the gate fails when one falls below its floor. The variation the earlier floors allowed for (identical builds gave reached 5218/5219/5218) came from the typer's node keys and is gone: `NodeMap` holds the nodes it is keyed by (integration `5e633ea4d`), and three runs of one build give byte-identical output. The phase floor is `bench/selfhost_pipeline.floor`.

The floor on 6fc731844 counts distinct instantiations, not clones. The rows it replaced (hello 601 375 194, parse 913 505 272, compile_native 2905 1839 1492) counted one instantiation once per call site. They are not a higher value of this measure. Of 62 labels a bodies merge no longer reaches under the lane's receiver, 50 moved off a bogus metaclass receiver (`Array(Some.class)#meth` and the same shape on `Pointer`). That move is a correction, not a loss, and it is not a reason to read the old number as ahead. 12 name and argument pairs are absent entirely; that remainder is a bodies regression (a splat restriction refused before the autocast retry), not a floor.

Merging inline macros a0a16fc2b drops 11 compile_native reached labels. They are not hosted functions (hosted-filtered reached stayed 348, 0 labels unmapped). The 11 are Array or Pointer of a metaclass (`Module.class`, `ObjectFile.class`) plus `Array(Int32)#count`. Hosted has 0 of those names and 12 methods on `Array(Compiler::Ir::Module::Module)`, the instance type. That drop is a correction. `Array(Compiler::Ir::Module::Module)#<<`, `#empty?`, and `#first` were already unreached before the merge.

## Headline: coverage against the hosted compiler

The number that says how far stage 1 is: which functions the hosted compiler emits for a root, and how many of them the
port lowers clean under the same name. The hosted list is the `define` names of `./bin/iyi build --no-debug --emit llvm-ir
-o <dir>/hosted <root>`. The port's list is `<output>.names`, written by the tool under `--keep-going` (one line per
distinct clean function name). `bench/pipeline_coverage.py <hosted.ll> <output>.names <root>` prints the line and the first missing names.

As measured on 2026-11-13 on `selfhost/s3-pipeline-wip` at 225a3f07d (the declarations trunk `d7ff41054` merged onto 61ffc5278; Class is a ClassType metaclass, builtin type ids in hosted order). The hosted IR is built by this checkout's `bin/iyi` from the same source. The port's names are as the call lowering names them: a class method by its class, `*Point::new`, as `call.iyi` passes `class_owner`. An instance-variable getter is not listed, since a call reads it in place (call.iyi 207).

- `hello`: hosted 698 functions; 73 match the port's clean list; 625 missing; 21 extra. (72 of 698 on 61ffc5278.)
- `compile_native` (as root): hosted 11,811 functions; 101 match; 11,710 missing; 43 extra. (100 of 11,772 on 61ffc5278. The hosted total moves with the compiler's own sources.)

The 625 missing names on hello, by the frontier: 378 not reached by the port; 58 `^Generic(T)` names (lowering core, `mangled_name`); 39 lowering-core refusals; 34 calls; 28 runtime shims; 24 bodies; 20 unassigned (no rule in `typed_owner`); 19 reached and lowered under another name; 13 declarations; 8 closures; 2 entry; 2 constant initialisers. On `compile_native`: 6,519 not reached; 4,869 `^Generic(T)`; 55 lowering core; 46 calls; 43 bodies; 38 closures; 36 shims; 35 unassigned; 32 lowered under another name; 20 constants; 15 declarations; 2 entry.

A class method the probe lowered can still be counted not-reached. `lower_def_probe` (lower.iyi) calls `target_def_fun` with the metaclass as `self_type` and no `class_owner`, so the function is emitted `*Owner.class#meth`. The table and the call lowering name it `*Owner::meth` (program.iyi, call.iyi `class_owner`). The lookup misses, and the clean function is left out of `.names`. The fix is in `lower_def_probe`, which lowering core owns.

The comparison is on exact `define` names. What is still counted as missing or extra and is not work:

- Generic instances. The hosted compiler names a method of a generic class with its owner's type parameters
  (`*Array(IyiSchedulerState)^Array(T)#grow:Nil`, 66 such defines in hello). The port's names carry no `^Generic(T)`
  segment at all (0 names with `^`). `mangled_name` (lower/fun.iyi, lowering core's) must add it. Until it does, every
  generic-class method is missing here.
- Extras that are over-reach, not naming. The body typer types and the lowering lowers defs the hosted compiler never
  reaches (`*Array(Int32)#each` is extra on hello; hosted hello has no `Array(Int32)`). Those are the typer's and are a
  real signal that the port lowers more than the program calls.
- Top-level prelude defs: the hosted compiler prefixes the file path (`*/abs/prelude.iyi::__iyi_say`); the script drops
  that file part on the hosted side so both sides compare on the def.

The gate does not check this line (the hosted build and the probe are too slow to run every gate); it is measured by hand
and recorded here.

The table below counts instances per call site (the typer had no instance cache on this head). Its reach counts are not
a measure of progress and are not a floor to chase; the coverage line above is.

## Owners and known exceptions

Program assembly (lower/program.iyi, this slice): the top-level code is named by the prelude (lower.iyi
`main_function_name`, as the hosted `abi_prefix` does): `__crystal_main` for a prelude-free program, `__iyi_main` with the
iyi prelude. The C `main` is emitted only when the root has no `fun main` of its own (fixture lower_fun_main). The
prelude-free name is checked by the gate. The prelude name is not: the prelude does not reach IR in the typed pipeline
yet (strict mode raises at main_visitor.iyi:214 on the prelude's macro control, concurrency.iyi:1557), so no fixture
can show it.

- Proc literals (`~procProc`, `~proc2Proc`, `~proc3Proc`): owner agent://S2a9Core (lowering core, closures).
- Runtime shims `__iyi_*`, `memcpy`, `memmove`, `memset`, `bzero`: owner agent://S2a9Core (landed on s2a-core as d6b6bdbb9).
- `~NAME:const_init` and the `STDOUT`/`STDERR` constants: owner agent://S2e6Globals. The port emits no `~STDOUT:const_init`
  or `~STDERR:const_init`, so a read of `STDOUT` refuses.
- Exception: a `@[ThreadLocal]` class variable (`IyiScheduler.class#state`) is lowered as a plain global, silently, on
  s2e-globals b2ef4c5b0. It is not counted as lowered clean until agent://S2e6Globals refuses or lowers it. Until then it
  is an exception here.
- Instance-variable getters (a def whose body is one instance variable) are read at the call (call.iyi 207, hosted
  call.cr 614) and are not listed as functions in the names. Their lowering still counts as clean.

## Table

<!-- table:begin: generated by bench/selfhost_pipeline_exercise.sh; do not edit by hand -->
```text
table: hello defs-reached=973 defs-typed-clean=928 root-refusals=1 refusal-sites=147
table: hello refusal 80 owner=bodies reason=pointerof of callstack is not ported yet: only a local variable is example=src/iyi/prelude.iyi:3 in Int64#raise
table: hello refusal 7 owner=bodies reason=the value of 'buffer' cannot be typed example=src/iyi/./string.iyi:38 in String.class#new
table: hello refusal 6 owner=calls reason=expected argument #1 to 'Pointer(UInt8)#+' to be Int64, not Int32 example=src/iyi/./string.iyi:37 in String.class#new
table: hello refusal 5 owner=bodies reason=undefined local variable or method 'cursor' for IyiHeap.class example=src/iyi/prelude.iyi:1665 in IyiHeap.class#thread_warm
table: hello refusal 4 owner=bodies reason=the value of 'cursor' cannot be typed example=src/iyi/prelude.iyi:1663 in IyiHeap.class#thread_warm
table: hello refusal 4 owner=bodies reason=the value of 'slot' cannot be typed example=src/iyi/prelude.iyi:1667 in IyiHeap.class#thread_warm
table: hello refusal 3 owner=calls reason=expected argument #2 to 'IyiAtomic.rmw' to be Pointer(T), not Pointer(UInt64) example=src/iyi/./atomic.iyi:70 in Atomic(UInt64)#add
table: hello refusal 3 owner=bodies reason=the value of 'following' cannot be typed example=src/iyi/prelude.iyi:1669 in IyiHeap.class#thread_warm
table: hello refusal 3 owner=bodies reason=the value of 'byte' cannot be typed example=src/iyi/prelude.iyi:1670 in IyiHeap.class#thread_warm
table: hello refusal 3 owner=bodies reason=the value of 'head' cannot be typed example=src/iyi/prelude.iyi:1681 in IyiHeap.class#thread_warm
table: hello refusal 2 owner=calls reason=expected argument #2 to 'IyiAtomic.rmw' to be Pointer(T), not Pointer(Int64) example=src/iyi/./atomic.iyi:70 in Atomic(Int64)#add
table: hello refusal 2 owner=calls reason=undefined method '==' for NoReturn example=src/iyi/prelude.iyi:1660 in IyiHeap.class#thread_warm
table: hello refusal 2 owner=calls reason=undefined method '-' for NoReturn example=src/iyi/prelude.iyi:1662 in IyiHeap.class#thread_warm
table: hello refusal 2 owner=bodies reason=undefined local variable or method 'head' for IyiHeap.class example=src/iyi/prelude.iyi:1631 in IyiHeap.class#reopen_in
table: hello refusal 2 owner=bodies reason=the value of 'count' cannot be typed example=src/iyi/prelude.iyi:1634 in IyiHeap.class#reopen_in
table: hello refusal 2 owner=bodies reason=undefined local variable or method 'buffer' for String.class example=src/iyi/./string.iyi:39 in String.class#new
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.load' to be Pointer(T), not Pointer(UInt64) example=src/iyi/./atomic.iyi:59 in Atomic(UInt64)#get
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.cmpxchg' to be Pointer(T), not Pointer(UInt64) example=src/iyi/./atomic.iyi:88 in Atomic(UInt64)#compare_and_set
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.store' to be Pointer(T), not Pointer(UInt64) example=src/iyi/./atomic.iyi:64 in Atomic(UInt64)#set
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.load' to be Pointer(T), not Pointer(Int64) example=src/iyi/./atomic.iyi:59 in Atomic(Int64)#get
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.cmpxchg' to be Pointer(T), not Pointer(Int64) example=src/iyi/./atomic.iyi:88 in Atomic(Int64)#compare_and_set
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.store' to be Pointer(T), not Pointer(Int64) example=src/iyi/./atomic.iyi:64 in Atomic(Int64)#set
table: hello refusal 1 owner=bodies reason=pointerof of LibIyiGCTable.__iyi_gc_layouts is not ported yet: only a local variable is example=src/iyi/prelude.iyi:3811 in IyiMark.class#layouts_table
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.cmpxchg' to be Pointer(T), not Pointer(UInt8) example=src/iyi/./atomic.iyi:88 in Atomic(UInt8)#compare_and_set
table: hello refusal 1 owner=declarations reason=primitive enum_value without a declared return type example=no location in IyiFiberState#value
table: hello refusal 1 owner=bodies reason=undefined local variable or method 'count' for IyiHeap.class example=src/iyi/prelude.iyi:1637 in IyiHeap.class#reopen_in
table: hello refusal 1 owner=unassigned reason=type mismatch for class variable '@@lot_tails': expected (Array(IyiWaiter | Nil) | Nil), got Array(IyiWaiter | Nil) example=src/iyi/./concurrency.iyi:3822 in IyiScheduler.class#make_lot
table: hello refusal 1 owner=unassigned reason=type mismatch for class variable '@@lot_heads': expected (Array(IyiWaiter | Nil) | Nil), got Array(IyiWaiter | Nil) example=src/iyi/./concurrency.iyi:3823 in IyiScheduler.class#make_lot
table: hello refusal 1 owner=unassigned reason=undefined class variable '@@installed' for IyiStackGuard example=src/iyi/concurrency.iyi:53 in IyiStackGuard.class#install
table: hello refusal 1 owner=calls reason=expected argument #1 to 'Pointer(UInt64)#+' to be Int64, not Int32 example=src/iyi/./concurrency.iyi:3827 in IyiScheduler.class#lot_lock
table: hello refusal 1 owner=bodies reason=undefined local variable or method 'buffer' for Int64 example=src/iyi/./number.iyi:289 in Int64#to_s
table: hello refusal 1 owner=bodies reason=undefined local variable or method 'buffer' for String example=src/iyi/./string.iyi:449 in String#upcase
table: hello refusal 1 owner=bodies reason=undefined local variable or method 'describe' for Array(Samples::Hello::Greet) example=samples/iyi/hello.iyi:117 in top level
table: hello defs-lowered-clean=392 lowering-refusal-sites=434
table: hello lowering 79 owner=bodies reason=BUG: the analysed program has no type for the call to load (hosted call.cr: visit(Call)) example=IyiSchedLock.class#lock
table: hello lowering 42 owner=lowering core reason=lower: visit(assign NoReturn to (Int32 | Nil): not a member (hosted cast.cr, compatible type)) (hosted codegen.cr) is not ported yet example=Tuple(UInt64, Bool)#raise
table: hello lowering 35 owner=lowering core reason=lower: visit(a class method call on a receiver that is not a constant path (hosted call.cr: prepare_call_args, Path)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#run_spawned_fiber
table: hello lowering 35 owner=lowering core reason=lower: visit(MagicConstant) (hosted codegen.cr) is not ported yet example=Tuple(UInt64, Bool)#[]
table: hello lowering 31 owner=lowering core reason=lower: visit(a call with default arguments or a splat (hosted call.cr)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#io_take
table: hello lowering 30 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of add (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiWorkers.class#link_shared
table: hello lowering 25 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of set (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#lists_unlock
table: hello lowering 21 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of compare_and_set (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#take_ring_head
table: hello lowering 21 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 1 of []= (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Pointer(IyiSchedulerState)#copy_run
table: hello lowering 16 owner=bodies reason=BUG: the analysed program has no type for the assigned value (hosted codegen.cr: codegen_assign) example=IyiScheduler.class#sleep_remove
table: hello lowering 15 owner=bodies reason=BUG: the analysed program has no type for a branch (hosted codegen.cr: visit(If)) example=IyiScheduler.class#panic_current
table: hello lowering 7 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of new (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#state
table: hello lowering 5 owner=lowering core reason=lower: visit(a call to == inherited from a superclass of IyiFiberState (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=IyiGroup#cancel_children_locked
table: hello lowering 5 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of sub (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiMark.class#count_out
table: hello lowering 4 owner=bodies reason=BUG: the analysed program has no type for the call to state (hosted call.cr: visit(Call)) example=IyiGroup#join
table: hello lowering 4 owner=lowering core reason=lower: visit(assign IyiFiber to Nil (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#heap_remove
table: hello lowering 4 owner=bodies reason=BUG: the analysed program has no type for the call to read64 (hosted call.cr: visit(Call)) example=IyiMark.class#scan
table: hello lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of compare_and_set (hosted codegen_fun: return type) example=Atomic(UInt64)#compare_and_set
table: hello lowering 3 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of copy_from (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Array(IyiSchedulerState)#<<
table: hello lowering 3 owner=lowering core reason=lower: visit(a call to a def with a &block parameter (hosted call.cr: codegen_call_with_block_as_fun_literal, closures)) (hosted codegen.cr) is not ported yet example=String#+
table: hello lowering 3 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of swap (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiThread.class#lock_turn
table: hello lowering 3 owner=bodies reason=BUG: the analysed program has no type for the call to new (hosted call.cr: visit(Call)) example=IyiMark.class#scavenge
table: hello lowering 3 owner=bodies reason=BUG: the analysed program has no type for the call to state= (hosted call.cr: visit(Call)) example=IyiScheduler.class#wake_completed
table: hello lowering 3 owner=unassigned reason=error[types]: icmp compares %"(Int64 | Nil)" with i64 example=Tuple(String, String, String)#__iyi_say
table: hello lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of get (hosted codegen_fun: return type) example=Atomic(UInt64)#get
table: hello lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of set (hosted codegen_fun: return type) example=Atomic(UInt64)#set
table: hello lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of add (hosted codegen_fun: return type) example=Atomic(Int64)#add
table: hello lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of sub (hosted codegen_fun: return type) example=Atomic(Int64)#sub
table: hello lowering 2 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of copy_run (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Pointer(IyiSchedulerState)#copy_from
table: hello lowering 2 owner=bodies reason=BUG: the analysed program has no type for the call to shared? (hosted call.cr: visit(Call)) example=IyiScheduler.class#take_mail
table: hello lowering 2 owner=lowering core reason=lower: visit(yield with no block in scope (hosted codegen.cr: visit(Yield), a block of an enclosing block body)) (hosted codegen.cr) is not ported yet example=Array(Int32)#each
table: hello lowering 2 owner=unassigned reason=a proc literal that returns NoReturn (hosted codegen_fun, the noreturn attribute on a literal) example=IyiMark.class#start_helpers
table: hello lowering 2 owner=lowering core reason=lower: visit(assign Proc(NoReturn) to Proc(Nil) (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=IyiThread.class#new
table: hello lowering 1 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of initialize (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Atomic(UInt64).class#new
table: hello lowering 1 owner=lowering core reason=lower: visit(upcast NoReturn to String (hosted cast.cr: upcast_distinct)) (hosted codegen.cr) is not ported yet example=String.class#interpolation
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of swap (hosted codegen_fun: return type) example=Atomic(UInt64)#swap
table: hello lowering 1 owner=lowering core reason=lower: visit(a call to != inherited from a superclass of IyiFiberState (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=IyiRoots.class#each_fiber_root
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of == (hosted codegen_fun: return type) example=IyiFiberState#==
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of thread_warm (hosted codegen_fun: return type) example=IyiHeap.class#thread_warm
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of reopen_in (hosted codegen_fun: return type) example=IyiHeap.class#reopen_in
table: hello lowering 1 owner=unassigned reason=lower: __iyi_once is not declared in the module: the prelude's once entry (hosted run_once, once.cr:22) was not visited example=IyiWorkers.class#listed_at
table: hello lowering 1 owner=unassigned reason=BUG: Cast operand has no analysed type (hosted codegen.cr: visit(Cast)) example=String#==
table: hello lowering 1 owner=unassigned reason=BUG: variable block is read before it is assigned (hosted codegen.cr: visit(Var)) example=IyiThread.class#start
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of make_lot (hosted codegen_fun: return type) example=IyiScheduler.class#make_lot
table: hello lowering 1 owner=lowering core reason=lower: visit(a call to new with no receiver inside a generic or builtin class method (hosted call.cr: prepare_call_args, the metaclass owner)) (hosted codegen.cr) is not ported yet example=Array(IyiWaiter | Nil).class#new
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of lot_lock (hosted codegen_fun: return type) example=IyiScheduler.class#lot_lock
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to get (hosted call.cr: visit(Call)) example=IyiChanLock.class#lock
table: hello lowering 1 owner=lowering core reason=lower: visit(upcast Samples::Hello::User to Samples::Hello::Greet (hosted cast.cr: upcast_distinct)) (hosted codegen.cr) is not ported yet example=Pointer(Samples::Hello::Greet)#[]=
table: hello lowering 1 owner=lowering core reason=lower: visit(upcast Samples::Hello::Robot to Samples::Hello::Greet (hosted cast.cr: upcast_distinct)) (hosted codegen.cr) is not ported yet example=Pointer(Samples::Hello::Greet)#[]=
table: parse defs-reached=2035 defs-typed-clean=1851 root-refusals=0 refusal-sites=999
table: parse refusal 165 owner=unassigned reason=expected type, got TokenKind example=src/compiler/syntax/lexer.iyi:431 in Compiler::Syntax::Parser::Parser#next_token
table: parse refusal 164 owner=bodies reason=pointerof of callstack is not ported yet: only a local variable is example=src/iyi/prelude.iyi:3 in Int64#raise
table: parse refusal 90 owner=unassigned reason=expected type, got Keyword example=src/compiler/syntax/lexer.iyi:764 in Compiler::Syntax::Parser::Parser#next_token
table: parse refusal 78 owner=unassigned reason=expected type, got ASTNode example=src/compiler/syntax/parser.iyi:2823 in Compiler::Syntax::Parser::Parser#parse_atomic_type
table: parse refusal 51 owner=unassigned reason=expected type, got Location example=src/compiler/syntax/parser.iyi:2109 in Compiler::Syntax::Parser::Parser#parse_parenthesized_expression
table: parse refusal 27 owner=calls reason=expected argument #3 to 'Compiler::Syntax::Ast::Call.new' to be Array(Compiler::Syntax::Ast::ASTNode) or Compiler::Syntax::Ast::ASTNode+, not Array(Compiler::Syntax::Ast::ASTNode) example=src/compiler/syntax/parser.iyi:1112 in Compiler::Syntax::Parser::Parser#parse_atomic
table: parse refusal 21 owner=bodies reason=the value of 'buffer' cannot be typed example=src/iyi/./string.iyi:38 in String.class#new
table: parse refusal 20 owner=calls reason=undefined method 'end_location' for Compiler::Syntax::Ast::ASTNode+ example=src/compiler/syntax/ast.iyi:158 in Compiler::Syntax::Ast::Not#at_end
table: parse refusal 20 owner=calls reason=undefined method 'at' for Compiler::Syntax::Ast::ASTNode+ example=src/compiler/syntax/parser.iyi:1574 in Compiler::Syntax::Parser::Parser#parse_out
table: parse refusal 14 owner=calls reason=expected argument #1 to 'Pointer(UInt8)#+' to be Int64, not Int32 example=src/iyi/./string.iyi:37 in String.class#new
table: parse refusal 13 owner=bodies reason=the value of 'type_declaration' cannot be typed example=src/compiler/syntax/parser.iyi:5702 in Compiler::Syntax::Parser::Parser#check_type_declaration
table: parse refusal 13 owner=bodies reason=undefined local variable or method 'type_declaration' for Compiler::Syntax::Parser::Parser example=src/compiler/syntax/parser.iyi:5703 in Compiler::Syntax::Parser::Parser#check_type_declaration
table: parse refusal 12 owner=bodies reason=undefined local variable or method 'ptr' for Compiler::Syntax::Parser::Parser example=src/compiler/syntax/lexer.iyi:137 in Compiler::Syntax::Parser::Parser#current_char
table: parse refusal 12 owner=bodies reason=undefined local variable or method 'b0' for Compiler::Syntax::Parser::Parser example=src/compiler/syntax/lexer.iyi:138 in Compiler::Syntax::Parser::Parser#current_char
table: parse refusal 12 owner=bodies reason=undefined local variable or method 'name' for Compiler::Syntax::Parser::Parser example=src/compiler/syntax/parser.iyi:5317 in Compiler::Syntax::Parser::Parser#parse_annotation
table: parse refusal 12 owner=calls reason=undefined method 'visibility=' for Compiler::Syntax::Ast::ASTNode+ example=src/compiler/syntax/parser.iyi:5627 in Compiler::Syntax::Parser::Parser#parse_pub
table: parse refusal 10 owner=unassigned reason=expected type, got DelimiterState example=src/compiler/syntax/parser.iyi:5793 in Compiler::Syntax::Parser::Parser#parse_delimiter
table: parse refusal 10 owner=bodies reason=the value of 'call' cannot be typed example=src/compiler/syntax/parser.iyi:1403 in Compiler::Syntax::Parser::Parser#parse_call_args
table: parse refusal 9 owner=bodies reason=the value of '__temp_1' cannot be typed example=no location in Compiler::Syntax::Parser::Parser#current_char
table: parse refusal 9 owner=unassigned reason=expected type, got B example=no location in Compiler::Syntax::Parser::Parser#next_token
table: parse refusal 9 owner=bodies reason=the value of 'node' cannot be typed example=src/compiler/syntax/parser.iyi:2103 in Compiler::Syntax::Parser::Parser#parse_parenthesized_expression
table: parse refusal 7 owner=unassigned reason=expected type, got NumberKind example=src/compiler/syntax/lexer.iyi:1578 in Compiler::Syntax::Parser::Parser#scan_number
table: parse refusal 7 owner=bodies reason=the value of 'class_def' cannot be typed example=src/compiler/syntax/parser.iyi:4744 in Compiler::Syntax::Parser::Parser#parse_class_def
table: parse refusal 6 owner=bodies reason=the value of 'b0' cannot be typed example=src/compiler/syntax/lexer.iyi:134 in Compiler::Syntax::Parser::Parser#current_char
table: parse refusal 6 owner=calls reason=undefined method 'ident_part?' for Compiler::Syntax::Lexer.class example=src/compiler/syntax/lexer.iyi:2014 in Compiler::Syntax::Parser::Parser#consume_heredoc_start
table: parse refusal 6 owner=calls reason=undefined method 'location' for Compiler::Syntax::Ast::ASTNode+ example=src/compiler/syntax/parser.iyi:2876 in Compiler::Syntax::Parser::Parser#parse_atomic_type
table: parse refusal 6 owner=bodies reason=undefined local variable or method 'extras' for Compiler::Syntax::Parser::Parser example=src/compiler/syntax/parser.iyi:4287 in Compiler::Syntax::Parser::Parser#parse_def_helper
table: parse refusal 5 owner=bodies reason=undefined local variable or method 'cursor' for IyiHeap.class example=src/iyi/prelude.iyi:1665 in IyiHeap.class#thread_warm
table: parse refusal 5 owner=unassigned reason=expected type, got DelimiterKind example=src/compiler/syntax/lexer.iyi:2028 in Compiler::Syntax::Parser::Parser#consume_heredoc_start
table: parse refusal 5 owner=unassigned reason=expected type, got Array(ASTNode | String) example=src/compiler/syntax/parser.iyi:5925 in Compiler::Syntax::Parser::Parser#remove_heredoc_indent
table: parse refusal 5 owner=bodies reason=undefined local variable or method 'call' for Compiler::Syntax::Parser::Parser example=src/compiler/syntax/parser.iyi:1406 in Compiler::Syntax::Parser::Parser#parse_call_args
table: parse refusal 5 owner=calls reason=expected argument #1 to 'Compiler::Syntax::Parser::CallArgs.new' to be (Array(Compiler::Syntax::Ast::ASTNode) | Nil), not Array(Compiler::Syntax::Ast::ASTNode) example=src/compiler/syntax/parser.iyi:1437 in Compiler::Syntax::Parser::Parser#parse_call_args
table: parse refusal 4 owner=bodies reason=the value of 'cursor' cannot be typed example=src/iyi/prelude.iyi:1663 in IyiHeap.class#thread_warm
table: parse refusal 4 owner=bodies reason=the value of 'slot' cannot be typed example=src/iyi/prelude.iyi:1667 in IyiHeap.class#thread_warm
table: parse refusal 4 owner=bodies reason=undefined local variable or method 'count' for String.class example=src/iyi/./string.iyi:102 in String.class#new
table: parse refusal 4 owner=declarations reason=undefined constant Keyword::None example=src/compiler/syntax/ast.iyi:1621 in Compiler::Syntax::Parser::Parser#parse_parenthesized_expression
table: parse refusal 4 owner=bodies reason=undefined local variable or method 'keyword' for Compiler::Syntax::Ast::Expressions.class example=no location in Compiler::Syntax::Ast::Expressions.class#new
table: parse refusal 4 owner=bodies reason=the value of 'l' cannot be typed example=src/compiler/syntax/parser.iyi:6119 in Compiler::Syntax::Parser::Parser#syntax_error
table: parse refusal 3 owner=calls reason=expected argument #2 to 'IyiAtomic.rmw' to be Pointer(T), not Pointer(UInt64) example=src/iyi/./atomic.iyi:70 in Atomic(UInt64)#add
table: parse refusal 3 owner=declarations reason=primitive enum_value without a declared return type example=no location in IyiFiberState#value
table: parse refusal 3 owner=bodies reason=the value of 'following' cannot be typed example=src/iyi/prelude.iyi:1669 in IyiHeap.class#thread_warm
table: parse refusal 3 owner=bodies reason=the value of 'byte' cannot be typed example=src/iyi/prelude.iyi:1670 in IyiHeap.class#thread_warm
table: parse refusal 3 owner=bodies reason=the value of 'head' cannot be typed example=src/iyi/prelude.iyi:1681 in IyiHeap.class#thread_warm
table: parse refusal 3 owner=calls reason=undefined method 'ident_start?' for Compiler::Syntax::Lexer.class example=src/compiler/syntax/lexer.iyi:1980 in Compiler::Syntax::Parser::Parser#consume_heredoc_start
table: parse refusal 3 owner=unassigned reason=no overload matches 'Compiler::Syntax::Ast::Call.new' with types Compiler::Syntax::Ast::ASTNode+, String example=src/compiler/syntax/parser.iyi:829 in Compiler::Syntax::Parser::Parser#parse_prefix
table: parse refusal 3 owner=calls reason=expected argument #1 to 'Compiler::Syntax::Parser::Parser#parse_proc_type_output' to be (Array(Compiler::Syntax::Ast::ASTNode) | Nil), not Array(Compiler::Syntax::Ast::ASTNode) example=src/compiler/syntax/parser.iyi:2854 in Compiler::Syntax::Parser::Parser#parse_atomic_type
table: parse refusal 3 owner=declarations reason=undefined constant RegexOptions::None example=src/compiler/syntax/ast.iyi:978 in Compiler::Syntax::Parser::Parser#parse_delimiter
table: parse refusal 3 owner=bodies reason=undefined local variable or method 'options' for Compiler::Syntax::Ast::RegexLiteral.class example=no location in Compiler::Syntax::Ast::RegexLiteral.class#new
table: parse refusal 3 owner=bodies reason=the value of 'name' cannot be typed example=src/compiler/syntax/parser.iyi:5283 in Compiler::Syntax::Parser::Parser#parse_annotation_def
table: parse refusal 2 owner=calls reason=expected argument #2 to 'IyiAtomic.rmw' to be Pointer(T), not Pointer(Int64) example=src/iyi/./atomic.iyi:70 in Atomic(Int64)#add
table: parse refusal 2 owner=calls reason=undefined method '==' for NoReturn example=src/iyi/prelude.iyi:1660 in IyiHeap.class#thread_warm
table: parse refusal 2 owner=calls reason=undefined method '-' for NoReturn example=src/iyi/prelude.iyi:1662 in IyiHeap.class#thread_warm
table: parse refusal 2 owner=bodies reason=undefined local variable or method 'head' for IyiHeap.class example=src/iyi/prelude.iyi:1631 in IyiHeap.class#reopen_in
table: parse refusal 2 owner=bodies reason=the value of 'count' cannot be typed example=src/iyi/prelude.iyi:1634 in IyiHeap.class#reopen_in
table: parse refusal 2 owner=bodies reason=undefined local variable or method 'buffer' for String.class example=src/iyi/./string.iyi:39 in String.class#new
table: parse refusal 2 owner=bodies reason=the value of 'ptr' cannot be typed example=src/compiler/syntax/lexer.iyi:133 in Compiler::Syntax::Parser::Parser#current_char
table: parse refusal 2 owner=unassigned reason=no overload matches 'Compiler::Syntax::Token::Token#keyword=' with type Compiler::Syntax::Token::Keyword example=src/compiler/syntax/lexer.iyi:788 in Compiler::Syntax::Parser::Parser#next_token
table: parse refusal 2 owner=bodies reason=the value of 'type' cannot be typed example=src/compiler/syntax/parser.iyi:2835 in Compiler::Syntax::Parser::Parser#parse_atomic_type
table: parse refusal 2 owner=bodies reason=the value of 'macro_control' cannot be typed example=src/compiler/syntax/parser.iyi:3932 in Compiler::Syntax::Parser::Parser#parse_percent_macro_control
table: parse refusal 2 owner=unassigned reason=expected type, got Array(Arg) example=src/compiler/syntax/parser.iyi:4283 in Compiler::Syntax::Parser::Parser#parse_def_helper
table: parse refusal 2 owner=bodies reason=the value of 'extras' cannot be typed example=src/compiler/syntax/parser.iyi:4284 in Compiler::Syntax::Parser::Parser#parse_def_helper
table: parse refusal 2 owner=calls reason=undefined method '[]' for Bool (compile-time type is (Bool | Tuple(Bool, Compiler::Foundation::Location::Location) | Nil)) example=no location in Compiler::Syntax::Parser::Parser#parse_macro
table: parse refusal 2 owner=bodies reason=the value of 'assoc_types' cannot be typed example=src/compiler/syntax/parser.iyi:5107 in Compiler::Syntax::Parser::Parser#parse_trait_def
table: parse refusal 2 owner=bodies reason=the value of 'trait_def' cannot be typed example=src/compiler/syntax/parser.iyi:5108 in Compiler::Syntax::Parser::Parser#parse_trait_def
table: parse refusal 2 owner=unassigned reason=no overload matches 'Compiler::Syntax::Ast::Arg.new' with types String, Nil, Compiler::Syntax::Ast::ASTNode+, String example=src/compiler/syntax/parser.iyi:5450 in Compiler::Syntax::Parser::Parser#parse_fun_def
table: parse refusal 2 owner=unassigned reason=expected type, got Array(ASTNode) example=src/compiler/syntax/parser.iyi:5537 in Compiler::Syntax::Parser::Parser#parse_c_struct_or_union_body_expressions
table: parse refusal 2 owner=unassigned reason=expected type, got Visibility example=src/compiler/syntax/parser.iyi:1278 in Compiler::Syntax::Parser::Parser#parse_atomic
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.load' to be Pointer(T), not Pointer(UInt64) example=src/iyi/./atomic.iyi:59 in Atomic(UInt64)#get
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.cmpxchg' to be Pointer(T), not Pointer(UInt64) example=src/iyi/./atomic.iyi:88 in Atomic(UInt64)#compare_and_set
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.store' to be Pointer(T), not Pointer(UInt64) example=src/iyi/./atomic.iyi:64 in Atomic(UInt64)#set
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.load' to be Pointer(T), not Pointer(Int64) example=src/iyi/./atomic.iyi:59 in Atomic(Int64)#get
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.cmpxchg' to be Pointer(T), not Pointer(Int64) example=src/iyi/./atomic.iyi:88 in Atomic(Int64)#compare_and_set
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.store' to be Pointer(T), not Pointer(Int64) example=src/iyi/./atomic.iyi:64 in Atomic(Int64)#set
table: parse refusal 1 owner=bodies reason=pointerof of LibIyiGCTable.__iyi_gc_layouts is not ported yet: only a local variable is example=src/iyi/prelude.iyi:3811 in IyiMark.class#layouts_table
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.cmpxchg' to be Pointer(T), not Pointer(UInt8) example=src/iyi/./atomic.iyi:88 in Atomic(UInt8)#compare_and_set
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'count' for IyiHeap.class example=src/iyi/prelude.iyi:1637 in IyiHeap.class#reopen_in
table: parse refusal 1 owner=unassigned reason=type mismatch for class variable '@@lot_tails': expected (Array(IyiWaiter | Nil) | Nil), got Array(IyiWaiter | Nil) example=src/iyi/./concurrency.iyi:3822 in IyiScheduler.class#make_lot
table: parse refusal 1 owner=unassigned reason=type mismatch for class variable '@@lot_heads': expected (Array(IyiWaiter | Nil) | Nil), got Array(IyiWaiter | Nil) example=src/iyi/./concurrency.iyi:3823 in IyiScheduler.class#make_lot
table: parse refusal 1 owner=unassigned reason=undefined class variable '@@installed' for IyiStackGuard example=src/iyi/concurrency.iyi:53 in IyiStackGuard.class#install
table: parse refusal 1 owner=calls reason=expected argument #1 to 'Pointer(UInt64)#+' to be Int64, not Int32 example=src/iyi/./concurrency.iyi:3827 in IyiScheduler.class#lot_lock
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'buffer' for Int64 example=src/iyi/./number.iyi:289 in Int64#to_s
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiSchedulerState#io_slots=' to be (Array(IyiFiber | Nil) | Nil), not Array(IyiFiber | Nil) example=src/iyi/./concurrency.iyi:3464 in IyiScheduler.class#io_room
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'target' for IyiIO example=src/iyi/./io.iyi:194 in IyiIO#read_all
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'super' for Compiler::Syntax::Parser::Parser example=src/compiler/syntax/parser.iyi:120 in Compiler::Syntax::Parser::Parser#initialize
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'buffer' for Char example=src/iyi/./string.iyi:592 in Char#to_s
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'bytes' for Compiler::Syntax::Parser::Parser example=src/iyi/./string.iyi:101 in Compiler::Syntax::Parser::Parser#escape_byte_string
table: parse refusal 1 owner=bodies reason=the value of '__temp_2' cannot be typed example=no location in Compiler::Syntax::Parser::Parser#ident_part_or_end?
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'super' for Compiler::Syntax::Ast::Not example=src/compiler/syntax/ast.iyi:2435 in Compiler::Syntax::Ast::Not#initialize
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'type' for Compiler::Syntax::Parser::Parser example=src/compiler/syntax/parser.iyi:2846 in Compiler::Syntax::Parser::Parser#parse_atomic_type
table: parse refusal 1 owner=unassigned reason=no overload matches 'Compiler::Syntax::Parser::Parser#copy_token' with type Compiler::Syntax::Token::Token example=src/compiler/syntax/parser.iyi:3097 in Compiler::Syntax::Parser::Parser#type_start?
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'tok' for Compiler::Syntax::Parser::Parser example=src/compiler/syntax/parser.iyi:3110 in Compiler::Syntax::Parser::Parser#type_start?
table: parse refusal 1 owner=unassigned reason=no overload matches 'Compiler::Syntax::Ast::ProcNotation.new' with types Nil, (Compiler::Syntax::Ast::ASTNode+ | Nil) example=src/compiler/syntax/parser.iyi:2961 in Compiler::Syntax::Parser::Parser#parse_proc_type_output
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'super' for Compiler::Syntax::Ast::Splat example=src/compiler/syntax/ast.iyi:2589 in Compiler::Syntax::Ast::Splat#initialize
table: parse refusal 1 owner=bodies reason=variable 'loc' cannot be typed example=src/compiler/syntax/parser.iyi:6118 in Compiler::Syntax::Parser::Parser#syntax_error
table: parse refusal 1 owner=bodies reason=the value of 'ex' cannot be typed example=src/compiler/syntax/parser.iyi:6121 in Compiler::Syntax::Parser::Parser#syntax_error
table: parse refusal 1 owner=unassigned reason=no overload matches 'Compiler::Syntax::Ast::ArrayLiteral#initialize' with types Array(Compiler::Syntax::Ast::ASTNode), (Compiler::Syntax::Ast::ASTNode+ | Nil), Nil example=no location in Compiler::Syntax::Ast::ArrayLiteral.class#new
table: parse refusal 1 owner=unassigned reason=expected type, got Array(Entry) example=src/compiler/syntax/parser.iyi:2203 in Compiler::Syntax::Parser::Parser#parse_hash_or_tuple_literal
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'super' for Compiler::Syntax::Ast::DoubleSplat example=src/compiler/syntax/ast.iyi:2604 in Compiler::Syntax::Ast::DoubleSplat#initialize
table: parse refusal 1 owner=bodies reason=the value of 'exp' cannot be typed example=src/compiler/syntax/parser.iyi:3923 in Compiler::Syntax::Parser::Parser#parse_expression_inside_macro
table: parse refusal 1 owner=bodies reason=the value of '__temp_32' cannot be typed example=no location in Compiler::Syntax::Parser::Parser#parse_atomic
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'super' for Compiler::Syntax::Ast::Out example=src/compiler/syntax/ast.iyi:2530 in Compiler::Syntax::Ast::Out#initialize
table: parse refusal 1 owner=unassigned reason=no overload matches 'Compiler::Syntax::Ast::Arg.new' with types String, Nil, (Compiler::Syntax::Ast::ASTNode+ | Nil), String example=src/compiler/syntax/parser.iyi:4439 in Compiler::Syntax::Parser::Parser#parse_fun_literal_param
table: parse refusal 1 owner=unassigned reason=no overload matches 'Compiler::Syntax::Ast::Def#initialize' with types String, Array(Compiler::Syntax::Ast::Arg), Compiler::Syntax::Ast::ASTNode+, Nil, Nil, (Compiler::Syntax::Ast::ASTNode+ | Nil), Bool, Bool, Nil, Nil, Nil, Bool example=no location in Compiler::Syntax::Ast::Def.class#new
table: parse refusal 1 owner=unassigned reason=no overload matches 'Compiler::Syntax::Ast::ProcLiteral.new' with type Compiler::Syntax::Ast::Def example=src/compiler/syntax/parser.iyi:4415 in Compiler::Syntax::Parser::Parser#parse_fun_literal
table: parse refusal 1 owner=bodies reason=the value of 'val' cannot be typed example=src/compiler/syntax/parser.iyi:2384 in Compiler::Syntax::Parser::Parser#with_isolated_var_scope
table: parse refusal 1 owner=unassigned reason=no overload matches 'Compiler::Syntax::Ast::Select#initialize' with types Array(Compiler::Syntax::Ast::When), (Compiler::Syntax::Ast::ASTNode+ | Nil) example=no location in Compiler::Syntax::Ast::Select.class#new
table: parse refusal 1 owner=unassigned reason=no overload matches 'Compiler::Syntax::Ast::Case.new' with types (Compiler::Syntax::Ast::ASTNode+ | Nil), Array(Compiler::Syntax::Ast::When), (Compiler::Syntax::Ast::ASTNode+ | Nil), Bool example=src/compiler/syntax/parser.iyi:1854 in Compiler::Syntax::Parser::Parser#parse_case
table: parse refusal 1 owner=unassigned reason=no overload matches 'Compiler::Syntax::Ast::Rescue.new' with types Compiler::Syntax::Ast::ASTNode+, (Array(Compiler::Syntax::Ast::ASTNode) | Nil), (String | Nil) example=src/compiler/syntax/parser.iyi:1998 in Compiler::Syntax::Parser::Parser#parse_rescue
table: parse refusal 1 owner=unassigned reason=no overload matches 'Compiler::Syntax::Ast::ExceptionHandler.new' with types Compiler::Syntax::Ast::ASTNode+, (Array(Compiler::Syntax::Ast::Rescue) | Nil), (Compiler::Syntax::Ast::ASTNode+ | Nil), (Compiler::Syntax::Ast::ASTNode+ | Nil) example=src/compiler/syntax/parser.iyi:1958 in Compiler::Syntax::Parser::Parser#parse_begin
table: parse refusal 1 owner=unassigned reason=no overload matches 'Compiler::Syntax::Ast::Return.new' with type (Compiler::Syntax::Ast::ASTNode+ | Nil) example=src/compiler/syntax/parser.iyi:2049 in Compiler::Syntax::Parser::Parser#parse_return
table: parse refusal 1 owner=unassigned reason=no overload matches 'Compiler::Syntax::Ast::Break.new' with type (Compiler::Syntax::Ast::ASTNode+ | Nil) example=src/compiler/syntax/parser.iyi:2064 in Compiler::Syntax::Parser::Parser#parse_break
table: parse refusal 1 owner=unassigned reason=no overload matches 'Compiler::Syntax::Ast::Next.new' with type (Compiler::Syntax::Ast::ASTNode+ | Nil) example=src/compiler/syntax/parser.iyi:2079 in Compiler::Syntax::Parser::Parser#parse_next
table: parse refusal 1 owner=bodies reason=the value of 'bp' cannot be typed example=src/compiler/syntax/parser.iyi:4296 in Compiler::Syntax::Parser::Parser#parse_def_helper
table: parse refusal 1 owner=unassigned reason=no overload matches 'Compiler::Syntax::Ast::Def#initialize' with types String, Array(Compiler::Syntax::Ast::Arg), Compiler::Syntax::Ast::ASTNode+, (Compiler::Syntax::Ast::ASTNode+ | Nil), (Compiler::Syntax::Ast::Arg | Nil), (Compiler::Syntax::Ast::ASTNode+ | Nil), Bool, Bool, (Int32 | Nil), (Compiler::Syntax::Ast::Arg | Nil), (Array(String) | Nil), Bool example=no location in Compiler::Syntax::Ast::Def.class#new
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'body' for Compiler::Syntax::Parser::Parser example=src/compiler/syntax/parser.iyi:3877 in Compiler::Syntax::Parser::Parser#parse_macro
table: parse refusal 1 owner=bodies reason=the value of 'module_def' cannot be typed example=src/compiler/syntax/parser.iyi:4826 in Compiler::Syntax::Parser::Parser#parse_module_def
table: parse refusal 1 owner=unassigned reason=no overload matches 'Compiler::Syntax::Ast::Arg.new' with types String, (Compiler::Syntax::Ast::ASTNode+ | Nil), Nil, String example=src/compiler/syntax/parser.iyi:5021 in Compiler::Syntax::Parser::Parser#parse_enum_body_expressions
table: parse refusal 1 owner=bodies reason=the value of 'arg' cannot be typed example=src/compiler/syntax/parser.iyi:5022 in Compiler::Syntax::Parser::Parser#parse_enum_body_expressions
table: parse refusal 1 owner=bodies reason=the value of 'member' cannot be typed example=src/compiler/syntax/parser.iyi:5037 in Compiler::Syntax::Parser::Parser#parse_enum_body_expressions
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'member' for Compiler::Syntax::Parser::Parser example=src/compiler/syntax/parser.iyi:5039 in Compiler::Syntax::Parser::Parser#parse_enum_body_expressions
table: parse refusal 1 owner=bodies reason=variable 'm' cannot be typed example=src/compiler/syntax/parser.iyi:6100 in Compiler::Syntax::Parser::Parser#unexpected_token
table: parse refusal 1 owner=bodies reason=the value of 'target' cannot be typed example=src/compiler/syntax/parser.iyi:5140 in Compiler::Syntax::Parser::Parser#parse_impl_def
table: parse refusal 1 owner=unassigned reason=expected type, got Path example=src/compiler/syntax/parser.iyi:5140 in Compiler::Syntax::Parser::Parser#parse_impl_def
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'target' for Compiler::Syntax::Parser::Parser example=src/compiler/syntax/parser.iyi:5174 in Compiler::Syntax::Parser::Parser#parse_impl_def
table: parse refusal 1 owner=bodies reason=the value of 'impl_def' cannot be typed example=src/compiler/syntax/parser.iyi:5175 in Compiler::Syntax::Parser::Parser#parse_impl_def
table: parse refusal 1 owner=unassigned reason=no overload matches 'Compiler::Syntax::Ast::FunDef#initialize' with types String, Array(Compiler::Syntax::Ast::Arg), (Compiler::Syntax::Ast::ASTNode+ | Nil), (Compiler::Syntax::Ast::ASTNode+ | Nil), String example=no location in Compiler::Syntax::Ast::FunDef.class#new
table: parse refusal 1 owner=unassigned reason=no overload matches 'Compiler::Syntax::Ast::CStructOrUnionDef.new' with types String, Compiler::Syntax::Ast::ASTNode+, Bool example=src/compiler/syntax/parser.iyi:5523 in Compiler::Syntax::Parser::Parser#parse_c_struct_or_union
table: parse refusal 1 owner=bodies reason=the value of 'ident' cannot be typed example=src/compiler/syntax/parser.iyi:5380 in Compiler::Syntax::Parser::Parser#parse_lib_body_exp
table: parse refusal 1 owner=unassigned reason=no overload matches 'Compiler::Syntax::Ast::Asm.new' with types String, (Array(Compiler::Syntax::Ast::AsmOperand) | Nil), (Array(Compiler::Syntax::Ast::AsmOperand) | Nil), (Array(String) | Nil), Bool, Bool, Bool, Bool example=src/compiler/syntax/parser.iyi:3242 in Compiler::Syntax::Parser::Parser#parse_asm
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'super' for Compiler::Syntax::Ast::PointerOf example=src/compiler/syntax/ast.iyi:2450 in Compiler::Syntax::Ast::PointerOf#initialize
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'super' for Compiler::Syntax::Ast::SizeOf example=src/compiler/syntax/ast.iyi:2466 in Compiler::Syntax::Ast::SizeOf#initialize
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'super' for Compiler::Syntax::Ast::InstanceSizeOf example=src/compiler/syntax/ast.iyi:2482 in Compiler::Syntax::Ast::InstanceSizeOf#initialize
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'super' for Compiler::Syntax::Ast::AlignOf example=src/compiler/syntax/ast.iyi:2498 in Compiler::Syntax::Ast::AlignOf#initialize
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'super' for Compiler::Syntax::Ast::InstanceAlignOf example=src/compiler/syntax/ast.iyi:2514 in Compiler::Syntax::Ast::InstanceAlignOf#initialize
table: parse refusal 1 owner=unassigned reason=no overload matches 'Compiler::Syntax::Ast::AssocTypeDecl.new' with types String, (Compiler::Syntax::Ast::ASTNode+ | Nil) example=src/compiler/syntax/parser.iyi:5201 in Compiler::Syntax::Parser::Parser#parse_assoc_type
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'super' for Compiler::Syntax::Ast::And example=src/compiler/syntax/ast.iyi:2403 in Compiler::Syntax::Ast::And#initialize
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'super' for Compiler::Syntax::Ast::Or example=src/compiler/syntax/ast.iyi:2419 in Compiler::Syntax::Ast::Or#initialize
table: parse refusal 1 owner=bodies reason=the value of 'last_is_target' cannot be typed example=src/compiler/syntax/parser.iyi:256 in Compiler::Syntax::Parser::Parser#parse_multi_assign
table: parse refusal 1 owner=unassigned reason=unsupported node: ExceptionHandler example=src/iyi/./file.iyi:68 in File.class#read
table: parse defs-lowered-clean=660 lowering-refusal-sites=1136
table: parse lowering 86 owner=lowering core reason=lower: visit(assign NoReturn to (Int32 | Nil): not a member (hosted cast.cr, compatible type)) (hosted codegen.cr) is not ported yet example=Tuple(UInt64, Bool)#raise
table: parse lowering 79 owner=bodies reason=BUG: the analysed program has no type for the call to load (hosted call.cr: visit(Call)) example=IyiSchedLock.class#lock
table: parse lowering 78 owner=lowering core reason=lower: visit(MagicConstant) (hosted codegen.cr) is not ported yet example=Tuple(UInt64, Bool)#[]
table: parse lowering 69 owner=lowering core reason=lower: visit(store of Compiler::Foundation::Location::Location in (Compiler::Foundation::Location::Location | Nil) (hosted store_value, not ported)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Ast::Nop#at
table: parse lowering 60 owner=lowering core reason=lower: visit(a call with default arguments or a splat (hosted call.cr)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#io_take
table: parse lowering 49 owner=lowering core reason=lower: visit(a class method call on a receiver that is not a constant path (hosted call.cr: prepare_call_args, Path)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#run_spawned_fiber
table: parse lowering 46 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of copy_from (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Array(IyiSchedulerState)#<<
table: parse lowering 44 owner=lowering core reason=lower: visit(yield with no block in scope (hosted codegen.cr: visit(Yield), a block of an enclosing block body)) (hosted codegen.cr) is not ported yet example=Array(Int32)#each
table: parse lowering 40 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 1 of []= (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Pointer(IyiSchedulerState)#copy_run
table: parse lowering 30 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of add (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiWorkers.class#link_shared
table: parse lowering 29 owner=lowering core reason=lower: visit(a call to == inherited from a superclass of Compiler::Syntax::Token::TokenKind (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#next_token
table: parse lowering 25 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of initialize (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Atomic(UInt64).class#new
table: parse lowering 25 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of set (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#lists_unlock
table: parse lowering 24 owner=unassigned reason=error[types]: icmp compares %"(Int64 | Nil)" with i64 example=Array(String)#__iyi_say
table: parse lowering 24 owner=lowering core reason=lower: visit(Case) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#consume_whitespace
table: parse lowering 21 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of compare_and_set (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#take_ring_head
table: parse lowering 21 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 1 of syntax_error (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#parse_percent_macro_expression
table: parse lowering 19 owner=bodies reason=BUG: the analysed program has no type for a branch (hosted codegen.cr: visit(If)) example=IyiScheduler.class#panic_current
table: parse lowering 16 owner=bodies reason=BUG: the analysed program has no type for the assigned value (hosted codegen.cr: codegen_assign) example=IyiScheduler.class#sleep_remove
table: parse lowering 16 owner=bodies reason=BUG: the analysed program has no type for the call to initialize (hosted call.cr: visit(Call)) example=Compiler::Syntax::Ast::Not.class#new
table: parse lowering 14 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of copy_run (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Pointer(IyiSchedulerState)#copy_from
table: parse lowering 13 owner=bodies reason=BUG: the analysed program has no type for the body of check_type_declaration (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#check_type_declaration
table: parse lowering 12 owner=lowering core reason=lower: visit(a call to next_token_skip_space inherited from a superclass of Compiler::Syntax::Parser::Parser (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#parse_empty_array_literal
table: parse lowering 11 owner=lowering core reason=lower: visit(a call to next_char inherited from a superclass of Compiler::Syntax::Parser::Parser (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#delimiter_state_for_percent_literal
table: parse lowering 11 owner=bodies reason=BUG: the analysed program has no type for the body of initialize (hosted codegen_fun: return type) example=Compiler::Syntax::Ast::Not#initialize
table: parse lowering 10 owner=lowering core reason=lower: visit(a call to a def with a &block parameter (hosted call.cr: codegen_call_with_block_as_fun_literal, closures)) (hosted codegen.cr) is not ported yet example=String#+
table: parse lowering 10 owner=lowering core reason=lower: visit(a call to next_token inherited from a superclass of Compiler::Syntax::Parser::Parser (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#next_token_skip_statement_end
table: parse lowering 10 owner=lowering core reason=lower: visit(a call to next_token_skip_space_or_newline inherited from a superclass of Compiler::Syntax::Parser::Parser (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#parse_array_literal
table: parse lowering 8 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of new (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#state
table: parse lowering 7 owner=lowering core reason=lower: codegen_cond of (Compiler::Syntax::Token::Keyword | Nil) is not ported yet (hosted cond.cr: nilable and union tests, slice S2c) example=Compiler::Syntax::Parser::Parser#check_void_expression_keyword
table: parse lowering 7 owner=bodies reason=BUG: the analysed program has no type for the call to end_location (hosted call.cr: visit(Call)) example=Compiler::Syntax::Ast::Not#at_end
table: parse lowering 7 owner=bodies reason=BUG: the analysed program has no type for the body of parse_class_def (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_class_def
table: parse lowering 6 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of << (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Ast::StringBuilder#<<
table: parse lowering 5 owner=lowering core reason=lower: visit(a call to == inherited from a superclass of IyiFiberState (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=IyiGroup#cancel_children_locked
table: parse lowering 5 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of sub (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiMark.class#count_out
table: parse lowering 5 owner=bodies reason=BUG: the analysed program has no type for the call to check (hosted call.cr: visit(Call)) example=Compiler::Syntax::Parser::Parser#parse_string_array
table: parse lowering 4 owner=bodies reason=BUG: the analysed program has no type for the call to state (hosted call.cr: visit(Call)) example=IyiGroup#join
table: parse lowering 4 owner=lowering core reason=lower: visit(assign IyiFiber to Nil (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#heap_remove
table: parse lowering 4 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of swap (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiThread.class#lock_turn
table: parse lowering 4 owner=bodies reason=BUG: the analysed program has no type for the call to read64 (hosted call.cr: visit(Call)) example=IyiMark.class#scan
table: parse lowering 4 owner=lowering core reason=lower: visit(a call to current_char inherited from a superclass of Compiler::Syntax::Parser::Parser (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#skip_comment
table: parse lowering 4 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 1 of initialize (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Ast::NamedArgument.class#new
table: parse lowering 4 owner=bodies reason=BUG: the analysed program has no type for the body of parse_call_args (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_call_args
table: parse lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of compare_and_set (hosted codegen_fun: return type) example=Atomic(UInt64)#compare_and_set
table: parse lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of == (hosted codegen_fun: return type) example=IyiFiberState#==
table: parse lowering 3 owner=bodies reason=BUG: the analysed program has no type for the call to new (hosted call.cr: visit(Call)) example=IyiMark.class#scavenge
table: parse lowering 3 owner=bodies reason=BUG: the analysed program has no type for the call to state= (hosted call.cr: visit(Call)) example=IyiScheduler.class#wake_completed
table: parse lowering 3 owner=unassigned reason=BUG: Cast operand has no analysed type (hosted codegen.cr: visit(Cast)) example=String#==
table: parse lowering 3 owner=lowering core reason=lower: visit(HashLiteral) (hosted codegen.cr) is not ported yet example=Compiler::Tools::Parse::ParseTool.class#parse_source
table: parse lowering 3 owner=lowering core reason=lower: visit(a call to string_range inherited from a superclass of Compiler::Syntax::Parser::Parser (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#string_range
table: parse lowering 3 owner=lowering core reason=lower: visit(a call to current_pos inherited from a superclass of Compiler::Syntax::Parser::Parser (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#consume_doc
table: parse lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of scan_number (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#scan_number
table: parse lowering 3 owner=unassigned reason=error[types]: an extension must widen an integer example=Compiler::Syntax::Parser::Parser#char_to_digit
table: parse lowering 3 owner=lowering core reason=lower: visit(a call to compare_numeric_strings inherited from a superclass of Compiler::Syntax::Parser::Parser (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#fits_in_i32?
table: parse lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of parse_delimiter (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_delimiter
table: parse lowering 3 owner=lowering core reason=lower: visit(assign Nil to (Proc(Hash(String, Compiler::Syntax::Ast::ASTNode), String, Compiler::Syntax::Ast::ASTNode) | Nil) (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=Hash(String, Compiler::Syntax::Ast::ASTNode).class#new
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of get (hosted codegen_fun: return type) example=Atomic(UInt64)#get
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of set (hosted codegen_fun: return type) example=Atomic(UInt64)#set
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of add (hosted codegen_fun: return type) example=Atomic(Int64)#add
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of sub (hosted codegen_fun: return type) example=Atomic(Int64)#sub
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the call to shared? (hosted call.cr: visit(Call)) example=IyiScheduler.class#take_mail
table: parse lowering 2 owner=unassigned reason=a proc literal that returns NoReturn (hosted codegen_fun, the noreturn attribute on a literal) example=IyiMark.class#start_helpers
table: parse lowering 2 owner=lowering core reason=lower: visit(a call to new with no receiver inside a generic or builtin class method (hosted call.cr: prepare_call_args, the metaclass owner)) (hosted codegen.cr) is not ported yet example=Array(IyiWaiter | Nil).class#new
table: parse lowering 2 owner=lowering core reason=lower: visit(assign Proc(NoReturn) to Proc(Nil) (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=IyiThread.class#new
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the call to < (hosted call.cr: visit(Call)) example=Compiler::Tools::Parse::ParseTool.class#run
table: parse lowering 2 owner=lowering core reason=lower: visit(assign Nil to (Proc(Hash(String, Bool), String, Bool) | Nil) (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=Hash(String, Bool).class#new
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the call to super (hosted call.cr: visit(Call)) example=Compiler::Syntax::Parser::Parser.class#new
table: parse lowering 2 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of type= (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#symbol
table: parse lowering 2 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of entry_of (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Hash(String, String)#[]?
table: parse lowering 2 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of slot_for (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Hash(String, String)#entry_of
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the call to location (hosted call.cr: visit(Call)) example=Compiler::Syntax::Ast::Union#at
table: parse lowering 2 owner=lowering core reason=lower: visit(assign String to (Compiler::Syntax::Ast::ASTNode+ | String) (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Piece.class#new
table: parse lowering 2 owner=lowering core reason=lower: visit(a call on a receiver of type (Compiler::Syntax::Token::Keyword | Nil) (hosted call.cr: prepare_call_args, owner is not a class or struct)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#parse_call_arg_value
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of parse_trait_def (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_trait_def
table: parse lowering 1 owner=lowering core reason=lower: visit(upcast NoReturn to String (hosted cast.cr: upcast_distinct)) (hosted codegen.cr) is not ported yet example=String.class#interpolation
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of swap (hosted codegen_fun: return type) example=Atomic(UInt64)#swap
table: parse lowering 1 owner=lowering core reason=lower: visit(a call to != inherited from a superclass of IyiFiberState (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=IyiRoots.class#each_fiber_root
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of thread_warm (hosted codegen_fun: return type) example=IyiHeap.class#thread_warm
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of reopen_in (hosted codegen_fun: return type) example=IyiHeap.class#reopen_in
table: parse lowering 1 owner=unassigned reason=lower: __iyi_once is not declared in the module: the prelude's once entry (hosted run_once, once.cr:22) was not visited example=IyiWorkers.class#listed_at
table: parse lowering 1 owner=unassigned reason=BUG: variable block is read before it is assigned (hosted codegen.cr: visit(Var)) example=IyiThread.class#start
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of make_lot (hosted codegen_fun: return type) example=IyiScheduler.class#make_lot
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of lot_lock (hosted codegen_fun: return type) example=IyiScheduler.class#lot_lock
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to get (hosted call.cr: visit(Call)) example=IyiChanLock.class#lock
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of current_char (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#current_char
table: parse lowering 1 owner=lowering core reason=lower: visit(a call to skip_comment inherited from a superclass of Compiler::Syntax::Parser::Parser (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#consume_comment
table: parse lowering 1 owner=lowering core reason=lower: visit(a call to next_codepoint_bytes inherited from a superclass of Compiler::Syntax::Parser::Parser (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#next_char_no_column_increment
table: parse lowering 1 owner=lowering core reason=lower: visit(a call to incr_column_number inherited from a superclass of Compiler::Syntax::Parser::Parser (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#next_char
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of peek_next_char (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#peek_next_char
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of consume_heredoc_start (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#consume_heredoc_start
table: parse lowering 1 owner=lowering core reason=lower: visit(a call to == inherited from a superclass of Compiler::Syntax::Token::NumberKind (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Token::NumberKind#float?
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of consume_symbol (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#consume_symbol
table: parse lowering 1 owner=lowering core reason=lower: visit(a call to hex_value inherited from a superclass of Compiler::Syntax::Parser::Parser (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#consume_string_hex_escape
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of escape_byte_string (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#escape_byte_string
table: parse lowering 1 owner=lowering core reason=lower: visit(a call to consume_char_unicode_escape inherited from a superclass of Compiler::Syntax::Parser::Parser (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#consume_string_unicode_escape
table: parse lowering 1 owner=lowering core reason=lower: visit(a call to peek_next_char inherited from a superclass of Compiler::Syntax::Parser::Parser (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#consume_char_unicode_escape
table: parse lowering 1 owner=lowering core reason=lower: visit(a call to string_range_from_pool inherited from a superclass of Compiler::Syntax::Parser::Parser (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#string_range_from_pool
table: parse lowering 1 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of []? (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Compiler::Foundation::StringPool::StringPool#get
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to ident_part? (hosted call.cr: visit(Call)) example=Compiler::Syntax::Parser::Parser#scan_ident
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of ident_part_or_end? (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#ident_part_or_end?
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_multi_assign (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_multi_assign
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_expression (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_expression
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_prefix (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_prefix
table: parse lowering 1 owner=lowering core reason=lower: visit(a phi over a passed-by-value Compiler::Foundation::Location::Location that is not a union (hosted phi.cr: close, struct pointer)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#syntax_error
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_atomic_with_method (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_atomic_with_method
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_atomic (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_atomic
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_parenthesized_expression (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_parenthesized_expression
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_bare_proc_type (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_bare_proc_type
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_union_type (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_union_type
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_atomic_type_with_suffix (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_atomic_type_with_suffix
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_atomic_type (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_atomic_type
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_proc_type_output (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_proc_type_output
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to copy_token (hosted call.cr: visit(Call)) example=Compiler::Syntax::Parser::Parser#type_start?
table: parse lowering 1 owner=lowering core reason=lower: codegen_cond of (Compiler::Foundation::Location::Location | Nil) is not ported yet (hosted cond.cr: nilable and union tests, slice S2c) example=Compiler::Syntax::Parser::Parser#syntax_error
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of syntax_error (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#syntax_error
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_expression_inside_macro (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_expression_inside_macro
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of check_macro_expression_end (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#check_macro_expression_end
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_percent_macro_control (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_percent_macro_control
table: parse lowering 1 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of heredoc_body (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#remove_heredoc_indent
table: parse lowering 1 owner=unassigned reason=error[call-operands]: a call passes 1 arguments to a 0-parameter type example=Compiler::Syntax::Ast::StringBuilder#initialize
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_annotation (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_annotation
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_instance_var_or_type_decl (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_instance_var_or_type_decl
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_class_var_or_type_decl (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_class_var_or_type_decl
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_fun_literal (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_fun_literal
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_fun_literal_param (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_fun_literal_param
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of with_isolated_var_scope (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#with_isolated_var_scope
table: parse lowering 1 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of has_key? (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Set(String)#add
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_if (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_if
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_unless (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_unless
table: parse lowering 1 owner=lowering core reason=lower: visit(a call to next_token_skip_statement_end inherited from a superclass of Compiler::Syntax::Parser::Parser (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#parse_select
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_case (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_case
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_begin (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_begin
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_rescue (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_rescue
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_return (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_return
table: parse lowering 1 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 5 of initialize (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::CallArgs.class#new
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_call_args_space_consumed (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_call_args_space_consumed
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_break (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_break
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_next (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_next
table: parse lowering 1 owner=lowering core reason=lower: visit(a call to iyi? inherited from a superclass of Compiler::Syntax::Parser::Parser (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#check_iyi_def_bang
table: parse lowering 1 owner=lowering core reason=lower: bounds is declared (Hash(String, Compiler::Syntax::Ast::ASTNode) | Nil) and assigned Nil: the hosted upcast is not ported yet example=Compiler::Syntax::Parser::Parser#parse_def_free_vars
table: parse lowering 1 owner=lowering core reason=lower: type_vars is declared (Array(String) | Nil) and assigned Nil: the hosted upcast is not ported yet example=Compiler::Syntax::Parser::Parser#parse_type_vars
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_macro (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_macro
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_module_def (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_module_def
table: parse lowering 1 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 3 of initialize (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Ast::ImportDecl.class#new
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_enum_def (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_enum_def
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of unexpected_token (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#unexpected_token
table: parse lowering 1 owner=lowering core reason=lower: visit(assign Compiler::Syntax::Ast::ClassVar to Compiler::Syntax::Ast::ASTNode+ (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Ast::Assign#initialize
table: parse lowering 1 owner=lowering core reason=lower: visit(a call to location inherited from a superclass of Compiler::Syntax::Ast::ClassVar (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Ast::Assign#at
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to preserve_stop_on_do (hosted call.cr: visit(Call)) example=Compiler::Syntax::Parser::Parser#parse_trait_or_impl_body
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_impl_def (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_impl_def
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_annotation_def (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_annotation_def
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_alias (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_alias
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_include (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_include
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_extend (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_extend
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_lib (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_lib
table: parse lowering 1 owner=lowering core reason=lower: visit(a call to skip_statement_end inherited from a superclass of Compiler::Syntax::Parser::Parser (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#parse_lib_body_expressions
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_lib_body_exp (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_lib_body_exp
table: parse lowering 1 owner=lowering core reason=lower: visit(a typed declaration in a block (hosted alloca_non_closured_vars, TypeDeclaration), not ported yet) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Parser::Parser#parse_fun_def
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_c_struct_or_union (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_c_struct_or_union
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_asm (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_asm
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_assoc_type (hosted codegen_fun: return type) example=Compiler::Syntax::Parser::Parser#parse_assoc_type
table: parse lowering 1 owner=lowering core reason=lower: visit(a call to location inherited from a superclass of Compiler::Syntax::Ast::Call (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Ast::Var#at
table: parse lowering 1 owner=lowering core reason=lower: visit(assign (Compiler::Syntax::Ast::ClassVar | Compiler::Syntax::Ast::Global | Compiler::Syntax::Ast::InstanceVar | Compiler::Syntax::Ast::Var) to Compiler::Syntax::Ast::ASTNode+ (union into a non-mixed target, hosted assign_distinct)) (hosted codegen.cr) is not ported yet example=Compiler::Syntax::Ast::UninitializedVar#initialize
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of read (hosted codegen_fun: return type) example=File.class#read
table: compile_native defs-reached=1243 defs-typed-clean=1168 root-refusals=3 refusal-sites=303
table: compile_native refusal 128 owner=bodies reason=pointerof of callstack is not ported yet: only a local variable is example=src/iyi/prelude.iyi:3 in Int64#raise
table: compile_native refusal 21 owner=bodies reason=the value of 'buffer' cannot be typed example=src/iyi/./string.iyi:38 in String.class#new
table: compile_native refusal 20 owner=bodies reason=the value of 'c' cannot be typed example=src/compiler/ir/parser.iyi:457 in Compiler::Ir::Parser::IrParser#read_header
table: compile_native refusal 12 owner=calls reason=expected argument #1 to 'Pointer(UInt8)#+' to be Int64, not Int32 example=src/iyi/./string.iyi:37 in String.class#new
table: compile_native refusal 8 owner=bodies reason=the value of 'slot' cannot be typed example=src/iyi/prelude.iyi:1667 in IyiHeap.class#thread_warm
table: compile_native refusal 6 owner=bodies reason=the value of 'err' cannot be typed example=src/compiler/ir/parser.iyi:434 in Compiler::Ir::Parser::IrParser#run
table: compile_native refusal 5 owner=bodies reason=undefined local variable or method 'cursor' for IyiHeap.class example=src/iyi/prelude.iyi:1665 in IyiHeap.class#thread_warm
table: compile_native refusal 4 owner=bodies reason=the value of 'cursor' cannot be typed example=src/iyi/prelude.iyi:1663 in IyiHeap.class#thread_warm
table: compile_native refusal 4 owner=bodies reason=the value of 'built' cannot be typed example=src/compiler/ir/parser.iyi:490 in Compiler::Ir::Parser::IrParser#read_header
table: compile_native refusal 3 owner=calls reason=expected argument #2 to 'IyiAtomic.rmw' to be Pointer(T), not Pointer(UInt64) example=src/iyi/./atomic.iyi:70 in Atomic(UInt64)#add
table: compile_native refusal 3 owner=bodies reason=the value of 'following' cannot be typed example=src/iyi/prelude.iyi:1669 in IyiHeap.class#thread_warm
table: compile_native refusal 3 owner=bodies reason=the value of 'byte' cannot be typed example=src/iyi/prelude.iyi:1670 in IyiHeap.class#thread_warm
table: compile_native refusal 3 owner=bodies reason=the value of 'head' cannot be typed example=src/iyi/prelude.iyi:1681 in IyiHeap.class#thread_warm
table: compile_native refusal 3 owner=unassigned reason=type mismatch for return type: expected Array(Int32), got Array example=src/std/base64.iyi:221 in top level
table: compile_native refusal 3 owner=bodies reason=the value of 'compiler' cannot be typed example=src/compiler/tools/compile_native.iyi:161 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 3 owner=bodies reason=undefined local variable or method 'triple_text' for Compiler::Ir::Parser::IrParser example=src/compiler/ir/parser.iyi:487 in Compiler::Ir::Parser::IrParser#read_header
table: compile_native refusal 3 owner=unassigned reason=type mismatch for return type: expected Std::Slice::Bytes, got Std::Slice::Slice(UInt8) example=no location in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 2 owner=calls reason=expected argument #2 to 'IyiAtomic.rmw' to be Pointer(T), not Pointer(Int64) example=src/iyi/./atomic.iyi:70 in Atomic(Int64)#add
table: compile_native refusal 2 owner=calls reason=undefined method '==' for NoReturn example=src/iyi/prelude.iyi:1660 in IyiHeap.class#thread_warm
table: compile_native refusal 2 owner=calls reason=undefined method '-' for NoReturn example=src/iyi/prelude.iyi:1662 in IyiHeap.class#thread_warm
table: compile_native refusal 2 owner=bodies reason=undefined local variable or method 'head' for IyiHeap.class example=src/iyi/prelude.iyi:1631 in IyiHeap.class#reopen_in
table: compile_native refusal 2 owner=bodies reason=the value of 'count' cannot be typed example=src/iyi/prelude.iyi:1634 in IyiHeap.class#reopen_in
table: compile_native refusal 2 owner=bodies reason=undefined local variable or method 'buffer' for String.class example=src/iyi/./string.iyi:39 in String.class#new
table: compile_native refusal 2 owner=bodies reason=the value of 'loader' cannot be typed example=src/compiler/tools/compile_native.iyi:159 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 2 owner=bodies reason=the value of 'refusal' cannot be typed example=src/compiler/tools/compile_native.iyi:164 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 2 owner=bodies reason=the value of 'entry' cannot be typed example=src/iyi/./hash.iyi:567 in Hash(String, Int64)#slot_for
table: compile_native refusal 2 owner=bodies reason=the value of 'errors' cannot be typed example=src/compiler/tools/compile_native.iyi:52 in Compiler::Tools::CompileNative::CompileNative.class#module_of
table: compile_native refusal 2 owner=bodies reason=the value of 'result' cannot be typed example=src/compiler/tools/compile_native.iyi:193 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.load' to be Pointer(T), not Pointer(UInt64) example=src/iyi/./atomic.iyi:59 in Atomic(UInt64)#get
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.cmpxchg' to be Pointer(T), not Pointer(UInt64) example=src/iyi/./atomic.iyi:88 in Atomic(UInt64)#compare_and_set
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.store' to be Pointer(T), not Pointer(UInt64) example=src/iyi/./atomic.iyi:64 in Atomic(UInt64)#set
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.load' to be Pointer(T), not Pointer(Int64) example=src/iyi/./atomic.iyi:59 in Atomic(Int64)#get
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.cmpxchg' to be Pointer(T), not Pointer(Int64) example=src/iyi/./atomic.iyi:88 in Atomic(Int64)#compare_and_set
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.store' to be Pointer(T), not Pointer(Int64) example=src/iyi/./atomic.iyi:64 in Atomic(Int64)#set
table: compile_native refusal 1 owner=bodies reason=pointerof of LibIyiGCTable.__iyi_gc_layouts is not ported yet: only a local variable is example=src/iyi/prelude.iyi:3811 in IyiMark.class#layouts_table
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.cmpxchg' to be Pointer(T), not Pointer(UInt8) example=src/iyi/./atomic.iyi:88 in Atomic(UInt8)#compare_and_set
table: compile_native refusal 1 owner=declarations reason=primitive enum_value without a declared return type example=no location in IyiFiberState#value
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'count' for IyiHeap.class example=src/iyi/prelude.iyi:1637 in IyiHeap.class#reopen_in
table: compile_native refusal 1 owner=unassigned reason=type mismatch for class variable '@@lot_tails': expected (Array(IyiWaiter | Nil) | Nil), got Array(IyiWaiter | Nil) example=src/iyi/./concurrency.iyi:3822 in IyiScheduler.class#make_lot
table: compile_native refusal 1 owner=unassigned reason=type mismatch for class variable '@@lot_heads': expected (Array(IyiWaiter | Nil) | Nil), got Array(IyiWaiter | Nil) example=src/iyi/./concurrency.iyi:3823 in IyiScheduler.class#make_lot
table: compile_native refusal 1 owner=unassigned reason=undefined class variable '@@installed' for IyiStackGuard example=src/iyi/concurrency.iyi:53 in IyiStackGuard.class#install
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'Pointer(UInt64)#+' to be Int64, not Int32 example=src/iyi/./concurrency.iyi:3827 in IyiScheduler.class#lot_lock
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'buffer' for Int64 example=src/iyi/./number.iyi:289 in Int64#to_s
table: compile_native refusal 1 owner=declarations reason=undefined constant IyiPath example=src/compiler/loader.iyi:135 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'iyi_path' for Compiler::Loader::Loader.class example=no location in Compiler::Loader::Loader.class#new
table: compile_native refusal 1 owner=unassigned reason=unsupported node: ExceptionHandler example=src/iyi/./file.iyi:68 in File.class#read
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiSchedulerState#io_slots=' to be (Array(IyiFiber | Nil) | Nil), not Array(IyiFiber | Nil) example=src/iyi/./concurrency.iyi:3464 in IyiScheduler.class#io_room
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'target' for IyiIO example=src/iyi/./io.iyi:194 in IyiIO#read_all
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'buffer' for Char example=src/iyi/./string.iyi:592 in Char#to_s
table: compile_native refusal 1 owner=unassigned reason=instance variable '@locals' of Compiler::Ir::Parser::IrParser must be Hash(String, Value), not (Hash(String, Value) | Hash(String, Compiler::Ir::Values::Value)) example=src/compiler/ir/parser.iyi:416 in Compiler::Ir::Parser::IrParser#initialize
table: compile_native refusal 1 owner=unassigned reason=instance variable '@unnamed' of Compiler::Ir::Parser::IrParser must be Array(Value), not (Array(Value) | Array(Compiler::Ir::Values::Value)) example=src/compiler/ir/parser.iyi:417 in Compiler::Ir::Parser::IrParser#initialize
table: compile_native refusal 1 owner=unassigned reason=instance variable '@pending_clauses' of Compiler::Ir::Parser::IrParser must be Array(Tuple(Compiler::Ir::Function, Int32)), not (Array(Tuple(Compiler::Ir::Function, Int32)) | Array(Tuple(Compiler::Ir::Function::Function, Int32))) example=src/compiler/ir/parser.iyi:423 in Compiler::Ir::Parser::IrParser#initialize
table: compile_native refusal 1 owner=unassigned reason=instance variable '@pending_defs' of Compiler::Ir::Parser::IrParser must be Array(Tuple(Compiler::Ir::Function, Int32)), not (Array(Tuple(Compiler::Ir::Function, Int32)) | Array(Tuple(Compiler::Ir::Function::Function, Int32))) example=src/compiler/ir/parser.iyi:424 in Compiler::Ir::Parser::IrParser#initialize
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'tokenize' for Compiler::Ir::Parser::IrParser example=src/compiler/ir/parser.iyi:428 in Compiler::Ir::Parser::IrParser#run
table: compile_native refusal 1 owner=declarations reason=undefined constant Cursor example=src/compiler/ir/parser.iyi:456 in Compiler::Ir::Parser::IrParser#read_header
table: compile_native refusal 1 owner=bodies reason=the value of 'what' cannot be typed example=src/compiler/ir/parser.iyi:469 in Compiler::Ir::Parser::IrParser#read_header
table: compile_native refusal 1 owner=bodies reason=the value of 'value' cannot be typed example=src/compiler/ir/parser.iyi:469 in Compiler::Ir::Parser::IrParser#read_header
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'what' for Compiler::Ir::Parser::IrParser example=src/compiler/ir/parser.iyi:470 in Compiler::Ir::Parser::IrParser#read_header
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'value' for Compiler::Ir::Parser::IrParser example=src/compiler/ir/parser.iyi:470 in Compiler::Ir::Parser::IrParser#read_header
table: compile_native refusal 1 owner=bodies reason=the value of 'key' cannot be typed example=src/compiler/ir/parser.iyi:478 in Compiler::Ir::Parser::IrParser#read_header
table: compile_native refusal 1 owner=bodies reason=the value of 'target' cannot be typed example=src/compiler/ir/parser.iyi:488 in Compiler::Ir::Parser::IrParser#read_header
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'name_text' for Compiler::Ir::Parser::IrParser example=src/compiler/ir/parser.iyi:489 in Compiler::Ir::Parser::IrParser#read_header
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'target' for Compiler::Ir::Parser::IrParser example=src/compiler/ir/parser.iyi:489 in Compiler::Ir::Parser::IrParser#read_header
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'built' for Compiler::Ir::Parser::IrParser example=src/compiler/ir/parser.iyi:491 in Compiler::Ir::Parser::IrParser#read_header
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'layout_text' for Compiler::Ir::Parser::IrParser example=src/compiler/ir/parser.iyi:492 in Compiler::Ir::Parser::IrParser#read_header
table: compile_native refusal 1 owner=calls reason=undefined method 'hash' for NoReturn example=src/iyi/./hash.iyi:564 in Hash(String, Int64)#slot_for
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'slot' for Hash(String, Int64) example=src/iyi/./hash.iyi:572 in Hash(String, Int64)#slot_for
table: compile_native refusal 1 owner=unassigned reason=no overload matches 'Compiler::Ir::Parser::IrParser#define_types' with type Compiler::Ir::Module::Module example=src/compiler/ir/parser.iyi:433 in Compiler::Ir::Parser::IrParser#run
table: compile_native refusal 1 owner=unassigned reason=no overload matches 'Compiler::Ir::Parser::IrParser#define_globals_and_functions' with type Compiler::Ir::Module::Module example=src/compiler/ir/parser.iyi:435 in Compiler::Ir::Parser::IrParser#run
table: compile_native refusal 1 owner=unassigned reason=no overload matches 'Compiler::Ir::Parser::IrParser#define_bodies' with type Compiler::Ir::Module::Module example=src/compiler/ir/parser.iyi:437 in Compiler::Ir::Parser::IrParser#run
table: compile_native refusal 1 owner=unassigned reason=no overload matches 'Compiler::Tools::CompileNative::CompileNative.verify' with type Compiler::Ir::Module::Module example=src/compiler/tools/compile_native.iyi:51 in Compiler::Tools::CompileNative::CompileNative.class#module_of
table: compile_native refusal 1 owner=unassigned reason=no overload matches 'Compiler::Tools::CompileNative::CompileNative.compile_wasm' with types Compiler::Ir::Module::Module, Compiler::Ir::Module::Module example=src/compiler/tools/compile_native.iyi:178 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'built' for Compiler::Tools::CompileNative::CompileNative.class example=src/compiler/tools/compile_native.iyi:182 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 1 owner=calls reason=expected argument #2 to 'Pointer(UInt8)#[]=' to be UInt8, not Nil example=src/std/slice.iyi:70 in Std::Slice::Slice(UInt8).class#new
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'Std::Slice::Slice(UInt8).new' to be Int32, not Pointer(UInt8) example=src/std/slice.iyi:73 in Std::Slice::Slice(UInt8).class#new
table: compile_native refusal 1 owner=unassigned reason=expected type, got Module example=src/compiler/tools/compile_native.iyi:192 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'result' for Compiler::Tools::CompileNative::CompileNative.class example=src/compiler/tools/compile_native.iyi:196 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native defs-lowered-clean=465 lowering-refusal-sites=578
table: compile_native lowering 79 owner=bodies reason=BUG: the analysed program has no type for the call to load (hosted call.cr: visit(Call)) example=IyiSchedLock.class#lock
table: compile_native lowering 67 owner=lowering core reason=lower: visit(assign NoReturn to (Int32 | Nil): not a member (hosted cast.cr, compatible type)) (hosted codegen.cr) is not ported yet example=Tuple(UInt64, Bool)#raise
table: compile_native lowering 51 owner=lowering core reason=lower: visit(MagicConstant) (hosted codegen.cr) is not ported yet example=Tuple(UInt64, Bool)#[]
table: compile_native lowering 49 owner=lowering core reason=lower: visit(a class method call on a receiver that is not a constant path (hosted call.cr: prepare_call_args, Path)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#run_spawned_fiber
table: compile_native lowering 41 owner=lowering core reason=lower: visit(a call with default arguments or a splat (hosted call.cr)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#io_take
table: compile_native lowering 30 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of add (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiWorkers.class#link_shared
table: compile_native lowering 27 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 1 of []= (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Pointer(IyiSchedulerState)#copy_run
table: compile_native lowering 25 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of set (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#lists_unlock
table: compile_native lowering 21 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of compare_and_set (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#take_ring_head
table: compile_native lowering 18 owner=bodies reason=BUG: the analysed program has no type for a branch (hosted codegen.cr: visit(If)) example=IyiScheduler.class#panic_current
table: compile_native lowering 16 owner=bodies reason=BUG: the analysed program has no type for the assigned value (hosted codegen.cr: codegen_assign) example=IyiScheduler.class#sleep_remove
table: compile_native lowering 14 owner=lowering core reason=lower: visit(a call to a def with a &block parameter (hosted call.cr: codegen_call_with_block_as_fun_literal, closures)) (hosted codegen.cr) is not ported yet example=String#+
table: compile_native lowering 14 owner=unassigned reason=error[types]: icmp compares %"(Int64 | Nil)" with i64 example=Array#__iyi_say
table: compile_native lowering 11 owner=lowering core reason=lower: visit(yield with no block in scope (hosted codegen.cr: visit(Yield), a block of an enclosing block body)) (hosted codegen.cr) is not ported yet example=Array(Int32)#each
table: compile_native lowering 8 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of new (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#state
table: compile_native lowering 6 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of copy_from (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Array(IyiSchedulerState)#<<
table: compile_native lowering 5 owner=lowering core reason=lower: visit(a call to == inherited from a superclass of IyiFiberState (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=IyiGroup#cancel_children_locked
table: compile_native lowering 5 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of sub (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiMark.class#count_out
table: compile_native lowering 4 owner=bodies reason=BUG: the analysed program has no type for the call to state (hosted call.cr: visit(Call)) example=IyiGroup#join
table: compile_native lowering 4 owner=lowering core reason=lower: visit(assign IyiFiber to Nil (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#heap_remove
table: compile_native lowering 4 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of swap (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiThread.class#lock_turn
table: compile_native lowering 4 owner=bodies reason=BUG: the analysed program has no type for the call to read64 (hosted call.cr: visit(Call)) example=IyiMark.class#scan
table: compile_native lowering 4 owner=unassigned reason=BUG: Cast operand has no analysed type (hosted codegen.cr: visit(Cast)) example=String#==
table: compile_native lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of compare_and_set (hosted codegen_fun: return type) example=Atomic(UInt64)#compare_and_set
table: compile_native lowering 3 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of copy_run (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Pointer(IyiSchedulerState)#copy_from
table: compile_native lowering 3 owner=bodies reason=BUG: the analysed program has no type for the call to new (hosted call.cr: visit(Call)) example=IyiMark.class#scavenge
table: compile_native lowering 3 owner=bodies reason=BUG: the analysed program has no type for the call to state= (hosted call.cr: visit(Call)) example=IyiScheduler.class#wake_completed
table: compile_native lowering 3 owner=lowering core reason=lower: visit(a class method call on Array(T).class (hosted call.cr: prepare_call_args, a generic or builtin metaclass)) (hosted codegen.cr) is not ported yet example=Std::Base64::Base64.class#decode_values
table: compile_native lowering 3 owner=lowering core reason=BUG: llvm_struct_type of Array is not ported yet (hosted create_llvm_struct_type) example=Array(T).class#new
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of get (hosted codegen_fun: return type) example=Atomic(UInt64)#get
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of set (hosted codegen_fun: return type) example=Atomic(UInt64)#set
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of add (hosted codegen_fun: return type) example=Atomic(Int64)#add
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of sub (hosted codegen_fun: return type) example=Atomic(Int64)#sub
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the call to shared? (hosted call.cr: visit(Call)) example=IyiScheduler.class#take_mail
table: compile_native lowering 2 owner=lowering core reason=lower: visit(upcast NoReturn to String (hosted cast.cr: upcast_distinct)) (hosted codegen.cr) is not ported yet example=String.class#interpolation
table: compile_native lowering 2 owner=unassigned reason=a proc literal that returns NoReturn (hosted codegen_fun, the noreturn attribute on a literal) example=IyiMark.class#start_helpers
table: compile_native lowering 2 owner=unassigned reason=lower: __iyi_once is not declared in the module: the prelude's once entry (hosted run_once, once.cr:22) was not visited example=IyiWorkers.class#listed_at
table: compile_native lowering 2 owner=lowering core reason=lower: visit(a call to new with no receiver inside a generic or builtin class method (hosted call.cr: prepare_call_args, the metaclass owner)) (hosted codegen.cr) is not ported yet example=Array(IyiWaiter | Nil).class#new
table: compile_native lowering 2 owner=lowering core reason=lower: visit(assign Proc(NoReturn) to Proc(Nil) (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=IyiThread.class#new
table: compile_native lowering 2 owner=lowering core reason=lower: visit(assign Nil to (Proc(Hash(UInt64, Hash(String, Bool)), UInt64, Hash(String, Bool)) | Nil) (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=Hash(UInt64, Hash(String, Bool)).class#new
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the call to initialize (hosted call.cr: visit(Call)) example=Compiler::Ir::Parser#parse
table: compile_native lowering 2 owner=lowering core reason=lower: visit(assign Nil to (Proc(Hash(String, Compiler::Ir::Values::Value), String, Compiler::Ir::Values::Value) | Nil) (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=Hash(String, Compiler::Ir::Values::Value).class#new
table: compile_native lowering 2 owner=lowering core reason=lower: visit(assign Nil to (Proc(Hash(String, Compiler::Ir::Inst::Block), String, Compiler::Ir::Inst::Block) | Nil) (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=Hash(String, Compiler::Ir::Inst::Block).class#new
table: compile_native lowering 2 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of << (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Compiler::Native::Rt::StartWasm32Text#start_wasm32_ir
table: compile_native lowering 1 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of initialize (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Atomic(UInt64).class#new
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of swap (hosted codegen_fun: return type) example=Atomic(UInt64)#swap
table: compile_native lowering 1 owner=lowering core reason=lower: visit(a call to != inherited from a superclass of IyiFiberState (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=IyiRoots.class#each_fiber_root
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of == (hosted codegen_fun: return type) example=IyiFiberState#==
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of thread_warm (hosted codegen_fun: return type) example=IyiHeap.class#thread_warm
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of reopen_in (hosted codegen_fun: return type) example=IyiHeap.class#reopen_in
table: compile_native lowering 1 owner=unassigned reason=BUG: variable block is read before it is assigned (hosted codegen.cr: visit(Var)) example=IyiThread.class#start
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of make_lot (hosted codegen_fun: return type) example=IyiScheduler.class#make_lot
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of lot_lock (hosted codegen_fun: return type) example=IyiScheduler.class#lot_lock
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to get (hosted call.cr: visit(Call)) example=IyiChanLock.class#lock
table: compile_native lowering 1 owner=lowering core reason=BUG: create_llvm_type for T is not ported yet (hosted llvm_typer.cr) example=Array#initialize
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of run (hosted codegen_fun: return type) example=Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to < (hosted call.cr: visit(Call)) example=Program.class#args
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of read (hosted codegen_fun: return type) example=File.class#read
table: compile_native lowering 1 owner=lowering core reason=lower: visit(a class method parse inherited from a superclass of Compiler::Tools::CompileNative::CompileNative (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Compiler::Tools::CompileNative::CompileNative.class#module_of
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of initialize (hosted codegen_fun: return type) example=Compiler::Ir::Parser::IrParser#initialize
table: compile_native lowering 1 owner=unassigned reason=error[types]: an extension must widen an integer example=Char#bytesize
table: compile_native lowering 1 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of index (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Compiler::Ir::Module::Module#file_index
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of slot_for (hosted codegen_fun: return type) example=Hash(String, Int64)#slot_for
table: compile_native lowering 1 owner=lowering core reason=lower: visit(upcast NoReturn to Int64 (hosted cast.cr: upcast_distinct)) (hosted codegen.cr) is not ported yet example=Pointer(Int64)#[]=
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of new (hosted codegen_fun: return type) example=Std::Slice::Slice(UInt8).class#new
table: compile_native lowering 1 owner=lowering core reason=lower: visit(a call to __iyi_say with no receiver inside a generic or builtin class method (hosted call.cr: prepare_call_args, the metaclass owner)) (hosted codegen.cr) is not ported yet example=Std::Slice::Slice(UInt8).class#raise
table: compile_native lowering 1 owner=lowering core reason=lower: visit(a call to __iyi_write with no receiver inside a generic or builtin class method (hosted call.cr: prepare_call_args, the metaclass owner)) (hosted codegen.cr) is not ported yet example=Std::Slice::Slice(UInt8).class#__iyi_say
```
<!-- table:end -->
