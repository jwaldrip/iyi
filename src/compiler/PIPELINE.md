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

## What the table counts

- `defs-reached`: the distinct defs the body typer started on. A call instantiates a clone of its def, and the
  clones are counted once per def.
- `defs-typed-clean`: the reached defs with no refusal node under them.
- `root-refusals`: refusals on top-level code, outside any def.
- `refusal-sites`: distinct (node, reason) pairs. A node refused once per instantiation counts once.
- One row per refusal reason, largest count first: its count, the slice that owns it (`owner`, from
  `typed_owner` in `lower/program.iyi`), the reason's first line, and one example with its file and line
  and the def that holds it. `owner=unassigned` means no rule names the reason yet and the rule belongs in
  `typed_owner`.

Lowering per def ("defs lowered with no refusal") runs `lower_def_probe` (lower/lower.iyi) on each reached instance,
alone, into one module. Its refusals are ranked as the body rows are, with the lowering's owner. A def is lowered clean
when each of its instances lowers with no refusal. A lowering refusal names its def, not a node, since the
lowering carries no location yet.

## Gate

`bench/selfhost_pipeline_exercise.sh` runs the tool with `--keep-going` on the three prelude roots and the
compiler's own tools, regenerates the block below (`SELFHOST_PIPELINE_RAISE=1`), fails when it is stale, and
holds `defs-reached`, `defs-typed-clean` and `defs-lowered-clean` per root against `bench/selfhost_pipeline_table.floor`.
All three may only rise, and the gate fails when one falls below its floor. The variation the earlier floors allowed for (identical builds gave reached 5218/5219/5218) came from the typer's node keys and is gone: `NodeMap` holds the nodes it is keyed by (integration `5e633ea4d`), and three runs of one build give byte-identical output. The phase floor is `bench/selfhost_pipeline.floor`.

## Headline: coverage against the hosted compiler

The number that says how far stage 1 is: which functions the hosted compiler emits for a root, and how many of them the
port lowers clean under the same name. The hosted list is the `define` names of `./bin/iyi build --no-debug --emit llvm-ir
-o <dir>/hosted <root>`. The port's list is `<output>.names`, written by the tool under `--keep-going` (one name per clean
instance). `bench/pipeline_coverage.py <hosted.ll> <output>.names <root>` prints the line and the first missing names.

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
table: hello defs-reached=601 defs-typed-clean=375 root-refusals=12 refusal-sites=495
table: hello refusal 56 owner=bodies reason=undefined local variable or method 'previous_def' for Atomic(Int64) example=src/iyi/./chaos_points.iyi:26 in Atomic(Int64)#add
table: hello refusal 39 owner=bodies reason=undefined local variable or method 'previous_def' for Atomic(UInt64) example=src/iyi/./chaos_points.iyi:26 in Atomic(UInt64)#add
table: hello refusal 32 owner=bodies reason=pointerof of callstack is not ported yet: only a local variable is example=src/iyi/prelude.iyi:3 in Int64#raise
table: hello refusal 27 owner=calls reason=expected argument #1 to 'IyiAtomic.store' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/./concurrency.iyi:1475 in IyiSchedLock.class#unlock
table: hello refusal 14 owner=bodies reason=the value of 'other' cannot be typed example=src/iyi/./chaos.iyi:374 in IyiChaos.class#outranked?
table: hello refusal 14 owner=calls reason=undefined method 'next_run=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2310 in IyiScheduler.class#take_mail
table: hello refusal 11 owner=unassigned reason=unsupported node: Asm example=src/iyi/./concurrency.iyi:2 in top level
table: hello refusal 11 owner=bodies reason=the value of 'buffer' cannot be typed example=src/iyi/./string.iyi:38 in String.class#new
table: hello refusal 10 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:1737 in IyiScheduler.class#state_id
table: hello refusal 10 owner=bodies reason=the value of '__temp_1' cannot be typed example=no location in IyiChaos.class#outranked?
table: hello refusal 9 owner=bodies reason=the value of 'memory' cannot be typed example=src/iyi/./string.iyi:37 in String.class#new
table: hello refusal 8 owner=calls reason=undefined method 'next_run' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./chaos.iyi:375 in IyiChaos.class#outranked?
table: hello refusal 8 owner=bodies reason=the value of 'state' cannot be typed example=src/iyi/./chaos.iyi:228 in IyiChaos.class#draw
table: hello refusal 8 owner=unassigned reason=wrong number of arguments for 'Proc#call' (given 2, expected 1) example=src/iyi/prelude.iyi:3 in Int64#raise
table: hello refusal 8 owner=calls reason=expected argument #1 to 'IyiFiber#state=' to be IyiFiberState, not Int32 example=src/iyi/./concurrency.iyi:5047 in IyiScheduler.class#panic_current
table: hello refusal 8 owner=calls reason=expected argument #1 to 'IyiScheduler.enqueue' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:3998 in IyiScheduler.class#deadlock_found
table: hello refusal 8 owner=bodies reason=the value of 'size' cannot be typed example=src/iyi/./concurrency.iyi:5531 in IyiWorkers.class#steal_unstarted
table: hello refusal 6 owner=declarations reason=undefined constant DEADLOCK example=src/iyi/./concurrency.iyi:4011 in IyiScheduler.class#deadlock
table: hello refusal 6 owner=bodies reason=the value of 'following' cannot be typed example=src/iyi/./concurrency.iyi:2318 in IyiScheduler.class#take_mail
table: hello refusal 6 owner=declarations reason=undefined constant RING example=src/iyi/./concurrency.iyi:1407 in IyiSchedulerState#slot
table: hello refusal 6 owner=bodies reason=undefined local variable or method 'block' for IyiThread.class example=src/iyi/thread.iyi:317 in IyiThread.class#start
table: hello refusal 6 owner=declarations reason=undefined constant HEADER_SIZE example=src/iyi/./string.iyi:36 in String.class#new
table: hello refusal 5 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3990 in IyiScheduler.class#deadlock_found
table: hello refusal 5 owner=calls reason=undefined method 'state' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3997 in IyiScheduler.class#deadlock_found
table: hello refusal 5 owner=calls reason=wrong number of arguments for 'String.interpolation' (given 5, expected 1) example=no location in Array(IyiFiber | Nil)#[]
table: hello refusal 5 owner=bodies reason=the value of 'victim' cannot be typed example=src/iyi/./concurrency.iyi:5534 in IyiWorkers.class#steal_unstarted
table: hello refusal 5 owner=declarations reason=undefined constant HELD example=src/iyi/./concurrency.iyi:1561 in IyiChanLock.class#acquire
table: hello refusal 4 owner=macros reason=macro control expansion (macros engine) example=src/iyi/./concurrency.iyi:1557 in top level
table: hello refusal 4 owner=declarations reason=undefined constant GOLDEN example=src/iyi/./chaos.iyi:227 in IyiChaos.class#draw
table: hello refusal 4 owner=calls reason=undefined method 'size' for Nil (compile-time type is (Array | Nil)) example=src/iyi/./concurrency.iyi:5529 in IyiWorkers.class#steal_unstarted
table: hello refusal 4 owner=unassigned reason=type mismatch for return type: expected <unresolved T>, got T example=src/iyi/./concurrency.iyi:5533 in IyiWorkers.class#steal_unstarted
table: hello refusal 4 owner=bodies reason=the value of 'fiber' cannot be typed example=src/iyi/./concurrency.iyi:5536 in IyiWorkers.class#steal_unstarted
table: hello refusal 4 owner=calls reason=expected argument #1 to 'IyiScheduler.switch_to' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:2595 in IyiScheduler.class#reschedule
table: hello refusal 4 owner=bodies reason=the value of 'rest' cannot be typed example=src/iyi/./concurrency.iyi:3611 in IyiScheduler.class#wake_joiners
table: hello refusal 3 owner=declarations reason=undefined constant SIMULATED example=src/iyi/./chaos.iyi:312 in IyiChaos.class#point
table: hello refusal 3 owner=declarations reason=undefined constant EVENTS example=src/iyi/./concurrency.iyi:4982 in IyiScheduler.class#events_buffer
table: hello refusal 3 owner=bodies reason=the value of 'held' cannot be typed example=src/iyi/./concurrency.iyi:5659 in IyiWorkers.class#handed_on?
table: hello refusal 2 owner=bodies reason=the value of 'unit' cannot be typed example=src/iyi/./chaos.iyi:265 in IyiChaos.class#unit_of
table: hello refusal 2 owner=calls reason=undefined method 'next_child' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:7246 in IyiGroup#cancel_children_locked
table: hello refusal 2 owner=calls reason=undefined method 'deadline' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4026 in IyiScheduler.class#wait_for_events
table: hello refusal 2 owner=bodies reason=the value of 'task' cannot be typed example=src/iyi/./concurrency.iyi:3987 in IyiScheduler.class#deadlock_found
table: hello refusal 2 owner=bodies reason=the value of 'group' cannot be typed example=src/iyi/./concurrency.iyi:3989 in IyiScheduler.class#deadlock_found
table: hello refusal 2 owner=calls reason=undefined method 'claim_any' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3998 in IyiScheduler.class#deadlock_found
table: hello refusal 2 owner=unassigned reason=can't deduce argument type example=src/iyi/./concurrency.iyi:17 in IyiScheduler.class#wait_for_events
table: hello refusal 2 owner=calls reason=expected argument #2 to 'IyiScheduler.io_remove' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:4907 in IyiScheduler.class#io_take
table: hello refusal 2 owner=calls reason=undefined method 'unit' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2326 in IyiScheduler.class#take_mail
table: hello refusal 2 owner=bodies reason=the value of 'waits_here' cannot be typed example=src/iyi/./concurrency.iyi:2327 in IyiScheduler.class#take_mail
table: hello refusal 2 owner=calls reason=expected argument #1 to 'IyiScheduler.ready' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:7160 in IyiGroup#child_finished
table: hello refusal 2 owner=calls reason=undefined method 'next_joiner' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3609 in IyiScheduler.class#wake_joiners
table: hello refusal 2 owner=calls reason=undefined method 'next_joiner=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3610 in IyiScheduler.class#wake_joiners
table: hello refusal 2 owner=declarations reason=undefined constant YIELDED example=src/iyi/./concurrency.iyi:980 in IyiUnit#hand_to_yielded
table: hello refusal 2 owner=declarations reason=undefined constant SPINNER example=src/iyi/./concurrency.iyi:1576 in IyiChanLock.class#contend
table: hello refusal 2 owner=declarations reason=undefined constant CACHE_REQUEST example=src/iyi/prelude.iyi:730 in IyiHeap.class#stop_requested?
table: hello refusal 2 owner=unassigned reason=unsupported node: AsmOperand example=no location in IyiThread.class#stop_here
table: hello refusal 2 owner=unassigned reason=wrong number of arguments for 'Proc(Nil)#call' (given 0, expected 1) example=src/iyi/./concurrency.iyi:2874 in IyiScheduler.class#run_spawned_fiber
table: hello refusal 2 owner=calls reason=expected argument #1 to 'IyiAtomic.load' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/prelude.iyi:10779 in top level
table: hello refusal 2 owner=calls reason=wrong number of arguments for 'String.interpolation' (given 3, expected 1) example=no location in Samples::Hello::User#greet
table: hello refusal 2 owner=bodies reason=the value of '__temp_3' cannot be typed example=no location in top level
table: hello refusal 2 owner=bodies reason=the value of '__temp_4' cannot be typed example=no location in top level
table: hello refusal 1 owner=unassigned reason=type mismatch for return type: expected IyiSchedulerState, got (IyiSchedulerState | Nil) example=src/iyi/./concurrency.iyi:1793 in IyiScheduler.class#state
table: hello refusal 1 owner=calls reason=undefined method 'chaos_unit' for IyiFiber example=src/iyi/./chaos.iyi:264 in IyiChaos.class#unit_of
table: hello refusal 1 owner=declarations reason=undefined constant HIGH example=src/iyi/./chaos.iyi:267 in IyiChaos.class#unit_of
table: hello refusal 1 owner=calls reason=undefined method 'chaos_unit=' for IyiFiber example=src/iyi/./chaos.iyi:269 in IyiChaos.class#unit_of
table: hello refusal 1 owner=declarations reason=undefined constant LOW example=src/iyi/./chaos.iyi:348 in IyiChaos.class#step
table: hello refusal 1 owner=declarations reason=undefined constant SPIN_STEPS example=src/iyi/./chaos.iyi:350 in IyiChaos.class#step
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiChaos.unit_of' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./chaos.iyi:373 in IyiChaos.class#outranked?
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.cancel' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:7245 in IyiGroup#cancel_children_locked
table: hello refusal 1 owner=declarations reason=undefined constant POLL_EVERY example=src/iyi/./concurrency.iyi:2591 in IyiScheduler.class#reschedule
table: hello refusal 1 owner=declarations reason=undefined constant POLL_IO_NS example=src/iyi/./concurrency.iyi:2761 in IyiScheduler.class#poll_now
table: hello refusal 1 owner=calls reason=undefined method 'awaited' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3986 in IyiScheduler.class#deadlock_found
table: hello refusal 1 owner=calls reason=undefined method 'joining' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3988 in IyiScheduler.class#deadlock_found
table: hello refusal 1 owner=calls reason=undefined method 'deadlocked=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3994 in IyiScheduler.class#deadlock_found
table: hello refusal 1 owner=bodies reason=the value of 'head_deadline' cannot be typed example=src/iyi/./concurrency.iyi:4047 in IyiScheduler.class#wait_for_events
table: hello refusal 1 owner=bodies reason=the value of 'gap' cannot be typed example=src/iyi/./concurrency.iyi:4048 in IyiScheduler.class#wait_for_events
table: hello refusal 1 owner=calls reason=undefined method 'size' for Nil (compile-time type is (Array(IyiFiber | Nil) | Nil)) example=src/iyi/./concurrency.iyi:3423 in IyiScheduler.class#io_slot
table: hello refusal 1 owner=calls reason=undefined method '[]' for Nil (compile-time type is (Array(IyiFiber | Nil) | Nil)) example=src/iyi/./concurrency.iyi:3423 in IyiScheduler.class#io_slot
table: hello refusal 1 owner=calls reason=expected argument #2 to 'IyiScheduler.heap_remove' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:4661 in IyiScheduler.class#wake_expired_sleepers
table: hello refusal 1 owner=calls reason=undefined method 'io_timed' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4662 in IyiScheduler.class#wake_expired_sleepers
table: hello refusal 1 owner=calls reason=undefined method 'io_timed=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4664 in IyiScheduler.class#wake_expired_sleepers
table: hello refusal 1 owner=calls reason=undefined method 'timed_out=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4665 in IyiScheduler.class#wake_expired_sleepers
table: hello refusal 1 owner=calls reason=undefined method 'next_cancel' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2323 in IyiScheduler.class#take_mail
table: hello refusal 1 owner=calls reason=undefined method 'next_cancel=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2324 in IyiScheduler.class#take_mail
table: hello refusal 1 owner=calls reason=undefined method 'cancel_posted=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2325 in IyiScheduler.class#take_mail
table: hello refusal 1 owner=calls reason=undefined method 'listed_on' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2326 in IyiScheduler.class#take_mail
table: hello refusal 1 owner=calls reason=undefined method 'waiting_out' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2327 in IyiScheduler.class#take_mail
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.cancel_wait' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:2328 in IyiScheduler.class#take_mail
table: hello refusal 1 owner=calls reason=undefined method 'each' for Nil (compile-time type is (Array(Int32) | Nil)) example=src/iyi/./concurrency.iyi:2335 in IyiScheduler.class#take_mail
table: hello refusal 1 owner=declarations reason=undefined constant PREEMPTED_TURN example=src/iyi/./concurrency.iyi:7 in IyiScheduler.class#worker_next
table: hello refusal 1 owner=calls reason=undefined method 'home' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:5514 in IyiWorkers.class#take_queued
table: hello refusal 1 owner=calls reason=undefined method 'home=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:5520 in IyiWorkers.class#take_queued
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.wake_completed' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/concurrency.iyi:71 in IyiScheduler.class#take_held
table: hello refusal 1 owner=calls reason=expected argument #2 to 'IyiScheduler.take_unit' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:19 in IyiScheduler.class#worker_next
table: hello refusal 1 owner=calls reason=undefined method 'give' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:2721 in IyiScheduler.class#release_unit
table: hello refusal 1 owner=calls reason=undefined method 'waiting?' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:2722 in IyiScheduler.class#release_unit
table: hello refusal 1 owner=calls reason=expected argument #2 to 'IyiScheduler.drain_unit' to be IyiUnit, not (IyiUnit | Nil) example=src/iyi/./concurrency.iyi:2724 in IyiScheduler.class#release_unit
table: hello refusal 1 owner=calls reason=undefined method 'quiet' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2500 in IyiScheduler.class#all_quiet?
table: hello refusal 1 owner=calls reason=undefined method 'idle' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: hello refusal 1 owner=bodies reason=the value of 'quiet' cannot be typed example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: hello refusal 1 owner=bodies reason=the value of '__temp_2' cannot be typed example=no location in IyiScheduler.class#all_quiet?
table: hello refusal 1 owner=calls reason=undefined method 'mail?' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: hello refusal 1 owner=calls reason=undefined method 'next_state' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2506 in IyiScheduler.class#all_quiet?
table: hello refusal 1 owner=calls reason=undefined method 'panicked' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:7213 in IyiGroup#join
table: hello refusal 1 owner=calls reason=undefined method 'panic_delivered' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:7213 in IyiGroup#join
table: hello refusal 1 owner=calls reason=undefined method 'panic_delivered=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:7214 in IyiGroup#join
table: hello refusal 1 owner=calls reason=undefined method 'panic_message' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:7220 in IyiGroup#join
table: hello refusal 1 owner=calls reason=undefined method 'join' for Nil (compile-time type is (IyiGroup | Nil)) example=src/iyi/./concurrency.iyi:5060 in IyiScheduler.class#panic_current
table: hello refusal 1 owner=calls reason=undefined method 'next_node' for Nil (compile-time type is (IyiDeferNode | Nil)) example=src/iyi/./concurrency.iyi:5065 in IyiScheduler.class#panic_current
table: hello refusal 1 owner=unassigned reason=wrong number of arguments for 'Proc#call' (given 0, expected 1) example=src/iyi/prelude.iyi:10849 in IyiDeferNode#run
table: hello refusal 1 owner=calls reason=undefined method 'run' for Nil (compile-time type is (IyiDeferNode | Nil)) example=src/iyi/./concurrency.iyi:5066 in IyiScheduler.class#panic_current
table: hello refusal 1 owner=calls reason=undefined method 'child_panicked' for Nil (compile-time type is (IyiGroup | Nil)) example=src/iyi/./concurrency.iyi:5078 in IyiScheduler.class#panic_current
table: hello refusal 1 owner=calls reason=undefined method 'awaited=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3620 in IyiScheduler.class#wake_joiners
table: hello refusal 1 owner=declarations reason=undefined constant FNV_PRIME example=src/iyi/./chaos.iyi:254 in IyiChaos.class#fold
table: hello refusal 1 owner=calls reason=undefined method 'chaos_held=' for IyiFiber example=src/iyi/./chaos.iyi:357 in IyiChaos.class#step
table: hello refusal 1 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:5659 in IyiWorkers.class#handed_on?
table: hello refusal 1 owner=declarations reason=undefined constant THREADS example=src/iyi/./chaos.iyi:314 in IyiChaos.class#point
table: hello refusal 1 owner=calls reason=undefined method 'hand_to_yielded' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:5 in IyiWorkers.class#give_up
table: hello refusal 1 owner=calls reason=undefined method 'take_yielded' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:9 in IyiWorkers.class#give_up
table: hello refusal 1 owner=declarations reason=undefined constant UNMARKED example=src/iyi/./concurrency.iyi:1572 in IyiChanLock.class#contend
table: hello refusal 1 owner=bodies reason=the value of 'taken' cannot be typed example=src/iyi/./concurrency.iyi:1573 in IyiChanLock.class#contend
table: hello refusal 1 owner=calls reason=expected argument #2 to 'IyiAtomic.rmw' to be Pointer(<unresolved T>), not Pointer(UInt64) example=src/iyi/prelude.iyi:104 in IyiRuntimeLock.class#lock
table: hello refusal 1 owner=declarations reason=undefined constant YIELD_AFTER example=src/iyi/thread.iyi:854 in IyiThread.class#lock_turn
table: hello refusal 1 owner=calls reason=undefined method '!=' for NoReturn example=src/iyi/prelude.iyi:1 in IyiRuntimeLock.class#lock
table: hello refusal 1 owner=unassigned reason=type mismatch for return type: expected IyiFiber, got (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:1829 in IyiScheduler.class#current
table: hello refusal 1 owner=unassigned reason=instance variable '@state' of IyiFiber must be IyiFiberState, not (IyiFiberState | Int32) example=src/iyi/./concurrency.iyi:635 in IyiFiber#initialize
table: hello refusal 1 owner=calls reason=undefined method 'prev_fiber=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1863 in IyiScheduler.class#register
table: hello refusal 1 owner=calls reason=undefined method 'on_cpu=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1917 in IyiScheduler.class#landed
table: hello refusal 1 owner=declarations reason=undefined constant STACK_BYTES example=src/iyi/./concurrency.iyi:926 in IyiFiber#release_stack
table: hello refusal 1 owner=calls reason=undefined method 'release_stack' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1932 in IyiScheduler.class#reap_dying
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.unregister' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:1933 in IyiScheduler.class#reap_dying
table: hello refusal 1 owner=calls reason=expected argument #1 to 'Pointer#+' to be Int64, not Int32 example=src/iyi/./io.iyi:300 in IyiIO#write
table: hello refusal 1 owner=calls reason=expected argument #1 to 'Pointer#copy_from' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/./io.iyi:313 in IyiIO#write
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.load' to be Pointer(<unresolved T>), not Pointer(UInt64) example=src/iyi/prelude.iyi:3 in IyiOnce.class#run
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.cmpxchg' to be Pointer(<unresolved T>), not Pointer(UInt64) example=src/iyi/prelude.iyi:4 in IyiOnce.class#run
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.store' to be Pointer(<unresolved T>), not Pointer(UInt64) example=src/iyi/prelude.iyi:3 in IyiOnce.class#run
table: hello refusal 1 owner=calls reason=wrong number of arguments for 'String.interpolation' (given 2, expected 1) example=no location in Samples::Hello::Robot#greet
table: hello refusal 1 owner=bodies reason=the value of 'crowd' cannot be typed example=samples/iyi/hello.iyi:117 in top level
table: hello refusal 1 owner=calls reason=expected argument #1 to 'Samples::Hello#announce' to be <unresolved T>, not Samples::Hello::Robot example=samples/iyi/hello.iyi:119 in top level
table: hello defs-lowered-clean=194 lowering-refusal-sites=323
table: hello lowering 27 owner=bodies reason=BUG: the analysed program has no type for the body of add (hosted codegen_fun: return type) example=Atomic(UInt64)#add
table: hello lowering 26 owner=bodies reason=BUG: the analysed program has no type for the body of unlock (hosted codegen_fun: return type) example=IyiSchedLock.class#unlock
table: hello lowering 24 owner=bodies reason=BUG: the analysed program has no type for the body of get (hosted codegen_fun: return type) example=Atomic(UInt64)#get
table: hello lowering 15 owner=bodies reason=BUG: the analysed program has no type for the body of sub (hosted codegen_fun: return type) example=Atomic(Int64)#sub
table: hello lowering 14 owner=bodies reason=BUG: the analysed program has no type for the body of compare_and_set (hosted codegen_fun: return type) example=Atomic(UInt64)#compare_and_set
table: hello lowering 13 owner=bodies reason=BUG: the analysed program has no type for the body of set (hosted codegen_fun: return type) example=Atomic(UInt64)#set
table: hello lowering 12 owner=lowering core reason=lower: visit(Cast) (hosted codegen.cr) is not ported yet example=UInt64#__iyi_say
table: hello lowering 11 owner=lowering core reason=lower: visit(UninitializedVar) (hosted codegen.cr) is not ported yet example=UInt64#raise
table: hello lowering 10 owner=bodies reason=lower: visit(pointerof of a ClassVar (hosted codegen.cr: visit(PointerOf), only a local variable is ported)) (hosted codegen.cr) is not ported yet example=IyiSchedLock.class#word
table: hello lowering 9 owner=bodies reason=BUG: the analysed program has no type for the body of state_id (hosted codegen_fun: return type) example=IyiScheduler.class#state_id
table: hello lowering 9 owner=unassigned reason=lower: is_a? of (IyiFiber | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiChaos.class#outranked?
table: hello lowering 6 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of set (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#free_lists
table: hello lowering 6 owner=bodies reason=BUG: the analysed program has no type for the body of start (hosted codegen_fun: return type) example=IyiThread.class#start
table: hello lowering 5 owner=lowering core reason=lower: visit(pointer_get of Atomic(UInt64) (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=IyiChanLock.class#acquire
table: hello lowering 5 owner=lowering core reason=BUG: create_llvm_type for T is not ported yet (hosted llvm_typer.cr) example=Array#[]
table: hello lowering 4 owner=lowering core reason=lower: visit(MagicConstant) (hosted codegen.cr) is not ported yet example=UInt64#%
table: hello lowering 4 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of compare_and_set (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiFiber#claim
table: hello lowering 4 owner=bodies reason=BUG: the analysed program has no type for the body of slot (hosted codegen_fun: return type) example=IyiSchedulerState#slot
table: hello lowering 4 owner=unassigned reason=a function or global named ~STDOUT:const_read already exists example=IyiScheduler.class#__iyi_flush_std
table: hello lowering 3 owner=unassigned reason=a function or global named IyiScheduler::shared already exists example=IyiScheduler.class#shared?
table: hello lowering 3 owner=lowering core reason=lower: visit(Assign to a parameter (hosted fun.cr, create_local_copy_of_arg)) (hosted codegen.cr) is not ported yet example=String#includes?
table: hello lowering 3 owner=calls reason=BUG: the call to st has no target def (hosted call.cr: visit(Call)) example=IyiScheduler.class#poll_now
table: hello lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of spin_pause (hosted codegen_fun: return type) example=IyiThread.class#spin_pause
table: hello lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of wake_one (hosted codegen_fun: return type) example=IyiWorkers.class#wake_one
table: hello lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of greet (hosted codegen_fun: return type) example=Samples::Hello::User#greet
table: hello lowering 2 owner=lowering core reason=lower: visit(a class method call on a receiver that is not a constant path (hosted call.cr: prepare_call_args, Path)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#current
table: hello lowering 2 owner=bodies reason=BUG: (IyiSchedulerState | Nil) has no type id (not reachable from Object) example=IyiScheduler.class#state
table: hello lowering 2 owner=lowering core reason=lower: visit(allocate of class IyiSchedulerState: the :headed byte is the program-wide census (lower/headed.iyi, NEEDS.md rows 26-27), not decided) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#first_state_here
table: hello lowering 2 owner=unassigned reason=lower: a bare return from a function that returns a value (hosted codegen_return, the nil upcast) example=IyiSchedLock.class#lock
table: hello lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of draw (hosted codegen_fun: return type) example=IyiChaos.class#draw
table: hello lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of deadlock (hosted codegen_fun: return type) example=IyiScheduler.class#deadlock
table: hello lowering 2 owner=lowering core reason=lower: visit(binary == on Int64 and Int32 (mixed operands, hosted codegen_binary_extend_int)) (hosted codegen.cr) is not ported yet example=Int64#//
table: hello lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of wake_io (hosted codegen_fun: return type) example=IyiScheduler.class#wake_io
table: hello lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of set_slot (hosted codegen_fun: return type) example=IyiSchedulerState#set_slot
table: hello lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of run (hosted codegen_fun: return type) example=IyiDeferNode#run
table: hello lowering 2 owner=lowering core reason=lower: visit(primitive object_id (hosted codegen_primitive, primitives.cr)) (hosted codegen.cr) is not ported yet example=IyiGroup#child_panicked
table: hello lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of swap (hosted codegen_fun: return type) example=Atomic(UInt64)#swap
table: hello lowering 2 owner=unassigned reason=lower: class variable @@line has a literal initialiser that is not an integer, Bool or Char (hosted class_var.cr: initialize_class_var) example=IyiThread.class#stop_here
table: hello lowering 2 owner=lowering core reason=lower: visit(allocate of class IyiFiber: the :headed byte is the program-wide census (lower/headed.iyi, NEEDS.md rows 26-27), not decided) (hosted codegen.cr) is not ported yet example=IyiFiber.class#main
table: hello lowering 2 owner=lowering core reason=lower: visit(a call to a def with a &block parameter (hosted call.cr: codegen_call_with_block_as_fun_literal, closures)) (hosted codegen.cr) is not ported yet example=IyiTestCases.class#verdict
table: hello lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(IyiFiber | Nil) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiScheduler.class#run_spawned_fiber
table: hello lowering 1 owner=lowering core reason=lower: visit(a class method call on Atomic(UInt64).class (hosted call.cr: prepare_call_args, a generic or builtin metaclass)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#initialize
table: hello lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Atomic(UInt64) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Atomic(UInt64).class#new
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of initialize (hosted codegen_fun: return type) example=Atomic(UInt64)#initialize
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to == (hosted call.cr: visit(Call)) example=IyiChaos.class#at_atomic
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to state (hosted call.cr: visit(Call)) example=IyiChaos.class#step
table: hello lowering 1 owner=unassigned reason=a function or global named IyiScheduler::state already exists example=IyiSchedLock.class#held_here?
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to chaos_unit (hosted call.cr: visit(Call)) example=IyiChaos.class#unit_of
table: hello lowering 1 owner=bodies reason=lower: visit(pointerof of a InstanceVar (hosted codegen.cr: visit(PointerOf), only a local variable is ported)) (hosted codegen.cr) is not ported yet example=String#to_unsafe
table: hello lowering 1 owner=unassigned reason=lower: class variable @@resolver is not an integer, a float or a nilable reference: the struct and the non-nilable pointer initialisers are not ported yet (hosted class_var.cr: initialize_class_var) example=IyiPanic.class#resolver
table: hello lowering 1 owner=lowering core reason=lower: visit(a call to held_here? with no receiver inside a class method (hosted call.cr: prepare_call_args, the metaclass owner)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#panic_current
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to store (hosted call.cr: visit(Call)) example=IyiSchedLock.class#release_held
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of join (hosted codegen_fun: return type) example=IyiGroup#join
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for a branch (hosted codegen.cr: visit(If)) example=IyiScheduler.class#reschedule
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to at_atomic (hosted call.cr: visit(Call)) example=IyiSchedulerState#take_lists
table: hello lowering 1 owner=lowering core reason=BUG: create_llvm_type for <unresolved T> is not ported yet (hosted llvm_typer.cr) example=Tuple(<unresolved T>, Bool)#[]
table: hello lowering 1 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of add (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiFiber#claim_any
table: hello lowering 1 owner=lowering core reason=lower: visit(binary > on Int64 and Int32 (mixed operands, hosted codegen_binary_extend_int)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#pollfd
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to malloc (hosted call.cr: visit(Call)) example=IyiScheduler.class#events_buffer
table: hello lowering 1 owner=calls reason=BUG: the call to entry has no target def (hosted call.cr: visit(Call)) example=IyiScheduler.class#event_ready
table: hello lowering 1 owner=unassigned reason=lower: is_a? of (Array(IyiFiber | Nil) | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiScheduler.class#io_take
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of io_slot (hosted codegen_fun: return type) example=IyiScheduler.class#io_slot
table: hello lowering 1 owner=unassigned reason=lower: instance variable @size of Array(IyiFiber | Nil): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(IyiFiber | Nil)#size
table: hello lowering 1 owner=lowering core reason=lower: visit(pointer_get of (IyiFiber | Nil) (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=Pointer((IyiFiber | Nil))#[]
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of end_idle (hosted codegen_fun: return type) example=IyiScheduler.class#end_idle
table: hello lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Atomic(Int64) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiWorkers.class#word
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to shared? (hosted call.cr: visit(Call)) example=IyiScheduler.class#take_mail
table: hello lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(Int32) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiSchedulerState#closed_fds
table: hello lowering 1 owner=unassigned reason=lower: instance variable @size of Array(Int32): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(Int32)#each
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to value (hosted call.cr: visit(Call)) example=IyiWorkers.class#pop
table: hello lowering 1 owner=unassigned reason=lower: is_a? of (Array | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiWorkers.class#steal_unstarted
table: hello lowering 1 owner=lowering core reason=BUG: llvm_struct_type of Array is not ported yet (hosted create_llvm_struct_type) example=Array#size
table: hello lowering 1 owner=lowering core reason=lower: visit(a call with default arguments or a splat (hosted call.cr)) (hosted codegen.cr) is not ported yet example=IyiWorkers.class#__iyi_flush_std
table: hello lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiIO: the :headed byte is the program-wide census (lower/headed.iyi, NEEDS.md rows 26-27), not decided) (hosted codegen.cr) is not ported yet example=IyiIO.class#new
table: hello lowering 1 owner=lowering core reason=lower: visit(Pointer#malloc with a count that is not the size type (hosted generic_array_malloc: builder.mul of the size and the count)) (hosted codegen.cr) is not ported yet example=IyiIO#initialize
table: hello lowering 1 owner=calls reason=BUG: the call to target_fd has no target def (hosted call.cr: visit(Call)) example=IyiIO#low_level_write
table: hello lowering 1 owner=lowering core reason=lower: taken is declared (IyiFiber | Nil) and assigned Nil: the hosted upcast is not ported yet example=IyiScheduler.class#take_held
table: hello lowering 1 owner=lowering core reason=lower: visit(a call to word with no receiver inside a class method (hosted call.cr: prepare_call_args, the metaclass owner)) (hosted codegen.cr) is not ported yet example=IyiWorkers.class#runtime_lock_free?
table: hello lowering 1 owner=unassigned reason=lower: is_a? of (IyiUnit | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiScheduler.class#release_unit
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to ensure_doorbell (hosted call.cr: visit(Call)) example=IyiScheduler.class#wait_shared
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of child_finished (hosted codegen_fun: return type) example=IyiGroup#child_finished
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to memory (hosted call.cr: visit(Call)) example=String.class#new
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of fold (hosted codegen_fun: return type) example=IyiChaos.class#fold
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to state= (hosted call.cr: visit(Call)) example=IyiScheduler.class#enqueue
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of thread_point (hosted codegen_fun: return type) example=IyiChaos.class#thread_point
table: hello lowering 1 owner=calls reason=BUG: the call to fiber has no target def (hosted call.cr: visit(Call)) example=IyiWorkers.class#chaos_give_up
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of give_up (hosted codegen_fun: return type) example=IyiWorkers.class#give_up
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of hand_to_yielded (hosted codegen_fun: return type) example=IyiUnit#hand_to_yielded
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of take_yielded (hosted codegen_fun: return type) example=IyiUnit#take_yielded
table: hello lowering 1 owner=lowering core reason=lower: visit(binary != on Int64 and Int32 (mixed operands, hosted codegen_binary_extend_int)) (hosted codegen.cr) is not ported yet example=IyiThread.class#lock_turn
table: hello lowering 1 owner=unassigned reason=lower: class variable @@control has a literal initialiser that is not an integer, Bool or Char (hosted class_var.cr: initialize_class_var) example=IyiThread.class#control
table: hello lowering 1 owner=unassigned reason=lower: class variable @@cache has a literal initialiser that is not an integer, Bool or Char (hosted class_var.cr: initialize_class_var) example=IyiThread.class#park_if_requested
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of stop_requested? (hosted codegen_fun: return type) example=IyiHeap.class#stop_requested?
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of clear_request (hosted codegen_fun: return type) example=IyiHeap.class#clear_request
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of park (hosted codegen_fun: return type) example=IyiThread.class#park
table: hello lowering 1 owner=lowering core reason=lower: visit(binary == on UInt64 and Int32 (mixed operands, hosted codegen_binary_extend_int)) (hosted codegen.cr) is not ported yet example=IyiThread.class#owe_turn
table: hello lowering 1 owner=lowering core reason=lower: visit(MacroFor) (hosted codegen.cr) is not ported yet example=Tuple(Int64, UInt64)#[]
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of lock_taken (hosted codegen_fun: return type) example=IyiThread.class#lock_taken
table: hello lowering 1 owner=lowering core reason=lower: visit(assign Int32 to IyiFiberState (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=IyiFiber#initialize
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of register (hosted codegen_fun: return type) example=IyiScheduler.class#register
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of reap_dying (hosted codegen_fun: return type) example=IyiScheduler.class#reap_dying
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of release_stack (hosted codegen_fun: return type) example=IyiFiber#release_stack
table: hello lowering 1 owner=lowering core reason=lower: visit(StringInterpolation) (hosted codegen.cr) is not ported yet example=Samples::Hello::User#shout
table: hello lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(Samples::Hello::Greet) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Array(Samples::Hello::Greet).class#unsafe_build
table: hello lowering 1 owner=unassigned reason=Cast from Compiler::Types::Types::GenericClassInstanceType to Compiler::Semantic::TopLevel::ClassType+ failed, at src/compiler/lower/primitives.iyi:718:11:718 example=Array(Samples::Hello::Greet).class#new
table: hello lowering 1 owner=lowering core reason=BUG: create_llvm_type for Samples::Hello::Greet is not ported yet (hosted llvm_typer.cr) example=Array(Samples::Hello::Greet)#initialize
table: hello lowering 1 owner=unassigned reason=lower: instance variable @size of Array(Samples::Hello::Greet): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(Samples::Hello::Greet)#unsafe_set_size
table: parse defs-reached=913 defs-typed-clean=505 root-refusals=6 refusal-sites=875
table: parse refusal 134 owner=bodies reason=undefined local variable or method 'previous_def' for Atomic(Int64) example=src/iyi/./chaos_points.iyi:26 in Atomic(Int64)#add
table: parse refusal 64 owner=bodies reason=undefined local variable or method 'previous_def' for Atomic(UInt64) example=src/iyi/./chaos_points.iyi:26 in Atomic(UInt64)#add
table: parse refusal 40 owner=bodies reason=pointerof of callstack is not ported yet: only a local variable is example=src/iyi/prelude.iyi:3 in Int64#raise
table: parse refusal 38 owner=bodies reason=the value of 'other' cannot be typed example=src/iyi/./chaos.iyi:374 in IyiChaos.class#outranked?
table: parse refusal 33 owner=calls reason=expected argument #1 to 'IyiAtomic.store' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/./concurrency.iyi:1475 in IyiSchedLock.class#unlock
table: parse refusal 28 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:1737 in IyiScheduler.class#state_id
table: parse refusal 24 owner=bodies reason=the value of 'size' cannot be typed example=src/iyi/./concurrency.iyi:5531 in IyiWorkers.class#steal_unstarted
table: parse refusal 19 owner=bodies reason=the value of '__temp_1' cannot be typed example=no location in IyiChaos.class#outranked?
table: parse refusal 18 owner=bodies reason=undefined local variable or method 'block' for IyiThread.class example=src/iyi/thread.iyi:317 in IyiThread.class#start
table: parse refusal 17 owner=calls reason=undefined method 'next_run=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2310 in IyiScheduler.class#take_mail
table: parse refusal 16 owner=bodies reason=the value of 'buffer' cannot be typed example=src/iyi/./string.iyi:38 in String.class#new
table: parse refusal 15 owner=calls reason=wrong number of arguments for 'String.interpolation' (given 5, expected 1) example=no location in Array(IyiFiber | Nil)#[]
table: parse refusal 15 owner=bodies reason=the value of 'memory' cannot be typed example=src/iyi/./string.iyi:37 in String.class#new
table: parse refusal 12 owner=calls reason=expected argument #1 to 'IyiFiber#state=' to be IyiFiberState, not Int32 example=src/iyi/./concurrency.iyi:5047 in IyiScheduler.class#panic_current
table: parse refusal 12 owner=bodies reason=the value of 'chunk' cannot be typed example=src/iyi/./concurrency.iyi:18 in IyiScheduler.class#io_chunk
table: parse refusal 11 owner=unassigned reason=unsupported node: Asm example=src/iyi/./concurrency.iyi:2 in top level
table: parse refusal 11 owner=bodies reason=the value of 'entry' cannot be typed example=src/iyi/./concurrency.iyi:17 in IyiScheduler.class#io_chunk
table: parse refusal 10 owner=unassigned reason=wrong number of arguments for 'Proc#call' (given 2, expected 1) example=src/iyi/prelude.iyi:3 in Int64#raise
table: parse refusal 10 owner=calls reason=undefined method 'size' for Nil (compile-time type is (Array | Nil)) example=src/iyi/./concurrency.iyi:5529 in IyiWorkers.class#steal_unstarted
table: parse refusal 10 owner=unassigned reason=type mismatch for return type: expected <unresolved T>, got T example=src/iyi/./concurrency.iyi:5533 in IyiWorkers.class#steal_unstarted
table: parse refusal 10 owner=declarations reason=undefined constant HEADER_SIZE example=src/iyi/./string.iyi:36 in String.class#new
table: parse refusal 9 owner=declarations reason=undefined constant RING example=src/iyi/./concurrency.iyi:1407 in IyiSchedulerState#slot
table: parse refusal 8 owner=calls reason=undefined method 'next_run' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./chaos.iyi:375 in IyiChaos.class#outranked?
table: parse refusal 8 owner=bodies reason=the value of 'state' cannot be typed example=src/iyi/./chaos.iyi:228 in IyiChaos.class#draw
table: parse refusal 8 owner=calls reason=expected argument #1 to 'IyiScheduler.enqueue' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:3998 in IyiScheduler.class#deadlock_found
table: parse refusal 8 owner=unassigned reason=can't deduce argument type example=src/iyi/./concurrency.iyi:17 in IyiScheduler.class#wait_for_events
table: parse refusal 8 owner=bodies reason=the value of 'following' cannot be typed example=src/iyi/./concurrency.iyi:2318 in IyiScheduler.class#take_mail
table: parse refusal 8 owner=declarations reason=undefined constant IO_CHUNK example=src/iyi/./concurrency.iyi:3 in IyiScheduler.class#io_chunk
table: parse refusal 7 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3990 in IyiScheduler.class#deadlock_found
table: parse refusal 6 owner=declarations reason=undefined constant DEADLOCK example=src/iyi/./concurrency.iyi:4011 in IyiScheduler.class#deadlock
table: parse refusal 6 owner=bodies reason=the value of 'held' cannot be typed example=src/iyi/./concurrency.iyi:5659 in IyiWorkers.class#handed_on?
table: parse refusal 6 owner=declarations reason=undefined constant IO_CHUNKS example=src/iyi/./concurrency.iyi:4 in IyiScheduler.class#io_chunk
table: parse refusal 6 owner=bodies reason=the value of 'which' cannot be typed example=src/iyi/./concurrency.iyi:4 in IyiScheduler.class#io_chunk
table: parse refusal 6 owner=calls reason=undefined method 'next_sleep=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4815 in IyiScheduler.class#sleep_pairs
table: parse refusal 6 owner=bodies reason=the value of 'first_child' cannot be typed example=src/iyi/./concurrency.iyi:4769 in IyiScheduler.class#heap_remove
table: parse refusal 5 owner=calls reason=undefined method 'state' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3997 in IyiScheduler.class#deadlock_found
table: parse refusal 5 owner=calls reason=undefined method 'size' for Nil (compile-time type is (Array(IyiFiber | Nil) | Nil)) example=src/iyi/./concurrency.iyi:3423 in IyiScheduler.class#io_slot
table: parse refusal 5 owner=calls reason=undefined method '[]' for Nil (compile-time type is (Array(IyiFiber | Nil) | Nil)) example=src/iyi/./concurrency.iyi:3423 in IyiScheduler.class#io_slot
table: parse refusal 5 owner=bodies reason=the value of 'victim' cannot be typed example=src/iyi/./concurrency.iyi:5534 in IyiWorkers.class#steal_unstarted
table: parse refusal 5 owner=bodies reason=the value of '__temp_2' cannot be typed example=no location in IyiScheduler.class#all_quiet?
table: parse refusal 5 owner=declarations reason=undefined constant HELD example=src/iyi/./concurrency.iyi:1561 in IyiChanLock.class#acquire
table: parse refusal 5 owner=calls reason=undefined method 'sleep_prev=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4816 in IyiScheduler.class#sleep_pairs
table: parse refusal 5 owner=bodies reason=the value of 'partner' cannot be typed example=src/iyi/./concurrency.iyi:4817 in IyiScheduler.class#sleep_pairs
table: parse refusal 5 owner=bodies reason=the value of 'count' cannot be typed example=src/iyi/./io.iyi:104 in IyiIO#fill_buffer
table: parse refusal 4 owner=macros reason=macro control expansion (macros engine) example=src/iyi/./concurrency.iyi:1557 in top level
table: parse refusal 4 owner=declarations reason=undefined constant GOLDEN example=src/iyi/./chaos.iyi:227 in IyiChaos.class#draw
table: parse refusal 4 owner=bodies reason=the value of 'fiber' cannot be typed example=src/iyi/./concurrency.iyi:5536 in IyiWorkers.class#steal_unstarted
table: parse refusal 4 owner=calls reason=expected argument #1 to 'IyiScheduler.switch_to' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:2595 in IyiScheduler.class#reschedule
table: parse refusal 4 owner=bodies reason=the value of 'rest' cannot be typed example=src/iyi/./concurrency.iyi:3611 in IyiScheduler.class#wake_joiners
table: parse refusal 4 owner=calls reason=expected argument #1 to 'IyiScheduler.sleep_meld' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:4731 in IyiScheduler.class#heap_insert
table: parse refusal 3 owner=declarations reason=undefined constant SIMULATED example=src/iyi/./chaos.iyi:312 in IyiChaos.class#point
table: parse refusal 3 owner=declarations reason=undefined constant EVENTS example=src/iyi/./concurrency.iyi:4982 in IyiScheduler.class#events_buffer
table: parse refusal 3 owner=calls reason=expected argument #1 to 'Pointer(UInt8)#+' to be Int64, not Int32 example=src/iyi/./string.iyi:537 in String#==
table: parse refusal 3 owner=calls reason=undefined method 'next_sleep' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4814 in IyiScheduler.class#sleep_pairs
table: parse refusal 3 owner=bodies reason=the value of 'got' cannot be typed example=src/iyi/./io.iyi:183 in IyiIO#read_all
table: parse refusal 2 owner=bodies reason=the value of 'unit' cannot be typed example=src/iyi/./chaos.iyi:265 in IyiChaos.class#unit_of
table: parse refusal 2 owner=calls reason=undefined method 'next_child' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:7246 in IyiGroup#cancel_children_locked
table: parse refusal 2 owner=calls reason=undefined method 'deadline' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4026 in IyiScheduler.class#wait_for_events
table: parse refusal 2 owner=bodies reason=the value of 'task' cannot be typed example=src/iyi/./concurrency.iyi:3987 in IyiScheduler.class#deadlock_found
table: parse refusal 2 owner=bodies reason=the value of 'group' cannot be typed example=src/iyi/./concurrency.iyi:3989 in IyiScheduler.class#deadlock_found
table: parse refusal 2 owner=calls reason=undefined method 'claim_any' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3998 in IyiScheduler.class#deadlock_found
table: parse refusal 2 owner=calls reason=expected argument #2 to 'IyiScheduler.io_remove' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:4907 in IyiScheduler.class#io_take
table: parse refusal 2 owner=calls reason=undefined method 'unit' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2326 in IyiScheduler.class#take_mail
table: parse refusal 2 owner=bodies reason=the value of 'waits_here' cannot be typed example=src/iyi/./concurrency.iyi:2327 in IyiScheduler.class#take_mail
table: parse refusal 2 owner=calls reason=undefined method 'next_node' for Nil (compile-time type is (IyiDeferNode | Nil)) example=src/iyi/./concurrency.iyi:5065 in IyiScheduler.class#panic_current
table: parse refusal 2 owner=unassigned reason=wrong number of arguments for 'Proc#call' (given 0, expected 1) example=src/iyi/prelude.iyi:10849 in IyiDeferNode#run
table: parse refusal 2 owner=calls reason=undefined method 'run' for Nil (compile-time type is (IyiDeferNode | Nil)) example=src/iyi/./concurrency.iyi:5066 in IyiScheduler.class#panic_current
table: parse refusal 2 owner=calls reason=expected argument #1 to 'IyiScheduler.ready' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:7160 in IyiGroup#child_finished
table: parse refusal 2 owner=calls reason=undefined method 'next_joiner' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3609 in IyiScheduler.class#wake_joiners
table: parse refusal 2 owner=calls reason=undefined method 'next_joiner=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3610 in IyiScheduler.class#wake_joiners
table: parse refusal 2 owner=declarations reason=undefined constant YIELDED example=src/iyi/./concurrency.iyi:980 in IyiUnit#hand_to_yielded
table: parse refusal 2 owner=declarations reason=undefined constant SPINNER example=src/iyi/./concurrency.iyi:1576 in IyiChanLock.class#contend
table: parse refusal 2 owner=declarations reason=undefined constant CACHE_REQUEST example=src/iyi/prelude.iyi:730 in IyiHeap.class#stop_requested?
table: parse refusal 2 owner=unassigned reason=unsupported node: AsmOperand example=no location in IyiThread.class#stop_here
table: parse refusal 2 owner=unassigned reason=wrong number of arguments for 'Proc(Nil)#call' (given 0, expected 1) example=src/iyi/./concurrency.iyi:2874 in IyiScheduler.class#run_spawned_fiber
table: parse refusal 2 owner=calls reason=expected argument #1 to 'Pointer#+' to be Int64, not Int32 example=src/iyi/./io.iyi:300 in IyiIO#write
table: parse refusal 2 owner=calls reason=expected argument #1 to 'IyiAtomic.load' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/prelude.iyi:10779 in top level
table: parse refusal 2 owner=bodies reason=the value of 'grown' cannot be typed example=src/iyi/./concurrency.iyi:3460 in IyiScheduler.class#io_room
table: parse refusal 2 owner=calls reason=wrong number of arguments for 'String.interpolation' (given 3, expected 1) example=no location in IyiScheduler.class#wait_posix
table: parse refusal 2 owner=calls reason=undefined method 'prev_io=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3436 in IyiScheduler.class#io_link
table: parse refusal 2 owner=calls reason=undefined method '[]=' for Nil (compile-time type is (Array(IyiFiber | Nil) | Nil)) example=src/iyi/./concurrency.iyi:3440 in IyiScheduler.class#io_link
table: parse refusal 2 owner=bodies reason=the value of 'pair' cannot be typed example=src/iyi/./concurrency.iyi:4826 in IyiScheduler.class#sleep_pairs
table: parse refusal 2 owner=calls reason=undefined method 'sleep_child' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4768 in IyiScheduler.class#heap_remove
table: parse refusal 2 owner=calls reason=undefined method 'sleep_child=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4770 in IyiScheduler.class#heap_remove
table: parse refusal 2 owner=calls reason=wrong number of arguments for 'String.interpolation' (given 2, expected 1) example=no location in String#[]
table: parse refusal 2 owner=bodies reason=the value of '__temp_3' cannot be typed example=no location in Compiler::Tools::Parse::ParseTool.class#parse_source
table: parse refusal 2 owner=bodies reason=undefined local variable or method 'var_scopes' for Compiler::Syntax::Parser::Parser.class example=no location in Compiler::Syntax::Parser::Parser.class#new
table: parse refusal 2 owner=bodies reason=the value of 'parser' cannot be typed example=src/compiler/tools/parse.iyi:37 in Compiler::Tools::Parse::ParseTool.class#parse_source
table: parse refusal 2 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiDeferNode | Nil)) example=src/iyi/./concurrency.iyi:6647 in File.class#__iyi_defer_push_node
table: parse refusal 2 owner=bodies reason=the value of 'below' cannot be typed example=src/iyi/./concurrency.iyi:6659 in File.class#__iyi_defer_pop_run
table: parse refusal 1 owner=unassigned reason=type mismatch for return type: expected IyiSchedulerState, got (IyiSchedulerState | Nil) example=src/iyi/./concurrency.iyi:1793 in IyiScheduler.class#state
table: parse refusal 1 owner=calls reason=undefined method 'chaos_unit' for IyiFiber example=src/iyi/./chaos.iyi:264 in IyiChaos.class#unit_of
table: parse refusal 1 owner=declarations reason=undefined constant HIGH example=src/iyi/./chaos.iyi:267 in IyiChaos.class#unit_of
table: parse refusal 1 owner=calls reason=undefined method 'chaos_unit=' for IyiFiber example=src/iyi/./chaos.iyi:269 in IyiChaos.class#unit_of
table: parse refusal 1 owner=declarations reason=undefined constant LOW example=src/iyi/./chaos.iyi:348 in IyiChaos.class#step
table: parse refusal 1 owner=declarations reason=undefined constant SPIN_STEPS example=src/iyi/./chaos.iyi:350 in IyiChaos.class#step
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiChaos.unit_of' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./chaos.iyi:373 in IyiChaos.class#outranked?
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.cancel' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:7245 in IyiGroup#cancel_children_locked
table: parse refusal 1 owner=declarations reason=undefined constant POLL_EVERY example=src/iyi/./concurrency.iyi:2591 in IyiScheduler.class#reschedule
table: parse refusal 1 owner=declarations reason=undefined constant POLL_IO_NS example=src/iyi/./concurrency.iyi:2761 in IyiScheduler.class#poll_now
table: parse refusal 1 owner=calls reason=undefined method 'awaited' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3986 in IyiScheduler.class#deadlock_found
table: parse refusal 1 owner=calls reason=undefined method 'joining' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3988 in IyiScheduler.class#deadlock_found
table: parse refusal 1 owner=calls reason=undefined method 'deadlocked=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3994 in IyiScheduler.class#deadlock_found
table: parse refusal 1 owner=bodies reason=the value of 'head_deadline' cannot be typed example=src/iyi/./concurrency.iyi:4047 in IyiScheduler.class#wait_for_events
table: parse refusal 1 owner=bodies reason=the value of 'gap' cannot be typed example=src/iyi/./concurrency.iyi:4048 in IyiScheduler.class#wait_for_events
table: parse refusal 1 owner=calls reason=expected argument #2 to 'IyiScheduler.heap_remove' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:4661 in IyiScheduler.class#wake_expired_sleepers
table: parse refusal 1 owner=calls reason=undefined method 'io_timed' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4662 in IyiScheduler.class#wake_expired_sleepers
table: parse refusal 1 owner=calls reason=undefined method 'io_timed=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4664 in IyiScheduler.class#wake_expired_sleepers
table: parse refusal 1 owner=calls reason=undefined method 'timed_out=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4665 in IyiScheduler.class#wake_expired_sleepers
table: parse refusal 1 owner=calls reason=undefined method 'next_cancel' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2323 in IyiScheduler.class#take_mail
table: parse refusal 1 owner=calls reason=undefined method 'next_cancel=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2324 in IyiScheduler.class#take_mail
table: parse refusal 1 owner=calls reason=undefined method 'cancel_posted=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2325 in IyiScheduler.class#take_mail
table: parse refusal 1 owner=calls reason=undefined method 'listed_on' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2326 in IyiScheduler.class#take_mail
table: parse refusal 1 owner=calls reason=undefined method 'waiting_out' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2327 in IyiScheduler.class#take_mail
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.cancel_wait' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:2328 in IyiScheduler.class#take_mail
table: parse refusal 1 owner=calls reason=undefined method 'each' for Nil (compile-time type is (Array(Int32) | Nil)) example=src/iyi/./concurrency.iyi:2335 in IyiScheduler.class#take_mail
table: parse refusal 1 owner=declarations reason=undefined constant PREEMPTED_TURN example=src/iyi/./concurrency.iyi:7 in IyiScheduler.class#worker_next
table: parse refusal 1 owner=calls reason=undefined method 'home' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:5514 in IyiWorkers.class#take_queued
table: parse refusal 1 owner=calls reason=undefined method 'home=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:5520 in IyiWorkers.class#take_queued
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.wake_completed' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/concurrency.iyi:71 in IyiScheduler.class#take_held
table: parse refusal 1 owner=calls reason=expected argument #2 to 'IyiScheduler.take_unit' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:19 in IyiScheduler.class#worker_next
table: parse refusal 1 owner=calls reason=undefined method 'give' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:2721 in IyiScheduler.class#release_unit
table: parse refusal 1 owner=calls reason=undefined method 'waiting?' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:2722 in IyiScheduler.class#release_unit
table: parse refusal 1 owner=calls reason=expected argument #2 to 'IyiScheduler.drain_unit' to be IyiUnit, not (IyiUnit | Nil) example=src/iyi/./concurrency.iyi:2724 in IyiScheduler.class#release_unit
table: parse refusal 1 owner=calls reason=undefined method 'quiet' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2500 in IyiScheduler.class#all_quiet?
table: parse refusal 1 owner=calls reason=undefined method 'idle' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: parse refusal 1 owner=bodies reason=the value of 'quiet' cannot be typed example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: parse refusal 1 owner=calls reason=undefined method 'mail?' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: parse refusal 1 owner=calls reason=undefined method 'next_state' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2506 in IyiScheduler.class#all_quiet?
table: parse refusal 1 owner=calls reason=undefined method 'panicked' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:7213 in IyiGroup#join
table: parse refusal 1 owner=calls reason=undefined method 'panic_delivered' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:7213 in IyiGroup#join
table: parse refusal 1 owner=calls reason=undefined method 'panic_delivered=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:7214 in IyiGroup#join
table: parse refusal 1 owner=calls reason=undefined method 'panic_message' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:7220 in IyiGroup#join
table: parse refusal 1 owner=calls reason=undefined method 'join' for Nil (compile-time type is (IyiGroup | Nil)) example=src/iyi/./concurrency.iyi:5060 in IyiScheduler.class#panic_current
table: parse refusal 1 owner=calls reason=undefined method 'child_panicked' for Nil (compile-time type is (IyiGroup | Nil)) example=src/iyi/./concurrency.iyi:5078 in IyiScheduler.class#panic_current
table: parse refusal 1 owner=calls reason=undefined method 'awaited=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3620 in IyiScheduler.class#wake_joiners
table: parse refusal 1 owner=declarations reason=undefined constant FNV_PRIME example=src/iyi/./chaos.iyi:254 in IyiChaos.class#fold
table: parse refusal 1 owner=calls reason=undefined method 'chaos_held=' for IyiFiber example=src/iyi/./chaos.iyi:357 in IyiChaos.class#step
table: parse refusal 1 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:5659 in IyiWorkers.class#handed_on?
table: parse refusal 1 owner=declarations reason=undefined constant THREADS example=src/iyi/./chaos.iyi:314 in IyiChaos.class#point
table: parse refusal 1 owner=calls reason=undefined method 'hand_to_yielded' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:5 in IyiWorkers.class#give_up
table: parse refusal 1 owner=calls reason=undefined method 'take_yielded' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:9 in IyiWorkers.class#give_up
table: parse refusal 1 owner=declarations reason=undefined constant UNMARKED example=src/iyi/./concurrency.iyi:1572 in IyiChanLock.class#contend
table: parse refusal 1 owner=bodies reason=the value of 'taken' cannot be typed example=src/iyi/./concurrency.iyi:1573 in IyiChanLock.class#contend
table: parse refusal 1 owner=calls reason=expected argument #2 to 'IyiAtomic.rmw' to be Pointer(<unresolved T>), not Pointer(UInt64) example=src/iyi/prelude.iyi:104 in IyiRuntimeLock.class#lock
table: parse refusal 1 owner=declarations reason=undefined constant YIELD_AFTER example=src/iyi/thread.iyi:854 in IyiThread.class#lock_turn
table: parse refusal 1 owner=calls reason=undefined method '!=' for NoReturn example=src/iyi/prelude.iyi:1 in IyiRuntimeLock.class#lock
table: parse refusal 1 owner=unassigned reason=type mismatch for return type: expected IyiFiber, got (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:1829 in IyiScheduler.class#current
table: parse refusal 1 owner=unassigned reason=instance variable '@state' of IyiFiber must be IyiFiberState, not (IyiFiberState | Int32) example=src/iyi/./concurrency.iyi:635 in IyiFiber#initialize
table: parse refusal 1 owner=calls reason=undefined method 'prev_fiber=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1863 in IyiScheduler.class#register
table: parse refusal 1 owner=calls reason=undefined method 'on_cpu=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1917 in IyiScheduler.class#landed
table: parse refusal 1 owner=declarations reason=undefined constant STACK_BYTES example=src/iyi/./concurrency.iyi:926 in IyiFiber#release_stack
table: parse refusal 1 owner=calls reason=undefined method 'release_stack' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1932 in IyiScheduler.class#reap_dying
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.unregister' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:1933 in IyiScheduler.class#reap_dying
table: parse refusal 1 owner=calls reason=expected argument #1 to 'Pointer#copy_from' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/./io.iyi:313 in IyiIO#write
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.load' to be Pointer(<unresolved T>), not Pointer(UInt64) example=src/iyi/prelude.iyi:3 in IyiOnce.class#run
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.cmpxchg' to be Pointer(<unresolved T>), not Pointer(UInt64) example=src/iyi/prelude.iyi:4 in IyiOnce.class#run
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.store' to be Pointer(<unresolved T>), not Pointer(UInt64) example=src/iyi/prelude.iyi:3 in IyiOnce.class#run
table: parse refusal 1 owner=calls reason=undefined method 'next_io=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3485 in IyiScheduler.class#io_unlink
table: parse refusal 1 owner=unassigned reason=type mismatch for return type: expected (Cancelled | Int64), got (Cancelled | Nil) example=src/iyi/./concurrency.iyi:4887 in IyiScheduler.class#read_posix
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'target' for IyiIO example=src/iyi/./io.iyi:194 in IyiIO#read_all
table: parse refusal 1 owner=calls reason=expected argument #1 to 'Pointer(UInt8)#copy_from' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/./file.iyi:141 in File.class#c_path
table: parse refusal 1 owner=unassigned reason=unsupported node: ExceptionHandler example=src/iyi/./file.iyi:68 in File.class#read
table: parse refusal 1 owner=calls reason=undefined method 'next_node=' for Nil (compile-time type is (IyiDeferNode | Nil)) example=src/iyi/./concurrency.iyi:6660 in File.class#__iyi_defer_pop_run
table: parse defs-lowered-clean=272 lowering-refusal-sites=540
table: parse lowering 57 owner=bodies reason=BUG: the analysed program has no type for the body of add (hosted codegen_fun: return type) example=Atomic(UInt64)#add
table: parse lowering 45 owner=bodies reason=BUG: the analysed program has no type for the body of get (hosted codegen_fun: return type) example=Atomic(UInt64)#get
table: parse lowering 33 owner=bodies reason=BUG: the analysed program has no type for the body of sub (hosted codegen_fun: return type) example=Atomic(Int64)#sub
table: parse lowering 32 owner=bodies reason=BUG: the analysed program has no type for the body of unlock (hosted codegen_fun: return type) example=IyiSchedLock.class#unlock
table: parse lowering 32 owner=bodies reason=BUG: the analysed program has no type for the body of compare_and_set (hosted codegen_fun: return type) example=Atomic(UInt64)#compare_and_set
table: parse lowering 28 owner=bodies reason=BUG: the analysed program has no type for the body of set (hosted codegen_fun: return type) example=Atomic(UInt64)#set
table: parse lowering 27 owner=bodies reason=BUG: the analysed program has no type for the body of state_id (hosted codegen_fun: return type) example=IyiScheduler.class#state_id
table: parse lowering 18 owner=bodies reason=BUG: the analysed program has no type for the body of start (hosted codegen_fun: return type) example=IyiThread.class#start
table: parse lowering 15 owner=lowering core reason=lower: visit(Cast) (hosted codegen.cr) is not ported yet example=UInt64#__iyi_say
table: parse lowering 14 owner=lowering core reason=lower: visit(UninitializedVar) (hosted codegen.cr) is not ported yet example=UInt64#raise
table: parse lowering 13 owner=unassigned reason=lower: is_a? of (IyiFiber | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiChaos.class#outranked?
table: parse lowering 11 owner=bodies reason=lower: visit(pointerof of a ClassVar (hosted codegen.cr: visit(PointerOf), only a local variable is ported)) (hosted codegen.cr) is not ported yet example=IyiSchedLock.class#word
table: parse lowering 11 owner=lowering core reason=BUG: create_llvm_type for T is not ported yet (hosted llvm_typer.cr) example=Array#[]
table: parse lowering 9 owner=bodies reason=BUG: the analysed program has no type for the body of wake_one (hosted codegen_fun: return type) example=IyiWorkers.class#wake_one
table: parse lowering 6 owner=lowering core reason=lower: visit(MagicConstant) (hosted codegen.cr) is not ported yet example=UInt64#%
table: parse lowering 6 owner=lowering core reason=lower: visit(Assign to a parameter (hosted fun.cr, create_local_copy_of_arg)) (hosted codegen.cr) is not ported yet example=String#includes?
table: parse lowering 6 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of set (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#free_lists
table: parse lowering 5 owner=lowering core reason=lower: visit(pointer_get of Atomic(UInt64) (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=IyiChanLock.class#acquire
table: parse lowering 5 owner=bodies reason=BUG: the analysed program has no type for the body of set_slot (hosted codegen_fun: return type) example=IyiSchedulerState#set_slot
table: parse lowering 4 owner=unassigned reason=a function or global named IyiScheduler::shared already exists example=IyiScheduler.class#shared?
table: parse lowering 4 owner=calls reason=BUG: the call to st has no target def (hosted call.cr: visit(Call)) example=IyiScheduler.class#poll_now
table: parse lowering 4 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of compare_and_set (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiFiber#claim
table: parse lowering 4 owner=bodies reason=BUG: the analysed program has no type for the body of slot (hosted codegen_fun: return type) example=IyiSchedulerState#slot
table: parse lowering 3 owner=unassigned reason=lower: a bare return from a function that returns a value (hosted codegen_return, the nil upcast) example=IyiSchedLock.class#lock
table: parse lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of io_slot (hosted codegen_fun: return type) example=IyiScheduler.class#io_slot
table: parse lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of spin_pause (hosted codegen_fun: return type) example=IyiThread.class#spin_pause
table: parse lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of run (hosted codegen_fun: return type) example=IyiDeferNode#run
table: parse lowering 3 owner=unassigned reason=a function or global named ~STDOUT:const_read already exists example=IyiScheduler.class#__iyi_flush_std
table: parse lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of swap (hosted codegen_fun: return type) example=Atomic(UInt64)#swap
table: parse lowering 3 owner=unassigned reason=Cast from Compiler::Types::Types::GenericClassInstanceType to Compiler::Semantic::TopLevel::ClassType+ failed, at src/compiler/lower/primitives.iyi:718:11:718 example=Array(String).class#new
table: parse lowering 3 owner=unassigned reason=lower: instance variable @size of Array(String): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(String)#initialize
table: parse lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of io_chunk (hosted codegen_fun: return type) example=IyiScheduler.class#io_chunk
table: parse lowering 2 owner=lowering core reason=lower: visit(a class method call on a receiver that is not a constant path (hosted call.cr: prepare_call_args, Path)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#current
table: parse lowering 2 owner=bodies reason=BUG: (IyiSchedulerState | Nil) has no type id (not reachable from Object) example=IyiScheduler.class#state
table: parse lowering 2 owner=lowering core reason=lower: visit(allocate of class IyiSchedulerState: the :headed byte is the program-wide census (lower/headed.iyi, NEEDS.md rows 26-27), not decided) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#first_state_here
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of draw (hosted codegen_fun: return type) example=IyiChaos.class#draw
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of deadlock (hosted codegen_fun: return type) example=IyiScheduler.class#deadlock
table: parse lowering 2 owner=lowering core reason=lower: visit(binary == on Int64 and Int32 (mixed operands, hosted codegen_binary_extend_int)) (hosted codegen.cr) is not ported yet example=Int64#//
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of wake_io (hosted codegen_fun: return type) example=IyiScheduler.class#wake_io
table: parse lowering 2 owner=unassigned reason=lower: is_a? of (Array(IyiFiber | Nil) | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiScheduler.class#io_take
table: parse lowering 2 owner=lowering core reason=lower: visit(a call with default arguments or a splat (hosted call.cr)) (hosted codegen.cr) is not ported yet example=IyiWorkers.class#__iyi_flush_std
table: parse lowering 2 owner=calls reason=BUG: the call to target_fd has no target def (hosted call.cr: visit(Call)) example=IyiIO#low_level_write
table: parse lowering 2 owner=lowering core reason=lower: visit(primitive object_id (hosted codegen_primitive, primitives.cr)) (hosted codegen.cr) is not ported yet example=IyiGroup#child_panicked
table: parse lowering 2 owner=calls reason=BUG: the call to fiber has no target def (hosted call.cr: visit(Call)) example=IyiWorkers.class#chaos_give_up
table: parse lowering 2 owner=unassigned reason=lower: class variable @@line has a literal initialiser that is not an integer, Bool or Char (hosted class_var.cr: initialize_class_var) example=IyiThread.class#stop_here
table: parse lowering 2 owner=lowering core reason=lower: visit(allocate of class IyiFiber: the :headed byte is the program-wide census (lower/headed.iyi, NEEDS.md rows 26-27), not decided) (hosted codegen.cr) is not ported yet example=IyiFiber.class#main
table: parse lowering 2 owner=lowering core reason=lower: visit(a call to a def with a &block parameter (hosted call.cr: codegen_call_with_block_as_fun_literal, closures)) (hosted codegen.cr) is not ported yet example=IyiTestCases.class#verdict
table: parse lowering 2 owner=calls reason=BUG: the call to fd has no target def (hosted call.cr: visit(Call)) example=IyiIO#iyi_read
table: parse lowering 2 owner=lowering core reason=lower: visit(pointer_set of (IyiFiber | Nil) (hosted assign, primitives.cr 927)) (hosted codegen.cr) is not ported yet example=Pointer((IyiFiber | Nil))#[]=
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of heap_remove (hosted codegen_fun: return type) example=IyiScheduler.class#heap_remove
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of parse_source (hosted codegen_fun: return type) example=Compiler::Tools::Parse::ParseTool.class#parse_source
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of low_level_close (hosted codegen_fun: return type) example=IyiIO#low_level_close
table: parse lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(IyiFiber | Nil) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiScheduler.class#run_spawned_fiber
table: parse lowering 1 owner=lowering core reason=lower: visit(a class method call on Atomic(UInt64).class (hosted call.cr: prepare_call_args, a generic or builtin metaclass)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#initialize
table: parse lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Atomic(UInt64) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Atomic(UInt64).class#new
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of initialize (hosted codegen_fun: return type) example=Atomic(UInt64)#initialize
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to == (hosted call.cr: visit(Call)) example=IyiChaos.class#at_atomic
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to state (hosted call.cr: visit(Call)) example=IyiChaos.class#step
table: parse lowering 1 owner=unassigned reason=a function or global named IyiScheduler::state already exists example=IyiSchedLock.class#held_here?
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to chaos_unit (hosted call.cr: visit(Call)) example=IyiChaos.class#unit_of
table: parse lowering 1 owner=bodies reason=lower: visit(pointerof of a InstanceVar (hosted codegen.cr: visit(PointerOf), only a local variable is ported)) (hosted codegen.cr) is not ported yet example=String#to_unsafe
table: parse lowering 1 owner=unassigned reason=lower: class variable @@resolver is not an integer, a float or a nilable reference: the struct and the non-nilable pointer initialisers are not ported yet (hosted class_var.cr: initialize_class_var) example=IyiPanic.class#resolver
table: parse lowering 1 owner=lowering core reason=lower: visit(a call to held_here? with no receiver inside a class method (hosted call.cr: prepare_call_args, the metaclass owner)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#panic_current
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to store (hosted call.cr: visit(Call)) example=IyiSchedLock.class#release_held
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of join (hosted codegen_fun: return type) example=IyiGroup#join
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for a branch (hosted codegen.cr: visit(If)) example=IyiScheduler.class#reschedule
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to at_atomic (hosted call.cr: visit(Call)) example=IyiSchedulerState#take_lists
table: parse lowering 1 owner=lowering core reason=BUG: create_llvm_type for <unresolved T> is not ported yet (hosted llvm_typer.cr) example=Tuple(<unresolved T>, Bool)#[]
table: parse lowering 1 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of add (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiFiber#claim_any
table: parse lowering 1 owner=lowering core reason=lower: visit(binary > on Int64 and Int32 (mixed operands, hosted codegen_binary_extend_int)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#pollfd
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to malloc (hosted call.cr: visit(Call)) example=IyiScheduler.class#events_buffer
table: parse lowering 1 owner=calls reason=BUG: the call to entry has no target def (hosted call.cr: visit(Call)) example=IyiScheduler.class#event_ready
table: parse lowering 1 owner=unassigned reason=lower: instance variable @size of Array(IyiFiber | Nil): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(IyiFiber | Nil)#size
table: parse lowering 1 owner=lowering core reason=lower: visit(pointer_get of (IyiFiber | Nil) (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=Pointer((IyiFiber | Nil))#[]
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of end_idle (hosted codegen_fun: return type) example=IyiScheduler.class#end_idle
table: parse lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Atomic(Int64) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiWorkers.class#word
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to shared? (hosted call.cr: visit(Call)) example=IyiScheduler.class#take_mail
table: parse lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(Int32) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiSchedulerState#closed_fds
table: parse lowering 1 owner=unassigned reason=lower: instance variable @size of Array(Int32): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(Int32)#each
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to value (hosted call.cr: visit(Call)) example=IyiWorkers.class#pop
table: parse lowering 1 owner=unassigned reason=lower: is_a? of (Array | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiWorkers.class#steal_unstarted
table: parse lowering 1 owner=lowering core reason=BUG: llvm_struct_type of Array is not ported yet (hosted create_llvm_struct_type) example=Array#size
table: parse lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiIO: the :headed byte is the program-wide census (lower/headed.iyi, NEEDS.md rows 26-27), not decided) (hosted codegen.cr) is not ported yet example=IyiIO.class#new
table: parse lowering 1 owner=lowering core reason=lower: visit(Pointer#malloc with a count that is not the size type (hosted generic_array_malloc: builder.mul of the size and the count)) (hosted codegen.cr) is not ported yet example=IyiIO#initialize
table: parse lowering 1 owner=lowering core reason=lower: taken is declared (IyiFiber | Nil) and assigned Nil: the hosted upcast is not ported yet example=IyiScheduler.class#take_held
table: parse lowering 1 owner=lowering core reason=lower: visit(a call to word with no receiver inside a class method (hosted call.cr: prepare_call_args, the metaclass owner)) (hosted codegen.cr) is not ported yet example=IyiWorkers.class#runtime_lock_free?
table: parse lowering 1 owner=unassigned reason=lower: is_a? of (IyiUnit | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiScheduler.class#release_unit
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to ensure_doorbell (hosted call.cr: visit(Call)) example=IyiScheduler.class#wait_shared
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of child_finished (hosted codegen_fun: return type) example=IyiGroup#child_finished
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to memory (hosted call.cr: visit(Call)) example=String.class#new
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of fold (hosted codegen_fun: return type) example=IyiChaos.class#fold
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to state= (hosted call.cr: visit(Call)) example=IyiScheduler.class#enqueue
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of thread_point (hosted codegen_fun: return type) example=IyiChaos.class#thread_point
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of give_up (hosted codegen_fun: return type) example=IyiWorkers.class#give_up
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of hand_to_yielded (hosted codegen_fun: return type) example=IyiUnit#hand_to_yielded
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of take_yielded (hosted codegen_fun: return type) example=IyiUnit#take_yielded
table: parse lowering 1 owner=lowering core reason=lower: visit(binary != on Int64 and Int32 (mixed operands, hosted codegen_binary_extend_int)) (hosted codegen.cr) is not ported yet example=IyiThread.class#lock_turn
table: parse lowering 1 owner=unassigned reason=lower: class variable @@control has a literal initialiser that is not an integer, Bool or Char (hosted class_var.cr: initialize_class_var) example=IyiThread.class#control
table: parse lowering 1 owner=unassigned reason=lower: class variable @@cache has a literal initialiser that is not an integer, Bool or Char (hosted class_var.cr: initialize_class_var) example=IyiThread.class#park_if_requested
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of stop_requested? (hosted codegen_fun: return type) example=IyiHeap.class#stop_requested?
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of clear_request (hosted codegen_fun: return type) example=IyiHeap.class#clear_request
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of park (hosted codegen_fun: return type) example=IyiThread.class#park
table: parse lowering 1 owner=lowering core reason=lower: visit(binary == on UInt64 and Int32 (mixed operands, hosted codegen_binary_extend_int)) (hosted codegen.cr) is not ported yet example=IyiThread.class#owe_turn
table: parse lowering 1 owner=lowering core reason=lower: visit(MacroFor) (hosted codegen.cr) is not ported yet example=Tuple(Int64, UInt64)#[]
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of lock_taken (hosted codegen_fun: return type) example=IyiThread.class#lock_taken
table: parse lowering 1 owner=lowering core reason=lower: visit(assign Int32 to IyiFiberState (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=IyiFiber#initialize
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of register (hosted codegen_fun: return type) example=IyiScheduler.class#register
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of reap_dying (hosted codegen_fun: return type) example=IyiScheduler.class#reap_dying
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of release_stack (hosted codegen_fun: return type) example=IyiFiber#release_stack
table: parse lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(String) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Compiler::Tools::Parse::ParseTool.class#run
table: parse lowering 1 owner=lowering core reason=lower: visit(ArrayLiteral) (hosted codegen.cr) is not ported yet example=Program.class#args
table: parse lowering 1 owner=lowering core reason=lower: visit(pointer_get of String (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=Pointer(String)#[]
table: parse lowering 1 owner=unassigned reason=a function or global named ~STDIN:const_read already exists example=Compiler::Tools::Parse::ParseTool.class#stdin
table: parse lowering 1 owner=unassigned reason=lower: return of Cancelled from a function returning another type (hosted upcast, the casts slice) example=IyiScheduler.class#wait_readable_posix
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of io_owner (hosted codegen_fun: return type) example=IyiScheduler.class#io_owner
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to sleep_head= (hosted call.cr: visit(Call)) example=IyiScheduler.class#arm_deadline
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of heap_insert (hosted codegen_fun: return type) example=IyiScheduler.class#heap_insert
table: parse lowering 1 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of swap (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiFiber#list_on
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of cancel_wait (hosted codegen_fun: return type) example=IyiScheduler.class#cancel_wait
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of io_owner_clear (hosted codegen_fun: return type) example=IyiScheduler.class#io_owner_clear
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to low_level_read (hosted call.cr: visit(Call)) example=IyiIO#fill_buffer
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to raise (hosted call.cr: visit(Call)) example=String#[]
table: parse lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Set(String) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Set(String).class#new
table: parse lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Hash(String, Bool) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Set(String)#initialize
table: parse lowering 1 owner=unassigned reason=lower: instance variable @size of Hash(String, Bool): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Hash(String, Bool)#initialize
table: parse lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(Set(String).class) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Array(Set(String).class).class#unsafe_build
table: parse lowering 1 owner=unassigned reason=lower: instance variable @size of Array(Set(String).class): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(Set(String).class)#unsafe_set_size
table: parse lowering 1 owner=calls reason=BUG: the call to path has no target def (hosted call.cr: visit(Call)) example=File.class#exists?
table: parse lowering 1 owner=lowering core reason=lower: codegen_cond of (Int32 | Nil) is not ported yet (hosted cond.cr: nilable and union tests, slice S2c) example=File.class#c_path
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of read (hosted codegen_fun: return type) example=File.class#read
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of __iyi_defer_push (hosted codegen_fun: return type) example=File.class#__iyi_defer_push
table: parse lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiDeferNode: the :headed byte is the program-wide census (lower/headed.iyi, NEEDS.md rows 26-27), not decided) (hosted codegen.cr) is not ported yet example=IyiDeferNode.class#new
table: parse lowering 1 owner=lowering core reason=lower: visit(assign Proc(Nil) to Proc (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=IyiDeferNode#initialize
table: parse lowering 1 owner=unassigned reason=lower: is_a? of (IyiDeferNode | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=File.class#__iyi_defer_push_node
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of __iyi_defer_pop_run (hosted codegen_fun: return type) example=File.class#__iyi_defer_pop_run
table: parse lowering 1 owner=lowering core reason=lower: visit(a class method call on Array(Set(String).class).class (hosted call.cr: prepare_call_args, a generic or builtin metaclass)) (hosted codegen.cr) is not ported yet example=Array(Set(String).class).class#unsafe_build
table: compile_native defs-reached=2905 defs-typed-clean=1839 root-refusals=6 refusal-sites=1707
table: compile_native refusal 577 owner=calls reason=expected argument #1 to 'Pointer(String)#copy_from' to be Pointer(<unresolved T>), not Pointer(String) example=src/iyi/./array.iyi:824 in Array(String)#reserve
table: compile_native refusal 134 owner=bodies reason=undefined local variable or method 'previous_def' for Atomic(Int64) example=src/iyi/./chaos_points.iyi:26 in Atomic(Int64)#add
table: compile_native refusal 64 owner=bodies reason=undefined local variable or method 'previous_def' for Atomic(UInt64) example=src/iyi/./chaos_points.iyi:26 in Atomic(UInt64)#add
table: compile_native refusal 48 owner=bodies reason=pointerof of callstack is not ported yet: only a local variable is example=src/iyi/prelude.iyi:3 in Int64#raise
table: compile_native refusal 38 owner=bodies reason=the value of 'other' cannot be typed example=src/iyi/./chaos.iyi:374 in IyiChaos.class#outranked?
table: compile_native refusal 33 owner=calls reason=expected argument #1 to 'IyiAtomic.store' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/./concurrency.iyi:1475 in IyiSchedLock.class#unlock
table: compile_native refusal 28 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:1737 in IyiScheduler.class#state_id
table: compile_native refusal 24 owner=bodies reason=the value of '__temp_1' cannot be typed example=no location in IyiChaos.class#outranked?
table: compile_native refusal 24 owner=bodies reason=the value of 'size' cannot be typed example=src/iyi/./concurrency.iyi:5531 in IyiWorkers.class#steal_unstarted
table: compile_native refusal 24 owner=bodies reason=the value of 'memory' cannot be typed example=src/iyi/./string.iyi:37 in String.class#new
table: compile_native refusal 24 owner=bodies reason=the value of 'buffer' cannot be typed example=src/iyi/./string.iyi:38 in String.class#new
table: compile_native refusal 20 owner=calls reason=expected argument #1 to 'Pointer(UInt8)#copy_from' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/./file.iyi:141 in File.class#c_path
table: compile_native refusal 18 owner=calls reason=wrong number of arguments for 'String.interpolation' (given 5, expected 1) example=no location in Array(IyiFiber | Nil)#[]
table: compile_native refusal 18 owner=bodies reason=undefined local variable or method 'block' for IyiThread.class example=src/iyi/thread.iyi:317 in IyiThread.class#start
table: compile_native refusal 17 owner=calls reason=undefined method 'next_run=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2310 in IyiScheduler.class#take_mail
table: compile_native refusal 16 owner=declarations reason=undefined constant HEADER_SIZE example=src/iyi/./string.iyi:36 in String.class#new
table: compile_native refusal 13 owner=bodies reason=the value of 'entry' cannot be typed example=src/iyi/./concurrency.iyi:17 in IyiScheduler.class#io_chunk
table: compile_native refusal 12 owner=calls reason=expected argument #1 to 'IyiFiber#state=' to be IyiFiberState, not Int32 example=src/iyi/./concurrency.iyi:5047 in IyiScheduler.class#panic_current
table: compile_native refusal 12 owner=declarations reason=undefined constant T example=src/iyi/./array.iyi:28 in Array#initialize
table: compile_native refusal 12 owner=calls reason=wrong number of arguments for 'String.interpolation' (given 3, expected 1) example=no location in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 12 owner=bodies reason=the value of 'chunk' cannot be typed example=src/iyi/./concurrency.iyi:18 in IyiScheduler.class#io_chunk
table: compile_native refusal 11 owner=unassigned reason=unsupported node: Asm example=src/iyi/./concurrency.iyi:2 in top level
table: compile_native refusal 11 owner=unassigned reason=wrong number of arguments for 'Proc#call' (given 2, expected 1) example=src/iyi/prelude.iyi:3 in Int64#raise
table: compile_native refusal 11 owner=calls reason=wrong number of arguments for 'String.interpolation' (given 2, expected 1) example=no location in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 11 owner=bodies reason=undefined local variable or method 'uleb' for Compiler::Native::Wasm::Module::WasmModule example=src/compiler/native/wasm/leb.iyi:50 in Compiler::Native::Wasm::Module::WasmModule#uleb_i
table: compile_native refusal 10 owner=calls reason=undefined method 'size' for Nil (compile-time type is (Array | Nil)) example=src/iyi/./concurrency.iyi:5529 in IyiWorkers.class#steal_unstarted
table: compile_native refusal 10 owner=unassigned reason=type mismatch for return type: expected <unresolved T>, got T example=src/iyi/./concurrency.iyi:5533 in IyiWorkers.class#steal_unstarted
table: compile_native refusal 9 owner=declarations reason=undefined constant RING example=src/iyi/./concurrency.iyi:1407 in IyiSchedulerState#slot
table: compile_native refusal 8 owner=calls reason=undefined method 'next_run' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./chaos.iyi:375 in IyiChaos.class#outranked?
table: compile_native refusal 8 owner=bodies reason=the value of 'state' cannot be typed example=src/iyi/./chaos.iyi:228 in IyiChaos.class#draw
table: compile_native refusal 8 owner=calls reason=expected argument #1 to 'IyiScheduler.enqueue' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:3998 in IyiScheduler.class#deadlock_found
table: compile_native refusal 8 owner=unassigned reason=can't deduce argument type example=src/iyi/./concurrency.iyi:17 in IyiScheduler.class#wait_for_events
table: compile_native refusal 8 owner=bodies reason=the value of 'following' cannot be typed example=src/iyi/./concurrency.iyi:2318 in IyiScheduler.class#take_mail
table: compile_native refusal 8 owner=unassigned reason=undefined fun 'backtrace_symbols_fd' for Compiler::Tools::CompileNative::LibC example=src/iyi/prelude.iyi:5 in File.class#raise
table: compile_native refusal 8 owner=declarations reason=undefined constant IO_CHUNK example=src/iyi/./concurrency.iyi:3 in IyiScheduler.class#io_chunk
table: compile_native refusal 7 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3990 in IyiScheduler.class#deadlock_found
table: compile_native refusal 7 owner=declarations reason=undefined constant TARGET example=src/compiler/tools/compile_native.iyi:82 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 7 owner=bodies reason=undefined local variable or method 'count' for File.class example=src/iyi/prelude.iyi:3 in File.class#raise
table: compile_native refusal 7 owner=bodies reason=undefined local variable or method 'wasm_vec' for Compiler::Native::Wasm::Module::WasmModule example=src/compiler/native/wasm/module.iyi:185 in Compiler::Native::Wasm::Module::WasmModule#write
table: compile_native refusal 6 owner=declarations reason=undefined constant DEADLOCK example=src/iyi/./concurrency.iyi:4011 in IyiScheduler.class#deadlock
table: compile_native refusal 6 owner=bodies reason=the value of 'held' cannot be typed example=src/iyi/./concurrency.iyi:5659 in IyiWorkers.class#handed_on?
table: compile_native refusal 6 owner=declarations reason=undefined constant IO_CHUNKS example=src/iyi/./concurrency.iyi:4 in IyiScheduler.class#io_chunk
table: compile_native refusal 6 owner=bodies reason=the value of 'which' cannot be typed example=src/iyi/./concurrency.iyi:4 in IyiScheduler.class#io_chunk
table: compile_native refusal 6 owner=calls reason=undefined method 'next_sleep=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4815 in IyiScheduler.class#sleep_pairs
table: compile_native refusal 6 owner=bodies reason=the value of 'first_child' cannot be typed example=src/iyi/./concurrency.iyi:4769 in IyiScheduler.class#heap_remove
table: compile_native refusal 6 owner=bodies reason=the value of 'ctx' cannot be typed example=src/compiler/native/wasm/codegen.iyi:1338 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 5 owner=calls reason=undefined method 'state' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3997 in IyiScheduler.class#deadlock_found
table: compile_native refusal 5 owner=calls reason=undefined method 'size' for Nil (compile-time type is (Array(IyiFiber | Nil) | Nil)) example=src/iyi/./concurrency.iyi:3423 in IyiScheduler.class#io_slot
table: compile_native refusal 5 owner=calls reason=undefined method '[]' for Nil (compile-time type is (Array(IyiFiber | Nil) | Nil)) example=src/iyi/./concurrency.iyi:3423 in IyiScheduler.class#io_slot
table: compile_native refusal 5 owner=bodies reason=the value of 'victim' cannot be typed example=src/iyi/./concurrency.iyi:5534 in IyiWorkers.class#steal_unstarted
table: compile_native refusal 5 owner=declarations reason=undefined constant HELD example=src/iyi/./concurrency.iyi:1561 in IyiChanLock.class#acquire
table: compile_native refusal 5 owner=unassigned reason=undefined fun 'read' for Compiler::Tools::CompileNative::LibC example=src/iyi/prelude.iyi:32 in IyiScheduler.class#__iyi_read
table: compile_native refusal 5 owner=calls reason=undefined method 'sleep_prev=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4816 in IyiScheduler.class#sleep_pairs
table: compile_native refusal 5 owner=bodies reason=the value of 'partner' cannot be typed example=src/iyi/./concurrency.iyi:4817 in IyiScheduler.class#sleep_pairs
table: compile_native refusal 5 owner=bodies reason=the value of 'count' cannot be typed example=src/iyi/./io.iyi:104 in IyiIO#fill_buffer
table: compile_native refusal 5 owner=declarations reason=undefined constant IrError example=src/iyi/./primitives.iyi:159 in Pointer(<unresolved IrError>)#value
table: compile_native refusal 5 owner=bodies reason=the value of 'slot' cannot be typed example=src/iyi/./hash.iyi:566 in Hash(Int32, Array(UInt8))#slot_for
table: compile_native refusal 4 owner=macros reason=macro control expansion (macros engine) example=src/iyi/./concurrency.iyi:1557 in top level
table: compile_native refusal 4 owner=declarations reason=undefined constant GOLDEN example=src/iyi/./chaos.iyi:227 in IyiChaos.class#draw
table: compile_native refusal 4 owner=bodies reason=the value of 'fiber' cannot be typed example=src/iyi/./concurrency.iyi:5536 in IyiWorkers.class#steal_unstarted
table: compile_native refusal 4 owner=calls reason=expected argument #1 to 'IyiScheduler.switch_to' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:2595 in IyiScheduler.class#reschedule
table: compile_native refusal 4 owner=bodies reason=the value of 'rest' cannot be typed example=src/iyi/./concurrency.iyi:3611 in IyiScheduler.class#wake_joiners
table: compile_native refusal 4 owner=calls reason=expected argument #1 to 'Pointer(UInt8)#+' to be Int64, not Int32 example=src/iyi/./string.iyi:537 in String#==
table: compile_native refusal 4 owner=unassigned reason=undefined fun 'backtrace' for Compiler::Tools::CompileNative::LibC example=src/iyi/prelude.iyi:3 in File.class#raise
table: compile_native refusal 4 owner=unassigned reason=undefined fun 'write' for Compiler::Tools::CompileNative::LibC example=src/iyi/prelude.iyi:28 in File.class#__iyi_write
table: compile_native refusal 4 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiDeferNode | Nil)) example=src/iyi/./concurrency.iyi:6647 in File.class#__iyi_defer_push_node
table: compile_native refusal 4 owner=calls reason=expected argument #1 to 'IyiScheduler.sleep_meld' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:4731 in IyiScheduler.class#heap_insert
table: compile_native refusal 4 owner=bodies reason=the value of 'below' cannot be typed example=src/iyi/./concurrency.iyi:6659 in File.class#__iyi_defer_pop_run
table: compile_native refusal 4 owner=bodies reason=the value of 'modules' cannot be typed example=src/compiler/native/wasm/codegen.iyi:1285 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 4 owner=bodies reason=undefined local variable or method 'wasm_section' for Compiler::Native::Wasm::Module::WasmModule example=src/compiler/native/wasm/module.iyi:194 in Compiler::Native::Wasm::Module::WasmModule#write
table: compile_native refusal 3 owner=declarations reason=undefined constant SIMULATED example=src/iyi/./chaos.iyi:312 in IyiChaos.class#point
table: compile_native refusal 3 owner=declarations reason=undefined constant EVENTS example=src/iyi/./concurrency.iyi:4982 in IyiScheduler.class#events_buffer
table: compile_native refusal 3 owner=bodies reason=the value of '__temp_2' cannot be typed example=no location in IyiScheduler.class#all_quiet?
table: compile_native refusal 3 owner=calls reason=undefined method 'next_node' for Nil (compile-time type is (IyiDeferNode | Nil)) example=src/iyi/./concurrency.iyi:5065 in IyiScheduler.class#panic_current
table: compile_native refusal 3 owner=unassigned reason=wrong number of arguments for 'Proc#call' (given 0, expected 1) example=src/iyi/prelude.iyi:10849 in IyiDeferNode#run
table: compile_native refusal 3 owner=calls reason=undefined method 'run' for Nil (compile-time type is (IyiDeferNode | Nil)) example=src/iyi/./concurrency.iyi:5066 in IyiScheduler.class#panic_current
table: compile_native refusal 3 owner=unassigned reason=undefined fun 'open' for Compiler::Tools::CompileNative::LibC example=src/iyi/prelude.iyi:57 in File.class#__iyi_open_read
table: compile_native refusal 3 owner=bodies reason=the value of 'compiler' cannot be typed example=src/compiler/tools/compile_native.iyi:161 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 3 owner=calls reason=undefined method 'next_sleep' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4814 in IyiScheduler.class#sleep_pairs
table: compile_native refusal 3 owner=bodies reason=the value of 'got' cannot be typed example=src/iyi/./io.iyi:183 in IyiIO#read_all
table: compile_native refusal 3 owner=bodies reason=undefined local variable or method 'e' for Compiler::Tools::CompileNative::CompileNative.class example=src/compiler/tools/compile_native.iyi:53 in Compiler::Tools::CompileNative::CompileNative.class#module_of
table: compile_native refusal 3 owner=bodies reason=undefined local variable or method 'data_base' for Compiler::Tools::CompileNative::CompileNative.class example=src/compiler/native/wasm/codegen.iyi:1283 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 3 owner=bodies reason=undefined local variable or method 'ctx' for Compiler::Tools::CompileNative::CompileNative.class example=src/compiler/native/wasm/codegen.iyi:1332 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 3 owner=calls reason=expected argument #1 to 'Pointer(Array(UInt8))#copy_from' to be Pointer(<unresolved T>), not Pointer(Array(UInt8)) example=src/iyi/./array.iyi:824 in Array(Array(UInt8))#reserve
table: compile_native refusal 3 owner=bodies reason=the value of 'program' cannot be typed example=src/compiler/native/driver.iyi:240 in Compiler::Tools::CompileNative::CompileNative.class#link_native_program
table: compile_native refusal 3 owner=bodies reason=the value of 'rt' cannot be typed example=src/compiler/native/driver.iyi:242 in Compiler::Tools::CompileNative::CompileNative.class#link_native_program
table: compile_native refusal 3 owner=bodies reason=the value of 'result' cannot be typed example=src/compiler/native/driver.iyi:245 in Compiler::Tools::CompileNative::CompileNative.class#link_native_program
table: compile_native refusal 2 owner=bodies reason=the value of 'unit' cannot be typed example=src/iyi/./chaos.iyi:265 in IyiChaos.class#unit_of
table: compile_native refusal 2 owner=calls reason=undefined method 'next_child' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:7246 in IyiGroup#cancel_children_locked
table: compile_native refusal 2 owner=calls reason=undefined method 'deadline' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4026 in IyiScheduler.class#wait_for_events
table: compile_native refusal 2 owner=bodies reason=the value of 'task' cannot be typed example=src/iyi/./concurrency.iyi:3987 in IyiScheduler.class#deadlock_found
table: compile_native refusal 2 owner=bodies reason=the value of 'group' cannot be typed example=src/iyi/./concurrency.iyi:3989 in IyiScheduler.class#deadlock_found
table: compile_native refusal 2 owner=calls reason=undefined method 'claim_any' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3998 in IyiScheduler.class#deadlock_found
table: compile_native refusal 2 owner=calls reason=expected argument #2 to 'IyiScheduler.io_remove' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:4907 in IyiScheduler.class#io_take
table: compile_native refusal 2 owner=calls reason=undefined method 'unit' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2326 in IyiScheduler.class#take_mail
table: compile_native refusal 2 owner=bodies reason=the value of 'waits_here' cannot be typed example=src/iyi/./concurrency.iyi:2327 in IyiScheduler.class#take_mail
table: compile_native refusal 2 owner=calls reason=expected argument #1 to 'IyiScheduler.ready' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:7160 in IyiGroup#child_finished
table: compile_native refusal 2 owner=calls reason=undefined method 'next_joiner' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3609 in IyiScheduler.class#wake_joiners
table: compile_native refusal 2 owner=calls reason=undefined method 'next_joiner=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3610 in IyiScheduler.class#wake_joiners
table: compile_native refusal 2 owner=declarations reason=undefined constant YIELDED example=src/iyi/./concurrency.iyi:980 in IyiUnit#hand_to_yielded
table: compile_native refusal 2 owner=declarations reason=undefined constant SPINNER example=src/iyi/./concurrency.iyi:1576 in IyiChanLock.class#contend
table: compile_native refusal 2 owner=declarations reason=undefined constant CACHE_REQUEST example=src/iyi/prelude.iyi:730 in IyiHeap.class#stop_requested?
table: compile_native refusal 2 owner=unassigned reason=unsupported node: AsmOperand example=no location in IyiThread.class#stop_here
table: compile_native refusal 2 owner=unassigned reason=wrong number of arguments for 'Proc(Nil)#call' (given 0, expected 1) example=src/iyi/./concurrency.iyi:2874 in IyiScheduler.class#run_spawned_fiber
table: compile_native refusal 2 owner=calls reason=expected argument #1 to 'Pointer#+' to be Int64, not Int32 example=src/iyi/./io.iyi:300 in IyiIO#write
table: compile_native refusal 2 owner=calls reason=expected argument #1 to 'IyiAtomic.load' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/prelude.iyi:10779 in top level
table: compile_native refusal 2 owner=unassigned reason=undefined fun 'close' for Compiler::Tools::CompileNative::LibC example=src/iyi/prelude.iyi:83 in File.class#__iyi_close
table: compile_native refusal 2 owner=bodies reason=the value of 'loader' cannot be typed example=src/compiler/tools/compile_native.iyi:159 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 2 owner=bodies reason=the value of 'refusal' cannot be typed example=src/compiler/tools/compile_native.iyi:164 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 2 owner=unassigned reason=unsupported node: ExceptionHandler example=src/iyi/./file.iyi:68 in File.class#read
table: compile_native refusal 2 owner=bodies reason=the value of 'grown' cannot be typed example=src/iyi/./concurrency.iyi:3460 in IyiScheduler.class#io_room
table: compile_native refusal 2 owner=unassigned reason=undefined fun 'kevent' for Compiler::Tools::CompileNative::LibC example=src/iyi/./concurrency.iyi:10 in IyiScheduler.class#wait_posix
table: compile_native refusal 2 owner=calls reason=undefined method 'prev_io=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3436 in IyiScheduler.class#io_link
table: compile_native refusal 2 owner=calls reason=undefined method '[]=' for Nil (compile-time type is (Array(IyiFiber | Nil) | Nil)) example=src/iyi/./concurrency.iyi:3440 in IyiScheduler.class#io_link
table: compile_native refusal 2 owner=bodies reason=the value of 'pair' cannot be typed example=src/iyi/./concurrency.iyi:4826 in IyiScheduler.class#sleep_pairs
table: compile_native refusal 2 owner=calls reason=undefined method 'sleep_child' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4768 in IyiScheduler.class#heap_remove
table: compile_native refusal 2 owner=calls reason=undefined method 'sleep_child=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4770 in IyiScheduler.class#heap_remove
table: compile_native refusal 2 owner=calls reason=undefined method 'next_node=' for Nil (compile-time type is (IyiDeferNode | Nil)) example=src/iyi/./concurrency.iyi:6660 in File.class#__iyi_defer_pop_run
table: compile_native refusal 2 owner=bodies reason=the value of 'where' cannot be typed example=src/compiler/tools/compile_native.iyi:54 in Compiler::Tools::CompileNative::CompileNative.class#module_of
table: compile_native refusal 2 owner=bodies reason=the value of 'data_end' cannot be typed example=src/compiler/native/wasm/codegen.iyi:1303 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 2 owner=bodies reason=the value of 'k' cannot be typed example=src/compiler/native/wasm/codegen.iyi:1303 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 2 owner=bodies reason=the value of 'ti' cannot be typed example=src/compiler/native/wasm/codegen.iyi:1333 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 2 owner=bodies reason=the value of 'idx' cannot be typed example=src/compiler/native/wasm/codegen.iyi:1335 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 2 owner=bodies reason=the value of 'stack_top' cannot be typed example=src/compiler/native/wasm/codegen.iyi:1359 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 2 owner=bodies reason=undefined local variable or method 'wasm_name' for Compiler::Native::Wasm::Module::WasmModule example=src/compiler/native/wasm/module.iyi:139 in Compiler::Native::Wasm::Module::WasmModule#add_export
table: compile_native refusal 2 owner=bodies reason=the value of 'keys' cannot be typed example=src/compiler/native/wasm/module.iyi:240 in Compiler::Native::Wasm::Module::WasmModule#write
table: compile_native refusal 2 owner=bodies reason=the value of 'acc' cannot be typed example=src/compiler/native/emit.iyi:70 in Compiler::Tools::CompileNative::CompileNative.class#to_bytes
table: compile_native refusal 2 owner=unassigned reason=wrong number of arguments for 'Int32#in?' (given 7, expected 1) example=src/iyi/./string.iyi:670 in Char#whitespace?
table: compile_native refusal 2 owner=bodies reason=undefined local variable or method 'compile_module' for Compiler::Tools::CompileNative::CompileNative.class example=src/compiler/native/driver.iyi:239 in Compiler::Tools::CompileNative::CompileNative.class#link_native_program
table: compile_native refusal 2 owner=bodies reason=the value of '__temp_3' cannot be typed example=no location in Compiler::Tools::CompileNative::CompileNative.class#link_native_program
table: compile_native refusal 2 owner=bodies reason=the value of '__temp_4' cannot be typed example=no location in Compiler::Tools::CompileNative::CompileNative.class#link_native_program
table: compile_native refusal 1 owner=unassigned reason=type mismatch for return type: expected IyiSchedulerState, got (IyiSchedulerState | Nil) example=src/iyi/./concurrency.iyi:1793 in IyiScheduler.class#state
table: compile_native refusal 1 owner=calls reason=undefined method 'chaos_unit' for IyiFiber example=src/iyi/./chaos.iyi:264 in IyiChaos.class#unit_of
table: compile_native refusal 1 owner=declarations reason=undefined constant HIGH example=src/iyi/./chaos.iyi:267 in IyiChaos.class#unit_of
table: compile_native refusal 1 owner=calls reason=undefined method 'chaos_unit=' for IyiFiber example=src/iyi/./chaos.iyi:269 in IyiChaos.class#unit_of
table: compile_native refusal 1 owner=declarations reason=undefined constant LOW example=src/iyi/./chaos.iyi:348 in IyiChaos.class#step
table: compile_native refusal 1 owner=declarations reason=undefined constant SPIN_STEPS example=src/iyi/./chaos.iyi:350 in IyiChaos.class#step
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiChaos.unit_of' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./chaos.iyi:373 in IyiChaos.class#outranked?
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.cancel' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:7245 in IyiGroup#cancel_children_locked
table: compile_native refusal 1 owner=declarations reason=undefined constant POLL_EVERY example=src/iyi/./concurrency.iyi:2591 in IyiScheduler.class#reschedule
table: compile_native refusal 1 owner=declarations reason=undefined constant POLL_IO_NS example=src/iyi/./concurrency.iyi:2761 in IyiScheduler.class#poll_now
table: compile_native refusal 1 owner=calls reason=undefined method 'awaited' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3986 in IyiScheduler.class#deadlock_found
table: compile_native refusal 1 owner=calls reason=undefined method 'joining' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3988 in IyiScheduler.class#deadlock_found
table: compile_native refusal 1 owner=calls reason=undefined method 'deadlocked=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3994 in IyiScheduler.class#deadlock_found
table: compile_native refusal 1 owner=bodies reason=the value of 'head_deadline' cannot be typed example=src/iyi/./concurrency.iyi:4047 in IyiScheduler.class#wait_for_events
table: compile_native refusal 1 owner=bodies reason=the value of 'gap' cannot be typed example=src/iyi/./concurrency.iyi:4048 in IyiScheduler.class#wait_for_events
table: compile_native refusal 1 owner=calls reason=expected argument #2 to 'IyiScheduler.heap_remove' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:4661 in IyiScheduler.class#wake_expired_sleepers
table: compile_native refusal 1 owner=calls reason=undefined method 'io_timed' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4662 in IyiScheduler.class#wake_expired_sleepers
table: compile_native refusal 1 owner=calls reason=undefined method 'io_timed=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4664 in IyiScheduler.class#wake_expired_sleepers
table: compile_native refusal 1 owner=calls reason=undefined method 'timed_out=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4665 in IyiScheduler.class#wake_expired_sleepers
table: compile_native refusal 1 owner=calls reason=undefined method 'next_cancel' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2323 in IyiScheduler.class#take_mail
table: compile_native refusal 1 owner=calls reason=undefined method 'next_cancel=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2324 in IyiScheduler.class#take_mail
table: compile_native refusal 1 owner=calls reason=undefined method 'cancel_posted=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2325 in IyiScheduler.class#take_mail
table: compile_native refusal 1 owner=calls reason=undefined method 'listed_on' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2326 in IyiScheduler.class#take_mail
table: compile_native refusal 1 owner=calls reason=undefined method 'waiting_out' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2327 in IyiScheduler.class#take_mail
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.cancel_wait' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:2328 in IyiScheduler.class#take_mail
table: compile_native refusal 1 owner=calls reason=undefined method 'each' for Nil (compile-time type is (Array(Int32) | Nil)) example=src/iyi/./concurrency.iyi:2335 in IyiScheduler.class#take_mail
table: compile_native refusal 1 owner=declarations reason=undefined constant PREEMPTED_TURN example=src/iyi/./concurrency.iyi:7 in IyiScheduler.class#worker_next
table: compile_native refusal 1 owner=calls reason=undefined method 'home' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:5514 in IyiWorkers.class#take_queued
table: compile_native refusal 1 owner=calls reason=undefined method 'home=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:5520 in IyiWorkers.class#take_queued
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.wake_completed' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/concurrency.iyi:71 in IyiScheduler.class#take_held
table: compile_native refusal 1 owner=calls reason=expected argument #2 to 'IyiScheduler.take_unit' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:19 in IyiScheduler.class#worker_next
table: compile_native refusal 1 owner=calls reason=undefined method 'give' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:2721 in IyiScheduler.class#release_unit
table: compile_native refusal 1 owner=calls reason=undefined method 'waiting?' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:2722 in IyiScheduler.class#release_unit
table: compile_native refusal 1 owner=calls reason=expected argument #2 to 'IyiScheduler.drain_unit' to be IyiUnit, not (IyiUnit | Nil) example=src/iyi/./concurrency.iyi:2724 in IyiScheduler.class#release_unit
table: compile_native refusal 1 owner=calls reason=undefined method 'quiet' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2500 in IyiScheduler.class#all_quiet?
table: compile_native refusal 1 owner=calls reason=undefined method 'idle' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: compile_native refusal 1 owner=bodies reason=the value of 'quiet' cannot be typed example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: compile_native refusal 1 owner=calls reason=undefined method 'mail?' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: compile_native refusal 1 owner=calls reason=undefined method 'next_state' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2506 in IyiScheduler.class#all_quiet?
table: compile_native refusal 1 owner=calls reason=undefined method 'panicked' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:7213 in IyiGroup#join
table: compile_native refusal 1 owner=calls reason=undefined method 'panic_delivered' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:7213 in IyiGroup#join
table: compile_native refusal 1 owner=calls reason=undefined method 'panic_delivered=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:7214 in IyiGroup#join
table: compile_native refusal 1 owner=calls reason=undefined method 'panic_message' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:7220 in IyiGroup#join
table: compile_native refusal 1 owner=calls reason=undefined method 'join' for Nil (compile-time type is (IyiGroup | Nil)) example=src/iyi/./concurrency.iyi:5060 in IyiScheduler.class#panic_current
table: compile_native refusal 1 owner=calls reason=undefined method 'child_panicked' for Nil (compile-time type is (IyiGroup | Nil)) example=src/iyi/./concurrency.iyi:5078 in IyiScheduler.class#panic_current
table: compile_native refusal 1 owner=calls reason=undefined method 'awaited=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3620 in IyiScheduler.class#wake_joiners
table: compile_native refusal 1 owner=declarations reason=undefined constant FNV_PRIME example=src/iyi/./chaos.iyi:254 in IyiChaos.class#fold
table: compile_native refusal 1 owner=calls reason=undefined method 'chaos_held=' for IyiFiber example=src/iyi/./chaos.iyi:357 in IyiChaos.class#step
table: compile_native refusal 1 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:5659 in IyiWorkers.class#handed_on?
table: compile_native refusal 1 owner=declarations reason=undefined constant THREADS example=src/iyi/./chaos.iyi:314 in IyiChaos.class#point
table: compile_native refusal 1 owner=calls reason=undefined method 'hand_to_yielded' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:5 in IyiWorkers.class#give_up
table: compile_native refusal 1 owner=calls reason=undefined method 'take_yielded' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:9 in IyiWorkers.class#give_up
table: compile_native refusal 1 owner=declarations reason=undefined constant UNMARKED example=src/iyi/./concurrency.iyi:1572 in IyiChanLock.class#contend
table: compile_native refusal 1 owner=bodies reason=the value of 'taken' cannot be typed example=src/iyi/./concurrency.iyi:1573 in IyiChanLock.class#contend
table: compile_native refusal 1 owner=calls reason=expected argument #2 to 'IyiAtomic.rmw' to be Pointer(<unresolved T>), not Pointer(UInt64) example=src/iyi/prelude.iyi:104 in IyiRuntimeLock.class#lock
table: compile_native refusal 1 owner=declarations reason=undefined constant YIELD_AFTER example=src/iyi/thread.iyi:854 in IyiThread.class#lock_turn
table: compile_native refusal 1 owner=calls reason=undefined method '!=' for NoReturn example=src/iyi/prelude.iyi:1 in IyiRuntimeLock.class#lock
table: compile_native refusal 1 owner=unassigned reason=type mismatch for return type: expected IyiFiber, got (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:1829 in IyiScheduler.class#current
table: compile_native refusal 1 owner=unassigned reason=instance variable '@state' of IyiFiber must be IyiFiberState, not (IyiFiberState | Int32) example=src/iyi/./concurrency.iyi:635 in IyiFiber#initialize
table: compile_native refusal 1 owner=calls reason=undefined method 'prev_fiber=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1863 in IyiScheduler.class#register
table: compile_native refusal 1 owner=calls reason=undefined method 'on_cpu=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1917 in IyiScheduler.class#landed
table: compile_native refusal 1 owner=declarations reason=undefined constant STACK_BYTES example=src/iyi/./concurrency.iyi:926 in IyiFiber#release_stack
table: compile_native refusal 1 owner=calls reason=undefined method 'release_stack' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1932 in IyiScheduler.class#reap_dying
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.unregister' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:1933 in IyiScheduler.class#reap_dying
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'Pointer#copy_from' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/./io.iyi:313 in IyiIO#write
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.load' to be Pointer(<unresolved T>), not Pointer(UInt64) example=src/iyi/prelude.iyi:3 in IyiOnce.class#run
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.cmpxchg' to be Pointer(<unresolved T>), not Pointer(UInt64) example=src/iyi/prelude.iyi:4 in IyiOnce.class#run
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiAtomic.store' to be Pointer(<unresolved T>), not Pointer(UInt64) example=src/iyi/prelude.iyi:3 in IyiOnce.class#run
table: compile_native refusal 1 owner=declarations reason=undefined constant NATIVE_TARGETS example=src/compiler/backend/backend.iyi:40 in Compiler::Backend::Backend::Backend.class#backend_for
table: compile_native refusal 1 owner=declarations reason=undefined constant IyiPath example=src/compiler/loader.iyi:131 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'iyi_path' for Compiler::Loader::Loader.class example=no location in Compiler::Loader::Loader.class#new
table: compile_native refusal 1 owner=unassigned reason=undefined fun 'fstat' for Compiler::Tools::CompileNative::LibC example=src/iyi/concurrency.iyi:7 in IyiScheduler.class#regular_file?
table: compile_native refusal 1 owner=bodies reason=the value of 'added' cannot be typed example=src/iyi/./concurrency.iyi:12 in IyiScheduler.class#wait_posix
table: compile_native refusal 1 owner=unassigned reason=undefined fun 'error_location' for Compiler::Tools::CompileNative::LibC example=src/iyi/./concurrency.iyi:14 in IyiScheduler.class#wait_posix
table: compile_native refusal 1 owner=calls reason=undefined method 'next_io=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3485 in IyiScheduler.class#io_unlink
table: compile_native refusal 1 owner=unassigned reason=type mismatch for return type: expected (Cancelled | Int64), got (Cancelled | Nil) example=src/iyi/./concurrency.iyi:4887 in IyiScheduler.class#read_posix
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'target' for IyiIO example=src/iyi/./io.iyi:194 in IyiIO#read_all
table: compile_native refusal 1 owner=declarations reason=undefined constant IrParser example=src/compiler/ir/parser.iyi:27 in Compiler::Tools::CompileNative::CompileNative.class#parse
table: compile_native refusal 1 owner=calls reason=undefined method 'to_s' for <unresolved IrParseError> (compile-time type is (<unresolved IrParseError> | Compiler::Ir::Module::Module)) example=src/compiler/tools/compile_native.iyi:48 in Compiler::Tools::CompileNative::CompileNative.class#module_of
table: compile_native refusal 1 owner=declarations reason=undefined constant Verifier example=src/compiler/ir/verifier.iyi:30 in Compiler::Tools::CompileNative::CompileNative.class#verify
table: compile_native refusal 1 owner=declarations reason=undefined constant WasmCtx example=src/compiler/native/wasm/codegen.iyi:1279 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 1 owner=bodies reason=the value of 'addr' cannot be typed example=src/compiler/native/wasm/codegen.iyi:1300 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'stack_size' for Compiler::Tools::CompileNative::CompileNative.class example=src/compiler/native/wasm/codegen.iyi:1358 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 1 owner=bodies reason=the value of 'pages' cannot be typed example=src/compiler/native/wasm/codegen.iyi:1360 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 1 owner=bodies reason=the value of 'sp' cannot be typed example=src/compiler/native/wasm/codegen.iyi:1363 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'i32_const_expr' for Compiler::Native::Wasm::Module::WasmModule example=src/compiler/native/wasm/module.iyi:157 in Compiler::Native::Wasm::Module::WasmModule#add_element
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'h' for Hash(Int32, Array(UInt8)) example=src/iyi/./hash.iyi:564 in Hash(Int32, Array(UInt8))#slot_for
table: compile_native refusal 1 owner=unassigned reason=wrong number of arguments for 'Proc(Hash(Int32, Array(UInt8)), Int32, Array(UInt8))#call' (given 2, expected 1) example=src/iyi/./hash.iyi:97 in Hash(Int32, Array(UInt8))#[]
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'Pointer(Int32)#copy_from' to be Pointer(<unresolved T>), not Pointer(Int32) example=src/iyi/./array.iyi:824 in Array(Int32)#reserve
table: compile_native refusal 1 owner=calls reason=undefined method 'new' for Slice(UInt8).class example=src/compiler/native/emit.iyi:67 in Compiler::Tools::CompileNative::CompileNative.class#to_bytes
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'String.new' to be Int32 or Array(UInt8) or Std::Slice::Slice(UInt8), not Std::Slice::Bytes example=src/compiler/tools/compile_native.iyi:183 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'buffer' for Char example=src/iyi/./string.iyi:592 in Char#to_s
table: compile_native refusal 1 owner=bodies reason=the value of 'objects' cannot be typed example=src/compiler/native/driver.iyi:244 in Compiler::Tools::CompileNative::CompileNative.class#link_native_program
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'libraries_of' for Compiler::Tools::CompileNative::CompileNative.class example=src/compiler/native/driver.iyi:244 in Compiler::Tools::CompileNative::CompileNative.class#link_native_program
table: compile_native defs-lowered-clean=1492 lowering-refusal-sites=1265
table: compile_native lowering 598 owner=bodies reason=BUG: the analysed program has no type for the body of grow (hosted codegen_fun: return type) example=Array(String)#grow
table: compile_native lowering 57 owner=bodies reason=BUG: the analysed program has no type for the body of add (hosted codegen_fun: return type) example=Atomic(UInt64)#add
table: compile_native lowering 45 owner=bodies reason=BUG: the analysed program has no type for the body of get (hosted codegen_fun: return type) example=Atomic(UInt64)#get
table: compile_native lowering 33 owner=bodies reason=BUG: the analysed program has no type for the body of sub (hosted codegen_fun: return type) example=Atomic(Int64)#sub
table: compile_native lowering 32 owner=bodies reason=BUG: the analysed program has no type for the body of unlock (hosted codegen_fun: return type) example=IyiSchedLock.class#unlock
table: compile_native lowering 32 owner=bodies reason=BUG: the analysed program has no type for the body of compare_and_set (hosted codegen_fun: return type) example=Atomic(UInt64)#compare_and_set
table: compile_native lowering 28 owner=bodies reason=BUG: the analysed program has no type for the body of set (hosted codegen_fun: return type) example=Atomic(UInt64)#set
table: compile_native lowering 27 owner=bodies reason=BUG: the analysed program has no type for the body of state_id (hosted codegen_fun: return type) example=IyiScheduler.class#state_id
table: compile_native lowering 18 owner=bodies reason=BUG: the analysed program has no type for the body of start (hosted codegen_fun: return type) example=IyiThread.class#start
table: compile_native lowering 17 owner=lowering core reason=lower: visit(Cast) (hosted codegen.cr) is not ported yet example=UInt64#__iyi_say
table: compile_native lowering 16 owner=lowering core reason=lower: visit(UninitializedVar) (hosted codegen.cr) is not ported yet example=UInt64#raise
table: compile_native lowering 13 owner=unassigned reason=lower: is_a? of (IyiFiber | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiChaos.class#outranked?
table: compile_native lowering 11 owner=bodies reason=lower: visit(pointerof of a ClassVar (hosted codegen.cr: visit(PointerOf), only a local variable is ported)) (hosted codegen.cr) is not ported yet example=IyiSchedLock.class#word
table: compile_native lowering 11 owner=lowering core reason=BUG: create_llvm_type for T is not ported yet (hosted llvm_typer.cr) example=Array#[]
table: compile_native lowering 11 owner=bodies reason=BUG: the analysed program has no type for the body of uleb_i (hosted codegen_fun: return type) example=Compiler::Native::Wasm::Module::WasmModule#uleb_i
table: compile_native lowering 9 owner=lowering core reason=lower: visit(MagicConstant) (hosted codegen.cr) is not ported yet example=UInt64#%
table: compile_native lowering 9 owner=bodies reason=BUG: the analysed program has no type for the body of wake_one (hosted codegen_fun: return type) example=IyiWorkers.class#wake_one
table: compile_native lowering 9 owner=lowering core reason=lower: visit(a call to a def with a &block parameter (hosted call.cr: codegen_call_with_block_as_fun_literal, closures)) (hosted codegen.cr) is not ported yet example=IyiTestCases.class#verdict
table: compile_native lowering 7 owner=lowering core reason=lower: visit(Assign to a parameter (hosted fun.cr, create_local_copy_of_arg)) (hosted codegen.cr) is not ported yet example=String#includes?
table: compile_native lowering 7 owner=unassigned reason=Cast from Compiler::Types::Types::GenericClassInstanceType to Compiler::Semantic::TopLevel::ClassType+ failed, at src/compiler/lower/primitives.iyi:718:11:718 example=Array(String).class#new
table: compile_native lowering 6 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of set (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#free_lists
table: compile_native lowering 6 owner=lowering core reason=lower: visit(ArrayLiteral) (hosted codegen.cr) is not ported yet example=Compiler::Tools::CompileNative::CompileNative.class#start_wasm32_ir
table: compile_native lowering 5 owner=unassigned reason=lower: a bare return from a function that returns a value (hosted codegen_return, the nil upcast) example=IyiSchedLock.class#lock
table: compile_native lowering 5 owner=lowering core reason=lower: visit(pointer_get of Atomic(UInt64) (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=IyiChanLock.class#acquire
table: compile_native lowering 5 owner=unassigned reason=lower: instance variable @size of Array(Int32): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(Int32)#each
table: compile_native lowering 5 owner=bodies reason=BUG: the analysed program has no type for the body of set_slot (hosted codegen_fun: return type) example=IyiSchedulerState#set_slot
table: compile_native lowering 5 owner=bodies reason=BUG: the analysed program has no type for the body of run (hosted codegen_fun: return type) example=IyiDeferNode#run
table: compile_native lowering 5 owner=bodies reason=BUG: the analysed program has no type for the body of __iyi_read (hosted codegen_fun: return type) example=IyiScheduler.class#__iyi_read
table: compile_native lowering 4 owner=bodies reason=BUG: the analysed program has no type for the body of initialize (hosted codegen_fun: return type) example=Atomic(UInt64)#initialize
table: compile_native lowering 4 owner=unassigned reason=a function or global named IyiScheduler::shared already exists example=IyiScheduler.class#shared?
table: compile_native lowering 4 owner=calls reason=BUG: the call to st has no target def (hosted call.cr: visit(Call)) example=IyiScheduler.class#poll_now
table: compile_native lowering 4 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of compare_and_set (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiFiber#claim
table: compile_native lowering 4 owner=bodies reason=BUG: the analysed program has no type for the body of slot (hosted codegen_fun: return type) example=IyiSchedulerState#slot
table: compile_native lowering 4 owner=unassigned reason=lower: instance variable @size of Array(String): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(String)#initialize
table: compile_native lowering 4 owner=bodies reason=BUG: the analysed program has no type for the body of __iyi_write (hosted codegen_fun: return type) example=File.class#__iyi_write
table: compile_native lowering 4 owner=unassigned reason=lower: instance variable @size of Array(UInt8): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(UInt8)#initialize
table: compile_native lowering 4 owner=unassigned reason=BUG: a primitive call has no receiver (hosted call.cr: codegen_primitive) example=Char#to_s
table: compile_native lowering 3 owner=bodies reason=BUG: the analysed program has no type for a branch (hosted codegen.cr: visit(If)) example=IyiScheduler.class#reschedule
table: compile_native lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of io_slot (hosted codegen_fun: return type) example=IyiScheduler.class#io_slot
table: compile_native lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of spin_pause (hosted codegen_fun: return type) example=IyiThread.class#spin_pause
table: compile_native lowering 3 owner=unassigned reason=a function or global named ~STDOUT:const_read already exists example=IyiScheduler.class#__iyi_flush_std
table: compile_native lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of swap (hosted codegen_fun: return type) example=Atomic(UInt64)#swap
table: compile_native lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of __iyi_open_read (hosted codegen_fun: return type) example=File.class#__iyi_open_read
table: compile_native lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of io_chunk (hosted codegen_fun: return type) example=IyiScheduler.class#io_chunk
table: compile_native lowering 3 owner=unassigned reason=lower: instance variable @size of Array(Array(UInt8)): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(Array(UInt8))#initialize
table: compile_native lowering 2 owner=lowering core reason=lower: visit(a class method call on a receiver that is not a constant path (hosted call.cr: prepare_call_args, Path)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#current
table: compile_native lowering 2 owner=bodies reason=BUG: (IyiSchedulerState | Nil) has no type id (not reachable from Object) example=IyiScheduler.class#state
table: compile_native lowering 2 owner=lowering core reason=lower: visit(allocate of class IyiSchedulerState: the :headed byte is the program-wide census (lower/headed.iyi, NEEDS.md rows 26-27), not decided) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#first_state_here
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of draw (hosted codegen_fun: return type) example=IyiChaos.class#draw
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of deadlock (hosted codegen_fun: return type) example=IyiScheduler.class#deadlock
table: compile_native lowering 2 owner=lowering core reason=lower: visit(binary == on Int64 and Int32 (mixed operands, hosted codegen_binary_extend_int)) (hosted codegen.cr) is not ported yet example=Int64#//
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of wake_io (hosted codegen_fun: return type) example=IyiScheduler.class#wake_io
table: compile_native lowering 2 owner=unassigned reason=lower: is_a? of (Array(IyiFiber | Nil) | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiScheduler.class#io_take
table: compile_native lowering 2 owner=lowering core reason=BUG: llvm_struct_type of Array is not ported yet (hosted create_llvm_struct_type) example=Array#size
table: compile_native lowering 2 owner=lowering core reason=lower: visit(Pointer#malloc with a count that is not the size type (hosted generic_array_malloc: builder.mul of the size and the count)) (hosted codegen.cr) is not ported yet example=IyiIO#initialize
table: compile_native lowering 2 owner=calls reason=BUG: the call to target_fd has no target def (hosted call.cr: visit(Call)) example=IyiIO#low_level_write
table: compile_native lowering 2 owner=lowering core reason=lower: visit(primitive object_id (hosted codegen_primitive, primitives.cr)) (hosted codegen.cr) is not ported yet example=IyiGroup#child_panicked
table: compile_native lowering 2 owner=calls reason=BUG: the call to fiber has no target def (hosted call.cr: visit(Call)) example=IyiWorkers.class#chaos_give_up
table: compile_native lowering 2 owner=unassigned reason=lower: class variable @@line has a literal initialiser that is not an integer, Bool or Char (hosted class_var.cr: initialize_class_var) example=IyiThread.class#stop_here
table: compile_native lowering 2 owner=lowering core reason=lower: visit(allocate of class IyiFiber: the :headed byte is the program-wide census (lower/headed.iyi, NEEDS.md rows 26-27), not decided) (hosted codegen.cr) is not ported yet example=IyiFiber.class#main
table: compile_native lowering 2 owner=lowering core reason=lower: visit(a class method call on Array(T).class (hosted call.cr: prepare_call_args, a generic or builtin metaclass)) (hosted codegen.cr) is not ported yet example=Std::Base64::Base64.class#decode_values
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of __iyi_close (hosted codegen_fun: return type) example=File.class#__iyi_close
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of read (hosted codegen_fun: return type) example=File.class#read
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of __iyi_defer_push (hosted codegen_fun: return type) example=File.class#__iyi_defer_push
table: compile_native lowering 2 owner=calls reason=BUG: the call to fd has no target def (hosted call.cr: visit(Call)) example=IyiIO#iyi_read
table: compile_native lowering 2 owner=lowering core reason=lower: visit(pointer_set of (IyiFiber | Nil) (hosted assign, primitives.cr 927)) (hosted codegen.cr) is not ported yet example=Pointer((IyiFiber | Nil))#[]=
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of heap_remove (hosted codegen_fun: return type) example=IyiScheduler.class#heap_remove
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of __iyi_defer_pop_run (hosted codegen_fun: return type) example=File.class#__iyi_defer_pop_run
table: compile_native lowering 2 owner=lowering core reason=lower: visit(allocate of class String::Builder: the :headed byte is the program-wide census (lower/headed.iyi, NEEDS.md rows 26-27), not decided) (hosted codegen.cr) is not ported yet example=String.class#build
table: compile_native lowering 2 owner=unassigned reason=lower: instance variable @size of Hash(Int32, String): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Hash(Int32, String)#initialize
table: compile_native lowering 2 owner=unassigned reason=lower: instance variable @size of Array(Compiler::Ir::Module::Module.class): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(Compiler::Ir::Module::Module.class)#each
table: compile_native lowering 2 owner=unassigned reason=lower: instance variable @size of Array(Compiler::Native::Obj::Object::ObjectFile.class): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(Compiler::Native::Obj::Object::ObjectFile.class)#each
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(IyiFiber | Nil) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiScheduler.class#run_spawned_fiber
table: compile_native lowering 1 owner=lowering core reason=lower: visit(a class method call on Atomic(UInt64).class (hosted call.cr: prepare_call_args, a generic or builtin metaclass)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#initialize
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Atomic(UInt64) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Atomic(UInt64).class#new
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to == (hosted call.cr: visit(Call)) example=IyiChaos.class#at_atomic
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to state (hosted call.cr: visit(Call)) example=IyiChaos.class#step
table: compile_native lowering 1 owner=unassigned reason=a function or global named IyiScheduler::state already exists example=IyiSchedLock.class#held_here?
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to chaos_unit (hosted call.cr: visit(Call)) example=IyiChaos.class#unit_of
table: compile_native lowering 1 owner=bodies reason=lower: visit(pointerof of a InstanceVar (hosted codegen.cr: visit(PointerOf), only a local variable is ported)) (hosted codegen.cr) is not ported yet example=String#to_unsafe
table: compile_native lowering 1 owner=unassigned reason=lower: class variable @@resolver is not an integer, a float or a nilable reference: the struct and the non-nilable pointer initialisers are not ported yet (hosted class_var.cr: initialize_class_var) example=IyiPanic.class#resolver
table: compile_native lowering 1 owner=lowering core reason=lower: visit(a call to held_here? with no receiver inside a class method (hosted call.cr: prepare_call_args, the metaclass owner)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#panic_current
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to store (hosted call.cr: visit(Call)) example=IyiSchedLock.class#release_held
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of join (hosted codegen_fun: return type) example=IyiGroup#join
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to at_atomic (hosted call.cr: visit(Call)) example=IyiSchedulerState#take_lists
table: compile_native lowering 1 owner=lowering core reason=BUG: create_llvm_type for <unresolved T> is not ported yet (hosted llvm_typer.cr) example=Tuple(<unresolved T>, Bool)#[]
table: compile_native lowering 1 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of add (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiFiber#claim_any
table: compile_native lowering 1 owner=lowering core reason=lower: visit(binary > on Int64 and Int32 (mixed operands, hosted codegen_binary_extend_int)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#pollfd
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to malloc (hosted call.cr: visit(Call)) example=IyiScheduler.class#events_buffer
table: compile_native lowering 1 owner=calls reason=BUG: the call to entry has no target def (hosted call.cr: visit(Call)) example=IyiScheduler.class#event_ready
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @size of Array(IyiFiber | Nil): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(IyiFiber | Nil)#size
table: compile_native lowering 1 owner=lowering core reason=lower: visit(pointer_get of (IyiFiber | Nil) (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=Pointer((IyiFiber | Nil))#[]
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of end_idle (hosted codegen_fun: return type) example=IyiScheduler.class#end_idle
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Atomic(Int64) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiWorkers.class#word
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to shared? (hosted call.cr: visit(Call)) example=IyiScheduler.class#take_mail
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(Int32) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiSchedulerState#closed_fds
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to value (hosted call.cr: visit(Call)) example=IyiWorkers.class#pop
table: compile_native lowering 1 owner=unassigned reason=lower: is_a? of (Array | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiWorkers.class#steal_unstarted
table: compile_native lowering 1 owner=lowering core reason=lower: visit(a call with default arguments or a splat (hosted call.cr)) (hosted codegen.cr) is not ported yet example=IyiWorkers.class#__iyi_flush_std
table: compile_native lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiIO: the :headed byte is the program-wide census (lower/headed.iyi, NEEDS.md rows 26-27), not decided) (hosted codegen.cr) is not ported yet example=IyiIO.class#new
table: compile_native lowering 1 owner=lowering core reason=lower: taken is declared (IyiFiber | Nil) and assigned Nil: the hosted upcast is not ported yet example=IyiScheduler.class#take_held
table: compile_native lowering 1 owner=lowering core reason=lower: visit(a call to word with no receiver inside a class method (hosted call.cr: prepare_call_args, the metaclass owner)) (hosted codegen.cr) is not ported yet example=IyiWorkers.class#runtime_lock_free?
table: compile_native lowering 1 owner=unassigned reason=lower: is_a? of (IyiUnit | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiScheduler.class#release_unit
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to ensure_doorbell (hosted call.cr: visit(Call)) example=IyiScheduler.class#wait_shared
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of child_finished (hosted codegen_fun: return type) example=IyiGroup#child_finished
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to memory (hosted call.cr: visit(Call)) example=String.class#new
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of fold (hosted codegen_fun: return type) example=IyiChaos.class#fold
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to state= (hosted call.cr: visit(Call)) example=IyiScheduler.class#enqueue
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of thread_point (hosted codegen_fun: return type) example=IyiChaos.class#thread_point
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of give_up (hosted codegen_fun: return type) example=IyiWorkers.class#give_up
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of hand_to_yielded (hosted codegen_fun: return type) example=IyiUnit#hand_to_yielded
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of take_yielded (hosted codegen_fun: return type) example=IyiUnit#take_yielded
table: compile_native lowering 1 owner=lowering core reason=lower: visit(binary != on Int64 and Int32 (mixed operands, hosted codegen_binary_extend_int)) (hosted codegen.cr) is not ported yet example=IyiThread.class#lock_turn
table: compile_native lowering 1 owner=unassigned reason=lower: class variable @@control has a literal initialiser that is not an integer, Bool or Char (hosted class_var.cr: initialize_class_var) example=IyiThread.class#control
table: compile_native lowering 1 owner=unassigned reason=lower: class variable @@cache has a literal initialiser that is not an integer, Bool or Char (hosted class_var.cr: initialize_class_var) example=IyiThread.class#park_if_requested
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of stop_requested? (hosted codegen_fun: return type) example=IyiHeap.class#stop_requested?
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of clear_request (hosted codegen_fun: return type) example=IyiHeap.class#clear_request
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of park (hosted codegen_fun: return type) example=IyiThread.class#park
table: compile_native lowering 1 owner=lowering core reason=lower: visit(binary == on UInt64 and Int32 (mixed operands, hosted codegen_binary_extend_int)) (hosted codegen.cr) is not ported yet example=IyiThread.class#owe_turn
table: compile_native lowering 1 owner=lowering core reason=lower: visit(MacroFor) (hosted codegen.cr) is not ported yet example=Tuple(Int64, UInt64)#[]
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of lock_taken (hosted codegen_fun: return type) example=IyiThread.class#lock_taken
table: compile_native lowering 1 owner=lowering core reason=lower: visit(assign Int32 to IyiFiberState (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=IyiFiber#initialize
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of register (hosted codegen_fun: return type) example=IyiScheduler.class#register
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of reap_dying (hosted codegen_fun: return type) example=IyiScheduler.class#reap_dying
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of release_stack (hosted codegen_fun: return type) example=IyiFiber#release_stack
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(String) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Program.class#args
table: compile_native lowering 1 owner=lowering core reason=lower: visit(pointer_get of String (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=Pointer(String)#[]
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of no_backend_message (hosted codegen_fun: return type) example=Compiler::Backend::Backend::Backend.class#no_backend_message
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to includes? (hosted call.cr: visit(Call)) example=Compiler::Backend::Backend::Backend.class#backend_for
table: compile_native lowering 1 owner=calls reason=BUG: the call to path has no target def (hosted call.cr: visit(Call)) example=File.class#exists?
table: compile_native lowering 1 owner=lowering core reason=lower: codegen_cond of (Int32 | Nil) is not ported yet (hosted cond.cr: nilable and union tests, slice S2c) example=File.class#c_path
table: compile_native lowering 1 owner=lowering core reason=lower: visit(allocate of class Compiler::Backend::Native::NativeBackend: the :headed byte is the program-wide census (lower/headed.iyi, NEEDS.md rows 26-27), not decided) (hosted codegen.cr) is not ported yet example=Compiler::Backend::Native::NativeBackend.class#new
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to puts (hosted call.cr: visit(Call)) example=Compiler::Tools::CompileNative::CompileNative.class#fail
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to close (hosted call.cr: visit(Call)) example=IyiIO#low_level_close
table: compile_native lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiDeferNode: the :headed byte is the program-wide census (lower/headed.iyi, NEEDS.md rows 26-27), not decided) (hosted codegen.cr) is not ported yet example=IyiDeferNode.class#new
table: compile_native lowering 1 owner=lowering core reason=lower: visit(assign Proc(Nil) to Proc (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=IyiDeferNode#initialize
table: compile_native lowering 1 owner=unassigned reason=lower: is_a? of (IyiDeferNode | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=File.class#__iyi_defer_push_node
table: compile_native lowering 1 owner=unassigned reason=lower: return of Cancelled from a function returning another type (hosted upcast, the casts slice) example=IyiScheduler.class#wait_readable_posix
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of io_owner (hosted codegen_fun: return type) example=IyiScheduler.class#io_owner
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to sleep_head= (hosted call.cr: visit(Call)) example=IyiScheduler.class#arm_deadline
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of heap_insert (hosted codegen_fun: return type) example=IyiScheduler.class#heap_insert
table: compile_native lowering 1 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of swap (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiFiber#list_on
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of cancel_wait (hosted codegen_fun: return type) example=IyiScheduler.class#cancel_wait
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of io_owner_clear (hosted codegen_fun: return type) example=IyiScheduler.class#io_owner_clear
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to low_level_read (hosted call.cr: visit(Call)) example=IyiIO#fill_buffer
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to raise (hosted call.cr: visit(Call)) example=String#[]
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(Compiler::Ir::Types::IrType) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Compiler::Tools::CompileNative::CompileNative.class#module_of
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse (hosted codegen_fun: return type) example=Compiler::Tools::CompileNative::CompileNative.class#parse
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of verify (hosted codegen_fun: return type) example=Compiler::Tools::CompileNative::CompileNative.class#verify
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(<unresolved IrError>) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Array(<unresolved IrError>)#each
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of [] (hosted codegen_fun: return type) example=Pointer(<unresolved IrError>)#[]
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @size of Array(<unresolved IrError>): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(<unresolved IrError>)#empty?
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @capacity of Array(String): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(String)#reserve
table: compile_native lowering 1 owner=lowering core reason=lower: visit(pointer_set of String (hosted assign, primitives.cr 927)) (hosted codegen.cr) is not ported yet example=Pointer(String)#[]=
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to write (hosted call.cr: visit(Call)) example=String::Builder#<<
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(UInt8) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Hash(Int32, String) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Compiler::Native::Wasm::Module::WasmModule.class#new
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(Array(UInt8)) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Array(Array(UInt8)).class#new
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Hash(String, Int32) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Hash(String, Int32).class#new
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @size of Hash(String, Int32): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Hash(String, Int32)#initialize
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Hash(Int32, Array(UInt8)) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Hash(Int32, Array(UInt8)).class#new
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @size of Hash(Int32, Array(UInt8)): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Hash(Int32, Array(UInt8))#initialize
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(Compiler::Ir::Module::Module.class) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Array(Compiler::Ir::Module::Module.class).class#unsafe_build
table: compile_native lowering 1 owner=lowering core reason=lower: visit(pointer_get of Compiler::Ir::Module::Module.class (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=Pointer(Compiler::Ir::Module::Module.class)#[]
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(Compiler::Ir::Function::Global) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Array(Compiler::Ir::Function::Global).class#new
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @size of Array(Compiler::Ir::Function::Global): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(Compiler::Ir::Function::Global)#initialize
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @capacity of Array(UInt8): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(UInt8)#reserve
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Hash(String, Bool) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Hash(String, Bool).class#new
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @size of Hash(String, Bool): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Hash(String, Bool)#initialize
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(Compiler::Ir::Function::Function) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Array(Compiler::Ir::Function::Function).class#new
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(Compiler::Ir::Inst::Attribute) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Array(Compiler::Ir::Function::Function)#initialize
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @size of Array(Compiler::Ir::Function::Function): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(Compiler::Ir::Function::Function)#each
table: compile_native lowering 1 owner=lowering core reason=lower: visit(pointer_get of Compiler::Ir::Function::Function (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=Pointer(Compiler::Ir::Function::Function)#[]
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of add_element (hosted codegen_fun: return type) example=Compiler::Native::Wasm::Module::WasmModule#add_element
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @capacity of Array(Array(UInt8)): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(Array(UInt8))#reserve
table: compile_native lowering 1 owner=lowering core reason=lower: visit(pointer_set of Array(UInt8) (hosted assign, primitives.cr 927)) (hosted codegen.cr) is not ported yet example=Pointer(Array(UInt8))#[]=
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of add_export (hosted codegen_fun: return type) example=Compiler::Native::Wasm::Module::WasmModule#add_export
table: compile_native lowering 1 owner=lowering core reason=lower: visit(a restriction that does not hold for argument 0 of entry_of (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Hash(Int32, Array(UInt8))#[]
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @capacity of Hash(Int32, Array(UInt8)): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Hash(Int32, Array(UInt8))#entry_of
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of slot_for (hosted codegen_fun: return type) example=Hash(Int32, Array(UInt8))#slot_for
table: compile_native lowering 1 owner=lowering core reason=lower: visit(pointer_get of Array(UInt8) (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=Pointer(Array(UInt8))#[]
table: compile_native lowering 1 owner=lowering core reason=lower: visit(a class method call on Array(Int32).class (hosted call.cr: prepare_call_args, a generic or builtin metaclass)) (hosted codegen.cr) is not ported yet example=Hash(Int32, String)#keys
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @first of Hash(Int32, String): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Hash(Int32, String)#each
table: compile_native lowering 1 owner=lowering core reason=lower: visit(pointer_get of Bool (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=Pointer(Bool)#[]
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @capacity of Array(Int32): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(Int32)#reserve
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of to_bytes (hosted codegen_fun: return type) example=Compiler::Tools::CompileNative::CompileNative.class#to_bytes
table: compile_native lowering 1 owner=lowering core reason=lower: visit(yield with no block in scope (hosted codegen.cr: visit(Yield), a block of an enclosing block body)) (hosted codegen.cr) is not ported yet example=String#each_point
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Hash(String, Std::Slice::Bytes) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Compiler::Tools::CompileNative::CompileNative.class#link_native_program
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(Compiler::Native::Obj::Object::ObjectFile.class) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Array(Compiler::Native::Obj::Object::ObjectFile.class).class#unsafe_build
table: compile_native lowering 1 owner=lowering core reason=lower: visit(pointer_get of Compiler::Native::Obj::Object::ObjectFile.class (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=Pointer(Compiler::Native::Obj::Object::ObjectFile.class)#[]
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of chmod (hosted codegen_fun: return type) example=File.class#chmod
```
<!-- table:end -->
