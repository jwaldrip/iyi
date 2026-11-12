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

As measured on 2026-11-12, head `ed86befc5` (the port's names as the call lowering names them: a class method by its
class, `*Point::new`, as `call.iyi` passes `class_owner`):

- `hello`: hosted 698 functions; 49 match the port's clean list; 649 missing; 55 extra.
- `compile_native` (as root): hosted 10,776 functions; 51 match; 10,725 missing; 56 extra.

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

## Table

<!-- table:begin: generated by bench/selfhost_pipeline_exercise.sh; do not edit by hand -->
```text
table: hello defs-reached=28457 defs-typed-clean=15916 root-refusals=45 refusal-sites=37975
table: hello refusal 9955 owner=declarations reason=undefined constant T example=src/iyi/primitives.iyi:159 in Pointer(Atomic(UInt64))#value
table: hello refusal 4904 owner=macros reason=macro control expansion (macros engine) example=src/iyi/./primitives.iyi:100 in top level
table: hello refusal 4884 owner=bodies reason=the value of 'seen' cannot be typed example=src/iyi/./concurrency.iyi:1561 in IyiChanLock.class#acquire
table: hello refusal 2730 owner=declarations reason=primitive pointer_new without a declared return type example=src/iyi/primitives.iyi:155 in Pointer(UInt64).class#new
table: hello refusal 2070 owner=unassigned reason=can't use instance variables in Atomic(UInt64) example=src/iyi/atomic.iyi:50 in Atomic(UInt64)#initialize
table: hello refusal 1740 owner=declarations reason=undefined constant HELD example=src/iyi/./concurrency.iyi:1561 in IyiChanLock.class#acquire
table: hello refusal 1398 owner=bodies reason=the value of '__temp_1' cannot be typed example=no location in IyiChanLock.class#acquire
table: hello refusal 819 owner=bodies reason=the value of '__temp_2' cannot be typed example=no location in IyiChanLock.class#contend
table: hello refusal 710 owner=calls reason=undefined method '>' for Int32 example=src/iyi/./concurrency.iyi:1576 in IyiChanLock.class#contend
table: hello refusal 696 owner=declarations reason=undefined constant SPINNER example=src/iyi/./concurrency.iyi:1576 in IyiChanLock.class#contend
table: hello refusal 474 owner=calls reason=undefined method '<' for Int64 example=src/iyi/prelude.iyi:104 in IyiRuntimeLock.class#lock
table: hello refusal 469 owner=bodies reason=the value of '__temp_3' cannot be typed example=no location in IyiRuntimeLock.class#lock
table: hello refusal 468 owner=calls reason=expected argument #2 to 'IyiAtomic.rmw' to be Pointer(<unresolved T>), not Pointer(UInt64) example=src/iyi/prelude.iyi:104 in IyiRuntimeLock.class#lock
table: hello refusal 462 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:1737 in IyiScheduler.class#state_id
table: hello refusal 440 owner=bodies reason=the value of 'state' cannot be typed example=src/iyi/./chaos.iyi:228 in IyiChaos.class#draw
table: hello refusal 385 owner=bodies reason=the value of 'unit' cannot be typed example=src/iyi/./chaos.iyi:265 in IyiChaos.class#unit_of
table: hello refusal 362 owner=calls reason=undefined method '&+' for Int32 example=src/iyi/./concurrency.iyi:1579 in IyiChanLock.class#contend
table: hello refusal 361 owner=calls reason=expected argument #1 to 'IyiAtomic.store' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/./concurrency.iyi:1475 in IyiSchedLock.class#unlock
table: hello refusal 348 owner=declarations reason=undefined constant UNMARKED example=src/iyi/./concurrency.iyi:1572 in IyiChanLock.class#contend
table: hello refusal 348 owner=bodies reason=the value of 'taken' cannot be typed example=src/iyi/./concurrency.iyi:1573 in IyiChanLock.class#contend
table: hello refusal 348 owner=calls reason=undefined method '&-' for Int32 example=src/iyi/./concurrency.iyi:1601 in IyiChanLock.class#contend
table: hello refusal 333 owner=unassigned reason=type mismatch for return type: expected IyiSchedulerState, got (IyiSchedulerState | Nil) example=src/iyi/./concurrency.iyi:1793 in IyiScheduler.class#state
table: hello refusal 277 owner=calls reason=undefined method '&+' for UInt64 example=src/iyi/./chaos.iyi:337 in IyiChaos.class#step
table: hello refusal 220 owner=declarations reason=undefined constant GOLDEN example=src/iyi/./chaos.iyi:227 in IyiChaos.class#draw
table: hello refusal 192 owner=calls reason=expected argument #1 to 'IyiFiber#state=' to be IyiFiberState, not Int32 example=src/iyi/./concurrency.iyi:756 in IyiFiber.class#main
table: hello refusal 165 owner=declarations reason=undefined constant SIMULATED example=src/iyi/./chaos.iyi:312 in IyiChaos.class#point
table: hello refusal 135 owner=unassigned reason=type mismatch for return type: expected IyiFiber, got (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:1829 in IyiScheduler.class#current
table: hello refusal 135 owner=unassigned reason=instance variable '@state' of IyiFiber must be IyiFiberState, not (IyiFiberState | Int32) example=src/iyi/./concurrency.iyi:635 in IyiFiber#initialize
table: hello refusal 135 owner=declarations reason=primitive pointer_malloc without a declared return type example=src/iyi/primitives.iyi:151 in Pointer(UInt8).class#malloc
table: hello refusal 135 owner=calls reason=undefined method 'prev_fiber=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1863 in IyiScheduler.class#register
table: hello refusal 110 owner=calls reason=undefined method '&-' for UInt64 example=src/iyi/./chaos.iyi:353 in IyiChaos.class#step
table: hello refusal 110 owner=bodies reason=the value of 'ordinal' cannot be typed example=src/iyi/./chaos.iyi:233 in IyiChaos.class#draw
table: hello refusal 110 owner=bodies reason=undefined local variable or method 'raise' for UInt64 example=src/iyi/number.iyi:169 in UInt64#%
table: hello refusal 110 owner=bodies reason=undefined local variable or method 'unsafe_mod' for UInt64 example=src/iyi/number.iyi:170 in UInt64#%
table: hello refusal 92 owner=bodies reason=undefined local variable or method 'previous_def' for Atomic(UInt64) example=src/iyi/./chaos_points.iyi:16 in Atomic(UInt64)#get
table: hello refusal 63 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3990 in IyiScheduler.class#deadlock_found
table: hello refusal 60 owner=declarations reason=undefined constant Tuple(T, Bool) example=src/iyi/./chaos_points.iyi:39 in IyiSchedulerState#take_lists
table: hello refusal 59 owner=calls reason=undefined method 'next_run=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2154 in IyiScheduler.class#enqueue
table: hello refusal 55 owner=calls reason=undefined method 'chaos_unit' for IyiFiber example=src/iyi/./chaos.iyi:264 in IyiChaos.class#unit_of
table: hello refusal 55 owner=declarations reason=undefined constant HIGH example=src/iyi/./chaos.iyi:267 in IyiChaos.class#unit_of
table: hello refusal 55 owner=calls reason=undefined method 'chaos_unit=' for IyiFiber example=src/iyi/./chaos.iyi:269 in IyiChaos.class#unit_of
table: hello refusal 55 owner=declarations reason=undefined constant LOW example=src/iyi/./chaos.iyi:348 in IyiChaos.class#step
table: hello refusal 55 owner=declarations reason=undefined constant SPIN_STEPS example=src/iyi/./chaos.iyi:350 in IyiChaos.class#step
table: hello refusal 55 owner=calls reason=undefined method '|' for UInt64 example=src/iyi/./chaos.iyi:356 in IyiChaos.class#step
table: hello refusal 55 owner=calls reason=undefined method 'chaos_held=' for IyiFiber example=src/iyi/./chaos.iyi:357 in IyiChaos.class#step
table: hello refusal 55 owner=declarations reason=undefined constant THREADS example=src/iyi/./chaos.iyi:314 in IyiChaos.class#point
table: hello refusal 55 owner=declarations reason=undefined constant IyiThread example=src/iyi/./chaos.iyi:525 in IyiChaos.class#thread_point
table: hello refusal 48 owner=declarations reason=undefined constant DEADLOCK example=src/iyi/./concurrency.iyi:4011 in IyiScheduler.class#deadlock
table: hello refusal 46 owner=bodies reason=the value of 'total' cannot be typed example=src/iyi/io.iyi:360 in IyiIO#flush
table: hello refusal 46 owner=bodies reason=the value of 'n' cannot be typed example=src/iyi/io.iyi:362 in IyiIO#flush
table: hello refusal 32 owner=calls reason=undefined method 'state' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3997 in IyiScheduler.class#deadlock_found
table: hello refusal 32 owner=calls reason=expected argument #1 to 'IyiScheduler.enqueue' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:3998 in IyiScheduler.class#deadlock_found
table: hello refusal 23 owner=calls reason=undefined method 'to_i64' for Int32 example=src/iyi/io.iyi:358 in IyiIO#flush
table: hello refusal 20 owner=bodies reason=undefined local variable or method 'raise' for IyiIO example=src/iyi/io.iyi:284 in IyiIO#write
table: hello refusal 18 owner=bodies reason=the value of 'now' cannot be typed example=src/iyi/./concurrency.iyi:2761 in IyiScheduler.class#poll_now
table: hello refusal 16 owner=bodies reason=undefined local variable or method '__iyi_monotonic_ns' for IyiScheduler.class example=src/iyi/./concurrency.iyi:2760 in IyiScheduler.class#poll_now
table: hello refusal 16 owner=bodies reason=the value of 'task' cannot be typed example=src/iyi/./concurrency.iyi:3987 in IyiScheduler.class#deadlock_found
table: hello refusal 16 owner=bodies reason=the value of 'group' cannot be typed example=src/iyi/./concurrency.iyi:3989 in IyiScheduler.class#deadlock_found
table: hello refusal 16 owner=calls reason=undefined method 'claim_any' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3998 in IyiScheduler.class#deadlock_found
table: hello refusal 14 owner=calls reason=undefined method 'deadline' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4026 in IyiScheduler.class#wait_for_events
table: hello refusal 14 owner=calls reason=undefined method '+' for Int64 example=src/iyi/./concurrency.iyi:4049 in IyiScheduler.class#wait_for_events
table: hello refusal 14 owner=calls reason=undefined method '+' for Int32 example=src/iyi/array.iyi:228 in Array(Int32)#each
table: hello refusal 12 owner=declarations reason=undefined constant IYI_POLL_EVENT_BYTES example=src/iyi/./concurrency.iyi:4167 in IyiScheduler.class#wait_for_events
table: hello refusal 12 owner=bodies reason=the value of 'entry' cannot be typed example=src/iyi/./concurrency.iyi:4168 in IyiScheduler.class#wait_for_events
table: hello refusal 12 owner=bodies reason=the value of 'ready' cannot be typed example=src/iyi/./concurrency.iyi:4181 in IyiScheduler.class#wait_for_events
table: hello refusal 10 owner=calls reason=undefined method 'to_u64' for Int32 example=src/iyi/io.iyi:36 in IyiIO#initialize
table: hello refusal 8 owner=calls reason=undefined method 'awaited' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3986 in IyiScheduler.class#deadlock_found
table: hello refusal 8 owner=calls reason=undefined method 'joining' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3988 in IyiScheduler.class#deadlock_found
table: hello refusal 8 owner=calls reason=undefined method 'deadlocked=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3994 in IyiScheduler.class#deadlock_found
table: hello refusal 8 owner=calls reason=expected argument #2 to 'IyiScheduler.heap_remove' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:4661 in IyiScheduler.class#wake_expired_sleepers
table: hello refusal 8 owner=calls reason=undefined method 'io_timed' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4662 in IyiScheduler.class#wake_expired_sleepers
table: hello refusal 8 owner=calls reason=undefined method 'io_timed=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4664 in IyiScheduler.class#wake_expired_sleepers
table: hello refusal 8 owner=calls reason=undefined method 'timed_out=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4665 in IyiScheduler.class#wake_expired_sleepers
table: hello refusal 7 owner=bodies reason=the value of 'following' cannot be typed example=src/iyi/./concurrency.iyi:2318 in IyiScheduler.class#take_mail
table: hello refusal 6 owner=bodies reason=the value of 'head_deadline' cannot be typed example=src/iyi/./concurrency.iyi:4047 in IyiScheduler.class#wait_for_events
table: hello refusal 6 owner=bodies reason=the value of 'gap' cannot be typed example=src/iyi/./concurrency.iyi:4048 in IyiScheduler.class#wait_for_events
table: hello refusal 6 owner=declarations reason=undefined constant EVENTS example=src/iyi/./concurrency.iyi:4982 in IyiScheduler.class#events_buffer
table: hello refusal 6 owner=declarations reason=undefined constant IYI_POLL_DATA_OFFSET example=src/iyi/./concurrency.iyi:4168 in IyiScheduler.class#wait_for_events
table: hello refusal 6 owner=bodies reason=the value of 'fd' cannot be typed example=src/iyi/./concurrency.iyi:4181 in IyiScheduler.class#wait_for_events
table: hello refusal 6 owner=calls reason=expected argument #1 to 'IyiScheduler.switch_to' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:2595 in IyiScheduler.class#reschedule
table: hello refusal 6 owner=bodies reason=undefined local variable or method 'file' for main example=src/iyi/prelude.iyi:11005 in raise
table: hello refusal 5 owner=bodies reason=undefined local variable or method 'raise' for IyiScheduler.class example=src/iyi/./concurrency.iyi:2587 in IyiScheduler.class#reschedule
table: hello refusal 4 owner=bodies reason=the value of 'parks' cannot be typed example=src/iyi/./concurrency.iyi:2590 in IyiScheduler.class#reschedule
table: hello refusal 4 owner=bodies reason=the value of 'waits_here' cannot be typed example=src/iyi/./concurrency.iyi:2327 in IyiScheduler.class#take_mail
table: hello refusal 4 owner=bodies reason=the value of 'rest' cannot be typed example=src/iyi/./concurrency.iyi:3611 in IyiScheduler.class#wake_joiners
table: hello refusal 4 owner=bodies reason=the value of 'byte' cannot be typed example=src/iyi/string.iyi:448 in String.class#new
table: hello refusal 3 owner=calls reason=undefined method '<=' for Int32 example=src/iyi/io.iyi:285 in IyiIO#write
table: hello refusal 3 owner=calls reason=expected argument #1 to 'Pointer#+' to be Int64, not Int32 example=src/iyi/io.iyi:300 in IyiIO#write
table: hello refusal 3 owner=calls reason=undefined method '>=' for Int32 example=src/iyi/io.iyi:304 in IyiIO#write
table: hello refusal 3 owner=calls reason=expected argument #1 to 'Pointer#copy_from' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/io.iyi:313 in IyiIO#write
table: hello refusal 3 owner=bodies reason=undefined local variable or method '__iyi_exit' for top-level example=src/iyi/prelude.iyi:10751 in top level
table: hello refusal 3 owner=bodies reason=undefined local variable or method 'puts' for Samples::Hello example=samples/iyi/hello.iyi:111 in top level
table: hello refusal 3 owner=bodies reason=the value of 'memory' cannot be typed example=src/iyi/string.iyi:37 in String.class#new
table: hello refusal 3 owner=bodies reason=the value of 'buffer' cannot be typed example=src/iyi/string.iyi:38 in String.class#new
table: hello refusal 2 owner=declarations reason=undefined constant POLL_EVERY example=src/iyi/./concurrency.iyi:2591 in IyiScheduler.class#reschedule
table: hello refusal 2 owner=declarations reason=undefined constant POLL_IO_NS example=src/iyi/./concurrency.iyi:2761 in IyiScheduler.class#poll_now
table: hello refusal 2 owner=calls reason=undefined method 'give' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:2721 in IyiScheduler.class#release_unit
table: hello refusal 2 owner=calls reason=undefined method 'waiting?' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:2722 in IyiScheduler.class#release_unit
table: hello refusal 2 owner=calls reason=expected argument #2 to 'IyiScheduler.drain_unit' to be IyiUnit, not (IyiUnit | Nil) example=src/iyi/./concurrency.iyi:2724 in IyiScheduler.class#release_unit
table: hello refusal 2 owner=calls reason=undefined method 'next_run' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2309 in IyiScheduler.class#take_mail
table: hello refusal 2 owner=calls reason=undefined method 'next_cancel' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2323 in IyiScheduler.class#take_mail
table: hello refusal 2 owner=calls reason=undefined method 'next_cancel=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2324 in IyiScheduler.class#take_mail
table: hello refusal 2 owner=calls reason=undefined method 'cancel_posted=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2325 in IyiScheduler.class#take_mail
table: hello refusal 2 owner=calls reason=undefined method 'unit' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2326 in IyiScheduler.class#take_mail
table: hello refusal 2 owner=calls reason=undefined method 'listed_on' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2326 in IyiScheduler.class#take_mail
table: hello refusal 2 owner=calls reason=undefined method 'waiting_out' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2327 in IyiScheduler.class#take_mail
table: hello refusal 2 owner=calls reason=expected argument #1 to 'IyiScheduler.cancel_wait' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:2328 in IyiScheduler.class#take_mail
table: hello refusal 2 owner=unassigned reason=can't infer the type of instance variable '@size' of Array(Int32) example=src/iyi/array.iyi:226 in Array(Int32)#each
table: hello refusal 2 owner=unassigned reason=can't infer the type of instance variable '@buffer' of Array(Int32) example=src/iyi/array.iyi:227 in Array(Int32)#each
table: hello refusal 2 owner=bodies reason=undefined local variable or method 'fd' for Array(Int32) example=src/iyi/./concurrency.iyi:2335 in Array(Int32)#each
table: hello refusal 2 owner=calls reason=undefined method 'each' for Nil (compile-time type is (Array(Int32) | Nil)) example=src/iyi/./concurrency.iyi:2335 in IyiScheduler.class#take_mail
table: hello refusal 2 owner=calls reason=undefined method 'quiet' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2500 in IyiScheduler.class#all_quiet?
table: hello refusal 2 owner=calls reason=undefined method 'idle' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: hello refusal 2 owner=bodies reason=the value of 'quiet' cannot be typed example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: hello refusal 2 owner=calls reason=undefined method 'mail?' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: hello refusal 2 owner=calls reason=undefined method 'next_state' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2506 in IyiScheduler.class#all_quiet?
table: hello refusal 2 owner=calls reason=undefined method '>' for Int64 example=src/iyi/./concurrency.iyi:2508 in IyiScheduler.class#all_quiet?
table: hello refusal 2 owner=bodies reason=the value of 'count' cannot be typed example=src/iyi/./concurrency.iyi:5784 in IyiWorkers.class#work_waiting?
table: hello refusal 2 owner=calls reason=undefined method 'to_u64' for Int64 example=src/iyi/./concurrency.iyi:5591 in IyiWorkers.class#listed_at
table: hello refusal 2 owner=calls reason=undefined method '>=' for UInt64 example=src/iyi/./concurrency.iyi:1436 in IyiSchedulerState#ring_size
table: hello refusal 2 owner=calls reason=undefined method '-' for UInt64 example=src/iyi/./concurrency.iyi:1436 in IyiSchedulerState#ring_size
table: hello refusal 2 owner=calls reason=undefined method '>' for UInt64 example=src/iyi/./concurrency.iyi:5785 in IyiWorkers.class#work_waiting?
table: hello refusal 2 owner=calls reason=undefined method '&+' for Int64 example=src/iyi/./concurrency.iyi:5786 in IyiWorkers.class#work_waiting?
table: hello refusal 2 owner=calls reason=undefined method 'next_joiner' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3609 in IyiScheduler.class#wake_joiners
table: hello refusal 2 owner=calls reason=undefined method 'next_joiner=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3610 in IyiScheduler.class#wake_joiners
table: hello refusal 2 owner=calls reason=expected argument #1 to 'IyiAtomic.load' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/prelude.iyi:10779 in top level
table: hello refusal 2 owner=unassigned reason=unsupported node: MagicConstant example=src/iyi/prelude.iyi:10967 in top level
table: hello refusal 2 owner=bodies reason=undefined local variable or method 'to_i64' for Int32 example=src/iyi/number.iyi:124 in Int32#to_s
table: hello refusal 2 owner=unassigned reason=unsupported node: TraitDef example=samples/iyi/hello.iyi:17 in top level
table: hello refusal 2 owner=unassigned reason=wrong number of arguments for 'String.interpolation' (given 3, expected 1) example=no location in Samples::Hello::User#greet
table: hello refusal 2 owner=declarations reason=undefined constant HEADER_SIZE example=src/iyi/string.iyi:36 in String.class#new
table: hello refusal 2 owner=calls reason=expected argument #2 to 'Pointer(Int32)#[]=' to be <unresolved T>, not Int32 example=src/iyi/string.iyi:42 in String.class#new
table: hello refusal 2 owner=bodies reason=the value of 'array' cannot be typed example=src/iyi/array.iyi:77 in Array(Samples::Hello::Greet).class#unsafe_build
table: hello refusal 2 owner=unassigned reason=can't infer the type of instance variable '@buffer' of Array(<unresolved T>) example=src/iyi/array.iyi:88 in Array(<unresolved T>)#to_unsafe
table: hello refusal 1 owner=calls reason=undefined method 'on_cpu=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1917 in IyiScheduler.class#landed
table: hello refusal 1 owner=declarations reason=undefined constant STACK_BYTES example=src/iyi/./concurrency.iyi:926 in IyiFiber#release_stack
table: hello refusal 1 owner=calls reason=undefined method 'release_stack' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1932 in IyiScheduler.class#reap_dying
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.unregister' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:1933 in IyiScheduler.class#reap_dying
table: hello refusal 1 owner=unassigned reason=wrong number of arguments for 'Proc(Nil)#call' (given 0, expected 1) example=src/iyi/./concurrency.iyi:2874 in IyiScheduler.class#run_spawned_fiber
table: hello refusal 1 owner=calls reason=undefined method 'awaited=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3620 in IyiScheduler.class#wake_joiners
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.ready' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:3621 in IyiScheduler.class#wake_joiners
table: hello refusal 1 owner=bodies reason=undefined local variable or method '__iyi_program' for top-level example=src/iyi/prelude.iyi:10726 in top level
table: hello refusal 1 owner=calls reason=undefined method '__iyi_main' for LibIyiMain.class example=src/iyi/prelude.iyi:10741 in top level
table: hello refusal 1 owner=bodies reason=the value of '__temp_4' cannot be typed example=no location in raise
table: hello refusal 1 owner=bodies reason=undefined local variable or method 'line' for main example=src/iyi/prelude.iyi:11009 in raise
table: hello refusal 1 owner=bodies reason=undefined local variable or method '__iyi_enter' for top-level example=src/iyi/prelude.iyi:11698 in top level
table: hello refusal 1 owner=unassigned reason=wrong number of arguments for 'Int32#-' (given 1, expected 0) example=src/iyi/testing.iyi:251 in IyiTestCases.class#verdict
table: hello refusal 1 owner=bodies reason=undefined local variable or method 'bytesize' for String.class example=src/iyi/string.iyi:446 in String.class#new
table: hello refusal 1 owner=bodies reason=undefined local variable or method 'to_unsafe' for String.class example=src/iyi/string.iyi:447 in String.class#new
table: hello refusal 1 owner=unassigned reason=wrong number of arguments for 'String.interpolation' (given 2, expected 1) example=no location in Samples::Hello::Robot#greet
table: hello refusal 1 owner=calls reason=expected argument #2 to 'Pointer(<unresolved T>)#[]=' to be <unresolved T>, not Samples::Hello::User example=no location in top level
table: hello refusal 1 owner=calls reason=expected argument #2 to 'Pointer(<unresolved T>)#[]=' to be <unresolved T>, not Samples::Hello::Robot example=no location in top level
table: hello refusal 1 owner=unassigned reason=can't infer the type of instance variable '@size' of Array(<unresolved T>) example=src/iyi/array.iyi:226 in Array(<unresolved T>)#each
table: hello refusal 1 owner=bodies reason=undefined local variable or method 'member' for Array(<unresolved T>) example=samples/iyi/hello.iyi:117 in Array(<unresolved T>)#each
table: hello refusal 1 owner=calls reason=expected argument #1 to 'Samples::Hello#announce' to be <unresolved T>, not Samples::Hello::Robot example=samples/iyi/hello.iyi:119 in top level
table: hello defs-lowered-clean=15864 lowering-refusal-sites=12593
table: hello lowering 3318 owner=bodies reason=BUG: the analysed program has no type for the body of value (hosted codegen_fun: return type) example=Pointer(Atomic(UInt64))#value
table: hello lowering 2730 owner=bodies reason=BUG: the analysed program has no type for the body of new (hosted codegen_fun: return type) example=Pointer(UInt64).class#new
table: hello lowering 2075 owner=bodies reason=BUG: the analysed program has no type for the body of initialize (hosted codegen_fun: return type) example=Atomic(UInt64)#initialize
table: hello lowering 1817 owner=bodies reason=BUG: the analysed program has no type for the body of word (hosted codegen_fun: return type) example=IyiSchedLock.class#word
table: hello lowering 828 owner=bodies reason=BUG: the analysed program has no type for the body of unlock (hosted codegen_fun: return type) example=IyiRuntimeLock.class#unlock
table: hello lowering 468 owner=bodies reason=BUG: the analysed program has no type for the body of lock (hosted codegen_fun: return type) example=IyiRuntimeLock.class#lock
table: hello lowering 460 owner=bodies reason=BUG: the analysed program has no type for the body of state_id (hosted codegen_fun: return type) example=IyiScheduler.class#state_id
table: hello lowering 135 owner=bodies reason=BUG: the analysed program has no type for the body of malloc (hosted codegen_fun: return type) example=Pointer(UInt8).class#malloc
table: hello lowering 112 owner=bodies reason=BUG: the analysed program has no type for the body of held_here? (hosted codegen_fun: return type) example=IyiSchedLock.class#held_here?
table: hello lowering 110 owner=bodies reason=BUG: the analysed program has no type for the body of draw (hosted codegen_fun: return type) example=IyiChaos.class#draw
table: hello lowering 110 owner=bodies reason=BUG: the analysed program has no type for the body of % (hosted codegen_fun: return type) example=UInt64#%
table: hello lowering 55 owner=bodies reason=BUG: the analysed program has no type for the body of thread_point (hosted codegen_fun: return type) example=IyiChaos.class#thread_point
table: hello lowering 55 owner=bodies reason=BUG: the analysed program has no type for the body of held? (hosted codegen_fun: return type) example=IyiRuntimeLock.class#held?
table: hello lowering 55 owner=bodies reason=BUG: the analysed program has no type for the body of give_up (hosted codegen_fun: return type) example=IyiWorkers.class#give_up
table: hello lowering 30 owner=bodies reason=BUG: the analysed program has no type for the body of compare_and_set (hosted codegen_fun: return type) example=Atomic(UInt64)#compare_and_set
table: hello lowering 28 owner=bodies reason=BUG: the analysed program has no type for the body of get (hosted codegen_fun: return type) example=Atomic(UInt64)#get
table: hello lowering 18 owner=bodies reason=BUG: the analysed program has no type for the body of set (hosted codegen_fun: return type) example=Atomic(UInt64)#set
table: hello lowering 16 owner=bodies reason=BUG: the analysed program has no type for the body of deadlock (hosted codegen_fun: return type) example=IyiScheduler.class#deadlock
table: hello lowering 16 owner=bodies reason=BUG: the analysed program has no type for the body of add (hosted codegen_fun: return type) example=Atomic(UInt64)#add
table: hello lowering 16 owner=bodies reason=BUG: the analysed program has no type for the body of claim (hosted codegen_fun: return type) example=IyiFiber#claim
table: hello lowering 15 owner=lowering core reason=lower: visit(ASTNode) (hosted codegen.cr) is not ported yet example=IyiSchedulerState.class#allocate
table: hello lowering 14 owner=bodies reason=BUG: the analysed program has no type for the body of take_lists (hosted codegen_fun: return type) example=IyiSchedulerState#take_lists
table: hello lowering 11 owner=lowering core reason=lower: visit(assign Nil to (IyiFiber | Nil) (nilable target, hosted assign_distinct NilableType)) (hosted codegen.cr) is not ported yet example=IyiFiber#prev_fiber=
table: hello lowering 11 owner=lowering core reason=lower: visit(a call with no receiver inside a method, an implicit self call (hosted call.cr: prepare_call_args, self)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#landed
table: hello lowering 9 owner=lowering core reason=lower: visit(ClassVar) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#state
table: hello lowering 7 owner=lowering core reason=lower: visit(assign IyiFiber to (IyiFiber | Nil) (nilable target, hosted assign_distinct NilableType)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#current=
table: hello lowering 6 owner=bodies reason=BUG: the analysed program has no type for the body of wait_for_events (hosted codegen_fun: return type) example=IyiScheduler.class#wait_for_events
table: hello lowering 4 owner=lowering core reason=lower: visit(a restriction that converts argument 0 of set (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiFiber#on_cpu=
table: hello lowering 3 owner=lowering core reason=lower: visit(MacroIf) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#poll_now
table: hello lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of greet (hosted codegen_fun: return type) example=Samples::Hello::User#greet
table: hello lowering 2 owner=calls reason=BUG: the call to get has no target def (hosted call.cr: visit(Call)) example=IyiChanLock.class#acquire
table: hello lowering 2 owner=lowering core reason=lower: visit(a class method call on a receiver that is not a constant path (hosted call.cr: prepare_call_args, Path)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#register
table: hello lowering 2 owner=lowering core reason=lower: visit(a call to == inherited from a superclass of UInt64 (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=IyiChaos.class#step
table: hello lowering 2 owner=lowering core reason=lower: visit(a call to != inherited from a superclass of UInt64 (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=IyiUnit#waiting?
table: hello lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of ensure_doorbell (hosted codegen_fun: return type) example=IyiScheduler.class#ensure_doorbell
table: hello lowering 2 owner=calls reason=BUG: the call to > has no target def (hosted call.cr: visit(Call)) example=IyiWorkers.class#work_waiting?
table: hello lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of ring_size (hosted codegen_fun: return type) example=IyiSchedulerState#ring_size
table: hello lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of to_s (hosted codegen_fun: return type) example=Int32#to_s
table: hello lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of + (hosted codegen_fun: return type) example=String#+
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of run_spawned_fiber (hosted codegen_fun: return type) example=IyiScheduler.class#run_spawned_fiber
table: hello lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(IyiFiber | Nil) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiScheduler.class#current
table: hello lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiSchedulerState: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#first_state_here
table: hello lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiSchedulerState.class: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=IyiSchedulerState.class#new
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to new (hosted call.cr: visit(Call)) example=IyiSchedulerState#initialize
table: hello lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Atomic(UInt64) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Atomic(UInt64).class#new
table: hello lowering 1 owner=lowering core reason=lower: visit(allocate of class Atomic(UInt64).class: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=Atomic(UInt64).class#new
table: hello lowering 1 owner=lowering core reason=lower: visit(a call to == inherited from a superclass of Int64 (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Int64#!=
table: hello lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiFiber: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=IyiFiber.class#main
table: hello lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiFiber.class: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=IyiFiber.class#new
table: hello lowering 1 owner=lowering core reason=lower: visit(assign Int32 to IyiFiberState (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=IyiFiber#initialize
table: hello lowering 1 owner=lowering core reason=lower: visit(assign IyiSchedulerState to (IyiSchedulerState | Nil) (nilable target, hosted assign_distinct NilableType)) (hosted codegen.cr) is not ported yet example=IyiFiber#home=
table: hello lowering 1 owner=calls reason=BUG: the call to chaos_unit has no target def (hosted call.cr: visit(Call)) example=IyiChaos.class#unit_of
table: hello lowering 1 owner=calls reason=BUG: the call to state= has no target def (hosted call.cr: visit(Call)) example=IyiScheduler.class#enqueue
table: hello lowering 1 owner=lowering core reason=lower: visit(a restriction that converts argument 0 of add (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiFiber#claim_any
table: hello lowering 1 owner=unassigned reason=lower: is_a? of (IyiUnit | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiScheduler.class#release_unit
table: hello lowering 1 owner=lowering core reason=lower: visit(assign Nil to (IyiUnit | Nil) (nilable target, hosted assign_distinct NilableType)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#unit=
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to lock (hosted call.cr: visit(Call)) example=IyiScheduler.class#take_mail
table: hello lowering 1 owner=calls reason=BUG: the call to point has no target def (hosted call.cr: visit(Call)) example=IyiFiber#listed_on
table: hello lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(Int32) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiSchedulerState#closed_fds
table: hello lowering 1 owner=lowering core reason=lower: visit(assign Nil to (Array(Int32) | Nil) (nilable target, hosted assign_distinct NilableType)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#closed_fds=
table: hello lowering 1 owner=calls reason=BUG: the call to < has no target def (hosted call.cr: visit(Call)) example=Array(Int32)#each
table: hello lowering 1 owner=lowering core reason=lower: visit(Cast) (hosted codegen.cr) is not ported yet example=IyiWorkers.class#listed_at
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of reap_dying (hosted codegen_fun: return type) example=IyiScheduler.class#reap_dying
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of release_stack (hosted codegen_fun: return type) example=IyiFiber#release_stack
table: hello lowering 1 owner=unassigned reason=lower: is_a? of (IyiFiber | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiScheduler.class#wake_joiners
table: hello lowering 1 owner=unassigned reason=lower: read of constant STDOUT (hosted const.cr: read_const, read_const_pointer): its global and initialiser are not ported yet example=print
table: hello lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiIO.class: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=IyiIO.class#new
table: hello lowering 1 owner=lowering core reason=lower: visit(PointerOf) (hosted codegen.cr) is not ported yet example=String#to_unsafe
table: hello lowering 1 owner=calls reason=BUG: the call to raise has no target def (hosted call.cr: visit(Call)) example=IyiIO#write
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of run (hosted codegen_fun: return type) example=IyiOnce.class#run
table: hello lowering 1 owner=calls reason=BUG: the call to to_i64 has no target def (hosted call.cr: visit(Call)) example=__iyi_say
table: hello lowering 1 owner=calls reason=BUG: the call to == has no target def (hosted call.cr: visit(Call)) example=IyiTestCases.class#verdict
table: hello lowering 1 owner=lowering core reason=lower: visit(a call to == inherited from a superclass of Int32 (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=String#empty?
table: hello lowering 1 owner=lowering core reason=lower: visit(allocate of class Samples::Hello::User.class: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=Samples::Hello::User.class#new
table: hello lowering 1 owner=calls reason=BUG: the call to memory has no target def (hosted call.cr: visit(Call)) example=String.class#new
table: hello lowering 1 owner=lowering core reason=lower: visit(allocate of class Samples::Hello::Robot.class: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=Samples::Hello::Robot.class#new
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of unsafe_build (hosted codegen_fun: return type) example=Array(Samples::Hello::Greet).class#unsafe_build
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of to_unsafe (hosted codegen_fun: return type) example=Array(<unresolved T>)#to_unsafe
table: hello lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(<unresolved T>) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Array(<unresolved T>)#each
table: parse defs-reached=28488 defs-typed-clean=15924 root-refusals=37 refusal-sites=38066
table: parse refusal 9982 owner=declarations reason=undefined constant T example=src/iyi/primitives.iyi:159 in Pointer(Atomic(UInt64))#value
table: parse refusal 4907 owner=macros reason=macro control expansion (macros engine) example=src/iyi/./primitives.iyi:100 in top level
table: parse refusal 4884 owner=bodies reason=the value of 'seen' cannot be typed example=src/iyi/./concurrency.iyi:1561 in IyiChanLock.class#acquire
table: parse refusal 2730 owner=declarations reason=primitive pointer_new without a declared return type example=src/iyi/primitives.iyi:155 in Pointer(UInt64).class#new
table: parse refusal 2070 owner=unassigned reason=can't use instance variables in Atomic(UInt64) example=src/iyi/atomic.iyi:50 in Atomic(UInt64)#initialize
table: parse refusal 1740 owner=declarations reason=undefined constant HELD example=src/iyi/./concurrency.iyi:1561 in IyiChanLock.class#acquire
table: parse refusal 1402 owner=bodies reason=the value of '__temp_1' cannot be typed example=no location in IyiChanLock.class#acquire
table: parse refusal 819 owner=bodies reason=the value of '__temp_2' cannot be typed example=no location in IyiChanLock.class#contend
table: parse refusal 711 owner=calls reason=undefined method '>' for Int32 example=src/iyi/./concurrency.iyi:1576 in IyiChanLock.class#contend
table: parse refusal 696 owner=declarations reason=undefined constant SPINNER example=src/iyi/./concurrency.iyi:1576 in IyiChanLock.class#contend
table: parse refusal 474 owner=calls reason=undefined method '<' for Int64 example=src/iyi/prelude.iyi:104 in IyiRuntimeLock.class#lock
table: parse refusal 469 owner=bodies reason=the value of '__temp_3' cannot be typed example=no location in IyiRuntimeLock.class#lock
table: parse refusal 468 owner=calls reason=expected argument #2 to 'IyiAtomic.rmw' to be Pointer(<unresolved T>), not Pointer(UInt64) example=src/iyi/prelude.iyi:104 in IyiRuntimeLock.class#lock
table: parse refusal 462 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:1737 in IyiScheduler.class#state_id
table: parse refusal 440 owner=bodies reason=the value of 'state' cannot be typed example=src/iyi/./chaos.iyi:228 in IyiChaos.class#draw
table: parse refusal 385 owner=bodies reason=the value of 'unit' cannot be typed example=src/iyi/./chaos.iyi:265 in IyiChaos.class#unit_of
table: parse refusal 362 owner=calls reason=undefined method '&+' for Int32 example=src/iyi/./concurrency.iyi:1579 in IyiChanLock.class#contend
table: parse refusal 361 owner=calls reason=expected argument #1 to 'IyiAtomic.store' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/./concurrency.iyi:1475 in IyiSchedLock.class#unlock
table: parse refusal 348 owner=declarations reason=undefined constant UNMARKED example=src/iyi/./concurrency.iyi:1572 in IyiChanLock.class#contend
table: parse refusal 348 owner=bodies reason=the value of 'taken' cannot be typed example=src/iyi/./concurrency.iyi:1573 in IyiChanLock.class#contend
table: parse refusal 348 owner=calls reason=undefined method '&-' for Int32 example=src/iyi/./concurrency.iyi:1601 in IyiChanLock.class#contend
table: parse refusal 333 owner=unassigned reason=type mismatch for return type: expected IyiSchedulerState, got (IyiSchedulerState | Nil) example=src/iyi/./concurrency.iyi:1793 in IyiScheduler.class#state
table: parse refusal 277 owner=calls reason=undefined method '&+' for UInt64 example=src/iyi/./chaos.iyi:337 in IyiChaos.class#step
table: parse refusal 220 owner=declarations reason=undefined constant GOLDEN example=src/iyi/./chaos.iyi:227 in IyiChaos.class#draw
table: parse refusal 192 owner=calls reason=expected argument #1 to 'IyiFiber#state=' to be IyiFiberState, not Int32 example=src/iyi/./concurrency.iyi:756 in IyiFiber.class#main
table: parse refusal 165 owner=declarations reason=undefined constant SIMULATED example=src/iyi/./chaos.iyi:312 in IyiChaos.class#point
table: parse refusal 135 owner=unassigned reason=type mismatch for return type: expected IyiFiber, got (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:1829 in IyiScheduler.class#current
table: parse refusal 135 owner=unassigned reason=instance variable '@state' of IyiFiber must be IyiFiberState, not (IyiFiberState | Int32) example=src/iyi/./concurrency.iyi:635 in IyiFiber#initialize
table: parse refusal 135 owner=declarations reason=primitive pointer_malloc without a declared return type example=src/iyi/primitives.iyi:151 in Pointer(UInt8).class#malloc
table: parse refusal 135 owner=calls reason=undefined method 'prev_fiber=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1863 in IyiScheduler.class#register
table: parse refusal 110 owner=calls reason=undefined method '&-' for UInt64 example=src/iyi/./chaos.iyi:353 in IyiChaos.class#step
table: parse refusal 110 owner=bodies reason=the value of 'ordinal' cannot be typed example=src/iyi/./chaos.iyi:233 in IyiChaos.class#draw
table: parse refusal 110 owner=bodies reason=undefined local variable or method 'raise' for UInt64 example=src/iyi/number.iyi:169 in UInt64#%
table: parse refusal 110 owner=bodies reason=undefined local variable or method 'unsafe_mod' for UInt64 example=src/iyi/number.iyi:170 in UInt64#%
table: parse refusal 92 owner=bodies reason=undefined local variable or method 'previous_def' for Atomic(UInt64) example=src/iyi/./chaos_points.iyi:16 in Atomic(UInt64)#get
table: parse refusal 63 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3990 in IyiScheduler.class#deadlock_found
table: parse refusal 60 owner=declarations reason=undefined constant Tuple(T, Bool) example=src/iyi/./chaos_points.iyi:39 in IyiSchedulerState#take_lists
table: parse refusal 59 owner=calls reason=undefined method 'next_run=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2154 in IyiScheduler.class#enqueue
table: parse refusal 55 owner=calls reason=undefined method 'chaos_unit' for IyiFiber example=src/iyi/./chaos.iyi:264 in IyiChaos.class#unit_of
table: parse refusal 55 owner=declarations reason=undefined constant HIGH example=src/iyi/./chaos.iyi:267 in IyiChaos.class#unit_of
table: parse refusal 55 owner=calls reason=undefined method 'chaos_unit=' for IyiFiber example=src/iyi/./chaos.iyi:269 in IyiChaos.class#unit_of
table: parse refusal 55 owner=declarations reason=undefined constant LOW example=src/iyi/./chaos.iyi:348 in IyiChaos.class#step
table: parse refusal 55 owner=declarations reason=undefined constant SPIN_STEPS example=src/iyi/./chaos.iyi:350 in IyiChaos.class#step
table: parse refusal 55 owner=calls reason=undefined method '|' for UInt64 example=src/iyi/./chaos.iyi:356 in IyiChaos.class#step
table: parse refusal 55 owner=calls reason=undefined method 'chaos_held=' for IyiFiber example=src/iyi/./chaos.iyi:357 in IyiChaos.class#step
table: parse refusal 55 owner=declarations reason=undefined constant THREADS example=src/iyi/./chaos.iyi:314 in IyiChaos.class#point
table: parse refusal 55 owner=declarations reason=undefined constant IyiThread example=src/iyi/./chaos.iyi:525 in IyiChaos.class#thread_point
table: parse refusal 49 owner=bodies reason=the value of 'n' cannot be typed example=src/iyi/io.iyi:362 in IyiIO#flush
table: parse refusal 48 owner=declarations reason=undefined constant DEADLOCK example=src/iyi/./concurrency.iyi:4011 in IyiScheduler.class#deadlock
table: parse refusal 46 owner=bodies reason=the value of 'total' cannot be typed example=src/iyi/io.iyi:360 in IyiIO#flush
table: parse refusal 37 owner=calls reason=undefined method 'to_i64' for Int32 example=src/iyi/io.iyi:358 in IyiIO#flush
table: parse refusal 32 owner=calls reason=undefined method 'state' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3997 in IyiScheduler.class#deadlock_found
table: parse refusal 32 owner=calls reason=expected argument #1 to 'IyiScheduler.enqueue' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:3998 in IyiScheduler.class#deadlock_found
table: parse refusal 28 owner=calls reason=undefined method '+' for Int32 example=src/iyi/array.iyi:228 in Array(Int32)#each
table: parse refusal 20 owner=bodies reason=undefined local variable or method 'raise' for IyiIO example=src/iyi/io.iyi:284 in IyiIO#write
table: parse refusal 18 owner=bodies reason=the value of 'now' cannot be typed example=src/iyi/./concurrency.iyi:2761 in IyiScheduler.class#poll_now
table: parse refusal 16 owner=bodies reason=undefined local variable or method '__iyi_monotonic_ns' for IyiScheduler.class example=src/iyi/./concurrency.iyi:2760 in IyiScheduler.class#poll_now
table: parse refusal 16 owner=bodies reason=the value of 'task' cannot be typed example=src/iyi/./concurrency.iyi:3987 in IyiScheduler.class#deadlock_found
table: parse refusal 16 owner=bodies reason=the value of 'group' cannot be typed example=src/iyi/./concurrency.iyi:3989 in IyiScheduler.class#deadlock_found
table: parse refusal 16 owner=calls reason=undefined method 'claim_any' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3998 in IyiScheduler.class#deadlock_found
table: parse refusal 14 owner=calls reason=undefined method 'deadline' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4026 in IyiScheduler.class#wait_for_events
table: parse refusal 14 owner=calls reason=undefined method '+' for Int64 example=src/iyi/./concurrency.iyi:4049 in IyiScheduler.class#wait_for_events
table: parse refusal 12 owner=declarations reason=undefined constant IYI_POLL_EVENT_BYTES example=src/iyi/./concurrency.iyi:4167 in IyiScheduler.class#wait_for_events
table: parse refusal 12 owner=bodies reason=the value of 'entry' cannot be typed example=src/iyi/./concurrency.iyi:4168 in IyiScheduler.class#wait_for_events
table: parse refusal 12 owner=bodies reason=the value of 'ready' cannot be typed example=src/iyi/./concurrency.iyi:4181 in IyiScheduler.class#wait_for_events
table: parse refusal 11 owner=calls reason=undefined method '<' for Int32 example=src/iyi/array.iyi:135 in Array(String)#[]
table: parse refusal 10 owner=calls reason=undefined method 'to_u64' for Int32 example=src/iyi/io.iyi:36 in IyiIO#initialize
table: parse refusal 9 owner=bodies reason=the value of 'fd' cannot be typed example=src/iyi/./concurrency.iyi:4181 in IyiScheduler.class#wait_for_events
table: parse refusal 9 owner=unassigned reason=can't infer the type of instance variable '@size' of Array(String) example=src/iyi/array.iyi:96 in Array(String)#empty?
table: parse refusal 8 owner=calls reason=undefined method 'awaited' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3986 in IyiScheduler.class#deadlock_found
table: parse refusal 8 owner=calls reason=undefined method 'joining' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3988 in IyiScheduler.class#deadlock_found
table: parse refusal 8 owner=calls reason=undefined method 'deadlocked=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3994 in IyiScheduler.class#deadlock_found
table: parse refusal 8 owner=calls reason=expected argument #2 to 'IyiScheduler.heap_remove' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:4661 in IyiScheduler.class#wake_expired_sleepers
table: parse refusal 8 owner=calls reason=undefined method 'io_timed' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4662 in IyiScheduler.class#wake_expired_sleepers
table: parse refusal 8 owner=calls reason=undefined method 'io_timed=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4664 in IyiScheduler.class#wake_expired_sleepers
table: parse refusal 8 owner=calls reason=undefined method 'timed_out=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4665 in IyiScheduler.class#wake_expired_sleepers
table: parse refusal 7 owner=bodies reason=the value of 'following' cannot be typed example=src/iyi/./concurrency.iyi:2318 in IyiScheduler.class#take_mail
table: parse refusal 6 owner=bodies reason=the value of 'head_deadline' cannot be typed example=src/iyi/./concurrency.iyi:4047 in IyiScheduler.class#wait_for_events
table: parse refusal 6 owner=bodies reason=the value of 'gap' cannot be typed example=src/iyi/./concurrency.iyi:4048 in IyiScheduler.class#wait_for_events
table: parse refusal 6 owner=declarations reason=undefined constant EVENTS example=src/iyi/./concurrency.iyi:4982 in IyiScheduler.class#events_buffer
table: parse refusal 6 owner=declarations reason=undefined constant IYI_POLL_DATA_OFFSET example=src/iyi/./concurrency.iyi:4168 in IyiScheduler.class#wait_for_events
table: parse refusal 6 owner=calls reason=expected argument #1 to 'IyiScheduler.switch_to' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:2595 in IyiScheduler.class#reschedule
table: parse refusal 6 owner=bodies reason=undefined local variable or method 'file' for main example=src/iyi/prelude.iyi:11005 in raise
table: parse refusal 5 owner=bodies reason=undefined local variable or method 'raise' for IyiScheduler.class example=src/iyi/./concurrency.iyi:2587 in IyiScheduler.class#reschedule
table: parse refusal 4 owner=bodies reason=the value of 'parks' cannot be typed example=src/iyi/./concurrency.iyi:2590 in IyiScheduler.class#reschedule
table: parse refusal 4 owner=bodies reason=the value of 'waits_here' cannot be typed example=src/iyi/./concurrency.iyi:2327 in IyiScheduler.class#take_mail
table: parse refusal 4 owner=bodies reason=the value of 'rest' cannot be typed example=src/iyi/./concurrency.iyi:3611 in IyiScheduler.class#wake_joiners
table: parse refusal 4 owner=unassigned reason=wrong number of arguments for 'Int32#-' (given 1, expected 0) example=src/iyi/testing.iyi:251 in IyiTestCases.class#verdict
table: parse refusal 4 owner=calls reason=undefined method '&*' for UInt64 example=src/iyi/string.iyi:508 in String#byte_index
table: parse refusal 3 owner=calls reason=undefined method '<=' for Int32 example=src/iyi/io.iyi:285 in IyiIO#write
table: parse refusal 3 owner=calls reason=expected argument #1 to 'Pointer#+' to be Int64, not Int32 example=src/iyi/io.iyi:300 in IyiIO#write
table: parse refusal 3 owner=calls reason=undefined method '>=' for Int32 example=src/iyi/io.iyi:304 in IyiIO#write
table: parse refusal 3 owner=calls reason=expected argument #1 to 'Pointer#copy_from' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/io.iyi:313 in IyiIO#write
table: parse refusal 3 owner=bodies reason=undefined local variable or method '__iyi_exit' for top-level example=src/iyi/prelude.iyi:10751 in top level
table: parse refusal 3 owner=unassigned reason=unsupported node: Unless example=src/iyi/string.iyi:531 in String#==
table: parse refusal 3 owner=bodies reason=the value of 'limit' cannot be typed example=src/iyi/string.iyi:490 in String#byte_index
table: parse refusal 3 owner=bodies reason=the value of 'buffer' cannot be typed example=src/iyi/file.iyi:141 in File.class#c_path
table: parse refusal 3 owner=bodies reason=the value of 'io' cannot be typed example=src/iyi/file.iyi:68 in File.class#read
table: parse refusal 2 owner=declarations reason=undefined constant POLL_EVERY example=src/iyi/./concurrency.iyi:2591 in IyiScheduler.class#reschedule
table: parse refusal 2 owner=declarations reason=undefined constant POLL_IO_NS example=src/iyi/./concurrency.iyi:2761 in IyiScheduler.class#poll_now
table: parse refusal 2 owner=calls reason=undefined method 'give' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:2721 in IyiScheduler.class#release_unit
table: parse refusal 2 owner=calls reason=undefined method 'waiting?' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:2722 in IyiScheduler.class#release_unit
table: parse refusal 2 owner=calls reason=expected argument #2 to 'IyiScheduler.drain_unit' to be IyiUnit, not (IyiUnit | Nil) example=src/iyi/./concurrency.iyi:2724 in IyiScheduler.class#release_unit
table: parse refusal 2 owner=calls reason=undefined method 'next_run' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2309 in IyiScheduler.class#take_mail
table: parse refusal 2 owner=calls reason=undefined method 'next_cancel' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2323 in IyiScheduler.class#take_mail
table: parse refusal 2 owner=calls reason=undefined method 'next_cancel=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2324 in IyiScheduler.class#take_mail
table: parse refusal 2 owner=calls reason=undefined method 'cancel_posted=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2325 in IyiScheduler.class#take_mail
table: parse refusal 2 owner=calls reason=undefined method 'unit' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2326 in IyiScheduler.class#take_mail
table: parse refusal 2 owner=calls reason=undefined method 'listed_on' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2326 in IyiScheduler.class#take_mail
table: parse refusal 2 owner=calls reason=undefined method 'waiting_out' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2327 in IyiScheduler.class#take_mail
table: parse refusal 2 owner=calls reason=expected argument #1 to 'IyiScheduler.cancel_wait' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:2328 in IyiScheduler.class#take_mail
table: parse refusal 2 owner=unassigned reason=can't infer the type of instance variable '@size' of Array(Int32) example=src/iyi/array.iyi:226 in Array(Int32)#each
table: parse refusal 2 owner=unassigned reason=can't infer the type of instance variable '@buffer' of Array(Int32) example=src/iyi/array.iyi:227 in Array(Int32)#each
table: parse refusal 2 owner=bodies reason=undefined local variable or method 'fd' for Array(Int32) example=src/iyi/./concurrency.iyi:2335 in Array(Int32)#each
table: parse refusal 2 owner=calls reason=undefined method 'each' for Nil (compile-time type is (Array(Int32) | Nil)) example=src/iyi/./concurrency.iyi:2335 in IyiScheduler.class#take_mail
table: parse refusal 2 owner=calls reason=undefined method 'quiet' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2500 in IyiScheduler.class#all_quiet?
table: parse refusal 2 owner=calls reason=undefined method 'idle' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: parse refusal 2 owner=bodies reason=the value of 'quiet' cannot be typed example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: parse refusal 2 owner=calls reason=undefined method 'mail?' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: parse refusal 2 owner=calls reason=undefined method 'next_state' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2506 in IyiScheduler.class#all_quiet?
table: parse refusal 2 owner=calls reason=undefined method '>' for Int64 example=src/iyi/./concurrency.iyi:2508 in IyiScheduler.class#all_quiet?
table: parse refusal 2 owner=bodies reason=the value of 'count' cannot be typed example=src/iyi/./concurrency.iyi:5784 in IyiWorkers.class#work_waiting?
table: parse refusal 2 owner=calls reason=undefined method 'to_u64' for Int64 example=src/iyi/./concurrency.iyi:5591 in IyiWorkers.class#listed_at
table: parse refusal 2 owner=calls reason=undefined method '>=' for UInt64 example=src/iyi/./concurrency.iyi:1436 in IyiSchedulerState#ring_size
table: parse refusal 2 owner=calls reason=undefined method '-' for UInt64 example=src/iyi/./concurrency.iyi:1436 in IyiSchedulerState#ring_size
table: parse refusal 2 owner=calls reason=undefined method '>' for UInt64 example=src/iyi/./concurrency.iyi:5785 in IyiWorkers.class#work_waiting?
table: parse refusal 2 owner=calls reason=undefined method '&+' for Int64 example=src/iyi/./concurrency.iyi:5786 in IyiWorkers.class#work_waiting?
table: parse refusal 2 owner=calls reason=undefined method 'next_joiner' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3609 in IyiScheduler.class#wake_joiners
table: parse refusal 2 owner=calls reason=undefined method 'next_joiner=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3610 in IyiScheduler.class#wake_joiners
table: parse refusal 2 owner=calls reason=expected argument #1 to 'IyiAtomic.load' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/prelude.iyi:10779 in top level
table: parse refusal 2 owner=unassigned reason=unsupported node: MagicConstant example=src/iyi/prelude.iyi:10967 in top level
table: parse refusal 2 owner=bodies reason=undefined local variable or method 'to_i64' for Int32 example=src/iyi/number.iyi:124 in Int32#to_s
table: parse refusal 2 owner=unassigned reason=can't infer the type of instance variable '@buffer' of Array(String) example=src/iyi/array.iyi:137 in Array(String)#[]
table: parse refusal 2 owner=calls reason=expected argument #1 to 'Pointer(UInt8)#+' to be Int64, not Int32 example=src/iyi/string.iyi:537 in String#==
table: parse refusal 2 owner=bodies reason=the value of 'source' cannot be typed example=src/compiler/tools/parse.iyi:15 in Compiler::Tools::Parse::ParseTool.class#run
table: parse refusal 1 owner=calls reason=undefined method 'on_cpu=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1917 in IyiScheduler.class#landed
table: parse refusal 1 owner=declarations reason=undefined constant STACK_BYTES example=src/iyi/./concurrency.iyi:926 in IyiFiber#release_stack
table: parse refusal 1 owner=calls reason=undefined method 'release_stack' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1932 in IyiScheduler.class#reap_dying
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.unregister' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:1933 in IyiScheduler.class#reap_dying
table: parse refusal 1 owner=unassigned reason=wrong number of arguments for 'Proc(Nil)#call' (given 0, expected 1) example=src/iyi/./concurrency.iyi:2874 in IyiScheduler.class#run_spawned_fiber
table: parse refusal 1 owner=calls reason=undefined method 'awaited=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3620 in IyiScheduler.class#wake_joiners
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.ready' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:3621 in IyiScheduler.class#wake_joiners
table: parse refusal 1 owner=bodies reason=undefined local variable or method '__iyi_program' for top-level example=src/iyi/prelude.iyi:10726 in top level
table: parse refusal 1 owner=calls reason=undefined method '__iyi_main' for LibIyiMain.class example=src/iyi/prelude.iyi:10741 in top level
table: parse refusal 1 owner=bodies reason=the value of '__temp_4' cannot be typed example=no location in raise
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'line' for main example=src/iyi/prelude.iyi:11009 in raise
table: parse refusal 1 owner=bodies reason=undefined local variable or method '__iyi_enter' for top-level example=src/iyi/prelude.iyi:11698 in top level
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'read_input' for Compiler::Tools::Parse::ParseTool.class example=src/compiler/tools/parse.iyi:14 in Compiler::Tools::Parse::ParseTool.class#run
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'raise' for Compiler::Tools::Parse::ParseTool.class example=src/compiler/tools/parse.iyi:24 in Compiler::Tools::Parse::ParseTool.class#run
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'raise' for File.class example=src/iyi/file.iyi:139 in File.class#c_path
table: parse refusal 1 owner=bodies reason=undefined local variable or method '__iyi_open_read' for File.class example=src/iyi/file.iyi:54 in File.class#read
table: parse refusal 1 owner=unassigned reason=wrong number of arguments for 'String.interpolation' (given 2, expected 1) example=no location in File.class#read
table: parse refusal 1 owner=unassigned reason=unsupported node: Defer example=src/iyi/file.iyi:68 in File.class#read
table: parse refusal 1 owner=unassigned reason=wrong number of arguments for 'String.interpolation' (given 3, expected 1) example=no location in File.class#read
table: parse refusal 1 owner=bodies reason=the value of 'text' cannot be typed example=src/iyi/file.iyi:71 in File.class#read
table: parse refusal 1 owner=declarations reason=undefined constant Parser example=src/compiler/tools/parse.iyi:36 in Compiler::Tools::Parse::ParseTool.class#parse_source
table: parse refusal 1 owner=bodies reason=the value of 'parser' cannot be typed example=src/compiler/tools/parse.iyi:37 in Compiler::Tools::Parse::ParseTool.class#parse_source
table: parse defs-lowered-clean=15880 lowering-refusal-sites=12608
table: parse lowering 3318 owner=bodies reason=BUG: the analysed program has no type for the body of value (hosted codegen_fun: return type) example=Pointer(Atomic(UInt64))#value
table: parse lowering 2730 owner=bodies reason=BUG: the analysed program has no type for the body of new (hosted codegen_fun: return type) example=Pointer(UInt64).class#new
table: parse lowering 2075 owner=bodies reason=BUG: the analysed program has no type for the body of initialize (hosted codegen_fun: return type) example=Atomic(UInt64)#initialize
table: parse lowering 1817 owner=bodies reason=BUG: the analysed program has no type for the body of word (hosted codegen_fun: return type) example=IyiSchedLock.class#word
table: parse lowering 828 owner=bodies reason=BUG: the analysed program has no type for the body of unlock (hosted codegen_fun: return type) example=IyiRuntimeLock.class#unlock
table: parse lowering 468 owner=bodies reason=BUG: the analysed program has no type for the body of lock (hosted codegen_fun: return type) example=IyiRuntimeLock.class#lock
table: parse lowering 460 owner=bodies reason=BUG: the analysed program has no type for the body of state_id (hosted codegen_fun: return type) example=IyiScheduler.class#state_id
table: parse lowering 135 owner=bodies reason=BUG: the analysed program has no type for the body of malloc (hosted codegen_fun: return type) example=Pointer(UInt8).class#malloc
table: parse lowering 112 owner=bodies reason=BUG: the analysed program has no type for the body of held_here? (hosted codegen_fun: return type) example=IyiSchedLock.class#held_here?
table: parse lowering 110 owner=bodies reason=BUG: the analysed program has no type for the body of draw (hosted codegen_fun: return type) example=IyiChaos.class#draw
table: parse lowering 110 owner=bodies reason=BUG: the analysed program has no type for the body of % (hosted codegen_fun: return type) example=UInt64#%
table: parse lowering 55 owner=bodies reason=BUG: the analysed program has no type for the body of thread_point (hosted codegen_fun: return type) example=IyiChaos.class#thread_point
table: parse lowering 55 owner=bodies reason=BUG: the analysed program has no type for the body of held? (hosted codegen_fun: return type) example=IyiRuntimeLock.class#held?
table: parse lowering 55 owner=bodies reason=BUG: the analysed program has no type for the body of give_up (hosted codegen_fun: return type) example=IyiWorkers.class#give_up
table: parse lowering 30 owner=bodies reason=BUG: the analysed program has no type for the body of compare_and_set (hosted codegen_fun: return type) example=Atomic(UInt64)#compare_and_set
table: parse lowering 28 owner=bodies reason=BUG: the analysed program has no type for the body of get (hosted codegen_fun: return type) example=Atomic(UInt64)#get
table: parse lowering 18 owner=bodies reason=BUG: the analysed program has no type for the body of set (hosted codegen_fun: return type) example=Atomic(UInt64)#set
table: parse lowering 16 owner=bodies reason=BUG: the analysed program has no type for the body of deadlock (hosted codegen_fun: return type) example=IyiScheduler.class#deadlock
table: parse lowering 16 owner=bodies reason=BUG: the analysed program has no type for the body of add (hosted codegen_fun: return type) example=Atomic(UInt64)#add
table: parse lowering 16 owner=bodies reason=BUG: the analysed program has no type for the body of claim (hosted codegen_fun: return type) example=IyiFiber#claim
table: parse lowering 16 owner=bodies reason=BUG: the analysed program has no type for the body of [] (hosted codegen_fun: return type) example=Array(String)#[]
table: parse lowering 14 owner=bodies reason=BUG: the analysed program has no type for the body of take_lists (hosted codegen_fun: return type) example=IyiSchedulerState#take_lists
table: parse lowering 13 owner=lowering core reason=lower: visit(ASTNode) (hosted codegen.cr) is not ported yet example=IyiSchedulerState.class#allocate
table: parse lowering 11 owner=lowering core reason=lower: visit(assign Nil to (IyiFiber | Nil) (nilable target, hosted assign_distinct NilableType)) (hosted codegen.cr) is not ported yet example=IyiFiber#prev_fiber=
table: parse lowering 9 owner=lowering core reason=lower: visit(ClassVar) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#state
table: parse lowering 9 owner=lowering core reason=lower: visit(a call with no receiver inside a method, an implicit self call (hosted call.cr: prepare_call_args, self)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#landed
table: parse lowering 7 owner=lowering core reason=lower: visit(assign IyiFiber to (IyiFiber | Nil) (nilable target, hosted assign_distinct NilableType)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#current=
table: parse lowering 6 owner=bodies reason=BUG: the analysed program has no type for the body of wait_for_events (hosted codegen_fun: return type) example=IyiScheduler.class#wait_for_events
table: parse lowering 4 owner=lowering core reason=lower: visit(a restriction that converts argument 0 of set (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiFiber#on_cpu=
table: parse lowering 3 owner=lowering core reason=lower: visit(MacroIf) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#poll_now
table: parse lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of + (hosted codegen_fun: return type) example=String#+
table: parse lowering 2 owner=calls reason=BUG: the call to get has no target def (hosted call.cr: visit(Call)) example=IyiChanLock.class#acquire
table: parse lowering 2 owner=lowering core reason=lower: visit(a class method call on a receiver that is not a constant path (hosted call.cr: prepare_call_args, Path)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#register
table: parse lowering 2 owner=lowering core reason=lower: visit(a call to == inherited from a superclass of UInt64 (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=IyiChaos.class#step
table: parse lowering 2 owner=lowering core reason=lower: visit(a call to != inherited from a superclass of UInt64 (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=IyiUnit#waiting?
table: parse lowering 2 owner=calls reason=BUG: the call to < has no target def (hosted call.cr: visit(Call)) example=Array(Int32)#each
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of ensure_doorbell (hosted codegen_fun: return type) example=IyiScheduler.class#ensure_doorbell
table: parse lowering 2 owner=calls reason=BUG: the call to > has no target def (hosted call.cr: visit(Call)) example=IyiWorkers.class#work_waiting?
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of ring_size (hosted codegen_fun: return type) example=IyiSchedulerState#ring_size
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of run (hosted codegen_fun: return type) example=IyiOnce.class#run
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of to_s (hosted codegen_fun: return type) example=Int32#to_s
table: parse lowering 2 owner=lowering core reason=lower: visit(a call to == inherited from a superclass of Int32 (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=String#empty?
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of size (hosted codegen_fun: return type) example=Array(String)#size
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of run_spawned_fiber (hosted codegen_fun: return type) example=IyiScheduler.class#run_spawned_fiber
table: parse lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(IyiFiber | Nil) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiScheduler.class#current
table: parse lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiSchedulerState: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#first_state_here
table: parse lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiSchedulerState.class: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=IyiSchedulerState.class#new
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to new (hosted call.cr: visit(Call)) example=IyiSchedulerState#initialize
table: parse lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Atomic(UInt64) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Atomic(UInt64).class#new
table: parse lowering 1 owner=lowering core reason=lower: visit(allocate of class Atomic(UInt64).class: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=Atomic(UInt64).class#new
table: parse lowering 1 owner=lowering core reason=lower: visit(a call to == inherited from a superclass of Int64 (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Int64#!=
table: parse lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiFiber: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=IyiFiber.class#main
table: parse lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiFiber.class: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=IyiFiber.class#new
table: parse lowering 1 owner=lowering core reason=lower: visit(assign Int32 to IyiFiberState (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=IyiFiber#initialize
table: parse lowering 1 owner=lowering core reason=lower: visit(assign IyiSchedulerState to (IyiSchedulerState | Nil) (nilable target, hosted assign_distinct NilableType)) (hosted codegen.cr) is not ported yet example=IyiFiber#home=
table: parse lowering 1 owner=calls reason=BUG: the call to chaos_unit has no target def (hosted call.cr: visit(Call)) example=IyiChaos.class#unit_of
table: parse lowering 1 owner=calls reason=BUG: the call to state= has no target def (hosted call.cr: visit(Call)) example=IyiScheduler.class#enqueue
table: parse lowering 1 owner=lowering core reason=lower: visit(a restriction that converts argument 0 of add (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiFiber#claim_any
table: parse lowering 1 owner=unassigned reason=lower: is_a? of (IyiUnit | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiScheduler.class#release_unit
table: parse lowering 1 owner=lowering core reason=lower: visit(assign Nil to (IyiUnit | Nil) (nilable target, hosted assign_distinct NilableType)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#unit=
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to lock (hosted call.cr: visit(Call)) example=IyiScheduler.class#take_mail
table: parse lowering 1 owner=calls reason=BUG: the call to point has no target def (hosted call.cr: visit(Call)) example=IyiFiber#listed_on
table: parse lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(Int32) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiSchedulerState#closed_fds
table: parse lowering 1 owner=lowering core reason=lower: visit(assign Nil to (Array(Int32) | Nil) (nilable target, hosted assign_distinct NilableType)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#closed_fds=
table: parse lowering 1 owner=lowering core reason=lower: visit(Cast) (hosted codegen.cr) is not ported yet example=IyiWorkers.class#listed_at
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of reap_dying (hosted codegen_fun: return type) example=IyiScheduler.class#reap_dying
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of release_stack (hosted codegen_fun: return type) example=IyiFiber#release_stack
table: parse lowering 1 owner=unassigned reason=lower: is_a? of (IyiFiber | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiScheduler.class#wake_joiners
table: parse lowering 1 owner=unassigned reason=lower: read of constant STDOUT (hosted const.cr: read_const, read_const_pointer): its global and initialiser are not ported yet example=print
table: parse lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiIO.class: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=IyiIO.class#new
table: parse lowering 1 owner=lowering core reason=lower: visit(PointerOf) (hosted codegen.cr) is not ported yet example=String#to_unsafe
table: parse lowering 1 owner=calls reason=BUG: the call to raise has no target def (hosted call.cr: visit(Call)) example=IyiIO#write
table: parse lowering 1 owner=calls reason=BUG: the call to to_i64 has no target def (hosted call.cr: visit(Call)) example=__iyi_say
table: parse lowering 1 owner=calls reason=BUG: the call to == has no target def (hosted call.cr: visit(Call)) example=IyiTestCases.class#verdict
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of args (hosted codegen_fun: return type) example=Program.class#args
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of empty? (hosted codegen_fun: return type) example=Array(String)#empty?
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of exists? (hosted codegen_fun: return type) example=File.class#exists?
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of read (hosted codegen_fun: return type) example=File.class#read
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of c_path (hosted codegen_fun: return type) example=File.class#c_path
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse_source (hosted codegen_fun: return type) example=Compiler::Tools::Parse::ParseTool.class#parse_source
table: compile_native defs-reached=28762 defs-typed-clean=16063 root-refusals=46 refusal-sites=38715
table: compile_native refusal 10171 owner=declarations reason=undefined constant T example=src/iyi/primitives.iyi:159 in Pointer(Atomic(UInt64))#value
table: compile_native refusal 4910 owner=macros reason=macro control expansion (macros engine) example=src/iyi/./primitives.iyi:100 in top level
table: compile_native refusal 4884 owner=bodies reason=the value of 'seen' cannot be typed example=src/iyi/./concurrency.iyi:1561 in IyiChanLock.class#acquire
table: compile_native refusal 2730 owner=declarations reason=primitive pointer_new without a declared return type example=src/iyi/primitives.iyi:155 in Pointer(UInt64).class#new
table: compile_native refusal 2070 owner=unassigned reason=can't use instance variables in Atomic(UInt64) example=src/iyi/atomic.iyi:50 in Atomic(UInt64)#initialize
table: compile_native refusal 1740 owner=declarations reason=undefined constant HELD example=src/iyi/./concurrency.iyi:1561 in IyiChanLock.class#acquire
table: compile_native refusal 1421 owner=bodies reason=the value of '__temp_1' cannot be typed example=no location in IyiChanLock.class#acquire
table: compile_native refusal 819 owner=bodies reason=the value of '__temp_2' cannot be typed example=no location in IyiChanLock.class#contend
table: compile_native refusal 715 owner=calls reason=undefined method '>' for Int32 example=src/iyi/./concurrency.iyi:1576 in IyiChanLock.class#contend
table: compile_native refusal 696 owner=declarations reason=undefined constant SPINNER example=src/iyi/./concurrency.iyi:1576 in IyiChanLock.class#contend
table: compile_native refusal 474 owner=calls reason=undefined method '<' for Int64 example=src/iyi/prelude.iyi:104 in IyiRuntimeLock.class#lock
table: compile_native refusal 469 owner=bodies reason=the value of '__temp_3' cannot be typed example=no location in IyiRuntimeLock.class#lock
table: compile_native refusal 468 owner=calls reason=expected argument #2 to 'IyiAtomic.rmw' to be Pointer(<unresolved T>), not Pointer(UInt64) example=src/iyi/prelude.iyi:104 in IyiRuntimeLock.class#lock
table: compile_native refusal 462 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:1737 in IyiScheduler.class#state_id
table: compile_native refusal 440 owner=bodies reason=the value of 'state' cannot be typed example=src/iyi/./chaos.iyi:228 in IyiChaos.class#draw
table: compile_native refusal 385 owner=bodies reason=the value of 'unit' cannot be typed example=src/iyi/./chaos.iyi:265 in IyiChaos.class#unit_of
table: compile_native refusal 362 owner=calls reason=undefined method '&+' for Int32 example=src/iyi/./concurrency.iyi:1579 in IyiChanLock.class#contend
table: compile_native refusal 361 owner=calls reason=expected argument #1 to 'IyiAtomic.store' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/./concurrency.iyi:1475 in IyiSchedLock.class#unlock
table: compile_native refusal 348 owner=declarations reason=undefined constant UNMARKED example=src/iyi/./concurrency.iyi:1572 in IyiChanLock.class#contend
table: compile_native refusal 348 owner=bodies reason=the value of 'taken' cannot be typed example=src/iyi/./concurrency.iyi:1573 in IyiChanLock.class#contend
table: compile_native refusal 348 owner=calls reason=undefined method '&-' for Int32 example=src/iyi/./concurrency.iyi:1601 in IyiChanLock.class#contend
table: compile_native refusal 333 owner=unassigned reason=type mismatch for return type: expected IyiSchedulerState, got (IyiSchedulerState | Nil) example=src/iyi/./concurrency.iyi:1793 in IyiScheduler.class#state
table: compile_native refusal 277 owner=calls reason=undefined method '&+' for UInt64 example=src/iyi/./chaos.iyi:337 in IyiChaos.class#step
table: compile_native refusal 220 owner=declarations reason=undefined constant GOLDEN example=src/iyi/./chaos.iyi:227 in IyiChaos.class#draw
table: compile_native refusal 192 owner=calls reason=expected argument #1 to 'IyiFiber#state=' to be IyiFiberState, not Int32 example=src/iyi/./concurrency.iyi:756 in IyiFiber.class#main
table: compile_native refusal 165 owner=declarations reason=undefined constant SIMULATED example=src/iyi/./chaos.iyi:312 in IyiChaos.class#point
table: compile_native refusal 135 owner=unassigned reason=type mismatch for return type: expected IyiFiber, got (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:1829 in IyiScheduler.class#current
table: compile_native refusal 135 owner=unassigned reason=instance variable '@state' of IyiFiber must be IyiFiberState, not (IyiFiberState | Int32) example=src/iyi/./concurrency.iyi:635 in IyiFiber#initialize
table: compile_native refusal 135 owner=declarations reason=primitive pointer_malloc without a declared return type example=src/iyi/primitives.iyi:151 in Pointer(UInt8).class#malloc
table: compile_native refusal 135 owner=calls reason=undefined method 'prev_fiber=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1863 in IyiScheduler.class#register
table: compile_native refusal 124 owner=calls reason=undefined method 'to_i64' for Int32 example=src/iyi/io.iyi:358 in IyiIO#flush
table: compile_native refusal 110 owner=calls reason=undefined method '&-' for UInt64 example=src/iyi/./chaos.iyi:353 in IyiChaos.class#step
table: compile_native refusal 110 owner=bodies reason=the value of 'ordinal' cannot be typed example=src/iyi/./chaos.iyi:233 in IyiChaos.class#draw
table: compile_native refusal 110 owner=bodies reason=undefined local variable or method 'raise' for UInt64 example=src/iyi/number.iyi:169 in UInt64#%
table: compile_native refusal 110 owner=bodies reason=undefined local variable or method 'unsafe_mod' for UInt64 example=src/iyi/number.iyi:170 in UInt64#%
table: compile_native refusal 94 owner=unassigned reason=wrong number of arguments for 'Int32#+' (given 1, expected 0) example=src/iyi/array.iyi:228 in Array(Int32)#each
table: compile_native refusal 92 owner=bodies reason=undefined local variable or method 'previous_def' for Atomic(UInt64) example=src/iyi/./chaos_points.iyi:16 in Atomic(UInt64)#get
table: compile_native refusal 63 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3990 in IyiScheduler.class#deadlock_found
table: compile_native refusal 60 owner=declarations reason=undefined constant Tuple(T, Bool) example=src/iyi/./chaos_points.iyi:39 in IyiSchedulerState#take_lists
table: compile_native refusal 59 owner=calls reason=undefined method 'next_run=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2154 in IyiScheduler.class#enqueue
table: compile_native refusal 57 owner=calls reason=undefined method '<' for Int32 example=src/iyi/array.iyi:25 in Array#initialize
table: compile_native refusal 55 owner=calls reason=undefined method 'chaos_unit' for IyiFiber example=src/iyi/./chaos.iyi:264 in IyiChaos.class#unit_of
table: compile_native refusal 55 owner=declarations reason=undefined constant HIGH example=src/iyi/./chaos.iyi:267 in IyiChaos.class#unit_of
table: compile_native refusal 55 owner=calls reason=undefined method 'chaos_unit=' for IyiFiber example=src/iyi/./chaos.iyi:269 in IyiChaos.class#unit_of
table: compile_native refusal 55 owner=declarations reason=undefined constant LOW example=src/iyi/./chaos.iyi:348 in IyiChaos.class#step
table: compile_native refusal 55 owner=declarations reason=undefined constant SPIN_STEPS example=src/iyi/./chaos.iyi:350 in IyiChaos.class#step
table: compile_native refusal 55 owner=calls reason=undefined method '|' for UInt64 example=src/iyi/./chaos.iyi:356 in IyiChaos.class#step
table: compile_native refusal 55 owner=calls reason=undefined method 'chaos_held=' for IyiFiber example=src/iyi/./chaos.iyi:357 in IyiChaos.class#step
table: compile_native refusal 55 owner=declarations reason=undefined constant THREADS example=src/iyi/./chaos.iyi:314 in IyiChaos.class#point
table: compile_native refusal 55 owner=declarations reason=undefined constant IyiThread example=src/iyi/./chaos.iyi:525 in IyiChaos.class#thread_point
table: compile_native refusal 52 owner=bodies reason=the value of 'n' cannot be typed example=src/iyi/io.iyi:362 in IyiIO#flush
table: compile_native refusal 48 owner=declarations reason=undefined constant DEADLOCK example=src/iyi/./concurrency.iyi:4011 in IyiScheduler.class#deadlock
table: compile_native refusal 46 owner=bodies reason=the value of 'total' cannot be typed example=src/iyi/io.iyi:360 in IyiIO#flush
table: compile_native refusal 44 owner=unassigned reason=can't infer the type of instance variable '@size' of Array(String) example=src/iyi/array.iyi:92 in Array(String)#size
table: compile_native refusal 32 owner=calls reason=undefined method 'state' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3997 in IyiScheduler.class#deadlock_found
table: compile_native refusal 32 owner=calls reason=expected argument #1 to 'IyiScheduler.enqueue' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:3998 in IyiScheduler.class#deadlock_found
table: compile_native refusal 28 owner=unassigned reason=unsupported node: Unless example=src/iyi/string.iyi:531 in String#==
table: compile_native refusal 20 owner=bodies reason=undefined local variable or method 'raise' for IyiIO example=src/iyi/io.iyi:284 in IyiIO#write
table: compile_native refusal 18 owner=bodies reason=the value of 'now' cannot be typed example=src/iyi/./concurrency.iyi:2761 in IyiScheduler.class#poll_now
table: compile_native refusal 18 owner=calls reason=expected argument #1 to 'Pointer(UInt8)#+' to be Int64, not Int32 example=src/iyi/string.iyi:537 in String#==
table: compile_native refusal 16 owner=bodies reason=undefined local variable or method '__iyi_monotonic_ns' for IyiScheduler.class example=src/iyi/./concurrency.iyi:2760 in IyiScheduler.class#poll_now
table: compile_native refusal 16 owner=bodies reason=the value of 'task' cannot be typed example=src/iyi/./concurrency.iyi:3987 in IyiScheduler.class#deadlock_found
table: compile_native refusal 16 owner=bodies reason=the value of 'group' cannot be typed example=src/iyi/./concurrency.iyi:3989 in IyiScheduler.class#deadlock_found
table: compile_native refusal 16 owner=calls reason=undefined method 'claim_any' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3998 in IyiScheduler.class#deadlock_found
table: compile_native refusal 14 owner=calls reason=undefined method 'deadline' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4026 in IyiScheduler.class#wait_for_events
table: compile_native refusal 14 owner=unassigned reason=wrong number of arguments for 'Int64#+' (given 1, expected 0) example=src/iyi/./concurrency.iyi:4049 in IyiScheduler.class#wait_for_events
table: compile_native refusal 13 owner=calls reason=undefined method 'to_u64' for Int32 example=src/iyi/io.iyi:36 in IyiIO#initialize
table: compile_native refusal 13 owner=unassigned reason=wrong number of arguments for 'Int32#-' (given 1, expected 0) example=src/iyi/testing.iyi:251 in IyiTestCases.class#verdict
table: compile_native refusal 13 owner=unassigned reason=can't infer the type of instance variable '@buffer' of Array(String) example=src/iyi/array.iyi:137 in Array(String)#[]
table: compile_native refusal 12 owner=declarations reason=undefined constant IYI_POLL_EVENT_BYTES example=src/iyi/./concurrency.iyi:4167 in IyiScheduler.class#wait_for_events
table: compile_native refusal 12 owner=bodies reason=the value of 'entry' cannot be typed example=src/iyi/./concurrency.iyi:4168 in IyiScheduler.class#wait_for_events
table: compile_native refusal 12 owner=bodies reason=the value of 'ready' cannot be typed example=src/iyi/./concurrency.iyi:4181 in IyiScheduler.class#wait_for_events
table: compile_native refusal 12 owner=bodies reason=the value of 'fd' cannot be typed example=src/iyi/./concurrency.iyi:4181 in IyiScheduler.class#wait_for_events
table: compile_native refusal 10 owner=bodies reason=the value of 'buffer' cannot be typed example=src/iyi/file.iyi:141 in File.class#c_path
table: compile_native refusal 9 owner=unassigned reason=unsupported node: TraitDef example=src/std/traits.iyi:24 in top level
table: compile_native refusal 9 owner=bodies reason=the value of 'target' cannot be typed example=src/compiler/tools/compile_native.iyi:137 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 8 owner=calls reason=undefined method 'awaited' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3986 in IyiScheduler.class#deadlock_found
table: compile_native refusal 8 owner=calls reason=undefined method 'joining' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3988 in IyiScheduler.class#deadlock_found
table: compile_native refusal 8 owner=calls reason=undefined method 'deadlocked=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3994 in IyiScheduler.class#deadlock_found
table: compile_native refusal 8 owner=calls reason=expected argument #2 to 'IyiScheduler.heap_remove' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:4661 in IyiScheduler.class#wake_expired_sleepers
table: compile_native refusal 8 owner=calls reason=undefined method 'io_timed' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4662 in IyiScheduler.class#wake_expired_sleepers
table: compile_native refusal 8 owner=calls reason=undefined method 'io_timed=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4664 in IyiScheduler.class#wake_expired_sleepers
table: compile_native refusal 8 owner=calls reason=undefined method 'timed_out=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4665 in IyiScheduler.class#wake_expired_sleepers
table: compile_native refusal 8 owner=calls reason=undefined method '&*' for UInt64 example=src/iyi/string.iyi:508 in String#byte_index
table: compile_native refusal 8 owner=bodies reason=the value of 'mod' cannot be typed example=src/compiler/tools/compile_native.iyi:51 in Compiler::Tools::CompileNative::CompileNative.class#module_of
table: compile_native refusal 7 owner=bodies reason=the value of 'following' cannot be typed example=src/iyi/./concurrency.iyi:2318 in IyiScheduler.class#take_mail
table: compile_native refusal 7 owner=declarations reason=undefined constant TARGET example=src/compiler/tools/compile_native.iyi:82 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 7 owner=unassigned reason=wrong number of arguments for 'String.interpolation' (given 2, expected 1) example=no location in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 7 owner=unassigned reason=wrong number of arguments for 'String.interpolation' (given 3, expected 1) example=no location in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 6 owner=bodies reason=the value of 'head_deadline' cannot be typed example=src/iyi/./concurrency.iyi:4047 in IyiScheduler.class#wait_for_events
table: compile_native refusal 6 owner=bodies reason=the value of 'gap' cannot be typed example=src/iyi/./concurrency.iyi:4048 in IyiScheduler.class#wait_for_events
table: compile_native refusal 6 owner=declarations reason=undefined constant EVENTS example=src/iyi/./concurrency.iyi:4982 in IyiScheduler.class#events_buffer
table: compile_native refusal 6 owner=declarations reason=undefined constant IYI_POLL_DATA_OFFSET example=src/iyi/./concurrency.iyi:4168 in IyiScheduler.class#wait_for_events
table: compile_native refusal 6 owner=calls reason=expected argument #1 to 'IyiScheduler.switch_to' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:2595 in IyiScheduler.class#reschedule
table: compile_native refusal 6 owner=bodies reason=undefined local variable or method 'file' for main example=src/iyi/prelude.iyi:11005 in raise
table: compile_native refusal 6 owner=bodies reason=the value of 'limit' cannot be typed example=src/iyi/string.iyi:490 in String#byte_index
table: compile_native refusal 6 owner=bodies reason=the value of 'io' cannot be typed example=src/iyi/file.iyi:68 in File.class#read
table: compile_native refusal 6 owner=unassigned reason=can't use instance variables in Array(String) example=src/iyi/array.iyi:17 in Array(String)#initialize
table: compile_native refusal 6 owner=bodies reason=the value of 'memory' cannot be typed example=src/iyi/string.iyi:37 in String.class#new
table: compile_native refusal 5 owner=bodies reason=undefined local variable or method 'raise' for IyiScheduler.class example=src/iyi/./concurrency.iyi:2587 in IyiScheduler.class#reschedule
table: compile_native refusal 4 owner=bodies reason=the value of 'parks' cannot be typed example=src/iyi/./concurrency.iyi:2590 in IyiScheduler.class#reschedule
table: compile_native refusal 4 owner=bodies reason=the value of 'waits_here' cannot be typed example=src/iyi/./concurrency.iyi:2327 in IyiScheduler.class#take_mail
table: compile_native refusal 4 owner=bodies reason=the value of 'rest' cannot be typed example=src/iyi/./concurrency.iyi:3611 in IyiScheduler.class#wake_joiners
table: compile_native refusal 4 owner=declarations reason=undefined constant HEADER_SIZE example=src/iyi/string.iyi:36 in String.class#new
table: compile_native refusal 4 owner=calls reason=expected argument #2 to 'Pointer(Int32)#[]=' to be <unresolved T>, not Int32 example=src/iyi/string.iyi:42 in String.class#new
table: compile_native refusal 3 owner=calls reason=undefined method '<=' for Int32 example=src/iyi/io.iyi:285 in IyiIO#write
table: compile_native refusal 3 owner=calls reason=expected argument #1 to 'Pointer#+' to be Int64, not Int32 example=src/iyi/io.iyi:300 in IyiIO#write
table: compile_native refusal 3 owner=calls reason=undefined method '>=' for Int32 example=src/iyi/io.iyi:304 in IyiIO#write
table: compile_native refusal 3 owner=calls reason=expected argument #1 to 'Pointer#copy_from' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/io.iyi:313 in IyiIO#write
table: compile_native refusal 3 owner=bodies reason=undefined local variable or method '__iyi_exit' for top-level example=src/iyi/prelude.iyi:10751 in top level
table: compile_native refusal 3 owner=bodies reason=undefined local variable or method 'raise' for Array example=src/iyi/array.iyi:25 in Array#initialize
table: compile_native refusal 3 owner=bodies reason=the value of 'compiler' cannot be typed example=src/compiler/tools/compile_native.iyi:161 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 3 owner=bodies reason=the value of 'parsed' cannot be typed example=src/compiler/tools/compile_native.iyi:47 in Compiler::Tools::CompileNative::CompileNative.class#module_of
table: compile_native refusal 3 owner=declarations reason=undefined constant Module example=src/compiler/tools/compile_native.iyi:50 in Compiler::Tools::CompileNative::CompileNative.class#module_of
table: compile_native refusal 3 owner=bodies reason=the value of 'built' cannot be typed example=src/compiler/tools/compile_native.iyi:179 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 3 owner=bodies reason=the value of 'name' cannot be typed example=src/compiler/tools/compile_native.iyi:74 in Array(String)#each
table: compile_native refusal 3 owner=bodies reason=the value of 'result' cannot be typed example=src/compiler/tools/compile_native.iyi:193 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 2 owner=declarations reason=undefined constant POLL_EVERY example=src/iyi/./concurrency.iyi:2591 in IyiScheduler.class#reschedule
table: compile_native refusal 2 owner=declarations reason=undefined constant POLL_IO_NS example=src/iyi/./concurrency.iyi:2761 in IyiScheduler.class#poll_now
table: compile_native refusal 2 owner=calls reason=undefined method 'give' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:2721 in IyiScheduler.class#release_unit
table: compile_native refusal 2 owner=calls reason=undefined method 'waiting?' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:2722 in IyiScheduler.class#release_unit
table: compile_native refusal 2 owner=calls reason=expected argument #2 to 'IyiScheduler.drain_unit' to be IyiUnit, not (IyiUnit | Nil) example=src/iyi/./concurrency.iyi:2724 in IyiScheduler.class#release_unit
table: compile_native refusal 2 owner=calls reason=undefined method 'next_run' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2309 in IyiScheduler.class#take_mail
table: compile_native refusal 2 owner=calls reason=undefined method 'next_cancel' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2323 in IyiScheduler.class#take_mail
table: compile_native refusal 2 owner=calls reason=undefined method 'next_cancel=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2324 in IyiScheduler.class#take_mail
table: compile_native refusal 2 owner=calls reason=undefined method 'cancel_posted=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2325 in IyiScheduler.class#take_mail
table: compile_native refusal 2 owner=calls reason=undefined method 'unit' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2326 in IyiScheduler.class#take_mail
table: compile_native refusal 2 owner=calls reason=undefined method 'listed_on' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2326 in IyiScheduler.class#take_mail
table: compile_native refusal 2 owner=calls reason=undefined method 'waiting_out' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2327 in IyiScheduler.class#take_mail
table: compile_native refusal 2 owner=calls reason=expected argument #1 to 'IyiScheduler.cancel_wait' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:2328 in IyiScheduler.class#take_mail
table: compile_native refusal 2 owner=unassigned reason=can't infer the type of instance variable '@size' of Array(Int32) example=src/iyi/array.iyi:226 in Array(Int32)#each
table: compile_native refusal 2 owner=unassigned reason=can't infer the type of instance variable '@buffer' of Array(Int32) example=src/iyi/array.iyi:227 in Array(Int32)#each
table: compile_native refusal 2 owner=bodies reason=undefined local variable or method 'fd' for Array(Int32) example=src/iyi/./concurrency.iyi:2335 in Array(Int32)#each
table: compile_native refusal 2 owner=calls reason=undefined method 'each' for Nil (compile-time type is (Array(Int32) | Nil)) example=src/iyi/./concurrency.iyi:2335 in IyiScheduler.class#take_mail
table: compile_native refusal 2 owner=calls reason=undefined method 'quiet' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2500 in IyiScheduler.class#all_quiet?
table: compile_native refusal 2 owner=calls reason=undefined method 'idle' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: compile_native refusal 2 owner=bodies reason=the value of 'quiet' cannot be typed example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: compile_native refusal 2 owner=calls reason=undefined method 'mail?' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: compile_native refusal 2 owner=calls reason=undefined method 'next_state' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2506 in IyiScheduler.class#all_quiet?
table: compile_native refusal 2 owner=calls reason=undefined method '>' for Int64 example=src/iyi/./concurrency.iyi:2508 in IyiScheduler.class#all_quiet?
table: compile_native refusal 2 owner=bodies reason=the value of 'count' cannot be typed example=src/iyi/./concurrency.iyi:5784 in IyiWorkers.class#work_waiting?
table: compile_native refusal 2 owner=calls reason=undefined method 'to_u64' for Int64 example=src/iyi/./concurrency.iyi:5591 in IyiWorkers.class#listed_at
table: compile_native refusal 2 owner=calls reason=undefined method '>=' for UInt64 example=src/iyi/./concurrency.iyi:1436 in IyiSchedulerState#ring_size
table: compile_native refusal 2 owner=calls reason=undefined method '-' for UInt64 example=src/iyi/./concurrency.iyi:1436 in IyiSchedulerState#ring_size
table: compile_native refusal 2 owner=calls reason=undefined method '>' for UInt64 example=src/iyi/./concurrency.iyi:5785 in IyiWorkers.class#work_waiting?
table: compile_native refusal 2 owner=calls reason=undefined method '&+' for Int64 example=src/iyi/./concurrency.iyi:5786 in IyiWorkers.class#work_waiting?
table: compile_native refusal 2 owner=calls reason=undefined method 'next_joiner' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3609 in IyiScheduler.class#wake_joiners
table: compile_native refusal 2 owner=calls reason=undefined method 'next_joiner=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3610 in IyiScheduler.class#wake_joiners
table: compile_native refusal 2 owner=calls reason=expected argument #1 to 'IyiAtomic.load' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/prelude.iyi:10779 in top level
table: compile_native refusal 2 owner=unassigned reason=unsupported node: MagicConstant example=src/iyi/prelude.iyi:10967 in top level
table: compile_native refusal 2 owner=bodies reason=undefined local variable or method 'to_i64' for Int32 example=src/iyi/number.iyi:124 in Int32#to_s
table: compile_native refusal 2 owner=calls reason=undefined method 'exit' for Compiler::Tools::CompileNative::LibC.class example=src/compiler/tools/compile_native.iyi:138 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 2 owner=bodies reason=the value of 'config' cannot be typed example=src/compiler/tools/compile_native.iyi:157 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 2 owner=bodies reason=the value of 'loader' cannot be typed example=src/compiler/tools/compile_native.iyi:159 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 2 owner=bodies reason=the value of 'refusal' cannot be typed example=src/compiler/tools/compile_native.iyi:164 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 2 owner=bodies reason=undefined local variable or method 'raise' for File.class example=src/iyi/file.iyi:139 in File.class#c_path
table: compile_native refusal 2 owner=bodies reason=undefined local variable or method '__iyi_open_read' for File.class example=src/iyi/file.iyi:54 in File.class#read
table: compile_native refusal 2 owner=unassigned reason=unsupported node: Defer example=src/iyi/file.iyi:68 in File.class#read
table: compile_native refusal 2 owner=bodies reason=the value of 'text' cannot be typed example=src/iyi/file.iyi:71 in File.class#read
table: compile_native refusal 2 owner=bodies reason=the value of 'errors' cannot be typed example=src/compiler/tools/compile_native.iyi:52 in Compiler::Tools::CompileNative::CompileNative.class#module_of
table: compile_native refusal 2 owner=bodies reason=the value of 'runtime' cannot be typed example=src/compiler/tools/compile_native.iyi:178 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 2 owner=bodies reason=undefined local variable or method 'each_byte' for String.class example=src/iyi/string.iyi:591 in String.class#new
table: compile_native refusal 2 owner=bodies reason=the value of 'image' cannot be typed example=src/compiler/tools/compile_native.iyi:197 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 1 owner=calls reason=undefined method 'on_cpu=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1917 in IyiScheduler.class#landed
table: compile_native refusal 1 owner=declarations reason=undefined constant STACK_BYTES example=src/iyi/./concurrency.iyi:926 in IyiFiber#release_stack
table: compile_native refusal 1 owner=calls reason=undefined method 'release_stack' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1932 in IyiScheduler.class#reap_dying
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.unregister' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:1933 in IyiScheduler.class#reap_dying
table: compile_native refusal 1 owner=unassigned reason=wrong number of arguments for 'Proc(Nil)#call' (given 0, expected 1) example=src/iyi/./concurrency.iyi:2874 in IyiScheduler.class#run_spawned_fiber
table: compile_native refusal 1 owner=calls reason=undefined method 'awaited=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3620 in IyiScheduler.class#wake_joiners
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.ready' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:3621 in IyiScheduler.class#wake_joiners
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method '__iyi_program' for top-level example=src/iyi/prelude.iyi:10726 in top level
table: compile_native refusal 1 owner=calls reason=undefined method '__iyi_main' for LibIyiMain.class example=src/iyi/prelude.iyi:10741 in top level
table: compile_native refusal 1 owner=bodies reason=the value of '__temp_4' cannot be typed example=no location in raise
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'line' for main example=src/iyi/prelude.iyi:11009 in raise
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method '__iyi_enter' for top-level example=src/iyi/prelude.iyi:11698 in top level
table: compile_native refusal 1 owner=bodies reason=the value of 'offset' cannot be typed example=src/iyi/string.iyi:334 in String#ends_with?
table: compile_native refusal 1 owner=declarations reason=undefined constant CompilerConfig example=src/compiler/tools/compile_native.iyi:156 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 1 owner=calls reason=undefined method 'new' for Compiler::Loader.class example=src/compiler/tools/compile_native.iyi:158 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 1 owner=declarations reason=undefined constant NativeBackend example=src/compiler/tools/compile_native.iyi:160 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'parse' for Compiler::Tools::CompileNative::CompileNative.class example=src/compiler/tools/compile_native.iyi:46 in Compiler::Tools::CompileNative::CompileNative.class#module_of
table: compile_native refusal 1 owner=declarations reason=undefined constant IrParseError example=src/compiler/tools/compile_native.iyi:47 in Compiler::Tools::CompileNative::CompileNative.class#module_of
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'start_wasm32_ir' for Compiler::Tools::CompileNative::CompileNative.class example=src/compiler/tools/compile_native.iyi:177 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'to_bytes' for Compiler::Tools::CompileNative::CompileNative.class example=src/compiler/tools/compile_native.iyi:183 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 1 owner=unassigned reason=can't infer the type of instance variable '@size' of Array(UInt8) example=src/iyi/array.iyi:92 in Array(UInt8)#size
table: compile_native refusal 1 owner=unassigned reason=wrong number of arguments for 'String.interpolation' (given 5, expected 1) example=no location in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'builtins_ir' for Compiler::Tools::CompileNative::CompileNative.class example=src/compiler/tools/compile_native.iyi:190 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'line' for Array(String) example=src/compiler/tools/compile_native.iyi:73 in Array(String)#each
table: compile_native refusal 1 owner=declarations reason=undefined constant LinkedImage example=src/compiler/tools/compile_native.iyi:196 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native defs-lowered-clean=16025 lowering-refusal-sites=12737
table: compile_native lowering 3318 owner=bodies reason=BUG: the analysed program has no type for the body of value (hosted codegen_fun: return type) example=Pointer(Atomic(UInt64))#value
table: compile_native lowering 2730 owner=bodies reason=BUG: the analysed program has no type for the body of new (hosted codegen_fun: return type) example=Pointer(UInt64).class#new
table: compile_native lowering 2081 owner=bodies reason=BUG: the analysed program has no type for the body of initialize (hosted codegen_fun: return type) example=Atomic(UInt64)#initialize
table: compile_native lowering 1817 owner=bodies reason=BUG: the analysed program has no type for the body of word (hosted codegen_fun: return type) example=IyiSchedLock.class#word
table: compile_native lowering 828 owner=bodies reason=BUG: the analysed program has no type for the body of unlock (hosted codegen_fun: return type) example=IyiRuntimeLock.class#unlock
table: compile_native lowering 468 owner=bodies reason=BUG: the analysed program has no type for the body of lock (hosted codegen_fun: return type) example=IyiRuntimeLock.class#lock
table: compile_native lowering 460 owner=bodies reason=BUG: the analysed program has no type for the body of state_id (hosted codegen_fun: return type) example=IyiScheduler.class#state_id
table: compile_native lowering 135 owner=bodies reason=BUG: the analysed program has no type for the body of malloc (hosted codegen_fun: return type) example=Pointer(UInt8).class#malloc
table: compile_native lowering 113 owner=bodies reason=BUG: the analysed program has no type for the body of [] (hosted codegen_fun: return type) example=Array(String)#[]
table: compile_native lowering 112 owner=bodies reason=BUG: the analysed program has no type for the body of held_here? (hosted codegen_fun: return type) example=IyiSchedLock.class#held_here?
table: compile_native lowering 110 owner=bodies reason=BUG: the analysed program has no type for the body of draw (hosted codegen_fun: return type) example=IyiChaos.class#draw
table: compile_native lowering 110 owner=bodies reason=BUG: the analysed program has no type for the body of % (hosted codegen_fun: return type) example=UInt64#%
table: compile_native lowering 55 owner=bodies reason=BUG: the analysed program has no type for the body of thread_point (hosted codegen_fun: return type) example=IyiChaos.class#thread_point
table: compile_native lowering 55 owner=bodies reason=BUG: the analysed program has no type for the body of held? (hosted codegen_fun: return type) example=IyiRuntimeLock.class#held?
table: compile_native lowering 55 owner=bodies reason=BUG: the analysed program has no type for the body of give_up (hosted codegen_fun: return type) example=IyiWorkers.class#give_up
table: compile_native lowering 30 owner=bodies reason=BUG: the analysed program has no type for the body of compare_and_set (hosted codegen_fun: return type) example=Atomic(UInt64)#compare_and_set
table: compile_native lowering 28 owner=bodies reason=BUG: the analysed program has no type for the body of get (hosted codegen_fun: return type) example=Atomic(UInt64)#get
table: compile_native lowering 18 owner=bodies reason=BUG: the analysed program has no type for the body of set (hosted codegen_fun: return type) example=Atomic(UInt64)#set
table: compile_native lowering 16 owner=lowering core reason=lower: visit(ASTNode) (hosted codegen.cr) is not ported yet example=IyiSchedulerState.class#allocate
table: compile_native lowering 16 owner=bodies reason=BUG: the analysed program has no type for the body of deadlock (hosted codegen_fun: return type) example=IyiScheduler.class#deadlock
table: compile_native lowering 16 owner=bodies reason=BUG: the analysed program has no type for the body of add (hosted codegen_fun: return type) example=Atomic(UInt64)#add
table: compile_native lowering 16 owner=bodies reason=BUG: the analysed program has no type for the body of claim (hosted codegen_fun: return type) example=IyiFiber#claim
table: compile_native lowering 14 owner=bodies reason=BUG: the analysed program has no type for the body of take_lists (hosted codegen_fun: return type) example=IyiSchedulerState#take_lists
table: compile_native lowering 11 owner=lowering core reason=lower: visit(assign Nil to (IyiFiber | Nil) (nilable target, hosted assign_distinct NilableType)) (hosted codegen.cr) is not ported yet example=IyiFiber#prev_fiber=
table: compile_native lowering 10 owner=lowering core reason=lower: visit(a call with no receiver inside a method, an implicit self call (hosted call.cr: prepare_call_args, self)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#landed
table: compile_native lowering 9 owner=lowering core reason=lower: visit(ClassVar) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#state
table: compile_native lowering 8 owner=bodies reason=BUG: the analysed program has no type for the body of size (hosted codegen_fun: return type) example=Array(String)#size
table: compile_native lowering 7 owner=lowering core reason=lower: visit(assign IyiFiber to (IyiFiber | Nil) (nilable target, hosted assign_distinct NilableType)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#current=
table: compile_native lowering 6 owner=bodies reason=BUG: the analysed program has no type for the body of wait_for_events (hosted codegen_fun: return type) example=IyiScheduler.class#wait_for_events
table: compile_native lowering 4 owner=lowering core reason=lower: visit(a restriction that converts argument 0 of set (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiFiber#on_cpu=
table: compile_native lowering 4 owner=calls reason=BUG: the call to < has no target def (hosted call.cr: visit(Call)) example=Array(Int32)#each
table: compile_native lowering 3 owner=lowering core reason=lower: visit(MacroIf) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#poll_now
table: compile_native lowering 3 owner=calls reason=BUG: the call to > has no target def (hosted call.cr: visit(Call)) example=IyiWorkers.class#work_waiting?
table: compile_native lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of + (hosted codegen_fun: return type) example=String#+
table: compile_native lowering 2 owner=calls reason=BUG: the call to get has no target def (hosted call.cr: visit(Call)) example=IyiChanLock.class#acquire
table: compile_native lowering 2 owner=lowering core reason=lower: visit(a class method call on a receiver that is not a constant path (hosted call.cr: prepare_call_args, Path)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#register
table: compile_native lowering 2 owner=lowering core reason=lower: visit(a call to == inherited from a superclass of UInt64 (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=IyiChaos.class#step
table: compile_native lowering 2 owner=lowering core reason=lower: visit(a call to != inherited from a superclass of UInt64 (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=IyiUnit#waiting?
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of ensure_doorbell (hosted codegen_fun: return type) example=IyiScheduler.class#ensure_doorbell
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of ring_size (hosted codegen_fun: return type) example=IyiSchedulerState#ring_size
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of run (hosted codegen_fun: return type) example=IyiOnce.class#run
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of to_s (hosted codegen_fun: return type) example=Int32#to_s
table: compile_native lowering 2 owner=lowering core reason=lower: visit(a call to == inherited from a superclass of Int32 (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=String#empty?
table: compile_native lowering 2 owner=lowering core reason=lower: visit(a class method call on Array(T).class (hosted call.cr: prepare_call_args, a generic or builtin metaclass)) (hosted codegen.cr) is not ported yet example=Std::Base64::Base64.class#decode_values
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of exists? (hosted codegen_fun: return type) example=File.class#exists?
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of read (hosted codegen_fun: return type) example=File.class#read
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of c_path (hosted codegen_fun: return type) example=File.class#c_path
table: compile_native lowering 2 owner=lowering core reason=lower: visit(ArrayLiteral) (hosted codegen.cr) is not ported yet example=Compiler::Tools::CompileNative::CompileNative.class#sidecar_libraries
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of run_spawned_fiber (hosted codegen_fun: return type) example=IyiScheduler.class#run_spawned_fiber
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(IyiFiber | Nil) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiScheduler.class#current
table: compile_native lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiSchedulerState: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#first_state_here
table: compile_native lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiSchedulerState.class: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=IyiSchedulerState.class#new
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to new (hosted call.cr: visit(Call)) example=IyiSchedulerState#initialize
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Atomic(UInt64) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Atomic(UInt64).class#new
table: compile_native lowering 1 owner=lowering core reason=lower: visit(allocate of class Atomic(UInt64).class: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=Atomic(UInt64).class#new
table: compile_native lowering 1 owner=lowering core reason=lower: visit(a call to == inherited from a superclass of Int64 (hosted call.cr: target_def.owner is the defining type)) (hosted codegen.cr) is not ported yet example=Int64#!=
table: compile_native lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiFiber: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=IyiFiber.class#main
table: compile_native lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiFiber.class: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=IyiFiber.class#new
table: compile_native lowering 1 owner=lowering core reason=lower: visit(assign Int32 to IyiFiberState (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=IyiFiber#initialize
table: compile_native lowering 1 owner=lowering core reason=lower: visit(assign IyiSchedulerState to (IyiSchedulerState | Nil) (nilable target, hosted assign_distinct NilableType)) (hosted codegen.cr) is not ported yet example=IyiFiber#home=
table: compile_native lowering 1 owner=calls reason=BUG: the call to chaos_unit has no target def (hosted call.cr: visit(Call)) example=IyiChaos.class#unit_of
table: compile_native lowering 1 owner=calls reason=BUG: the call to state= has no target def (hosted call.cr: visit(Call)) example=IyiScheduler.class#enqueue
table: compile_native lowering 1 owner=lowering core reason=lower: visit(a restriction that converts argument 0 of add (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiFiber#claim_any
table: compile_native lowering 1 owner=unassigned reason=lower: is_a? of (IyiUnit | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiScheduler.class#release_unit
table: compile_native lowering 1 owner=lowering core reason=lower: visit(assign Nil to (IyiUnit | Nil) (nilable target, hosted assign_distinct NilableType)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#unit=
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to lock (hosted call.cr: visit(Call)) example=IyiScheduler.class#take_mail
table: compile_native lowering 1 owner=calls reason=BUG: the call to point has no target def (hosted call.cr: visit(Call)) example=IyiFiber#listed_on
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(Int32) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiSchedulerState#closed_fds
table: compile_native lowering 1 owner=lowering core reason=lower: visit(assign Nil to (Array(Int32) | Nil) (nilable target, hosted assign_distinct NilableType)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#closed_fds=
table: compile_native lowering 1 owner=lowering core reason=lower: visit(Cast) (hosted codegen.cr) is not ported yet example=IyiWorkers.class#listed_at
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of reap_dying (hosted codegen_fun: return type) example=IyiScheduler.class#reap_dying
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of release_stack (hosted codegen_fun: return type) example=IyiFiber#release_stack
table: compile_native lowering 1 owner=unassigned reason=lower: is_a? of (IyiFiber | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiScheduler.class#wake_joiners
table: compile_native lowering 1 owner=unassigned reason=lower: read of constant STDOUT (hosted const.cr: read_const, read_const_pointer): its global and initialiser are not ported yet example=print
table: compile_native lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiIO.class: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=IyiIO.class#new
table: compile_native lowering 1 owner=lowering core reason=lower: visit(PointerOf) (hosted codegen.cr) is not ported yet example=String#to_unsafe
table: compile_native lowering 1 owner=calls reason=BUG: the call to raise has no target def (hosted call.cr: visit(Call)) example=IyiIO#write
table: compile_native lowering 1 owner=calls reason=BUG: the call to to_i64 has no target def (hosted call.cr: visit(Call)) example=__iyi_say
table: compile_native lowering 1 owner=calls reason=BUG: the call to == has no target def (hosted call.cr: visit(Call)) example=IyiTestCases.class#verdict
table: compile_native lowering 1 owner=lowering core reason=lower: visit(allocate of class Array(T).class: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=Array(T).class#new
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of args (hosted codegen_fun: return type) example=Program.class#args
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of fail (hosted codegen_fun: return type) example=Compiler::Tools::CompileNative::CompileNative.class#fail
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of module_of (hosted codegen_fun: return type) example=Compiler::Tools::CompileNative::CompileNative.class#module_of
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(String) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=String#split
table: compile_native lowering 1 owner=lowering core reason=lower: visit(allocate of class Array(String).class: the :headed byte is the program-wide census (gc_layouts.cr iyi_headed?), not ported) (hosted codegen.cr) is not ported yet example=Array(String).class#new
table: compile_native lowering 1 owner=unassigned reason=BUG: a primitive call has no receiver (hosted call.cr: codegen_primitive) example=Char#bytesize
table: compile_native lowering 1 owner=calls reason=BUG: the call to memory has no target def (hosted call.cr: visit(Call)) example=String.class#new
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of chmod (hosted codegen_fun: return type) example=File.class#chmod
```
<!-- table:end -->
