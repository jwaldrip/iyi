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

As measured on 2026-11-12 on `selfhost/s3-pipeline` after the declarations, ivars, calls, primitives, globals and core merges
(the port's names as the call lowering names them: a class method by its class, `*Point::new`, as `call.iyi` passes
`class_owner`; an instance-variable getter is not listed, since a call reads it in place, call.iyi 207):

- `hello`: hosted 698 functions; 52 match the port's clean list; 646 missing; 13 extra.
- `compile_native` (as root): hosted 11,596 functions; 59 match; 11,537 missing; 31 extra.

The hosted `compile_native` count is 11,596 here, against 10,793 on the earlier head. The cause is not checked: the hosted
build was rerun for this measurement, and its source may have changed since.

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

Program assembly (lower/program.iyi, this slice): the top-level code is named `__iyi_main`, and the C `main` is emitted only
when the root has no `fun main` of its own (fixture lower_fun_main). The name follows the prelude in the lowering core's
`codegen_program` once the s2a-core head carrying that change is merged (agent://S2a9Core); until then every build names
it `__iyi_main`.

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
table: hello defs-reached=360 defs-typed-clean=236 root-refusals=15 refusal-sites=391
table: hello refusal 147 owner=macros reason=macro control expansion (macros engine) example=src/iyi/./concurrency.iyi:1557 in top level
table: hello refusal 17 owner=bodies reason=undefined local variable or method 'previous_def' for Atomic(UInt64) example=src/iyi/./chaos_points.iyi:26 in Atomic(UInt64)#add
table: hello refusal 12 owner=calls reason=expected argument #1 to 'IyiScheduler.enqueue' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:3998 in IyiScheduler.class#deadlock_found
table: hello refusal 11 owner=bodies reason=the value of 'buffer' cannot be typed example=src/iyi/./string.iyi:38 in String.class#new
table: hello refusal 10 owner=calls reason=expected argument #1 to 'IyiAtomic.store' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/./concurrency.iyi:1475 in IyiSchedLock.class#unlock
table: hello refusal 9 owner=bodies reason=the value of 'memory' cannot be typed example=src/iyi/./string.iyi:37 in String.class#new
table: hello refusal 8 owner=bodies reason=the value of 'state' cannot be typed example=src/iyi/./chaos.iyi:228 in IyiChaos.class#draw
table: hello refusal 8 owner=declarations reason=undefined constant Tuple(T, Bool) example=src/iyi/./chaos_points.iyi:39 in IyiSchedulerState#take_lists
table: hello refusal 6 owner=bodies reason=the value of '__temp_1' cannot be typed example=no location in IyiChaos.class#outranked?
table: hello refusal 6 owner=declarations reason=undefined constant HEADER_SIZE example=src/iyi/./string.iyi:36 in String.class#new
table: hello refusal 6 owner=declarations reason=undefined constant DEADLOCK example=src/iyi/./concurrency.iyi:4011 in IyiScheduler.class#deadlock
table: hello refusal 6 owner=declarations reason=undefined constant T example=src/iyi/./array.iyi:76 in Array(Samples::Hello::Greet).class#unsafe_build
table: hello refusal 5 owner=bodies reason=the value of 'following' cannot be typed example=src/iyi/./concurrency.iyi:2318 in IyiScheduler.class#take_mail
table: hello refusal 5 owner=declarations reason=undefined constant HELD example=src/iyi/./concurrency.iyi:1561 in IyiChanLock.class#acquire
table: hello refusal 4 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:1737 in IyiScheduler.class#state_id
table: hello refusal 4 owner=declarations reason=undefined constant GOLDEN example=src/iyi/./chaos.iyi:227 in IyiChaos.class#draw
table: hello refusal 4 owner=calls reason=expected argument #1 to 'IyiFiber#state=' to be IyiFiberState, not Int32 example=src/iyi/./concurrency.iyi:2140 in IyiScheduler.class#enqueue
table: hello refusal 4 owner=calls reason=undefined method 'deadline' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4026 in IyiScheduler.class#wait_for_events
table: hello refusal 4 owner=calls reason=undefined method 'state' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3997 in IyiScheduler.class#deadlock_found
table: hello refusal 4 owner=bodies reason=the value of 'rest' cannot be typed example=src/iyi/./concurrency.iyi:3611 in IyiScheduler.class#wake_joiners
table: hello refusal 3 owner=declarations reason=undefined constant SIMULATED example=src/iyi/./chaos.iyi:312 in IyiChaos.class#point
table: hello refusal 3 owner=calls reason=undefined method 'next_run=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2154 in IyiScheduler.class#enqueue
table: hello refusal 3 owner=bodies reason=the value of 'head_deadline' cannot be typed example=src/iyi/./concurrency.iyi:4047 in IyiScheduler.class#wait_for_events
table: hello refusal 3 owner=bodies reason=the value of 'gap' cannot be typed example=src/iyi/./concurrency.iyi:4048 in IyiScheduler.class#wait_for_events
table: hello refusal 3 owner=calls reason=expected argument #1 to 'IyiScheduler.switch_to' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:2595 in IyiScheduler.class#reschedule
table: hello refusal 3 owner=bodies reason=undefined local variable or method 'previous_def' for Atomic(Int64) example=src/iyi/./chaos_points.iyi:16 in Atomic(Int64)#get
table: hello refusal 2 owner=bodies reason=the value of 'unit' cannot be typed example=src/iyi/./chaos.iyi:265 in IyiChaos.class#unit_of
table: hello refusal 2 owner=bodies reason=the value of 'other' cannot be typed example=src/iyi/./chaos.iyi:374 in IyiChaos.class#outranked?
table: hello refusal 2 owner=calls reason=undefined method 'next_run' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./chaos.iyi:375 in IyiChaos.class#outranked?
table: hello refusal 2 owner=bodies reason=the value of 'task' cannot be typed example=src/iyi/./concurrency.iyi:3987 in IyiScheduler.class#deadlock_found
table: hello refusal 2 owner=bodies reason=the value of 'group' cannot be typed example=src/iyi/./concurrency.iyi:3989 in IyiScheduler.class#deadlock_found
table: hello refusal 2 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3990 in IyiScheduler.class#deadlock_found
table: hello refusal 2 owner=calls reason=undefined method 'claim_any' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3998 in IyiScheduler.class#deadlock_found
table: hello refusal 2 owner=bodies reason=the value of 'waits_here' cannot be typed example=src/iyi/./concurrency.iyi:2327 in IyiScheduler.class#take_mail
table: hello refusal 2 owner=declarations reason=undefined constant SPINNER example=src/iyi/./concurrency.iyi:1576 in IyiChanLock.class#contend
table: hello refusal 2 owner=calls reason=expected argument #2 to 'IyiAtomic.rmw' to be Pointer(<unresolved T>), not Pointer(UInt64) example=src/iyi/prelude.iyi:104 in IyiRuntimeLock.class#lock
table: hello refusal 2 owner=unassigned reason=wrong number of arguments for 'Proc(Nil)#call' (given 0, expected 1) example=src/iyi/./concurrency.iyi:2874 in IyiScheduler.class#run_spawned_fiber
table: hello refusal 2 owner=calls reason=undefined method 'next_joiner' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3609 in IyiScheduler.class#wake_joiners
table: hello refusal 2 owner=calls reason=undefined method 'next_joiner=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3610 in IyiScheduler.class#wake_joiners
table: hello refusal 2 owner=calls reason=expected argument #1 to 'IyiAtomic.load' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/prelude.iyi:10779 in top level
table: hello refusal 2 owner=unassigned reason=unsupported node: TraitDef example=samples/iyi/hello.iyi:17 in top level
table: hello refusal 2 owner=unassigned reason=wrong number of arguments for 'String.interpolation' (given 3, expected 1) example=no location in Samples::Hello::User#greet
table: hello refusal 2 owner=bodies reason=the value of 'array' cannot be typed example=src/iyi/./array.iyi:77 in Array(Samples::Hello::Greet).class#unsafe_build
table: hello refusal 1 owner=unassigned reason=type mismatch for return type: expected IyiSchedulerState, got (IyiSchedulerState | Nil) example=src/iyi/./concurrency.iyi:1793 in IyiScheduler.class#state
table: hello refusal 1 owner=calls reason=undefined method 'chaos_unit' for IyiFiber example=src/iyi/./chaos.iyi:264 in IyiChaos.class#unit_of
table: hello refusal 1 owner=declarations reason=undefined constant HIGH example=src/iyi/./chaos.iyi:267 in IyiChaos.class#unit_of
table: hello refusal 1 owner=calls reason=undefined method 'chaos_unit=' for IyiFiber example=src/iyi/./chaos.iyi:269 in IyiChaos.class#unit_of
table: hello refusal 1 owner=declarations reason=undefined constant LOW example=src/iyi/./chaos.iyi:348 in IyiChaos.class#step
table: hello refusal 1 owner=declarations reason=undefined constant SPIN_STEPS example=src/iyi/./chaos.iyi:350 in IyiChaos.class#step
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiChaos.unit_of' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./chaos.iyi:373 in IyiChaos.class#outranked?
table: hello refusal 1 owner=declarations reason=undefined constant FNV_PRIME example=src/iyi/./chaos.iyi:254 in IyiChaos.class#fold
table: hello refusal 1 owner=calls reason=undefined method 'chaos_held=' for IyiFiber example=src/iyi/./chaos.iyi:357 in IyiChaos.class#step
table: hello refusal 1 owner=declarations reason=undefined constant POLL_EVERY example=src/iyi/./concurrency.iyi:2591 in IyiScheduler.class#reschedule
table: hello refusal 1 owner=declarations reason=undefined constant POLL_IO_NS example=src/iyi/./concurrency.iyi:2761 in IyiScheduler.class#poll_now
table: hello refusal 1 owner=calls reason=undefined method 'awaited' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3986 in IyiScheduler.class#deadlock_found
table: hello refusal 1 owner=calls reason=undefined method 'joining' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3988 in IyiScheduler.class#deadlock_found
table: hello refusal 1 owner=calls reason=undefined method 'deadlocked=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3994 in IyiScheduler.class#deadlock_found
table: hello refusal 1 owner=declarations reason=undefined constant EVENTS example=src/iyi/./concurrency.iyi:4982 in IyiScheduler.class#events_buffer
table: hello refusal 1 owner=calls reason=undefined method 'size' for Nil (compile-time type is (Array(IyiFiber | Nil) | Nil)) example=src/iyi/./concurrency.iyi:3423 in IyiScheduler.class#io_slot
table: hello refusal 1 owner=unassigned reason=wrong number of arguments for 'String.interpolation' (given 5, expected 1) example=no location in Array(IyiFiber | Nil)#[]
table: hello refusal 1 owner=calls reason=undefined method '[]' for Nil (compile-time type is (Array(IyiFiber | Nil) | Nil)) example=src/iyi/./concurrency.iyi:3423 in IyiScheduler.class#io_slot
table: hello refusal 1 owner=calls reason=expected argument #2 to 'IyiScheduler.io_remove' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:4907 in IyiScheduler.class#io_take
table: hello refusal 1 owner=calls reason=expected argument #2 to 'IyiScheduler.heap_remove' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:4661 in IyiScheduler.class#wake_expired_sleepers
table: hello refusal 1 owner=calls reason=undefined method 'io_timed' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4662 in IyiScheduler.class#wake_expired_sleepers
table: hello refusal 1 owner=calls reason=undefined method 'io_timed=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4664 in IyiScheduler.class#wake_expired_sleepers
table: hello refusal 1 owner=calls reason=undefined method 'timed_out=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4665 in IyiScheduler.class#wake_expired_sleepers
table: hello refusal 1 owner=calls reason=undefined method 'give' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:2721 in IyiScheduler.class#release_unit
table: hello refusal 1 owner=calls reason=undefined method 'waiting?' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:2722 in IyiScheduler.class#release_unit
table: hello refusal 1 owner=calls reason=expected argument #2 to 'IyiScheduler.drain_unit' to be IyiUnit, not (IyiUnit | Nil) example=src/iyi/./concurrency.iyi:2724 in IyiScheduler.class#release_unit
table: hello refusal 1 owner=calls reason=undefined method 'next_cancel' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2323 in IyiScheduler.class#take_mail
table: hello refusal 1 owner=calls reason=undefined method 'next_cancel=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2324 in IyiScheduler.class#take_mail
table: hello refusal 1 owner=calls reason=undefined method 'cancel_posted=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2325 in IyiScheduler.class#take_mail
table: hello refusal 1 owner=calls reason=undefined method 'unit' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2326 in IyiScheduler.class#take_mail
table: hello refusal 1 owner=calls reason=undefined method 'listed_on' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2326 in IyiScheduler.class#take_mail
table: hello refusal 1 owner=calls reason=undefined method 'waiting_out' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2327 in IyiScheduler.class#take_mail
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.cancel_wait' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:2328 in IyiScheduler.class#take_mail
table: hello refusal 1 owner=calls reason=undefined method 'each' for Nil (compile-time type is (Array(Int32) | Nil)) example=src/iyi/./concurrency.iyi:2335 in IyiScheduler.class#take_mail
table: hello refusal 1 owner=calls reason=undefined method 'quiet' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2500 in IyiScheduler.class#all_quiet?
table: hello refusal 1 owner=calls reason=undefined method 'idle' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: hello refusal 1 owner=bodies reason=the value of 'quiet' cannot be typed example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: hello refusal 1 owner=bodies reason=the value of '__temp_2' cannot be typed example=no location in IyiScheduler.class#all_quiet?
table: hello refusal 1 owner=calls reason=undefined method 'mail?' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: hello refusal 1 owner=calls reason=undefined method 'next_state' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2506 in IyiScheduler.class#all_quiet?
table: hello refusal 1 owner=declarations reason=undefined constant THREADS example=src/iyi/./chaos.iyi:314 in IyiChaos.class#point
table: hello refusal 1 owner=declarations reason=undefined constant UNMARKED example=src/iyi/./concurrency.iyi:1572 in IyiChanLock.class#contend
table: hello refusal 1 owner=bodies reason=the value of 'taken' cannot be typed example=src/iyi/./concurrency.iyi:1573 in IyiChanLock.class#contend
table: hello refusal 1 owner=unassigned reason=type mismatch for return type: expected IyiFiber, got (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:1829 in IyiScheduler.class#current
table: hello refusal 1 owner=unassigned reason=instance variable '@state' of IyiFiber must be IyiFiberState, not (IyiFiberState | Int32) example=src/iyi/./concurrency.iyi:635 in IyiFiber#initialize
table: hello refusal 1 owner=calls reason=undefined method 'prev_fiber=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1863 in IyiScheduler.class#register
table: hello refusal 1 owner=calls reason=undefined method 'on_cpu=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1917 in IyiScheduler.class#landed
table: hello refusal 1 owner=declarations reason=undefined constant STACK_BYTES example=src/iyi/./concurrency.iyi:926 in IyiFiber#release_stack
table: hello refusal 1 owner=calls reason=undefined method 'release_stack' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1932 in IyiScheduler.class#reap_dying
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.unregister' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:1933 in IyiScheduler.class#reap_dying
table: hello refusal 1 owner=calls reason=undefined method 'awaited=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3620 in IyiScheduler.class#wake_joiners
table: hello refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.ready' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:3621 in IyiScheduler.class#wake_joiners
table: hello refusal 1 owner=calls reason=expected argument #1 to 'Pointer#+' to be Int64, not Int32 example=src/iyi/./io.iyi:300 in IyiIO#write
table: hello refusal 1 owner=calls reason=expected argument #1 to 'Pointer#copy_from' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/./io.iyi:313 in IyiIO#write
table: hello refusal 1 owner=unassigned reason=wrong number of arguments for 'String.interpolation' (given 2, expected 1) example=no location in Samples::Hello::Robot#greet
table: hello refusal 1 owner=calls reason=expected argument #2 to 'Pointer(<unresolved T>)#[]=' to be <unresolved T>, not Samples::Hello::User example=no location in top level
table: hello refusal 1 owner=calls reason=expected argument #2 to 'Pointer(<unresolved T>)#[]=' to be <unresolved T>, not Samples::Hello::Robot example=no location in top level
table: hello refusal 1 owner=bodies reason=undefined local variable or method 'member' for Array(<unresolved T>) example=samples/iyi/hello.iyi:117 in top level
table: hello refusal 1 owner=calls reason=expected argument #1 to 'Samples::Hello#announce' to be <unresolved T>, not Samples::Hello::Robot example=samples/iyi/hello.iyi:119 in top level
table: hello defs-lowered-clean=121 lowering-refusal-sites=169
table: hello lowering 12 owner=bodies reason=BUG: the analysed program has no type for the body of raise (hosted codegen_fun: return type) example=UInt64#raise
table: hello lowering 9 owner=bodies reason=BUG: the analysed program has no type for the body of unlock (hosted codegen_fun: return type) example=IyiSchedLock.class#unlock
table: hello lowering 7 owner=bodies reason=BUG: the analysed program has no type for the body of get (hosted codegen_fun: return type) example=Atomic(UInt64)#get
table: hello lowering 7 owner=lowering core reason=lower: visit(Cast) (hosted codegen.cr) is not ported yet example=UInt64#__iyi_say
table: hello lowering 6 owner=bodies reason=BUG: the analysed program has no type for the body of initialize (hosted codegen_fun: return type) example=Atomic(UInt64)#initialize
table: hello lowering 5 owner=unassigned reason=Cast from Compiler::Semantic::TopLevel::MetaclassType to Compiler::Semantic::TopLevel::ClassType+ failed, at src/compiler/lower/primitives.iyi:690:11:690 example=IyiSchedulerState.class#new
table: hello lowering 5 owner=unassigned reason=lower: is_a? of (IyiFiber | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiChaos.class#outranked?
table: hello lowering 5 owner=bodies reason=BUG: the analysed program has no type for the body of add (hosted codegen_fun: return type) example=Atomic(UInt64)#add
table: hello lowering 5 owner=lowering core reason=lower: visit(MacroIf) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#poll_now
table: hello lowering 5 owner=bodies reason=BUG: the analysed program has no type for the body of __iyi_monotonic_ns (hosted codegen_fun: return type) example=IyiScheduler.class#__iyi_monotonic_ns
table: hello lowering 4 owner=bodies reason=BUG: the analysed program has no type for the body of compare_and_set (hosted codegen_fun: return type) example=Atomic(UInt64)#compare_and_set
table: hello lowering 4 owner=lowering core reason=lower: visit(a restriction that converts argument 0 of set (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#free_lists
table: hello lowering 4 owner=bodies reason=BUG: the analysed program has no type for the body of set (hosted codegen_fun: return type) example=Atomic(UInt64)#set
table: hello lowering 4 owner=bodies reason=BUG: the analysed program has no type for the body of wake_io (hosted codegen_fun: return type) example=IyiScheduler.class#wake_io
table: hello lowering 3 owner=unassigned reason=a function or global named IyiScheduler::shared already exists example=IyiScheduler.class#shared?
table: hello lowering 3 owner=bodies reason=lower: visit(pointerof of a ClassVar (hosted codegen.cr: visit(PointerOf), only a local variable is ported)) (hosted codegen.cr) is not ported yet example=IyiSchedLock.class#word
table: hello lowering 3 owner=lowering core reason=lower: visit(pointer_get of Atomic(UInt64) (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=IyiChanLock.class#acquire
table: hello lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of state_id (hosted codegen_fun: return type) example=IyiScheduler.class#state_id
table: hello lowering 3 owner=lowering core reason=lower: visit(MagicConstant) (hosted codegen.cr) is not ported yet example=UInt64#%
table: hello lowering 3 owner=lowering core reason=lower: visit(Assign to a parameter (hosted fun.cr, create_local_copy_of_arg)) (hosted codegen.cr) is not ported yet example=String#includes?
table: hello lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of wait_for_events (hosted codegen_fun: return type) example=IyiScheduler.class#wait_for_events
table: hello lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of event_ready (hosted codegen_fun: return type) example=IyiScheduler.class#event_ready
table: hello lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of low_level_write (hosted codegen_fun: return type) example=IyiIO#low_level_write
table: hello lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of greet (hosted codegen_fun: return type) example=Samples::Hello::User#greet
table: hello lowering 2 owner=bodies reason=BUG: (IyiSchedulerState | Nil) has no type id (not reachable from Object) example=IyiScheduler.class#state
table: hello lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of draw (hosted codegen_fun: return type) example=IyiChaos.class#draw
table: hello lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of deadlock (hosted codegen_fun: return type) example=IyiScheduler.class#deadlock
table: hello lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of lock (hosted codegen_fun: return type) example=IyiRuntimeLock.class#lock
table: hello lowering 2 owner=lowering core reason=lower: read of constant STDOUT before its initialisation: the flag path (hosted read_const_pointer, create_read_const_function) is not ported yet example=print
table: hello lowering 2 owner=lowering core reason=lower: visit(a call to a def with a &block parameter (hosted call.cr: codegen_call_with_block_as_fun_literal, closures)) (hosted codegen.cr) is not ported yet example=IyiTestCases.class#verdict
table: hello lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(IyiFiber | Nil) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiScheduler.class#run_spawned_fiber
table: hello lowering 1 owner=lowering core reason=lower: visit(a class method call on a receiver that is not a constant path (hosted call.cr: prepare_call_args, Path)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#current
table: hello lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiSchedulerState: the :headed byte is the program-wide census (lower/headed.iyi, NEEDS.md rows 26-27), not decided) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#first_state_here
table: hello lowering 1 owner=lowering core reason=lower: visit(a class method call on Atomic(UInt64).class (hosted call.cr: prepare_call_args, a generic or builtin metaclass)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#initialize
table: hello lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Atomic(UInt64) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Atomic(UInt64).class#new
table: hello lowering 1 owner=unassigned reason=lower: a bare return from a function that returns a value (hosted codegen_return, the nil upcast) example=IyiSchedLock.class#lock
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to == (hosted call.cr: visit(Call)) example=IyiChaos.class#at_atomic
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to state (hosted call.cr: visit(Call)) example=IyiChaos.class#step
table: hello lowering 1 owner=unassigned reason=a function or global named IyiScheduler::state already exists example=IyiSchedLock.class#held_here?
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to chaos_unit (hosted call.cr: visit(Call)) example=IyiChaos.class#unit_of
table: hello lowering 1 owner=unassigned reason=not a number: "13787848793156543929" example=IyiChaos.class#mix
table: hello lowering 1 owner=bodies reason=lower: visit(pointerof of a InstanceVar (hosted codegen.cr: visit(PointerOf), only a local variable is ported)) (hosted codegen.cr) is not ported yet example=String#to_unsafe
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to memory (hosted call.cr: visit(Call)) example=String.class#new
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of fold (hosted codegen_fun: return type) example=IyiChaos.class#fold
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to state= (hosted call.cr: visit(Call)) example=IyiScheduler.class#enqueue
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for a branch (hosted codegen.cr: visit(If)) example=IyiScheduler.class#reschedule
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of take_lists (hosted codegen_fun: return type) example=IyiSchedulerState#take_lists
table: hello lowering 1 owner=lowering core reason=lower: visit(a restriction that converts argument 0 of add (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiFiber#claim_any
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of claim (hosted codegen_fun: return type) example=IyiFiber#claim
table: hello lowering 1 owner=lowering core reason=lower: visit(binary == on Int64 and Int32 (mixed operands, hosted codegen_binary_extend_int)) (hosted codegen.cr) is not ported yet example=Int64#//
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to malloc (hosted call.cr: visit(Call)) example=IyiScheduler.class#events_buffer
table: hello lowering 1 owner=unassigned reason=lower: is_a? of (Array(IyiFiber | Nil) | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiScheduler.class#io_take
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of io_slot (hosted codegen_fun: return type) example=IyiScheduler.class#io_slot
table: hello lowering 1 owner=unassigned reason=lower: instance variable @size of Array(IyiFiber | Nil): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(IyiFiber | Nil)#size
table: hello lowering 1 owner=lowering core reason=lower: visit(pointer_get of (IyiFiber | Nil) (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=Pointer((IyiFiber | Nil))#[]
table: hello lowering 1 owner=unassigned reason=lower: is_a? of (IyiUnit | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiScheduler.class#release_unit
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to at_atomic (hosted call.cr: visit(Call)) example=IyiUnit#waiting?
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to shared? (hosted call.cr: visit(Call)) example=IyiScheduler.class#take_mail
table: hello lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(Int32) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiSchedulerState#closed_fds
table: hello lowering 1 owner=unassigned reason=lower: instance variable @size of Array(Int32): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(Int32)#each
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of ensure_doorbell (hosted codegen_fun: return type) example=IyiScheduler.class#ensure_doorbell
table: hello lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Atomic(Int64) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiWorkers.class#word
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of thread_point (hosted codegen_fun: return type) example=IyiChaos.class#thread_point
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of give_up (hosted codegen_fun: return type) example=IyiWorkers.class#give_up
table: hello lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiFiber: the :headed byte is the program-wide census (lower/headed.iyi, NEEDS.md rows 26-27), not decided) (hosted codegen.cr) is not ported yet example=IyiFiber.class#main
table: hello lowering 1 owner=lowering core reason=lower: visit(assign Int32 to IyiFiberState (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=IyiFiber#initialize
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of register (hosted codegen_fun: return type) example=IyiScheduler.class#register
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of reap_dying (hosted codegen_fun: return type) example=IyiScheduler.class#reap_dying
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of release_stack (hosted codegen_fun: return type) example=IyiFiber#release_stack
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of run (hosted codegen_fun: return type) example=IyiOnce.class#run
table: hello lowering 1 owner=lowering core reason=lower: visit(StringInterpolation) (hosted codegen.cr) is not ported yet example=Samples::Hello::User#shout
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of unsafe_build (hosted codegen_fun: return type) example=Array(Samples::Hello::Greet).class#unsafe_build
table: hello lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(<unresolved T>) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Array(<unresolved T>)#to_unsafe
table: hello lowering 1 owner=unassigned reason=lower: instance variable @size of Array(<unresolved T>): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(<unresolved T>)#each
table: hello lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of [] (hosted codegen_fun: return type) example=Pointer(<unresolved T>)#[]
table: parse defs-reached=396 defs-typed-clean=255 root-refusals=9 refusal-sites=452
table: parse refusal 178 owner=macros reason=macro control expansion (macros engine) example=src/iyi/./concurrency.iyi:1557 in top level
table: parse refusal 17 owner=bodies reason=undefined local variable or method 'previous_def' for Atomic(UInt64) example=src/iyi/./chaos_points.iyi:26 in Atomic(UInt64)#add
table: parse refusal 16 owner=bodies reason=the value of 'buffer' cannot be typed example=src/iyi/./string.iyi:38 in String.class#new
table: parse refusal 15 owner=bodies reason=the value of 'memory' cannot be typed example=src/iyi/./string.iyi:37 in String.class#new
table: parse refusal 12 owner=calls reason=expected argument #1 to 'IyiScheduler.enqueue' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:3998 in IyiScheduler.class#deadlock_found
table: parse refusal 10 owner=declarations reason=undefined constant HEADER_SIZE example=src/iyi/./string.iyi:36 in String.class#new
table: parse refusal 10 owner=calls reason=expected argument #1 to 'IyiAtomic.store' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/./concurrency.iyi:1475 in IyiSchedLock.class#unlock
table: parse refusal 8 owner=bodies reason=the value of 'state' cannot be typed example=src/iyi/./chaos.iyi:228 in IyiChaos.class#draw
table: parse refusal 8 owner=declarations reason=undefined constant Tuple(T, Bool) example=src/iyi/./chaos_points.iyi:39 in IyiSchedulerState#take_lists
table: parse refusal 6 owner=bodies reason=the value of '__temp_1' cannot be typed example=no location in IyiChaos.class#outranked?
table: parse refusal 6 owner=declarations reason=undefined constant DEADLOCK example=src/iyi/./concurrency.iyi:4011 in IyiScheduler.class#deadlock
table: parse refusal 5 owner=bodies reason=the value of 'following' cannot be typed example=src/iyi/./concurrency.iyi:2318 in IyiScheduler.class#take_mail
table: parse refusal 5 owner=bodies reason=the value of '__temp_2' cannot be typed example=no location in IyiScheduler.class#all_quiet?
table: parse refusal 5 owner=declarations reason=undefined constant HELD example=src/iyi/./concurrency.iyi:1561 in IyiChanLock.class#acquire
table: parse refusal 4 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:1737 in IyiScheduler.class#state_id
table: parse refusal 4 owner=declarations reason=undefined constant GOLDEN example=src/iyi/./chaos.iyi:227 in IyiChaos.class#draw
table: parse refusal 4 owner=calls reason=expected argument #1 to 'IyiFiber#state=' to be IyiFiberState, not Int32 example=src/iyi/./concurrency.iyi:2140 in IyiScheduler.class#enqueue
table: parse refusal 4 owner=calls reason=undefined method 'deadline' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4026 in IyiScheduler.class#wait_for_events
table: parse refusal 4 owner=calls reason=undefined method 'state' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3997 in IyiScheduler.class#deadlock_found
table: parse refusal 4 owner=bodies reason=the value of 'rest' cannot be typed example=src/iyi/./concurrency.iyi:3611 in IyiScheduler.class#wake_joiners
table: parse refusal 3 owner=declarations reason=undefined constant SIMULATED example=src/iyi/./chaos.iyi:312 in IyiChaos.class#point
table: parse refusal 3 owner=calls reason=undefined method 'next_run=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2154 in IyiScheduler.class#enqueue
table: parse refusal 3 owner=bodies reason=the value of 'head_deadline' cannot be typed example=src/iyi/./concurrency.iyi:4047 in IyiScheduler.class#wait_for_events
table: parse refusal 3 owner=bodies reason=the value of 'gap' cannot be typed example=src/iyi/./concurrency.iyi:4048 in IyiScheduler.class#wait_for_events
table: parse refusal 3 owner=unassigned reason=wrong number of arguments for 'String.interpolation' (given 5, expected 1) example=no location in Array(IyiFiber | Nil)#[]
table: parse refusal 3 owner=calls reason=expected argument #1 to 'IyiScheduler.switch_to' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:2595 in IyiScheduler.class#reschedule
table: parse refusal 3 owner=bodies reason=undefined local variable or method 'previous_def' for Atomic(Int64) example=src/iyi/./chaos_points.iyi:16 in Atomic(Int64)#get
table: parse refusal 3 owner=calls reason=expected argument #1 to 'Pointer(UInt8)#+' to be Int64, not Int32 example=src/iyi/./string.iyi:537 in String#==
table: parse refusal 2 owner=bodies reason=the value of 'unit' cannot be typed example=src/iyi/./chaos.iyi:265 in IyiChaos.class#unit_of
table: parse refusal 2 owner=bodies reason=the value of 'other' cannot be typed example=src/iyi/./chaos.iyi:374 in IyiChaos.class#outranked?
table: parse refusal 2 owner=calls reason=undefined method 'next_run' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./chaos.iyi:375 in IyiChaos.class#outranked?
table: parse refusal 2 owner=bodies reason=the value of 'task' cannot be typed example=src/iyi/./concurrency.iyi:3987 in IyiScheduler.class#deadlock_found
table: parse refusal 2 owner=bodies reason=the value of 'group' cannot be typed example=src/iyi/./concurrency.iyi:3989 in IyiScheduler.class#deadlock_found
table: parse refusal 2 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3990 in IyiScheduler.class#deadlock_found
table: parse refusal 2 owner=calls reason=undefined method 'claim_any' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3998 in IyiScheduler.class#deadlock_found
table: parse refusal 2 owner=bodies reason=the value of 'waits_here' cannot be typed example=src/iyi/./concurrency.iyi:2327 in IyiScheduler.class#take_mail
table: parse refusal 2 owner=declarations reason=undefined constant SPINNER example=src/iyi/./concurrency.iyi:1576 in IyiChanLock.class#contend
table: parse refusal 2 owner=calls reason=expected argument #2 to 'IyiAtomic.rmw' to be Pointer(<unresolved T>), not Pointer(UInt64) example=src/iyi/prelude.iyi:104 in IyiRuntimeLock.class#lock
table: parse refusal 2 owner=unassigned reason=wrong number of arguments for 'Proc(Nil)#call' (given 0, expected 1) example=src/iyi/./concurrency.iyi:2874 in IyiScheduler.class#run_spawned_fiber
table: parse refusal 2 owner=calls reason=undefined method 'next_joiner' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3609 in IyiScheduler.class#wake_joiners
table: parse refusal 2 owner=calls reason=undefined method 'next_joiner=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3610 in IyiScheduler.class#wake_joiners
table: parse refusal 2 owner=calls reason=expected argument #1 to 'Pointer#+' to be Int64, not Int32 example=src/iyi/./io.iyi:300 in IyiIO#write
table: parse refusal 2 owner=calls reason=expected argument #1 to 'IyiAtomic.load' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/prelude.iyi:10779 in top level
table: parse refusal 2 owner=unassigned reason=wrong number of arguments for 'String.interpolation' (given 2, expected 1) example=no location in String#[]
table: parse refusal 2 owner=lowering core reason=typeof is not ported yet: it needs typed bodies example=no location in Compiler::Tools::Parse::ParseTool.class#parse_source
table: parse refusal 2 owner=bodies reason=the value of '__temp_3' cannot be typed example=no location in Compiler::Tools::Parse::ParseTool.class#parse_source
table: parse refusal 2 owner=bodies reason=undefined local variable or method 'var_scopes' for Compiler::Syntax::Parser::Parser.class example=no location in Compiler::Syntax::Parser::Parser.class#new
table: parse refusal 2 owner=bodies reason=the value of 'parser' cannot be typed example=src/compiler/tools/parse.iyi:37 in Compiler::Tools::Parse::ParseTool.class#parse_source
table: parse refusal 2 owner=bodies reason=the value of 'below' cannot be typed example=src/iyi/./concurrency.iyi:6659 in File.class#__iyi_defer_pop_run
table: parse refusal 1 owner=unassigned reason=type mismatch for return type: expected IyiSchedulerState, got (IyiSchedulerState | Nil) example=src/iyi/./concurrency.iyi:1793 in IyiScheduler.class#state
table: parse refusal 1 owner=calls reason=undefined method 'chaos_unit' for IyiFiber example=src/iyi/./chaos.iyi:264 in IyiChaos.class#unit_of
table: parse refusal 1 owner=declarations reason=undefined constant HIGH example=src/iyi/./chaos.iyi:267 in IyiChaos.class#unit_of
table: parse refusal 1 owner=calls reason=undefined method 'chaos_unit=' for IyiFiber example=src/iyi/./chaos.iyi:269 in IyiChaos.class#unit_of
table: parse refusal 1 owner=declarations reason=undefined constant LOW example=src/iyi/./chaos.iyi:348 in IyiChaos.class#step
table: parse refusal 1 owner=declarations reason=undefined constant SPIN_STEPS example=src/iyi/./chaos.iyi:350 in IyiChaos.class#step
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiChaos.unit_of' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./chaos.iyi:373 in IyiChaos.class#outranked?
table: parse refusal 1 owner=declarations reason=undefined constant FNV_PRIME example=src/iyi/./chaos.iyi:254 in IyiChaos.class#fold
table: parse refusal 1 owner=calls reason=undefined method 'chaos_held=' for IyiFiber example=src/iyi/./chaos.iyi:357 in IyiChaos.class#step
table: parse refusal 1 owner=declarations reason=undefined constant POLL_EVERY example=src/iyi/./concurrency.iyi:2591 in IyiScheduler.class#reschedule
table: parse refusal 1 owner=declarations reason=undefined constant POLL_IO_NS example=src/iyi/./concurrency.iyi:2761 in IyiScheduler.class#poll_now
table: parse refusal 1 owner=calls reason=undefined method 'awaited' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3986 in IyiScheduler.class#deadlock_found
table: parse refusal 1 owner=calls reason=undefined method 'joining' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3988 in IyiScheduler.class#deadlock_found
table: parse refusal 1 owner=calls reason=undefined method 'deadlocked=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3994 in IyiScheduler.class#deadlock_found
table: parse refusal 1 owner=declarations reason=undefined constant EVENTS example=src/iyi/./concurrency.iyi:4982 in IyiScheduler.class#events_buffer
table: parse refusal 1 owner=calls reason=undefined method 'size' for Nil (compile-time type is (Array(IyiFiber | Nil) | Nil)) example=src/iyi/./concurrency.iyi:3423 in IyiScheduler.class#io_slot
table: parse refusal 1 owner=calls reason=undefined method '[]' for Nil (compile-time type is (Array(IyiFiber | Nil) | Nil)) example=src/iyi/./concurrency.iyi:3423 in IyiScheduler.class#io_slot
table: parse refusal 1 owner=calls reason=expected argument #2 to 'IyiScheduler.io_remove' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:4907 in IyiScheduler.class#io_take
table: parse refusal 1 owner=calls reason=expected argument #2 to 'IyiScheduler.heap_remove' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:4661 in IyiScheduler.class#wake_expired_sleepers
table: parse refusal 1 owner=calls reason=undefined method 'io_timed' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4662 in IyiScheduler.class#wake_expired_sleepers
table: parse refusal 1 owner=calls reason=undefined method 'io_timed=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4664 in IyiScheduler.class#wake_expired_sleepers
table: parse refusal 1 owner=calls reason=undefined method 'timed_out=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4665 in IyiScheduler.class#wake_expired_sleepers
table: parse refusal 1 owner=calls reason=undefined method 'give' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:2721 in IyiScheduler.class#release_unit
table: parse refusal 1 owner=calls reason=undefined method 'waiting?' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:2722 in IyiScheduler.class#release_unit
table: parse refusal 1 owner=calls reason=expected argument #2 to 'IyiScheduler.drain_unit' to be IyiUnit, not (IyiUnit | Nil) example=src/iyi/./concurrency.iyi:2724 in IyiScheduler.class#release_unit
table: parse refusal 1 owner=calls reason=undefined method 'next_cancel' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2323 in IyiScheduler.class#take_mail
table: parse refusal 1 owner=calls reason=undefined method 'next_cancel=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2324 in IyiScheduler.class#take_mail
table: parse refusal 1 owner=calls reason=undefined method 'cancel_posted=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2325 in IyiScheduler.class#take_mail
table: parse refusal 1 owner=calls reason=undefined method 'unit' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2326 in IyiScheduler.class#take_mail
table: parse refusal 1 owner=calls reason=undefined method 'listed_on' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2326 in IyiScheduler.class#take_mail
table: parse refusal 1 owner=calls reason=undefined method 'waiting_out' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2327 in IyiScheduler.class#take_mail
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.cancel_wait' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:2328 in IyiScheduler.class#take_mail
table: parse refusal 1 owner=calls reason=undefined method 'each' for Nil (compile-time type is (Array(Int32) | Nil)) example=src/iyi/./concurrency.iyi:2335 in IyiScheduler.class#take_mail
table: parse refusal 1 owner=calls reason=undefined method 'quiet' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2500 in IyiScheduler.class#all_quiet?
table: parse refusal 1 owner=calls reason=undefined method 'idle' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: parse refusal 1 owner=bodies reason=the value of 'quiet' cannot be typed example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: parse refusal 1 owner=calls reason=undefined method 'mail?' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: parse refusal 1 owner=calls reason=undefined method 'next_state' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2506 in IyiScheduler.class#all_quiet?
table: parse refusal 1 owner=declarations reason=undefined constant THREADS example=src/iyi/./chaos.iyi:314 in IyiChaos.class#point
table: parse refusal 1 owner=declarations reason=undefined constant UNMARKED example=src/iyi/./concurrency.iyi:1572 in IyiChanLock.class#contend
table: parse refusal 1 owner=bodies reason=the value of 'taken' cannot be typed example=src/iyi/./concurrency.iyi:1573 in IyiChanLock.class#contend
table: parse refusal 1 owner=unassigned reason=type mismatch for return type: expected IyiFiber, got (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:1829 in IyiScheduler.class#current
table: parse refusal 1 owner=unassigned reason=instance variable '@state' of IyiFiber must be IyiFiberState, not (IyiFiberState | Int32) example=src/iyi/./concurrency.iyi:635 in IyiFiber#initialize
table: parse refusal 1 owner=calls reason=undefined method 'prev_fiber=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1863 in IyiScheduler.class#register
table: parse refusal 1 owner=calls reason=undefined method 'on_cpu=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1917 in IyiScheduler.class#landed
table: parse refusal 1 owner=declarations reason=undefined constant STACK_BYTES example=src/iyi/./concurrency.iyi:926 in IyiFiber#release_stack
table: parse refusal 1 owner=calls reason=undefined method 'release_stack' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1932 in IyiScheduler.class#reap_dying
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.unregister' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:1933 in IyiScheduler.class#reap_dying
table: parse refusal 1 owner=calls reason=undefined method 'awaited=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3620 in IyiScheduler.class#wake_joiners
table: parse refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.ready' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:3621 in IyiScheduler.class#wake_joiners
table: parse refusal 1 owner=calls reason=expected argument #1 to 'Pointer#copy_from' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/./io.iyi:313 in IyiIO#write
table: parse refusal 1 owner=bodies reason=undefined local variable or method 'target' for IyiIO example=src/iyi/./io.iyi:194 in IyiIO#read_all
table: parse refusal 1 owner=declarations reason=undefined constant T example=no location in Set(String)#initialize
table: parse refusal 1 owner=calls reason=expected argument #1 to 'Pointer(UInt8)#copy_from' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/./file.iyi:141 in File.class#c_path
table: parse refusal 1 owner=unassigned reason=unsupported node: ProcLiteral example=src/iyi/./file.iyi:68 in File.class#read
table: parse refusal 1 owner=unassigned reason=unsupported node: ExceptionHandler example=src/iyi/./file.iyi:68 in File.class#read
table: parse refusal 1 owner=unassigned reason=wrong number of arguments for 'String.interpolation' (given 3, expected 1) example=no location in File.class#read
table: parse refusal 1 owner=calls reason=undefined method 'next_node' for Nil (compile-time type is (IyiDeferNode | Nil)) example=src/iyi/./concurrency.iyi:6658 in File.class#__iyi_defer_pop_run
table: parse refusal 1 owner=calls reason=undefined method 'next_node=' for Nil (compile-time type is (IyiDeferNode | Nil)) example=src/iyi/./concurrency.iyi:6660 in File.class#__iyi_defer_pop_run
table: parse refusal 1 owner=unassigned reason=wrong number of arguments for 'Proc#call' (given 0, expected 1) example=src/iyi/prelude.iyi:10849 in IyiDeferNode#run
table: parse refusal 1 owner=calls reason=undefined method 'run' for Nil (compile-time type is (IyiDeferNode | Nil)) example=src/iyi/./concurrency.iyi:6661 in File.class#__iyi_defer_pop_run
table: parse defs-lowered-clean=132 lowering-refusal-sites=191
table: parse lowering 16 owner=bodies reason=BUG: the analysed program has no type for the body of raise (hosted codegen_fun: return type) example=UInt64#raise
table: parse lowering 11 owner=lowering core reason=lower: visit(Cast) (hosted codegen.cr) is not ported yet example=UInt64#__iyi_say
table: parse lowering 9 owner=bodies reason=BUG: the analysed program has no type for the body of unlock (hosted codegen_fun: return type) example=IyiSchedLock.class#unlock
table: parse lowering 8 owner=bodies reason=BUG: the analysed program has no type for the body of initialize (hosted codegen_fun: return type) example=Atomic(UInt64)#initialize
table: parse lowering 7 owner=bodies reason=BUG: the analysed program has no type for the body of get (hosted codegen_fun: return type) example=Atomic(UInt64)#get
table: parse lowering 5 owner=unassigned reason=lower: is_a? of (IyiFiber | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiChaos.class#outranked?
table: parse lowering 5 owner=bodies reason=BUG: the analysed program has no type for the body of add (hosted codegen_fun: return type) example=Atomic(UInt64)#add
table: parse lowering 5 owner=lowering core reason=lower: visit(MacroIf) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#poll_now
table: parse lowering 5 owner=bodies reason=BUG: the analysed program has no type for the body of __iyi_monotonic_ns (hosted codegen_fun: return type) example=IyiScheduler.class#__iyi_monotonic_ns
table: parse lowering 4 owner=lowering core reason=lower: visit(MagicConstant) (hosted codegen.cr) is not ported yet example=UInt64#%
table: parse lowering 4 owner=lowering core reason=lower: visit(Assign to a parameter (hosted fun.cr, create_local_copy_of_arg)) (hosted codegen.cr) is not ported yet example=String#includes?
table: parse lowering 4 owner=bodies reason=BUG: the analysed program has no type for the body of compare_and_set (hosted codegen_fun: return type) example=Atomic(UInt64)#compare_and_set
table: parse lowering 4 owner=lowering core reason=lower: visit(a restriction that converts argument 0 of set (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#free_lists
table: parse lowering 4 owner=bodies reason=BUG: the analysed program has no type for the body of set (hosted codegen_fun: return type) example=Atomic(UInt64)#set
table: parse lowering 4 owner=bodies reason=BUG: the analysed program has no type for the body of wake_io (hosted codegen_fun: return type) example=IyiScheduler.class#wake_io
table: parse lowering 3 owner=unassigned reason=Cast from Compiler::Semantic::TopLevel::MetaclassType to Compiler::Semantic::TopLevel::ClassType+ failed, at src/compiler/lower/primitives.iyi:690:11:690 example=IyiSchedulerState.class#new
table: parse lowering 3 owner=unassigned reason=a function or global named IyiScheduler::shared already exists example=IyiScheduler.class#shared?
table: parse lowering 3 owner=bodies reason=lower: visit(pointerof of a ClassVar (hosted codegen.cr: visit(PointerOf), only a local variable is ported)) (hosted codegen.cr) is not ported yet example=IyiSchedLock.class#word
table: parse lowering 3 owner=lowering core reason=lower: visit(pointer_get of Atomic(UInt64) (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=IyiChanLock.class#acquire
table: parse lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of state_id (hosted codegen_fun: return type) example=IyiScheduler.class#state_id
table: parse lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of wait_for_events (hosted codegen_fun: return type) example=IyiScheduler.class#wait_for_events
table: parse lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of event_ready (hosted codegen_fun: return type) example=IyiScheduler.class#event_ready
table: parse lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of low_level_write (hosted codegen_fun: return type) example=IyiIO#low_level_write
table: parse lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of low_level_read (hosted codegen_fun: return type) example=IyiIO#low_level_read
table: parse lowering 2 owner=bodies reason=BUG: (IyiSchedulerState | Nil) has no type id (not reachable from Object) example=IyiScheduler.class#state
table: parse lowering 2 owner=unassigned reason=lower: a bare return from a function that returns a value (hosted codegen_return, the nil upcast) example=IyiSchedLock.class#lock
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of draw (hosted codegen_fun: return type) example=IyiChaos.class#draw
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of deadlock (hosted codegen_fun: return type) example=IyiScheduler.class#deadlock
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of lock (hosted codegen_fun: return type) example=IyiRuntimeLock.class#lock
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of run (hosted codegen_fun: return type) example=IyiOnce.class#run
table: parse lowering 2 owner=lowering core reason=lower: visit(a call to a def with a &block parameter (hosted call.cr: codegen_call_with_block_as_fun_literal, closures)) (hosted codegen.cr) is not ported yet example=IyiTestCases.class#verdict
table: parse lowering 2 owner=unassigned reason=lower: instance variable @size of Array(String): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(String)#empty?
table: parse lowering 2 owner=lowering core reason=lower: read of constant STDIN before its initialisation: the flag path (hosted read_const_pointer, create_read_const_function) is not ported yet example=Compiler::Tools::Parse::ParseTool.class#read_input
table: parse lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of parse_source (hosted codegen_fun: return type) example=Compiler::Tools::Parse::ParseTool.class#parse_source
table: parse lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(IyiFiber | Nil) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiScheduler.class#run_spawned_fiber
table: parse lowering 1 owner=lowering core reason=lower: visit(a class method call on a receiver that is not a constant path (hosted call.cr: prepare_call_args, Path)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#current
table: parse lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiSchedulerState: the :headed byte is the program-wide census (lower/headed.iyi, NEEDS.md rows 26-27), not decided) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#first_state_here
table: parse lowering 1 owner=lowering core reason=lower: visit(a class method call on Atomic(UInt64).class (hosted call.cr: prepare_call_args, a generic or builtin metaclass)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#initialize
table: parse lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Atomic(UInt64) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Atomic(UInt64).class#new
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to == (hosted call.cr: visit(Call)) example=IyiChaos.class#at_atomic
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to state (hosted call.cr: visit(Call)) example=IyiChaos.class#step
table: parse lowering 1 owner=unassigned reason=a function or global named IyiScheduler::state already exists example=IyiSchedLock.class#held_here?
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to chaos_unit (hosted call.cr: visit(Call)) example=IyiChaos.class#unit_of
table: parse lowering 1 owner=unassigned reason=not a number: "13787848793156543929" example=IyiChaos.class#mix
table: parse lowering 1 owner=bodies reason=lower: visit(pointerof of a InstanceVar (hosted codegen.cr: visit(PointerOf), only a local variable is ported)) (hosted codegen.cr) is not ported yet example=String#to_unsafe
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to memory (hosted call.cr: visit(Call)) example=String.class#new
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of fold (hosted codegen_fun: return type) example=IyiChaos.class#fold
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to state= (hosted call.cr: visit(Call)) example=IyiScheduler.class#enqueue
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for a branch (hosted codegen.cr: visit(If)) example=IyiScheduler.class#reschedule
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of take_lists (hosted codegen_fun: return type) example=IyiSchedulerState#take_lists
table: parse lowering 1 owner=lowering core reason=lower: visit(a restriction that converts argument 0 of add (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiFiber#claim_any
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of claim (hosted codegen_fun: return type) example=IyiFiber#claim
table: parse lowering 1 owner=lowering core reason=lower: visit(binary == on Int64 and Int32 (mixed operands, hosted codegen_binary_extend_int)) (hosted codegen.cr) is not ported yet example=Int64#//
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to malloc (hosted call.cr: visit(Call)) example=IyiScheduler.class#events_buffer
table: parse lowering 1 owner=unassigned reason=lower: is_a? of (Array(IyiFiber | Nil) | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiScheduler.class#io_take
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of io_slot (hosted codegen_fun: return type) example=IyiScheduler.class#io_slot
table: parse lowering 1 owner=unassigned reason=lower: instance variable @size of Array(IyiFiber | Nil): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(IyiFiber | Nil)#size
table: parse lowering 1 owner=lowering core reason=lower: visit(pointer_get of (IyiFiber | Nil) (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=Pointer((IyiFiber | Nil))#[]
table: parse lowering 1 owner=unassigned reason=lower: is_a? of (IyiUnit | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiScheduler.class#release_unit
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to at_atomic (hosted call.cr: visit(Call)) example=IyiUnit#waiting?
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to shared? (hosted call.cr: visit(Call)) example=IyiScheduler.class#take_mail
table: parse lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(Int32) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiSchedulerState#closed_fds
table: parse lowering 1 owner=unassigned reason=lower: instance variable @size of Array(Int32): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(Int32)#each
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of ensure_doorbell (hosted codegen_fun: return type) example=IyiScheduler.class#ensure_doorbell
table: parse lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Atomic(Int64) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiWorkers.class#word
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of thread_point (hosted codegen_fun: return type) example=IyiChaos.class#thread_point
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of give_up (hosted codegen_fun: return type) example=IyiWorkers.class#give_up
table: parse lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiFiber: the :headed byte is the program-wide census (lower/headed.iyi, NEEDS.md rows 26-27), not decided) (hosted codegen.cr) is not ported yet example=IyiFiber.class#main
table: parse lowering 1 owner=lowering core reason=lower: visit(assign Int32 to IyiFiberState (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=IyiFiber#initialize
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of register (hosted codegen_fun: return type) example=IyiScheduler.class#register
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of reap_dying (hosted codegen_fun: return type) example=IyiScheduler.class#reap_dying
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of release_stack (hosted codegen_fun: return type) example=IyiFiber#release_stack
table: parse lowering 1 owner=lowering core reason=lower: read of constant STDOUT before its initialisation: the flag path (hosted read_const_pointer, create_read_const_function) is not ported yet example=print
table: parse lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(String) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Compiler::Tools::Parse::ParseTool.class#run
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of args (hosted codegen_fun: return type) example=Program.class#args
table: parse lowering 1 owner=lowering core reason=lower: visit(pointer_get of String (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=Pointer(String)#[]
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to raise (hosted call.cr: visit(Call)) example=String#[]
table: parse lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Set(String) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Set(String).class#new
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of exists? (hosted codegen_fun: return type) example=File.class#exists?
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of read (hosted codegen_fun: return type) example=File.class#read
table: parse lowering 1 owner=lowering core reason=lower: codegen_cond of (Int32 | Nil) is not ported yet (hosted cond.cr: nilable and union tests, slice S2c) example=File.class#c_path
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of __iyi_defer_pop_run (hosted codegen_fun: return type) example=File.class#__iyi_defer_pop_run
table: parse lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of low_level_close (hosted codegen_fun: return type) example=IyiIO#low_level_close
table: compile_native defs-reached=2370 defs-typed-clean=1553 root-refusals=18 refusal-sites=2553
table: compile_native refusal 1218 owner=bodies reason=the value of 'buffer' cannot be typed example=src/iyi/./string.iyi:38 in String.class#new
table: compile_native refusal 651 owner=declarations reason=undefined constant T example=src/iyi/./array.iyi:28 in Array#initialize
table: compile_native refusal 193 owner=macros reason=macro control expansion (macros engine) example=src/iyi/./concurrency.iyi:1557 in top level
table: compile_native refusal 24 owner=bodies reason=the value of 'memory' cannot be typed example=src/iyi/./string.iyi:37 in String.class#new
table: compile_native refusal 17 owner=bodies reason=undefined local variable or method 'previous_def' for Atomic(UInt64) example=src/iyi/./chaos_points.iyi:26 in Atomic(UInt64)#add
table: compile_native refusal 16 owner=declarations reason=undefined constant HEADER_SIZE example=src/iyi/./string.iyi:36 in String.class#new
table: compile_native refusal 12 owner=calls reason=expected argument #1 to 'IyiScheduler.enqueue' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:3998 in IyiScheduler.class#deadlock_found
table: compile_native refusal 12 owner=bodies reason=undefined local variable or method 'uleb' for Compiler::Native::Wasm::Module::WasmModule example=src/compiler/native/wasm/leb.iyi:50 in Compiler::Native::Wasm::Module::WasmModule#uleb_i
table: compile_native refusal 11 owner=bodies reason=the value of '__temp_1' cannot be typed example=no location in IyiChaos.class#outranked?
table: compile_native refusal 11 owner=unassigned reason=wrong number of arguments for 'String.interpolation' (given 3, expected 1) example=no location in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 10 owner=calls reason=expected argument #1 to 'IyiAtomic.store' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/./concurrency.iyi:1475 in IyiSchedLock.class#unlock
table: compile_native refusal 10 owner=unassigned reason=wrong number of arguments for 'String.interpolation' (given 2, expected 1) example=no location in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 10 owner=unassigned reason=expected block to return Nil, not Int32 example=src/iyi/./string.iyi:604 in Char#each_byte
table: compile_native refusal 9 owner=unassigned reason=unsupported node: TraitDef example=src/std/traits.iyi:24 in top level
table: compile_native refusal 8 owner=bodies reason=the value of 'state' cannot be typed example=src/iyi/./chaos.iyi:228 in IyiChaos.class#draw
table: compile_native refusal 8 owner=declarations reason=undefined constant Tuple(T, Bool) example=src/iyi/./chaos_points.iyi:39 in IyiSchedulerState#take_lists
table: compile_native refusal 7 owner=declarations reason=undefined constant TARGET example=src/compiler/tools/compile_native.iyi:82 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 7 owner=bodies reason=undefined local variable or method 'wasm_vec' for Compiler::Native::Wasm::Module::WasmModule example=src/compiler/native/wasm/module.iyi:185 in Compiler::Native::Wasm::Module::WasmModule#write
table: compile_native refusal 6 owner=declarations reason=undefined constant DEADLOCK example=src/iyi/./concurrency.iyi:4011 in IyiScheduler.class#deadlock
table: compile_native refusal 6 owner=unassigned reason=wrong number of arguments for 'String.interpolation' (given 5, expected 1) example=no location in Array(IyiFiber | Nil)#[]
table: compile_native refusal 6 owner=declarations reason=undefined constant K example=src/iyi/./hash.iyi:44 in Hash(String, Int32)#initialize
table: compile_native refusal 6 owner=bodies reason=the value of 'ctx' cannot be typed example=src/compiler/native/wasm/codegen.iyi:1338 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 6 owner=bodies reason=the value of 'width' cannot be typed example=src/iyi/./array.iyi:444 in Array(<unresolved T>)#sort_in_place
table: compile_native refusal 5 owner=bodies reason=the value of 'following' cannot be typed example=src/iyi/./concurrency.iyi:2318 in IyiScheduler.class#take_mail
table: compile_native refusal 5 owner=declarations reason=undefined constant HELD example=src/iyi/./concurrency.iyi:1561 in IyiChanLock.class#acquire
table: compile_native refusal 5 owner=declarations reason=undefined constant IrError example=src/iyi/./primitives.iyi:159 in Pointer(<unresolved IrError>)#value
table: compile_native refusal 5 owner=bodies reason=the value of 'slot' cannot be typed example=src/iyi/./hash.iyi:566 in Hash(Int32, Array(UInt8))#slot_for
table: compile_native refusal 4 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:1737 in IyiScheduler.class#state_id
table: compile_native refusal 4 owner=declarations reason=undefined constant GOLDEN example=src/iyi/./chaos.iyi:227 in IyiChaos.class#draw
table: compile_native refusal 4 owner=calls reason=expected argument #1 to 'IyiFiber#state=' to be IyiFiberState, not Int32 example=src/iyi/./concurrency.iyi:2140 in IyiScheduler.class#enqueue
table: compile_native refusal 4 owner=calls reason=undefined method 'deadline' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4026 in IyiScheduler.class#wait_for_events
table: compile_native refusal 4 owner=calls reason=undefined method 'state' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3997 in IyiScheduler.class#deadlock_found
table: compile_native refusal 4 owner=bodies reason=the value of '__temp_2' cannot be typed example=no location in IyiScheduler.class#all_quiet?
table: compile_native refusal 4 owner=bodies reason=the value of 'rest' cannot be typed example=src/iyi/./concurrency.iyi:3611 in IyiScheduler.class#wake_joiners
table: compile_native refusal 4 owner=calls reason=expected argument #1 to 'Pointer(UInt8)#+' to be Int64, not Int32 example=src/iyi/./string.iyi:537 in String#==
table: compile_native refusal 4 owner=bodies reason=the value of 'below' cannot be typed example=src/iyi/./concurrency.iyi:6659 in File.class#__iyi_defer_pop_run
table: compile_native refusal 4 owner=declarations reason=undefined constant V example=src/iyi/./hash.iyi:45 in Hash(String, Int32)#initialize
table: compile_native refusal 4 owner=bodies reason=the value of 'modules' cannot be typed example=src/compiler/native/wasm/codegen.iyi:1285 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 4 owner=bodies reason=undefined local variable or method 'wasm_section' for Compiler::Native::Wasm::Module::WasmModule example=src/compiler/native/wasm/module.iyi:194 in Compiler::Native::Wasm::Module::WasmModule#write
table: compile_native refusal 4 owner=bodies reason=the value of 'result' cannot be typed example=src/iyi/./hash.iyi:157 in Hash(Int32, String)#keys
table: compile_native refusal 4 owner=declarations reason=undefined constant SORT_RUN example=src/iyi/./array.iyi:426 in Array(<unresolved T>)#sort_in_place
table: compile_native refusal 4 owner=bodies reason=the value of 'middle' cannot be typed example=src/iyi/./array.iyi:448 in Array(<unresolved T>)#sort_in_place
table: compile_native refusal 4 owner=bodies reason=the value of 'right' cannot be typed example=src/iyi/./array.iyi:454 in Array(<unresolved T>)#sort_in_place
table: compile_native refusal 3 owner=declarations reason=undefined constant SIMULATED example=src/iyi/./chaos.iyi:312 in IyiChaos.class#point
table: compile_native refusal 3 owner=calls reason=undefined method 'next_run=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2154 in IyiScheduler.class#enqueue
table: compile_native refusal 3 owner=bodies reason=the value of 'head_deadline' cannot be typed example=src/iyi/./concurrency.iyi:4047 in IyiScheduler.class#wait_for_events
table: compile_native refusal 3 owner=bodies reason=the value of 'gap' cannot be typed example=src/iyi/./concurrency.iyi:4048 in IyiScheduler.class#wait_for_events
table: compile_native refusal 3 owner=calls reason=expected argument #1 to 'IyiScheduler.switch_to' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:2595 in IyiScheduler.class#reschedule
table: compile_native refusal 3 owner=bodies reason=undefined local variable or method 'previous_def' for Atomic(Int64) example=src/iyi/./chaos_points.iyi:16 in Atomic(Int64)#get
table: compile_native refusal 3 owner=bodies reason=the value of 'compiler' cannot be typed example=src/compiler/tools/compile_native.iyi:161 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 3 owner=bodies reason=undefined local variable or method 'e' for Compiler::Tools::CompileNative::CompileNative.class example=src/compiler/tools/compile_native.iyi:53 in Compiler::Tools::CompileNative::CompileNative.class#module_of
table: compile_native refusal 3 owner=bodies reason=undefined local variable or method 'data_base' for Compiler::Tools::CompileNative::CompileNative.class example=src/compiler/native/wasm/codegen.iyi:1283 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 3 owner=bodies reason=the value of 'high' cannot be typed example=src/iyi/./array.iyi:452 in Array(<unresolved T>)#sort_in_place
table: compile_native refusal 3 owner=bodies reason=the value of 'into' cannot be typed example=src/iyi/./array.iyi:455 in Array(<unresolved T>)#sort_in_place
table: compile_native refusal 3 owner=bodies reason=the value of 'program' cannot be typed example=src/compiler/native/driver.iyi:240 in Compiler::Tools::CompileNative::CompileNative.class#link_native_program
table: compile_native refusal 3 owner=bodies reason=the value of 'rt' cannot be typed example=src/compiler/native/driver.iyi:242 in Compiler::Tools::CompileNative::CompileNative.class#link_native_program
table: compile_native refusal 2 owner=bodies reason=the value of 'unit' cannot be typed example=src/iyi/./chaos.iyi:265 in IyiChaos.class#unit_of
table: compile_native refusal 2 owner=bodies reason=the value of 'other' cannot be typed example=src/iyi/./chaos.iyi:374 in IyiChaos.class#outranked?
table: compile_native refusal 2 owner=calls reason=undefined method 'next_run' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./chaos.iyi:375 in IyiChaos.class#outranked?
table: compile_native refusal 2 owner=bodies reason=the value of 'task' cannot be typed example=src/iyi/./concurrency.iyi:3987 in IyiScheduler.class#deadlock_found
table: compile_native refusal 2 owner=bodies reason=the value of 'group' cannot be typed example=src/iyi/./concurrency.iyi:3989 in IyiScheduler.class#deadlock_found
table: compile_native refusal 2 owner=calls reason=undefined method 'object_id' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3990 in IyiScheduler.class#deadlock_found
table: compile_native refusal 2 owner=calls reason=undefined method 'claim_any' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3998 in IyiScheduler.class#deadlock_found
table: compile_native refusal 2 owner=bodies reason=the value of 'waits_here' cannot be typed example=src/iyi/./concurrency.iyi:2327 in IyiScheduler.class#take_mail
table: compile_native refusal 2 owner=declarations reason=undefined constant SPINNER example=src/iyi/./concurrency.iyi:1576 in IyiChanLock.class#contend
table: compile_native refusal 2 owner=calls reason=expected argument #2 to 'IyiAtomic.rmw' to be Pointer(<unresolved T>), not Pointer(UInt64) example=src/iyi/prelude.iyi:104 in IyiRuntimeLock.class#lock
table: compile_native refusal 2 owner=unassigned reason=wrong number of arguments for 'Proc(Nil)#call' (given 0, expected 1) example=src/iyi/./concurrency.iyi:2874 in IyiScheduler.class#run_spawned_fiber
table: compile_native refusal 2 owner=calls reason=undefined method 'next_joiner' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3609 in IyiScheduler.class#wake_joiners
table: compile_native refusal 2 owner=calls reason=undefined method 'next_joiner=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3610 in IyiScheduler.class#wake_joiners
table: compile_native refusal 2 owner=calls reason=expected argument #1 to 'Pointer#+' to be Int64, not Int32 example=src/iyi/./io.iyi:300 in IyiIO#write
table: compile_native refusal 2 owner=calls reason=expected argument #1 to 'IyiAtomic.load' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/prelude.iyi:10779 in top level
table: compile_native refusal 2 owner=bodies reason=the value of 'loader' cannot be typed example=src/compiler/tools/compile_native.iyi:159 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 2 owner=bodies reason=the value of 'refusal' cannot be typed example=src/compiler/tools/compile_native.iyi:164 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 2 owner=calls reason=expected argument #1 to 'Pointer(UInt8)#copy_from' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/./file.iyi:141 in File.class#c_path
table: compile_native refusal 2 owner=unassigned reason=undefined fun 'open' for Compiler::Tools::CompileNative::LibC example=src/iyi/prelude.iyi:57 in File.class#__iyi_open_read
table: compile_native refusal 2 owner=unassigned reason=unsupported node: ProcLiteral example=src/iyi/./file.iyi:68 in File.class#read
table: compile_native refusal 2 owner=unassigned reason=unsupported node: ExceptionHandler example=src/iyi/./file.iyi:68 in File.class#read
table: compile_native refusal 2 owner=calls reason=undefined method 'next_node' for Nil (compile-time type is (IyiDeferNode | Nil)) example=src/iyi/./concurrency.iyi:6658 in File.class#__iyi_defer_pop_run
table: compile_native refusal 2 owner=calls reason=undefined method 'next_node=' for Nil (compile-time type is (IyiDeferNode | Nil)) example=src/iyi/./concurrency.iyi:6660 in File.class#__iyi_defer_pop_run
table: compile_native refusal 2 owner=unassigned reason=wrong number of arguments for 'Proc#call' (given 0, expected 1) example=src/iyi/prelude.iyi:10849 in IyiDeferNode#run
table: compile_native refusal 2 owner=calls reason=undefined method 'run' for Nil (compile-time type is (IyiDeferNode | Nil)) example=src/iyi/./concurrency.iyi:6661 in File.class#__iyi_defer_pop_run
table: compile_native refusal 2 owner=bodies reason=the value of 'where' cannot be typed example=src/compiler/tools/compile_native.iyi:54 in Compiler::Tools::CompileNative::CompileNative.class#module_of
table: compile_native refusal 2 owner=lowering core reason=typeof is not ported yet: it needs typed bodies example=no location in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 2 owner=bodies reason=the value of 'data_end' cannot be typed example=src/compiler/native/wasm/codegen.iyi:1303 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 2 owner=bodies reason=the value of 'k' cannot be typed example=src/compiler/native/wasm/codegen.iyi:1303 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 2 owner=bodies reason=the value of 'stack_top' cannot be typed example=src/compiler/native/wasm/codegen.iyi:1359 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 2 owner=bodies reason=undefined local variable or method 'wasm_name' for Compiler::Native::Wasm::Module::WasmModule example=src/compiler/native/wasm/module.iyi:139 in Compiler::Native::Wasm::Module::WasmModule#add_export
table: compile_native refusal 2 owner=bodies reason=the value of 'entry' cannot be typed example=src/iyi/./hash.iyi:567 in Hash(Int32, Array(UInt8))#slot_for
table: compile_native refusal 2 owner=bodies reason=the value of 'copy' cannot be typed example=src/iyi/./array.iyi:786 in Array(<unresolved K>)#dup
table: compile_native refusal 2 owner=bodies reason=the value of 'finish' cannot be typed example=src/iyi/./array.iyi:428 in Array(<unresolved T>)#sort_in_place
table: compile_native refusal 2 owner=bodies reason=the value of 'value' cannot be typed example=src/iyi/./array.iyi:431 in Array(<unresolved T>)#sort_in_place
table: compile_native refusal 2 owner=unassigned reason=expected block to return Int32, not Nil example=src/iyi/./array.iyi:431 in Array(<unresolved T>)#sort_in_place
table: compile_native refusal 2 owner=bodies reason=undefined local variable or method 'k' for Compiler::Native::Wasm::Module::WasmModule example=src/compiler/native/wasm/module.iyi:242 in Compiler::Native::Wasm::Module::WasmModule#write
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
table: compile_native refusal 1 owner=declarations reason=undefined constant FNV_PRIME example=src/iyi/./chaos.iyi:254 in IyiChaos.class#fold
table: compile_native refusal 1 owner=calls reason=undefined method 'chaos_held=' for IyiFiber example=src/iyi/./chaos.iyi:357 in IyiChaos.class#step
table: compile_native refusal 1 owner=declarations reason=undefined constant POLL_EVERY example=src/iyi/./concurrency.iyi:2591 in IyiScheduler.class#reschedule
table: compile_native refusal 1 owner=declarations reason=undefined constant POLL_IO_NS example=src/iyi/./concurrency.iyi:2761 in IyiScheduler.class#poll_now
table: compile_native refusal 1 owner=calls reason=undefined method 'awaited' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3986 in IyiScheduler.class#deadlock_found
table: compile_native refusal 1 owner=calls reason=undefined method 'joining' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3988 in IyiScheduler.class#deadlock_found
table: compile_native refusal 1 owner=calls reason=undefined method 'deadlocked=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3994 in IyiScheduler.class#deadlock_found
table: compile_native refusal 1 owner=declarations reason=undefined constant EVENTS example=src/iyi/./concurrency.iyi:4982 in IyiScheduler.class#events_buffer
table: compile_native refusal 1 owner=calls reason=undefined method 'size' for Nil (compile-time type is (Array(IyiFiber | Nil) | Nil)) example=src/iyi/./concurrency.iyi:3423 in IyiScheduler.class#io_slot
table: compile_native refusal 1 owner=calls reason=undefined method '[]' for Nil (compile-time type is (Array(IyiFiber | Nil) | Nil)) example=src/iyi/./concurrency.iyi:3423 in IyiScheduler.class#io_slot
table: compile_native refusal 1 owner=calls reason=expected argument #2 to 'IyiScheduler.io_remove' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:4907 in IyiScheduler.class#io_take
table: compile_native refusal 1 owner=calls reason=expected argument #2 to 'IyiScheduler.heap_remove' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:4661 in IyiScheduler.class#wake_expired_sleepers
table: compile_native refusal 1 owner=calls reason=undefined method 'io_timed' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4662 in IyiScheduler.class#wake_expired_sleepers
table: compile_native refusal 1 owner=calls reason=undefined method 'io_timed=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4664 in IyiScheduler.class#wake_expired_sleepers
table: compile_native refusal 1 owner=calls reason=undefined method 'timed_out=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:4665 in IyiScheduler.class#wake_expired_sleepers
table: compile_native refusal 1 owner=calls reason=undefined method 'give' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:2721 in IyiScheduler.class#release_unit
table: compile_native refusal 1 owner=calls reason=undefined method 'waiting?' for Nil (compile-time type is (IyiUnit | Nil)) example=src/iyi/./concurrency.iyi:2722 in IyiScheduler.class#release_unit
table: compile_native refusal 1 owner=calls reason=expected argument #2 to 'IyiScheduler.drain_unit' to be IyiUnit, not (IyiUnit | Nil) example=src/iyi/./concurrency.iyi:2724 in IyiScheduler.class#release_unit
table: compile_native refusal 1 owner=calls reason=undefined method 'next_cancel' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2323 in IyiScheduler.class#take_mail
table: compile_native refusal 1 owner=calls reason=undefined method 'next_cancel=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2324 in IyiScheduler.class#take_mail
table: compile_native refusal 1 owner=calls reason=undefined method 'cancel_posted=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2325 in IyiScheduler.class#take_mail
table: compile_native refusal 1 owner=calls reason=undefined method 'unit' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2326 in IyiScheduler.class#take_mail
table: compile_native refusal 1 owner=calls reason=undefined method 'listed_on' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2326 in IyiScheduler.class#take_mail
table: compile_native refusal 1 owner=calls reason=undefined method 'waiting_out' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:2327 in IyiScheduler.class#take_mail
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.cancel_wait' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:2328 in IyiScheduler.class#take_mail
table: compile_native refusal 1 owner=calls reason=undefined method 'each' for Nil (compile-time type is (Array(Int32) | Nil)) example=src/iyi/./concurrency.iyi:2335 in IyiScheduler.class#take_mail
table: compile_native refusal 1 owner=calls reason=undefined method 'quiet' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2500 in IyiScheduler.class#all_quiet?
table: compile_native refusal 1 owner=calls reason=undefined method 'idle' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: compile_native refusal 1 owner=bodies reason=the value of 'quiet' cannot be typed example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: compile_native refusal 1 owner=calls reason=undefined method 'mail?' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2504 in IyiScheduler.class#all_quiet?
table: compile_native refusal 1 owner=calls reason=undefined method 'next_state' for Nil (compile-time type is (IyiSchedulerState | Nil)) example=src/iyi/./concurrency.iyi:2506 in IyiScheduler.class#all_quiet?
table: compile_native refusal 1 owner=declarations reason=undefined constant THREADS example=src/iyi/./chaos.iyi:314 in IyiChaos.class#point
table: compile_native refusal 1 owner=declarations reason=undefined constant UNMARKED example=src/iyi/./concurrency.iyi:1572 in IyiChanLock.class#contend
table: compile_native refusal 1 owner=bodies reason=the value of 'taken' cannot be typed example=src/iyi/./concurrency.iyi:1573 in IyiChanLock.class#contend
table: compile_native refusal 1 owner=unassigned reason=type mismatch for return type: expected IyiFiber, got (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:1829 in IyiScheduler.class#current
table: compile_native refusal 1 owner=unassigned reason=instance variable '@state' of IyiFiber must be IyiFiberState, not (IyiFiberState | Int32) example=src/iyi/./concurrency.iyi:635 in IyiFiber#initialize
table: compile_native refusal 1 owner=calls reason=undefined method 'prev_fiber=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1863 in IyiScheduler.class#register
table: compile_native refusal 1 owner=calls reason=undefined method 'on_cpu=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1917 in IyiScheduler.class#landed
table: compile_native refusal 1 owner=declarations reason=undefined constant STACK_BYTES example=src/iyi/./concurrency.iyi:926 in IyiFiber#release_stack
table: compile_native refusal 1 owner=calls reason=undefined method 'release_stack' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:1932 in IyiScheduler.class#reap_dying
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.unregister' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:1933 in IyiScheduler.class#reap_dying
table: compile_native refusal 1 owner=calls reason=undefined method 'awaited=' for Nil (compile-time type is (IyiFiber | Nil)) example=src/iyi/./concurrency.iyi:3620 in IyiScheduler.class#wake_joiners
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'IyiScheduler.ready' to be IyiFiber, not (IyiFiber | Nil) example=src/iyi/./concurrency.iyi:3621 in IyiScheduler.class#wake_joiners
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'Pointer#copy_from' to be Pointer(<unresolved T>), not Pointer(UInt8) example=src/iyi/./io.iyi:313 in IyiIO#write
table: compile_native refusal 1 owner=declarations reason=undefined constant NATIVE_TARGETS example=src/compiler/backend/backend.iyi:40 in Compiler::Backend::Backend::Backend.class#backend_for
table: compile_native refusal 1 owner=declarations reason=undefined constant IyiPath example=src/compiler/loader.iyi:131 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'iyi_path' for Compiler::Loader::Loader.class example=no location in Compiler::Loader::Loader.class#new
table: compile_native refusal 1 owner=unassigned reason=undefined fun 'write' for Compiler::Tools::CompileNative::LibC example=src/iyi/prelude.iyi:28 in File.class#__iyi_write
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'target' for IyiIO example=src/iyi/./io.iyi:194 in IyiIO#read_all
table: compile_native refusal 1 owner=unassigned reason=undefined fun 'close' for Compiler::Tools::CompileNative::LibC example=src/iyi/prelude.iyi:83 in IyiIO#__iyi_close
table: compile_native refusal 1 owner=declarations reason=undefined constant IrParser example=src/compiler/ir/parser.iyi:27 in Compiler::Tools::CompileNative::CompileNative.class#parse
table: compile_native refusal 1 owner=calls reason=undefined method 'to_s' for <unresolved IrParseError> (compile-time type is (<unresolved IrParseError> | Compiler::Ir::Module::Module)) example=src/compiler/tools/compile_native.iyi:48 in Compiler::Tools::CompileNative::CompileNative.class#module_of
table: compile_native refusal 1 owner=declarations reason=undefined constant Verifier example=src/compiler/ir/verifier.iyi:30 in Compiler::Tools::CompileNative::CompileNative.class#verify
table: compile_native refusal 1 owner=unassigned reason=expected block to return Nil, not Bool example=src/iyi/./array.iyi:227 in Array(String)#each
table: compile_native refusal 1 owner=declarations reason=undefined constant WasmCtx example=src/compiler/native/wasm/codegen.iyi:1279 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 1 owner=declarations reason=undefined constant Global example=no location in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 1 owner=bodies reason=the value of 'addr' cannot be typed example=src/compiler/native/wasm/codegen.iyi:1300 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 1 owner=declarations reason=undefined constant Function example=no location in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 1 owner=bodies reason=the value of 'imports' cannot be typed example=src/compiler/native/wasm/codegen.iyi:1331 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'stack_size' for Compiler::Tools::CompileNative::CompileNative.class example=src/compiler/native/wasm/codegen.iyi:1358 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 1 owner=bodies reason=the value of 'pages' cannot be typed example=src/compiler/native/wasm/codegen.iyi:1360 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 1 owner=bodies reason=the value of 'sp' cannot be typed example=src/compiler/native/wasm/codegen.iyi:1363 in Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'i32_const_expr' for Compiler::Native::Wasm::Module::WasmModule example=src/compiler/native/wasm/module.iyi:157 in Compiler::Native::Wasm::Module::WasmModule#add_element
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'h' for Hash(Int32, Array(UInt8)) example=src/iyi/./hash.iyi:564 in Hash(Int32, Array(UInt8))#slot_for
table: compile_native refusal 1 owner=unassigned reason=wrong number of arguments for 'Proc(Hash(Int32, Array(UInt8)), Int32, Array(UInt8))#call' (given 2, expected 1) example=src/iyi/./hash.iyi:97 in Hash(Int32, Array(UInt8))#[]
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'result' for Hash(Int32, String) example=src/iyi/./hash.iyi:156 in Hash(Int32, String)#keys
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'a' for Array(<unresolved K>) example=src/iyi/./array.iyi:479 in Array(<unresolved K>)#sorted
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'b' for Array(<unresolved K>) example=src/iyi/./array.iyi:479 in Array(<unresolved K>)#sorted
table: compile_native refusal 1 owner=calls reason=undefined method '>' for Nil example=src/iyi/./array.iyi:431 in Array(<unresolved T>)#sort_in_place
table: compile_native refusal 1 owner=calls reason=undefined method '<=' for Nil example=src/iyi/./array.iyi:454 in Array(<unresolved T>)#sort_in_place
table: compile_native refusal 1 owner=calls reason=undefined method 'new' for Slice(UInt8).class example=src/compiler/native/emit.iyi:67 in Compiler::Tools::CompileNative::CompileNative.class#to_bytes
table: compile_native refusal 1 owner=calls reason=expected argument #1 to 'String.new' to be Int32 or Array(UInt8) or Std::Slice::Slice(UInt8), not Std::Slice::Bytes example=src/compiler/tools/compile_native.iyi:183 in Compiler::Tools::CompileNative::CompileNative.class#run
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'buffer' for Char example=src/iyi/./string.iyi:592 in Char#to_s
table: compile_native refusal 1 owner=bodies reason=the value of 'objects' cannot be typed example=src/compiler/native/driver.iyi:244 in Compiler::Tools::CompileNative::CompileNative.class#link_native_program
table: compile_native refusal 1 owner=bodies reason=undefined local variable or method 'libraries_of' for Compiler::Tools::CompileNative::CompileNative.class example=src/compiler/native/driver.iyi:244 in Compiler::Tools::CompileNative::CompileNative.class#link_native_program
table: compile_native defs-lowered-clean=1350 lowering-refusal-sites=903
table: compile_native lowering 597 owner=bodies reason=BUG: the analysed program has no type for the body of grow (hosted codegen_fun: return type) example=Array(String)#grow
table: compile_native lowering 18 owner=bodies reason=BUG: the analysed program has no type for the body of raise (hosted codegen_fun: return type) example=UInt64#raise
table: compile_native lowering 14 owner=bodies reason=BUG: the analysed program has no type for the body of initialize (hosted codegen_fun: return type) example=Atomic(UInt64)#initialize
table: compile_native lowering 12 owner=bodies reason=BUG: the analysed program has no type for the body of uleb_i (hosted codegen_fun: return type) example=Compiler::Native::Wasm::Module::WasmModule#uleb_i
table: compile_native lowering 11 owner=lowering core reason=lower: visit(Cast) (hosted codegen.cr) is not ported yet example=UInt64#__iyi_say
table: compile_native lowering 9 owner=bodies reason=BUG: the analysed program has no type for the body of unlock (hosted codegen_fun: return type) example=IyiSchedLock.class#unlock
table: compile_native lowering 8 owner=bodies reason=BUG: the analysed program has no type for the body of [] (hosted codegen_fun: return type) example=Pointer(<unresolved IrError>)#[]
table: compile_native lowering 7 owner=unassigned reason=Cast from Compiler::Semantic::TopLevel::MetaclassType to Compiler::Semantic::TopLevel::ClassType+ failed, at src/compiler/lower/primitives.iyi:690:11:690 example=IyiSchedulerState.class#new
table: compile_native lowering 7 owner=bodies reason=BUG: the analysed program has no type for the body of get (hosted codegen_fun: return type) example=Atomic(UInt64)#get
table: compile_native lowering 6 owner=lowering core reason=lower: visit(a call to a def with a &block parameter (hosted call.cr: codegen_call_with_block_as_fun_literal, closures)) (hosted codegen.cr) is not ported yet example=IyiTestCases.class#verdict
table: compile_native lowering 6 owner=lowering core reason=lower: visit(ArrayLiteral) (hosted codegen.cr) is not ported yet example=Compiler::Tools::CompileNative::CompileNative.class#start_wasm32_ir
table: compile_native lowering 5 owner=unassigned reason=lower: is_a? of (IyiFiber | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiChaos.class#outranked?
table: compile_native lowering 5 owner=bodies reason=BUG: the analysed program has no type for the body of add (hosted codegen_fun: return type) example=Atomic(UInt64)#add
table: compile_native lowering 5 owner=lowering core reason=lower: visit(Assign to a parameter (hosted fun.cr, create_local_copy_of_arg)) (hosted codegen.cr) is not ported yet example=String#includes?
table: compile_native lowering 5 owner=lowering core reason=lower: visit(MacroIf) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#poll_now
table: compile_native lowering 5 owner=bodies reason=BUG: the analysed program has no type for the body of __iyi_monotonic_ns (hosted codegen_fun: return type) example=IyiScheduler.class#__iyi_monotonic_ns
table: compile_native lowering 4 owner=unassigned reason=lower: a bare return from a function that returns a value (hosted codegen_return, the nil upcast) example=IyiSchedLock.class#lock
table: compile_native lowering 4 owner=lowering core reason=lower: visit(MagicConstant) (hosted codegen.cr) is not ported yet example=UInt64#%
table: compile_native lowering 4 owner=bodies reason=BUG: the analysed program has no type for the body of compare_and_set (hosted codegen_fun: return type) example=Atomic(UInt64)#compare_and_set
table: compile_native lowering 4 owner=lowering core reason=lower: visit(a restriction that converts argument 0 of set (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#free_lists
table: compile_native lowering 4 owner=bodies reason=BUG: the analysed program has no type for the body of set (hosted codegen_fun: return type) example=Atomic(UInt64)#set
table: compile_native lowering 4 owner=bodies reason=BUG: the analysed program has no type for the body of wake_io (hosted codegen_fun: return type) example=IyiScheduler.class#wake_io
table: compile_native lowering 4 owner=bodies reason=BUG: the analysed program has no type for the body of run (hosted codegen_fun: return type) example=IyiOnce.class#run
table: compile_native lowering 4 owner=unassigned reason=Cast from Compiler::Types::Types::GenericClassInstanceMetaclassType to Compiler::Semantic::TopLevel::ClassType+ failed, at src/compiler/lower/primitives.iyi:690:11:690 example=Array(String).class#new
table: compile_native lowering 4 owner=unassigned reason=BUG: a primitive call has no receiver (hosted call.cr: codegen_primitive) example=Char#to_s
table: compile_native lowering 3 owner=unassigned reason=a function or global named IyiScheduler::shared already exists example=IyiScheduler.class#shared?
table: compile_native lowering 3 owner=bodies reason=lower: visit(pointerof of a ClassVar (hosted codegen.cr: visit(PointerOf), only a local variable is ported)) (hosted codegen.cr) is not ported yet example=IyiSchedLock.class#word
table: compile_native lowering 3 owner=lowering core reason=lower: visit(pointer_get of Atomic(UInt64) (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=IyiChanLock.class#acquire
table: compile_native lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of state_id (hosted codegen_fun: return type) example=IyiScheduler.class#state_id
table: compile_native lowering 3 owner=bodies reason=BUG: the analysed program has no type for a branch (hosted codegen.cr: visit(If)) example=IyiScheduler.class#reschedule
table: compile_native lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of wait_for_events (hosted codegen_fun: return type) example=IyiScheduler.class#wait_for_events
table: compile_native lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of event_ready (hosted codegen_fun: return type) example=IyiScheduler.class#event_ready
table: compile_native lowering 3 owner=unassigned reason=lower: instance variable @size of Array(Int32): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(Int32)#each
table: compile_native lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of low_level_write (hosted codegen_fun: return type) example=IyiIO#low_level_write
table: compile_native lowering 3 owner=bodies reason=BUG: the analysed program has no type for the body of low_level_read (hosted codegen_fun: return type) example=IyiIO#low_level_read
table: compile_native lowering 3 owner=unassigned reason=lower: instance variable @size of Array(UInt8): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(UInt8)#<<
table: compile_native lowering 2 owner=bodies reason=BUG: (IyiSchedulerState | Nil) has no type id (not reachable from Object) example=IyiScheduler.class#state
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of draw (hosted codegen_fun: return type) example=IyiChaos.class#draw
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of deadlock (hosted codegen_fun: return type) example=IyiScheduler.class#deadlock
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of lock (hosted codegen_fun: return type) example=IyiRuntimeLock.class#lock
table: compile_native lowering 2 owner=lowering core reason=lower: visit(a class method call on Array(T).class (hosted call.cr: prepare_call_args, a generic or builtin metaclass)) (hosted codegen.cr) is not ported yet example=Std::Base64::Base64.class#decode_values
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of exists? (hosted codegen_fun: return type) example=File.class#exists?
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of read (hosted codegen_fun: return type) example=File.class#read
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of __iyi_open_read (hosted codegen_fun: return type) example=File.class#__iyi_open_read
table: compile_native lowering 2 owner=bodies reason=BUG: the analysed program has no type for the body of __iyi_defer_pop_run (hosted codegen_fun: return type) example=File.class#__iyi_defer_pop_run
table: compile_native lowering 2 owner=unassigned reason=lower: instance variable @size of Array(String): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(String)#<<
table: compile_native lowering 2 owner=unassigned reason=lower: instance variable @size of Hash(Int32, String): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Hash(Int32, String)#initialize
table: compile_native lowering 2 owner=unassigned reason=lower: instance variable @size of Array(Array(UInt8)): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(Array(UInt8))#<<
table: compile_native lowering 2 owner=lowering core reason=BUG: create_llvm_type for <unresolved T> is not ported yet (hosted llvm_typer.cr) example=Pointer(<unresolved T>)#copy_from
table: compile_native lowering 2 owner=unassigned reason=lower: instance variable @size of Array(<unresolved T>): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(<unresolved T>)#size
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(IyiFiber | Nil) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiScheduler.class#run_spawned_fiber
table: compile_native lowering 1 owner=lowering core reason=lower: visit(a class method call on a receiver that is not a constant path (hosted call.cr: prepare_call_args, Path)) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#current
table: compile_native lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiSchedulerState: the :headed byte is the program-wide census (lower/headed.iyi, NEEDS.md rows 26-27), not decided) (hosted codegen.cr) is not ported yet example=IyiScheduler.class#first_state_here
table: compile_native lowering 1 owner=lowering core reason=lower: visit(a class method call on Atomic(UInt64).class (hosted call.cr: prepare_call_args, a generic or builtin metaclass)) (hosted codegen.cr) is not ported yet example=IyiSchedulerState#initialize
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Atomic(UInt64) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Atomic(UInt64).class#new
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to == (hosted call.cr: visit(Call)) example=IyiChaos.class#at_atomic
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to state (hosted call.cr: visit(Call)) example=IyiChaos.class#step
table: compile_native lowering 1 owner=unassigned reason=a function or global named IyiScheduler::state already exists example=IyiSchedLock.class#held_here?
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to chaos_unit (hosted call.cr: visit(Call)) example=IyiChaos.class#unit_of
table: compile_native lowering 1 owner=unassigned reason=not a number: "13787848793156543929" example=IyiChaos.class#mix
table: compile_native lowering 1 owner=bodies reason=lower: visit(pointerof of a InstanceVar (hosted codegen.cr: visit(PointerOf), only a local variable is ported)) (hosted codegen.cr) is not ported yet example=String#to_unsafe
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to memory (hosted call.cr: visit(Call)) example=String.class#new
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of fold (hosted codegen_fun: return type) example=IyiChaos.class#fold
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to state= (hosted call.cr: visit(Call)) example=IyiScheduler.class#enqueue
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of take_lists (hosted codegen_fun: return type) example=IyiSchedulerState#take_lists
table: compile_native lowering 1 owner=lowering core reason=lower: visit(a restriction that converts argument 0 of add (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=IyiFiber#claim_any
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of claim (hosted codegen_fun: return type) example=IyiFiber#claim
table: compile_native lowering 1 owner=lowering core reason=lower: visit(binary == on Int64 and Int32 (mixed operands, hosted codegen_binary_extend_int)) (hosted codegen.cr) is not ported yet example=Int64#//
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to malloc (hosted call.cr: visit(Call)) example=IyiScheduler.class#events_buffer
table: compile_native lowering 1 owner=unassigned reason=lower: is_a? of (Array(IyiFiber | Nil) | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiScheduler.class#io_take
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of io_slot (hosted codegen_fun: return type) example=IyiScheduler.class#io_slot
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @size of Array(IyiFiber | Nil): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(IyiFiber | Nil)#size
table: compile_native lowering 1 owner=lowering core reason=lower: visit(pointer_get of (IyiFiber | Nil) (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=Pointer((IyiFiber | Nil))#[]
table: compile_native lowering 1 owner=unassigned reason=lower: is_a? of (IyiUnit | Nil) reads the union's or virtual type's id word (hosted match_type_id), not ported yet (slice S2c3) example=IyiScheduler.class#release_unit
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to at_atomic (hosted call.cr: visit(Call)) example=IyiUnit#waiting?
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to shared? (hosted call.cr: visit(Call)) example=IyiScheduler.class#take_mail
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(Int32) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiSchedulerState#closed_fds
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of ensure_doorbell (hosted codegen_fun: return type) example=IyiScheduler.class#ensure_doorbell
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Atomic(Int64) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=IyiWorkers.class#word
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of thread_point (hosted codegen_fun: return type) example=IyiChaos.class#thread_point
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of give_up (hosted codegen_fun: return type) example=IyiWorkers.class#give_up
table: compile_native lowering 1 owner=lowering core reason=lower: visit(allocate of class IyiFiber: the :headed byte is the program-wide census (lower/headed.iyi, NEEDS.md rows 26-27), not decided) (hosted codegen.cr) is not ported yet example=IyiFiber.class#main
table: compile_native lowering 1 owner=lowering core reason=lower: visit(assign Int32 to IyiFiberState (hosted assign_distinct, not ported)) (hosted codegen.cr) is not ported yet example=IyiFiber#initialize
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of register (hosted codegen_fun: return type) example=IyiScheduler.class#register
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of reap_dying (hosted codegen_fun: return type) example=IyiScheduler.class#reap_dying
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of release_stack (hosted codegen_fun: return type) example=IyiFiber#release_stack
table: compile_native lowering 1 owner=lowering core reason=lower: read of constant STDOUT before its initialisation: the flag path (hosted read_const_pointer, create_read_const_function) is not ported yet example=print
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of args (hosted codegen_fun: return type) example=Program.class#args
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(String) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Array(String)#size
table: compile_native lowering 1 owner=lowering core reason=lower: visit(pointer_get of String (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=Pointer(String)#[]
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of no_backend_message (hosted codegen_fun: return type) example=Compiler::Backend::Backend::Backend.class#no_backend_message
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to includes? (hosted call.cr: visit(Call)) example=Compiler::Backend::Backend::Backend.class#backend_for
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to puts (hosted call.cr: visit(Call)) example=Compiler::Tools::CompileNative::CompileNative.class#fail
table: compile_native lowering 1 owner=lowering core reason=lower: codegen_cond of (Int32 | Nil) is not ported yet (hosted cond.cr: nilable and union tests, slice S2c) example=File.class#c_path
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of __iyi_write (hosted codegen_fun: return type) example=File.class#__iyi_write
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to raise (hosted call.cr: visit(Call)) example=String#[]
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to close (hosted call.cr: visit(Call)) example=IyiIO#low_level_close
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of __iyi_close (hosted codegen_fun: return type) example=IyiIO#__iyi_close
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(Compiler::Ir::Types::IrType) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Compiler::Tools::CompileNative::CompileNative.class#module_of
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of parse (hosted codegen_fun: return type) example=Compiler::Tools::CompileNative::CompileNative.class#parse
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of verify (hosted codegen_fun: return type) example=Compiler::Tools::CompileNative::CompileNative.class#verify
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(<unresolved IrError>) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Array(<unresolved IrError>)#each
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @size of Array(<unresolved IrError>): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(<unresolved IrError>)#empty?
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @capacity of Array(String): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(String)#reserve
table: compile_native lowering 1 owner=lowering core reason=lower: visit(pointer_set of String (hosted assign, primitives.cr 927)) (hosted codegen.cr) is not ported yet example=Pointer(String)#[]=
table: compile_native lowering 1 owner=lowering core reason=lower: visit(allocate of class String::Builder: the :headed byte is the program-wide census (lower/headed.iyi, NEEDS.md rows 26-27), not decided) (hosted codegen.cr) is not ported yet example=String.class#build
table: compile_native lowering 1 owner=lowering core reason=lower: visit(primitive pointer_malloc (hosted codegen_primitive_pointer_malloc, primitives.cr 905-965: its helper is not ported)) (hosted codegen.cr) is not ported yet example=String::Builder#initialize
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the call to write (hosted call.cr: visit(Call)) example=String::Builder#<<
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(UInt8) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Compiler::Tools::CompileNative::CompileNative.class#compile_wasm
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Hash(Int32, String) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Compiler::Native::Wasm::Module::WasmModule.class#new
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(Array(UInt8)) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Array(Array(UInt8)).class#new
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Hash(String, Int32) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Hash(String, Int32).class#new
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @size of Hash(String, Int32): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Hash(String, Int32)#initialize
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Hash(Int32, Array(UInt8)) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Hash(Int32, Array(UInt8)).class#new
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @size of Hash(Int32, Array(UInt8)): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Hash(Int32, Array(UInt8))#initialize
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @capacity of Array(UInt8): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(UInt8)#reserve
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Hash(String, Bool) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Hash(String, Bool).class#new
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @size of Hash(String, Bool): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Hash(String, Bool)#initialize
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of add_element (hosted codegen_fun: return type) example=Compiler::Native::Wasm::Module::WasmModule#add_element
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @capacity of Array(Array(UInt8)): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Array(Array(UInt8))#reserve
table: compile_native lowering 1 owner=lowering core reason=lower: visit(pointer_set of Array(UInt8) (hosted assign, primitives.cr 927)) (hosted codegen.cr) is not ported yet example=Pointer(Array(UInt8))#[]=
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of add_export (hosted codegen_fun: return type) example=Compiler::Native::Wasm::Module::WasmModule#add_export
table: compile_native lowering 1 owner=lowering core reason=lower: visit(a restriction that converts argument 0 of entry_of (hosted call.cr: prepare_call_args)) (hosted codegen.cr) is not ported yet example=Hash(Int32, Array(UInt8))#[]
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @capacity of Hash(Int32, Array(UInt8)): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Hash(Int32, Array(UInt8))#entry_of
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of slot_for (hosted codegen_fun: return type) example=Hash(Int32, Array(UInt8))#slot_for
table: compile_native lowering 1 owner=lowering core reason=lower: visit(pointer_get of Array(UInt8) (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=Pointer(Array(UInt8))#[]
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of keys (hosted codegen_fun: return type) example=Hash(Int32, String)#keys
table: compile_native lowering 1 owner=unassigned reason=lower: instance variable @first of Hash(Int32, String): not a class or struct (hosted instance_var_ptr, union or virtual owner) (slice S2a) example=Hash(Int32, String)#each
table: compile_native lowering 1 owner=lowering core reason=lower: visit(pointer_get of Bool (hosted to_lhs, primitives.cr 938)) (hosted codegen.cr) is not ported yet example=Pointer(Bool)#[]
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(<unresolved K>) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Array(<unresolved K>)#sorted
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of dup (hosted codegen_fun: return type) example=Array(<unresolved K>)#dup
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Array(<unresolved T>) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Array(<unresolved T>)#sort_in_place
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of to_bytes (hosted codegen_fun: return type) example=Compiler::Tools::CompileNative::CompileNative.class#to_bytes
table: compile_native lowering 1 owner=lowering core reason=lower: visit(yield with no block in scope (hosted codegen.cr: visit(Yield), a block of an enclosing block body)) (hosted codegen.cr) is not ported yet example=String#each_point
table: compile_native lowering 1 owner=lowering core reason=BUG: llvm_struct_type of generic instance Hash(String, Std::Slice::Bytes) is not ported: the port model has no all_instance_vars for it (see NEEDS.md) example=Compiler::Tools::CompileNative::CompileNative.class#link_native_program
table: compile_native lowering 1 owner=bodies reason=BUG: the analysed program has no type for the body of chmod (hosted codegen_fun: return type) example=File.class#chmod
```
<!-- table:end -->
