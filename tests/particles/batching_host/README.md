# Source-bound particle batching reclamation tests

This is a **host recorder**, not a native engine or GPU test. It extends the
batching-disabled fixture used to investigate PR #338 by compiling the selected
production reclaim, upload, mirror and gather code with batching enabled.
Production files and algorithms are not edited.

## What actually runs

`bind_production.py` extracts 24 complete definitions verbatim from:

- `CWorldParticles.cpp`: buffer acquire/release and normal/water/refraction render methods.
- `ParticleRenderBuckets.cpp`: upload, pruning, fill, cleanup, mirror store, gather store, batching selection, gathering, and original-draw fallback.
- `ParticleRenderWorkItem.cpp`: interval initialization, expiry, cleanup, and work-item destruction.
- `GpuPathSettings.cpp`: production feature/setting selection.

The production `ParticlePoolReclaim.h`, `fa::vector`, `fa::list`, and GPU feature
constants are included directly. The generated include and JSON manifest record
source paths, line numbers, source SHA256 and definition SHA256. Missing or
ambiguous source definitions fail the build instead of substituting a model.

The fixture uses a synchronous byte-recording graphics device and particle
buffer locks/draws, `std::map` bucket lookup, simplified particle payload fields,
`std::shared_ptr`, and no-op camera/shader selection. Trail execution fails
explicitly if reached; the trail map is empty in these tests. These adapters do
not test real graphics resources, command submission, synchronization, shader
output, device reset, pool initialization, engine layouts, or GPU performance.
`FAF_PARTICLE_BATCH_DIAG` must be unset.

The repository's normal host/x64 `LayoutAsserts.h` configuration is used only
around its container header. This is not a retail-layout check. GCC 14 emits
existing production diagnostics for repeated list iterator typedef names and
a discarded freed-pointer return; those two warnings remain visible but are
not fatal in this target. No production source was changed to silence them.

## Cases

15 GoogleTests cover:

- Exhausted pool, early suffix pruning, reused descriptor/mirror slot, and exact drawn bytes for the new contents.
- Reused slots with a nonzero live interval cursor and exact gather byte offsets.
- A failed mirror upload after reuse, then an appended upload: both gather the original buffer instead of stale or incomplete mirror data.
- Failure of the second gather copy: original buffers are drawn once each, in the original reverse order, with no prematurely drawn gathered copy.
- Normal, water and refraction render entry points for each of the above cases.
- Repeated pruning and repeated `ForgetMirroredParticles` calls without duplicate free slots or pool entries.
- 32 alternating bucket refill/reclaim cycles with slot uniqueness and draw order checks.
- Batch-off reuse followed by re-enabling batching, without reviving an old mirror.

Assertions check 92-byte instance records, not just particle counts. Assertions
about mirror ownership and free-slot uniqueness also catch omitted cleanup
that may not corrupt bytes immediately after a successful complete refill.

## Run

Use an existing official GoogleTest 1.15.2 source directory. No dependency is
downloaded by this harness. From an engine checkout containing these files:

```sh
cmake -S tests/particles/batching_host -B build/particle-batch-host \
  -DGTEST_SOURCE_DIR=/path/to/googletest-1.15.2 -DCMAKE_BUILD_TYPE=Debug
cmake --build build/particle-batch-host -j2
ctest --test-dir build/particle-batch-host --output-on-failure
```

For a separate candidate overlay, also pass `-DFAF_SOURCE_ROOT=/path/to/source`.
The target builds and runs both the new 15 tests and the 14 committed helper
tests from that source tree. It does not silently add itself to the Windows
engine target or its CI workflows.

```sh
cmake -S tests/particles/batching_host -B build/particle-batch-sanitize \
  -DGTEST_SOURCE_DIR=/path/to/googletest-1.15.2 -DCMAKE_BUILD_TYPE=Debug -DSANITIZE=ON
cmake --build build/particle-batch-sanitize -j2
ASAN_OPTIONS=detect_leaks=0 ctest --test-dir build/particle-batch-sanitize --output-on-failure
ASAN_OPTIONS=detect_leaks=0 build/particle-batch-sanitize/faf_particle_batch_reclaim_host_tests \
  --gtest_repeat=100 --gtest_shuffle --gtest_random_seed=338
```

`detect_leaks=0` means no leak-test claim is made. Leave LeakSanitizer enabled
where the execution environment supports it.

## Negative controls

```sh
python3 tests/particles/batching_host/run_negative_controls.py \
  --source-root . --binding build/particle-batch-host/ParticleBatchProduction.inc \
  --gtest-root /path/to/googletest-1.15.2 --gtest-build build/particle-batch-host \
  --output-dir build/particle-batch-controls --source-head "$(git rev-parse HEAD)"
```

This GCC-oriented runner changes only copies of the generated bindings. It
requires each mutation to compile and then fail a GoogleTest assertion; a
compiler error or crash does not count as a caught defect:

1. Omit the expiry-path `ForgetMirroredParticles` call.
2. Retain a released mirror slot's ownership mapping, enabling repeated frees.
3. Ignore a failed mirror copy and leave its validity bit true.
4. Report gather success after a copy failure, omitting the original-buffer fallback.

The engine source tree, positive generated bindings, and test expectations are
never modified by the controls. Each result records the mutation, binding hash,
compiler command, exit status and failing test names.

## Evidence boundary

These tests narrow the batching-on **source-control-flow** gap. They do not
establish Windows build success, native device/backend/GPU execution, visible
equivalence or game performance. Review readiness also depends on the current
source/base, applicable compilation checks and the buffer-discard/copy lifetime
contract; it is not equivalent to merge, deployment or visual acceptance.

For renderer integration, exercise a constrained pool where an expired later
bucket supplies an earlier bucket, with batching off/on and particle, trail,
water and refraction lanes. Check membership/draw order and graphics validation.
Those results remain separate from the host recorder and must be reported as
such; do not infer an in-game or GPU pass from this suite.
