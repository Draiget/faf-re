# Particle pool session statistics: source-bound host tests

This standalone GTest suite tests the session-statistics candidate without a
Windows/Direct3D SDK. It is not an engine build, retail-layout check, GPU test,
replay execution, performance benchmark, or concurrency test.

## Executed production code

`bind_stats.py` extracts complete definitions verbatim, emits source `#line`
locations, and records SHA-256 identities for full input files, individual
original/bound definitions, generated files, and included container/Math headers.
An absent or ambiguous definition, or a declaration instead of a body, fails
binding. The ordinary target applies no functional mutation.

- The complete `ParticlePoolStats.h` is directly included.
- Production trail payload, interval, work-item, buffer and bucket structs are
  copied verbatim. Real `fa::vector`, `fa::list`, `fa::map`, `fa::set`, `fa::string`,
  `fa::auto_ptr`, `CountedPtr`, and patched WildMagic vector code are compiled.
- Whole trail acquisition/release, Ensure, upload, vertex pack, interval,
  prune/recycle/destroy, world Clear, pool Init/destruction, and Begin/End bodies
  execute. Production capacity constants and `ren_LargeParticlePools`' actual
  default definition are bound, not replaced with test-specific capacities.
- Whole `WLD_CreateSession`, `DeleteWldSessionAndReturn`, `WLD_DestroySession`,
  and `WLD_Teardown` bodies execute with explicit collaborators described below.
- Whole `ResetWorldParticleBuffers`, `ParticleBuffer::Reset`, and
  `ParticleBuffer::Shutdown` bodies execute using host resource handles.
- `CWldSession::ResetForNewReplaySim` is inspected as a source contract only.
  Its Clear call executes separately through the actual Clear body; this suite
  does not execute the full replay-reset implementation.

## Explicit adapter boundary

`CWorldParticles` is a host shell with real production container types for the
lanes used by bound definitions. It is not the recovered class/vtable/layout.
Bucket-map keys are integer fixture IDs. The particle-bucket destruction adapter
throws if reached; these tests populate only trail buckets. Cached-key reset and
beam cleanup collaborators carry no graphics resources in the fixture.

The trail vertex-sheet/stream adapter records Lock ranges/flags and Unlocks,
returns bounded CPU storage, and can return null or throw at resource creation.
The particle resource handles are `std::shared_ptr<int>`. Shared trail-index
creation is an adapter, not a GPU allocation. Texture resources use a minimal
counting adapter; their `CountedPtr` and payload copy/destruction code are real.

World construction/destruction, sync driver, DoBeat, UI, audio, replay cleanup,
and teardown callbacks are synchronous adapters. DoBeat contributes known loss
counts so moving End before the final drain is observable. The recording logger
checks that occupied trail descriptors are not yet returned when End logs, so
moving End after Clear is also observable. Actual session constructor/destructor
internals and actual sync effects are outside the fixture. The explicit
`operator new(size, nothrow)` overload injects only session allocation failure;
ordinary allocation and container behavior are not replaced.

The recording `gpg::Logf` adapter formats the production format/arguments, can
throw, and can reenter End. It does not represent native logging sinks or native
logger availability. Repeated End is closed before the callback executes.

## Coverage

34 GTests cover inactive/empty/consecutive sessions, repeated Begin/End,
capacity metadata reuse, inherited unavailable/exhausted pools, guarded unsigned
differences, width-aware cumulative uint64 counters, fixed scalar storage, real legacy and
large Init, partially successful trail Init, acquire/release/reacquire,
segment-not-vertex drop units, partially filled tail pressure, distinct null
buffer/lock pending discards with previous intervals, bounded successful quad
packing, expiration and Clear exclusion, replay-style continuation, pool destroy
and device-reset behavior, exact log fields, throwing/reentrant logger, create
allocation/constructor failure, normal/full-restart/direct-destroy paths, and
final-drain/end/clear ordering.

The cumulative-counter test adds SIZE_MAX followed by 1 to all four counters.
For a 64-bit size_t it expects UINT64_MAX and saturated=true. For a narrower
size_t it expects uint64_t(SIZE_MAX)+1 and saturated=false. The assertions are
portable; the recorded executions are x64 only, not evidence of x86 execution.

Statistics measure descriptors absent from the free pool, including previously
stranded descriptors; they do not measure visible particles. Pending upload
discards do not count invalidated previously uploaded intervals. No claim is made
for arbitrary concurrent or reentrant device/allocation callbacks. The stock
main/event-thread owner model is the intended use, not a race-tested interface.

The sidecar static check verifies bounded scalar storage and absence of hot-path
allocation/container/lock/log/loop constructs in its header. This establishes a
code bound, not an end-to-end performance measurement. Existing pool/tree/list
operations still have their original allocation behavior.

### Leak-check limitation

ASan/UBSan runs use `ASAN_OPTIONS=detect_leaks=0` as specified for this validation.
The partial-Init test throws from NewVertexSheet after a raw segment descriptor
was allocated but before insertion. The existing production path abandons that
unincluded descriptor on this exception. The fixture deliberately preserves
this existing behavior rather than changing ownership to make the test clean.
A passing run is not evidence of leak freedom or exception-safety fixes.

## Build and run

Use already prepared official GoogleTest and repository-patched WildMagic
sources. No test script downloads or installs anything. From the repository:

```sh
cmake -S tests/particles/stats_host -B build/stats-host
cmake --build build/stats-host -j2
ctest --test-dir build/stats-host --output-on-failure
build/stats-host/particle_stats_host --gtest_output=xml:build/stats-host/results.xml

cmake -S tests/particles/stats_host -B build/stats-host-san \
  -DFAF_PARTICLE_SANITIZE=ON
cmake --build build/stats-host-san -j2
ASAN_OPTIONS=detect_leaks=0 build/stats-host-san/particle_stats_host \
  --gtest_output=xml:build/stats-host-san/results.xml
ctest --test-dir build/stats-host-san --output-on-failure
```

`FAF_GTEST_LIBRARY_DIR` optionally reuses matching existing `libgtest.a` and
`libgtest_main.a`; the production/adaptor test translation unit remains fully
ASan/UBSan-instrumented even if these GoogleTest support libraries are not.
The sanitizer build disables recovery on sanitizer error and rejects an enabled
sanitizer option for compiler families other than GCC/Clang, instead of silently
ignoring it. Retail pointer/layout
assertions are not checked on the host x64 build.

## Negative controls

```sh
python tests/particles/stats_host/run_negative_controls.py \
  --cmake "$(command -v cmake)" \
  --build-root build/stats-host-negative \
  --gtest-library-dir "$PWD/build/stats-host/lib"
```

Eight controls mutate generated copies only: count segments as vertices, omit
partial-capacity recording, End on Clear, silently reset statistics on Clear,
End before the final drain, End after Clear, omit inherited occupancy, and omit
the summary log. Each must configure and compile successfully, return exactly
GTest failure exit code 1, and produce fresh XML with failures for the exact
selected test names/count and completed/run status. The runner deletes the old
summary before beginning and the old XML immediately before each execution.
It verifies the GTest completion and environment-teardown markers, rejects
skipped/disabled/error outcomes and sanitizer diagnostic text, and requires
an assertion failure for every selected case. A compiler failure, crash, signal,
sanitizer diagnostic, incomplete run, or missing fresh XML is rejected. Read each
directory's manifest and test log.

Generated files and manifests belong in the build directories. No production
file is edited by this suite or the negative-control runner. This standalone
suite is not automatically registered by the engine's root CMake project.
