# Pending particle upload host tests

This standalone GoogleTest target binds selected definitions from the current
checkout. It does not build the engine, vendor a source snapshot, or require a
second historical checkout. Both switch values run the same compiled code.

## Build and run

Requirements: CMake 3.25+, Python 3, a C++20 compiler, and this repository's
patched WildMagic and GoogleTest dependencies. On a fresh checkout, prepare only
the two needed dependencies with the existing repository helper:

```sh
cmake -DFAF_DEPENDENCIES_ONLY="WildMagic3p8;googletest" -P cmake/FafDependencies.cmake
cmake -S tests/particles/upload_host -B build/particle-upload-host
cmake --build build/particle-upload-host --parallel 2
ctest --test-dir build/particle-upload-host -L ParticlesHost --output-on-failure
```

`FAF_GTEST_DIR` can select an existing official GoogleTest 1.15.2 source tree.
`FAF_GTEST_LIBRARY_DIR` optionally selects matching prebuilt `libgtest.a` and
`libgtest_main.a` archives, avoiding a duplicate framework build. Omit it to build
GoogleTest normally. No dependency is downloaded by this standalone target.

For the Linux GCC/Clang sanitizer configuration:

```sh
cmake -S tests/particles/upload_host -B build/particle-upload-sanitize -DFAF_PARTICLE_SANITIZE=ON
cmake --build build/particle-upload-sanitize --parallel 2
ctest --test-dir build/particle-upload-sanitize -L ParticlesHost --output-on-failure
```

CTest runs the correctness suite four times, with `ren_ParticleLinearUpload`
and `ren_ParticleBatch` both off/on. The mirror-failure test deliberately enables
batching even in the batch-off pass. A separate executable, `particle_upload_allocation`, injects allocation failures
with linear upload off/on; the final Python comparison requires their selected
serialized boundary states to agree. Run the whole label, not only the comparison,
so it consumes freshly generated records. Each allocation run truncates its
relative-filename manifest and lists only successfully written current-run states;
the comparison rejects missing, duplicate or invalid entries and ignores stale
files outside those manifests. Allocation scenarios include both
batching settings. Ordinary correctness/timing runs do not include the global
allocation overrides. CTest uses `ASAN_OPTIONS=detect_leaks=0`; this is not an LSan pass.

The host tests have been run on Linux x64 with GCC 14.2. The standalone target is
not a Windows/x86 engine build or a replacement for the repository's target CI.

## What is checked

- Full uploaded 92-byte records and interval order, with existing tails of
  0/1/199/200 and pending counts around the 200-particle boundary through 4,000.
- Reference relocation counts through 40,000 pending particles: the off path
  retains the repeated-prefix-erase count; the on path is bounded linearly.
- Pool exhaustion, null buffers/locks, direct one-batch wrapper calls, exceptions
  at Lock/Unlock/mirror and a partial second-batch interval append.
- Counted-reference release before graphics boundaries, unique tags, different
  last-reference textures, and adapter destruction at each Unlock.
- A controlled append at the first Unlock, the deliberately different transient
  pending-vector observations, and callback switch changes in either direction.
  A mode change affects the next call, including after an exception.
- Every ordinary allocation failure observed in five selected 401-particle
  scenarios: fresh/tail work items, one-descriptor exhaustion and batching on/off.
  On the tested x64 host these are 169 failpoints plus five successful traces.

The allocation comparison covers returned/thrown status, allocation request
sizes, selected pending fields/order/owned-resource identities, pool identities,
work-item indices/intervals, upload bytes, mirror maps/relevant bytes, copies and
remaining tracked allocation sizes. It is not bytewise equivalence of every
object, every particle field, all capacities or every platform/driver state.
The fixture intercepts ordinary C++ new/new[], not aligned allocation, arbitrary
malloc/realloc, custom new-handlers or native graphics allocations.

The existing failure of active-work-item vector growth leaves an unlinked
work item at 11 tested failpoints in both modes. Each tracked block is 48 bytes
in this x64 host adapter, not a claimed production size for every architecture. The fixture records
these allocations after normal owner cleanup, then frees the raw test-process
storage to keep repeated tests bounded. This optimization does not fix that leak.

## Binding and adapter boundary

`bind_production.py` and `bind_payload.py` extract named definitions directly from
this checkout and fail if they cannot find exactly one definition. Generated
`.inc` files and SHA256 manifests go into the build directory. Source identities
and `#line` directives are repository-relative, including the real WildMagic
header closure. Production switch initialization is bound as well.

The only deliberate body instrumentation is a throwing hook immediately before
`AppendInterval` pushes its interval. All other selected bodies are unmodified.
The payload, `fa::vector`, `fa::string`, `CountedPtr` and patched WildMagic vector
are real source definitions. Graphics buffers/copies/draws are synchronous byte
recorders; texture lifetime calls, work-item/world/bucket storage and device state use
adapters. They do not establish real backend destruction, GPU correctness,
Windows ABI/layout acceptance or in-game behavior.

The whole-particle nothrow-move trait is false for the real WildMagic vector and
is checked as false here with layout-assert suppression removed. Production uses
an `enable_if_t` requirement for the owned members/destructor and exact vector
member types. Vector3's copy assignment must also retain its audited
three-scalar-assignment body; the whole-particle trait must not be substituted.

## Contract and native checks still needed

`ren_ParticleLinearUpload` defaults to 0. Positive values enable the linear
path; zero and negative values retain per-batch prefix erase. Use `/con ren_ParticleLinearUpload=1`
at startup or set `ren_ParticleLinearUpload 1` in the console to opt in. The mode
is captured at the start of each Ensure/Upload call. Pool capacities, admission,
payload math, simulation and shared-container implementations are unchanged.

With the switch on, consumed scalar slots can remain in the pending vector with
their owned members cleared until compaction. For a 1,000-particle call the
controlled Unlock observations are sizes 1000/1000/1000/200/0, rather than
800/600/400/200/0 with the switch off. Strict callback-visible equivalence is
therefore not claimed. The append test is one controlled case, not support for
recursive Ensure/Upload, arbitrary synchronous mutation or concurrent access.

Before enabling by default or recommending merge, review this transient-storage
contract and any supported custom backend/logger/allocation callbacks, run the
applicable Windows/x86/x64 builds and CI, and check supported renderers with
batching off/on, single/multiple views, water/refraction and device/resource
lifecycle transitions. Visual fixes, smoke-limit changes and frame-time gains
need actual game evidence. This patch does not raise any particle limit.

## Optional host timing

Use a normal, non-sanitized build, not the sanitizer binary:

```sh
PARTICLE_LINEAR_UPLOAD=0 PARTICLE_BENCHMARK=1 build/particle-upload-host/particle_upload_host --gtest_filter='*BenchmarkWarmUploadMatrix'
PARTICLE_LINEAR_UPLOAD=1 PARTICLE_BENCHMARK=1 build/particle-upload-host/particle_upload_host --gtest_filter='*BenchmarkWarmUploadMatrix'
```

Repeat in reverse order. The opt-in test uses one warm-up plus seven samples for
nine sizes and three pool modes, with batching off. Pending construction is
outside the measured call; work-item/interval allocation is inside. Adapter
resource operations and host scheduling affect the result. This is not a GPU or
game frame-time benchmark, and small-load overhead must be reported alongside
any large-batch improvement.
