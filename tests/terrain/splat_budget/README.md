# Terrain splat budget tests

`faf_splat_budget_tests` includes the production `SplatBudget.h`,
`CWldSplat::SplatVertex` and `FastVectorN`. It links `faf_engine` and `gtest_main`,
inherits the engine's headers, compiler configuration and existing forced
`platform/LayoutAsserts.h`, and does not replace its allocator or bypass its
container assertions. The target is excluded from the default build and registered with CTest's
`Terrain` label. Build it explicitly as shown below.

From a configured Windows checkout:

```powershell
cmake --build --preset clang-x64-release --target faf_splat_budget_tests
ctest --test-dir build/clang-x64-release -R '^splat_budget$' --output-on-failure
```

Repeat with `clang-x86-release` and its build directory. For a new build,
configure the corresponding preset using the README toolchain requirements.
No `build.ps1` copy/deploy step is needed. Normal engine runtime libraries must
be available, but the tests do not need game data or a GPU. The Linux simulation
build does not include the Windows engine test targets.

Coverage:

- The 10000-vertex storage used by high/medium fidelity and the 1000-vertex
  storage used by low fidelity, all four tiers and invalid integers.
- Original inline limits, bounded geometric growth preserving every live
  vertex, same-tier reuse, downshifts, and return to inline storage.
- Atlas-restart storage contract at each growth boundary: clearing removes
  stale UVs while retaining capacity and the original view's budget; rebuilding
  to the cap never writes beyond the reserved storage.
- Sparse output, as when atlas skips consume candidate positions without
  appending vertices.
- The real growth function's 32-call backoff path after restart, recovery with
  the live prefix intact, smaller-fidelity success retaining a larger failure,
  default/invalid views leaving backoff untouched, and thread-local isolation.
- A view's budget snapshot remaining fixed until the next prepare call.

These are native budget/container tests, not end-to-end terrain collector or
atlas tests. Restart and sparse-output scenarios call the production budget
helpers and container operations that collectors use; they do not call
`UpdateRenderContext`, `OnAtlasResult`, or the GPU draw helper. Failure-state
coverage seeds `AllocationBackoff::Failed`; it does not inject `bad_alloc` into
the native engine allocator. Collector ordering, atlas reset/skip decisions,
chunk/pass sequencing, and actual allocation-failure handling need separate
integration checks. Pointer/capacity observations do not instrument every
process allocation.

Build and run this target on Windows before claiming native acceptance.
Host-compiling it with dependency substitutes checks only the test logic and
budget/container behavior, not the real Windows includes, ABI, startup or link.
No result here proves GPU output, visual quality or frame-time performance.
