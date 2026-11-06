# Terrain splat budget tests

`faf_splat_budget_tests` includes the production SplatBudget, CWldSplat::SplatVertex and FastVectorN. It links `faf_engine`, inherits its headers, compiler configuration and existing forced `platform/LayoutAsserts.h`, and is excluded from the default build like the other small engine regression targets. It does not edit or bypass FastVector assertions. Checks use runtime failure reporting because normal engine builds disable layout static_asserts.

From an already configured Windows checkout:

```
cmake --build --preset clang-x64-release --target faf_splat_budget_tests
ctest --test-dir build/clang-x64-release -R '^splat_budget$' --output-on-failure
```

Repeat with `clang-x86-release` and its build directory. For a new isolated build, configure the corresponding preset first using the README toolchain requirements. No `build.ps1` copy/deploy step is needed. Like other engine-linked tests, normal engine runtime libraries must be available; no game data, terrain renderer or GPU is exercised by this test. The Linux simulation build does not include the Windows engine test targets.

Coverage: both inline capacities; four tiers and invalid integers; original inline behavior; bounded growth preserving every live vertex; same-tier storage reuse; oversized-storage release on downshift; return to original; the actual AllocationBackoff pure state transitions, 32 skipped overflow calls and smaller-success behavior. No replacement global new, allocation-failure injection or modification of engine allocators is used. Allocation faults, collector filters, camera-list order, chunk/pass call sequencing and UI preferences remain covered by separate source-bound host tests, not by this target. Pointer/capacity observations establish retained storage but do not instrument all process allocations or TLS accesses.

This target must be built and run with the native toolchain before claiming native acceptance. Host-compiling the same test with documented dependency substitutes is only a harness/syntax check, not proof of the real Windows includes, ABI, allocator, startup or link. Neither test proves GPU output or frame-time performance.
