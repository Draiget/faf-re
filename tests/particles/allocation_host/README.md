# Particle allocation ownership host tests

Standalone GoogleTest/CTest coverage for the pre-upload ownership transaction in
`EnsureAndFillParticleBucketWorkItems`. This fixture uses exact source-extracted
production functions, the real `fa::vector` and `fa::list`, real work-item and
particle declarations, the real counted-pointer/string implementations, and the
repository-patched WildMagic vector. The scripts reject missing/ambiguous source
matches and write hashes beside generated bindings.

Graphics, world setup and texture destruction use synchronous host adapters.
These are not Windows, ABI, driver, GPU, replay or in-game tests. The ordinary
x64 layout-assertion suppression is undone before test-owned assertions; no
claim that the whole particle type is nothrow-movable is made.

## Build and run

Initialize the repository's public GoogleTest and WildMagic dependencies and
apply the documented WildMagic patch first. No installed game data is needed.

```sh
cmake -S tests/particles/allocation_host -B build/particle-allocation-host
cmake --build build/particle-allocation-host
ctest --test-dir build/particle-allocation-host --output-on-failure
```

An existing matching GoogleTest build can be reused with `FAF_GTEST_DIR` and
`FAF_GTEST_LIBRARY_DIR`. GCC/Clang builds support
`-DFAF_PARTICLE_SANITIZE=ON` for AddressSanitizer/UndefinedBehaviorSanitizer.
Allocation interception is confined to the `particle_allocation_faults` binary;
ordinary upload regression checks use `particle_allocation_host`.

CMake does not disable leak detection. In a restricted environment where LSan
itself reports that ptrace prevents it from running, rerun with
`ASAN_OPTIONS=detect_leaks=0` and report only ASan/UBSan coverage. Keep the original
LSan failure separate; the fixture's bounded allocation tracking is not a full
LSan pass or a general engine leak scan.

## Assertions and exception boundaries

- A real allocation failpoint sweeps every allocation reached in five selected
  upload scenarios, both once and persistently through unwinding.
- Assertions traverse actual available-buffer and active-work-item identities,
  verify disjoint ownership and FIFO order, inspect real backing bytes and
  preserve already committed work items. All allocations armed around upload
  must be reclaimed after world/recorder teardown.
- Work-item allocation and active-vector growth failures must leave the exact
  available buffers untouched and no orphan item. No rollback may allocate a
  replacement list node.
- The exact recovered initializer has **zero** internal allocations. A separate
  test arms failure at the first allocation, calls it unchanged, and compares all
  initialized fields/interval state with the new full-object construction. An
  invented initializer-allocation failure would not test production behavior.
- At both allocation windows, a bounded callback borrows either the available
  head or all available buffers. The item must use the actual Acquire result;
  exhaustion must remove the empty active slot and clean its work item.
- Lock, interval-append, Unlock and mirror failures after linking retain the
  linked work item's ownership. Ordinary successful payload bytes, intervals,
  counted-resource release timing, lock failure, pool exhaustion and partial
  tails are covered separately.

`SuccessfulStateSnapshotsPreservePriorBaseline` optionally exports five selected
serialized success boundary states when `PARTICLE_SUCCESS_STATE_DIR` names an
existing directory. That export includes allocator requests, selected pending
and active state, available FIFO identities, selected bytes, mirror slots and
copy traces. It is not a serialization of all engine/driver state.

## Deliberately unchanged limitations

This fix only establishes work-item and borrowed-buffer ownership before upload.
Upload itself is not transactional: an interval allocation failure can leave a
locked buffer and partially changed pending values; mirror allocation failures
have their existing partial state. Recycle can itself allocate. Those adjacent
paths are not repaired here. No claim of complete out-of-memory recovery or an
observed game-crash fix follows from these checks.

Pool-only callbacks during allocation are tested. Concurrent mutation, mutation
of the same vector from inside its own insertion, arbitrary deallocation-hook
reentrancy, and world destruction during the call remain outside the renderer's
existing contract. A callback throwing through an existing `noexcept` deletion
boundary still terminates.

Native Windows x64/x86 compilation, retail-layout checks, linked engine testing,
and rendering/in-game acceptance remain separate gates.
