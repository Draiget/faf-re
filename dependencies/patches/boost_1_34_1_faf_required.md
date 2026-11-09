# FAF Boost 1.34.1 patch

Baseline: the upstream `boost_1_34_1.tar.bz2` from SourceForge, SHA256 `0f866c75b025a4f1340117a106595cc0675f48ba1e5a9b5c221ec7f19e96ec4c`. `cmake/FafDependencies.cmake` downloads it, checks the hash, extracts it to `dependencies/boost_1_34_1` and applies this patch (ten files, all code changes).

## There is no bjam step

The engine links no boost library and defines `BOOST_ALL_NO_LIB`. It compiles twelve `libs/thread/src/*.cpp` files straight into `main.exe` (listed in `src/sources.cmake`); everything else boost provides here is header-only. A change to any of those twelve files is therefore a change to the engine.

```
barrier.cpp  condition.cpp  exceptions.cpp  mutex.cpp  once.cpp  recursive_mutex.cpp
thread.cpp   tss.cpp        tss_dll.cpp     tss_hooks.cpp  tss_pe.cpp  xtime.cpp
```

## Patch scope

**Modern-toolchain fixes**: without these the build fails or misbehaves.

| File | Change |
|---|---|
| `libs/thread/src/once.cpp` | `compare_exchange` calls `::InterlockedCompareExchange` directly; the original `ice_wrapper` indirection does not compile on a modern compiler |
| `libs/thread/src/timeconv.inl` | `#undef TIME_UTC`: C11 defines it as a macro, colliding with boost's enumerator |
| `boost/thread/xtime.hpp` | `push_macro`/`undef` guard around the same `TIME_UTC` collision |
| `boost/thread/mutex.hpp`, `recursive_mutex.hpp` | modern-compiler compatibility |
| `boost/function/function_base.hpp`, `function_template.hpp` | modern-compiler compatibility |
| `boost/get_pointer.hpp` | modern-compiler compatibility |
| `boost/config/compiler/visualc.hpp` | known-version ceiling raised from `1400` (VC8) to `1950`, suppressing the unknown-compiler diagnostic |
| `boost/type_traits/intrinsics.hpp` | `BOOST_IS_POD` uses `__is_trivially_constructible(T)` instead of `__has_trivial_constructor(T)`, which clang deprecates (`-Wdeprecated-builtins`); the two agree for every POD type. The other `__has_*` macros in that block are not used by the engine and stay as they are |

Not a patch but related: `src/CMakeLists.txt` compiles `libs/thread/src/condition.cpp` without `UNICODE`/`_UNICODE`, so `CreateSemaphore`/`CreateMutex` resolve to the `…A` entry points the shipped binary uses (0x00AC2190).

Binary-address notes that earlier versions of this patch carried as comments are kept in the recovery archive (`faf-re-archive/dependency-patches-with-provenance/`), not here.

## Applying it by hand

CMake configure does this automatically and records it in the tree's `.faf-patches` stamp. By hand, from inside the extracted tree with `GIT_CEILING_DIRECTORIES` set to its parent:

```bat
git -c core.autocrlf=false apply --unsafe-paths --whitespace=nowarn <repo>\dependencies\patches\boost_1_34_1_faf_required.patch
```

Add `--check --reverse` to test whether it is already applied.
