# FAF Boost 1.34.1 patch

Baseline: **upstream** `boost_1_34_1.tar.bz2`, SHA256
`0f866c75b025a4f1340117a106595cc0675f48ba1e5a9b5c221ec7f19e96ec4c`
(SourceForge). Pinned in [`docker/deps.lock.json`](../../docker/deps.lock.json).

`boost_1_34_1_faf_required.patch` carries every FAF modification on top of that
release: twelve files, twenty-one hunks.

## There is no bjam step

`main.vcxproj` links **no** boost library and defines `BOOST_ALL_NO_LIB`. What
it does instead is compile twelve `libs/thread/src/*.cpp` files directly, as
`ClCompile` entries:

```
barrier.cpp  condition.cpp  exceptions.cpp  mutex.cpp  once.cpp  recursive_mutex.cpp
thread.cpp   tss.cpp        tss_dll.cpp     tss_hooks.cpp  tss_pe.cpp  xtime.cpp
```

Everything else boost provides here is header-only. So resolving this
dependency is extract-and-patch; nothing is staged, and
`scripts/bootstrap_boost_1_34_1_required.ps1` — which builds
`libboost_thread` / `libboost_filesystem` with bjam — is dead code for the
current build.

Because those twelve `.cpp` files compile straight into `main.exe`, a change to
any of them is a change to the engine, not to a support library.

## Patch scope

**Modern-toolchain fixes** — without these the build fails or misbehaves:

| File | Change |
|---|---|
| `libs/thread/src/once.cpp` | `compare_exchange` calls `::InterlockedCompareExchange` directly; the original `ice_wrapper` indirection does not compile on modern MSVC |
| `libs/thread/src/timeconv.inl` | `#undef TIME_UTC` — C11 defines it as a macro, colliding with boost's enumerator |
| `boost/thread/xtime.hpp` | `push_macro`/`undef` guard around the same `TIME_UTC` collision |
| `boost/thread/mutex.hpp` | modern-MSVC compatibility |
| `boost/thread/recursive_mutex.hpp` | modern-MSVC compatibility |
| `boost/function/function_base.hpp` | modern-MSVC compatibility |
| `boost/function/function_template.hpp` | modern-MSVC compatibility |
| `boost/get_pointer.hpp` | modern-MSVC compatibility |
| `boost/config/compiler/visualc.hpp` | known-version ceiling raised from `1400` (VC8) to `1950`, suppressing the unknown-compiler diagnostic |

**Binary-provenance comments** — no effect on codegen, recording where the
shipped binary implements each function:

| File | Addresses |
|---|---|
| `libs/thread/src/condition.cpp` | `0x00AC2190` `condition_impl::condition_impl` |
| `libs/thread/src/thread.cpp` | `0x00AC32C0` `thread_proxy`, `0x00AC2760` `thread::~thread` |
| `libs/thread/src/xtime.cpp` | `0x00AC5650` `xtime_get` |

The `condition.cpp` note is the load-bearing one to read: that translation
unit's `ClCompile` entry undefines `UNICODE`/`_UNICODE` so `CreateSemaphore` /
`CreateMutex` resolve to the `…A` entry points, matching the disassembly at
`0x00AC2190`. The project-wide Unicode character set would otherwise flip them
to `…W` and diverge from the shipped binary.

## Regenerated 2026-09-23

The previous patch covered six files and applied in neither direction. Seven
further modifications existed in the working tree and were captured nowhere —
including the two load-bearing fixes above.

The regenerated patch was verified by applying it to a fresh extraction of the
upstream tarball: the result matches the working tree with zero functional
differences.

## Applying it

Normally automatic — `docker/scripts/Resolve-Deps.ps1` then
`docker/scripts/Apply-Patches.ps1`. By hand, from a directory that is **not**
inside a git work tree (otherwise `core.autocrlf` interferes):

```bat
cd /d <boost root>
git apply --unsafe-paths <repo>\dependencies\patches\boost_1_34_1_faf_required.patch
```

Check whether it is already applied:

```powershell
.\docker\scripts\Apply-Patches.ps1 -CheckOnly -Only boost_1_34_1
```
