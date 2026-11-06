# Splat source-bound host regressions

These are small host tests of the **live checkout**, not a standalone renderer,
retail-layout build, full engine link, GPU test, or game-performance benchmark.
No baseline checkout or historical test harness is required for normal acceptance.
Python 3.9+, a GCC/Clang-compatible C++20 compiler, and an existing GoogleTest
source checkout are required (validated with the upstream-pinned 1.15.2). There
are no Python packages, automatic downloads, generated checked-in files, or
workflow changes. The C++ fixtures use GoogleTest assertions, named test cases,
and the upstream `gtest_main`; they do not supply a custom test entry point.

From a complete faf-re checkout, set `GTEST_ROOT` to the existing GoogleTest
subdirectory containing `include/gtest/gtest.h` and `src/gtest-all.cc`:

```sh
python3 tests/terrain/splat/run.py --source . --gtest-root "$GTEST_ROOT"
python3 tests/terrain/splat/run.py --source . --gtest-root "$GTEST_ROOT" --cxx g++ --sanitize
python3 tests/terrain/splat/run.py --source . --gtest-root "$GTEST_ROOT" --negative
```

`--sanitize` enables ASan and UBSan, with no UB recovery. Leak checking is
explicitly disabled because this isolated test replaces global new/delete to
inject deterministic allocation failures. Test expressions are evaluated with
tracking unchanged; a scoped pause then keeps GoogleTest assertion reporting
out of allocation counts and injected failures. Each collection test resets the
injection state. Do not reuse that allocator in a
full engine-linked test. Only the host compiler command is supported; these
scripts are not an MSVC/native-build alternative.

Optional source and compatibility inputs:

```sh
# Compile the existing WildMagic copy/assignment bodies instead of math mocks.
python3 tests/terrain/splat/run.py --source . --gtest-root "$GTEST_ROOT" --wildmagic /path/to/WildMagic

# Additional original-default and small-draw equivalence, not the main oracle.
python3 tests/terrain/splat/run.py --source . --gtest-root "$GTEST_ROOT" --baseline /path/to/original/faf-re

# FAF dialect: production Lua bytes are unchanged.
python3 tests/terrain/splat/run.py --source . --gtest-root "$GTEST_ROOT" \
  --faf-root /path/to/FAF --lua /path/to/faf-lua

# Explicit stock-Lua compatibility adapter (tested with texlua/Lua 5.3).
python3 tests/terrain/splat/run.py --source . --gtest-root "$GTEST_ROOT" --only ui \
  --faf-root /path/to/FAF --lua texlua --lua-dialect stock
```

`--only collection`, `--only draw`, and `--only ui` select individual gates.
`--source-root`, `--baseline-root`, and `--wildmagic-root` are aliases.
UI is **not run** unless both `--faf-root` and `--lua` are supplied. Missing
requested inputs, changed extraction shapes, failed compiles, and failed
assertions are errors, never skipped-success results. All generated headers,
Lua fragments, executables, and mutated sources live only in an automatically
removed temporary directory. SHA-256 source/fixture manifests are printed to
stdout before compilation/execution; redirect stdout if a local record is wanted.

## What is tested

- High/medium/low collectors: 232 tier/count combinations per lane, covering all
  four tiers, invalid values and both sides of every budget boundary. Independent
  expectations are 2,499/249 at default, then 10,000/1,000, 25,000/2,500 and
  50,000/5,000 (high+medium/low). Tests check original order, vertex IDs, UVs,
  explicit near/far alpha cases, transparency, and texture/update call counts.
- At default/invalid tiers, 100,000 visible candidates cause zero additional
  tracked allocations and leave a seeded allocation-backoff TLS state unchanged.
  This is **not** a claim that the complete frame has no allocation or TLS read.
  Downshifting may free previously enlarged output storage.
- Filtering precedes growth: completely filtered and sparse eligible sets do not
  reserve, including low-fidelity exclusion. Capacity/peak bytes are bounded;
  retained frames reuse storage; tier downshifts release oversized storage.
- Every one of the five geometric growth attempts can fail. Accepted prefixes
  survive, only one failed attempt occurs in a view, 32 overflow attempts are
  skipped, and later recovery works. Smaller successes preserve larger failures;
  decreasing failure thresholds, per-view snapshots and thread isolation pass.
- Three actual terrain draw bodies plus production `DrawTriangleList` and
  `SelectTechnique`: zero through three passes and 15 sizes per lane. Independent
  expected event sequences include text flush before sheet binding, atlas and
  technique order, pass-major geometry, and full 28-byte vertex attributes. Sheet
  capacities stay 250/2,500. Sequential views cannot replay stale vertices.
- Null lock, malformed geometry and all reachable helper GAL exception sites are
  covered. A failing stage is fatal without retrying a partially submitted batch.
- Optional UI: five current Lua sources parse, hooks and preferences execute,
  capability loss/old engines hide the option, duplicate hook loading is safe,
  all four tiers and invalid values are checked, and actual extracted dialog
  Apply/Reset/Cancel callbacks run against widget mocks. Runtime SHA is recorded.
- Seven opt-in negative controls restore each lane's old cap, alter the default
  off-by-one, remove OOM backoff, erase a large failure after smaller success,
  and omit multipass reupload. **Each must compile successfully and then fail a
  GoogleTest assertion** (exit code 1 with failure diagnostics). A parser/compile
  failure, signal termination, or unrelated exception is not a detected mutation.

## Explicit host adaptations and limits

`source_extract.py` checks exactly one qualified function, one visible-list
anchor, one counter and one loop for each collector. Braces are balanced with
comments/ordinary strings masked. Unexpected raw-string syntax, duplicate
anchors and changed shapes fail closed. The preparation statement and collector
body are compiled unedited. Camera/spatial database lookup and outer frame,
minimap and rendering-enable gates are not executed. Camera row storage, visible
input lists and texture/vertex-update effects are explicit mocks.

The current `FastVector.h` implementation is compiled with exactly **five** known
retail-x86 `sizeof` assertions omitted. Other container assertions are retained.
No production file is changed. `CWldSplat`'s exact `SplatVertex` and four-vertex
array declarations, and four inherited cutoff/fidelity/alpha fields from
`CWldTerrainDecal.h`, are extracted. Their surrounding classes are mocked; the
vertex's 28-byte size and UV/alpha offsets are asserted. This does not validate
retail class ABI, object ownership, native includes or linking.

Two WildMagic storage shells expose the existing named float lanes. Without
`--wildmagic` their explicit nontrivial copy/assignment operations are mocks;
with it the actual Vector2/Vector3 copy constructor and assignment bodies and
storage declarations are read from `Foundation/Math` and hashed. Neither mode
compiles the full math library or claims native type/layout acceptance.

The helper's exact ordered list of **12** quoted includes is checked; **11** GAL,
render or text headers are redirected to recording interfaces, while the splat
header uses the extracted layout. `DrawTriangleList` and `SelectTechnique` bodies
are extracted unchanged from `src/moho/render/d3d/CD3DDevice.cpp`. The effect,
streams, device and text flush implementation remain mocks; text flush is an
ordered event, not a simulated text render. These tests cannot establish backend
resource transitions, buffer lifetimes across real drivers, culling or image
correctness. The optional Lua-only gate does not require `--gtest-root`. Native CTest/build
and actual game/renderer acceptance remain
separate gates.

UI stock mode performs only documented exact-count replacements in the Python
map. FAF mode performs no production-source rewriting. Dialog handlers are
extracted between unique ordered anchors. Both modes mock imports, preferences,
engine console and widgets: standalone FAF Lua compatibility is not the embedded
game runtime or a complete options-dialog/VFS test.

## Maintaining the tests

Change the explicit adapters only after reviewing upstream changes. Keep expected
limits, events and source-alpha cases independent of the production helpers.
Do not weaken extraction checks to let unexplained drift pass. Fixtures contain
mock interfaces and independent tests, not frozen production implementations;
all budget/collection/draw/container/device bodies are reread each run. Optional
baseline comparisons use the current device/mocks on both sides and supplement,
never replace, the independent expected behavior.
