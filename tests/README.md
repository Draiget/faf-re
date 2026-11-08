# Engine Tests

This directory contains unit and integration test executables for engine subsystems, networking, codecs, and simulation arithmetic.

## Test Guidelines

### Always Use GoogleTest (GTest)

All new and existing tests must use **GoogleTest**. Do not write self-made test harnesses, hand-rolled failure counters (`gFailures`), custom assertion macros, or ad-hoc `main()` test loops.

**Why GTest over custom suites:**
- **Standardized Reporting & Diagnostics:** Failure messages show actual vs. expected values with file and line numbers automatically.
- **Granular Test Filtering:** Filter tests easily via `--gtest_filter=SuiteName.TestName`.
- **Fixture Lifecycle:** Set up and tear down test states cleanly with `TEST_F` without manual cleanup logic leaking across test cases.
- **Tooling & CI Integration:** Produces standard exit codes and supports XML/JSON test result exports (`--gtest_output=xml:...`) for automated CI pipelines.

### Test Authoring Conventions

1. **Test Macros:** Use `TEST(SuiteName, TestName)` or `TEST_F(FixtureClass, TestName)`.
2. **Assertions:**
   - Use non-fatal `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `EXPECT_NE`, `EXPECT_LT`, etc. when subsequent checks in the test case are still safe to execute.
   - Use fatal `ASSERT_TRUE`, `ASSERT_NE`, `ASSERT_FALSE`, etc. when subsequent statements depend on the check (such as pointer validity or resource acquisition).
3. **Entry Points:**
   - Prefer linking against `gtest_main` so you do not need to write a `main()` function.
   - If the executable accepts command-line arguments (e.g. `--host`, `--bind`, `--generate`, or font file paths), link against `gtest`, initialize GoogleTest in `main()` via `::testing::InitGoogleTest(&argc, argv)`, parse custom options, and return `RUN_ALL_TESTS()`.

### CMake & CTest Registration

In `tests/CMakeLists.txt`:
```cmake
add_executable(faf_my_tests EXCLUDE_FROM_ALL my_subsystem/MyTests.cpp)
target_link_libraries(faf_my_tests PRIVATE faf_engine gtest_main)
set_target_properties(faf_my_tests PROPERTIES FOLDER "Tests")
add_test(NAME my_subsystem_test COMMAND faf_my_tests)
set_tests_properties(my_subsystem_test PROPERTIES LABELS "MySubsystem")
```

### Existing Test Group

Existing test suites that were converted from legacy custom runners are grouped together across several layers:
- **Suite Prefix:** Suite names begin with `Existing_` (e.g. `Existing_ProfilerFacade`, `Existing_NetRobustness`, `Existing_SimMath`).
- **CMake Folder:** Set to `FOLDER "Tests/Existing"`.
- **CTest Label:** Tagged with `LABELS "Existing"`.
- **Custom Build Target:** `existing_tests` builds all existing test targets.

## Running Tests

Build every test (`faf_tests` collects each executable that links gtest, see `cmake/FafTests.cmake`) and run them all:
```powershell
cmake --build build/clang-x64-release --target faf_tests
ctest --test-dir build/clang-x64-release --output-on-failure
```

Only the existing group:
```powershell
cmake --build build/clang-x64-release --target existing_tests
ctest --test-dir build/clang-x64-release -L Existing --output-on-failure
```

`tests/particles/upload_host` is a CMake project of its own (GoogleTest, configured without the engine; its README says how), so `faf_tests` and the engine's ctest don't include them. Programs that need data or a server are not run by ctest: `faf_terrain_check --maps <list> /init <init.lua>` (its test is skipped without `--maps`), and the tools `faf_registration_dump`, `faf_juice_gather` and `faf_datachannel_test`, which print rather than pass or fail.

### Recorded games

`replay_playback` (`tests/replay/ReplayPlaybackTests.cpp`) plays recorded games through headless and fails on any checksum mismatch, crash, or a playback that stops before the game-over beat. It needs the game data and is skipped without it:

```bash
FAF_REPLAY_DATA=<folder with replays/ and faf/bin/> FAF_REPLAY_INIT=init_replay.lua FAF_REPLAY_IDS=26930624,26902315 ctest -R replay_playback
```

## Coverage

Line coverage of `src/` by these tests, from an instrumented build (`cmake/FafCoverage.cmake`):
```bash
cmake --preset clang-x64-release-coverage
cmake --build --preset clang-x64-release-coverage --target faf_tests
tools/coverage/report.sh build/clang-x64-release-coverage tmp/coverage
```
`tmp/coverage/folders.txt` lists covered lines per `src/` folder, `summary.txt` per file, and `html/` line by line. Set `LLVM_ROOT` when `llvm-cov` is not on `PATH`.

Run a specific test executable with GTest filter:
```powershell
.\build\clang-x64-release\tests\faf_net_tests.exe --gtest_filter=Existing_NetRobustness.*
```
