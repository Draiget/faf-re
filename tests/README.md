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

Build all existing test targets:
```powershell
cmake --build build/clang-x64-release --target existing_tests
```

Run all existing tests via CTest:
```powershell
ctest --test-dir build/clang-x64-release -L Existing --output-on-failure
```

Run a specific test executable with GTest filter:
```powershell
.\build\clang-x64-release\tests\faf_net_tests.exe --gtest_filter=Existing_NetRobustness.*
```
