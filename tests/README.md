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

A replay that needs its own init file (the M28AI ones) is written `id:init`, for example `26943656:init_replay_noaff_m28_v0294.lua`.

`UnitZooRunsEveryUnitAndCall` plays the first replay with the unit zoo, `tests/replay/zoo/lua/simInit.lua`. Its init file mounts that folder at `/zoo` and names it a hook folder, so the engine appends the script to FAF's `/lua/simInit.lua`. The zoo spawns every unit blueprint for the first two armies, wave by wave, and makes them fight. It then drives an AI platoon, building, a factory, an upgrade, a transport, missiles, reclaim, repair, capture and squad orders. Last, it calls every getter of the sim's Lua objects. The zoo changes the game, so the recorded checksums no longer apply. Instead, the sim's checksum at each recorded beat (headless prints it as `Checksum for beat N mismatched: <md5> (sim)`) is compared with `tests/replay/zoo/golden_26930624.txt`. The original game played the same zoo, and its checksums are those of that file up to beat 5050, which covers the waves and the scenarios. It never gets through the getter sweeps (some getters crash or hang it; the script names them), so the later beats are this engine's own. After changing the zoo, regenerate the file: the original game in a window with an init file that adds the same two lines to `init_parity.lua`, then headless.

## Coverage

Line coverage of `src/` by these tests, from an instrumented build (`cmake/FafCoverage.cmake`):
```bash
cmake --preset clang-x64-release-coverage
cmake --build --preset clang-x64-release-coverage --target faf_tests
tools/coverage/report.sh build/clang-x64-release-coverage tmp/coverage
```
`tmp/coverage/folders.txt` lists covered lines per `src/` folder, `summary.txt` per file, and `html/` line by line. Set `LLVM_ROOT` when `llvm-cov` is not on `PATH`.

The renderers, UI and sound run only in the game client, so they count only when the instrumented client (`--target faf_main`) plays a game: run it with `LLVM_PROFILE_FILE=<folder>/%p-%m.profraw` and `/replay <file> /exitattick <tick>` (it quits cleanly there, which writes the counters), then add its counters to the report without running ctest again:
```bash
FAF_COVERAGE_EXTRA_RAW=<folder> FAF_COVERAGE_SKIP_CTEST=1 tools/coverage/report.sh build/clang-x64-release-coverage tmp/coverage
```

The client tour, `tools/coverage/tour`, drives the parts of the client a replay leaves alone. It is a hook folder that the engine appends to FAF's `/lua/ui/game/gamemain.lua`. An init file next to the client turns it on:
```lua
dofile(InitFileDir .. '/init_parity.lua')
table.insert(path, { dir = '<repository>/tools/coverage/tour', mountpoint = '/covtour' })
table.insert(hook, '/covtour')
```
With it, a replay played by the client selects the first army's units and calls the getters of the user-side objects. It also moves the camera, builds one of each UI control, calls every global getter and runs the console commands. With `/tourvars` on the command line, it instead sets every console variable to 1, then to 0, and leaves each at a working value. Both runs take about as long as the replay.

`/tourlive` is for a live game: `tools/scenarios/1p-coverage-live.yaml` starts one through mpemu, on the `faf_re_lockstep` test map, whose script drives the army. The tour waits 90 seconds, then issues every kind of order through the user-side command functions and enters command mode for each kind of order in turn. Then it runs the replay tour and quits the game (`/tourexit`). The game writes its counters when it quits. Its init file, `init_tour_live.lua` in `C:\ProgramData\FAForever\bin`, is the one above with `init_mpemu_localvault.lua` in place of `init_parity.lua`. `tools/coverage/tour/drive.ps1`, started beside it, posts mouse messages to the game window: moves, clicks, right-clicks, box drags and wheel turns. Those reach the world view's command code, which a script alone can't. The driver never moves the real cursor or takes the foreground. The command-queue display needs a real Shift key on the foreground window, so the tour doesn't reach it. For a multiplayer game, `/tourquitafter <seconds>` quits that long after the session starts, and `/tournone` leaves the tour out. `tools/scenarios/2p-coverage-rejoin.yaml` uses them for a 1v1 in which player 2 is killed and rejoins. The terrain is built at its detail level when the map loads, so the low and medium terrain code needs a run that starts at that level. `/con` doesn't do it, because the `fidelity` option in the profile wins. Use a copy of `Game.prefs` with `fidelity = 0` (or `1`), passed with `/prefs <copy>.prefs`; the log then says `creating low fidelity terrain`. Give each run's counter files a name of their own before merging them: they are named after process ids, which repeat across runs. Console commands that quit, crash on purpose, pause the sim, reset the device, open a modal window or write `Game.prefs` are left out. So are a few calls that crash the original game the same way; the script names them with their addresses.

Run a specific test executable with GTest filter:
```powershell
.\build\clang-x64-release\tests\faf_net_tests.exe --gtest_filter=Existing_NetRobustness.*
```
