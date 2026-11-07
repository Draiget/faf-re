# Lua arena host regression tests

Run the repository's `tools/test-lua-arena.sh` wrapper. It uses CMake, GoogleTest 1.15.2, gtest_main and CTest. Set SANITIZER=address, SANITIZER=undefined or SANITIZER=thread for instrumented host runs; use a separate BUILD_DIR per configuration. Under clang's ThreadSanitizer the reuse test leaves operator new to the sanitizer runtime, so its FullCapacity case there does not check that the arena runs without host allocations. Pass -DFETCHCONTENT_SOURCE_DIR_GOOGLETEST=/path/to/googletest to use an offline source tree.

CTest is the supported suite entry point. Every case is a separate process because the actual included LuaArena.cpp owns process-global reservation state and thread-local caches. Running a multi-case executable with no filter is deliberately rejected in SetUp before allocator state is touched. For a single case, use --gtest_filter=Suite.Case. Do not use --gtest_repeat greater than 1.

These tests compile the actual allocator on x64 without faf_engine, so they reserve and commit through VirtualAlloc on Windows and mmap on Linux. They do not validate full-engine builds, retail game data, or replay parity. In the engine build they are Windows x64 targets; the Linux engine build skips `tests/`. Capacity-restricted tests leave OS reservation size unchanged. Fault-injection scopes make no GoogleTest calls while operator new is disabled and restore the flag through RAII before assertions.

The wrapper defaults to BUILD_CONFIG=Release. Set BUILD_CONFIG to choose another configuration; it passes the same value to CMAKE_BUILD_TYPE, cmake --build --config and ctest -C, including multi-configuration generators such as Visual Studio. For example:

```sh
BUILD_CONFIG=Release bash tools/test-lua-arena.sh -DFETCHCONTENT_SOURCE_DIR_GOOGLETEST=/path/to/googletest
```

Equivalent manual build/test commands after configuring are `cmake --build <build-dir> --config Release --target faf_lua_arena_large_run_tests faf_lua_arena_pressure_tests faf_lua_arena_reuse_tests` and `ctest --test-dir <build-dir> -C Release --output-on-failure -L LuaArenaHost`.
