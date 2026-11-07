#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
build=${BUILD_DIR:-"$root/build/lua-arena-host"}
config=${BUILD_CONFIG:-Release}
cmake -S "$root/tests/memory/lua_arena" -B "$build" \
  -DCMAKE_BUILD_TYPE="$config" -DFAF_LUA_ARENA_SANITIZER="${SANITIZER:-none}" "$@"
cmake --build "$build" --config "$config" --parallel --target faf_lua_arena_large_run_tests faf_lua_arena_pressure_tests faf_lua_arena_reuse_tests
ctest --test-dir "$build" -C "$config" --output-on-failure -L LuaArenaHost
