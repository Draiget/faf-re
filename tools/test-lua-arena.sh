#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
cxx=${CXX:-g++}
flags=(-std=c++20 -O2 -pthread -I"$root/src")
case "${SANITIZER:-none}" in
  none) ;;
  undefined) flags+=(-O1 -g -fsanitize=undefined -fno-sanitize-recover=all) ;;
  thread) flags+=(-O1 -g -fsanitize=thread) ;;
  *) echo 'SANITIZER must be none, undefined, or thread' >&2; exit 2 ;;
esac
"$cxx" "${flags[@]}" "$root/tests/memory/LuaArenaLargeRunTests.cpp" -o "$build/large-runs"
if [[ ${SANITIZER:-none} == thread ]]; then
  "$build/large-runs" threads
else
  for mode in capacity failed-order host-oom oversized threads; do
    "$build/large-runs" "$mode"
  done
  "$cxx" "${flags[@]}" "$root/tests/memory/LuaArenaPressureTests.cpp" -o "$build/pressure"
  "$build/pressure"
fi
