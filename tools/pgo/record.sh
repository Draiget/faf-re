#!/bin/bash
# Records the profile the Linux server build optimises with (docs/SWITCHES.md, "Profile-guided
# Linux build"): builds an instrumented headless from this tree, plays the replays with the view
# bench so the per-player code runs too, and merges the counts. Every replay must pass.
#
#   tools/pgo/record.sh --init <init_replay.lua> [--out <file.profdata>] [--jobs N] <replay file>...
#
# Needs the pinned toolchain plus llvm-18 and libclang-rt-18-dev. Takes hours on a full game.
set -u
cd "$(dirname "$0")/../.."
OUT=cmake/pgo/headless-linux-x64.profdata
JOBS=4
INIT=
while [ $# -gt 0 ]; do
  case "$1" in
    --init) INIT=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --jobs) JOBS=$2; shift 2 ;;
    *) break ;;
  esac
done
if [ -z "$INIT" ] || [ $# -eq 0 ]; then
  sed -n 2,8p "$0" >&2
  exit 2
fi
export PATH="/usr/lib/llvm-18/bin:$PATH"
PRESET=linux-clang-x64-release-pgogen
BUILD=build/$PRESET
cmake --preset $PRESET > /dev/null || exit 1
cmake --build --preset $PRESET --target headless || exit 1
WORK=$BUILD/pgo-record
rm -rf "$WORK"
mkdir -p "$WORK"
HEADLESS=$(pwd)/$BUILD/headless

play() {
  local replay=$1 name
  name=$(basename "$replay" .scfareplay)
  LLVM_PROFILE_FILE="$(pwd)/$WORK/$name.profraw" "$HEADLESS" --label "$name" --replay "$replay" /init "$INIT" \
    /nobugreport /nosound /log "$WORK/$name.log" --timeout 480 /simworkers 3 --parallel-views \
    --view-bench "$WORK/$name.csv" > "$WORK/$name.out" 2>&1
  local verdict
  verdict=$(grep -a VERDICT "$WORK/$name.out" | tail -n 1)
  echo "$name: $verdict"
  case "$verdict" in
    *"mismatches=0 crash=False"*) ;;
    *) echo "FAILED $name" >> "$WORK/failed" ;;
  esac
}

for replay in "$@"; do
  while [ "$(jobs -r | wc -l)" -ge "$JOBS" ]; do
    wait -n
  done
  play "$replay" &
done
wait
if [ -e "$WORK/failed" ]; then
  cat "$WORK/failed" >&2
  exit 1
fi
mkdir -p "$(dirname "$OUT")"
llvm-profdata merge -o "$OUT" "$WORK"/*.profraw || exit 1
ls -l "$OUT"
