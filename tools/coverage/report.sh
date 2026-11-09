#!/bin/bash
# Line coverage of src/ by the GoogleTest suites, from a FAF_COVERAGE build (cmake/FafCoverage.cmake).
#
#   cmake --preset clang-x64-release-coverage            (Linux: linux-clang-x64-release-coverage)
#   cmake --build --preset clang-x64-release-coverage --target faf_tests
#   tools/coverage/report.sh build/clang-x64-release-coverage [out folder] [ctest arguments...]
#
# Runs ctest with the counters on, merges them, and writes to the out folder (default
# tmp/coverage): summary.txt (llvm-cov's per-file table), folders.txt (per src/ folder),
# coverage.json (llvm-cov export, summary only) and html/ (line by line).
# LLVM_ROOT names the LLVM folder when llvm-profdata and llvm-cov aren't on PATH.
#
# Counters from runs ctest doesn't make (the game client watching a replay, say: tests/README.md) come in
# through FAF_COVERAGE_EXTRA_RAW, a folder of .profraw files merged with ctest's; the game client (main*.exe) then
# counts as an object too. FAF_COVERAGE_SKIP_CTEST=1 keeps the counters of the out folder's last run instead of
# running ctest again.
set -u
BUILD=${1:?usage: report.sh <build folder> [out folder] [ctest arguments...]}
OUT=${2:-tmp/coverage}
shift $(( $# >= 2 ? 2 : 1 ))
HERE=$(cd "$(dirname "$0")" && pwd)

tool() {
  for name in "$1" "$1-18" "$1.exe"; do
    if [ -n "${LLVM_ROOT:-}" ] && [ -x "$LLVM_ROOT/bin/$name" ]; then echo "$LLVM_ROOT/bin/$name"; return; fi
    if command -v "$name" > /dev/null 2>&1; then command -v "$name"; return; fi
  done
  echo "report.sh: $1 not found; set LLVM_ROOT" >&2
  exit 2
}
PROFDATA=$(tool llvm-profdata)
COV=$(tool llvm-cov)
PYTHON=$(command -v python3 || command -v python)

mkdir -p "$OUT/raw"
OUT=$(cd "$OUT" && pwd)
CTEST_RC=0
if [ "${FAF_COVERAGE_SKIP_CTEST:-0}" = 1 ]; then
  echo "report.sh: ctest not run; the counters of the last run in $OUT/raw"
else
  # A fresh run: the counters of an earlier one would add up with these.
  find "$OUT/raw" -name '*.profraw' -delete

  # %p: one file per process, as ctest runs one process per test; %m: per instrumented binary.
  LLVM_PROFILE_FILE="$OUT/raw/%p-%m.profraw" ctest --test-dir "$BUILD" --output-on-failure "$@" > "$OUT/ctest.log" 2>&1
  CTEST_RC=$?
  tail -3 "$OUT/ctest.log"
fi

RAW=$(find "$OUT/raw" -name '*.profraw' | wc -l)
[ "$RAW" -gt 0 ] || { echo "report.sh: no counters written; is $BUILD a FAF_COVERAGE build?"; exit 3; }
PROFILES=("$OUT"/raw/*.profraw)
EXTRA=0
if [ -n "${FAF_COVERAGE_EXTRA_RAW:-}" ]; then
  for file in "$FAF_COVERAGE_EXTRA_RAW"/*.profraw; do
    [ -f "$file" ] && PROFILES+=("$file") && EXTRA=$((EXTRA + 1))
  done
  echo "report.sh: $EXTRA counter files from $FAF_COVERAGE_EXTRA_RAW"
fi
"$PROFDATA" merge -sparse "${PROFILES[@]}" -o "$OUT/merged.profdata" || exit 3

# Every test executable ctest ran, as llvm-cov's objects.
OBJECTS=()
while IFS= read -r exe; do
  exe=${exe%$'\r'}  # a Windows python ends its lines with CR LF
  OBJECTS+=(-object "$exe")
done < <("$PYTHON" "$HERE/test_executables.py" "$BUILD")
[ "${#OBJECTS[@]}" -gt 0 ] || { echo "report.sh: ctest lists no executables"; exit 3; }
# The replay test runs headless as a child process, which writes counters of its own.
for exe in "$BUILD"/src/headless*.exe "$BUILD/headless"; do
  [ -f "$exe" ] && OBJECTS+=(-object "$exe")
done
# The game client, when counters of its runs came in.
if [ "$EXTRA" -gt 0 ]; then
  for exe in "$BUILD"/src/main*.exe; do
    [ -f "$exe" ] && OBJECTS+=(-object "$exe")
  done
fi

# Only the engine's own code: no dependencies, tests or generated files.
IGNORE='([\\/](dependencies|tests|build|_deps|tools)[\\/])|([\\/]gtest[\\/])|([\\/]deps-[^\\/]+[\\/])'
"$COV" report -instr-profile "$OUT/merged.profdata" "${OBJECTS[@]}" -ignore-filename-regex="$IGNORE" > "$OUT/summary.txt" || exit 3
"$COV" export -summary-only -instr-profile "$OUT/merged.profdata" "${OBJECTS[@]}" -ignore-filename-regex="$IGNORE" > "$OUT/coverage.json" || exit 3
"$COV" show -format=html -output-dir="$OUT/html" -instr-profile "$OUT/merged.profdata" "${OBJECTS[@]}" -ignore-filename-regex="$IGNORE" > /dev/null || exit 3
# The source root as llvm-cov spells it: a Windows path under Git Bash (pwd -W), else pwd.
ROOT=$(cd "$HERE/../.." && { pwd -W 2> /dev/null || pwd; })
"$PYTHON" "$HERE/folders.py" "$OUT/coverage.json" "$ROOT" > "$OUT/folders.txt" || exit 3

tail -1 "$OUT/summary.txt"
head -25 "$OUT/folders.txt"
echo "RESULT coverage written to $OUT (ctest exit $CTEST_RC, $RAW counter files, $EXTRA extra)"
exit $CTEST_RC
