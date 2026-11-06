#!/usr/bin/env python3
"""Source-bound splat fade regression without a game, renderer, or engine build.

Run: python tests/terrain/test_splat_fade.py --cxx g++
Or:  python tests/terrain/test_splat_fade.py --source PATH --cxx clang++ --sanitize

Requires Python 3 and a GCC/Clang-compatible C++20 compiler. The three production
fade blocks are extracted unchanged, then compiled against a branch-by-branch
translation of the finite-input SSE paths in the original FAF executable:
  high:   0x00800B7E..0x00800C04 (far arm 0x00800BBB)
  medium: 0x00804BAE..0x00804C34 (far arm 0x00804BEB)
  low:    0x00808D56..0x00808DDC (far arm 0x00808D93)
This is a host arithmetic test, not execution of those binary instructions or a
GPU/client integration test. The contract is finite inputs, cutoff > 0,
0 <= fraction < 1, a representable nonzero denominator, 0 <= currentAlpha <= 1,
and the default host rounding/denormal environment. NaN/Inf, overflow, FTZ/DAZ
and alternate rounding modes are outside its contract. Leak checking is not
required; set ASAN_OPTIONS=detect_leaks=0 where LeakSanitizer is unavailable.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile

TIERS = ("Low", "Medium", "High")
PREFIX = r'''
#include <algorithm>
#include <bit>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <limits>

struct Splat { float mCutoffLOD, mNearCutoff, mCurrentAlpha; };
'''
CHECKS = r'''
// The original branch order and subtraction operands, not the candidate's
// min/max expression. xmm0 = distance; xmm1 = cutoff; xmm2 = fade start.
float reference(float distance, Splat s, float fraction) {
  float result;
  if (s.mNearCutoff > 0.0f) {
    float near = s.mNearCutoff;
    const float start = near * fraction;
    if (!(near > distance)) distance = near;
    float numerator = distance;
    if (start > distance) numerator = start;
    numerator -= start;
    near -= start;
    result = numerator / near;
  } else {
    float cutoff = s.mCutoffLOD;
    const float start = cutoff * fraction;
    if (!(cutoff > distance)) distance = cutoff;
    if (start > distance) distance = start;
    cutoff -= start;
    distance -= start;
    distance /= cutoff;
    result = 1.0f - distance;
  }
  return result * s.mCurrentAlpha;
}

using Fade = float (*)(float, Splat, float);
const Fade functions[] = {fade_Low, fade_Medium, fade_High};
const char* names[] = {"Low", "Medium", "High"};
std::uint64_t checks = 0, failures = 0;
void check(bool ok, const char* tier, const char* what, float actual, float expected) {
  ++checks;
  if (!ok) {
    if (failures++ < 12) std::printf("FAIL %s %s: got %.9g expected %.9g\n", tier, what, actual, expected);
  }
}
bool same(float a, float b) {
  return std::bit_cast<std::uint32_t>(a) == std::bit_cast<std::uint32_t>(b);
}
void compare(float distance, Splat s, float fraction) {
  const float expected = reference(distance, s, fraction);
  for (int i = 0; i != 3; ++i) {
    const float actual = functions[i](distance, s, fraction);
    check(same(actual, expected), names[i], "binary-derived finite oracle", actual, expected);
    check(std::isfinite(actual) && actual >= 0.0f && actual <= s.mCurrentAlpha,
          names[i], "bounded baked alpha", actual, s.mCurrentAlpha);
  }
}
int main() {
  // Regression witness: old source produces 2.0 rather than 1.0 here.
  for (int i = 0; i != 3; ++i) {
    check(same(functions[i](0.0f, {100.0f, 0.0f, 1.0f}, 0.5f), 1.0f), names[i], "near-camera far fade", functions[i](0.0f, {100.0f, 0.0f, 1.0f}, 0.5f), 1.0f);
    check(same(functions[i](75.0f, {100.0f, 0.0f, 0.5f}, 0.5f), 0.25f), names[i], "fade ramp and current alpha", functions[i](75.0f, {100.0f, 0.0f, 0.5f}, 0.5f), 0.25f);
  }
  // Endpoints, adjacent floats, negative camera distance, negative/zero near
  // cutoff selecting far fade, positive near cutoff, and current alpha scaling.
  for (float cutoff : {0.001f, 1.0f, 100.0f, 1000000.0f}) {
    for (float fraction : {0.0f, 0.25f, 0.5f, 0.75f, 0.99f}) {
      for (float near : {-1.0f, 0.0f, cutoff * 0.25f, cutoff}) {
        const float limit = near > 0.0f ? near : cutoff;
        const float start = limit * fraction;
        const float distances[] = {-cutoff, 0.0f,
          std::nextafter(start, -std::numeric_limits<float>::infinity()), start,
          std::nextafter(start, std::numeric_limits<float>::infinity()),
          start + (limit - start) * 0.5f,
          std::nextafter(limit, 0.0f), limit, cutoff};
        for (float alpha : {0.0f, 0.125f, 0.5f, 1.0f})
          for (float distance : distances) compare(distance, {cutoff, near, alpha}, fraction);
        // Monotone far fade (decreasing) and near fade (increasing).
        for (int i = 0; i != 3; ++i) {
          float previous = functions[i](0.0f, {cutoff, near, 1.0f}, fraction);
          for (int step = 1; step <= 256; ++step) {
            const float distance = cutoff * (static_cast<float>(step) / 256.0f);
            const float value = functions[i](distance, {cutoff, near, 1.0f}, fraction);
            check(near > 0.0f ? value >= previous : value <= previous,
                  names[i], "monotone fade", value, previous);
            previous = value;
          }
        }
      }
    }
  }
  // Deterministic finite coverage, independent of standard-library RNGs.
  std::uint32_t state = 0x7d619327u;
  const auto unit = [&state]() {
    state = state * 1664525u + 1013904223u;
    return static_cast<float>(state >> 8) / 16777216.0f;
  };
  for (int i = 0; i < 100000; ++i) {
    const float cutoff = 0.01f + unit() * 100000.0f;
    const float fraction = unit() * 0.999f;
    const float distance = cutoff * (unit() * 2.0f - 1.0f);
    const float near = i % 3 == 0 ? 0.0f : (i % 3 == 1 ? -1.0f : cutoff * (0.01f + unit() * 0.99f));
    compare(distance, {cutoff, near, unit()}, fraction);
  }
  std::printf("splat fade: %llu checks, %llu failures (three extracted source blocks)\n",
              static_cast<unsigned long long>(checks), static_cast<unsigned long long>(failures));
  return failures ? 1 : 0;
}
'''


def generate(source):
    functions = []
    for tier in TIERS:
        path = source / "src/moho/terrain" / (tier + "FidelityTerrain.cpp")
        text = path.read_text(encoding="utf-8")
        blocks = re.findall(r"float fadeAlpha;\s*if \(splat->mNearCutoff <= 0\.0f\) \{.*?const float bakedAlpha = fadeAlpha \* splat->mCurrentAlpha;", text, re.S)
        if len(blocks) != 1:
            raise ValueError(f"{path}: expected exactly one source fade block, found {len(blocks)}")
        functions.append(f"float fade_{tier}(float worldDistance, Splat value, float ren_DecalFadeFraction) {{\n  const auto* splat = &value;\n{blocks[0]}\nreturn bakedAlpha;\n}}\n")
    return PREFIX + "\n".join(functions) + CHECKS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--cxx", default=os.environ.get("CXX", "c++"))
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="faf-splat-fade-") as temp:
        source = Path(temp) / "SplatFadeTests.cpp"
        exe = Path(temp) / ("splat_fade.exe" if os.name == "nt" else "splat_fade")
        source.write_text(generate(args.source), encoding="utf-8")
        flags = ["-std=c++20", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-ffp-contract=off"]
        if args.sanitize:
            flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
            if os.name != "nt":
                flags += ["-no-pie"]
        subprocess.run([args.cxx, *flags, str(source), "-o", str(exe)], check=True)
        return subprocess.run([str(exe)], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
