// Engine addition (dedicated-server plan WPL.23): golden tests of the
// simulation's parity-sensitive arithmetic.
//
// Every src/legacy/math/X87Math* helper, and the other places
// docs/RETAIL_REPLAY_PARITY.md ("Where divergences came from") names - the box
// separating-axis radius, vector lengths, the Gaussian's logarithm, sqrt
// under 24-bit precision control, fistp rounding, the pathfinder's edge-cost
// bucket, unsigned cell coordinates, the random stream - run on fixed edge
// cases (+-0, denormals, infinities, NaNs, halfway and near-integer values)
// and on seeded random inputs. Every result is compared bit for bit with
// tests/sim_math/golden.txt, which `--generate` wrote once on Windows x64,
// the build with 75/75 replay parity. The same file must hold on Windows x86,
// Windows x64 and Linux: a sim change that moves one result fails at once.
//
// Usage:
//   faf_sim_math_tests <golden.txt>              check (exit 1 on any difference)
//   faf_sim_math_tests --generate <golden.txt>   write the golden file
//
// The thread runs in the simulation's floating-point environment first: the
// x87 precision field at 24 bits (x86; the x64 helpers set it themselves, as
// the simulation's x64 threads keep the default) and the CRT's SSE2 math lane
// off, as CScApp sets it without /sse2.

#include <bit>
#include <cfloat>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <limits>
#include <map>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#elif defined(__linux__)
#include <unistd.h>
#endif

#include <gtest/gtest.h>

#include "legacy/math/X87Math.h"
#include "moho/ai/NavigatorCellMath.h"
#include "platform/X87Precision.h"

// FAF_SIM_MATH_SUBSET (the Linux build until every faf_sim object links): only
// the cases whose code builds there run, and the check reports the golden
// cases it skipped instead of failing on them.
#if !defined(FAF_SIM_MATH_SUBSET)
#include "gpg/core/algorithms/Cluster.h"
#include "moho/sim/CRandomStream.h"
#endif

namespace
{
  constexpr int kRandomCases = 384;
  constexpr int kRandomCasesWide = 160; // functions with many float arguments

  // ---------------------------------------------------------------- formatting
  std::string Hex(const float value)
  {
    char text[16];
    std::snprintf(text, sizeof(text), "%08X", std::bit_cast<std::uint32_t>(value));
    return text;
  }

  std::string Hex(const double value)
  {
    char text[24];
    std::snprintf(text, sizeof(text), "%016llX", static_cast<unsigned long long>(std::bit_cast<std::uint64_t>(value)));
    return text;
  }

  std::string Hex(const std::int32_t value)
  {
    char text[16];
    std::snprintf(text, sizeof(text), "i%08X", static_cast<std::uint32_t>(value));
    return text;
  }

  std::string Hex(const std::uint32_t value)
  {
    char text[16];
    std::snprintf(text, sizeof(text), "u%08X", value);
    return text;
  }

  template <class... T>
  std::string Join(const T&... values)
  {
    std::string out;
    ((out += (out.empty() ? "" : " ") + Hex(values)), ...);
    return out;
  }

  std::string JoinFloats(const float* const values, const int count)
  {
    std::string out;
    for (int i = 0; i < count; ++i) {
      out += (i ? " " : "") + Hex(values[i]);
    }
    return out;
  }

  // ------------------------------------------------------------------- inputs
  /** splitmix64: a fixed, platform-independent input stream. */
  struct InputStream
  {
    std::uint64_t state;

    explicit InputStream(const std::string& name, const int salt)
      : state(0x9E3779B97F4A7C15ull ^ static_cast<std::uint64_t>(salt))
    {
      for (const char c : name) {
        state = (state ^ static_cast<unsigned char>(c)) * 0x100000001B3ull;
      }
    }

    std::uint64_t Next()
    {
      std::uint64_t z = (state += 0x9E3779B97F4A7C15ull);
      z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
      z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
      return z ^ (z >> 31);
    }

    /** A float: any bit pattern (1/4), in [-1, 1] (1/4), or +-[2^-24, 2^24) (1/2). */
    float Float()
    {
      const std::uint64_t r = Next();
      const std::uint32_t bits = static_cast<std::uint32_t>(r);
      switch ((r >> 32) & 3u) {
      case 0:
        return std::bit_cast<float>(bits);
      case 1: {
        const float unit = static_cast<float>(bits >> 8) * 0x1p-24f;
        return ((r >> 40) & 1u) ? -unit : unit;
      }
      default: {
        const int exponent = static_cast<int>((r >> 34) % 48u) - 24;
        const float mantissa = 1.0f + static_cast<float>(bits >> 9) * 0x1p-23f;
        const float magnitude = std::ldexp(mantissa, exponent);
        return ((r >> 41) & 1u) ? -magnitude : magnitude;
      }
      }
    }

    /** A positive, finite float in [2^-24, 2^24). */
    float Positive()
    {
      const std::uint64_t r = Next();
      const int exponent = static_cast<int>((r >> 34) % 48u) - 24;
      return std::ldexp(1.0f + static_cast<float>(static_cast<std::uint32_t>(r) >> 9) * 0x1p-23f, exponent);
    }

    /** A double: a widened float (3/4) or any bit pattern (1/4). */
    double Double()
    {
      const std::uint64_t r = Next();
      if ((r & 3u) == 0) {
        return std::bit_cast<double>(Next());
      }
      return static_cast<double>(Float());
    }

    std::int32_t Int() { return static_cast<std::int32_t>(Next()); }
    std::int16_t Short() { return static_cast<std::int16_t>(Next()); }
    std::uint8_t Byte() { return static_cast<std::uint8_t>(Next()); }
  };

  const std::vector<float>& EdgeFloats()
  {
    static const std::vector<float> values = [] {
      const std::uint32_t bits[] = {
        0x00000000u, 0x80000000u, // +-0
        0x00000001u, 0x80000001u, 0x007FFFFFu, 0x00400000u, // denormals
        0x00800000u, 0x80800000u, // +-FLT_MIN
        0x7F7FFFFFu, 0xFF7FFFFFu, // +-FLT_MAX
        0x7F800000u, 0xFF800000u, // +-inf
        0x7FC00000u, 0xFFC00000u, 0x7FA00000u, // quiet NaNs, a signalling NaN
        0x3F800000u, 0xBF800000u, 0x3F000000u, 0xBF000000u, // +-1, +-0.5
        0x3FC00000u, 0xC0200000u, 0x40200000u, 0xBFC00000u, // +-1.5, +-2.5 (halfway)
        0x3EFFFFFFu, 0x3F7FFFFFu, 0x3F800001u, 0x4049000Fu, 0x42C90000u, // near 0.5 / 1, 3.1415927, 100.5
        0x40490FDBu, 0x3FC90FDBu, 0x40C90FDBu, // pi, pi/2, 2pi
        0x4B000000u, 0x4AFFFFFFu, 0x4B7FFFFFu, 0x4B800000u, // 2^23, 2^23 - 0.5, 2^24 - 1, 2^24
        0x4EFFFFFFu, 0x4F000000u, 0xCF000000u, 0xCF000001u, 0x4F32D05Eu, // near +-2^31, 3e9
        0x0DA24260u, 0x1E3CE508u, 0x15F79688u, 0x5F0AC723u, 0x5F8AC723u, // 1e-30, 1e-20, 1e-25, 1e19, 2e19
        0x41AB54C2u, 0x3F052EAAu, // pow(x, 2) and asin parity cases
        0x358637BDu, 0x49742400u, 0x3DCCCCCDu, 0xC2C80000u, // 1e-6, 1e6, 0.1, -100
      };
      std::vector<float> out;
      for (const std::uint32_t b : bits) {
        out.push_back(std::bit_cast<float>(b));
      }
      return out;
    }();
    return values;
  }

  // ------------------------------------------------------------------- runner
  struct Results
  {
    std::vector<std::string> order;
    std::map<std::string, std::string> lines; // "name idx" -> "inputs -> outputs"

    void Add(const std::string& name, const int index, const std::string& inputs, const std::string& outputs)
    {
      char key[160];
      std::snprintf(key, sizeof(key), "%s %d", name.c_str(), index);
      order.emplace_back(key);
      lines[key] = inputs + " -> " + outputs;
    }
  };

  using Unary = std::function<std::string(float)>;

  /** One float argument: the edge list, then `randomCount` stream values. */
  void RunUnary(Results& results, const std::string& name, const Unary& fn, const bool positive = false)
  {
    int index = 0;
    for (const float x : EdgeFloats()) {
      results.Add(name, index++, Hex(x), fn(x));
    }
    InputStream in(name, 1);
    for (int i = 0; i < kRandomCases; ++i) {
      const float x = positive ? in.Positive() : in.Float();
      results.Add(name, index++, Hex(x), fn(x));
    }
  }

  /** Several float arguments: every pair from a short edge list, then random. */
  void RunFloats(
    Results& results, const std::string& name, const int arity, const std::function<std::string(const float*)>& fn,
    const int randomCount = kRandomCases
  )
  {
    int index = 0;
    const std::vector<float>& edges = EdgeFloats();
    float args[24];
    // Edge sweep: argument k takes edge value (i + k * 7) mod n.
    for (std::size_t i = 0; i < edges.size(); ++i) {
      for (int k = 0; k < arity; ++k) {
        args[k] = edges[(i + static_cast<std::size_t>(k) * 7u) % edges.size()];
      }
      results.Add(name, index++, JoinFloats(args, arity), fn(args));
    }
    InputStream in(name, arity);
    for (int i = 0; i < randomCount; ++i) {
      for (int k = 0; k < arity; ++k) {
        args[k] = in.Float();
      }
      results.Add(name, index++, JoinFloats(args, arity), fn(args));
    }
  }

  void RunDoubles(
    Results& results, const std::string& name, const int arity, const std::function<std::string(const double*)>& fn
  )
  {
    int index = 0;
    const std::vector<float>& edges = EdgeFloats();
    double args[4];
    auto inputs = [&] {
      std::string out;
      for (int k = 0; k < arity; ++k) {
        out += (k ? " " : "") + Hex(args[k]);
      }
      return out;
    };
    for (std::size_t i = 0; i < edges.size(); ++i) {
      for (int k = 0; k < arity; ++k) {
        args[k] = static_cast<double>(edges[(i + static_cast<std::size_t>(k) * 7u) % edges.size()]);
      }
      results.Add(name, index++, inputs(), fn(args));
    }
    InputStream in(name, 10 + arity);
    for (int i = 0; i < kRandomCases; ++i) {
      for (int k = 0; k < arity; ++k) {
        args[k] = in.Double();
      }
      results.Add(name, index++, inputs(), fn(args));
    }
  }

  // --------------------------------------------------------------- the cases
  void RunAll(Results& r)
  {
    // fistp-style rounding (float-to-cell conversions).
    RunUnary(r, "RoundToInt", [](const float x) { return Hex(fa::RoundToInt(x)); });

    // Twister word scaling (CRandomStream::FRand).
    {
      int index = 0;
      const std::uint32_t words[] = {0u, 1u, 0x7FFFFFFFu, 0x80000000u, 0x80000001u, 0xFFFFFF7Fu, 0xFFFFFF80u, 0xFFFFFFFFu};
      for (const float factor : EdgeFloats()) {
        for (const std::uint32_t word : words) {
          r.Add("MulTwisterWord", index++, Join(factor, word), Hex(fa::MulTwisterWord(factor, word)));
        }
      }
      InputStream in("MulTwisterWord", 2);
      for (int i = 0; i < kRandomCases; ++i) {
        const float factor = in.Float();
        const std::uint32_t word = static_cast<std::uint32_t>(in.Next());
        r.Add("MulTwisterWord", index++, Join(factor, word), Hex(fa::MulTwisterWord(factor, word)));
      }
    }

    // Vector lengths and scales.
    RunFloats(r, "ScaleVectorByMaxLengthX87", 4, [](const float* a) {
      float x = a[0], y = a[1], z = a[2];
      fa::ScaleVectorByMaxLengthX87(x, y, z, a[3]);
      return Join(x, y, z);
    });
    RunFloats(r, "ScaleVectorToLengthX87", 5, [](const float* a) {
      float out[3];
      fa::ScaleVectorToLengthX87(out, a, a[3], a[4]);
      return JoinFloats(out, 3);
    });
    RunFloats(r, "ScaleVectorX87", 4, [](const float* a) {
      float out[3];
      fa::ScaleVectorX87(out, a, a[3]);
      return JoinFloats(out, 3);
    });
    RunFloats(r, "ScaleVectorToLengthOfX87", 7, [](const float* a) {
      float out[3];
      fa::ScaleVectorToLengthOfX87(out, a, a + 3, a[6]);
      return JoinFloats(out, 3);
    });
    RunFloats(r, "VectorLengthZYXX87", 3, [](const float* a) { return Hex(fa::VectorLengthZYXX87(a)); });

    // Box-vs-box separating-axis radius: box = center(3), axes(9), extents(3); then the axis.
    RunFloats(
      r, "BoxRadiusOnAxisX87", 18, [](const float* a) { return Hex(fa::BoxRadiusOnAxisX87(a, a + 15)); },
      kRandomCasesWide
    );

    // MSVC8 CRT fmod/frexp.
    RunDoubles(r, "fmod", 2, [](const double* a) { return Hex(fa::fmod(a[0], a[1])); });
    RunDoubles(r, "frexp", 1, [](const double* a) {
      int exponent = 0x5A5A5A5A;
      const double mantissa = fa::frexp(a[0], &exponent);
      return Join(mantissa, static_cast<std::int32_t>(exponent));
    });

    // Products and half sums under 24-bit precision.
    RunFloats(r, "MultiplyX87", 2, [](const float* a) { return Hex(fa::MultiplyX87(a[0], a[1])); });
    {
      int index = 0;
      InputStream in("MultiplyIntegerX87", 2);
      const std::int32_t ints[] = {0, 1, -1, 2028178766, 0x7FFFFFFF, static_cast<std::int32_t>(0x80000000u), 16777217, -16777217};
      for (const float factor : EdgeFloats()) {
        for (const std::int32_t integer : ints) {
          r.Add("MultiplyIntegerX87", index++, Join(integer, factor), Hex(fa::MultiplyIntegerX87(integer, factor)));
        }
      }
      for (int i = 0; i < kRandomCases; ++i) {
        const std::int32_t integer = in.Int();
        const float factor = in.Float();
        r.Add("MultiplyIntegerX87", index++, Join(integer, factor), Hex(fa::MultiplyIntegerX87(integer, factor)));
      }
    }
    RunFloats(r, "HalfSumX87", 2, [](const float* a) { return Hex(fa::HalfSumX87(a[0], a[1])); });
    RunFloats(r, "HalfAbsDifferenceX87", 2, [](const float* a) { return Hex(fa::HalfAbsDifferenceX87(a[0], a[1])); });

    // Terrain interpolation.
    RunFloats(r, "BilinearHeight", 6, [](const float* a) {
      return Hex(fa::BilinearHeight(a[0], a[1], a[2], a[3], a[4], a[5]));
    });

    // x87 transcendentals.
    RunUnary(r, "sinf", [](const float x) { return Hex(fa::sinf(x)); });
    RunUnary(r, "cosf", [](const float x) { return Hex(fa::cosf(x)); });
    RunUnary(r, "tanf", [](const float x) { return Hex(fa::tanf(x)); });
    RunUnary(r, "atanf", [](const float x) { return Hex(fa::atanf(x)); });
    RunFloats(r, "atan2f", 2, [](const float* a) { return Hex(fa::atan2f(a[0], a[1])); });
    RunFloats(r, "Atan2Difference", 4, [](const float* a) {
      return Hex(fa::Atan2Difference(a[0], a[1], a[2], a[3]));
    });
    RunFloats(r, "Atan2Plus", 3, [](const float* a) { return Hex(fa::Atan2Plus(a[0], a[1], a[2])); });
    RunFloats(r, "SinTimesCos", 2, [](const float* a) { return Hex(fa::SinTimesCos(a[0], a[1])); });
    RunFloats(r, "SinOfProductTimes", 3, [](const float* a) {
      return Hex(fa::SinOfProductTimes(a[0], a[1], a[2]));
    });
    RunFloats(r, "CosTimesCos", 2, [](const float* a) { return Hex(fa::CosTimesCos(a[0], a[1])); });
    RunFloats(
      r, "SlerpSphericalBlend", 11,
      [](const float* a) {
        float out[4];
        fa::SlerpSphericalBlend(out, a, a + 4, a[8], a[9], a[10]);
        return JoinFloats(out, 4);
      },
      kRandomCasesWide
    );

    // /Oi exp and log expansions; the edge-cost logarithm; the Gaussian's (IntrinsicLn).
    RunUnary(r, "IntrinsicExp", [](const float x) { return Hex(fa::IntrinsicExp(x)); });
    RunUnary(r, "IntrinsicLn", [](const float x) { return Hex(fa::IntrinsicLn(x)); });
    RunUnary(r, "IntrinsicLog10", [](const float x) { return Hex(fa::IntrinsicLog10(x)); });
    RunFloats(r, "IntrinsicLnQuotient", 2, [](const float* a) {
      return Hex(fa::IntrinsicLnQuotient(a[0], static_cast<double>(a[1])));
    });
    RunFloats(r, "ScaledLnQuotient", 3, [](const float* a) { return Hex(fa::ScaledLnQuotient(a[0], a[1], a[2])); });

    // CRT-dispatched functions (x87 bodies at the caller's precision; the
    // others through the host CRT, WPL.11).
    RunUnary(r, "asinf", [](const float x) { return Hex(fa::asinf(x)); });
    RunUnary(r, "acosf", [](const float x) { return Hex(fa::acosf(x)); });
    RunDoubles(r, "acos", 1, [](const double* a) { return Hex(fa::acos(a[0])); });
    RunDoubles(r, "asin", 1, [](const double* a) { return Hex(fa::asin(a[0])); });
    RunDoubles(r, "pow", 2, [](const double* a) { return Hex(fa::pow(a[0], a[1])); });
    RunUnary(r, "expf", [](const float x) { return Hex(fa::expf(x)); });
    RunUnary(r, "logf", [](const float x) { return Hex(fa::logf(x)); });
    RunFloats(r, "powf", 2, [](const float* a) { return Hex(fa::powf(a[0], a[1])); });

    // sqrt as sim code calls it: float in and out, and a widened float in double.
    RunUnary(r, "sqrt_float", [](const float x) { return Hex(std::sqrt(x)); });
    RunUnary(r, "sqrt_double", [](const float x) { return Hex(std::sqrt(static_cast<double>(x))); });

#if !defined(FAF_SIM_MATH_SUBSET)
    // Pathfinder edge-cost bucket: ceil(ln(cost / distance) * 6), clamped.
    RunFloats(r, "QuantizeEdgeCost", 2, [](const float* a) {
      return Hex(gpg::HaStar::Cluster::QuantizeEdgeCost(a[0], a[1]));
    });
    {
      int index = 0;
      InputStream in("NodeCostTo", 5);
      for (int i = 0; i < kRandomCases * 2; ++i) {
        const gpg::HaStar::Cluster::Node from{in.Byte(), in.Byte()};
        const gpg::HaStar::Cluster::Node to{in.Byte(), in.Byte()};
        const float cost = (i & 1) ? in.Positive() : in.Float();
        r.Add(
          "NodeCostTo", index++,
          Join(static_cast<std::uint32_t>(from.x | (from.z << 8) | (to.x << 16) | (to.z << 24)), cost),
          Hex(static_cast<std::int32_t>(gpg::HaStar::Cluster::Node::CostTo(from, to, cost)))
        );
      }
    }
#endif

    // Unsigned cell coordinates (path navigator).
    {
      int index = 0;
      InputStream in("NavigatorCells", 4);
      const std::int16_t edges[] = {0, 1, -1, -2, 255, 256, 1023, 1024, 32767, -32768};
      auto add = [&](const moho::SOCellPos a, const moho::SOCellPos b) {
        r.Add(
          "NavigatorCells", index++,
          Join(static_cast<std::int32_t>(a.x), static_cast<std::int32_t>(a.z), static_cast<std::int32_t>(b.x),
               static_cast<std::int32_t>(b.z)),
          Join(moho::CellDistance(a, b), moho::ManhattanDistance(a, b))
        );
      };
      for (const std::int16_t ax : edges) {
        for (const std::int16_t bz : edges) {
          add(moho::SOCellPos{ax, 5}, moho::SOCellPos{3, bz});
        }
      }
      for (int i = 0; i < kRandomCases; ++i) {
        // One draw per statement: argument evaluation order differs between
        // the Microsoft ABI (right to left) and System V (left to right).
        const moho::SOCellPos a{in.Short(), in.Short()};
        const moho::SOCellPos b{in.Short(), in.Short()};
        add(a, b);
      }
    }

#if !defined(FAF_SIM_MATH_SUBSET)
    // The random stream: twister words, uniform and Gaussian samples from fixed seeds.
    {
      const std::uint32_t seeds[] = {0u, 1u, moho::CRandomStream::kDefaultSeed, 0x12345678u, 123456789u, 0xFFFFFFFFu};
      for (const std::uint32_t seed : seeds) {
        moho::CRandomStream stream(seed);
        char name[48];
        std::snprintf(name, sizeof(name), "RandomStream_%08X", seed);
        for (int i = 0; i < 400; ++i) {
          std::string out;
          switch (i % 4) {
          case 0:
            out = Hex(stream.twister.NextUInt32());
            break;
          case 1:
            out = Hex(stream.FRand());
            break;
          case 2:
            out = Hex(stream.FRand(-5.0f, 7.0f));
            break;
          default:
            out = Hex(stream.FRandGaussian());
            break;
          }
          r.Add(name, i, std::to_string(i % 4), out);
        }
      }
    }
#endif
  }

  const char* PlatformName()
  {
#if defined(_WIN32) && defined(_M_X64)
    return "windows-x64";
#elif defined(_WIN32)
    return "windows-x86";
#elif defined(__x86_64__)
    return "linux-x64";
#else
    return "unknown";
#endif
  }
} // namespace

namespace
{
  /** Reads "name index rest" lines (comments skipped) into `into`, overwriting. */
  bool ReadCaseFile(const char* const path, std::map<std::string, std::string>& into)
  {
    std::FILE* const in = std::fopen(path, "rb");
    if (in == nullptr) {
      return false;
    }
    char line[1024];
    while (std::fgets(line, sizeof(line), in) != nullptr) {
      if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
        continue;
      }
      std::string text(line);
      while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
        text.pop_back();
      }
      const std::size_t first = text.find(' ');
      const std::size_t second = text.find(' ', first + 1);
      into[text.substr(0, second)] = text.substr(second + 1);
    }
    std::fclose(in);
    return true;
  }
  /**
   * Engine addition (plan WPL.12): `--sweep <function>` runs one unary float function of the
   * engine on every float bit pattern (NaNs included) and prints one FNV-1a hash of the
   * (input, output) bit pairs per block of 2^20 inputs, "function block hash". The same sweep
   * on another platform, diffed, finds every input whose result differs.
   */
  int RunSweep(const char* const name)
  {
    using UnaryFloat = float (*)(float);
    struct Entry
    {
      const char* name;
      UnaryFloat fn;
    };
    static const Entry kFunctions[] = {
      {"sinf", [](const float x) { return fa::sinf(x); }},
      {"cosf", [](const float x) { return fa::cosf(x); }},
      {"tanf", [](const float x) { return fa::tanf(x); }},
      {"atanf", [](const float x) { return fa::atanf(x); }},
      {"asinf", [](const float x) { return fa::asinf(x); }},
      {"acosf", [](const float x) { return fa::acosf(x); }},
      {"expf", [](const float x) { return fa::expf(x); }},
      {"logf", [](const float x) { return fa::logf(x); }},
      {"IntrinsicExp", [](const float x) { return fa::IntrinsicExp(x); }},
      {"IntrinsicLn", [](const float x) { return fa::IntrinsicLn(x); }},
      {"IntrinsicLog10", [](const float x) { return fa::IntrinsicLog10(x); }},
      {"sqrt_float", [](const float x) { return std::sqrt(x); }},
      {"RoundToInt", [](const float x) { return std::bit_cast<float>(fa::RoundToInt(x)); }},
    };
    UnaryFloat fn = nullptr;
    for (const Entry& entry : kFunctions) {
      if (std::strcmp(entry.name, name) == 0) {
        fn = entry.fn;
      }
    }
    if (fn == nullptr) {
      std::fprintf(stderr, "unknown sweep function %s\n", name);
      return 2;
    }
    for (std::uint64_t block = 0; block < (1ull << 12); ++block) {
      std::uint64_t hash = 1469598103934665603ull;
      for (std::uint64_t index = 0; index < (1ull << 20); ++index) {
        const auto bits = static_cast<std::uint32_t>((block << 20) | index);
        const std::uint32_t out = std::bit_cast<std::uint32_t>(fn(std::bit_cast<float>(bits)));
        hash = (hash ^ bits) * 1099511628211ull;
        hash = (hash ^ out) * 1099511628211ull;
      }
      std::printf("%s %llu %016llx\n", name, static_cast<unsigned long long>(block), static_cast<unsigned long long>(hash));
    }
    return 0;
  }

  std::string gGoldenPath;
  std::string gKnownPath;

  void RunParityCheck(const char* path, const char* knownPath)
  {
    ASSERT_NE(path, nullptr) << "Golden file path must be provided";
    std::map<std::string, std::string> golden;
    ASSERT_TRUE(ReadCaseFile(path, golden)) << "cannot read " << path;

    // The simulation thread's floating-point environment.
#if defined(_PC_24)
    platform::SetX87PrecisionControl(_PC_24);
#endif
    (void)SetSse2Mode(0);

    Results results;
    RunAll(results);

    int known = 0;
    if (knownPath != nullptr) {
      std::map<std::string, std::string> overlay;
      ASSERT_TRUE(ReadCaseFile(knownPath, overlay)) << "cannot read " << knownPath;
      for (const auto& [key, value] : overlay) {
        golden[key] = value;
        ++known;
      }
    }

    std::map<std::string, int> mismatchesByName;
    std::map<std::string, std::string> firstMismatch;
    int missing = 0;
    for (const std::string& key : results.order) {
      const auto it = golden.find(key);
      const std::string& actual = results.lines[key];
      const std::string name = key.substr(0, key.find(' '));
      if (it == golden.end()) {
        ++missing;
        continue;
      }
      if (it->second != actual) {
        if (mismatchesByName[name]++ == 0) {
          firstMismatch[name] = key + ": expected " + it->second + ", got " + actual.substr(actual.find("->") + 3);
        }
      }
    }

    int total = 0;
    for (const auto& [name, count] : mismatchesByName) {
      std::printf("FAIL %s: %d case(s) differ; first: %s\n", name.c_str(), count, firstMismatch[name].c_str());
      total += count;
    }
    std::printf(
      "faf_sim_math_tests (%s): %zu cases, %d differ, %d missing from %s (%d known platform difference(s) applied)\n",
      PlatformName(), results.order.size(), total, missing, path, known
    );
    const std::size_t skipped = golden.size() - (results.order.size() - static_cast<std::size_t>(missing));
#if defined(FAF_SIM_MATH_SUBSET)
    std::printf("subset build: %zu golden case(s) not run here (pathfinder, random stream)\n", skipped);
    EXPECT_EQ(total, 0);
    EXPECT_EQ(missing, 0);
#else
    EXPECT_EQ(total, 0);
    EXPECT_EQ(missing, 0);
    EXPECT_EQ(skipped, 0);
#endif
  }
  std::filesystem::path GetExecutableDir()
  {
    std::error_code ec;
#if defined(_WIN32)
    char buffer[MAX_PATH];
    const DWORD len = GetModuleFileNameA(nullptr, buffer, static_cast<DWORD>(sizeof(buffer)));
    if (len > 0 && len < sizeof(buffer)) {
      return std::filesystem::path(buffer).parent_path();
    }
#elif defined(__linux__)
    char buffer[1024];
    const ssize_t len = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (len > 0) {
      buffer[len] = '\0';
      return std::filesystem::path(buffer).parent_path();
    }
#endif
    return std::filesystem::current_path(ec);
  }

  std::filesystem::path FindInAncestors(const std::filesystem::path& startDir, const std::filesystem::path& relativeTarget)
  {
    std::error_code ec;
    std::filesystem::path cur = std::filesystem::absolute(startDir, ec);
    while (!cur.empty()) {
      const std::filesystem::path candidate = cur / relativeTarget;
      if (std::filesystem::exists(candidate, ec)) {
        return candidate;
      }
      const std::filesystem::path parent = cur.parent_path();
      if (parent == cur) {
        break;
      }
      cur = parent;
    }
    return {};
  }

  std::string ResolveGoldenPath()
  {
    if (!gGoldenPath.empty()) {
      return gGoldenPath;
    }
    std::error_code ec;
#if defined(FAF_SIM_MATH_GOLDEN)
    const std::filesystem::path compiledGolden(FAF_SIM_MATH_GOLDEN);
    if (std::filesystem::exists(compiledGolden, ec)) {
      return compiledGolden.string();
    }
#endif
    const std::filesystem::path cur = std::filesystem::current_path(ec);
    for (const auto& rel : {"sim_math/golden.txt", "tests/sim_math/golden.txt"}) {
      const std::filesystem::path found = FindInAncestors(cur, rel);
      if (!found.empty()) {
        return found.string();
      }
    }
    const std::filesystem::path exeDir = GetExecutableDir();
    for (const auto& rel : {"sim_math/golden.txt", "tests/sim_math/golden.txt"}) {
      const std::filesystem::path found = FindInAncestors(exeDir, rel);
      if (!found.empty()) {
        return found.string();
      }
    }
    return {};
  }

  std::string ResolveKnownPath(const std::string& resolvedGolden)
  {
    if (!gKnownPath.empty()) {
      return gKnownPath;
    }
    std::error_code ec;
#if defined(FAF_SIM_MATH_KNOWN)
    const std::filesystem::path compiledKnown(FAF_SIM_MATH_KNOWN);
    if (std::filesystem::exists(compiledKnown, ec)) {
      return compiledKnown.string();
    }
#endif
    if (!resolvedGolden.empty()) {
      const std::filesystem::path goldenDir = std::filesystem::path(resolvedGolden).parent_path();
      const std::filesystem::path candidate = goldenDir / ("known_" + std::string(PlatformName()) + ".txt");
      if (std::filesystem::exists(candidate, ec)) {
        return candidate.string();
      }
    }
    return {};
  }
} // namespace

TEST(Existing_SimMath, GoldenParity)
{
  const std::string golden = ResolveGoldenPath();
  const std::string known = ResolveKnownPath(golden);
  RunParityCheck(golden.empty() ? nullptr : golden.c_str(), known.empty() ? nullptr : known.c_str());
}

int main(int argc, char** argv)
{
  if (argc > 2 && std::strcmp(argv[1], "--sweep") == 0) {
#if defined(_PC_24)
    platform::SetX87PrecisionControl(_PC_24);
#endif
    (void)SetSse2Mode(0);
    return RunSweep(argv[2]);
  }

  const bool generate = argc > 2 && std::strcmp(argv[1], "--generate") == 0;
  const bool generateKnown = argc > 4 && std::strcmp(argv[1], "--generate-known") == 0;

  if (generate) {
#if defined(_PC_24)
    platform::SetX87PrecisionControl(_PC_24);
#endif
    (void)SetSse2Mode(0);
    Results results;
    RunAll(results);
    const char* const path = argv[2];
    std::FILE* const out = std::fopen(path, "wb");
    if (out == nullptr) {
      std::fprintf(stderr, "cannot write %s\n", path);
      return 2;
    }
    std::fprintf(out, "# faf_sim_math_tests golden values (plan WPL.23), generated on %s. One line per case:\n", PlatformName());
    std::fprintf(out, "# name index inputs -> outputs (hex bit patterns; i/u prefixes for integers).\n");
    for (const std::string& key : results.order) {
      std::fprintf(out, "%s %s\n", key.c_str(), results.lines[key].c_str());
    }
    std::fclose(out);
    std::printf("wrote %zu cases to %s\n", results.order.size(), path);
    return 0;
  }

  if (generateKnown) {
#if defined(_PC_24)
    platform::SetX87PrecisionControl(_PC_24);
#endif
    (void)SetSse2Mode(0);
    Results results;
    RunAll(results);
    const char* const path = argv[2];
    std::map<std::string, std::string> golden;
    if (!ReadCaseFile(path, golden)) {
      std::fprintf(stderr, "cannot read %s\n", path);
      return 2;
    }
    std::FILE* const out = std::fopen(argv[3], "wb");
    if (out == nullptr) {
      std::fprintf(stderr, "cannot write %s\n", argv[3]);
      return 2;
    }
    std::fprintf(out, "# faf_sim_math_tests known differences on %s from %s (plan WPL.23).\n", PlatformName(), path);
    std::fprintf(out, "# Reason: %s\n", argv[4]);
    int written = 0;
    for (const std::string& key : results.order) {
      const auto it = golden.find(key);
      if (it != golden.end() && it->second != results.lines[key]) {
        std::fprintf(out, "%s %s\n", key.c_str(), results.lines[key].c_str());
        ++written;
      }
    }
    std::fclose(out);
    std::printf("wrote %d known difference(s) to %s\n", written, argv[3]);
    return 0;
  }

  ::testing::InitGoogleTest(&argc, argv);

  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--known") == 0 && i + 1 < argc) {
      gKnownPath = argv[++i];
    } else if (argv[i][0] != '-') {
      gGoldenPath = argv[i];
    }
  }

  return RUN_ALL_TESTS();
}
