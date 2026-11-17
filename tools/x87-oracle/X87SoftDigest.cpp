// Engine addition (#262): one hash per software x87 routine over a fixed set of inputs - every
// float for the one-argument routines, a seeded random corpus for the rest. The same digests on
// x86-64 and ARM64 show the software gives the same bits on both, so tools/x87-oracle/X87Oracle.cpp's
// comparison with the x87 unit (x86-64 only) holds for the ARM64 build too.
//
//   faf_x87_soft_digest [random cases per routine] [threads]

#include "legacy/math/X87Soft.h"

#include <bit>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <print>
#include <string>
#include <thread>
#include <vector>

namespace
{
  /// FNV-1a over 64-bit words.
  struct Digest
  {
    std::uint64_t value = 0xCBF29CE484222325ull;

    void Add(
      const std::uint64_t word
    ) noexcept
    {
      for (int i = 0; i < 8; ++i) {
        value = (value ^ ((word >> (8 * i)) & 0xFF)) * 0x100000001B3ull;
      }
    }
  };

  std::uint64_t Mix(
    std::uint64_t z
  ) noexcept
  {
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
  }

  /// A float from a counter: any bit pattern, or values in the game's ranges.
  float CaseFloat(
    const std::uint64_t index,
    const int lane
  ) noexcept
  {
    const std::uint64_t r = Mix(index * 16 + static_cast<std::uint64_t>(lane) + 0x9E3779B97F4A7C15ull);
    switch (r & 3) {
    case 0:
      return std::bit_cast<float>(static_cast<std::uint32_t>(r >> 32));
    case 1:
      return (static_cast<float>(r >> 40) * 0x1p-24f - 0.5f) * 2048.0f;
    case 2:
      return (static_cast<float>(r >> 40) * 0x1p-24f - 0.5f) * 4.0f;
    default:
      return (static_cast<float>(r >> 40) * 0x1p-24f) * 0x1p-20f;
    }
  }

  std::uint64_t Bits(
    const float v
  ) noexcept
  {
    return std::bit_cast<std::uint32_t>(v);
  }
  std::uint64_t Bits(
    const double v
  ) noexcept
  {
    return std::bit_cast<std::uint64_t>(v);
  }

  /// Hashes `count` cases of `body(index, digest)` in 64 fixed slices, whatever the thread count,
  /// so every machine forms the same digest from the same results.
  template <class Body>
  std::uint64_t Run(
    const std::uint64_t count,
    const unsigned threads,
    Body body
  )
  {
    constexpr unsigned kSlices = 64;
    std::vector<Digest> slices(kSlices);
    std::vector<std::thread> workers;
    for (unsigned t = 0; t < threads; ++t) {
      workers.emplace_back([&, t] {
        for (unsigned slice = t; slice < kSlices; slice += threads) {
          const std::uint64_t begin = count * slice / kSlices;
          const std::uint64_t end = count * (slice + 1) / kSlices;
          for (std::uint64_t i = begin; i < end; ++i) {
            body(i, slices[slice]);
          }
        }
      });
    }
    for (std::thread& worker : workers) {
      worker.join();
    }
    Digest total;
    for (const Digest& slice : slices) {
      total.Add(slice.value);
    }
    return total.value;
  }
} // namespace

int main(
  const int argc,
  char** const argv
)
{
  const std::uint64_t randomCases = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 50'000'000ull;
  const unsigned threads = argc > 2
    ? static_cast<unsigned>(std::strtoul(argv[2], nullptr, 10))
    : (std::thread::hardware_concurrency() != 0 ? std::thread::hardware_concurrency() : 4);
  constexpr std::uint64_t kAll = 1ull << 32;
  const auto unary = [&](const char* name, auto f) {
    std::println(
      "{:26} {:016x}", name, static_cast<unsigned long long>(Run(kAll, threads, [&](const std::uint64_t i, Digest& d) {
      d.Add(Bits(f(std::bit_cast<float>(static_cast<std::uint32_t>(i)))));
    }))
    );
    std::fflush(stdout);
  };
  unary("sinf", [](float x) {
    return fa::x87::Sinf(x);
  });
  unary("cosf", [](float x) {
    return fa::x87::Cosf(x);
  });
  unary("tanf", [](float x) {
    return fa::x87::Tanf(x);
  });
  unary("round_to_int", [](float x) {
    return static_cast<float>(fa::x87::RoundToInt(x));
  });
  unary("exp", [](float x) {
    return fa::x87::IntrinsicExp(x);
  });
  unary("ln", [](float x) {
    return fa::x87::IntrinsicLn(x);
  });
  unary("log10", [](float x) {
    return fa::x87::IntrinsicLog10(x);
  });
  unary("asin", [](float x) {
    return fa::x87::Asin(x);
  });
  unary("acos", [](float x) {
    return fa::x87::Acos(x);
  });

  const auto random = [&](const char* name, auto body) {
    std::println("{:26} {:016x}", name, static_cast<unsigned long long>(Run(randomCases, threads, body)));
    std::fflush(stdout);
  };
  random("atan2f", [](std::uint64_t i, Digest& d) {
    d.Add(Bits(fa::x87::Atan2f(CaseFloat(i, 0), CaseFloat(i, 1))));
  });
  random("pow", [](std::uint64_t i, Digest& d) {
    d.Add(Bits(fa::x87::Pow(CaseFloat(i, 0), static_cast<double>(static_cast<int>(CaseFloat(i, 1)) % 8))));
  });
  random("pow_fraction", [](std::uint64_t i, Digest& d) {
    d.Add(Bits(fa::x87::Pow(CaseFloat(i, 0), CaseFloat(i, 1))));
  });
  random("atan2_difference", [](std::uint64_t i, Digest& d) {
    d.Add(Bits(fa::x87::Atan2Difference(CaseFloat(i, 0), CaseFloat(i, 1), CaseFloat(i, 2), CaseFloat(i, 3))));
  });
  random("atan2_plus", [](std::uint64_t i, Digest& d) {
    d.Add(Bits(fa::x87::Atan2Plus(CaseFloat(i, 0), CaseFloat(i, 1), CaseFloat(i, 2))));
  });
  random("sin_times_cos", [](std::uint64_t i, Digest& d) {
    d.Add(Bits(fa::x87::SinTimesCos(CaseFloat(i, 0), CaseFloat(i, 1))));
  });
  random("sin_of_product_times", [](std::uint64_t i, Digest& d) {
    d.Add(Bits(fa::x87::SinOfProductTimes(CaseFloat(i, 0), CaseFloat(i, 1), CaseFloat(i, 2))));
  });
  random("cos_times_cos", [](std::uint64_t i, Digest& d) {
    d.Add(Bits(fa::x87::CosTimesCos(CaseFloat(i, 0), CaseFloat(i, 1))));
  });
  random("twister_word_in_range", [](std::uint64_t i, Digest& d) {
    d.Add(Bits(fa::x87::TwisterWordInRange(CaseFloat(i, 0), CaseFloat(i, 1), static_cast<std::uint32_t>(Mix(i)))));
  });
  random("slerp_spherical_blend", [](std::uint64_t i, Digest& d) {
    const float q1[4] = {CaseFloat(i, 0), CaseFloat(i, 1), CaseFloat(i, 2), CaseFloat(i, 3)};
    const float rhs[4] = {CaseFloat(i, 4), CaseFloat(i, 5), CaseFloat(i, 6), CaseFloat(i, 7)};
    float out[4];
    fa::x87::SlerpSphericalBlend(out, q1, rhs, CaseFloat(i, 8), CaseFloat(i, 9), CaseFloat(i, 10));
    for (const float lane : out) {
      d.Add(Bits(lane));
    }
  });
  random("ln_quotient", [](std::uint64_t i, Digest& d) {
    d.Add(Bits(fa::x87::IntrinsicLnQuotient(CaseFloat(i, 0), CaseFloat(i, 1))));
  });
  random("scaled_ln_quotient", [](std::uint64_t i, Digest& d) {
    d.Add(Bits(fa::x87::ScaledLnQuotient(CaseFloat(i, 0), CaseFloat(i, 1), CaseFloat(i, 2))));
  });
  random("bilinear_height", [](std::uint64_t i, Digest& d) {
    d.Add(Bits(
      fa::x87::BilinearHeight(
        CaseFloat(i, 0), CaseFloat(i, 1), CaseFloat(i, 2), CaseFloat(i, 3), CaseFloat(i, 4), CaseFloat(i, 5)
      )
    ));
  });
  random("subtract_bilinear_height", [](std::uint64_t i, Digest& d) {
    d.Add(Bits(
      fa::x87::SubtractBilinearHeight(
        CaseFloat(i, 6),
        CaseFloat(i, 0),
        CaseFloat(i, 1),
        CaseFloat(i, 2),
        CaseFloat(i, 3),
        CaseFloat(i, 4),
        CaseFloat(i, 5)
      )
    ));
  });
  random("scale_vectors", [](std::uint64_t i, Digest& d) {
    float x = CaseFloat(i, 0), y = CaseFloat(i, 1), z = CaseFloat(i, 2);
    fa::x87::ScaleVectorMaxLength(&x, &y, &z, CaseFloat(i, 3), CaseFloat(i, 4));
    const float source[3] = {CaseFloat(i, 5), CaseFloat(i, 6), CaseFloat(i, 7)};
    const float target[3] = {CaseFloat(i, 8), CaseFloat(i, 9), CaseFloat(i, 10)};
    float a[3], b[3], c[3];
    fa::x87::ScaleVectorToLength(a, source, CaseFloat(i, 11), CaseFloat(i, 12));
    fa::x87::ScaleVector(b, source, CaseFloat(i, 13));
    fa::x87::ScaleVectorToLengthOf(c, source, target, CaseFloat(i, 14));
    for (const float v : {x, y, z, a[0], a[1], a[2], b[0], b[1], b[2], c[0], c[1], c[2]}) {
      d.Add(Bits(v));
    }
  });
  random("box_and_length", [](std::uint64_t i, Digest& d) {
    float box[15];
    for (int lane = 0; lane < 15; ++lane) {
      box[lane] = CaseFloat(i, lane);
    }
    const float axis[3] = {CaseFloat(i, 15), CaseFloat(i + 1, 0), CaseFloat(i + 1, 1)};
    d.Add(Bits(fa::x87::BoxRadiusOnAxis(box, axis)));
    d.Add(Bits(fa::x87::VectorLengthZYX(axis)));
  });
  return 0;
}
