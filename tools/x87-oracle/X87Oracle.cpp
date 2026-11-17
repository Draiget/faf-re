// Engine addition (#262): the software x87 (legacy/math/X87Soft.cpp) against the x87 unit
// (legacy/math/X87Math64.S), in one process on x86-64. Every input gives the same result bits,
// or the run fails and lists the first differences.
//
//   faf_x87_oracle all [threads]                   every routine below, as the CI runs it
//   faf_x87_oracle exhaustive <routine> [threads]   all 2^32 float inputs of a one-argument routine
//   faf_x87_oracle random <routine> <count> [seed] [threads]
//
// One-argument routines: sinf cosf tanf round_to_int exp ln log10 asin acos (the last two take the
// float widened to double, as Lua's math.asin does). Every routine also runs under `random`.

#include "legacy/math/X87Routines.h"
#include "legacy/math/X87Soft.h"

#include <atomic>
#include <bit>
#include <cinttypes>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <print>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

namespace
{
  /// A source of test floats: random bit patterns (every class, NaNs and denormals included) mixed
  /// with values in the ranges the game uses and values near rounding edges.
  class Inputs
  {
  public:
    explicit Inputs(
      const std::uint64_t seed
    ) noexcept
      : mState(seed * 0x9E3779B97F4A7C15ull + 1)
    {}

    std::uint64_t Next() noexcept
    {
      // splitmix64
      std::uint64_t z = (mState += 0x9E3779B97F4A7C15ull);
      z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
      z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
      return z ^ (z >> 31);
    }

    float Float() noexcept
    {
      const std::uint64_t r = Next();
      switch (r & 7) {
      case 0:
      case 1:
        return std::bit_cast<float>(static_cast<std::uint32_t>(r >> 32)); // any pattern
      case 2:
        return Uniform(r, 1.0f);
      case 3:
        return Uniform(r, 8.0f);
      case 4:
        return Uniform(r, 1024.0f);
      case 5:
        return Uniform(r, 65536.0f);
      case 6: {
        // Near a power of two, a few units from it.
        const int exponent = static_cast<int>((r >> 8) % 60) - 30;
        const auto base = std::bit_cast<std::uint32_t>(std::ldexp(1.0f, exponent));
        const std::int32_t offset = static_cast<std::int32_t>((r >> 40) & 15) - 8;
        return std::bit_cast<float>(base + static_cast<std::uint32_t>(offset));
      }
      default:
        return std::bit_cast<float>(static_cast<std::uint32_t>((r >> 32) & 0x807FFFFFu) | 0x00000000u); // denormals
      }
    }

  private:
    static float Uniform(
      const std::uint64_t r,
      const float scale
    ) noexcept
    {
      const float unit = static_cast<float>(r >> 40) * 0x1p-24f; // [0, 1)
      return ((r & 0x100) != 0 ? -unit : unit) * scale;
    }

    std::uint64_t mState;
  };

  std::uint32_t Bits(
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

  struct Report
  {
    std::mutex lock;
    std::atomic<std::uint64_t> mismatches{0};
    std::atomic<std::uint64_t> checked{0};
    std::vector<std::string> first;

    void Fail(
      const std::string& line
    )
    {
      if (mismatches.fetch_add(1) < 20) {
        const std::lock_guard<std::mutex> guard(lock);
        first.push_back(line);
      }
    }
  };

  using UnaryCheck = void (*)(std::uint32_t inputBits, Report& report);

  template <typename F>
  std::string Hex(
    const F value
  )
  {
    char text[32];
    if constexpr (sizeof(F) == 4) {
      std::snprintf(text, sizeof(text), "0x%08" PRIX32, Bits(value));
    } else {
      std::snprintf(text, sizeof(text), "0x%016" PRIX64, Bits(value));
    }
    return text;
  }

  template <typename R>
  void Compare(
    Report& report,
    const char* name,
    const std::string& args,
    const R hardware,
    const R software
  )
  {
    report.checked.fetch_add(1, std::memory_order_relaxed);
    bool same = false;
    if constexpr (std::is_same_v<R, float> || std::is_same_v<R, double>) {
      same = Bits(hardware) == Bits(software);
    } else {
      same = hardware == software;
    }
    if (!same) {
      std::string line = std::string(name) + "(" + args + "): x87 ";
      if constexpr (std::is_same_v<R, float> || std::is_same_v<R, double>) {
        line += Hex(hardware) + " software " + Hex(software);
      } else {
        line += std::to_string(hardware) + " software " + std::to_string(software);
      }
      report.Fail(line);
    }
  }

  void CheckSinf(
    const std::uint32_t b,
    Report& r
  )
  {
    const float x = std::bit_cast<float>(b);
    Compare(r, "sinf", Hex(x), msvc8_x87_sinf(x), fa::x87::Sinf(x));
  }
  void CheckCosf(
    const std::uint32_t b,
    Report& r
  )
  {
    const float x = std::bit_cast<float>(b);
    Compare(r, "cosf", Hex(x), msvc8_x87_cosf(x), fa::x87::Cosf(x));
  }
  void CheckTanf(
    const std::uint32_t b,
    Report& r
  )
  {
    const float x = std::bit_cast<float>(b);
    Compare(r, "tanf", Hex(x), msvc8_x87_tanf(x), fa::x87::Tanf(x));
  }
  void CheckRound(
    const std::uint32_t b,
    Report& r
  )
  {
    const float x = std::bit_cast<float>(b);
    Compare(r, "round_to_int", Hex(x), msvc8_x87_round_to_int(x), fa::x87::RoundToInt(x));
  }
  void CheckExp(
    const std::uint32_t b,
    Report& r
  )
  {
    const float x = std::bit_cast<float>(b);
    Compare(r, "exp", Hex(x), msvc8_x87_intrinsic_exp(x), fa::x87::IntrinsicExp(x));
  }
  void CheckLn(
    const std::uint32_t b,
    Report& r
  )
  {
    const float x = std::bit_cast<float>(b);
    Compare(r, "ln", Hex(x), msvc8_x87_intrinsic_ln(x), fa::x87::IntrinsicLn(x));
  }
  void CheckLog10(
    const std::uint32_t b,
    Report& r
  )
  {
    const float x = std::bit_cast<float>(b);
    Compare(r, "log10", Hex(x), msvc8_x87_intrinsic_log10(x), fa::x87::IntrinsicLog10(x));
  }
  void CheckAsin(
    const std::uint32_t b,
    Report& r
  )
  {
    const double x = std::bit_cast<float>(b);
    Compare(r, "asin", Hex(x), msvc8_x87_asin(x), fa::x87::Asin(x));
  }
  void CheckAcos(
    const std::uint32_t b,
    Report& r
  )
  {
    const double x = std::bit_cast<float>(b);
    Compare(r, "acos", Hex(x), msvc8_x87_acos(x), fa::x87::Acos(x));
  }

  struct UnaryRoutine
  {
    const char* name;
    UnaryCheck check;
  };

  constexpr UnaryRoutine kUnary[] = {
    {"sinf", CheckSinf},
    {"cosf", CheckCosf},
    {"tanf", CheckTanf},
    {"round_to_int", CheckRound},
    {"exp", CheckExp},
    {"ln", CheckLn},
    {"log10", CheckLog10},
    {"asin", CheckAsin},
    {"acos", CheckAcos},
  };

  /// One random case of a multi-argument routine (or a one-argument one).
  void RandomCase(
    const std::string& routine,
    Inputs& in,
    Report& r
  )
  {
    const float a = in.Float();
    const float b = in.Float();
    const float c = in.Float();
    const float d = in.Float();
    const float e = in.Float();
    const float f = in.Float();
    const float g = in.Float();
    for (const UnaryRoutine& unary : kUnary) {
      if (routine == unary.name) {
        unary.check(Bits(a), r);
        return;
      }
    }
    const std::string ab = Hex(a) + "," + Hex(b);
    const std::string abc = ab + "," + Hex(c);
    if (routine == "atan2f") {
      Compare(r, "atan2f", ab, msvc8_x87_atan2f(a, b), fa::x87::Atan2f(a, b));
    } else if (routine == "pow") {
      const double x = a;
      const double y = (in.Next() & 1) != 0 ? static_cast<double>(b) : static_cast<double>(static_cast<int>(b) % 8);
      Compare(r, "pow", Hex(x) + "," + Hex(y), msvc8_x87_pow(x, y), fa::x87::Pow(x, y));
    } else if (routine == "atan2_difference") {
      Compare(
        r,
        "atan2_difference",
        abc + "," + Hex(d),
        msvc8_x87_atan2_difference(a, b, c, d),
        fa::x87::Atan2Difference(a, b, c, d)
      );
    } else if (routine == "atan2_plus") {
      Compare(r, "atan2_plus", abc, msvc8_x87_atan2_plus(a, b, c), fa::x87::Atan2Plus(a, b, c));
    } else if (routine == "sin_times_cos") {
      Compare(r, "sin_times_cos", ab, msvc8_x87_sin_times_cos(a, b), fa::x87::SinTimesCos(a, b));
    } else if (routine == "sin_of_product_times") {
      Compare(
        r, "sin_of_product_times", abc, msvc8_x87_sin_of_product_times(a, b, c), fa::x87::SinOfProductTimes(a, b, c)
      );
    } else if (routine == "twister_word_in_range") {
      const auto word = static_cast<std::uint32_t>(in.Next());
      Compare(
        r,
        "twister_word_in_range",
        ab + "," + std::to_string(word),
        msvc8_x87_twister_word_in_range(a, b, word),
        fa::x87::TwisterWordInRange(a, b, word)
      );
    } else if (routine == "slerp_spherical_blend") {
      const float q1[4] = {a, b, c, d};
      const float rhs[4] = {e, f, g, in.Float()};
      const float angle = in.Float();
      const float t = in.Float();
      const float oneMinusT = in.Float();
      float hardware[4];
      float software[4];
      msvc8_x87_slerp_spherical_blend(hardware, q1, rhs, angle, oneMinusT, t);
      fa::x87::SlerpSphericalBlend(software, q1, rhs, angle, oneMinusT, t);
      for (int lane = 0; lane < 4; ++lane) {
        Compare(
          r, "slerp_spherical_blend", Hex(angle) + " lane " + std::to_string(lane), hardware[lane], software[lane]
        );
      }
    } else if (routine == "ln_quotient") {
      const double base = b;
      Compare(r, "ln_quotient", ab, msvc8_x87_intrinsic_ln_quotient(a, base), fa::x87::IntrinsicLnQuotient(a, base));
    } else if (routine == "scaled_ln_quotient") {
      Compare(r, "scaled_ln_quotient", abc, msvc8_x87_scaled_ln_quotient(a, b, c), fa::x87::ScaledLnQuotient(a, b, c));
    } else if (routine == "cos_times_cos") {
      Compare(r, "cos_times_cos", ab, msvc8_x87_cos_times_cos(a, b), fa::x87::CosTimesCos(a, b));
    } else if (routine == "bilinear_height") {
      Compare(
        r,
        "bilinear_height",
        abc,
        msvc8_x87_bilinear_height(a, b, c, d, e, f),
        fa::x87::BilinearHeight(a, b, c, d, e, f)
      );
    } else if (routine == "subtract_bilinear_height") {
      Compare(
        r,
        "subtract_bilinear_height",
        abc,
        msvc8_x87_subtract_bilinear_height(g, a, b, c, d, e, f),
        fa::x87::SubtractBilinearHeight(g, a, b, c, d, e, f)
      );
    } else if (routine == "scale_vector_max_length") {
      float hx = a, hy = b, hz = c, sx = a, sy = b, sz = c;
      msvc8_x87_scale_vector_max_length(&hx, &hy, &hz, d, e);
      fa::x87::ScaleVectorMaxLength(&sx, &sy, &sz, d, e);
      Compare(r, "scale_vector_max_length x", abc, hx, sx);
      Compare(r, "scale_vector_max_length y", abc, hy, sy);
      Compare(r, "scale_vector_max_length z", abc, hz, sz);
    } else if (routine == "scale_vector_to_length") {
      const float source[3] = {a, b, c};
      float hardware[3];
      float software[3];
      msvc8_x87_scale_vector_to_length(hardware, source, d, e);
      fa::x87::ScaleVectorToLength(software, source, d, e);
      for (int lane = 0; lane < 3; ++lane) {
        Compare(r, "scale_vector_to_length", abc, hardware[lane], software[lane]);
      }
    } else if (routine == "scale_vector") {
      const float source[3] = {a, b, c};
      float hardware[3];
      float software[3];
      msvc8_x87_scale_vector(hardware, source, d);
      fa::x87::ScaleVector(software, source, d);
      for (int lane = 0; lane < 3; ++lane) {
        Compare(r, "scale_vector", abc, hardware[lane], software[lane]);
      }
    } else if (routine == "scale_vector_to_length_of") {
      const float source[3] = {a, b, c};
      const float target[3] = {d, e, f};
      float hardware[3];
      float software[3];
      msvc8_x87_scale_vector_to_length_of(hardware, source, target, g);
      fa::x87::ScaleVectorToLengthOf(software, source, target, g);
      for (int lane = 0; lane < 3; ++lane) {
        Compare(r, "scale_vector_to_length_of", abc, hardware[lane], software[lane]);
      }
    } else if (routine == "box_radius_on_axis") {
      float box[15];
      for (float& lane : box) {
        lane = in.Float();
      }
      const float axis[3] = {a, b, c};
      Compare(
        r, "box_radius_on_axis", abc, msvc8_x87_box_radius_on_axis(box, axis), fa::x87::BoxRadiusOnAxis(box, axis)
      );
    } else if (routine == "vector_length_zyx") {
      const float lanes[3] = {a, b, c};
      Compare(r, "vector_length_zyx", abc, msvc8_x87_vector_length_zyx(lanes), fa::x87::VectorLengthZYX(lanes));
    } else {
      std::println(stderr, "unknown routine {}", routine);
      std::exit(2);
    }
  }

  const char* const kRandomRoutines[] = {
    "atan2f",
    "pow",
    "atan2_difference",
    "atan2_plus",
    "sin_times_cos",
    "sin_of_product_times",
    "twister_word_in_range",
    "slerp_spherical_blend",
    "ln_quotient",
    "scaled_ln_quotient",
    "cos_times_cos",
    "bilinear_height",
    "subtract_bilinear_height",
    "scale_vector_max_length",
    "scale_vector_to_length",
    "scale_vector",
    "scale_vector_to_length_of",
    "box_radius_on_axis",
    "vector_length_zyx",
  };

  int Finish(
    const char* what,
    Report& report
  )
  {
    for (const std::string& line : report.first) {
      std::println("  {}", line);
    }
    std::println("{}: {} checked, {} differ", what, report.checked.load(), report.mismatches.load());
    return report.mismatches.load() == 0 ? 0 : 1;
  }

  int Exhaustive(
    const UnaryRoutine& routine,
    const unsigned threads
  )
  {
    Report report;
    std::vector<std::thread> workers;
    constexpr std::uint64_t kAll = 1ull << 32;
    for (unsigned t = 0; t < threads; ++t) {
      workers.emplace_back([&, t] {
        for (std::uint64_t b = t; b < kAll; b += threads) {
          routine.check(static_cast<std::uint32_t>(b), report);
        }
      });
    }
    for (std::thread& worker : workers) {
      worker.join();
    }
    return Finish(routine.name, report);
  }

  int Random(
    const std::string& routine,
    const std::uint64_t count,
    const std::uint64_t seed,
    const unsigned threads
  )
  {
    Report report;
    std::vector<std::thread> workers;
    for (unsigned t = 0; t < threads; ++t) {
      workers.emplace_back([&, t] {
        Inputs in(seed * 1000003 + t);
        for (std::uint64_t i = t; i < count; i += threads) {
          RandomCase(routine, in, report);
        }
      });
    }
    for (std::thread& worker : workers) {
      worker.join();
    }
    return Finish(routine.c_str(), report);
  }
} // namespace

int main(
  const int argc,
  char** const argv
)
{
  const std::string mode = argc > 1 ? argv[1] : "all";
  const auto threadsArg = [&](const int index) {
    const unsigned fallback = std::thread::hardware_concurrency() != 0 ? std::thread::hardware_concurrency() : 4;
    return argc > index ? static_cast<unsigned>(std::strtoul(argv[index], nullptr, 10)) : fallback;
  };
  if (mode == "exhaustive" && argc > 2) {
    for (const UnaryRoutine& routine : kUnary) {
      if (std::string(argv[2]) == routine.name) {
        return Exhaustive(routine, threadsArg(3));
      }
    }
    std::println(stderr, "unknown one-argument routine {}", argv[2]);
    return 2;
  }
  if (mode == "random" && argc > 3) {
    const std::uint64_t seed = argc > 4 ? std::strtoull(argv[4], nullptr, 10) : 1;
    return Random(argv[2], std::strtoull(argv[3], nullptr, 10), seed, threadsArg(5));
  }
  if (mode == "all") {
    const unsigned threads = threadsArg(2);
    int failed = 0;
    for (const UnaryRoutine& routine : kUnary) {
      failed |= Exhaustive(routine, threads);
    }
    for (const char* routine : kRandomRoutines) {
      failed |= Random(routine, 100'000'000, 1, threads);
    }
    return failed;
  }
  std::println(
    stderr,
    "usage: {} all [threads] | exhaustive <routine> [threads] | random <routine> <count> [seed] [threads]",
    argv[0]
  );
  return 2;
}
