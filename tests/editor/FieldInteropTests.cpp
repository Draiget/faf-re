// The terrain library's interop ops (src/editor/terrain/EdFieldInterop.cpp): image resampling with each filter,
// orientation, and the rectangle and point masks.
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "editor/terrain/EdFieldCore.h"

#include <gtest/gtest.h>

using namespace faf::editor::field;

namespace
{

#define CHECK(cond, ...)                                                                                               \
  do {                                                                                                                 \
    if (!(cond)) {                                                                                                     \
      char checkMessage[1024];                                                                                         \
      std::snprintf(checkMessage, sizeof(checkMessage), __VA_ARGS__);                                                  \
      ADD_FAILURE_AT(__FILE__, __LINE__) << checkMessage;                                                              \
    }                                                                                                                  \
  } while (0)

  static GridPtr Make(
    const int w,
    const int h,
    float (*f)(int, int, int, int),
    const float cell = 1.0f
  )
  {
    auto g = std::make_shared<Grid>(w, h, cell, 0.0f, 0.0f);
    for (int z = 0; z < h; ++z)
      for (int x = 0; x < w; ++x)
        g->At(x, z) = f(x, z, w, h);
    return g;
  }

  static bool RunField(
    const char* const op,
    OpArgs& args,
    Grid& out
  )
  {
    std::string err;
    const bool ok = RunOp(op, args, out, err);
    if (!ok)
      std::printf("op %s: %s\n", op, err.c_str());
    return ok;
  }

  static float Pattern(
    const int x,
    const int z,
    const int,
    const int
  )
  {
    return static_cast<float>((x * 7 + z * 13) % 101) / 100.0f;
  }
  static float RampX(
    const int x,
    const int,
    const int w,
    const int
  )
  {
    return static_cast<float>(x) / static_cast<float>(w - 1);
  }
  static float Tilt(
    const int x,
    const int z,
    const int,
    const int
  )
  {
    return 0.25f * x + 0.5f * z;
  }

  TEST(
    FieldInterop,
    ResampleOrientAndMasks
  )
  {
    const char* const filters[] = {"nearest", "bilinear", "bicubic", "lanczos"};

    // 1. identity: a 65 x 65 image over a 65 x 65 grid with corner alignment is exact for every filter
    {
      GridPtr src = Make(65, 65, Pattern);
      GridPtr like = Make(65, 65, Pattern);
      for (const char* fname : filters) {
        OpArgs a;
        a.in["a"] = src;
        a.in["like"] = like;
        a.p.str["align"] = "corner";
        a.p.str["filter"] = fname;
        Grid out;
        if (!RunField("img_resample", a, out))
          continue;
        int bad = 0;
        for (std::size_t i = 0; i < out.v.size(); ++i)
          bad += out.v[i] != src->v[i];
        CHECK(bad == 0, "identity %s: %d samples differ", fname, bad);
      }
    }

    // 2. cell alignment: a 4 x 4 image over a 5 x 5 grid (4 cells): pixel k is centred on (k + 0.5), so the sample at 2
    // (the middle) sits between pixels 1 and 2
    {
      GridPtr src = Make(4, 4, RampX); // 0, 1/3, 2/3, 1
      GridPtr like = std::make_shared<Grid>(5, 5, 1.0f, 0.0f, 0.0f);
      OpArgs a;
      a.in["a"] = src;
      a.in["like"] = like;
      a.p.str["filter"] = "bilinear";
      Grid out;
      RunField("img_resample", a, out);
      CHECK(std::fabs(out.At(2, 2) - 0.5f) < 1e-6f, "cell: middle sample = %f, expected 0.5", out.At(2, 2));
      CHECK(std::fabs(out.At(0, 0) - 0.0f) < 1e-6f, "cell: first sample clamps to the first pixel (%f)", out.At(0, 0));
      CHECK(std::fabs(out.At(4, 4) - 1.0f) < 1e-6f, "cell: last sample clamps to the last pixel (%f)", out.At(4, 4));
      CHECK(std::fabs(out.At(1, 0) - 1.0f / 6.0f) < 1e-6f, "cell: sample 1 = %f", out.At(1, 0));
    }

    // 3. a linear ramp stays linear for bilinear / bicubic / lanczos (interior samples), also when the image is 2x
    // larger (low pass keeps linear functions)
    {
      GridPtr src = Make(129, 129, Tilt);
      GridPtr like = std::make_shared<Grid>(65, 65, 1.0f, 0.0f, 0.0f);
      for (const char* fname : {"bilinear", "bicubic", "lanczos"}) {
        OpArgs a;
        a.in["a"] = src;
        a.in["like"] = like;
        a.p.str["align"] = "corner";
        a.p.str["filter"] = fname;
        Grid out;
        if (!RunField("img_resample", a, out))
          continue;
        // output sample i = source coordinate 2 i, value 0.25 * 2 i + 0.5 * 2 j
        double worst = 0.0;
        for (int z = 8; z < 57; ++z)
          for (int x = 8; x < 57; ++x)
            worst = std::max(worst, static_cast<double>(std::fabs(out.At(x, z) - (0.5f * x + 1.0f * z))));
        CHECK(worst < 2e-3, "%s keeps a linear ramp when shrinking (worst %g)", fname, worst);
      }
    }

    // 4. a constant stays constant (weights are normalised), also in the clamped border
    {
      GridPtr src = Make(32, 32, [](int, int, int, int) {
        return 0.37f;
      });
      GridPtr like = std::make_shared<Grid>(129, 129, 1.0f, 0.0f, 0.0f);
      for (const char* fname : filters) {
        OpArgs a;
        a.in["a"] = src;
        a.in["like"] = like;
        a.p.str["filter"] = fname;
        Grid out;
        if (!RunField("img_resample", a, out))
          continue;
        double worst = 0.0;
        for (float v : out.v)
          worst = std::max(worst, static_cast<double>(std::fabs(v - 0.37f)));
        CHECK(worst < 1e-6, "%s keeps a constant (worst %g)", fname, worst);
      }
    }

    // 5. region: samples outside the rectangle keep `outside`; the rectangle is filled
    {
      GridPtr src = Make(16, 16, [](int, int, int, int) {
        return 1.0f;
      });
      GridPtr like = std::make_shared<Grid>(33, 33, 1.0f, 0.0f, 0.0f);
      OpArgs a;
      a.in["a"] = src;
      a.in["like"] = like;
      a.p.num["x0"] = 8;
      a.p.num["z0"] = 4;
      a.p.num["x1"] = 24;
      a.p.num["z1"] = 20;
      a.p.num["outside"] = -5;
      Grid out;
      RunField("img_resample", a, out);
      CHECK(
        out.At(7, 10) == -5.0f && out.At(8, 10) == 1.0f && out.At(24, 20) == 1.0f && out.At(25, 20) == -5.0f &&
          out.At(10, 3) == -5.0f && out.At(10, 4) == 1.0f,
        "region edges"
      );
    }

    // 6. thread independence: same result with 1 and 5 threads
    {
      GridPtr src = Make(300, 200, Pattern);
      GridPtr like = std::make_shared<Grid>(129, 97, 1.0f, 0.0f, 0.0f);
      Grid one, five;
      SetThreads(1);
      {
        OpArgs a;
        a.in["a"] = src;
        a.in["like"] = like;
        a.p.str["filter"] = "lanczos";
        RunField("img_resample", a, one);
      }
      SetThreads(5);
      {
        OpArgs a;
        a.in["a"] = src;
        a.in["like"] = like;
        a.p.str["filter"] = "lanczos";
        RunField("img_resample", a, five);
      }
      CHECK(one.v == five.v, "thread independent");
    }

    // 7. orientation: transpose, flips; eight combinations are distinct for an asymmetric image
    {
      GridPtr src = Make(3, 2, [](int x, int z, int, int) {
        return static_cast<float>(z * 3 + x);
      }); // 0 1 2 / 3 4 5
      OpArgs a;
      a.in["a"] = src;
      Grid out;
      a.p.num["flip_x"] = 1;
      RunField("img_orient", a, out);
      CHECK(out.w == 3 && out.h == 2 && out.At(0, 0) == 2 && out.At(2, 1) == 3, "flip_x");
      a.p.num["flip_x"] = 0;
      a.p.num["flip_z"] = 1;
      RunField("img_orient", a, out);
      CHECK(out.At(0, 0) == 3 && out.At(2, 1) == 2, "flip_z");
      a.p.num["flip_z"] = 0;
      a.p.num["transpose"] = 1;
      RunField("img_orient", a, out);
      CHECK(out.w == 2 && out.h == 3 && out.At(1, 0) == 3 && out.At(0, 2) == 2, "transpose");
      a.p.num["flip_x"] = 1;
      RunField("img_orient", a, out); // a 90 degree turn: rows 3 0 / 4 1 / 5 2
      CHECK(out.At(0, 0) == 3 && out.At(1, 0) == 0 && out.At(0, 2) == 5 && out.At(1, 2) == 2, "transpose + flip_x");
      std::vector<float> seen;
      for (int t = 0; t < 2; ++t)
        for (int fx = 0; fx < 2; ++fx)
          for (int fz = 0; fz < 2; ++fz) {
            OpArgs b;
            b.in["a"] = src;
            b.p.num["transpose"] = t;
            b.p.num["flip_x"] = fx;
            b.p.num["flip_z"] = fz;
            Grid o;
            RunField("img_orient", b, o);
            float key = 0;
            for (std::size_t i = 0; i < o.v.size(); ++i)
              key = key * 7.0f + o.v[i] + 1.0f + static_cast<float>(o.w);
            CHECK(std::find(seen.begin(), seen.end(), key) == seen.end(), "orientation %d%d%d distinct", t, fx, fz);
            seen.push_back(key);
          }
    }

    // 8. rect_mask: hard, feathered inwards, sides left hard
    {
      GridPtr like = std::make_shared<Grid>(21, 21, 1.0f, 0.0f, 0.0f);
      OpArgs a;
      a.in["like"] = like;
      a.p.num["x0"] = 4;
      a.p.num["z0"] = 4;
      a.p.num["x1"] = 16;
      a.p.num["z1"] = 16;
      Grid out;
      RunField("rect_mask", a, out);
      CHECK(
        out.At(4, 4) == 1.0f && out.At(16, 16) == 1.0f && out.At(3, 10) == 0.0f && out.At(17, 10) == 0.0f,
        "hard rectangle"
      );
      a.p.num["feather"] = 4;
      RunField("rect_mask", a, out);
      CHECK(
        out.At(4, 10) == 0.0f && out.At(6, 10) > 0.0f && out.At(6, 10) < 1.0f && out.At(8, 10) == 1.0f &&
          out.At(10, 10) == 1.0f,
        "feather: 0 at the border, 1 after 4 samples"
      );
      CHECK(std::fabs(out.At(6, 10) - 0.5f) < 1e-6f, "smoothstep(0.5) = 0.5 (%f)", out.At(6, 10));
      a.p.num["feather_l"] = 0;
      RunField("rect_mask", a, out);
      CHECK(out.At(4, 10) == 1.0f && out.At(16, 10) == 0.0f, "a hard left side");
    }

    // 9. points_mask: a disc with a soft rim, maximum of overlapping points
    {
      GridPtr like = std::make_shared<Grid>(41, 41, 1.0f, 0.0f, 0.0f);
      OpArgs a;
      a.in["like"] = like;
      a.p.arr["pts"] = {10, 10, 3, 1, 30, 30, 2, 0.5};
      a.p.num["feather"] = 4;
      Grid out;
      RunField("points_mask", a, out);
      CHECK(
        out.At(10, 10) == 1.0f && out.At(13, 10) == 1.0f && out.At(15, 10) > 0.0f && out.At(15, 10) < 1.0f &&
          out.At(17, 10) == 0.0f,
        "disc and rim"
      );
      CHECK(out.At(30, 30) == 0.5f && out.At(25, 25) == 0.0f, "second point value 0.5");
    }
  }
} // namespace
