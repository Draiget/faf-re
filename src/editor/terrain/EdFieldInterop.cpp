// ops for the terrain interop (FAF Studio's docs/projects/editor/TERRAIN_INTEROP.md). Engine independent like
// EdFieldCore; registered through RegisterOp.
//
//   img_resample  a (source image field), like (the target grid: size, cell, origin). Fits `a` over the sample
//   rectangle x0, z0, x1, z1 of `like` (default: all of it; inclusive sample
//                 indices); samples outside the rectangle get `outside` (default 0).
//                 align = cell (default; the image covers the rectangle's cells: pixel k is centred on (k + 0.5) /
//                 width of the rectangle, a 1024 image over a 1025 sample map)
//                       | corner (the first and last pixel sit on the first and last sample: a 1025 image is the
//                       identity)
//                 filter = bilinear (default) | bicubic (Catmull-Rom) | lanczos (a = 3) | nearest. When the image is
//                 larger than the rectangle the kernel is widened by the scale (a proper low pass, no aliasing); edges
//                 replicate. Exact for the identity (weights at integer offsets are exactly 0 / 1).
//   img_orient    a. transpose (0 / 1) swaps x and z, then flip_x, flip_z mirror: together the 8 orientations of a
//   square. Cell 1, origin 0. rect_mask     like. 1 inside the sample rectangle x0, z0, x1, z1 (inclusive), 0 outside;
//   `feather` samples at the rectangle's border rise smoothly from 0 (curve = smooth | linear).
//                 feather_l / feather_r / feather_t / feather_b = 0 keep a side hard (the sides on the map border). The
//                 distance is rectangular (min over the sides).
//   points_mask   like. pts = x, z, radius, value per point (world units): `value` inside the disc, falling to 0 over
//   `feather` world units beyond the radius (smooth); the maximum of all.
//
// Every output sample depends on the inputs only, so results are bit identical for any thread count.
// The golden checksums (tests/editor/FieldTests.cpp) assume no fused multiply-add.
#if defined(__clang__)
#pragma clang fp contract(off)
#else
#pragma fp_contract(off)
#endif

#include "editor/terrain/EdFieldCore.h"

#include <algorithm>
#include <cmath>
#include <cstdint>

namespace faf::editor::field
{
  namespace
  {
    constexpr double kPi = 3.14159265358979323846;

    const Grid* Need(
      const OpArgs& a,
      const char* const name,
      std::string& err
    )
    {
      const auto it = a.in.find(name);
      if (it == a.in.end() || !it->second) {
        err = std::string("missing input field ") + name;
        return nullptr;
      }
      return it->second.get();
    }

    inline double SmoothStep(
      const double t
    )
    {
      const double c = t < 0.0 ? 0.0 : (t > 1.0 ? 1.0 : t);
      return c * c * (3.0 - 2.0 * c);
    }

    // ---- kernels
    // -----------------------------------------------------------------------------------------------------------------------------

    enum class Kind
    {
      Nearest,
      Bilinear,
      Bicubic,
      Lanczos
    };

    double Kernel(
      const Kind kind,
      const double x
    )
    {
      const double ax = std::fabs(x);
      switch (kind) {
      case Kind::Bilinear:
        return ax < 1.0 ? 1.0 - ax : 0.0;
      case Kind::Bicubic: {
        // Catmull-Rom (a = -0.5): 1 at 0, exactly 0 at the other integers
        if (ax <= 1.0)
          return (1.5 * ax - 2.5) * ax * ax + 1.0;
        if (ax < 2.0)
          return ((-0.5 * ax + 2.5) * ax - 4.0) * ax + 2.0;
        return 0.0;
      }
      case Kind::Lanczos: {
        if (ax >= 3.0)
          return 0.0;
        if (ax < 1.0e-12)
          return 1.0;
        if (std::fabs(ax - std::floor(ax + 0.5)) < 1.0e-9)
          return 0.0; // integer offsets are exactly 0 (the identity stays exact)
        const double px = kPi * ax;
        return 3.0 * std::sin(px) * std::sin(px / 3.0) / (px * px);
      }
      default:
        return ax < 0.5 ? 1.0 : 0.0;
      }
    }

    double Support(
      const Kind kind
    )
    {
      switch (kind) {
      case Kind::Bilinear:
        return 1.0;
      case Kind::Bicubic:
        return 2.0;
      case Kind::Lanczos:
        return 3.0;
      default:
        return 0.5;
      }
    }

    struct Taps
    {
      int first = 0;        // index of the first tap (clamped later)
      std::vector<float> w; // normalised weights, w[k] belongs to source index first + k
    };

    /** The taps of every output sample i = 0..out-1. `u(i)` is the source coordinate (pixel k has its centre at k),
     * `scale` the source pixels per output step. */
    std::vector<Taps> BuildTaps(
      const Kind kind,
      const int out,
      const int srcN,
      const double scaleIn,
      const bool cell,
      const int cells
    )
    {
      const double scale = scaleIn < 1.0 ? 1.0 : scaleIn; // widen the kernel when shrinking
      const double radius = Support(kind) * scale;
      std::vector<Taps> taps(static_cast<std::size_t>(out));
      for (int i = 0; i < out; ++i) {
        double u;
        if (cell) {
          u = static_cast<double>(i) * srcN / cells - 0.5;
        } else {
          u = static_cast<double>(i) * (srcN - 1) / cells;
        }
        Taps& t = taps[static_cast<std::size_t>(i)];
        if (kind == Kind::Nearest) {
          t.first = static_cast<int>(std::floor(u + 0.5));
          t.w.assign(1, 1.0f);
          continue;
        }
        const int lo = static_cast<int>(std::floor(u - radius)) + 1;
        const int hi = static_cast<int>(std::floor(u + radius));
        t.first = lo;
        std::vector<double> ws;
        double sum = 0.0;
        for (int k = lo; k <= hi; ++k) {
          const double w = Kernel(kind, (static_cast<double>(k) - u) / scale);
          ws.push_back(w);
          sum += w;
        }
        if (sum == 0.0) {
          t.first = static_cast<int>(std::floor(u + 0.5));
          t.w.assign(1, 1.0f);
          continue;
        }
        t.w.resize(ws.size());
        for (std::size_t k = 0; k < ws.size(); ++k) {
          t.w[k] = static_cast<float>(ws[k] / sum);
        }
      }
      return taps;
    }

    bool OpImgResample(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      const Grid* like = Need(a, "like", err);
      if (src == nullptr || like == nullptr) {
        return false;
      }
      if (src->w < 1 || src->h < 1) {
        err = "img_resample: empty image";
        return false;
      }
      const int x0 = std::max(0, static_cast<int>(a.p.N("x0", 0)));
      const int z0 = std::max(0, static_cast<int>(a.p.N("z0", 0)));
      const int x1 = std::min(like->w - 1, static_cast<int>(a.p.N("x1", like->w - 1)));
      const int z1 = std::min(like->h - 1, static_cast<int>(a.p.N("z1", like->h - 1)));
      if (x1 - x0 < 1 || z1 - z0 < 1) {
        err = "img_resample: the target rectangle is smaller than 2 x 2 samples";
        return false;
      }
      const std::string align = a.p.S("align", "cell");
      const bool cell = align != "corner";
      if (!cell && (src->w < 2 || src->h < 2)) {
        err = "img_resample: corner alignment needs an image of at least 2 x 2";
        return false;
      }
      const std::string fname = a.p.S("filter", "bilinear");
      const Kind kind = fname == "nearest"
        ? Kind::Nearest
        : (fname == "bicubic" ? Kind::Bicubic : (fname == "lanczos" ? Kind::Lanczos : Kind::Bilinear));
      const float outside = static_cast<float>(a.p.N("outside", 0.0));

      const int rw = x1 - x0 + 1;
      const int rh = z1 - z0 + 1;
      const int cx = rw - 1;
      const int cz = rh - 1;
      const double sx = cell ? static_cast<double>(src->w) / cx : static_cast<double>(src->w - 1) / cx;
      const double sz = cell ? static_cast<double>(src->h) / cz : static_cast<double>(src->h - 1) / cz;
      const std::vector<Taps> tx = BuildTaps(kind, rw, src->w, sx, cell, cx);
      const std::vector<Taps> tz = BuildTaps(kind, rh, src->h, sz, cell, cz);

      // pass 1: horizontal, every source row -> rw samples
      std::vector<float> mid(static_cast<std::size_t>(rw) * static_cast<std::size_t>(src->h));
      ParallelFor(src->h, [&](const int y) {
        const float* row = &src->v[static_cast<std::size_t>(y) * static_cast<std::size_t>(src->w)];
        float* dst = &mid[static_cast<std::size_t>(y) * static_cast<std::size_t>(rw)];
        for (int i = 0; i < rw; ++i) {
          const Taps& t = tx[static_cast<std::size_t>(i)];
          double acc = 0.0;
          for (std::size_t k = 0; k < t.w.size(); ++k) {
            const int idx = std::min(src->w - 1, std::max(0, t.first + static_cast<int>(k)));
            acc += static_cast<double>(t.w[k]) * static_cast<double>(row[idx]);
          }
          dst[i] = static_cast<float>(acc);
        }
      });

      // pass 2: vertical
      out = Grid(like->w, like->h, like->cell, like->ox, like->oz, outside);
      ParallelFor(rh, [&](const int j) {
        const Taps& t = tz[static_cast<std::size_t>(j)];
        float* dst =
          &out.v[static_cast<std::size_t>(z0 + j) * static_cast<std::size_t>(out.w) + static_cast<std::size_t>(x0)];
        for (int i = 0; i < rw; ++i) {
          double acc = 0.0;
          for (std::size_t k = 0; k < t.w.size(); ++k) {
            const int idx = std::min(src->h - 1, std::max(0, t.first + static_cast<int>(k)));
            acc += static_cast<double>(t.w[k]) *
              static_cast<double>(
                     mid[static_cast<std::size_t>(idx) * static_cast<std::size_t>(rw) + static_cast<std::size_t>(i)]
              );
          }
          dst[i] = static_cast<float>(acc);
        }
      });
      return true;
    }

    // ---- orientation
    // -------------------------------------------------------------------------------------------------------------------------

    bool OpImgOrient(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      if (src == nullptr) {
        return false;
      }
      const bool transpose = a.p.N("transpose", 0) > 0.5;
      const bool fx = a.p.N("flip_x", 0) > 0.5;
      const bool fz = a.p.N("flip_z", 0) > 0.5;
      const int w = transpose ? src->h : src->w;
      const int h = transpose ? src->w : src->h;
      out = Grid(w, h, 1.0f, 0.0f, 0.0f);
      ParallelFor(h, [&](const int z) {
        for (int x = 0; x < w; ++x) {
          const int px = fx ? w - 1 - x : x;
          const int pz = fz ? h - 1 - z : z;
          // (px, pz) in the oriented image; before the flips it came from the (possibly transposed) source
          out.At(x, z) = transpose ? src->At(pz, px) : src->At(px, pz);
        }
      });
      return true;
    }

    // ---- masks
    // -------------------------------------------------------------------------------------------------------------------------------

    bool OpRectMask(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* like = Need(a, "like", err);
      if (like == nullptr) {
        return false;
      }
      const int x0 = static_cast<int>(a.p.N("x0", 0));
      const int z0 = static_cast<int>(a.p.N("z0", 0));
      const int x1 = static_cast<int>(a.p.N("x1", like->w - 1));
      const int z1 = static_cast<int>(a.p.N("z1", like->h - 1));
      const double feather = std::max(0.0, a.p.N("feather", 0.0));
      const bool smooth = a.p.S("curve", "smooth") != "linear";
      const bool fl = a.p.N("feather_l", 1) > 0.5;
      const bool fr = a.p.N("feather_r", 1) > 0.5;
      const bool ft = a.p.N("feather_t", 1) > 0.5;
      const bool fb = a.p.N("feather_b", 1) > 0.5;
      out = Grid(like->w, like->h, like->cell, like->ox, like->oz, 0.0f);
      ParallelFor(like->h, [&](const int z) {
        if (z < z0 || z > z1)
          return;
        for (int x = x0 < 0 ? 0 : x0; x <= x1 && x < like->w; ++x) {
          double t = 1.0;
          if (feather > 0.0) {
            if (fl)
              t = std::min(t, (x - x0) / feather);
            if (fr)
              t = std::min(t, (x1 - x) / feather);
            if (ft)
              t = std::min(t, (z - z0) / feather);
            if (fb)
              t = std::min(t, (z1 - z) / feather);
            t = smooth ? SmoothStep(t) : (t < 0.0 ? 0.0 : (t > 1.0 ? 1.0 : t));
          }
          out.At(x, z) = static_cast<float>(t);
        }
      });
      return true;
    }

    bool OpPointsMask(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* like = Need(a, "like", err);
      if (like == nullptr) {
        return false;
      }
      const std::vector<double>* pts = a.p.A("pts");
      const double feather = std::max(0.0, a.p.N("feather", 0.0));
      out = Grid(like->w, like->h, like->cell, like->ox, like->oz, 0.0f);
      if (pts == nullptr || pts->size() < 4) {
        return true;
      }
      const std::size_t count = pts->size() / 4;
      ParallelFor(like->h, [&](const int z) {
        const double wz = like->oz + static_cast<double>(z) * like->cell;
        for (int x = 0; x < like->w; ++x) {
          const double wx = like->ox + static_cast<double>(x) * like->cell;
          double best = 0.0;
          for (std::size_t k = 0; k < count; ++k) {
            const double px = (*pts)[k * 4 + 0];
            const double pz = (*pts)[k * 4 + 1];
            const double r = (*pts)[k * 4 + 2];
            const double value = (*pts)[k * 4 + 3];
            const double reach = r + feather;
            const double dz = wz - pz;
            if (dz > reach || dz < -reach)
              continue;
            const double dx = wx - px;
            if (dx > reach || dx < -reach)
              continue;
            const double d = std::sqrt(dx * dx + dz * dz);
            double t;
            if (d <= r)
              t = 1.0;
            else if (feather <= 0.0 || d >= reach)
              continue;
            else
              t = 1.0 - SmoothStep((d - r) / feather);
            best = std::max(best, t * value);
          }
          out.At(x, z) = static_cast<float>(best);
        }
      });
      return true;
    }

    struct Registrar
    {
      Registrar()
      {
        RegisterOp("img_resample", &OpImgResample);
        RegisterOp("img_orient", &OpImgOrient);
        RegisterOp("rect_mask", &OpRectMask);
        RegisterOp("points_mask", &OpPointsMask);
      }
    };
    const Registrar gRegistrar;
  } // namespace
} // namespace faf::editor::field
