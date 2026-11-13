// Supreme Commander specific ops of the field engine (FAF Studio's docs/projects/editor/TERRAIN_GEN_DESIGN.md, stage
// T6). Engine independent like EdFieldCore; registered through RegisterOp.
//
//   pad_flatten  a = heights. Base pads and resource rings: every pad is a flat square core (edges snapped outward to
//   the build grid, so whole cells are level) with a smooth skirt.
//                `pads` = 6 numbers per pad: x, z, half (half size of the core, world units), skirt (width of the blend
//                beyond the core), y (absolute target height, used when group == -1), group. group 0: the pad is
//                levelled to its own ground (mean | min | max of the core, `level` 0 | 1 | 2); group k >= 1: all pads
//                of the group share ONE height (the same statistic over all their cores: a mass cluster on one level);
//                group -1: y. Pads apply in list order (a later pad wins where they overlap). `grid` (default 1) is the
//                build grid in world units, `snap` (default 1) 0 keeps the exact rectangle, `word` (default 128)
//                quantises targets to 1 / word units (0 = off), `strength` 0..1, `output` height | weight (the largest
//                pad weight, 0..1) | core (1 inside any core).
//   symmetrize   a = any field. The master wedge of the map is copied onto the rest by the symmetry group: mode
//   mirror_x | mirror_z | mirror_xz | diag | adiag | diag_both | rot2 | rot4 |
//                rotn (n = `n`, any N-fold turn). Centre cx, cz (world; default the middle of the field), `side` /
//                `sector` picks the master wedge (0 .. wedges - 1, larger / negative values wrap; mirrors across one
//                line 2 wedges, rot2 2, rot4 / mirror_xz / diag_both 4, rotn n; side 0 is the left / upper half or
//                quadrant like the `mirror` op), `angle` (degrees) turns the layout of the wedges: the start of wedge 0
//                of rotn, or added to the default start (180 degrees) of rot2 / rot4. `combine` copy (the master wedge,
//                default) | avg | max | min over all images; `nearest` 1 reads the closest sample instead of
//                interpolating (codes such as terrain types, no seam); `seam` (world units, copy only) cross-fades
//                every wedge border: near a border the value blends towards the neighbouring image (the master turned /
//                mirrored over that border), weight 0.5 on the border falling to 0 over `seam` (smoothstep), so the
//                result is continuous across the borders (a turn joins the two borders of the master, which hold
//                unrelated contents). Every output is a function of the input and the group alone, so the result is
//                invariant under the group exactly when the centre lies on a lattice point (or half lattice) and the
//                group is made of quarter turns / mirrors. Only images that lie inside the field count (a turn or
//                diagonal mirror of a map that is not square maps part of it outside itself: such a sample takes the
//                image closest to the master wedge that does exist, instead of an edge clamped value).
//   slope_limit  a = heights. Makes every neighbouring pair of samples differ by at most (limit - margin) * cell: the
//   engine's pathing rule (the steepest neighbouring difference over a
//                footprint window, 0.75 blocks land units) then holds for every unit class. Exact in two sweeps:
//                `lower` = the highest Lipschitz surface below the input (cuts peaks), `raise` = the lowest above it
//                (fills valleys), `both` blends the two with `balance` (0 raise .. 1 lower). `mask` (0..1) blends the
//                result into the input, `strength` too.
//   reach        a = passable mask (>= 0.5 passable), optional b = cost multiplier (>= 1). Travel distance (world
//   units, 8 neighbours without corner cutting) from the sources
//                `src` (x, z pairs, world; snapped to the nearest passable sample within `snap` samples, default 4).
//                Not reachable: `unreach` (default -1).
//   regions      a = passable mask. Connected regions of passable samples (connectivity 4 | 8, default 8 without corner
//   cutting): mode label (1..N in raster order, 0 blocked, default) |
//                size (area of the region in world units squared).
//
// Every output sample is computed from the inputs alone (the sweeps and the search are sequential and ordered), so the
// results are bit identical for any thread count. The golden checksums (tests/editor/FieldTests.cpp) assume no fused
// multiply-add.
#if defined(__clang__)
#pragma clang fp contract(off)
#else
#pragma fp_contract(off)
#endif

#include "editor/terrain/EdFieldCore.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <queue>

namespace faf::editor::field
{
  namespace
  {
    constexpr double kPi = 3.14159265358979323846;
    constexpr int kChunk = 8;

    inline double F32(
      const double v
    )
    {
      return static_cast<double>(static_cast<float>(v));
    }
    inline double Clamp01(
      const double v
    )
    {
      return v < 0.0 ? 0.0 : (v > 1.0 ? 1.0 : v);
    }
    inline double SmoothStep(
      const double t
    )
    {
      const double c = Clamp01(t);
      return c * c * (3.0 - 2.0 * c);
    }

    const Grid* Get(
      const OpArgs& a,
      const char* const key
    )
    {
      const auto it = a.in.find(key);
      return it != a.in.end() ? it->second.get() : nullptr;
    }

    const Grid* Need(
      const OpArgs& a,
      const char* const key,
      std::string& err
    )
    {
      const Grid* g = Get(a, key);
      if (g == nullptr) {
        err = std::string("missing input '") + key + "'";
      }
      return g;
    }

    template <class F>
    void Rows(
      const int h,
      F&& f
    )
    {
      const int chunks = (h + kChunk - 1) / kChunk;
      ParallelFor(chunks, [&](const int c) {
        const int z0 = c * kChunk;
        f(z0, std::min(h, z0 + kChunk));
      });
    }

    inline double WX(
      const Grid& g,
      const int x
    )
    {
      return static_cast<double>(g.ox) + static_cast<double>(x) * static_cast<double>(g.cell);
    }
    inline double WZ(
      const Grid& g,
      const int z
    )
    {
      return static_cast<double>(g.oz) + static_cast<double>(z) * static_cast<double>(g.cell);
    }

    // ---- pad_flatten
    // ----------------------------------------------------------------------------------------------------------------------------

    struct Pad
    {
      double x0, z0, x1, z1; // the snapped core rectangle (world)
      double skirt;
      double target;
      double y;
      int group;
      double bx0, bz0, bx1, bz1; // bounding box including the skirt
    };

    double Weight(
      const Pad& p,
      const double wx,
      const double wz
    )
    {
      const double dx = std::max(std::max(p.x0 - wx, wx - p.x1), 0.0);
      const double dz = std::max(std::max(p.z0 - wz, wz - p.z1), 0.0);
      if (dx == 0.0 && dz == 0.0)
        return 1.0;
      if (p.skirt <= 0.0)
        return 0.0;
      const double d = std::sqrt(dx * dx + dz * dz);
      if (d >= p.skirt)
        return 0.0;
      return 1.0 - SmoothStep(d / p.skirt);
    }

    bool OpPadFlatten(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      if (src == nullptr)
        return false;
      const std::vector<double>* v = a.p.A("pads");
      if (v == nullptr || v->size() % 6 != 0) {
        err = "'pads' needs 6 numbers per pad (x, z, half, skirt, y, group)";
        return false;
      }
      const std::string output = a.p.S("output", "height");
      if (output != "height" && output != "weight" && output != "core") {
        err = "output must be height, weight or core";
        return false;
      }
      const double grid = std::max(1e-6, a.p.N("grid", 1.0));
      const bool snap = a.p.N("snap", 1.0) != 0.0;
      const double word = a.p.N("word", 128.0);
      const int level = static_cast<int>(a.p.N("level", 0.0));
      const double strength = Clamp01(a.p.N("strength", 1.0));
      std::vector<Pad> pads(v->size() / 6);
      for (std::size_t i = 0; i < pads.size(); ++i) {
        const double* q = v->data() + i * 6;
        Pad& p = pads[i];
        const double x = F32(q[0]), z = F32(q[1]);
        const double half = std::max(0.0, F32(q[2]));
        p.skirt = std::max(0.0, F32(q[3]));
        p.y = F32(q[4]);
        p.group = static_cast<int>(std::lround(q[5]));
        p.x0 = x - half;
        p.x1 = x + half;
        p.z0 = z - half;
        p.z1 = z + half;
        if (snap) {
          p.x0 = std::floor(p.x0 / grid + 1e-9) * grid;
          p.z0 = std::floor(p.z0 / grid + 1e-9) * grid;
          p.x1 = std::ceil(p.x1 / grid - 1e-9) * grid;
          p.z1 = std::ceil(p.z1 / grid - 1e-9) * grid;
          if (p.x1 <= p.x0)
            p.x1 = p.x0 + grid;
          if (p.z1 <= p.z0)
            p.z1 = p.z0 + grid;
        }
        p.bx0 = p.x0 - p.skirt;
        p.bx1 = p.x1 + p.skirt;
        p.bz0 = p.z0 - p.skirt;
        p.bz1 = p.z1 + p.skirt;
        p.target = 0.0;
      }
      // targets: statistic of the core samples of the INPUT, one value per pad or per group (sequential, fixed order)
      struct Acc
      {
        double sum = 0.0, lo = 1e30, hi = -1e30;
        long long n = 0;
      };
      const auto Core = [&](const Pad& p, Acc& acc) {
        const int ix0 = std::max(0, static_cast<int>(std::ceil((p.x0 - src->ox) / src->cell - 1e-9)));
        const int ix1 = std::min(src->w - 1, static_cast<int>(std::floor((p.x1 - src->ox) / src->cell + 1e-9)));
        const int iz0 = std::max(0, static_cast<int>(std::ceil((p.z0 - src->oz) / src->cell - 1e-9)));
        const int iz1 = std::min(src->h - 1, static_cast<int>(std::floor((p.z1 - src->oz) / src->cell + 1e-9)));
        for (int z = iz0; z <= iz1; ++z) {
          for (int x = ix0; x <= ix1; ++x) {
            const double h = src->At(x, z);
            acc.sum += h;
            acc.lo = std::min(acc.lo, h);
            acc.hi = std::max(acc.hi, h);
            ++acc.n;
          }
        }
      };
      const auto Value = [&](const Acc& acc, const Pad& p) {
        if (acc.n == 0)
          return static_cast<double>(SampleWorld(*src, 0.5 * (p.x0 + p.x1), 0.5 * (p.z0 + p.z1)));
        return level == 1 ? acc.lo : (level == 2 ? acc.hi : acc.sum / static_cast<double>(acc.n));
      };
      std::map<int, Acc> groups;
      for (const Pad& p : pads) {
        if (p.group >= 1)
          Core(p, groups[p.group]);
      }
      for (Pad& p : pads) {
        if (p.group == -1) {
          p.target = p.y;
        } else if (p.group >= 1) {
          p.target = Value(groups[p.group], p);
        } else {
          Acc acc;
          Core(p, acc);
          p.target = Value(acc, p);
        }
        if (word > 0.0)
          p.target = std::floor(p.target * word + 0.5) / word;
        p.target = F32(p.target);
      }
      out = *src;
      const int w = src->w;
      const int h = src->h;
      Rows(h, [&](const int z0, const int z1) {
        for (int z = z0; z < z1; ++z) {
          const double wz = WZ(*src, z);
          for (int x = 0; x < w; ++x) {
            const double wx = WX(*src, x);
            double height = src->At(x, z);
            double wmax = 0.0;
            bool core = false;
            for (const Pad& p : pads) {
              if (wx < p.bx0 || wx > p.bx1 || wz < p.bz0 || wz > p.bz1)
                continue;
              const double wgt = Weight(p, wx, wz);
              if (wgt <= 0.0)
                continue;
              wmax = std::max(wmax, wgt);
              if (wgt >= 1.0)
                core = true;
              const double s = wgt * strength;
              height = (s >= 1.0) ? p.target : height + (p.target - height) * s;
            }
            float r;
            if (output == "weight")
              r = static_cast<float>(wmax * strength);
            else if (output == "core")
              r = core ? 1.0f : 0.0f;
            else
              r = static_cast<float>(height);
            out.At(x, z) = r;
          }
        }
      });
      return true;
    }

    // ---- symmetrize
    // -----------------------------------------------------------------------------------------------------------------------------

    struct Mat
    {
      double a, b, c, d; // (u, v) -> (a u + b v, c u + d v)
    };

    inline double Snap(
      const double v
    )
    {
      if (std::fabs(v) < 1e-9)
        return 0.0;
      if (std::fabs(v - 1.0) < 1e-9)
        return 1.0;
      if (std::fabs(v + 1.0) < 1e-9)
        return -1.0;
      return v;
    }

    Mat Rot(
      const double ang
    )
    {
      return {Snap(std::cos(ang)), Snap(-std::sin(ang)), Snap(std::sin(ang)), Snap(std::cos(ang))};
    }

    /** Reflection across the line through the origin at angle `ang`. */
    Mat Refl(
      const double ang
    )
    {
      return {
        Snap(std::cos(2.0 * ang)), Snap(std::sin(2.0 * ang)), Snap(std::sin(2.0 * ang)), Snap(-std::cos(2.0 * ang))
      };
    }

    struct Group
    {
      std::vector<Mat> m;    // the group elements about the centre, m[0] is the identity
      double a0 = 0.0;       // start angle of wedge 0 (radians, atan2(z, x) of the field)
      double width = 0.0;    // width of every wedge
      bool mirrored = false; // dihedral group: the wedge borders are mirror lines
    };

    /** Mode / n / angle -> the group. `angle` (degrees) turns the start of wedge 0: for rotn it IS the start angle, for
     * rot2 / rot4 it is added to their default start (180 degrees: wedge 0 is the upper half / upper left quarter), for
     * the mirror modes it is ignored. Wedge k runs from a0 + k * width to a0 + (k + 1) * width (increasing angle =
     * clockwise on a map that has z pointing down), the same numbering the Symmetry panel's "Symmetrise from" parts
     * use. */
    bool BuildGroup(
      const std::string& mode,
      const OpArgs& a,
      Group& g,
      std::string& err
    )
    {
      int n = 1;
      bool mirrored = false;
      double axis = 0.0; // for dihedral groups: the angle of a mirror line = start of wedge 0
      double a0 = 0.0;
      const double turn = a.p.N("angle", 0.0) * kPi / 180.0;
      if (mode == "mirror_x") {
        n = 1;
        mirrored = true;
        axis = kPi / 2.0;
      } else if (mode == "mirror_z") {
        n = 1;
        mirrored = true;
        axis = kPi;
      } else if (mode == "mirror_xz") {
        n = 2;
        mirrored = true;
        axis = kPi;
      } else if (mode == "diag") {
        n = 1;
        mirrored = true;
        axis = kPi / 4.0;
      } else if (mode == "adiag") {
        n = 1;
        mirrored = true;
        axis = 3.0 * kPi / 4.0;
      } else if (mode == "diag_both") {
        n = 2;
        mirrored = true;
        axis = kPi / 4.0;
      } else if (mode == "rot2") {
        n = 2;
        a0 = kPi + turn;
      } else if (mode == "rot4") {
        n = 4;
        a0 = kPi + turn;
      } else if (mode == "rotn") {
        n = static_cast<int>(std::lround(a.p.N("n", 3.0)));
        if (n < 2 || n > 16) {
          err = "symmetrize: rotn needs 2 <= n <= 16";
          return false;
        }
        a0 = turn;
      } else {
        err = "symmetrize: unknown mode '" + mode + "'";
        return false;
      }
      for (int k = 0; k < n; ++k) {
        g.m.push_back(Rot(2.0 * kPi * k / n));
      }
      g.mirrored = mirrored;
      if (mirrored) {
        // mirror lines at axis + k * pi / n
        for (int k = 0; k < n; ++k) {
          g.m.push_back(Refl(axis + kPi * k / n));
        }
        g.a0 = axis;
        g.width = kPi / n;
      } else {
        g.a0 = a0;
        g.width = 2.0 * kPi / n;
      }
      return true;
    }

    float Bilinear(
      const Grid& g,
      const double sx,
      const double sz,
      const bool nearest = false
    )
    {
      if (nearest) {
        const int ix = static_cast<int>(std::max(0.0, std::min(static_cast<double>(g.w - 1), std::floor(sx + 0.5))));
        const int iz = static_cast<int>(std::max(0.0, std::min(static_cast<double>(g.h - 1), std::floor(sz + 0.5))));
        return g.At(ix, iz);
      }
      const double cx = std::max(0.0, std::min(static_cast<double>(g.w - 1), sx));
      const double cz = std::max(0.0, std::min(static_cast<double>(g.h - 1), sz));
      const int x0 = static_cast<int>(std::floor(cx));
      const int z0 = static_cast<int>(std::floor(cz));
      const int x1 = std::min(g.w - 1, x0 + 1);
      const int z1 = std::min(g.h - 1, z0 + 1);
      const double fx = cx - x0, fz = cz - z0;
      if (fx == 0.0 && fz == 0.0)
        return g.At(x0, z0);
      const double top = g.At(x0, z0) * (1.0 - fx) + g.At(x1, z0) * fx;
      const double bot = g.At(x0, z1) * (1.0 - fx) + g.At(x1, z1) * fx;
      return static_cast<float>(top * (1.0 - fz) + bot * fz);
    }

    /** Reads the source at a world position. False when the position lies outside the field (nothing is read: a turn of
     * a map that is not square, or a diagonal mirror of one, maps part of the map outside itself, and clamping to the
     * edge would paint a smear of edge values). A position within 1e-7 of a sample snaps onto it (exact copies for 90
     * degree turns / mirrors). */
    struct Reader
    {
      const Grid& g;
      double inv;
      bool nearest;
      bool Read(
        const double wx,
        const double wz,
        float& out
      ) const
      {
        double sx = (wx - static_cast<double>(g.ox)) * inv;
        double sz = (wz - static_cast<double>(g.oz)) * inv;
        constexpr double kOut = 1e-6;
        if (
          sx < -kOut || sz < -kOut || sx > static_cast<double>(g.w - 1) + kOut ||
          sz > static_cast<double>(g.h - 1) + kOut
        )
          return false;
        const double rx = std::round(sx), rz = std::round(sz);
        if (std::fabs(sx - rx) < 1e-7)
          sx = rx;
        if (std::fabs(sz - rz) < 1e-7)
          sz = rz;
        out = Bilinear(g, sx, sz, nearest);
        return true;
      }
    };

    inline bool SameMat(
      const Mat& p,
      const Mat& q
    )
    {
      return std::fabs(p.a - q.a) < 1e-9 && std::fabs(p.b - q.b) < 1e-9 && std::fabs(p.c - q.c) < 1e-9 &&
        std::fabs(p.d - q.d) < 1e-9;
    }

    /** Distance from a point at radius r and angle `ang` from a border ray (which starts at the centre) to that ray. */
    inline double RayDistance(
      const double r,
      const double ang
    )
    {
      return ang >= kPi / 2.0 ? r : r * std::sin(ang);
    }

    // The result at every sample is a function of the source and the group alone:
    //   copy      the value of the point's image inside the master wedge, i.e. the orbit point of the group with the
    //   SMALLEST angle from the start of the master wedge (the master wedge is
    //             the half open angle range [start, start + width), so a point on its closing border takes the image on
    //             the opening border; a mirror line is its own image). Only images inside the field count: on a map
    //             that is not square a 90 degree turn can map a point out of the field, then the nearest-to-master
    //             image inside it is used, so the result is still exactly symmetric wherever the map is.
    //   seam > 0  soft wedge borders. Near a border the image blends towards the NEIGHBOUR image across that border
    //   (the master content mirrored / turned over the border; what the
    //             next wedge would show), with weight 0.5 on the border falling to 0 over `seam` units (smoothstep): on
    //             the border both sides compute the same blend, so the result is continuous across it (a turn has no
    //             other way to join two arbitrary wedge contents).
    //   avg, max, min   over all images inside the field (exactly symmetric, no master wedge).
    bool OpSymmetrize(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      if (src == nullptr)
        return false;
      Group grp;
      const std::string mode = a.p.S("mode", "mirror_x");
      if (!BuildGroup(mode, a, grp, err))
        return false;
      const std::string combine = a.p.S("combine", "copy");
      if (combine != "copy" && combine != "avg" && combine != "max" && combine != "min") {
        err = "symmetrize: combine must be copy, avg, max or min";
        return false;
      }
      const int combineMode = combine == "copy" ? 0 : (combine == "avg" ? 1 : (combine == "max" ? 2 : 3));
      const int count = static_cast<int>(grp.m.size());
      int wedge = static_cast<int>(std::lround(a.p.Has("sector") ? a.p.N("sector", 0.0) : a.p.N("side", 0.0)));
      wedge = ((wedge % count) + count) % count;
      const double cx = a.p.Has("cx")
        ? F32(a.p.N("cx", 0.0))
        : static_cast<double>(src->ox) + 0.5 * (src->w - 1) * static_cast<double>(src->cell);
      const double cz = a.p.Has("cz")
        ? F32(a.p.N("cz", 0.0))
        : static_cast<double>(src->oz) + 0.5 * (src->h - 1) * static_cast<double>(src->cell);
      const bool nearest = a.p.N("nearest", 0.0) != 0.0;
      const double seam =
        nearest ? 0.0 : std::max(0.0, a.p.N("seam", 0.0)); // blending codes (terrain types) makes no sense
      const double start = grp.a0 + wedge * grp.width;
      const double width = grp.width;
      // the image that a point near the opening / closing border of the master wedge blends towards. Mirrors: its
      // reflection over that border line (the content on the other side of the line). Turns: the wedge next to the
      // master is the master turned by +width (over the closing border) / -width (over the opening border), so what
      // continues the master across its closing border is the master's own opening border turned back (rotation by
      // -width), and the other way round
      const Mat tOpen = grp.mirrored ? Refl(start) : Rot(width);
      const Mat tClose = grp.mirrored ? Refl(start + width) : Rot(-width);
      const bool oneLine = SameMat(tOpen, tClose); // mirror_x / z, diag, adiag, rot2: both borders lie on one line
      const double kTol = 1e-9;
      out = *src;
      const Reader rd{*src, 1.0 / static_cast<double>(src->cell), nearest};
      Rows(src->h, [&](const int z0, const int z1) {
        for (int z = z0; z < z1; ++z) {
          for (int x = 0; x < src->w; ++x) {
            const double u = WX(*src, x) - cx;
            const double v = WZ(*src, z) - cz;
            const double r = std::sqrt(u * u + v * v);
            int cnt = 0;
            double sum = 0.0, mx = 0.0, mn = 0.0;
            double bestPh = 1e30, bu = u, bv = v;
            float bestVal = src->At(x, z);
            for (int i = 0; i < count; ++i) {
              const Mat& m = grp.m[static_cast<std::size_t>(i)];
              const double qu = m.a * u + m.b * v;
              const double qv = m.c * u + m.d * v;
              float val;
              if (!rd.Read(cx + qu, cz + qv, val))
                continue;
              if (cnt == 0) {
                mx = val;
                mn = val;
              } else {
                mx = std::max(mx, static_cast<double>(val));
                mn = std::min(mn, static_cast<double>(val));
              }
              sum += val;
              ++cnt;
              if (combineMode == 0) {
                // angle of the image from the start of the master wedge, in [0, 2 pi); just below 2 pi is the opening
                // border seen from the other side
                double ph = (qu == 0.0 && qv == 0.0) ? 0.0 : std::fmod(std::atan2(qv, qu) - start, 2.0 * kPi);
                if (ph < 0.0)
                  ph += 2.0 * kPi;
                if (ph > 2.0 * kPi - kTol)
                  ph = 0.0;
                if (ph < bestPh - kTol) {
                  bestPh = ph;
                  bestVal = val;
                  bu = qu;
                  bv = qv;
                }
              }
            }
            float result;
            if (combineMode == 0) {
              double value = bestVal;
              if (seam > 0.0 && bestPh <= width + kTol && r > 0.0) {
                // the image is in the master wedge: blend towards the neighbour images over the borders
                const double psi = std::min(bestPh, width);
                const double dOpen = RayDistance(r, psi);
                const double dClose = RayDistance(r, width - psi);
                double wOpen = 0.0, wClose = 0.0;
                if (oneLine)
                  wOpen = 0.5 * (1.0 - SmoothStep(std::min(dOpen, dClose) / seam));
                else {
                  wOpen = 0.5 * (1.0 - SmoothStep(dOpen / seam));
                  wClose = 0.5 * (1.0 - SmoothStep(dClose / seam));
                }
                float nb;
                if (wOpen > 0.0 && rd.Read(cx + tOpen.a * bu + tOpen.b * bv, cz + tOpen.c * bu + tOpen.d * bv, nb))
                  value += wOpen * (static_cast<double>(nb) - static_cast<double>(bestVal));
                if (wClose > 0.0 && rd.Read(cx + tClose.a * bu + tClose.b * bv, cz + tClose.c * bu + tClose.d * bv, nb))
                  value += wClose * (static_cast<double>(nb) - static_cast<double>(bestVal));
              }
              result = static_cast<float>(value);
            } else if (combineMode == 1) {
              result = static_cast<float>(sum / cnt);
            } else {
              result = static_cast<float>(combineMode == 2 ? mx : mn);
            }
            out.At(x, z) = result;
          }
        }
      });
      return true;
    }

    // ---- slope_limit
    // ----------------------------------------------------------------------------------------------------------------------------

    bool OpSlopeLimit(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      if (src == nullptr)
        return false;
      const std::string mode = a.p.S("mode", "both");
      if (mode != "lower" && mode != "raise" && mode != "both") {
        err = "slope_limit: mode must be lower, raise or both";
        return false;
      }
      const double limit = a.p.N("limit", 0.75);
      const double margin = std::max(0.0, a.p.N("margin", 0.03));
      const double balance = Clamp01(a.p.N("balance", 0.5));
      const double strength = Clamp01(a.p.N("strength", 1.0));
      const Grid* mask = Get(a, "mask");
      if (mask != nullptr && !mask->SameShape(*src)) {
        err = "'mask' must have the shape of 'a'";
        return false;
      }
      const double L = std::max(0.0, (limit - margin)) * static_cast<double>(src->cell);
      const int w = src->w;
      const int h = src->h;
      const std::size_t n = src->Count();
      const auto Envelope = [&](const bool lower) {
        std::vector<double> g(n);
        for (std::size_t i = 0; i < n; ++i)
          g[i] = src->v[i];
        const double sgn = lower ? 1.0 : -1.0; // raise = lower envelope of the negated field, negated back
        if (!lower)
          for (std::size_t i = 0; i < n; ++i)
            g[i] = -g[i];
        (void)sgn;
        for (int z = 0; z < h; ++z) {
          for (int x = 0; x < w; ++x) {
            double& c = g[static_cast<std::size_t>(z) * w + x];
            if (x > 0)
              c = std::min(c, g[static_cast<std::size_t>(z) * w + x - 1] + L);
            if (z > 0)
              c = std::min(c, g[static_cast<std::size_t>(z - 1) * w + x] + L);
          }
        }
        for (int z = h - 1; z >= 0; --z) {
          for (int x = w - 1; x >= 0; --x) {
            double& c = g[static_cast<std::size_t>(z) * w + x];
            if (x < w - 1)
              c = std::min(c, g[static_cast<std::size_t>(z) * w + x + 1] + L);
            if (z < h - 1)
              c = std::min(c, g[static_cast<std::size_t>(z + 1) * w + x] + L);
          }
        }
        if (!lower)
          for (std::size_t i = 0; i < n; ++i)
            g[i] = -g[i];
        return g;
      };
      std::vector<double> lo, hi;
      if (mode != "raise")
        lo = Envelope(true);
      if (mode != "lower")
        hi = Envelope(false);
      out = *src;
      for (std::size_t i = 0; i < n; ++i) {
        double r;
        if (mode == "lower")
          r = lo[i];
        else if (mode == "raise")
          r = hi[i];
        else
          r = hi[i] + (lo[i] - hi[i]) * balance;
        double s = strength;
        if (mask != nullptr)
          s *= Clamp01(mask->v[i]);
        out.v[i] = static_cast<float>(static_cast<double>(src->v[i]) + (r - static_cast<double>(src->v[i])) * s);
      }
      return true;
    }

    // ---- reach and regions
    // ----------------------------------------------------------------------------------------------------------------------

    inline bool Pass(
      const Grid& m,
      const int x,
      const int z
    )
    {
      return m.At(x, z) >= 0.5f;
    }

    bool OpReach(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* pass = Need(a, "a", err);
      if (pass == nullptr)
        return false;
      const Grid* cost = Get(a, "b");
      if (cost != nullptr && !cost->SameShape(*pass)) {
        err = "reach: 'b' must have the shape of 'a'";
        return false;
      }
      const std::vector<double>* src = a.p.A("src");
      if (src == nullptr || src->empty() || src->size() % 2 != 0) {
        err = "reach: 'src' needs x, z pairs";
        return false;
      }
      const int w = pass->w;
      const int h = pass->h;
      const float unreach = static_cast<float>(a.p.N("unreach", -1.0));
      const int snapR = std::max(0, static_cast<int>(a.p.N("snap", 4.0)));
      const double cell = pass->cell;
      out = Grid(w, h, pass->cell, pass->ox, pass->oz, unreach);
      std::vector<double> dist(pass->Count(), std::numeric_limits<double>::infinity());
      using Item = std::pair<double, std::size_t>;
      std::priority_queue<Item, std::vector<Item>, std::greater<Item>> pq;
      for (std::size_t i = 0; i + 1 < src->size(); i += 2) {
        const double fx = ((*src)[i] - pass->ox) / cell;
        const double fz = ((*src)[i + 1] - pass->oz) / cell;
        const int cx = static_cast<int>(std::lround(fx));
        const int cz = static_cast<int>(std::lround(fz));
        int bx = -1, bz = -1;
        double bestD = 1e30;
        for (int dz = -snapR; dz <= snapR; ++dz) {
          for (int dx = -snapR; dx <= snapR; ++dx) {
            const int x = cx + dx, z = cz + dz;
            if (x < 0 || z < 0 || x >= w || z >= h || !Pass(*pass, x, z))
              continue;
            const double d = (x - fx) * (x - fx) + (z - fz) * (z - fz);
            if (d < bestD) {
              bestD = d;
              bx = x;
              bz = z;
            }
          }
        }
        if (bx >= 0) {
          const std::size_t id = static_cast<std::size_t>(bz) * w + bx;
          if (dist[id] > 0.0) {
            dist[id] = 0.0;
            pq.push({0.0, id});
          }
        }
      }
      static const int dxs[8] = {1, -1, 0, 0, 1, 1, -1, -1};
      static const int dzs[8] = {0, 0, 1, -1, 1, -1, 1, -1};
      while (!pq.empty()) {
        const Item it = pq.top();
        pq.pop();
        if (it.first > dist[it.second])
          continue;
        const int x = static_cast<int>(it.second % static_cast<std::size_t>(w));
        const int z = static_cast<int>(it.second / static_cast<std::size_t>(w));
        for (int k = 0; k < 8; ++k) {
          const int nx = x + dxs[k], nz = z + dzs[k];
          if (nx < 0 || nz < 0 || nx >= w || nz >= h || !Pass(*pass, nx, nz))
            continue;
          if (k >= 4 && (!Pass(*pass, x + dxs[k], z) || !Pass(*pass, x, z + dzs[k])))
            continue; // no corner cutting
          double step = (k < 4 ? 1.0 : 1.4142135623730951) * cell;
          const std::size_t nid = static_cast<std::size_t>(nz) * w + nx;
          if (cost != nullptr)
            step *= 0.5 *
              (std::max(1.0, static_cast<double>(cost->v[it.second])) +
               std::max(1.0, static_cast<double>(cost->v[nid])));
          const double nd = it.first + step;
          if (nd < dist[nid]) {
            dist[nid] = nd;
            pq.push({nd, nid});
          }
        }
      }
      for (std::size_t i = 0; i < dist.size(); ++i) {
        if (dist[i] != std::numeric_limits<double>::infinity())
          out.v[i] = static_cast<float>(dist[i]);
      }
      return true;
    }

    bool OpRegions(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* pass = Need(a, "a", err);
      if (pass == nullptr)
        return false;
      const std::string mode = a.p.S("mode", "label");
      if (mode != "label" && mode != "size") {
        err = "regions: mode must be label or size";
        return false;
      }
      const int conn = a.p.N("connectivity", 8.0) == 4.0 ? 4 : 8;
      const int w = pass->w;
      const int h = pass->h;
      std::vector<int> label(pass->Count(), 0);
      std::vector<std::size_t> sizes(1, 0);
      std::vector<std::size_t> stack;
      int next = 0;
      static const int dxs[8] = {1, -1, 0, 0, 1, 1, -1, -1};
      static const int dzs[8] = {0, 0, 1, -1, 1, -1, 1, -1};
      for (int z = 0; z < h; ++z) {
        for (int x = 0; x < w; ++x) {
          const std::size_t id = static_cast<std::size_t>(z) * w + x;
          if (label[id] != 0 || !Pass(*pass, x, z))
            continue;
          ++next;
          sizes.push_back(0);
          label[id] = next;
          stack.assign(1, id);
          while (!stack.empty()) {
            const std::size_t cur = stack.back();
            stack.pop_back();
            ++sizes[static_cast<std::size_t>(next)];
            const int cx = static_cast<int>(cur % static_cast<std::size_t>(w));
            const int cz = static_cast<int>(cur / static_cast<std::size_t>(w));
            for (int k = 0; k < conn; ++k) {
              const int nx = cx + dxs[k], nz = cz + dzs[k];
              if (nx < 0 || nz < 0 || nx >= w || nz >= h || !Pass(*pass, nx, nz))
                continue;
              if (k >= 4 && (!Pass(*pass, cx + dxs[k], cz) || !Pass(*pass, cx, cz + dzs[k])))
                continue;
              const std::size_t nid = static_cast<std::size_t>(nz) * w + nx;
              if (label[nid] != 0)
                continue;
              label[nid] = next;
              stack.push_back(nid);
            }
          }
        }
      }
      out = Grid(w, h, pass->cell, pass->ox, pass->oz, 0.0f);
      const double area = static_cast<double>(pass->cell) * static_cast<double>(pass->cell);
      for (std::size_t i = 0; i < label.size(); ++i) {
        if (label[i] == 0)
          continue;
        out.v[i] = mode == "label"
          ? static_cast<float>(label[i])
          : static_cast<float>(static_cast<double>(sizes[static_cast<std::size_t>(label[i])]) * area);
      }
      return true;
    }

    /** Registers the ops with the field engine at start-up (EdFieldCore.cpp: RegisterOp). */
    struct ScOpRegistrar
    {
      ScOpRegistrar()
      {
        RegisterOp("pad_flatten", &OpPadFlatten);
        RegisterOp("symmetrize", &OpSymmetrize);
        RegisterOp("slope_limit", &OpSlopeLimit);
        RegisterOp("reach", &OpReach);
        RegisterOp("regions", &OpRegions);
      }
    };
    const ScOpRegistrar gScOpRegistrar{};
  } // namespace
} // namespace faf::editor::field
