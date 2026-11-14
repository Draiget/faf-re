// path (spline) ops of the field engine (FAF Studio's docs/projects/editor/TERRAIN_GEN_DESIGN.md, stage T4). Engine
// independent like EdFieldCore; registered through RegisterOp.
//
// A path arrives as the number list `pts` (Lua samples the Bezier / Catmull-Rom curve into a dense polyline), 8 numbers
// per point:
//   x, z       world position
//   y          absolute target height (world units) for mode 'target'
//   w, f       half width of the shaped section and the falloff width beyond it (world units)
//   bank       bank angle in degrees: the section is tilted by tan(bank) * signed distance (positive raises the side
//   with positive signed distance) off        height offset (world units) for mode 'offset' s          arc length from
//   the first point
// Signed distance: positive where cross(direction, point - nearest) > 0 (the right hand side of the way of travel with
// x to the right and z down).
//
//
//   path_dist   distance of every sample to the path (unsigned, or signed with signed=1); samples out of reach of every
//   segment get `far` (default: the largest reach) path_along  arc length at the nearest point of the path
//   (normalize=1: 0..1 of the whole length); samples out of reach get `outside` (default -1) path_u      cross-section
//   coordinate signed distance / (w + f) at the nearest point; samples out of reach get 2 path_mask   kind = weight
//   (default: the profile across the section, then the smooth falloff) | core (1 inside the half width, smooth falloff
//   beyond) |
//               reach (1 inside w + f with a soft edge of `soft` units) | bank (reach minus core: the falloff band)
//   path_shape  a = heights. mode = offset (a + off * weight) | target (blend a towards y + tan(bank) * signed distance
//   by the weight); clip = none | min | max keeps only
//               lowering (carve) or raising; strength (0..1); optional `mask` multiplies the weight. Samples out of
//               reach keep a.
//   path_paste  a, b: puts field b into a at b's world placement (same cell size, whole sample offsets): mode = add |
//   sub | set | max | min, scale
// Section: the half width `w` carries the profile curve (x = |u| with u = signed distance / w, or (u + 1) / 2 for an
// asymmetric profile `symmetric=0`), the falloff `f` fades the weight at the profile's end value to 0 beyond the half
// width. `profile` is a list x0, v0, x1, v1, ... (x ascending 0..1), a monotone cubic through the points (smooth=1,
// default) or a polyline (smooth=0); no profile = constant 1.
//
// Every output sample is computed from the inputs alone (the nearest segment of a sample is found with a fixed order
// and strict comparison), so the results are bit identical for any thread count. The golden checksums
// (tests/editor/FieldTests.cpp) assume no fused multiply-add.
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
    constexpr int kStride = 8;
    constexpr int kLut = 512;
    constexpr int kChunk = 8;
    constexpr double kPi = 3.14159265358979323846;

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

    struct Pt
    {
      double x, z, y, w, f, bank, off, s;
    };

    struct Path
    {
      std::vector<Pt> p;
      double maxReach = 0.0;
      [[nodiscard]] int Segments() const
      {
        return p.size() <= 1 ? 1 : static_cast<int>(p.size()) - 1;
      }
      [[nodiscard]] const Pt& A(
        const int seg
      ) const
      {
        return p[static_cast<std::size_t>(seg)];
      }
      [[nodiscard]] const Pt& B(
        const int seg
      ) const
      {
        return p[static_cast<std::size_t>(std::min(seg + 1, static_cast<int>(p.size()) - 1))];
      }
    };

    bool ReadPath(
      const OpArgs& a,
      Path& path,
      std::string& err
    )
    {
      const std::vector<double>* v = a.p.A("pts");
      if (v == nullptr || v->size() < kStride || v->size() % kStride != 0) {
        err = "'pts' needs 8 numbers per point (x, z, y, w, f, bank, off, s)";
        return false;
      }
      const std::size_t n = v->size() / kStride;
      path.p.resize(n);
      for (std::size_t i = 0; i < n; ++i) {
        const double* q = v->data() + i * kStride;
        Pt& pt = path.p[i];
        pt.x = F32(q[0]);
        pt.z = F32(q[1]);
        pt.y = F32(q[2]);
        pt.w = std::max(0.001, F32(q[3]));
        pt.f = std::max(0.0, F32(q[4]));
        pt.bank = F32(q[5]);
        pt.off = F32(q[6]);
        pt.s = F32(q[7]);
        path.maxReach = std::max(path.maxReach, pt.w + pt.f);
      }
      return true;
    }

    const Grid* Get(
      const OpArgs& a,
      const char* const key
    )
    {
      const auto it = a.in.find(key);
      return it != a.in.end() ? it->second.get() : nullptr;
    }

    bool MakeOut(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* ref = Get(a, "like");
      if (ref == nullptr) {
        ref = Get(a, "a");
      }
      if (ref == nullptr) {
        err = "give 'like' or 'a'";
        return false;
      }
      // the ops index their inputs with the output's size: two inputs of different shapes would read or write out of
      // range
      if (
        const Grid* const inA = Get(a, "a"); inA != nullptr && ref != nullptr && (inA->w != ref->w || inA->h != ref->h)
      ) {
        err = "'like' and 'a' differ in size";
        return false;
      }
      out = Grid(ref->w, ref->h, ref->cell, ref->ox, ref->oz);
      return true;
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

    // ---- profile curve
    // ---------------------------------------------------------------------------------------------------------------------------

    /** Monotone cubic (Fritsch-Carlson) or linear through the points; constant outside the first and last x. */
    class Curve
    {
    public:
      void Build(
        const std::vector<double>& flat,
        const bool smooth
      )
      {
        x_.clear();
        y_.clear();
        std::vector<std::pair<double, double>> pts;
        for (std::size_t i = 0; i + 1 < flat.size(); i += 2) {
          pts.emplace_back(F32(flat[i]), F32(flat[i + 1]));
        }
        std::stable_sort(pts.begin(), pts.end(), [](const auto& a, const auto& b) {
          return a.first < b.first;
        });
        for (const auto& pt : pts) {
          if (!x_.empty() && pt.first <= x_.back()) {
            continue; // a vertical step: the first point of the x wins
          }
          x_.push_back(pt.first);
          y_.push_back(pt.second);
        }
        smooth_ = smooth;
        const std::size_t n = x_.size();
        m_.assign(n, 0.0);
        if (n < 2 || !smooth) {
          return;
        }
        std::vector<double> d(n - 1);
        for (std::size_t k = 0; k + 1 < n; ++k) {
          d[k] = (y_[k + 1] - y_[k]) / (x_[k + 1] - x_[k]);
        }
        m_[0] = d[0];
        m_[n - 1] = d[n - 2];
        for (std::size_t k = 1; k + 1 < n; ++k) {
          if (d[k - 1] * d[k] <= 0.0) {
            m_[k] = 0.0;
          } else {
            const double h0 = x_[k] - x_[k - 1];
            const double h1 = x_[k + 1] - x_[k];
            const double w1 = 2.0 * h1 + h0;
            const double w2 = h1 + 2.0 * h0;
            m_[k] = (w1 + w2) / (w1 / d[k - 1] + w2 / d[k]);
          }
        }
      }

      [[nodiscard]] double Eval(
        const double x
      ) const
      {
        const std::size_t n = x_.size();
        if (n == 0) {
          return 1.0;
        }
        if (x <= x_.front() || n == 1) {
          return y_.front();
        }
        if (x >= x_.back()) {
          return y_.back();
        }
        std::size_t k = 0;
        while (k + 2 < n && x >= x_[k + 1]) {
          ++k;
        }
        const double h = x_[k + 1] - x_[k];
        const double t = (x - x_[k]) / h;
        if (!smooth_) {
          return y_[k] + (y_[k + 1] - y_[k]) * t;
        }
        const double t2 = t * t;
        const double t3 = t2 * t;
        return (2 * t3 - 3 * t2 + 1) * y_[k] + (t3 - 2 * t2 + t) * h * m_[k] + (-2 * t3 + 3 * t2) * y_[k + 1] +
          (t3 - t2) * h * m_[k + 1];
      }

    private:
      std::vector<double> x_, y_, m_;
      bool smooth_ = true;
    };

    /** The profile as a lookup table (linear between 513 samples): deterministic and cheap per sample. */
    struct Profile
    {
      std::vector<float> lut;
      bool symmetric = true;

      void Build(
        const OpArgs& a
      )
      {
        symmetric = a.p.N("symmetric", 1.0) != 0.0;
        lut.assign(kLut + 1, 1.0f);
        const std::vector<double>* flat = a.p.A("profile");
        if (flat == nullptr || flat->size() < 2) {
          return;
        }
        Curve c;
        c.Build(*flat, a.p.N("smooth", 1.0) != 0.0);
        for (int i = 0; i <= kLut; ++i) {
          lut[static_cast<std::size_t>(i)] = static_cast<float>(c.Eval(static_cast<double>(i) / kLut));
        }
      }

      /** Profile value at the signed cross-section coordinate u (-1..1 spans the half width on both sides). */
      [[nodiscard]] double At(
        const double u
      ) const
      {
        const double x = Clamp01(symmetric ? std::fabs(u) : (u + 1.0) * 0.5);
        const double pos = x * kLut;
        const int i = std::min(kLut - 1, static_cast<int>(pos));
        const double t = pos - i;
        const double a0 = lut[static_cast<std::size_t>(i)];
        const double a1 = lut[static_cast<std::size_t>(i + 1)];
        return a0 + (a1 - a0) * t;
      }
    };

    /** Profile across the half width, then the falloff band that fades the profile's end value to 0. */
    inline double Weight(
      const Profile& pr,
      const double sd,
      const double w,
      const double f
    )
    {
      const double ad = std::fabs(sd);
      if (ad <= w) {
        return pr.At(sd / w);
      }
      if (f <= 0.0 || ad >= w + f) {
        return 0.0;
      }
      return pr.At(sd < 0.0 ? -1.0 : 1.0) * (1.0 - SmoothStep((ad - w) / f));
    }

    // ---- nearest point of the path for every sample
    // ----------------------------------------------------------------------------------------------

    struct Loc
    {
      std::vector<float> sd; // signed distance
      std::vector<float> bd; // unsigned distance (3e38 = out of reach of every segment)
      std::vector<float> tt; // position on the segment
      std::vector<std::int32_t> seg;
      [[nodiscard]] bool Hit(
        const std::size_t i
      ) const
      {
        return seg[i] >= 0;
      }
    };

    struct Attr
    {
      double w, f, y, bank, off, s;
    };

    inline Attr AttrAt(
      const Path& P,
      const int seg,
      const double t
    )
    {
      const Pt& a = P.A(seg);
      const Pt& b = P.B(seg);
      const auto L = [&](const double u, const double v) {
        return u + (v - u) * t;
      };
      return {L(a.w, b.w), L(a.f, b.f), L(a.y, b.y), L(a.bank, b.bank), L(a.off, b.off), L(a.s, b.s)};
    }

    void Locate(
      const Path& P,
      const Grid& g,
      Loc& L
    )
    {
      const std::size_t count = g.Count();
      L.sd.assign(count, 0.0f);
      L.bd.assign(count, 3.0e38f);
      L.tt.assign(count, 0.0f);
      L.seg.assign(count, -1);
      const int segs = P.Segments();
      struct Box
      {
        int x0, x1, z0, z1;
      };
      std::vector<Box> boxes(static_cast<std::size_t>(segs));
      for (int s = 0; s < segs; ++s) {
        const Pt& a = P.A(s);
        const Pt& b = P.B(s);
        const double r = std::max(a.w + a.f, b.w + b.f);
        const double cell = static_cast<double>(g.cell);
        boxes[static_cast<std::size_t>(s)] = {
          std::max(0, static_cast<int>(std::floor((std::min(a.x, b.x) - r - g.ox) / cell))),
          std::min(g.w - 1, static_cast<int>(std::ceil((std::max(a.x, b.x) + r - g.ox) / cell))),
          std::max(0, static_cast<int>(std::floor((std::min(a.z, b.z) - r - g.oz) / cell))),
          std::min(g.h - 1, static_cast<int>(std::ceil((std::max(a.z, b.z) + r - g.oz) / cell)))
        };
      }
      Rows(g.h, [&](const int z0, const int z1) {
        for (int s = 0; s < segs; ++s) {
          const Box& bx = boxes[static_cast<std::size_t>(s)];
          if (bx.z1 < z0 || bx.z0 >= z1 || bx.x1 < bx.x0) {
            continue;
          }
          const Pt& a = P.A(s);
          const Pt& b = P.B(s);
          const double dx = b.x - a.x;
          const double dz = b.z - a.z;
          const double len2 = dx * dx + dz * dz;
          for (int z = std::max(bx.z0, z0); z <= std::min(bx.z1, z1 - 1); ++z) {
            const double wz = static_cast<double>(g.oz) + static_cast<double>(z) * static_cast<double>(g.cell);
            for (int x = bx.x0; x <= bx.x1; ++x) {
              const double wx = static_cast<double>(g.ox) + static_cast<double>(x) * static_cast<double>(g.cell);
              double t = len2 > 1e-12 ? ((wx - a.x) * dx + (wz - a.z) * dz) / len2 : 0.0;
              t = Clamp01(t);
              const double vx = wx - (a.x + dx * t);
              const double vz = wz - (a.z + dz * t);
              const double d = std::sqrt(vx * vx + vz * vz);
              const double reach = (a.w + a.f) + ((b.w + b.f) - (a.w + a.f)) * t;
              if (d > reach) {
                continue;
              }
              const std::size_t i =
                static_cast<std::size_t>(z) * static_cast<std::size_t>(g.w) + static_cast<std::size_t>(x);
              const float df = static_cast<float>(d);
              if (df < L.bd[i]) {
                const double cross = dx * vz - dz * vx;
                L.bd[i] = df;
                L.sd[i] = cross >= 0.0 ? df : -df;
                L.tt[i] = static_cast<float>(t);
                L.seg[i] = s;
              }
            }
          }
        }
      });
    }

    template <class F>
    void EachCell(
      Grid& out,
      F&& f
    )
    {
      const int w = out.w;
      Rows(out.h, [&](const int z0, const int z1) {
        for (int z = z0; z < z1; ++z) {
          for (int x = 0; x < w; ++x) {
            const std::size_t i =
              static_cast<std::size_t>(z) * static_cast<std::size_t>(w) + static_cast<std::size_t>(x);
            out.v[i] = f(i);
          }
        }
      });
    }

    // ---- ops
    // -------------------------------------------------------------------------------------------------------------------------------------

    bool Prepare(
      const OpArgs& a,
      Path& P,
      Grid& out,
      Loc& L,
      std::string& err
    )
    {
      if (!ReadPath(a, P, err) || !MakeOut(a, out, err)) {
        return false;
      }
      Locate(P, out, L);
      return true;
    }

    bool OpDist(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      Path P;
      Loc L;
      if (!Prepare(a, P, out, L, err))
        return false;
      const bool sgn = a.p.N("signed", 0.0) != 0.0;
      const float far = static_cast<float>(a.p.N("far", P.maxReach));
      EachCell(out, [&](const std::size_t i) {
        return L.Hit(i) ? (sgn ? L.sd[i] : L.bd[i]) : far;
      });
      return true;
    }

    bool OpAlong(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      Path P;
      Loc L;
      if (!Prepare(a, P, out, L, err))
        return false;
      const bool norm = a.p.N("normalize", 0.0) != 0.0;
      const double total = P.p.back().s;
      const float outside = static_cast<float>(a.p.N("outside", -1.0));
      EachCell(out, [&](const std::size_t i) {
        if (!L.Hit(i))
          return outside;
        const double s = AttrAt(P, L.seg[i], L.tt[i]).s;
        return static_cast<float>(norm ? (total > 0.0 ? s / total : 0.0) : s);
      });
      return true;
    }

    bool OpU(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      Path P;
      Loc L;
      if (!Prepare(a, P, out, L, err))
        return false;
      EachCell(out, [&](const std::size_t i) {
        if (!L.Hit(i))
          return 2.0f;
        const Attr at = AttrAt(P, L.seg[i], L.tt[i]);
        return static_cast<float>(L.sd[i] / (at.w + at.f));
      });
      return true;
    }

    bool OpMask(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      Path P;
      Loc L;
      if (!Prepare(a, P, out, L, err))
        return false;
      const std::string kind = a.p.S("kind", "weight");
      if (kind != "weight" && kind != "core" && kind != "reach" && kind != "bank") {
        err = "kind must be weight, core, reach or bank";
        return false;
      }
      Profile flat; // constant 1
      flat.lut.assign(kLut + 1, 1.0f);
      Profile prof;
      prof.Build(a);
      const double soft = std::max(0.0, a.p.N("soft", 1.0));
      EachCell(out, [&](const std::size_t i) {
        if (!L.Hit(i))
          return 0.0f;
        const Attr at = AttrAt(P, L.seg[i], L.tt[i]);
        const double d = L.sd[i];
        const double core = Weight(flat, d, at.w, at.f);
        if (kind == "weight")
          return static_cast<float>(Clamp01(Weight(prof, d, at.w, at.f)));
        if (kind == "core")
          return static_cast<float>(core);
        const double reach = at.w + at.f;
        const double ad = std::fabs(d);
        const double r = soft <= 0.0 ? (ad <= reach ? 1.0 : 0.0) : 1.0 - SmoothStep((ad - (reach - soft)) / soft);
        if (kind == "reach")
          return static_cast<float>(r);
        return static_cast<float>(std::max(0.0, r - core));
      });
      return true;
    }

    bool OpShape(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Get(a, "a");
      if (src == nullptr) {
        err = "missing input 'a'";
        return false;
      }
      Path P;
      Loc L;
      if (!Prepare(a, P, out, L, err))
        return false;
      const std::string mode = a.p.S("mode", "offset");
      const std::string clip = a.p.S("clip", "none");
      if (mode != "offset" && mode != "target") {
        err = "mode must be offset or target";
        return false;
      }
      if (clip != "none" && clip != "min" && clip != "max") {
        err = "clip must be none, min or max";
        return false;
      }
      const bool target = mode == "target";
      const int clipMode = clip == "min" ? 1 : (clip == "max" ? 2 : 0);
      const double strength = Clamp01(a.p.N("strength", 1.0));
      const Grid* mask = Get(a, "mask");
      if (mask != nullptr && !mask->SameShape(*src)) {
        err = "'mask' must have the shape of 'a'";
        return false;
      }
      Profile prof;
      prof.Build(a);
      EachCell(out, [&](const std::size_t i) {
        const float base = src->v[i];
        if (!L.Hit(i))
          return base;
        const Attr at = AttrAt(P, L.seg[i], L.tt[i]);
        double wgt = Weight(prof, L.sd[i], at.w, at.f) * strength;
        if (mask != nullptr)
          wgt *= Clamp01(mask->v[i]);
        double h;
        if (target) {
          const double tc = at.y + std::tan(at.bank * kPi / 180.0) * L.sd[i];
          h = base + (tc - base) * Clamp01(wgt);
        } else {
          h = base + at.off * wgt;
        }
        if (clipMode == 1)
          h = std::min(h, static_cast<double>(base));
        else if (clipMode == 2)
          h = std::max(h, static_cast<double>(base));
        return static_cast<float>(h);
      });
      return true;
    }

    bool OpPaste(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Get(a, "a");
      const Grid* b = Get(a, "b");
      if (src == nullptr || b == nullptr) {
        err = "path_paste needs 'a' and 'b'";
        return false;
      }
      if (std::fabs(static_cast<double>(src->cell) - static_cast<double>(b->cell)) > 1e-6) {
        err = "path_paste: both fields need the same cell size";
        return false;
      }
      const double offx = (static_cast<double>(b->ox) - static_cast<double>(src->ox)) / static_cast<double>(src->cell);
      const double offz = (static_cast<double>(b->oz) - static_cast<double>(src->oz)) / static_cast<double>(src->cell);
      if (std::fabs(offx - std::round(offx)) > 1e-3 || std::fabs(offz - std::round(offz)) > 1e-3) {
        err = "path_paste: 'b' must lie on whole samples of 'a'";
        return false;
      }
      const std::string mode = a.p.S("mode", "add");
      if (mode != "add" && mode != "sub" && mode != "set" && mode != "max" && mode != "min") {
        err = "mode must be add, sub, set, max or min";
        return false;
      }
      const int ix = static_cast<int>(std::lround(offx));
      const int iz = static_cast<int>(std::lround(offz));
      const float scale = static_cast<float>(a.p.N("scale", 1.0));
      out = *src;
      Rows(b->h, [&](const int z0, const int z1) {
        for (int z = z0; z < z1; ++z) {
          const int oz = z + iz;
          if (oz < 0 || oz >= out.h)
            continue;
          for (int x = 0; x < b->w; ++x) {
            const int ox = x + ix;
            if (ox < 0 || ox >= out.w)
              continue;
            float& d = out.At(ox, oz);
            const float v = b->At(x, z) * scale;
            if (mode == "add")
              d += v;
            else if (mode == "sub")
              d -= v;
            else if (mode == "set")
              d = v;
            else if (mode == "max")
              d = std::max(d, v);
            else
              d = std::min(d, v);
          }
        }
      });
      return true;
    }
    /** Registers the ops with the field engine at start-up (EdFieldCore.cpp: RegisterOp). */
    struct PathOpRegistrar
    {
      PathOpRegistrar()
      {
        RegisterOp("path_dist", &OpDist);
        RegisterOp("path_along", &OpAlong);
        RegisterOp("path_u", &OpU);
        RegisterOp("path_mask", &OpMask);
        RegisterOp("path_shape", &OpShape);
        RegisterOp("path_paste", &OpPaste);
      }
    };
    const PathOpRegistrar gPathOpRegistrar{};
  } // namespace
} // namespace faf::editor::field
