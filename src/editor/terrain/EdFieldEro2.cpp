// stage T7 erosion variants of the field engine (FAF Studio's docs/projects/editor/TERRAIN_GEN_DESIGN.md, section T7).
// Engine independent; registered through RegisterOp. Every op takes `output` (the main result, default height) and puts
// all the other results into the extra outputs by name (ed_field_op_multi), like the T3 solvers.
//
//   thermal_map     a heights, optional b (a talus map 0..1 between talus_lo and talus_hi; else `talus`), optional mask
//   (rate). iterations, rate. Material slides where the drop exceeds the talus of
//                   the cell it leaves. output height | scree (what arrived, a debris mask) | moved (what left);
//                   scree_scale (units for 1).
//   erode_rocksoil  a heights, optional b (soil thickness, units; else `soil`). Rock weathers into soil (weather,
//   depth0), soil slides at soil_talus (never more than there is), the rock itself
//                   at rock_talus every rock_every steps. output height | soil (thickness) | rock (exposure 0..1 over
//                   rock_vis units of soil) | moved.
//   erode_snow      a heights, optional mask (accumulation). Snow lies above snowline (soft band), not on ground
//   steeper than steep_lo..steep_hi, and slumps at snow_talus.
//                   output height (ground + snow) | snow (depth) | cover (0..1 over cover_depth) | moved.
//   erode_wind      a heights, optional b (sand depth). Wind towards azimuth abrades exposed windward rock into sand,
//   carries the sand (slowed uphill, free in the lee) and the sand slides at
//                   `repose`. iterations, speed, abrade, drag, sand. output height | sand | abrasion.
//   erode_glacier   a heights, optional b (accumulation 0..1). Shallow ice approximation: ice thickness from mass
//   balance (ela, grad, acc_max, abl_max) flows downhill (flow, max_ice), erodes
//                   the bed under thick fast ice (erode, erode_pow, max_cut) so valleys turn U shaped. iterations, dt.
//                   output height | ice | cover | carve.
//   settle          a heights. Sediment settles in hollows: low ground rises towards the mean of its neighbours where
//   it is flat enough (slope_lo .. slope_hi), at most `cap` per step.
//                   iterations, rate. output height | deposit.
//
// All updates are gather style on double buffers and reductions combine fixed chunks, so the results are bit identical
// for any thread count.
// The golden checksums (tests/editor/FieldTests.cpp, ErosionTests.cpp) assume no fused multiply-add.
#if defined(__clang__)
#pragma clang fp contract(off)
#else
#pragma fp_contract(off)
#endif

#include "editor/terrain/EdFieldUtil.h"

#include <algorithm>
#include <cmath>
#include <map>

namespace faf::editor::field
{
  using namespace t7;

  namespace
  {
    const int kDx[8] = {-1, 1, 0, 0, -1, 1, -1, 1};
    const int kDz[8] = {0, 0, -1, 1, -1, -1, 1, 1};

    /** Puts the chosen result into `out` and the others into the extra outputs. */
    bool Emit(
      const OpArgs& a,
      Grid& out,
      std::map<std::string, Grid>& all,
      const char* const fallback,
      std::string& err
    )
    {
      const std::string want = a.p.S("output", fallback);
      const auto it = all.find(want);
      if (it == all.end()) {
        err = "unknown output '" + want + "'";
        return false;
      }
      for (auto& kv : all) {
        if (kv.first == want)
          continue;
        if (a.extra != nullptr)
          (*a.extra)[kv.first] = std::move(kv.second);
      }
      out = std::move(it->second);
      return true;
    }

    Grid Like(
      const Grid& g,
      const float fill = 0.0f
    )
    {
      return Grid(g.w, g.h, g.cell, g.ox, g.oz, fill);
    }

    /** Buffers of Slide kept between calls (one call per iteration of an outer loop must not allocate and clear 12 MB
     * every time). */
    struct SlideScratch
    {
      std::vector<float> next, share, moved, surf;
    };

    /**
     * Thermal slides of a loose layer over a bed. Surface = rock + loose (rock may be null: the loose layer is the
     * whole surface and nothing caps the moved amount). The drop to a neighbour above talus (rise per run, per source
     * cell) slides; a cell never gives more than its loose layer holds. Order independent, conserves the total. `gain`
     * / `lost` (optional) add what arrived / left in every step. The inner cells run on a path without bounds checks
     * (the neighbours are fixed offsets, the surface is formed once per step), the one cell wide border on the checked
     * path; both compute every value with the same operations in the same order.
     */
    template <bool kRock, bool kMap>
    void SlideT(
      const int w,
      const int h,
      const float cell,
      const float* const rock,
      std::vector<float>& loose,
      const float* const talusMap,
      const float talusConst,
      const float* const rateMask,
      const float rate,
      const int iterations,
      float* const gain,
      float* const lost,
      SlideScratch& sc
    )
    {
      const std::size_t n = static_cast<std::size_t>(w) * static_cast<std::size_t>(h);
      if (sc.next.size() != n)
        sc.next.assign(n, 0.0f);
      if (sc.share.size() != n)
        sc.share.assign(n, 0.0f);
      if (sc.moved.size() != n)
        sc.moved.assign(n, 0.0f);
      if (kRock && sc.surf.size() != n)
        sc.surf.assign(n, 0.0f);
      const std::ptrdiff_t off[8] = {
        -1,
        1,
        -static_cast<std::ptrdiff_t>(w),
        static_cast<std::ptrdiff_t>(w),
        -static_cast<std::ptrdiff_t>(w) - 1,
        -static_cast<std::ptrdiff_t>(w) + 1,
        static_cast<std::ptrdiff_t>(w) - 1,
        static_cast<std::ptrdiff_t>(w) + 1
      };
      for (int it = 0; it < iterations; ++it) {
        float* const next = sc.next.data();
        float* const share = sc.share.data();
        float* const moved = sc.moved.data();
        const float* const L = loose.data();
        if (kRock) {
          float* const sf = sc.surf.data();
          Rows(h, [&](const int z0, const int z1) {
            for (std::size_t i = static_cast<std::size_t>(z0) * static_cast<std::size_t>(w);
                 i < static_cast<std::size_t>(z1) * static_cast<std::size_t>(w);
                 ++i)
              sf[i] = rock[i] + L[i];
          });
        }
        const float* const S = kRock ? sc.surf.data() : L;
        // pass 1: what every cell gives away
        const auto give = [&](
                            const std::size_t i,
                            const float c,
                            const float talus,
                            const float e0,
                            const float e1,
                            const float e2,
                            const float e3,
                            const float e4,
                            const float e5,
                            const float e6,
                            const float e7
                          ) {
          float maxEx = 0.0f, sumEx = 0.0f;
          const float tA = talus * cell, tD = talus * cell * 1.41421356f;
          const float ex[8] = {
            (c - e0) - tA,
            (c - e1) - tA,
            (c - e2) - tA,
            (c - e3) - tA,
            (c - e4) - tD,
            (c - e5) - tD,
            (c - e6) - tD,
            (c - e7) - tD
          };
          for (int k = 0; k < 8; ++k) {
            const float e = ex[k] > 0.0f ? ex[k] : 0.0f; // adding 0 changes nothing: the same sums as with a branch
            sumEx += e;
            maxEx = std::max(maxEx, e);
          }
          float s = 0.0f, mv = 0.0f;
          if (sumEx > 0.0f) {
            float r = rate;
            if (rateMask != nullptr)
              r *= Clamp01(rateMask[i]);
            s = r * 0.5f * maxEx / sumEx;
            mv = s * sumEx;
            if (kRock && mv > L[i]) {
              const float f = L[i] > 0.0f ? L[i] / mv : 0.0f;
              s *= f;
              mv = L[i];
            }
          }
          share[i] = s;
          moved[i] = mv;
        };
        Rows(h, [&](const int z0, const int z1) {
          for (int z = z0; z < z1; ++z) {
            const std::size_t row = static_cast<std::size_t>(z) * static_cast<std::size_t>(w);
            for (int x = 0; x < w; ++x) {
              const std::size_t i = row + static_cast<std::size_t>(x);
              const float talus = kMap ? talusMap[i] : talusConst;
              if (x > 0 && x < w - 1 && z > 0 && z < h - 1) {
                const float* const p = S + i;
                give(
                  i, p[0], talus, p[off[0]], p[off[1]], p[off[2]], p[off[3]], p[off[4]], p[off[5]], p[off[6]], p[off[7]]
                );
              } else {
                // the border: a missing neighbour never gives or takes (its excess stays <= 0)
                const float c = S[i];
                const float big = 3.0e38f;
                float e[8];
                for (int k = 0; k < 8; ++k) {
                  static const int dxs[8] = {-1, 1, 0, 0, -1, 1, -1, 1};
                  static const int dzs[8] = {0, 0, -1, 1, -1, -1, 1, 1};
                  const int nx = x + dxs[k], nz = z + dzs[k];
                  e[k] = (nx < 0 || nz < 0 || nx >= w || nz >= h)
                    ? big
                    : S[static_cast<std::size_t>(nz) * static_cast<std::size_t>(w) + static_cast<std::size_t>(nx)];
                }
                give(i, c, talus, e[0], e[1], e[2], e[3], e[4], e[5], e[6], e[7]);
              }
            }
          }
        });
        // pass 2: what every cell receives
        Rows(h, [&](const int z0, const int z1) {
          for (int z = z0; z < z1; ++z) {
            const std::size_t row = static_cast<std::size_t>(z) * static_cast<std::size_t>(w);
            for (int x = 0; x < w; ++x) {
              const std::size_t i = row + static_cast<std::size_t>(x);
              const float c = S[i];
              float got = 0.0f;
              const auto take = [&](const std::size_t j, const int k) {
                const float tj = kMap ? talusMap[j] : talusConst;
                const float ex = (S[j] - c) - tj * cell * (k < 4 ? 1.0f : 1.41421356f);
                got += share[j] * (ex > 0.0f ? ex : 0.0f);
              };
              if (x > 0 && x < w - 1 && z > 0 && z < h - 1) {
                for (int k = 0; k < 8; ++k)
                  take(static_cast<std::size_t>(static_cast<std::ptrdiff_t>(i) + off[k]), k);
              } else {
                static const int dxs[8] = {-1, 1, 0, 0, -1, 1, -1, 1};
                static const int dzs[8] = {0, 0, -1, 1, -1, -1, 1, 1};
                for (int k = 0; k < 8; ++k) {
                  const int nx = x + dxs[k], nz = z + dzs[k];
                  if (nx < 0 || nz < 0 || nx >= w || nz >= h)
                    continue;
                  take(static_cast<std::size_t>(nz) * static_cast<std::size_t>(w) + static_cast<std::size_t>(nx), k);
                }
              }
              next[i] = L[i] - moved[i] + got;
              if (gain != nullptr)
                gain[i] += got;
              if (lost != nullptr)
                lost[i] += moved[i];
            }
          }
        });
        std::swap(loose, sc.next);
      }
    }

    void Slide(
      const int w,
      const int h,
      const float cell,
      const std::vector<float>* rock,
      std::vector<float>& loose,
      const std::vector<float>* talusMap,
      const float talusConst,
      const std::vector<float>* rateMask,
      const float rate,
      const int iterations,
      std::vector<float>* gain,
      std::vector<float>* lost,
      SlideScratch& sc
    )
    {
      const float* const rk = rock != nullptr ? rock->data() : nullptr;
      const float* const tm = talusMap != nullptr ? talusMap->data() : nullptr;
      const float* const rm = rateMask != nullptr ? rateMask->data() : nullptr;
      float* const g = gain != nullptr ? gain->data() : nullptr;
      float* const l = lost != nullptr ? lost->data() : nullptr;
      if (rk != nullptr) {
        if (tm != nullptr)
          SlideT<true, true>(w, h, cell, rk, loose, tm, talusConst, rm, rate, iterations, g, l, sc);
        else
          SlideT<true, false>(w, h, cell, rk, loose, tm, talusConst, rm, rate, iterations, g, l, sc);
      } else {
        if (tm != nullptr)
          SlideT<false, true>(w, h, cell, rk, loose, tm, talusConst, rm, rate, iterations, g, l, sc);
        else
          SlideT<false, false>(w, h, cell, rk, loose, tm, talusConst, rm, rate, iterations, g, l, sc);
      }
    }

    inline int ItersOf(
      const OpArgs& a,
      const int fallback,
      const int cap = 20000
    )
    {
      return std::max(0, std::min(cap, static_cast<int>(a.p.N("iterations", fallback))));
    }

    // ---- thermal_map
    // -----------------------------------------------------------------------------------------------------------------------------

    bool OpThermalMap(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      if (src == nullptr || !MakeOut(a, out, err))
        return false;
      const Grid* tmap = Get(a, "b");
      const Grid* mask = Get(a, "mask");
      if (!SameOrNone(tmap, *src, "b", err) || !SameOrNone(mask, *src, "mask", err))
        return false;
      const int w = src->w, h = src->h;
      const std::size_t n = src->Count();
      std::vector<float> talus(n, static_cast<float>(a.p.N("talus", 0.6)));
      const float lo = std::max(0.0f, static_cast<float>(a.p.N("talus_lo", 0.35))),
                  hi = std::max(0.0f, static_cast<float>(a.p.N("talus_hi", 1.0)));
      if (tmap != nullptr) {
        for (std::size_t i = 0; i < n; ++i)
          talus[i] = lo + (hi - lo) * Clamp01(tmap->v[i]);
      }
      std::vector<float> loose = src->v, gain(n, 0.0f), lost(n, 0.0f);
      SlideScratch scratch;
      Slide(
        w,
        h,
        src->cell,
        nullptr,
        loose,
        &talus,
        0.0f,
        mask != nullptr ? &mask->v : nullptr,
        std::max(0.0f, std::min(1.0f, static_cast<float>(a.p.N("rate", 0.5)))),
        ItersOf(a, 30),
        &gain,
        &lost,
        scratch
      );
      const float sc = std::max(1e-4f, static_cast<float>(a.p.N("scree_scale", 1.0)));
      std::map<std::string, Grid> all;
      all["height"] = Like(*src);
      all["height"].v = std::move(loose);
      all["scree"] = Like(*src);
      all["moved"] = Like(*src);
      for (std::size_t i = 0; i < n; ++i) {
        all["scree"].v[i] = Clamp01(gain[i] / sc);
        all["moved"].v[i] = Clamp01(lost[i] / sc);
      }
      return Emit(a, out, all, "height", err);
    }

    // ---- erode_rocksoil
    // --------------------------------------------------------------------------------------------------------------------------

    bool OpRockSoil(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      if (src == nullptr || !MakeOut(a, out, err))
        return false;
      const Grid* soil0 = Get(a, "b");
      if (!SameOrNone(soil0, *src, "b", err))
        return false;
      const int w = src->w, h = src->h;
      const std::size_t n = src->Count();
      const float weather = std::max(0.0f, static_cast<float>(a.p.N("weather", 0.01)));
      const float depth0 = std::max(1e-3f, static_cast<float>(a.p.N("depth0", 1.0)));
      const float soilTalus = std::max(0.0f, static_cast<float>(a.p.N("soil_talus", 0.35)));
      const float rockTalus = std::max(0.0f, static_cast<float>(a.p.N("rock_talus", 1.2)));
      const int rockEvery = std::max(1, static_cast<int>(a.p.N("rock_every", 4)));
      const float rate = std::max(0.0f, std::min(1.0f, static_cast<float>(a.p.N("rate", 0.5))));
      const float vis = std::max(1e-3f, static_cast<float>(a.p.N("rock_vis", 0.4)));
      const int iterations = ItersOf(a, 60);
      std::vector<float> soil(n), rock(n);
      const float soilConst = static_cast<float>(a.p.N("soil", 0.8));
      for (std::size_t i = 0; i < n; ++i) {
        soil[i] = std::max(0.0f, soil0 != nullptr ? soil0->v[i] : soilConst);
        rock[i] = src->v[i] - soil[i];
      }
      std::vector<float> lost(n, 0.0f);
      SlideScratch sc;
      for (int it = 0; it < iterations; ++it) {
        Rows(h, [&](const int z0, const int z1) {
          for (int z = z0; z < z1; ++z) {
            for (int x = 0; x < w; ++x) {
              const std::size_t i =
                static_cast<std::size_t>(z) * static_cast<std::size_t>(w) + static_cast<std::size_t>(x);
              const float d = weather * std::exp(-soil[i] / depth0);
              rock[i] -= d;
              soil[i] += d;
            }
          }
        });
        Slide(w, h, src->cell, &rock, soil, nullptr, soilTalus, nullptr, rate, 1, nullptr, &lost, sc);
        if (rockTalus > 0.0f && (it % rockEvery) == rockEvery - 1) {
          // the rock slides as a layer of its own (no cap); the soil rides along on top of it
          Slide(w, h, src->cell, nullptr, rock, nullptr, rockTalus, nullptr, rate, 1, nullptr, nullptr, sc);
        }
      }
      std::map<std::string, Grid> all;
      all["height"] = Like(*src);
      all["soil"] = Like(*src);
      all["rock"] = Like(*src);
      all["moved"] = Like(*src);
      for (std::size_t i = 0; i < n; ++i) {
        all["height"].v[i] = rock[i] + soil[i];
        all["soil"].v[i] = soil[i];
        all["rock"].v[i] = 1.0f - SmoothStep(0.0f, vis, soil[i]);
        all["moved"].v[i] = Clamp01(lost[i]);
      }
      return Emit(a, out, all, "height", err);
    }

    // ---- erode_snow
    // ------------------------------------------------------------------------------------------------------------------------------

    bool OpSnow(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      if (src == nullptr || !MakeOut(a, out, err))
        return false;
      const Grid* acc = Get(a, "mask");
      if (!SameOrNone(acc, *src, "mask", err))
        return false;
      const int w = src->w, h = src->h;
      const std::size_t n = src->Count();
      const float line = static_cast<float>(a.p.N("snowline", 40.0));
      const float band = std::max(1e-3f, static_cast<float>(a.p.N("band", 10.0)));
      const float amount = std::max(0.0f, static_cast<float>(a.p.N("amount", 3.0)));
      const float sLo = static_cast<float>(a.p.N("steep_lo", 0.8)), sHi = static_cast<float>(a.p.N("steep_hi", 1.4));
      const float talus = std::max(0.0f, static_cast<float>(a.p.N("snow_talus", 0.9)));
      const float rate = std::max(0.0f, std::min(1.0f, static_cast<float>(a.p.N("rate", 0.5))));
      const float coverDepth = std::max(1e-3f, static_cast<float>(a.p.N("cover_depth", 0.5)));
      std::vector<float> snow(n), ground = src->v;
      for (int z = 0; z < h; ++z) {
        for (int x = 0; x < w; ++x) {
          const std::size_t i = static_cast<std::size_t>(z) * static_cast<std::size_t>(w) + static_cast<std::size_t>(x);
          float gx, gz;
          GradientAt(*src, x, z, gx, gz);
          float s = amount * SmoothStep(line - band, line + band, ground[i]) *
            (1.0f - SmoothStep(sLo, sHi, std::sqrt(gx * gx + gz * gz)));
          if (acc != nullptr)
            s *= Clamp01(acc->v[i]);
          snow[i] = s;
        }
      }
      std::vector<float> lost(n, 0.0f);
      SlideScratch sc;
      Slide(w, h, src->cell, &ground, snow, nullptr, talus, nullptr, rate, ItersOf(a, 40), nullptr, &lost, sc);
      std::map<std::string, Grid> all;
      all["height"] = Like(*src);
      all["snow"] = Like(*src);
      all["cover"] = Like(*src);
      all["moved"] = Like(*src);
      for (std::size_t i = 0; i < n; ++i) {
        all["height"].v[i] = ground[i] + snow[i];
        all["snow"].v[i] = snow[i];
        all["cover"].v[i] = SmoothStep(0.0f, coverDepth, snow[i]);
        all["moved"].v[i] = Clamp01(lost[i]);
      }
      return Emit(a, out, all, "height", err);
    }

    // ---- erode_wind
    // ------------------------------------------------------------------------------------------------------------------------------

    bool OpWind(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      if (src == nullptr || !MakeOut(a, out, err))
        return false;
      const Grid* sand0 = Get(a, "b");
      if (!SameOrNone(sand0, *src, "b", err))
        return false;
      const int w = src->w, h = src->h;
      const std::size_t n = src->Count();
      const double az = a.p.N("azimuth", 0.0) * kPiD / 180.0;
      const float wx = static_cast<float>(std::cos(az)), wz = static_cast<float>(std::sin(az));
      const float speed = std::max(0.0f, std::min(0.7f, static_cast<float>(a.p.N("speed", 0.5))));
      const float abrade = std::max(0.0f, static_cast<float>(a.p.N("abrade", 0.02)));
      const float drag = std::max(0.0f, static_cast<float>(a.p.N("drag", 1.5)));
      const float repose = std::max(0.05f, static_cast<float>(a.p.N("repose", 0.62)));
      const float sandConst = std::max(0.0f, static_cast<float>(a.p.N("sand", 0.5)));
      const int iterations = ItersOf(a, 40);
      std::vector<float> sand(n), rock(n), wear(n, 0.0f), surf(n), vel(n), take(n), next(n);
      for (std::size_t i = 0; i < n; ++i) {
        sand[i] = std::max(0.0f, sand0 != nullptr ? sand0->v[i] : sandConst);
        rock[i] = src->v[i] - sand[i];
      }
      const float cell = src->cell;
      const float awx = std::fabs(wx), awz = std::fabs(wz);
      SlideScratch sc;
      for (int it = 0; it < iterations; ++it) {
        // the surface, then abrasion and the carrying speed from the slope along the wind (read-only pass, then the
        // update: no cell reads what another thread writes)
        Rows(h, [&](const int z0, const int z1) {
          for (std::size_t i = static_cast<std::size_t>(z0) * static_cast<std::size_t>(w);
               i < static_cast<std::size_t>(z1) * static_cast<std::size_t>(w);
               ++i)
            surf[i] = rock[i] + sand[i];
        });
        Rows(h, [&](const int z0, const int z1) {
          for (int z = z0; z < z1; ++z) {
            const std::size_t row = static_cast<std::size_t>(z) * static_cast<std::size_t>(w);
            const std::size_t rowU = static_cast<std::size_t>(std::max(0, z - 1)) * static_cast<std::size_t>(w);
            const std::size_t rowD = static_cast<std::size_t>(std::min(h - 1, z + 1)) * static_cast<std::size_t>(w);
            for (int x = 0; x < w; ++x) {
              const std::size_t i = row + static_cast<std::size_t>(x);
              const std::size_t xl = static_cast<std::size_t>(std::max(0, x - 1)),
                                xr = static_cast<std::size_t>(std::min(w - 1, x + 1));
              const float gx = (surf[row + xr] - surf[row + xl]) / (2.0f * cell),
                          gz = (surf[rowD + static_cast<std::size_t>(x)] - surf[rowU + static_cast<std::size_t>(x)]) /
                (2.0f * cell);
              const float ds = gx * wx + gz * wz; // rise per run along the wind
              const float up = std::max(0.0f, ds);
              const float bare = 1.0f - SmoothStep(0.0f, 0.5f, sand[i]);
              take[i] = std::min(abrade * up * bare, abrade);
              vel[i] = speed * Clamp01(1.0f - drag * up);
            }
          }
        });
        Rows(h, [&](const int z0, const int z1) {
          for (std::size_t i = static_cast<std::size_t>(z0) * static_cast<std::size_t>(w);
               i < static_cast<std::size_t>(z1) * static_cast<std::size_t>(w);
               ++i) {
            rock[i] -= take[i];
            sand[i] += take[i];
            wear[i] += take[i];
          }
        });
        // upwind transport of the sand (conservative, open downwind edges, nothing enters)
        Rows(h, [&](const int z0, const int z1) {
          for (int z = z0; z < z1; ++z) {
            for (int x = 0; x < w; ++x) {
              const std::size_t i =
                static_cast<std::size_t>(z) * static_cast<std::size_t>(w) + static_cast<std::size_t>(x);
              float in = 0.0f;
              const int ux = wx > 0.0f ? x - 1 : x + 1;
              const int uz = wz > 0.0f ? z - 1 : z + 1;
              if (awx > 0.0f && ux >= 0 && ux < w) {
                const std::size_t j =
                  static_cast<std::size_t>(z) * static_cast<std::size_t>(w) + static_cast<std::size_t>(ux);
                in += awx * vel[j] * sand[j];
              }
              if (awz > 0.0f && uz >= 0 && uz < h) {
                const std::size_t j =
                  static_cast<std::size_t>(uz) * static_cast<std::size_t>(w) + static_cast<std::size_t>(x);
                in += awz * vel[j] * sand[j];
              }
              next[i] = sand[i] - (awx + awz) * vel[i] * sand[i] + in;
            }
          }
        });
        std::swap(sand, next);
        Slide(w, h, cell, &rock, sand, nullptr, repose, nullptr, 0.5f, 1, nullptr, nullptr, sc);
        if (next.size() != n)
          next.assign(n, 0.0f); // Slide trades its buffer with `sand`: keep our own scratch the right size
      }
      std::map<std::string, Grid> all;
      all["height"] = Like(*src);
      all["sand"] = Like(*src);
      all["abrasion"] = Like(*src);
      for (std::size_t i = 0; i < n; ++i) {
        all["height"].v[i] = rock[i] + sand[i];
        all["sand"].v[i] = sand[i];
        all["abrasion"].v[i] = Clamp01(wear[i]);
      }
      return Emit(a, out, all, "height", err);
    }

    // ---- erode_glacier
    // ---------------------------------------------------------------------------------------------------------------------------

    bool OpGlacier(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      if (src == nullptr || !MakeOut(a, out, err))
        return false;
      const Grid* accMask = Get(a, "b");
      if (!SameOrNone(accMask, *src, "b", err))
        return false;
      const int w = src->w, h = src->h;
      const std::size_t n = src->Count();
      const float cell = src->cell;
      const float ela = static_cast<float>(a.p.N("ela", 40.0));
      const float grad = std::max(0.0f, static_cast<float>(a.p.N("grad", 0.02)));
      const float accMax = std::max(0.0f, static_cast<float>(a.p.N("acc_max", 0.5)));
      const float ablMax = std::max(0.0f, static_cast<float>(a.p.N("abl_max", 1.0)));
      const float flow = std::max(0.0f, static_cast<float>(a.p.N("flow", 0.02)));
      const float maxIce = std::max(1.0f, static_cast<float>(a.p.N("max_ice", 120.0)));
      const float erode = std::max(0.0f, static_cast<float>(a.p.N("erode", 0.0005)));
      const float erodePow = std::max(0.5f, static_cast<float>(a.p.N("erode_pow", 1.5)));
      const float maxCut = std::max(0.0f, static_cast<float>(a.p.N("max_cut", 25.0)));
      const float dtMax = std::max(1e-4f, static_cast<float>(a.p.N("dt", 1.0)));
      const int iterations = ItersOf(a, 200, 5000);
      const int powKind = erodePow == 1.0f ? 1 : (erodePow == 2.0f ? 2 : (erodePow == 1.5f ? 3 : 0));
      std::vector<float> bed = src->v, ice(n, 0.0f), cut(n, 0.0f), dif(n, 0.0f), gsl(n, 0.0f), next(n, 0.0f),
                         surf(n, 0.0f);
      const int chunks = (h + kChunk - 1) / kChunk;
      std::vector<float> chunkMax(static_cast<std::size_t>(chunks), 0.0f);
      const float cc = cell * cell;
      for (int it = 0; it < iterations; ++it) {
        // surface, then diffusivity D = flow * H^5 * |grad s|^2 (n = 3) and the surface slope
        Rows(h, [&](const int z0, const int z1) {
          for (std::size_t i = static_cast<std::size_t>(z0) * static_cast<std::size_t>(w);
               i < static_cast<std::size_t>(z1) * static_cast<std::size_t>(w);
               ++i)
            surf[i] = bed[i] + ice[i];
        });
        ParallelFor(chunks, [&](const int c) {
          const int z0 = c * kChunk, z1 = std::min(h, z0 + kChunk);
          float mx = 0.0f;
          for (int z = z0; z < z1; ++z) {
            const std::size_t row = static_cast<std::size_t>(z) * static_cast<std::size_t>(w);
            const std::size_t rowU = static_cast<std::size_t>(std::max(0, z - 1)) * static_cast<std::size_t>(w);
            const std::size_t rowD = static_cast<std::size_t>(std::min(h - 1, z + 1)) * static_cast<std::size_t>(w);
            for (int x = 0; x < w; ++x) {
              const std::size_t i = row + static_cast<std::size_t>(x);
              const std::size_t xl = static_cast<std::size_t>(std::max(0, x - 1)),
                                xr = static_cast<std::size_t>(std::min(w - 1, x + 1));
              const float gx = (surf[row + xr] - surf[row + xl]) / (2.0f * cell),
                          gz = (surf[rowD + static_cast<std::size_t>(x)] - surf[rowU + static_cast<std::size_t>(x)]) /
                (2.0f * cell);
              const float s2 = gx * gx + gz * gz;
              const float hh = ice[i];
              const float h2 = hh * hh;
              const float d = flow * h2 * h2 * hh * s2;
              dif[i] = d;
              gsl[i] = std::sqrt(s2);
              mx = std::max(mx, d);
            }
          }
          chunkMax[static_cast<std::size_t>(c)] = mx;
        });
        float dmax = 0.0f;
        for (const float m : chunkMax)
          dmax = std::max(dmax, m);
        const float dt = dmax > 0.0f ? std::min(dtMax, 0.2f * cc / dmax) : dtMax;
        Rows(h, [&](const int z0, const int z1) {
          for (int z = z0; z < z1; ++z) {
            const std::size_t row = static_cast<std::size_t>(z) * static_cast<std::size_t>(w);
            for (int x = 0; x < w; ++x) {
              const std::size_t i = row + static_cast<std::size_t>(x);
              const float s = surf[i];
              float div = 0.0f;
              if (x > 0)
                div += 0.5f * (dif[i] + dif[i - 1]) * (surf[i - 1] - s) / cc;
              if (x < w - 1)
                div += 0.5f * (dif[i] + dif[i + 1]) * (surf[i + 1] - s) / cc;
              if (z > 0)
                div += 0.5f * (dif[i] + dif[i - static_cast<std::size_t>(w)]) *
                  (surf[i - static_cast<std::size_t>(w)] - s) / cc;
              if (z < h - 1)
                div += 0.5f * (dif[i] + dif[i + static_cast<std::size_t>(w)]) *
                  (surf[i + static_cast<std::size_t>(w)] - s) / cc;
              float b = grad * (s - ela);
              b = std::max(-ablMax, std::min(accMax * (accMask != nullptr ? Clamp01(accMask->v[i]) : 1.0f), b));
              const float nh = std::max(0.0f, std::min(maxIce, ice[i] + dt * (div + b)));
              next[i] = nh;
              if (nh > 0.0f && erode > 0.0f && ice[i] > 0.0f) {
                const float v = ice[i] * gsl[i];
                const float p =
                  powKind == 1 ? v : (powKind == 2 ? v * v : (powKind == 3 ? v * std::sqrt(v) : std::pow(v, erodePow)));
                cut[i] = std::min(maxCut, cut[i] + dt * (erode * p));
              }
            }
          }
        });
        std::swap(ice, next);
      }
      std::map<std::string, Grid> all;
      all["height"] = Like(*src);
      all["ice"] = Like(*src);
      all["cover"] = Like(*src);
      all["carve"] = Like(*src);
      for (std::size_t i = 0; i < n; ++i) {
        all["height"].v[i] = bed[i] - cut[i];
        all["ice"].v[i] = ice[i];
        all["cover"].v[i] = SmoothStep(0.0f, 2.0f, ice[i]);
        all["carve"].v[i] = cut[i];
      }
      return Emit(a, out, all, "height", err);
    }

    // ---- settle
    // ----------------------------------------------------------------------------------------------------------------------------------

    bool OpSettle(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      if (src == nullptr || !MakeOut(a, out, err))
        return false;
      const Grid* mask = Get(a, "mask");
      if (!SameOrNone(mask, *src, "mask", err))
        return false;
      const int w = src->w, h = src->h;
      const std::size_t n = src->Count();
      const float rate = std::max(0.0f, std::min(1.0f, static_cast<float>(a.p.N("rate", 0.4))));
      const float cap = std::max(0.0f, static_cast<float>(a.p.N("cap", 0.5)));
      const float sLo = static_cast<float>(a.p.N("slope_lo", 0.2)), sHi = static_cast<float>(a.p.N("slope_hi", 0.6));
      const int iterations = ItersOf(a, 20);
      const float cell = src->cell;
      Grid cur = *src, next = *src;
      std::vector<float> dep(n, 0.0f);
      for (int it = 0; it < iterations; ++it) {
        Rows(h, [&](const int z0, const int z1) {
          for (int z = z0; z < z1; ++z) {
            for (int x = 0; x < w; ++x) {
              const std::size_t i =
                static_cast<std::size_t>(z) * static_cast<std::size_t>(w) + static_cast<std::size_t>(x);
              const float c = cur.v[i];
              float sum = 0.0f;
              int cnt = 0;
              for (int k = 0; k < 8; ++k) {
                const int nx = x + kDx[k], nz = z + kDz[k];
                if (nx < 0 || nz < 0 || nx >= w || nz >= h)
                  continue;
                sum += cur.At(nx, nz);
                ++cnt;
              }
              const float mean = cnt > 0 ? sum / static_cast<float>(cnt) : c;
              float gx, gz;
              GradientAt(cur, x, z, gx, gz);
              float wgt = 1.0f - SmoothStep(sLo, sHi, std::sqrt(gx * gx + gz * gz));
              if (mask != nullptr)
                wgt *= Clamp01(mask->v[i]);
              const float fill = rate * std::min(cap, std::max(0.0f, mean - c)) * wgt;
              next.v[i] = c + fill;
              dep[i] += fill;
            }
          }
        });
        std::swap(cur.v, next.v);
        (void)cell;
      }
      std::map<std::string, Grid> all;
      all["height"] = std::move(cur);
      all["deposit"] = Like(*src);
      const float sc = std::max(1e-4f, static_cast<float>(a.p.N("deposit_scale", 1.0)));
      for (std::size_t i = 0; i < n; ++i)
        all["deposit"].v[i] = Clamp01(dep[i] / sc);
      return Emit(a, out, all, "height", err);
    }

    struct Ero2OpRegistrar
    {
      Ero2OpRegistrar()
      {
        RegisterOp("thermal_map", &OpThermalMap);
        RegisterOp("erode_rocksoil", &OpRockSoil);
        RegisterOp("erode_snow", &OpSnow);
        RegisterOp("erode_wind", &OpWind);
        RegisterOp("erode_glacier", &OpGlacier);
        RegisterOp("settle", &OpSettle);
      }
    };
    const Ero2OpRegistrar gEro2OpRegistrar{};
  } // namespace
} // namespace faf::editor::field
