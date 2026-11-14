// stage T7 filters, analysis masks and the colour ramp of the field engine (FAF Studio's
// docs/projects/editor/TERRAIN_GEN_DESIGN.md, section T7). Engine independent; registered through RegisterOp.
//
//   bilateral    a. Edge preserving smooth: a window average weighted by distance and by the height difference
//   (Lorentzian range weight 1 / (1 + (d / sigma_r)^2)). radius (units), sigma_r (height
//                units), mask (0..1: how much of the smoothed result is used).
//   diffuse      a. Perona-Malik anisotropic diffusion: smooths flat ground, keeps cliffs and ridges. iterations, kappa
//   (rise per run that still diffuses), rate (<= 0.25), g lorentz | exp, mask. unsharp      a. Sharpen: a + amount * (a
//   - blur(a)); radius (sigma, units), amount, threshold (height units; smaller differences are left alone), mask. edge
//   a. Edge detection: mode sobel | prewitt (rise per run) | laplace | dog (difference of gaussians, radius / radius *
//   ratio); gain; smooth (sigma, units, applied first); signed (laplace, dog). morph        a. Grey scale morphology:
//   op dilate | erode | open | close | gradient | tophat | bothat; radius (units), shape square | disc | cross |
//   diamond. convolve     a. Convolution with the square `kernel` (n x n numbers, n odd up to 15), normalize (divide by
//   the sum; default 1 when the sum is not 0), scale, bias, edge. blur_dir     a. Directional blur: angle (degrees; the
//   direction (cos, sin) of the blur), length (units), shape box | tri | gauss, mask. blur_slope   a. Blur that follows
//   the slope: blurs (sigma, units) only where the ground is flat (mode flat) or only where it is steep (steep); lo /
//   hi (rise per run) are the soft limits. stratify     a. Rock layering: the height is pushed onto shelves of random
//   thickness: thickness (units), variation, tilt_x / tilt_z (rise per run: the layers dip), warp / warp_size
//                (units), sharpness, strength, slope_lo / slope_hi (layering only on ground steeper than this; 0 / 0 =
//                everywhere), seed.
//   occlusion    a. Ambient occlusion of the surface: mode cavity (how closed the ground is, pits and gullies) | convex
//   (how exposed, ridges) | both (0.5 = flat, above = concave); radius
//                (units), directions, gain.
//   hillshade    a. Shading: azimuth (degrees towards the light, the direction (cos, sin)), altitude (degrees), z
//   (vertical exaggeration), mode shade | lit (sun facing and not shadowed) |
//                shadow (cast shadow only), shadow_len (units), ambient.
//   wetness      a. Topographic wetness: multiple flow direction accumulation (Freeman, exponent p) and the slope:
//   ln(specific catchment / tan(slope)). mode wet (smoothed to 0..1 between lo
//                and hi) | twi (raw) | area (log scale of the catchment), smooth (sigma, units).
//   rockiness    a, optional b (soil thickness, units). Where bare rock shows: slope (slope_lo .. slope_hi degrees),
//   convexity (radius, gain) and thin soil (soil_full units); weights w_slope,
//                w_convex, w_soil; breakup (noise amplitude), seed.
//   normal_map   a (heights). The map normal of the engine (CHeightField::GetNormal: (left - right, 1, top - bottom)
//   normalized, the samples half a unit either side) as three fields in the range
//                0..1 (n * 0.5 + 0.5, what the terrain's own normal map stores): x is the result, y and z come back as
//                the extra outputs. span (units between the two samples of a difference), strength (scales the slope),
//                shift (units added to the sample positions; the result's origin moves with it: 0.5 puts the samples at
//                the centres of the map squares like the engine's normal map), signed (-1..1 instead).
//   color_ramp   a (a mask). A gradient map: `stops` = 5 numbers per stop (position, r, g, b, a, all 0..1), positions
//   sorted by the op; lo / hi map the input onto 0..1; interp linear | smooth |
//                step. The result is the red channel; green, blue and alpha come back as the extra outputs g, b, a.
//
// Every output sample is computed from the inputs alone in a fixed order, so the results are bit identical for any
// thread count. The golden checksums (tests/editor/FieldTests.cpp) assume no fused multiply-add.
#if defined(__clang__)
#pragma clang fp contract(off)
#else
#pragma fp_contract(off)
#endif

#include "editor/terrain/EdFieldUtil.h"

#include <algorithm>
#include <cmath>
#include <numeric>

namespace faf::editor::field
{
  using namespace t7;

  namespace
  {
    inline int SamplesOf(
      const double units,
      const Grid& g,
      const int lo,
      const int hi
    )
    {
      return std::max(lo, std::min(hi, static_cast<int>(std::lround(units / static_cast<double>(g.cell)))));
    }

    // ---- bilateral
    // -------------------------------------------------------------------------------------------------------------------------------

    bool OpBilateral(
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
      const int r = SamplesOf(a.p.N("radius", 6.0), *src, 1, 12);
      const float sr = std::max(1e-4f, static_cast<float>(a.p.N("sigma_r", 2.0)));
      const float inv = 1.0f / (sr * sr);
      const float sigS = std::max(0.3f, static_cast<float>(r) * 0.5f);
      std::vector<float> ws(static_cast<std::size_t>((2 * r + 1) * (2 * r + 1)));
      for (int dz = -r; dz <= r; ++dz) {
        for (int dx = -r; dx <= r; ++dx) {
          ws[static_cast<std::size_t>((dz + r) * (2 * r + 1) + dx + r)] =
            std::exp(-0.5f * static_cast<float>(dx * dx + dz * dz) / (sigS * sigS));
        }
      }
      const int w = src->w, h = src->h;
      Cells(out, [&](const int x, const int z) {
        const float c = src->At(x, z);
        float sum = 0.0f, wsum = 0.0f;
        for (int dz = -r; dz <= r; ++dz) {
          const int zz = z + dz;
          if (zz < 0 || zz >= h)
            continue;
          const float* row = src->v.data() + static_cast<std::size_t>(zz) * static_cast<std::size_t>(w);
          const float* wrow = ws.data() + static_cast<std::size_t>((dz + r) * (2 * r + 1) + r);
          const int x0 = std::max(0, x - r), x1 = std::min(w - 1, x + r);
          for (int xx = x0; xx <= x1; ++xx) {
            const float v = row[xx];
            const float d = v - c;
            const float wt = wrow[xx - x] / (1.0f + d * d * inv);
            sum += wt * v;
            wsum += wt;
          }
        }
        const float res = sum / wsum;
        return mask != nullptr ? Lerp(c, res, Clamp01(mask->At(x, z))) : res;
      });
      return true;
    }

    // ---- diffuse (Perona-Malik)
    // --------------------------------------------------------------------------------------------------------------------

    bool OpDiffuse(
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
      const int iterations = std::max(0, std::min(5000, static_cast<int>(a.p.N("iterations", 20))));
      const float kappa = std::max(1e-4f, static_cast<float>(a.p.N("kappa", 0.4)));
      const float rate = std::max(0.0f, std::min(0.25f, static_cast<float>(a.p.N("rate", 0.2))));
      const bool expo = a.p.S("g", "lorentz") == "exp";
      const float invK2 = 1.0f / (kappa * kappa);
      const float invCell = 1.0f / src->cell;
      const int w = src->w, h = src->h;
      Grid cur = *src;
      Grid next = *src;
      const auto cond = [&](const float diff) {
        const float g = diff * invCell;
        const float t = g * g * invK2;
        return expo ? std::exp(-t) : 1.0f / (1.0f + t);
      };
      for (int it = 0; it < iterations; ++it) {
        Rows(h, [&](const int z0, const int z1) {
          for (int z = z0; z < z1; ++z) {
            for (int x = 0; x < w; ++x) {
              const float c = cur.At(x, z);
              float flux = 0.0f;
              if (x > 0) {
                const float d = cur.At(x - 1, z) - c;
                flux += cond(d) * d;
              }
              if (x < w - 1) {
                const float d = cur.At(x + 1, z) - c;
                flux += cond(d) * d;
              }
              if (z > 0) {
                const float d = cur.At(x, z - 1) - c;
                flux += cond(d) * d;
              }
              if (z < h - 1) {
                const float d = cur.At(x, z + 1) - c;
                flux += cond(d) * d;
              }
              float r = rate;
              if (mask != nullptr)
                r *= Clamp01(mask->At(x, z));
              next.At(x, z) = c + r * flux;
            }
          }
        });
        std::swap(cur.v, next.v);
      }
      out.v = std::move(cur.v);
      return true;
    }

    // ---- unsharp
    // ---------------------------------------------------------------------------------------------------------------------------------

    bool OpUnsharp(
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
      const double sigma = std::max(0.3, a.p.N("radius", 4.0) / static_cast<double>(src->cell));
      const float amount = static_cast<float>(a.p.N("amount", 1.0));
      const float thr = std::max(0.0f, static_cast<float>(a.p.N("threshold", 0.0)));
      Grid blur;
      GaussBlur(*src, blur, sigma);
      Cells(out, [&](const int x, const int z) {
        const float c = src->At(x, z);
        const float d = c - blur.At(x, z);
        float amt = amount;
        if (thr > 0.0f)
          amt *= SmoothStep(0.0f, thr, std::fabs(d));
        if (mask != nullptr)
          amt *= Clamp01(mask->At(x, z));
        return c + amt * d;
      });
      return true;
    }

    // ---- edge
    // ------------------------------------------------------------------------------------------------------------------------------------

    bool OpEdge(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src0 = Need(a, "a", err);
      if (src0 == nullptr || !MakeOut(a, out, err))
        return false;
      const std::string mode = a.p.S("mode", "sobel");
      if (mode != "sobel" && mode != "prewitt" && mode != "laplace" && mode != "dog") {
        err = "edge: mode must be sobel, prewitt, laplace or dog";
        return false;
      }
      const float gain = static_cast<float>(a.p.N("gain", 1.0));
      const bool sgn = a.p.N("signed", 0) != 0;
      const double pre = a.p.N("smooth", 0.0) / static_cast<double>(src0->cell);
      Grid smoothed;
      const Grid* src = src0;
      if (pre > 0.05) {
        GaussBlur(*src0, smoothed, pre);
        src = &smoothed;
      }
      const int w = src->w, h = src->h;
      const float cell = src->cell;
      if (mode == "dog") {
        const double s1 = std::max(0.3, a.p.N("radius", 2.0) / static_cast<double>(src->cell));
        const double s2 = s1 * std::max(1.1, a.p.N("ratio", 1.6));
        Grid b1, b2;
        GaussBlur(*src, b1, s1);
        GaussBlur(*src, b2, s2);
        Cells(out, [&](const int x, const int z) {
          const float d = (b1.At(x, z) - b2.At(x, z)) * gain;
          return sgn ? Clamp01(0.5f + d) : Clamp01(std::fabs(d));
        });
        return true;
      }
      const auto at = [&](const int x, const int z) {
        return src->At(std::max(0, std::min(w - 1, x)), std::max(0, std::min(h - 1, z)));
      };
      Cells(out, [&](const int x, const int z) {
        if (mode == "laplace") {
          const float lap =
            (at(x - 1, z) + at(x + 1, z) + at(x, z - 1) + at(x, z + 1) - 4.0f * at(x, z)) / (cell * cell);
          return sgn ? Clamp01(0.5f + gain * lap) : Clamp01(std::fabs(lap) * gain);
        }
        const float wc = mode == "sobel" ? 2.0f : 1.0f;
        const float gx = ((at(x + 1, z - 1) + wc * at(x + 1, z) + at(x + 1, z + 1)) -
                          (at(x - 1, z - 1) + wc * at(x - 1, z) + at(x - 1, z + 1))) /
          ((2.0f + wc) * 2.0f * cell);
        const float gz = ((at(x - 1, z + 1) + wc * at(x, z + 1) + at(x + 1, z + 1)) -
                          (at(x - 1, z - 1) + wc * at(x, z - 1) + at(x + 1, z - 1))) /
          ((2.0f + wc) * 2.0f * cell);
        return Clamp01(std::sqrt(gx * gx + gz * gz) * gain);
      });
      return true;
    }

    // ---- morph
    // -----------------------------------------------------------------------------------------------------------------------------------

    struct Offsets
    {
      std::vector<int> dx, dz;
    };

    /** One dilation (isMax) or erosion over the window; the square shape is two separable passes. */
    void MorphPass(
      const Grid& src,
      Grid& dst,
      const int r,
      const int shape,
      const bool isMax
    )
    {
      const int w = src.w, h = src.h;
      dst = Grid(w, h, src.cell, src.ox, src.oz);
      const auto better = [&](const float a, const float b) {
        return isMax ? a > b : a < b;
      };
      if (shape == 0) {
        Grid tmp(w, h, src.cell, src.ox, src.oz);
        Rows(h, [&](const int z0, const int z1) {
          for (int z = z0; z < z1; ++z) {
            const float* in = src.v.data() + static_cast<std::size_t>(z) * static_cast<std::size_t>(w);
            float* o = tmp.v.data() + static_cast<std::size_t>(z) * static_cast<std::size_t>(w);
            for (int x = 0; x < w; ++x) {
              float best = in[x];
              const int x0 = std::max(0, x - r), x1 = std::min(w - 1, x + r);
              for (int xx = x0; xx <= x1; ++xx)
                if (better(in[xx], best))
                  best = in[xx];
              o[x] = best;
            }
          }
        });
        Rows(h, [&](const int z0, const int z1) {
          for (int z = z0; z < z1; ++z) {
            float* o = dst.v.data() + static_cast<std::size_t>(z) * static_cast<std::size_t>(w);
            for (int x = 0; x < w; ++x)
              o[x] = tmp.At(x, z);
            const int za = std::max(0, z - r), zb = std::min(h - 1, z + r);
            for (int zz = za; zz <= zb; ++zz) {
              const float* in = tmp.v.data() + static_cast<std::size_t>(zz) * static_cast<std::size_t>(w);
              for (int x = 0; x < w; ++x)
                if (better(in[x], o[x]))
                  o[x] = in[x];
            }
          }
        });
        return;
      }
      Offsets off;
      for (int dz = -r; dz <= r; ++dz) {
        for (int dx = -r; dx <= r; ++dx) {
          bool in = false;
          if (shape == 1)
            in = dx * dx + dz * dz <= r * r;
          else if (shape == 2)
            in = dx == 0 || dz == 0;
          else
            in = std::abs(dx) + std::abs(dz) <= r;
          if (in) {
            off.dx.push_back(dx);
            off.dz.push_back(dz);
          }
        }
      }
      Cells(dst, [&](const int x, const int z) {
        float best = src.At(x, z);
        for (std::size_t k = 0; k < off.dx.size(); ++k) {
          const int xx = x + off.dx[k], zz = z + off.dz[k];
          if (xx < 0 || zz < 0 || xx >= w || zz >= h)
            continue;
          const float v = src.At(xx, zz);
          if (better(v, best))
            best = v;
        }
        return best;
      });
    }

    bool OpMorph(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      if (src == nullptr || !MakeOut(a, out, err))
        return false;
      const std::string op = a.p.S("op", "dilate");
      static const char* const ops[] = {"dilate", "erode", "open", "close", "gradient", "tophat", "bothat"};
      int k = -1;
      for (int i = 0; i < 7; ++i)
        if (op == ops[i])
          k = i;
      if (k < 0) {
        err = "morph: op must be dilate, erode, open, close, gradient, tophat or bothat";
        return false;
      }
      const std::string sh = a.p.S("shape", "square");
      int shape = sh == "square" ? 0 : (sh == "disc" ? 1 : (sh == "cross" ? 2 : (sh == "diamond" ? 3 : -1)));
      if (shape < 0) {
        err = "morph: shape must be square, disc, cross or diamond";
        return false;
      }
      const int r = SamplesOf(a.p.N("radius", 4.0), *src, 1, shape == 0 ? 32 : 16);
      Grid t1, t2;
      switch (k) {
      case 0:
        MorphPass(*src, out, r, shape, true);
        break;
      case 1:
        MorphPass(*src, out, r, shape, false);
        break;
      case 2:
        MorphPass(*src, t1, r, shape, false);
        MorphPass(t1, out, r, shape, true);
        break;
      case 3:
        MorphPass(*src, t1, r, shape, true);
        MorphPass(t1, out, r, shape, false);
        break;
      case 4:
        MorphPass(*src, t1, r, shape, true);
        MorphPass(*src, t2, r, shape, false);
        Cells(out, [&](const int x, const int z) {
          return t1.At(x, z) - t2.At(x, z);
        });
        break;
      case 5:
        MorphPass(*src, t1, r, shape, false);
        MorphPass(t1, t2, r, shape, true);
        Cells(out, [&](const int x, const int z) {
          return src->At(x, z) - t2.At(x, z);
        });
        break;
      default:
        MorphPass(*src, t1, r, shape, true);
        MorphPass(t1, t2, r, shape, false);
        Cells(out, [&](const int x, const int z) {
          return t2.At(x, z) - src->At(x, z);
        });
        break;
      }
      return true;
    }

    // ---- convolve
    // --------------------------------------------------------------------------------------------------------------------------------

    bool OpConvolve(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      if (src == nullptr || !MakeOut(a, out, err))
        return false;
      const std::vector<double>* kv = a.p.A("kernel");
      if (kv == nullptr || kv->empty()) {
        err = "convolve: 'kernel' needs n x n numbers";
        return false;
      }
      const int n = static_cast<int>(std::lround(std::sqrt(static_cast<double>(kv->size()))));
      if (n * n != static_cast<int>(kv->size()) || n % 2 == 0 || n > 15) {
        err = "convolve: the kernel must be n x n numbers with n odd and at most 15";
        return false;
      }
      std::vector<float> k(kv->size());
      double sum = 0.0;
      for (std::size_t i = 0; i < k.size(); ++i) {
        k[i] = static_cast<float>((*kv)[i]);
        sum += static_cast<double>(k[i]);
      }
      float mul = static_cast<float>(a.p.N("scale", 1.0));
      if (a.p.N("normalize", 1) != 0 && std::fabs(sum) > 1e-6)
        mul /= static_cast<float>(sum);
      const float bias = static_cast<float>(a.p.N("bias", 0.0));
      const Edge e = ParseEdge(a, kClamp);
      const int r = n / 2;
      Cells(out, [&](const int x, const int z) {
        float acc = 0.0f;
        for (int j = 0; j < n; ++j) {
          for (int i = 0; i < n; ++i) {
            acc += k[static_cast<std::size_t>(j * n + i)] * Fetch(*src, x + i - r, z + j - r, e);
          }
        }
        return acc * mul + bias;
      });
      return true;
    }

    // ---- blur_dir
    // --------------------------------------------------------------------------------------------------------------------------------

    bool OpBlurDir(
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
      const double ang = a.p.N("angle", 0.0) * kPiD / 180.0;
      const float ux = static_cast<float>(std::cos(ang)), uz = static_cast<float>(std::sin(ang));
      const float len = std::max(0.0f, static_cast<float>(a.p.N("length", 20.0) / static_cast<double>(src->cell)));
      const std::string shape = a.p.S("shape", "box");
      const int half = std::max(0, std::min(256, static_cast<int>(std::ceil(len * 0.5f))));
      if (half == 0) {
        out.v = src->v;
        return true;
      }
      std::vector<float> wt(static_cast<std::size_t>(2 * half + 1));
      float wsum = 0.0f;
      for (int i = -half; i <= half; ++i) {
        const float t = static_cast<float>(i) / static_cast<float>(half);
        float v = 1.0f;
        if (shape == "tri")
          v = 1.0f - std::fabs(t);
        else if (shape == "gauss")
          v = std::exp(-2.0f * t * t);
        wt[static_cast<std::size_t>(i + half)] = v;
        wsum += v;
      }
      Cells(out, [&](const int x, const int z) {
        float acc = 0.0f;
        for (int i = -half; i <= half; ++i) {
          acc += wt[static_cast<std::size_t>(i + half)] *
            BilinearC(
                   *src,
                   static_cast<float>(x) + ux * static_cast<float>(i),
                   static_cast<float>(z) + uz * static_cast<float>(i)
            );
        }
        const float res = acc / wsum;
        return mask != nullptr ? Lerp(src->At(x, z), res, Clamp01(mask->At(x, z))) : res;
      });
      return true;
    }

    // ---- blur_slope
    // ------------------------------------------------------------------------------------------------------------------------------

    bool OpBlurSlope(
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
      const std::string mode = a.p.S("mode", "flat");
      if (mode != "flat" && mode != "steep") {
        err = "blur_slope: mode must be flat or steep";
        return false;
      }
      const double sigma = std::max(0.3, a.p.N("radius", 6.0) / static_cast<double>(src->cell));
      const float lo = static_cast<float>(a.p.N("lo", 0.3));
      const float hi = static_cast<float>(a.p.N("hi", 0.7));
      const float amount = Clamp01(static_cast<float>(a.p.N("amount", 1.0)));
      const bool flat = mode == "flat";
      Grid blur;
      GaussBlur(*src, blur, sigma);
      Cells(out, [&](const int x, const int z) {
        float gx, gz;
        GradientAt(*src, x, z, gx, gz);
        const float s = std::sqrt(gx * gx + gz * gz);
        float wgt = flat ? 1.0f - SmoothStep(lo, hi, s) : SmoothStep(lo, hi, s);
        wgt *= amount;
        if (mask != nullptr)
          wgt *= Clamp01(mask->At(x, z));
        return Lerp(src->At(x, z), blur.At(x, z), wgt);
      });
      return true;
    }

    // ---- stratify
    // --------------------------------------------------------------------------------------------------------------------------------

    bool OpStratify(
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
      const std::uint32_t seed = SeedOf(a);
      const float thick = std::max(0.2f, static_cast<float>(a.p.N("thickness", 3.0)));
      const float variation = Clamp01(static_cast<float>(a.p.N("variation", 0.5)));
      const float tiltX = static_cast<float>(a.p.N("tilt_x", 0.0)), tiltZ = static_cast<float>(a.p.N("tilt_z", 0.0));
      const double warp = a.p.N("warp", 0.0);
      const double warpSize = std::max(2.0, a.p.N("warp_size", 120.0));
      const float sharp = Clamp01(static_cast<float>(a.p.N("sharpness", 0.7)));
      const float strength = Clamp01(static_cast<float>(a.p.N("strength", 1.0)));
      const float sLo = static_cast<float>(a.p.N("slope_lo", 0.0)), sHi = static_cast<float>(a.p.N("slope_hi", 0.0));
      constexpr int K = 2048;
      std::vector<float> bounds(static_cast<std::size_t>(2 * K + 1), 0.0f);
      std::vector<float> hard(static_cast<std::size_t>(2 * K), 0.0f);
      for (int k = 0; k < K; ++k) {
        const float t = thick * (1.0f + variation * (2.0f * Unit(Hash2(k, 0, seed)) - 1.0f));
        bounds[static_cast<std::size_t>(K + k + 1)] = bounds[static_cast<std::size_t>(K + k)] + t;
      }
      for (int k = -1; k >= -K; --k) {
        const float t = thick * (1.0f + variation * (2.0f * Unit(Hash2(k, 0, seed)) - 1.0f));
        bounds[static_cast<std::size_t>(K + k)] = bounds[static_cast<std::size_t>(K + k + 1)] - t;
      }
      for (int i = 0; i < 2 * K; ++i)
        hard[static_cast<std::size_t>(i)] = 0.25f + 0.5f * Unit(Hash2(i - K, 1, seed));
      const float wdt = 0.5f * (1.0f - sharp) + 0.02f;
      const Grid& g = *src;
      Cells(out, [&](const int x, const int z) {
        const float hgt = g.At(x, z);
        float hh = hgt + tiltX * static_cast<float>(WorldX(g, x)) + tiltZ * static_cast<float>(WorldZ(g, z));
        if (warp != 0.0)
          hh += static_cast<float>(warp) * (2.0f * Fbm01(WorldX(g, x), WorldZ(g, z), seed + 911U, warpSize, 3) - 1.0f);
        const auto it = std::upper_bound(bounds.begin(), bounds.end(), hh);
        int i = static_cast<int>(it - bounds.begin()) - 1;
        i = std::max(0, std::min(2 * K - 1, i));
        const float b0 = bounds[static_cast<std::size_t>(i)], b1 = bounds[static_cast<std::size_t>(i + 1)];
        const float f = Clamp01((hh - b0) / std::max(1e-6f, b1 - b0));
        const float c = hard[static_cast<std::size_t>(i)];
        const float shelf = SmoothStep(c - wdt, c + wdt, f);
        const float hs = b0 + (b1 - b0) * shelf;
        float m = strength;
        if (sHi > sLo) {
          float gx, gz;
          GradientAt(g, x, z, gx, gz);
          m *= SmoothStep(sLo, sHi, std::sqrt(gx * gx + gz * gz));
        }
        if (mask != nullptr)
          m *= Clamp01(mask->At(x, z));
        return hgt + m * (hs - hh);
      });
      return true;
    }

    // ---- occlusion
    // -------------------------------------------------------------------------------------------------------------------------------

    bool OpOcclusion(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      if (src == nullptr || !MakeOut(a, out, err))
        return false;
      const std::string mode = a.p.S("mode", "cavity");
      if (mode != "cavity" && mode != "convex" && mode != "both") {
        err = "occlusion: mode must be cavity, convex or both";
        return false;
      }
      const int m = mode == "cavity" ? 0 : (mode == "convex" ? 1 : 2);
      const int dirs = std::max(4, std::min(32, static_cast<int>(a.p.N("directions", 12))));
      const float radius = std::max(static_cast<float>(src->cell), static_cast<float>(a.p.N("radius", 30.0)));
      const float gain = static_cast<float>(a.p.N("gain", 1.0));
      const int steps = std::max(2, std::min(32, static_cast<int>(std::lround(radius / src->cell))));
      std::vector<float> dist(static_cast<std::size_t>(steps));
      for (int s = 0; s < steps; ++s) {
        const float t = static_cast<float>(s + 1) / static_cast<float>(steps);
        dist[static_cast<std::size_t>(s)] =
          std::max(1.0f, (radius / src->cell) * t * t); // samples; denser close to the point
      }
      std::vector<float> cs(static_cast<std::size_t>(dirs)), sn(static_cast<std::size_t>(dirs));
      for (int d = 0; d < dirs; ++d) {
        const float th = 2.0f * kPi * static_cast<float>(d) / static_cast<float>(dirs);
        cs[static_cast<std::size_t>(d)] = std::cos(th);
        sn[static_cast<std::size_t>(d)] = std::sin(th);
      }
      const float cell = src->cell;
      Cells(out, [&](const int x, const int z) {
        const float c = src->At(x, z);
        float occConcave = 0.0f, occConvex = 0.0f;
        for (int d = 0; d < dirs; ++d) {
          float up = 0.0f, down = 0.0f; // largest rise / drop per run seen along the direction
          for (int s = 0; s < steps; ++s) {
            const float dsm = dist[static_cast<std::size_t>(s)];
            const float v = BilinearC(
              *src,
              static_cast<float>(x) + cs[static_cast<std::size_t>(d)] * dsm,
              static_cast<float>(z) + sn[static_cast<std::size_t>(d)] * dsm
            );
            const float tg = (v - c) / (dsm * cell);
            up = std::max(up, tg);
            down = std::max(down, -tg);
          }
          occConcave += up / std::sqrt(1.0f + up * up);
          occConvex += down / std::sqrt(1.0f + down * down);
        }
        occConcave /= static_cast<float>(dirs);
        occConvex /= static_cast<float>(dirs);
        if (m == 0)
          return Clamp01(occConcave * gain);
        if (m == 1)
          return Clamp01(occConvex * gain);
        return Clamp01(0.5f + 0.5f * (occConcave - occConvex) * gain);
      });
      return true;
    }

    // ---- hillshade
    // -------------------------------------------------------------------------------------------------------------------------------

    bool OpHillshade(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      if (src == nullptr || !MakeOut(a, out, err))
        return false;
      const std::string mode = a.p.S("mode", "shade");
      if (mode != "shade" && mode != "lit" && mode != "shadow") {
        err = "hillshade: mode must be shade, lit or shadow";
        return false;
      }
      const int m = mode == "shade" ? 0 : (mode == "lit" ? 1 : 2);
      const double az = a.p.N("azimuth", 315.0) * kPiD / 180.0;
      const double alt = std::max(1.0, std::min(89.0, a.p.N("altitude", 40.0))) * kPiD / 180.0;
      const float zf = static_cast<float>(a.p.N("z", 1.0));
      const float ambient = Clamp01(static_cast<float>(a.p.N("ambient", 0.15)));
      const bool shadows = (m != 0) || a.p.N("shadows", 0) != 0;
      const float len =
        std::max(static_cast<float>(src->cell), static_cast<float>(a.p.N("shadow_len", 150.0))) / src->cell; // samples
      const float lx = static_cast<float>(std::cos(alt) * std::cos(az)), ly = static_cast<float>(std::sin(alt)),
                  lz = static_cast<float>(std::cos(alt) * std::sin(az));
      const float dirx = static_cast<float>(std::cos(az)), dirz = static_cast<float>(std::sin(az));
      const float tanAlt = static_cast<float>(std::tan(alt));
      const float cell = src->cell;
      Cells(out, [&](const int x, const int z) {
        float gx, gz;
        GradientAt(*src, x, z, gx, gz);
        gx *= zf;
        gz *= zf;
        const float inv = 1.0f / std::sqrt(gx * gx + gz * gz + 1.0f);
        const float ndl = (-gx * lx + ly - gz * lz) * inv;
        float lit = ndl > 0.0f ? 1.0f : 0.0f;
        if (shadows) {
          const float h0 = src->At(x, z);
          float t = 1.0f;
          float shade = 1.0f;
          while (t < len) {
            const float hs = BilinearC(*src, static_cast<float>(x) + dirx * t, static_cast<float>(z) + dirz * t);
            const float ray = h0 + t * cell * tanAlt;
            if (hs > ray + 0.01f) {
              shade = 0.0f;
              break;
            }
            t += 1.0f + t * 0.12f;
          }
          lit *= shade;
          if (m == 2)
            return 1.0f - shade;
          if (m == 1)
            return lit * SmoothStep(0.0f, 0.25f, ndl);
          return Clamp01(ambient + (1.0f - ambient) * std::max(0.0f, ndl) * shade);
        }
        return Clamp01(ambient + (1.0f - ambient) * std::max(0.0f, ndl));
      });
      return true;
    }

    // ---- normal_map
    // ------------------------------------------------------------------------------------------------------------------------------

    bool OpNormalMap(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      if (src == nullptr || !MakeOut(a, out, err))
        return false;
      const float span = std::max(0.05f, static_cast<float>(a.p.N("span", 1.0)));
      const float strength = static_cast<float>(a.p.N("strength", 1.0));
      const float shiftUnits = static_cast<float>(a.p.N("shift", 0.0));
      const float shift = shiftUnits / src->cell;
      out.ox = src->ox + shiftUnits; // the result lies where it was computed
      out.oz = src->oz + shiftUnits;
      const bool raw = a.p.N("signed", 0.0) != 0.0;
      const float half = 0.5f * span / src->cell; // samples either side of the point
      const float scale = strength / span;        // slope (rise per run) from a difference over `span`
      Grid Y(out.w, out.h, out.cell, out.ox, out.oz), Z = Y;
      Rows(out.h, [&](const int z0, const int z1) {
        for (int z = z0; z < z1; ++z) {
          for (int x = 0; x < out.w; ++x) {
            const float fx = static_cast<float>(x) + shift, fz = static_cast<float>(z) + shift;
            const float left = BilinearC(*src, fx - half, fz), right = BilinearC(*src, fx + half, fz);
            const float top = BilinearC(*src, fx, fz - half), bottom = BilinearC(*src, fx, fz + half);
            const float nx = (left - right) * scale, nz = (top - bottom) * scale;
            const float inv = 1.0f / std::sqrt(nx * nx + 1.0f + nz * nz);
            const float ex = nx * inv, ey = inv, ez = nz * inv;
            out.At(x, z) = raw ? ex : ex * 0.5f + 0.5f;
            Y.At(x, z) = raw ? ey : ey * 0.5f + 0.5f;
            Z.At(x, z) = raw ? ez : ez * 0.5f + 0.5f;
          }
        }
      });
      if (a.extra != nullptr) {
        (*a.extra)["y"] = std::move(Y);
        (*a.extra)["z"] = std::move(Z);
      }
      return true;
    }

    // ---- wetness
    // ---------------------------------------------------------------------------------------------------------------------------------

    bool OpWetness(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      if (src == nullptr || !MakeOut(a, out, err))
        return false;
      const std::string mode = a.p.S("mode", "wet");
      if (mode != "wet" && mode != "twi" && mode != "area") {
        err = "wetness: mode must be wet, twi or area";
        return false;
      }
      const float pf = static_cast<float>(std::max(0.5, std::min(8.0, a.p.N("p", 1.1))));
      const float lo = static_cast<float>(a.p.N("lo", 3.0)), hi = static_cast<float>(a.p.N("hi", 11.0));
      const int w = src->w, h = src->h;
      const std::size_t n = src->Count();
      std::vector<std::uint32_t> order;
      SortDescending(src->v, order);
      const std::vector<float>& H = src->v;
      std::vector<float> area(n, 1.0f);
      static const int dxs[8] = {-1, 1, 0, 0, -1, 1, -1, 1};
      static const int dzs[8] = {0, 0, -1, 1, -1, -1, 1, 1};
      const float cell = src->cell;
      for (const std::uint32_t idx : order) {
        const int x = static_cast<int>(idx % static_cast<std::uint32_t>(w)),
                  z = static_cast<int>(idx / static_cast<std::uint32_t>(w));
        const float c = H[static_cast<std::size_t>(idx)];
        float wk[8];
        float sum = 0.0f;
        for (int k = 0; k < 8; ++k) {
          const int nx = x + dxs[k], nz = z + dzs[k];
          wk[k] = 0.0f;
          if (nx < 0 || nz < 0 || nx >= w || nz >= h)
            continue;
          const float drop =
            c - H[static_cast<std::size_t>(nz) * static_cast<std::size_t>(w) + static_cast<std::size_t>(nx)];
          if (drop <= 0.0f)
            continue;
          const float dist = k < 4 ? 1.0f : 1.41421356f;
          wk[k] = pf == 1.0f ? drop / dist : std::pow(drop / dist, pf);
          sum += wk[k];
        }
        if (sum <= 0.0f)
          continue;
        const float share = area[static_cast<std::size_t>(idx)] / sum;
        for (int k = 0; k < 8; ++k) {
          if (wk[k] > 0.0f)
            area
              [static_cast<std::size_t>(z + dzs[k]) * static_cast<std::size_t>(w) +
               static_cast<std::size_t>(x + dxs[k])] += share * wk[k];
        }
      }
      Grid twi(w, h, cell, src->ox, src->oz);
      Cells(twi, [&](const int x, const int z) {
        float gx, gz;
        GradientAt(*src, x, z, gx, gz);
        const float tb = std::max(0.005f, std::sqrt(gx * gx + gz * gz));
        const float sca =
          area[static_cast<std::size_t>(z) * static_cast<std::size_t>(w) + static_cast<std::size_t>(x)] * cell;
        return std::log(sca / tb);
      });
      const double sm = a.p.N("smooth", 0.0) / static_cast<double>(cell);
      Grid sgrid;
      const Grid* t = &twi;
      if (sm > 0.05) {
        GaussBlur(twi, sgrid, sm);
        t = &sgrid;
      }
      Cells(out, [&](const int x, const int z) {
        if (mode == "twi")
          return t->At(x, z);
        if (mode == "area")
          return Clamp01(
            std::log2(area[static_cast<std::size_t>(z) * static_cast<std::size_t>(w) + static_cast<std::size_t>(x)]) /
            14.0f
          );
        return SmoothStep(lo, hi, t->At(x, z));
      });
      return true;
    }

    // ---- rockiness
    // -------------------------------------------------------------------------------------------------------------------------------

    bool OpRockiness(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      if (src == nullptr || !MakeOut(a, out, err))
        return false;
      const Grid* soil = Get(a, "b");
      if (!SameOrNone(soil, *src, "b", err))
        return false;
      const float slo = static_cast<float>(a.p.N("slope_lo", 25.0)), shi = static_cast<float>(a.p.N("slope_hi", 50.0));
      const int n = std::max(1, std::min(16, static_cast<int>(std::lround(a.p.N("radius", 6.0) / src->cell))));
      const float gain = static_cast<float>(a.p.N("gain", 14.0));
      const float soilFull = std::max(1e-3f, static_cast<float>(a.p.N("soil_full", 1.5)));
      const float wS = std::max(0.0f, static_cast<float>(a.p.N("w_slope", 1.0)));
      const float wC = std::max(0.0f, static_cast<float>(a.p.N("w_convex", 0.5)));
      float wB = soil != nullptr ? std::max(0.0f, static_cast<float>(a.p.N("w_soil", 1.0))) : 0.0f;
      const float breakup = static_cast<float>(a.p.N("breakup", 0.15));
      const std::uint32_t seed = SeedOf(a);
      const float norm = std::max(1e-6f, wS + wC + wB);
      const int w = src->w, h = src->h;
      const float cell = src->cell;
      const float d2 = static_cast<float>(n) * static_cast<float>(n) * cell * cell;
      const Grid& g = *src;
      Cells(out, [&](const int x, const int z) {
        float gx, gz;
        GradientAt(g, x, z, gx, gz);
        const float deg = std::atan(std::sqrt(gx * gx + gz * gz)) * (180.0f / kPi);
        const float c = g.At(x, z);
        const float lap = (g.At(std::max(0, x - n), z) + g.At(std::min(w - 1, x + n), z) + g.At(x, std::max(0, z - n)) +
                           g.At(x, std::min(h - 1, z + n)) - 4.0f * c) /
          d2;
        const float convex = Clamp01(0.5f - gain * lap);
        float v = wS * SmoothStep(slo, shi, deg) + wC * SmoothStep(0.5f, 1.0f, convex);
        if (soil != nullptr)
          v += wB * (1.0f - SmoothStep(0.0f, soilFull, soil->At(x, z)));
        v /= norm;
        if (breakup != 0.0f)
          v += breakup * (Fbm01(WorldX(g, x), WorldZ(g, z), seed, 14.0, 3) - 0.5f) * 2.0f;
        return Clamp01(v);
      });
      return true;
    }

    // ---- color_ramp
    // ------------------------------------------------------------------------------------------------------------------------------

    bool OpColorRamp(
      const OpArgs& a,
      Grid& out,
      std::string& err
    )
    {
      const Grid* src = Need(a, "a", err);
      if (src == nullptr || !MakeOut(a, out, err))
        return false;
      const std::vector<double>* sv = a.p.A("stops");
      if (sv == nullptr || sv->size() < 10 || sv->size() % 5 != 0) {
        err = "color_ramp: 'stops' needs at least two stops of 5 numbers (position, r, g, b, a)";
        return false;
      }
      struct Stop
      {
        float pos, r, g, b, a;
      };
      std::vector<Stop> st;
      for (std::size_t i = 0; i + 4 < sv->size(); i += 5) {
        st.push_back(
          {static_cast<float>((*sv)[i]),
           static_cast<float>((*sv)[i + 1]),
           static_cast<float>((*sv)[i + 2]),
           static_cast<float>((*sv)[i + 3]),
           static_cast<float>((*sv)[i + 4])}
        );
      }
      std::stable_sort(st.begin(), st.end(), [](const Stop& p, const Stop& q) {
        return p.pos < q.pos;
      });
      const float lo = static_cast<float>(a.p.N("lo", 0.0)), hi = static_cast<float>(a.p.N("hi", 1.0));
      const std::string interp = a.p.S("interp", "linear");
      const int im = interp == "step" ? 2 : (interp == "smooth" ? 1 : 0);
      Grid G(src->w, src->h, src->cell, src->ox, src->oz), B = G, A = G;
      const float span = hi != lo ? hi - lo : 1.0f;
      Rows(src->h, [&](const int z0, const int z1) {
        for (int z = z0; z < z1; ++z) {
          for (int x = 0; x < src->w; ++x) {
            const float t = Clamp01((src->At(x, z) - lo) / span);
            std::size_t i = 0;
            while (i + 1 < st.size() && t >= st[i + 1].pos)
              ++i;
            Stop s0 = st[i], s1 = st[std::min(st.size() - 1, i + 1)];
            float f = 0.0f;
            if (im != 2 && s1.pos > s0.pos && t > s0.pos)
              f = Clamp01((t - s0.pos) / (s1.pos - s0.pos));
            if (t >= st.back().pos) {
              s0 = s1 = st.back();
              f = 0.0f;
            }
            if (t <= st.front().pos) {
              s0 = s1 = st.front();
              f = 0.0f;
            }
            if (im == 1)
              f = f * f * (3.0f - 2.0f * f);
            out.At(x, z) = Lerp(s0.r, s1.r, f);
            G.At(x, z) = Lerp(s0.g, s1.g, f);
            B.At(x, z) = Lerp(s0.b, s1.b, f);
            A.At(x, z) = Lerp(s0.a, s1.a, f);
          }
        }
      });
      if (a.extra != nullptr) {
        (*a.extra)["g"] = std::move(G);
        (*a.extra)["b"] = std::move(B);
        (*a.extra)["a"] = std::move(A);
      }
      return true;
    }

    struct FiltOpRegistrar
    {
      FiltOpRegistrar()
      {
        RegisterOp("bilateral", &OpBilateral);
        RegisterOp("diffuse", &OpDiffuse);
        RegisterOp("unsharp", &OpUnsharp);
        RegisterOp("edge", &OpEdge);
        RegisterOp("morph", &OpMorph);
        RegisterOp("convolve", &OpConvolve);
        RegisterOp("blur_dir", &OpBlurDir);
        RegisterOp("blur_slope", &OpBlurSlope);
        RegisterOp("stratify", &OpStratify);
        RegisterOp("occlusion", &OpOcclusion);
        RegisterOp("hillshade", &OpHillshade);
        RegisterOp("normal_map", &OpNormalMap);
        RegisterOp("wetness", &OpWetness);
        RegisterOp("rockiness", &OpRockiness);
        RegisterOp("color_ramp", &OpColorRamp);
      }
    };
    const FiltOpRegistrar gFiltOpRegistrar{};
  } // namespace
} // namespace faf::editor::field
