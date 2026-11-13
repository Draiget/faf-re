#include "editor/tools/EdRecipes.h"

#include "editor/tools/EdMaskBrush.h"

#include <algorithm>
#include <cmath>
#include <memory>
#include <utility>

namespace faf::editor
{
  namespace
  {
    using enum GroundKind;
    constexpr std::size_t K(
      const GroundKind kind
    )
    {
      return static_cast<std::size_t>(kind);
    }

    MaskGenRule Rule(
      const char* const type,
      std::initializer_list<std::pair<const char*, float>> values,
      const MaskCombine op = MaskCombine::And
    )
    {
      MaskGenRule rule = NewMaskRule(type);
      for (const auto& [key, value] : values) {
        rule.v[key] = value;
      }
      rule.op = op;
      return rule;
    }

    /** What the builders read: the map's numbers, the knobs, the style, the plan, and the noise percentiles. */
    struct Builder
    {
      MaskGenContext& context;
      const RecipePlan& plan;
      const RecipeStats& st;
      const RecipeKnobs& k;
      const RecipeStyle& style;
      std::map<std::string, std::array<float, 101>>& noiseCache;

      float H(
        const float p
      ) const
      {
        return RecipeHeightAt(st, p);
      }
      /** The bottom of the land and its relief (3rd to 99.5th percentile). */
      void Zone(
        float& z0,
        float& relief
      ) const
      {
        z0 = H(0.03f);
        relief = std::max(1.0f, H(0.995f) - z0);
      }
      float Size() const
      {
        return std::clamp(k.patch * 1.6f, 40.0f, 160.0f);
      }
      float Breakup() const
      {
        return k.breakup * 2.0f;
      }
      /** How much altitude counts: 0 for flat country (a relief under 18 units), 1 from 60 units. */
      float Alt() const
      {
        if (style.altForce) {
          return 1.0f;
        }
        return std::clamp((H(0.99f) - H(0.03f) - 18.0f) / 42.0f, 0.0f, 1.0f);
      }
      bool HasOrBase(
        const GroundKind kind
      ) const
      {
        return plan.Has(kind) || plan.base == kind;
      }

      MaskGenRule SteepFrom(
        const float a0,
        const float a1,
        const float wobble = 0.0f,
        const float size = 80.0f,
        const float seed = 1.0f,
        const MaskCombine op = MaskCombine::And
      ) const
      {
        return Rule(
          "slope",
          {{"lo", a1},
           {"hi", 90},
           {"soft", std::max(1.0f, a1 - a0)},
           {"wobble", wobble},
           {"wsize", size},
           {"wseed", seed}},
          op
        );
      }
      MaskGenRule FlatTo(
        const float a0,
        const float a1,
        const float wobble,
        const float size,
        const float seed,
        const MaskCombine op
      ) const
      {
        return Rule(
          "slope",
          {{"lo", 0},
           {"hi", a0},
           {"soft", std::max(1.0f, a1 - a0)},
           {"wobble", wobble},
           {"wsize", size},
           {"wseed", seed}},
          op
        );
      }
      MaskGenRule RiseFrom(
        const float h0,
        const float h1,
        const float wobble,
        const float size,
        const float seed,
        const MaskCombine op,
        const float sun = 0.0f
      ) const
      {
        return Rule(
          "height",
          {{"lo", h1},
           {"hi", st.hmax + 1000.0f},
           {"soft", std::max(0.5f, h1 - h0)},
           {"wobble", wobble},
           {"wsize", size},
           {"wseed", seed},
           {"sun", sun}},
          op
        );
      }
      MaskGenRule FallTo(
        const float h0,
        const float h1,
        const float wobble,
        const float size,
        const float seed,
        const MaskCombine op
      ) const
      {
        return Rule(
          "height",
          {{"lo", st.hmin - 1000.0f},
           {"hi", h0},
           {"soft", std::max(0.5f, h1 - h0)},
           {"wobble", wobble},
           {"wsize", size},
           {"wseed", seed}},
          op
        );
      }
      static MaskGenRule Blur(
        const float radius
      )
      {
        return Rule("blur", {{"radius", radius}});
      }
      static MaskGenRule AtMost(
        const float factor
      )
      {
        return Rule("amount", {{"factor", factor}});
      }
      MaskGenRule Crisp(
        const float seed,
        const float size = 0.0f
      ) const
      {
        return Rule(
          "crisp",
          {{"crisp", k.crisp},
           {"noise", 0.25f + 0.4f * k.breakup},
           {"size", size > 0.0f ? size : std::max(10.0f, k.patch * 0.4f)},
           {"seed", seed}}
        );
      }
      MaskGenRule Grain(
        const float seed,
        const float scale
      ) const
      {
        return Rule("grain", {{"amount", std::min(0.8f, scale * (0.1f + 0.6f * k.fine))}, {"size", 7}, {"seed", seed}});
      }
      float SnowLine() const
      {
        float z0 = 0.0f;
        float relief = 0.0f;
        Zone(z0, relief);
        return std::max(H(1.0f - k.snow), z0 + relief * std::max(0.0f, 0.45f - 1.2f * k.snow));
      }

      /** The value a share p of a fractal noise lies below (its percentiles, from the noise itself; cached). */
      float NoiseAt(
        const float seed,
        const float size,
        const float p
      )
      {
        const std::string key = std::to_string(static_cast<int>(seed)) + "_" + std::to_string(static_cast<int>(size));
        auto found = noiseCache.find(key);
        if (found == noiseCache.end()) {
          std::array<float, 101> pct{};
          // On a coarse grid over the same ground: the noise depends on the world position only.
          const field::Grid& h = *context.heights;
          const float step = 4.0f;
          auto coarse = std::make_shared<field::Grid>(
            std::max(2, static_cast<int>(static_cast<float>(h.w - 1) / step) + 1),
            std::max(2, static_cast<int>(static_cast<float>(h.h - 1) / step) + 1),
            h.cell * step,
            h.ox,
            h.oz
          );
          field::OpArgs args;
          args.in["like"] = coarse;
          args.p.num["seed"] = std::floor(seed);
          args.p.num["scale"] = size;
          args.p.num["octaves"] = 5;
          field::Grid noise;
          std::string error;
          if (field::RunOpCpu("fractal", args, noise, error) && RecipePercentiles(noise.v, pct)) {
            found = noiseCache.emplace(key, pct).first;
          } else {
            for (int i = 0; i <= 100; ++i) {
              pct[static_cast<std::size_t>(i)] =
                0.5f + (static_cast<float>(i) / 100.0f - 0.5f) * 0.4f; // a typical spread
            }
            found = noiseCache.emplace(key, pct).first;
          }
        }
        const float x = std::clamp(p, 0.0f, 1.0f) * 100.0f;
        const int i = std::min(99, static_cast<int>(x));
        const auto& pct = found->second;
        return pct[static_cast<std::size_t>(i)] +
          (pct[static_cast<std::size_t>(i) + 1] - pct[static_cast<std::size_t>(i)]) * (x - static_cast<float>(i));
      }

      /** A fractal noise as a gentle 0..1 mix: 0 at the value a share p0 lies below, 1 at p1's. */
      MaskGenRule Mix(
        const float seed,
        const float size,
        const float p0,
        const float p1
      )
      {
        const float from = NoiseAt(seed, size, p0);
        float to = NoiseAt(seed, size, p1);
        if (to - from < 0.02f) {
          to = from + 0.02f;
        }
        return Rule("noise", {{"kind", 5}, {"seed", seed}, {"size", size}, {"octaves", 5}, {"from", from}, {"to", to}});
      }

      /** Below the snow line, on the kinds that stop where snow starts. */
      void UnderSnow(
        std::vector<MaskGenRule>& rules
      )
      {
        if (HasOrBase(Snow) && k.snow > 0.004f && Alt() > 0.04f) {
          float z0 = 0.0f;
          float relief = 0.0f;
          Zone(z0, relief);
          const float line = SnowLine();
          rules.push_back(FallTo(
            line - 0.12f * relief,
            line + 0.04f * relief,
            0.1f * relief * Breakup(),
            Size(),
            k.seed + 7,
            MaskCombine::Mul
          ));
        }
      }

      /** The kind's selection; false when it is off on this map (the style, or nothing for it here). */
      bool Build(
        const GroundKind kind,
        std::vector<MaskGenRule>& rules
      )
      {
        rules.clear();
        if (plan.base == kind) {
          return true; // the base kind: what the others leave
        }
        const float size = Size();
        const float bk = Breakup();
        float z0 = 0.0f;
        float relief = 0.0f;
        Zone(z0, relief);
        switch (kind) {
        case Grass:
          rules = {
            Mix(k.seed + 5, size * 1.6f, 0.05f, 0.6f),
            Rule("const", {{"value", 0.75f}}, MaskCombine::Or),
            FlatTo(k.rock - 4, k.rock + 12, 3 * bk, size, k.seed + 6, MaskCombine::Mul)
          };
          if (st.hasWater) {
            rules.push_back(Rule(
              "water",
              {{"mode", 1}, {"offset", plan.Has(Sand) ? k.beach + 0.5f : 0.5f}, {"soft", std::max(2.0f, k.beach)}},
              MaskCombine::Mul
            ));
          }
          UnderSnow(rules);
          rules.push_back(Blur(3));
          rules.push_back(Grain(k.seed + 301, 0.7f));
          return true;
        case Dirt:
          if (k.dirt <= 0.005f) {
            return false;
          }
          if (style.relief) {
            // The open ground of a valley: flat ground that doesn't stand above its surroundings.
            MaskGenRule mix = Mix(k.seed, k.patch * 2.4f, 0.3f - 0.25f * k.dirt, 0.55f - 0.25f * k.dirt);
            mix.op = MaskCombine::Mul;
            rules = {
              Rule(
                "relief",
                {{"radius", std::max(40.0f, k.patch * 2.0f)},
                 {"lo", -80},
                 {"hi", 0.35f + 3.0f * (k.dirt - 0.5f)},
                 {"soft", 1.5f + 2.0f * bk}}
              ),
              mix,
              Crisp(k.seed + 4),
              FlatTo(k.rock - 8, k.rock + 6, 3 * bk, size, k.seed + 3, MaskCombine::Mul)
            };
          } else {
            rules = {
              Mix(k.seed, k.patch * 2.4f, 1 - k.dirt - 0.22f, 1 - k.dirt + 0.22f),
              Crisp(k.seed + 4),
              FlatTo(k.rock - 6, k.rock + 10, 3 * bk, size, k.seed + 3, MaskCombine::Mul)
            };
          }
          UnderSnow(rules);
          rules.push_back(Blur(1.5f));
          rules.push_back(Grain(k.seed + 302, 1.0f));
          rules.push_back(AtMost(0.88f));
          return true;
        case Wet:
          // The bed of the drainage lines (a concave channel on flat ground) and a strip along the waterline.
          rules = {
            Rule("flow", {{"range", 600}, {"from", 0.62f}, {"to", 0.86f}}),
            Rule("curvature", {{"radius", 4}, {"gain", 20}, {"lo", 0}, {"hi", 0.45f}, {"soft", 0.08f}}),
            FlatTo(7, 20, 0, size, 1, MaskCombine::Mul)
          };
          if (st.hasWater && k.wet > 0.0f) {
            rules.push_back(
              Rule("shoredist", {{"width", k.wet * 2.0f}, {"depth", 2}, {"soft", 1.5f + k.wet}}, MaskCombine::Or)
            );
          }
          rules.push_back(Blur(2));
          rules.push_back(Crisp(k.seed + 51, 12));
          rules.push_back(AtMost(0.72f));
          return true;
        case Sand:
          if (st.hasWater) {
            if (k.beach <= 0.0f) {
              return false;
            }
            rules = {
              Rule("shoredist", {{"width", k.beach * 2.5f}, {"depth", 3}, {"soft", 1.0f + k.beach}}),
              FlatTo(10, 28, 2 * bk, size, k.seed + 8, MaskCombine::Mul),
              Crisp(k.seed + 81, 14),
              Blur(1.5f),
              Grain(k.seed + 303, 0.5f),
              AtMost(0.92f)
            };
            return true;
          }
          if (!style.drySand) {
            return false; // sand lies along water; a dry map has it only when the style asks (desert: dry basins)
          }
          {
            const float h0 = H(0.04f);
            const float h1 = H(0.3f);
            rules = {
              FallTo(h0, h1, 0.4f * (h1 - h0) * bk, size * 1.5f, k.seed + 9, MaskCombine::And),
              FlatTo(6, 18, 0, size, 1, MaskCombine::Mul),
              Crisp(k.seed + 82, 20),
              Blur(2.5f),
              Grain(k.seed + 304, 0.7f),
              AtMost(0.65f)
            };
          }
          return true;
        case Rock:
          rules = {
            SteepFrom(k.rock, std::max(k.rock + 4, k.cliff), 4 * bk, size, k.seed + 11),
            Crisp(k.seed + 12, 18),
            Blur(1.2f)
          };
          return true;
        case DarkRock:
          if (k.dark <= 0.01f) {
            return false;
          }
          rules = {
            Rule("curvature", {{"radius", 6}, {"gain", 18}, {"lo", 0}, {"hi", 0.42f}, {"soft", 0.1f}}),
            SteepFrom(k.rock * 0.45f, k.rock + 6, 3 * bk, size, k.seed + 31, MaskCombine::Mul),
            Blur(5),
            Grain(k.seed + 305, 1.0f),
            AtMost(0.15f + 0.45f * k.dark)
          };
          return true;
        case HighRock: {
          const float alt = Alt();
          if (alt < 0.05f) {
            return false;
          }
          const float h = z0 + relief * k.high;
          rules = {
            SteepFrom(k.rock * 0.4f, k.rock + 8),
            Rule("curvature", {{"radius", 6}, {"gain", 25}, {"lo", 0.56f}, {"hi", 1}, {"soft", 0.1f}}, MaskCombine::Or)
          };
          if (!plan.biplanar) {
            rules.push_back(Rule("const", {{"value", 0.3f}}, MaskCombine::Or)); // some rock on flat high ground
          }
          rules.push_back(
            RiseFrom(h - 0.12f * relief, h + 0.14f * relief, 0.1f * relief * bk, size, k.seed + 41, MaskCombine::Mul)
          );
          rules.push_back(Crisp(k.seed + 42, 22));
          rules.push_back(Blur(2));
          rules.push_back(AtMost(alt));
          return true;
        }
        case Snow: {
          if (k.snow <= 0.004f) {
            return false;
          }
          const float alt = Alt();
          if (alt < 0.05f) {
            return false;
          }
          const float line = SnowLine();
          rules = {
            RiseFrom(
              line - 0.14f * relief,
              line + 0.06f * relief,
              0.08f * relief * bk,
              size,
              k.seed + 21,
              MaskCombine::And,
              0.05f * relief
            ),
            FlatTo(k.cliff, k.cliff + 22, 4 * bk, size, k.seed + 22, MaskCombine::Mul),
            Crisp(k.seed + 23, 16),
            Blur(2),
            AtMost(alt)
          };
          return true;
        }
        case Unknown:
          break;
        }
        return false;
      }
    };
  } // namespace

  const std::vector<RecipeKnobInfo>& RecipeKnobList()
  {
    static const std::vector<RecipeKnobInfo> list = {
      {&RecipeKnobs::cliff, "Cliff slope from (degrees)", 20, 85, "%.0f"},
      {&RecipeKnobs::rock, "Rock slope from (degrees)", 5, 80, "%.0f"},
      {&RecipeKnobs::snow, "Snow covers the top (share of land)", 0, 0.6f, "%.2f"},
      {&RecipeKnobs::high, "High rock starts at (share of height range)", 0.2f, 0.95f, "%.2f"},
      {&RecipeKnobs::beach, "Beach half width (units)", 0, 20, "%.1f"},
      {&RecipeKnobs::wet, "Wet strip half width (units)", 0, 10, "%.1f"},
      {&RecipeKnobs::dirt, "Dirt coverage (share of flat ground)", 0, 0.8f, "%.2f"},
      {&RecipeKnobs::dark, "Dark rock in cavities (amount)", 0, 1, "%.2f"},
      {&RecipeKnobs::breakup, "Edge breakup (noise)", 0, 1, "%.2f"},
      {&RecipeKnobs::patch, "Patch size (units)", 8, 300, "%.0f"},
      {&RecipeKnobs::crisp, "Edge crispness (0 soft, 1 sharp)", 0, 1, "%.2f"},
      {&RecipeKnobs::fine, "Fine grain (variation at texture size)", 0, 1, "%.2f"},
      {&RecipeKnobs::mix, "Variant mix (a second texture of a kind)", 0.1f, 0.95f, "%.2f"},
      {&RecipeKnobs::soft, "Blend width between kinds (units)", 0, 20, "%.1f"},
      {&RecipeKnobs::seed, "Seed", 0, 9999, "%.0f"},
    };
    return list;
  }

  const std::vector<RecipeStyle>& RecipeStyles()
  {
    constexpr std::uint16_t kNoSnow = 1u << K(Snow);
    static const std::vector<RecipeStyle> styles = {
      {"temperate", "Natural (all eight kinds of ground)"},
      {"alpine", "Alpine (more rock, high rock and snow)", 0, true},
      {"desert", "Desert (dust and sand, no snow)", kNoSnow, false, true},
      {"arctic", "Arctic (snow and ice, rock)", 0, true},
      {"rocky", "Rocky (cliffs, dark rock, little grass)"},
      {"valley", "Open valley (bare plains, green ridges, rock on the steep)", kNoSnow, false, false, true},
      {"layered", "Layered (soft wide blends)", kNoSnow},
      {"coast", "Coast and wetland (wide beach, wet ground)", kNoSnow},
    };
    return styles;
  }

  RecipeKnobs RecipeKnobsOf(
    const int style
  )
  {
    RecipeKnobs k;
    const std::string id = style >= 0 && style < static_cast<int>(RecipeStyles().size())
      ? RecipeStyles()[static_cast<std::size_t>(style)].id
      : "";
    if (id == "alpine") {
      k.snow = 0.18f, k.high = 0.4f, k.cliff = 46, k.rock = 28, k.dark = 0.6f;
    } else if (id == "desert") {
      k.snow = 0, k.beach = 4, k.dirt = 0.42f, k.dark = 0.4f, k.wet = 1, k.crisp = 0.3f;
    } else if (id == "arctic") {
      k.snow = 0.4f, k.high = 0.35f, k.beach = 2, k.dirt = 0.15f, k.cliff = 48, k.rock = 30;
    } else if (id == "rocky") {
      k.cliff = 44, k.rock = 26, k.dirt = 0.5f, k.dark = 0.8f, k.high = 0.4f, k.snow = 0.05f, k.crisp = 0.55f;
    } else if (id == "valley") {
      k.dirt = 0.5f, k.snow = 0, k.high = 0.7f, k.beach = 3, k.wet = 1.5f, k.dark = 0.5f, k.crisp = 0.7f, k.fine = 0.5f,
      k.breakup = 0.7f, k.patch = 70, k.rock = 30, k.cliff = 48;
    } else if (id == "layered") {
      k.mix = 0.8f, k.soft = 4, k.patch = 36, k.crisp = 0.3f, k.breakup = 0.7f, k.fine = 0.55f, k.dirt = 0.4f,
      k.rock = 20, k.cliff = 40, k.wet = 3, k.dark = 0.5f, k.snow = 0;
    } else if (id == "coast") {
      k.beach = 6, k.wet = 3, k.dirt = 0.36f, k.snow = 0, k.rock = 38, k.cliff = 56, k.crisp = 0.3f;
    }
    return k;
  }

  bool RecipePercentiles(
    const std::vector<float>& values,
    std::array<float, 101>& out
  )
  {
    if (values.empty()) {
      return false;
    }
    const auto [lowIt, highIt] = std::minmax_element(values.begin(), values.end());
    const float lo = *lowIt;
    const float hi = *highIt;
    if (hi - lo < 1e-6f) {
      out.fill(lo);
      return true;
    }
    constexpr int kBins = 1024;
    std::vector<std::size_t> bins(kBins, 0);
    const double scale = (kBins - 0.001) / (static_cast<double>(hi) - lo);
    for (const float v : values) {
      ++bins[static_cast<std::size_t>(std::min(kBins - 1, static_cast<int>((v - lo) * scale)))];
    }
    const double count = static_cast<double>(values.size());
    std::size_t b = 0;
    double cumulative = 0.0;
    for (int p = 0; p <= 100; ++p) {
      const double target = p / 100.0 * count;
      while (b + 1 < kBins && cumulative + static_cast<double>(bins[b]) < target) {
        cumulative += static_cast<double>(bins[b]);
        ++b;
      }
      const double frac =
        bins[b] > 0 ? std::clamp((target - cumulative) / static_cast<double>(bins[b]), 0.0, 1.0) : 0.0;
      out[static_cast<std::size_t>(p)] =
        static_cast<float>(lo + (static_cast<double>(b) + frac) / kBins * (static_cast<double>(hi) - lo));
    }
    out[0] = lo;
    out[100] = hi;
    return true;
  }

  RecipeStats RecipeStatsOf(
    const std::vector<float>& heights,
    const float water,
    const bool waterOn
  )
  {
    RecipeStats st;
    st.water = water;
    if (heights.empty()) {
      for (int p = 0; p <= 100; ++p) {
        st.pct[static_cast<std::size_t>(p)] = static_cast<float>(p);
      }
      return st;
    }
    const auto [lowIt, highIt] = std::minmax_element(heights.begin(), heights.end());
    st.hmin = *lowIt;
    st.hmax = *highIt;
    st.hasWater = waterOn && water > st.hmin + 0.5f && water < st.hmax - 0.5f;
    bool made = false;
    if (st.hasWater) {
      std::vector<float> land;
      for (const float h : heights) {
        if (h >= water) {
          land.push_back(h);
        }
      }
      if (static_cast<double>(land.size()) >= static_cast<double>(heights.size()) * 0.03) {
        made = RecipePercentiles(land, st.pct);
      }
    }
    if (!made) {
      (void)RecipePercentiles(heights, st.pct);
    }
    return st;
  }

  float RecipeHeightAt(
    const RecipeStats& stats,
    const float p
  )
  {
    if (p <= 0.0f) {
      return stats.pct[0];
    }
    if (p >= 1.0f) {
      return stats.pct[100];
    }
    const float x = p * 100.0f;
    const int i = static_cast<int>(x);
    return stats.pct[static_cast<std::size_t>(i)] +
      (stats.pct[static_cast<std::size_t>(i) + 1] - stats.pct[static_cast<std::size_t>(i)]) *
      (x - static_cast<float>(i));
  }

  RecipePlan PlanRecipe(
    const std::array<GroundKind, 9>& kinds,
    const std::array<bool, 9>& textured,
    const int cap,
    const bool biplanar
  )
  {
    RecipePlan plan;
    plan.cap = std::clamp(cap, 1, 8);
    plan.biplanar = biplanar;
    for (int layer = 0; layer <= 8; ++layer) {
      if (!textured[static_cast<std::size_t>(layer)]) {
        continue;
      }
      if (layer > plan.cap) {
        plan.beyond.push_back(layer);
        continue;
      }
      const GroundKind kind = kinds[static_cast<std::size_t>(layer)];
      if (kind == Unknown) {
        plan.unknown.push_back(layer);
        continue;
      }
      plan.byKind[K(kind)].push_back(layer);
      if (layer == 0) {
        plan.base = kind;
      }
    }
    return plan;
  }

  const std::array<GroundKind, 8>& RecipeOrder()
  {
    static constexpr std::array<GroundKind, 8> order = {Grass, Dirt, Wet, Sand, Rock, DarkRock, HighRock, Snow};
    return order;
  }

  const std::array<GroundKind, 8>& RecipePriority()
  {
    static constexpr std::array<GroundKind, 8> priority = {Snow, HighRock, DarkRock, Rock, Wet, Sand, Dirt, Grass};
    return priority;
  }

  const char* RecipeKindLabel(
    const GroundKind kind
  ) noexcept
  {
    switch (kind) {
    case Grass:
      return "Grass (open ground)";
    case Dirt:
      return "Dirt (patches)";
    case Wet:
      return "Wet ground (waterline, gullies)";
    case Sand:
      return "Sand (beach)";
    case Rock:
      return "Rock (cliffs)";
    case DarkRock:
      return "Dark rock (cavities)";
    case HighRock:
      return "High rock (peaks)";
    case Snow:
      return "Snow (high, flat)";
    case Unknown:
      break;
    }
    return "Not used";
  }

  bool RecipeRoles(
    MaskGenContext& context,
    const RecipePlan& plan,
    const RecipeStats& stats,
    const RecipeKnobs& knobs,
    const int style,
    std::vector<RecipeRole>& roles,
    std::string& error
  )
  {
    if (context.heights == nullptr) {
      error = "no heights";
      return false;
    }
    static std::map<std::string, std::array<float, 101>> noiseCache;
    if (noiseCache.size() > 60) {
      noiseCache.clear();
    }
    const RecipeStyle& look =
      RecipeStyles()[static_cast<std::size_t>(std::clamp(style, 0, static_cast<int>(RecipeStyles().size()) - 1))];
    Builder builder{context, plan, stats, knobs, look, noiseCache};
    roles.clear();
    for (const GroundKind kind : RecipeOrder()) {
      RecipeRole role;
      role.kind = kind;
      role.base = plan.base == kind;
      const bool on = builder.Build(kind, role.rules);
      role.off = !role.base && (!on || (look.off & (1u << K(kind))) != 0);
      roles.push_back(std::move(role));
    }
    return true;
  }

  bool ResolveRecipe(
    MaskGenContext& context,
    const RecipePlan& plan,
    const std::vector<RecipeRole>& roles,
    const RecipeKnobs& knobs,
    std::map<int, field::Grid>& target,
    std::string& error
  )
  {
    target.clear();
    const field::Grid& h = *context.heights;
    const std::size_t n = h.v.size();
    const auto empty = [&] {
      field::Grid g = h;
      std::fill(g.v.begin(), g.v.end(), 0.0f);
      return g;
    };
    // Each kind's selection on the heights' grid.
    std::array<std::vector<float>, 9> selection;
    for (const RecipeRole& role : roles) {
      const std::vector<int>& layers = plan.byKind[K(role.kind)];
      if (layers.empty() || role.off || role.base || role.rules.empty()) {
        continue;
      }
      field::Grid mask;
      if (!EvaluateMaskRules(context, role.rules, mask, error)) {
        error = std::string(RecipeKindLabel(role.kind)) + ": " + error;
        return false;
      }
      // A kind on a layer the B shaders draw from the side (3, 4) only gets steep ground.
      if (plan.biplanar && std::any_of(layers.begin(), layers.end(), [](const int l) {
        return l == 3 || l == 4;
      })) {
        field::Grid gate;
        if (!EvaluateMaskRules(
              context,
              {[] {
          MaskGenRule r = NewMaskRule("slope");
          r.v["lo"] = 24;
          r.v["hi"] = 90;
          r.v["soft"] = 12;
          return r;
        }()},
              gate,
              error
            )) {
          return false;
        }
        for (std::size_t i = 0; i < n && i < mask.v.size(); ++i) {
          mask.v[i] *= gate.v[i];
        }
      }
      selection[K(role.kind)] = std::move(mask.v);
    }
    // The priority cascade: each kind takes its selection of what the kinds above it left.
    std::vector<float> rest(n, 1.0f);
    std::array<std::vector<float>, 9> region;
    for (const GroundKind kind : RecipePriority()) {
      const std::vector<float>& s = selection[K(kind)];
      if (s.size() != n) {
        continue;
      }
      region[K(kind)].resize(n);
      for (std::size_t i = 0; i < n; ++i) {
        region[K(kind)][i] = s[i] * rest[i];
        rest[i] *= 1.0f - s[i];
      }
    }
    if (plan.base != Unknown && !plan.byKind[K(plan.base)].empty()) {
      region[K(plan.base)] = rest;
    }
    // Every layer of a kind: the second and later ones take soft noise patches of the kind's region.
    for (std::size_t order = 0; order < RecipeOrder().size(); ++order) {
      const GroundKind kind = RecipeOrder()[order];
      const std::vector<int>& layers = plan.byKind[K(kind)];
      if (layers.empty() || region[K(kind)].size() != n) {
        continue;
      }
      std::vector<float> left = region[K(kind)];
      for (std::size_t gi = 1; gi < layers.size(); ++gi) {
        const float seed = knobs.seed + 91.0f + static_cast<float>(gi) * 17.0f + static_cast<float>(order + 1) * 7.0f;
        const float size = std::max(60.0f, knobs.patch * 2.2f);
        // FAF Studio's PatchField: a wide smoothstep of fractal noise, at most `mix`, blurred.
        std::map<std::string, std::array<float, 101>> cache;
        const RecipeStats none{};
        const RecipeStyle look{};
        RecipePlan noPlan;
        Builder b{context, noPlan, none, knobs, look, cache};
        field::Grid patch;
        if (!EvaluateMaskRules(
              context, {b.Mix(seed, size, 0.3f, 0.85f), Builder::AtMost(knobs.mix), Builder::Blur(3)}, patch, error
            )) {
          return false;
        }
        field::Grid t = empty();
        for (std::size_t i = 0; i < n; ++i) {
          t.v[i] = left[i] * patch.v[i];
          left[i] -= t.v[i];
        }
        target[layers[gi]] = std::move(t);
      }
      field::Grid first = empty();
      first.v = std::move(left);
      target[layers[0]] = std::move(first);
    }
    // Kinds that are off: their layers cleared (an earlier run's paint would cover the others).
    for (const RecipeRole& role : roles) {
      if (!role.off) {
        continue;
      }
      for (const int layer : plan.byKind[K(role.kind)]) {
        if (layer >= 1 && target.count(layer) == 0) {
          target[layer] = empty();
        }
      }
    }
    // Wide transitions: every visible weight blurred (they still add up to 1).
    if (knobs.soft > 0.4f) {
      for (auto& [layer, weight] : target) {
        field::OpArgs args;
        args.in["a"] = std::make_shared<field::Grid>(weight);
        args.p.num["radius"] = knobs.soft;
        field::Grid blurred;
        if (field::RunOpCpu("blur", args, blurred, error)) {
          weight = std::move(blurred);
        }
      }
    }
    return true;
  }

  std::size_t WriteRecipe(
    std::uint64_t* const texels,
    const int width,
    const int height,
    const float mapSize,
    const std::uint8_t remapped,
    const int cap,
    const std::array<bool, 9>& textured,
    const std::map<int, field::Grid>& target,
    std::array<float, 9>& shares
  )
  {
    shares.fill(0.0f);
    if (texels == nullptr || width < 1 || height < 1) {
      return 0;
    }
    const float cell = mapSize / static_cast<float>(width);
    const int top = std::clamp(cap, 1, 8);
    std::size_t changed = 0;
    std::array<double, 9> sums{};
    for (int z = 0; z < height; ++z) {
      for (int x = 0; x < width; ++x) {
        std::uint64_t& texel =
          texels[static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x)];
        const float wx = (static_cast<float>(x) + 0.5f) * cell;
        const float wz = (static_cast<float>(z) + 0.5f) * cell;
        float free = 1.0f;
        for (int layer = top; layer >= 1; --layer) {
          const int byte = layer - 1;
          const bool range = (remapped & (1U << byte)) != 0;
          const auto found = target.find(layer);
          float m = 0.0f;
          if (found != target.end()) {
            const float w = std::clamp(SampleField(found->second, wx, wz), 0.0f, 1.0f);
            // The opacity that shows exactly the weight under what the layers above cover.
            m = free > 1e-4f ? std::clamp(w / free, 0.0f, 1.0f) : (w > 1e-4f ? 1.0f : 0.0f);
            const std::uint8_t before = MaskByte(texel, byte);
            const std::uint8_t stored = MaskStoredFor(m * 255.0f, range, before);
            if (stored != before) {
              texel = WithMaskByte(texel, byte, stored);
              ++changed;
            }
            m = MaskWeight(stored, range) / 255.0f;
          } else if (textured[static_cast<std::size_t>(layer)]) {
            // Outside the recipe: its mask stays and covers what lies under it.
            m = MaskWeight(MaskByte(texel, byte), range) / 255.0f;
          } else {
            continue;
          }
          sums[static_cast<std::size_t>(layer)] += m * free;
          free *= 1.0f - m;
        }
        sums[0] += free;
      }
    }
    const double count = static_cast<double>(width) * static_cast<double>(height);
    for (std::size_t i = 0; i < shares.size(); ++i) {
      shares[i] = static_cast<float>(sums[i] / count);
    }
    return changed;
  }
} // namespace faf::editor
