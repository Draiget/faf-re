#include "editor/tools/EdMaskGen.h"

#include "editor/tools/EdMaskBrush.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <stdexcept>

namespace faf::editor
{
  namespace
  {
    using Field = std::shared_ptr<field::Grid>;

    /** An op that failed: its message ends the evaluation. */
    struct OpFailed : std::runtime_error
    {
      using std::runtime_error::runtime_error;
    };

    struct In
    {
      const char* name;
      Field grid;
    };
    struct Num
    {
      template <class T>
      Num(
        const char* const key,
        const T number
      )
        : name(key)
        , value(static_cast<double>(number))
      {}
      const char* name;
      double value;
    };
    struct Str
    {
      const char* name;
      const char* value;
    };

    Field Op(
      const char* const name,
      std::initializer_list<In> inputs,
      std::initializer_list<Num> numbers = {},
      std::initializer_list<Str> strings = {}
    )
    {
      field::OpArgs args;
      for (const In& input : inputs) {
        args.in[input.name] = input.grid;
      }
      for (const Num& n : numbers) {
        args.p.num[n.name] = n.value;
      }
      for (const Str& s : strings) {
        args.p.str[s.name] = s.value;
      }
      auto out = std::make_shared<field::Grid>();
      std::string error;
      if (!field::RunOpCpu(name, args, *out, error)) {
        throw OpFailed(std::string(name) + ": " + error);
      }
      return out;
    }

    struct Evaluator
    {
      MaskGenContext& c;

      int Samples(
        const float units
      ) const
      {
        return std::max(1, static_cast<int>(std::lround(units / c.heights->cell)));
      }

      template <class Make>
      Field Cached(
        const std::string& key,
        Make make
      )
      {
        auto found = c.cache.find(key);
        if (found == c.cache.end()) {
          found = c.cache.emplace(key, make()).first;
        }
        return found->second;
      }

      Field Const(
        const float value
      )
      {
        return Op("const", {{"like", c.heights}}, {{"value", value}});
      }

      Field Invert(
        const Field& f
      )
      {
        return Op("invert", {{"a", f}}, {{"lo", 0}, {"hi", 1}});
      }

      Field Clamp01(
        const Field& f
      )
      {
        return Op("clamp", {{"a", f}}, {{"lo", 0}, {"hi", 1}});
      }

      /** A paint layer (1..8) as a 0..1 field on the heights' grid; nothing where the layer isn't given. */
      Field Layer(
        const int layer
      )
      {
        return Cached("layer" + std::to_string(layer), [&] {
          const Field& mask = c.layers[static_cast<std::size_t>(std::clamp(layer, 1, 8) - 1)];
          return mask == nullptr ? Const(0.0f) : Op("resample", {{"a", mask}, {"like", c.heights}});
        });
      }

      Field FreeAbove(
        const int layer
      )
      {
        return Cached("above" + std::to_string(layer), [&] {
          Field free = Const(1.0f);
          for (int k = layer + 1; k <= 8; ++k) {
            free = Op("mul", {{"a", free}, {"b", Invert(Layer(k))}});
          }
          return free;
        });
      }

      /** `f` moved by up to +-amount of fractal noise (the noise has mean 0.5 and spread 0.155): limits that wobble. */
      Field Wobbled(
        const Field& f,
        const float amount,
        const float size,
        const float seed
      )
      {
        if (amount <= 0.0f) {
          return f;
        }
        const Field noise = Cached(
          "fractal" + std::to_string(static_cast<int>(size)) + "_" + std::to_string(static_cast<int>(seed)), [&] {
          return Op("fractal", {{"like", c.heights}}, {{"seed", std::floor(seed)}, {"scale", size}, {"octaves", 5}});
        }
        );
        return Op(
          "add",
          {{"a", f}, {"b", Op("affine", {{"a", noise}}, {{"mul", amount / 0.31}, {"add", -amount * 0.5 / 0.31}})}}
        );
      }

      Field Band(
        const Field& f,
        const float lo,
        const float hi,
        const float soft
      )
      {
        return Op("height_band", {{"a", f}}, {{"lo", lo}, {"hi", hi}, {"soft", soft}});
      }

      Field Below(
        const Field& f,
        const float level,
        const float soft
      )
      {
        return Op("water_below", {{"a", f}}, {{"level", level}, {"soft", soft}});
      }

      Field Above(
        const Field& f,
        const float level,
        const float soft
      )
      {
        return Op("water_above", {{"a", f}}, {{"level", level}, {"soft", soft}});
      }

      Field Smooth(
        const Field& f,
        const float from,
        const float to
      )
      {
        return Op("smoothstep", {{"a", f}}, {{"edge0", from}, {"edge1", to}});
      }

      Field Distance(
        const Field& f,
        const char* const mode
      )
      {
        return Op("distance", {{"a", f}}, {{"threshold", 0.5}}, {{"mode", mode}});
      }

      Field Grow(
        const Field& m,
        const float distance,
        const float soft
      )
      {
        return Op("max", {{"a", m}, {"b", Below(Distance(m, "outside"), distance, soft)}});
      }

      Field Shrink(
        const Field& m,
        const float distance,
        const float soft
      )
      {
        return Op("min", {{"a", m}, {"b", Above(Distance(m, "inside"), distance, soft)}});
      }

      Field Source(
        const MaskGenRule& rule
      )
      {
        const auto v = [&](const char* const key) {
          return rule.Value(key);
        };
        const std::string& type = rule.type;
        if (type == "slope") {
          const Field slope = Cached("slope", [&] {
            return Op("slope", {{"a", c.heights}}, {{"radius", 1}}, {{"mode", "degrees"}});
          });
          return Band(Wobbled(slope, v("wobble"), v("wsize"), v("wseed")), v("lo"), v("hi"), v("soft"));
        }
        if (type == "unitclass") {
          // FAF Studio's CLASSES: land units by footprint (the engine's slope rating), then structures (variation).
          static constexpr struct
          {
            const char* kind;
            float window;
            float limit;
          } kClasses[] = {
            {"rating", 1, 0.75f},
            {"rating", 2, 0.75f},
            {"rating", 3, 0.75f},
            {"rating", 5, 0.75f},
            {"variation", 2, 1.1f}
          };
          const auto& cls = kClasses[std::clamp(static_cast<int>(std::lround(v("class"))), 1, 5) - 1];
          const float limit = v("limit") > 0.0f ? v("limit") : cls.limit;
          const int window = Samples(cls.window);
          const Field rating = Cached(std::string(cls.kind) + std::to_string(window), [&] {
            return Op("slope", {{"a", c.heights}}, {{"window", window}}, {{"mode", cls.kind}});
          });
          const Field pass = Below(rating, limit, v("soft"));
          return v("blocked") >= 0.5f ? Invert(pass) : pass;
        }
        if (type == "height") {
          Field f = Wobbled(c.heights, v("wobble"), v("wsize"), v("wseed"));
          if (const float sun = v("sun"); sun != 0.0f) {
            // Starts `sun` units higher on the ground that faces the sun and as much lower on the far side.
            const int n = Samples(6.0f);
            const float azimuth = v("sunaz");
            const Field facing =
              Cached("facing" + std::to_string(static_cast<int>(azimuth)) + "_" + std::to_string(n), [&] {
              return Op("aspect", {{"a", c.heights}}, {{"azimuth", azimuth}, {"flat", 0.03}, {"radius", n}});
            });
            f = Op("sub", {{"a", f}, {"b", Op("affine", {{"a", facing}}, {{"mul", 2.0 * sun}, {"add", -sun}})}});
          }
          return Band(f, v("lo"), v("hi"), v("soft"));
        }
        if (type == "curvature") {
          const int n = Samples(v("radius"));
          const float gain = v("gain");
          const Field curvature =
            Cached("curv" + std::to_string(n) + "_" + std::to_string(static_cast<int>(gain)), [&] {
            return Op("curvature", {{"a", c.heights}}, {{"radius", n}, {"gain", gain}});
          });
          return Band(curvature, v("lo"), v("hi"), v("soft"));
        }
        if (type == "relief") {
          const int n = Samples(v("radius"));
          const Field relief = Cached("relief" + std::to_string(n), [&] {
            return Op("sub", {{"a", c.heights}, {"b", Op("blur", {{"a", c.heights}}, {{"radius", n}})}});
          });
          return Band(relief, v("lo"), v("hi"), v("soft"));
        }
        if (type == "aspect") {
          const Field aspect =
            Op("aspect", {{"a", c.heights}}, {{"azimuth", v("azimuth")}, {"flat", v("flat")}, {"radius", 1}});
          return Band(aspect, v("from"), 1.0f, v("soft"));
        }
        if (type == "water") {
          const float level = c.water + v("offset");
          const int mode = static_cast<int>(std::lround(v("mode")));
          if (mode == 2) {
            return Below(c.heights, level, v("soft"));
          }
          if (mode == 3) {
            return Op("shore", {{"a", c.heights}}, {{"level", level}, {"width", v("width")}, {"soft", v("soft")}});
          }
          return Above(c.heights, level, v("soft"));
        }
        if (type == "shoredist") {
          // The land up to `width` along the ground from the waterline, and the shallow water in front of it.
          const Field wet = Below(c.heights, c.water, 0.01f);
          const Field land = Below(Distance(wet, "outside"), v("width"), std::max(0.5f, v("soft")));
          const Field gate = Above(c.heights, c.water - v("depth"), std::max(0.5f, v("depth") * 0.5f));
          return Op("mul", {{"a", land}, {"b", gate}});
        }
        if (type == "noise") {
          static constexpr const char* kNoises[] = {"perlin", "simplex", "ridged", "billow", "fractal"};
          const Field noise = Op(
            kNoises[std::clamp(static_cast<int>(std::lround(v("kind"))), 1, 5) - 1],
            {{"like", c.heights}},
            {{"seed", std::floor(v("seed"))}, {"scale", v("size")}, {"octaves", std::floor(v("octaves"))}}
          );
          return Smooth(noise, v("from"), v("to"));
        }
        if (type == "flow") {
          const Field flow = Op("flow", {{"a", c.heights}}, {{"range", v("range") * 1000.0}}, {{"mode", "log"}});
          return Smooth(flow, v("from"), v("to"));
        }
        if (type == "position") {
          const Field g = v("kind") >= 1.5f
            ? Op("radial", {{"like", c.heights}})
            : Op("gradient", {{"like", c.heights}}, {{"angle", v("angle")}, {"lo", 0}, {"hi", 1}});
          return Smooth(g, v("from"), v("to"));
        }
        if (type == "layer") {
          const int layer = static_cast<int>(std::lround(v("layer")));
          const Field m = Layer(layer);
          return v("visible") >= 0.5f ? Op("mul", {{"a", m}, {"b", FreeAbove(layer)}}) : m;
        }
        if (type == "free_above") {
          return FreeAbove(static_cast<int>(std::lround(v("layer"))));
        }
        if (type == "near_layer") {
          const Field m = Layer(static_cast<int>(std::lround(v("layer"))));
          return Below(Distance(m, "outside"), v("distance"), v("soft"));
        }
        if (type == "const") {
          return Const(v("value"));
        }
        throw OpFailed("unknown rule " + type);
      }

      Field Modify(
        const MaskGenRule& rule,
        const Field& m
      )
      {
        const auto v = [&](const char* const key) {
          return rule.Value(key);
        };
        const std::string& type = rule.type;
        if (type == "not") {
          return Invert(m);
        }
        if (type == "blur") {
          return Clamp01(Op("blur", {{"a", m}}, {{"radius", v("radius")}}));
        }
        if (type == "threshold") {
          return Op("threshold", {{"a", m}}, {{"value", v("value")}});
        }
        if (type == "smoothstep") {
          return Smooth(m, v("edge0"), v("edge1"));
        }
        if (type == "amount") {
          return Clamp01(Op("affine", {{"a", m}}, {{"mul", v("factor")}, {"add", 0}}));
        }
        if (type == "grow") {
          return Grow(m, v("distance"), v("soft"));
        }
        if (type == "shrink") {
          return Shrink(m, v("distance"), v("soft"));
        }
        if (type == "open") {
          return Grow(Shrink(m, v("radius"), 0.0f), v("radius"), 0.0f);
        }
        if (type == "close") {
          return Shrink(Grow(m, v("radius"), 0.0f), v("radius"), 0.0f);
        }
        if (type == "crisp") {
          // The mask plus a noise through a smoothstep around one half: ragged edges, the inside and outside kept.
          const Field noise = Op(
            "fractal", {{"like", c.heights}}, {{"seed", std::floor(v("seed"))}, {"scale", v("size")}, {"octaves", 4}}
          );
          const float amount = v("noise");
          const Field shifted =
            Op("add", {{"a", m}, {"b", Op("affine", {{"a", noise}}, {{"mul", amount}, {"add", -0.5 * amount}})}});
          const float w = std::max(0.05f, 0.5f * (1.0f - v("crisp")));
          return Clamp01(Smooth(shifted, 0.5f - w, 0.5f + w));
        }
        if (type == "grain") {
          const Field noise = Op(
            "fractal", {{"like", c.heights}}, {{"seed", std::floor(v("seed"))}, {"scale", v("size")}, {"octaves", 3}}
          );
          const float amount = v("amount");
          return Clamp01(
            Op("mul", {{"a", m}, {"b", Op("affine", {{"a", noise}}, {{"mul", amount}, {"add", 1.0 - amount}})}})
          );
        }
        throw OpFailed("unknown rule " + type);
      }

      Field Combine(
        const Field& acc,
        const Field& r,
        const MaskCombine op
      )
      {
        switch (op) {
        case MaskCombine::Or:
          return Op("max", {{"a", acc}, {"b", r}});
        case MaskCombine::Mul:
          return Op("mul", {{"a", acc}, {"b", r}});
        case MaskCombine::Sub:
          return Op("mul", {{"a", acc}, {"b", Invert(r)}});
        case MaskCombine::Add:
          return Clamp01(Op("add", {{"a", acc}, {"b", r}}));
        case MaskCombine::And:
          break;
        }
        return Op("min", {{"a", acc}, {"b", r}});
      }
    };

    MaskParamSpec P(
      const char* key,
      const char* label,
      float min,
      float max,
      float step,
      const char* format,
      float fallback
    )
    {
      return {key, label, min, max, step, format, fallback};
    }

    MaskGenRule Rule(
      const char* const type,
      std::initializer_list<std::pair<const char*, float>> values,
      const MaskCombine op = MaskCombine::And,
      const bool invert = false
    )
    {
      MaskGenRule rule = NewMaskRule(type);
      for (const auto& [key, value] : values) {
        rule.v[key] = value;
      }
      rule.op = op;
      rule.invert = invert;
      return rule;
    }
  } // namespace

  const std::vector<MaskRuleSpec>& MaskRuleCatalogue()
  {
    // FAF Studio's maskgen.lua Types and Order (its "Imported mask" source is left out: there is no import slot here).
    static const std::vector<MaskRuleSpec> catalogue = {
      {"slope",
       "Slope",
       false,
       {P("lo", "From (degrees)", 0, 89, 0.5f, "%.1f", 0),
        P("hi", "To (degrees)", 0.5f, 90, 0.5f, "%.1f", 25),
        P("soft", "Soft edge (degrees)", 0, 45, 0.5f, "%.1f", 3),
        P("wobble", "Wobble (degrees, fractal noise)", 0, 30, 0.5f, "%.1f", 0),
        P("wsize", "Wobble feature size (units)", 8, 600, 2, "%.0f", 80),
        P("wseed", "Wobble seed", 0, 9999, 1, "%.0f", 1)}},
      {"unitclass",
       "Unit class slope",
       false,
       {P("class", "Class (1-3 land by size, 4 experimental, 5 structure)", 1, 5, 1, "%.0f", 1),
        P("limit", "Limit (0 = the class rule)", 0, 4, 0.05f, "%.2f", 0),
        P("soft", "Soft edge", 0, 1, 0.01f, "%.2f", 0.05f),
        P("blocked", "Mask the blocked ground (1) or the passable (0)", 0, 1, 1, "%.0f", 0)}},
      {"height",
       "Height band",
       false,
       {P("lo", "From (units)", -100, 600, 0.5f, "%.1f", 0),
        P("hi", "To (units)", -100, 600, 0.5f, "%.1f", 40),
        P("soft", "Soft edge (units)", 0, 100, 0.5f, "%.1f", 4),
        P("wobble", "Wobble (units, fractal noise)", 0, 100, 0.5f, "%.1f", 0),
        P("wsize", "Wobble feature size (units)", 8, 600, 2, "%.0f", 80),
        P("wseed", "Wobble seed", 0, 9999, 1, "%.0f", 1),
        P("sun", "Sun side starts the band higher by (units; negative: lower)", -100, 100, 0.5f, "%.1f", 0),
        P("sunaz", "Sun direction (degrees, 0 = +x, 90 = +z)", 0, 360, 5, "%.0f", 225)}},
      {"curvature",
       "Curvature",
       false,
       {P("radius", "Radius (units)", 1, 60, 1, "%.0f", 6),
        P("gain", "Gain", 1, 300, 1, "%.0f", 25),
        P("lo", "From (0.5 = flat)", 0, 1, 0.01f, "%.2f", 0.56f),
        P("hi", "To (1 = sharpest ridge)", 0, 1, 0.01f, "%.2f", 1),
        P("soft", "Soft edge", 0, 0.5f, 0.01f, "%.2f", 0.04f)}},
      {"relief",
       "Relief (height above the surroundings)",
       false,
       {P("radius", "Surroundings: blur radius (units)", 8, 300, 2, "%.0f", 60),
        P("lo", "From (units above the surroundings)", -60, 60, 0.25f, "%.2f", 0.5f),
        P("hi", "To (units above the surroundings)", -60, 100, 0.25f, "%.2f", 100),
        P("soft", "Soft edge (units)", 0, 30, 0.25f, "%.2f", 1.5f)}},
      {"aspect",
       "Aspect (facing)",
       false,
       {P("azimuth", "Facing direction (degrees, 0 = +x, 90 = +z)", 0, 360, 5, "%.0f", 225),
        P("from", "Facing from (0.5 = across, 1 = straight at it)", 0, 1, 0.01f, "%.2f", 0.6f),
        P("soft", "Soft edge", 0, 1, 0.01f, "%.2f", 0.15f),
        P("flat", "Level below this rise per run", 0.005f, 1, 0.005f, "%.3f", 0.05f)}},
      {"water",
       "Water",
       false,
       {P("mode", "Mode (1 land above, 2 under water, 3 shore band)", 1, 3, 1, "%.0f", 1),
        P("offset", "Level above the water surface (units)", -60, 200, 0.5f, "%.1f", 0),
        P("width", "Band half width (mode 3, units)", 0, 50, 0.5f, "%.1f", 2),
        P("soft", "Soft edge (units)", 0, 50, 0.5f, "%.1f", 2)}},
      {"shoredist",
       "Shore (width along the ground)",
       false,
       {P("width", "Width on land (units)", 0, 100, 0.5f, "%.1f", 6),
        P("depth", "Shallow water that counts (units)", 0, 30, 0.5f, "%.1f", 3),
        P("soft", "Soft edge (units)", 0, 50, 0.5f, "%.1f", 3)}},
      {"noise",
       "Noise",
       false,
       {P("kind", "Kind (1 perlin, 2 simplex, 3 ridged, 4 billow, 5 fractal)", 1, 5, 1, "%.0f", 1),
        P("seed", "Seed", 0, 9999, 1, "%.0f", 1),
        P("size", "Feature size (units)", 4, 600, 2, "%.0f", 60),
        P("octaves", "Octaves", 1, 8, 1, "%.0f", 4),
        P("from", "From", 0, 1, 0.01f, "%.2f", 0.45f),
        P("to", "To", 0, 1, 0.01f, "%.2f", 0.65f)}},
      {"flow",
       "Flow (drainage)",
       false,
       {P("range", "Catchment area that reads 1 (x1000 units squared)", 10, 100000, 10, "%.0f", 1000),
        P("from", "From", 0, 1, 0.01f, "%.2f", 0.5f),
        P("to", "To", 0, 1, 0.01f, "%.2f", 0.7f)}},
      {"position",
       "Position",
       false,
       {P("kind", "Kind (1 linear, 2 distance from the middle)", 1, 2, 1, "%.0f", 1),
        P("angle", "Direction (degrees)", 0, 360, 5, "%.0f", 90),
        P("from", "From", -1, 2, 0.01f, "%.2f", 0),
        P("to", "To", -1, 2, 0.01f, "%.2f", 1)}},
      {"layer",
       "Texture layer",
       false,
       {P("layer", "Layer", 1, 8, 1, "%.0f", 1),
        P("visible", "Only where visible (1) or all of it (0)", 0, 1, 1, "%.0f", 0)}},
      {"free_above", "Free of layers above", false, {P("layer", "Layers above this one", 0, 8, 1, "%.0f", 1)}},
      {"near_layer",
       "Near a texture layer",
       false,
       {P("layer", "Layer", 1, 8, 1, "%.0f", 1),
        P("distance", "Distance (units)", 0, 300, 1, "%.0f", 12),
        P("soft", "Soft edge (units)", 0, 100, 1, "%.0f", 4)}},
      {"const", "Constant", false, {P("value", "Value", 0, 1, 0.05f, "%.2f", 1)}},
      {"not", "Not (invert)", true, {}},
      {"blur", "Blur", true, {P("radius", "Sigma (units)", 0.5f, 100, 0.5f, "%.1f", 6)}},
      {"grow",
       "Grow",
       true,
       {P("distance", "Distance (units)", 0.5f, 200, 0.5f, "%.1f", 6),
        P("soft", "Soft edge (units)", 0, 50, 0.5f, "%.1f", 2)}},
      {"shrink",
       "Shrink",
       true,
       {P("distance", "Distance (units)", 0.5f, 200, 0.5f, "%.1f", 6),
        P("soft", "Soft edge (units)", 0, 50, 0.5f, "%.1f", 2)}},
      {"open", "Remove specks", true, {P("radius", "Smaller than (units)", 0.5f, 100, 0.5f, "%.1f", 3)}},
      {"close", "Fill holes", true, {P("radius", "Smaller than (units)", 0.5f, 100, 0.5f, "%.1f", 3)}},
      {"threshold", "Threshold", true, {P("value", "Above", 0, 1, 0.01f, "%.2f", 0.5f)}},
      {"smoothstep",
       "Smooth step",
       true,
       {P("edge0", "Edge 0", 0, 1, 0.01f, "%.2f", 0.3f), P("edge1", "Edge 1", 0, 1, 0.01f, "%.2f", 0.7f)}},
      {"amount", "Amount", true, {P("factor", "Multiply by", 0, 10, 0.05f, "%.2f", 1.5f)}},
      {"crisp",
       "Ragged edge",
       true,
       {P("crisp", "Crispness (0 soft, 1 sharp)", 0, 1, 0.05f, "%.2f", 0.5f),
        P("noise", "Edge noise", 0, 1, 0.05f, "%.2f", 0.35f),
        P("size", "Noise feature size (units)", 4, 300, 2, "%.0f", 24),
        P("seed", "Seed", 0, 9999, 1, "%.0f", 1)}},
      {"grain",
       "Fine grain",
       true,
       {P("amount", "How much the paint varies (0..1)", 0, 1, 0.05f, "%.2f", 0.3f),
        P("size", "Grain size (units)", 2, 60, 1, "%.0f", 7),
        P("seed", "Seed", 0, 9999, 1, "%.0f", 1)}},
    };
    return catalogue;
  }

  const MaskRuleSpec* MaskRuleSpecOf(
    const std::string& id
  )
  {
    for (const MaskRuleSpec& spec : MaskRuleCatalogue()) {
      if (id == spec.id) {
        return &spec;
      }
    }
    return nullptr;
  }

  const char* MaskCombineName(
    const MaskCombine op
  ) noexcept
  {
    switch (op) {
    case MaskCombine::Or:
      return "OR (the larger)";
    case MaskCombine::Mul:
      return "Multiply";
    case MaskCombine::Sub:
      return "Difference (minus)";
    case MaskCombine::Add:
      return "Add";
    case MaskCombine::And:
      break;
    }
    return "AND (the smaller)";
  }

  float MaskGenRule::Value(
    const char* const key
  ) const
  {
    if (const auto found = v.find(key); found != v.end()) {
      return found->second;
    }
    if (const MaskRuleSpec* const spec = MaskRuleSpecOf(type)) {
      for (const MaskParamSpec& p : spec->params) {
        if (std::string_view(p.key) == key) {
          return p.fallback;
        }
      }
    }
    return 0.0f;
  }

  MaskGenRule NewMaskRule(
    const std::string& type
  )
  {
    MaskGenRule rule;
    rule.type = type;
    if (const MaskRuleSpec* const spec = MaskRuleSpecOf(type)) {
      for (const MaskParamSpec& p : spec->params) {
        rule.v[p.key] = p.fallback;
      }
    }
    return rule;
  }

  std::string DescribeMaskRule(
    const MaskGenRule& rule
  )
  {
    const MaskRuleSpec* const spec = MaskRuleSpecOf(rule.type);
    if (spec == nullptr) {
      return rule.type;
    }
    std::string text = spec->label;
    for (std::size_t i = 0; i < spec->params.size() && i < 3; ++i) {
      char value[32];
      std::snprintf(value, sizeof(value), spec->params[i].format, static_cast<double>(rule.Value(spec->params[i].key)));
      text += (i == 0 ? "  " : " / ");
      text += value;
    }
    return text;
  }

  void MaskLayerFields(
    const std::uint64_t* const texels,
    const int width,
    const int height,
    const float mapSize,
    const std::uint8_t remapped,
    MaskGenContext& context
  )
  {
    const float cell = mapSize / static_cast<float>(std::max(1, width));
    for (int layer = 1; layer <= 8; ++layer) {
      auto f = std::make_shared<field::Grid>(width, height, cell, cell * 0.5f, cell * 0.5f);
      const int byte = layer - 1;
      const bool range = (remapped & (1U << byte)) != 0;
      for (std::size_t i = 0; i < f->v.size(); ++i) {
        f->v[i] = MaskWeight(MaskByte(texels[i], byte), range) / 255.0f;
      }
      context.layers[static_cast<std::size_t>(byte)] = std::move(f);
    }
    context.cache.clear();
  }

  bool EvaluateMaskRules(
    MaskGenContext& context,
    const std::vector<MaskGenRule>& rules,
    field::Grid& out,
    std::string& error
  )
  {
    if (context.heights == nullptr || context.heights->v.empty()) {
      error = "no heights";
      return false;
    }
    try {
      Evaluator e{context};
      Field acc;
      for (const MaskGenRule& rule : rules) {
        if (!rule.enabled) {
          continue;
        }
        const MaskRuleSpec* const spec = MaskRuleSpecOf(rule.type);
        if (spec == nullptr) {
          throw OpFailed("unknown rule " + rule.type);
        }
        if (spec->modifier) {
          if (acc != nullptr) {
            acc = e.Modify(rule, acc);
          }
          continue;
        }
        Field r = e.Source(rule);
        if (rule.invert) {
          r = e.Invert(r);
        }
        acc = acc == nullptr ? r : e.Combine(acc, r, rule.op);
      }
      if (acc == nullptr) {
        error = "no rule is switched on";
        return false;
      }
      out = *acc;
      return true;
    } catch (const OpFailed& failed) {
      error = failed.what();
      return false;
    }
  }

  bool FreeAboveLayer(
    MaskGenContext& context,
    const int layer,
    field::Grid& out,
    std::string& error
  )
  {
    try {
      Evaluator e{context};
      out = *e.FreeAbove(layer);
      return true;
    } catch (const OpFailed& failed) {
      error = failed.what();
      return false;
    }
  }

  const std::vector<MaskPreset>& MaskPresets()
  {
    static const std::vector<MaskPreset> presets = {
      {"cliffs", "Cliffs (steep ground)"},
      {"blocked", "Ground land units cannot cross"},
      {"buildable", "Buildable flat ground (structures, above water)"},
      {"beach", "Beach (shore band on gentle ground)"},
      {"snow", "Snow caps (top fifth, not steep, patchy)"},
      {"ridges", "Ridge tops (convex ground)"},
      {"gullies", "Gullies and river beds (drainage on concave ground)"},
      {"sunny", "Sun-facing slopes (south west)"},
      {"patches", "Dirt patches (noise on flat ground)"},
      {"shorefoam", "Shore foam (the band where land meets water)"},
      {"deepcalm", "Deep water (for calm patches)"},
      {"edge", "Map edge band"},
    };
    return presets;
  }

  std::vector<MaskGenRule> MaskPresetRules(
    const std::string& id,
    const float heightLow,
    const float heightHigh
  )
  {
    using enum MaskCombine;
    if (id == "cliffs") {
      return {Rule("slope", {{"lo", 38}, {"hi", 90}, {"soft", 6}}), Rule("blur", {{"radius", 2}})};
    }
    if (id == "blocked") {
      return {Rule("unitclass", {{"class", 1}, {"blocked", 1}, {"soft", 0.05f}})};
    }
    if (id == "buildable") {
      return {
        Rule("unitclass", {{"class", 5}, {"blocked", 0}, {"soft", 0.05f}}),
        Rule("water", {{"mode", 1}, {"offset", 0.5f}, {"soft", 0.5f}})
      };
    }
    if (id == "beach") {
      return {
        Rule("water", {{"mode", 3}, {"offset", 0.5f}, {"width", 3}, {"soft", 2}}),
        Rule("slope", {{"lo", 0}, {"hi", 22}, {"soft", 6}}),
        Rule("blur", {{"radius", 1.5f}})
      };
    }
    if (id == "snow") {
      const float span = heightHigh - heightLow;
      return {
        Rule("height", {{"lo", heightLow + span * 0.78f}, {"hi", heightHigh + 50.0f}, {"soft", span * 0.08f}}),
        Rule("slope", {{"lo", 0}, {"hi", 38}, {"soft", 10}}),
        Rule("noise", {{"kind", 1}, {"seed", 3}, {"size", 40}, {"octaves", 4}, {"from", 0.3f}, {"to", 0.6f}}, Mul)
      };
    }
    if (id == "ridges") {
      return {
        Rule("curvature", {{"radius", 6}, {"gain", 30}, {"lo", 0.56f}, {"hi", 1}, {"soft", 0.05f}}),
        Rule("blur", {{"radius", 2}})
      };
    }
    if (id == "gullies") {
      return {
        Rule("flow", {{"range", 1000}, {"from", 0.45f}, {"to", 0.65f}}),
        Rule("curvature", {{"radius", 4}, {"gain", 25}, {"lo", 0}, {"hi", 0.46f}, {"soft", 0.04f}}, Or),
        Rule("blur", {{"radius", 1.5f}})
      };
    }
    if (id == "sunny") {
      return {
        Rule("aspect", {{"azimuth", 225}, {"from", 0.62f}, {"soft", 0.2f}, {"flat", 0.04f}}),
        Rule("slope", {{"lo", 6}, {"hi", 60}, {"soft", 6}})
      };
    }
    if (id == "patches") {
      return {
        Rule("noise", {{"kind", 1}, {"seed", 5}, {"size", 48}, {"octaves", 4}, {"from", 0.5f}, {"to", 0.62f}}),
        Rule("slope", {{"lo", 0}, {"hi", 28}, {"soft", 8}})
      };
    }
    if (id == "shorefoam") {
      return {
        Rule("water", {{"mode", 3}, {"offset", 0}, {"width", 2.5f}, {"soft", 2.5f}}), Rule("blur", {{"radius", 1.5f}})
      };
    }
    if (id == "deepcalm") {
      return {Rule("water", {{"mode", 2}, {"offset", -8}, {"soft", 6}})};
    }
    if (id == "edge") {
      return {Rule("position", {{"kind", 2}, {"from", 0.8f}, {"to", 1}})};
    }
    return {};
  }

  float SampleField(
    const field::Grid& grid,
    const float x,
    const float z
  )
  {
    if (grid.w < 1 || grid.h < 1 || grid.v.empty()) {
      return 0.0f;
    }
    const float gx = std::clamp((x - grid.ox) / grid.cell, 0.0f, static_cast<float>(grid.w - 1));
    const float gz = std::clamp((z - grid.oz) / grid.cell, 0.0f, static_cast<float>(grid.h - 1));
    const int x0 = static_cast<int>(gx);
    const int z0 = static_cast<int>(gz);
    const int x1 = std::min(x0 + 1, grid.w - 1);
    const int z1 = std::min(z0 + 1, grid.h - 1);
    const float fx = gx - static_cast<float>(x0);
    const float fz = gz - static_cast<float>(z0);
    const auto at = [&](const int i, const int j) {
      return grid.v[static_cast<std::size_t>(j) * static_cast<std::size_t>(grid.w) + static_cast<std::size_t>(i)];
    };
    const float top = at(x0, z0) + (at(x1, z0) - at(x0, z0)) * fx;
    const float bottom = at(x0, z1) + (at(x1, z1) - at(x0, z1)) * fx;
    return top + (bottom - top) * fz;
  }

  std::size_t WriteMaskLayer(
    std::uint64_t* const texels,
    const int width,
    const int height,
    const float mapSize,
    const int layer,
    const std::uint8_t remapped,
    const field::Grid& mask,
    const MaskWriteMode mode,
    const float strength,
    const bool takeAway
  )
  {
    if (texels == nullptr || width < 1 || height < 1 || layer < 1 || layer > 8) {
      return 0;
    }
    const int byte = layer - 1;
    const bool range = (remapped & (1U << byte)) != 0;
    const float cell = mapSize / static_cast<float>(width);
    std::size_t changed = 0;
    for (int z = 0; z < height; ++z) {
      for (int x = 0; x < width; ++x) {
        std::uint64_t& texel =
          texels[static_cast<std::size_t>(z) * static_cast<std::size_t>(width) + static_cast<std::size_t>(x)];
        float m = std::clamp(
          SampleField(mask, (static_cast<float>(x) + 0.5f) * cell, (static_cast<float>(z) + 0.5f) * cell), 0.0f, 1.0f
        );
        if (takeAway) {
          for (int k = byte + 1; k < 8; ++k) {
            m *= 1.0f - MaskWeight(MaskByte(texel, k), (remapped & (1U << k)) != 0) / 255.0f;
          }
        }
        const std::uint8_t before = MaskByte(texel, byte);
        const float old = MaskWeight(before, range) / 255.0f;
        const float target = mode == MaskWriteMode::AddTo ? std::max(old, m)
          : mode == MaskWriteMode::SubtractFrom           ? old * (1.0f - m)
                                                          : m;
        const float weight = old + (target - old) * std::clamp(strength, 0.0f, 1.0f);
        const std::uint8_t stored = MaskStoredFor(weight * 255.0f, range, before);
        if (stored != before) {
          texel = WithMaskByte(texel, byte, stored);
          ++changed;
        }
      }
    }
    return changed;
  }
} // namespace faf::editor
