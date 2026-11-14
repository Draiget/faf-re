// The terrain graph's node types (FAF Studio's graphnodes.lua and graphnodes_land.lua): their pins, their parameters
// (the inspector's sliders) and their evaluations over the field library's ops. A number parameter marked `wire` also
// has an input pin of its name that overrides it.

#include "editor/graph/EdTerrainEval.h"
#include "editor/tools/EdErosionSuite.h"
#include "editor/tools/EdMaskGen.h"
#include "editor/tools/EdRecipes.h"

#include <algorithm>
#include <array>
#include <functional>
#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace faf::editor::terrain
{
  namespace
  {
    ParamDef N(
      const char* key,
      const char* label,
      const float min,
      const float max,
      const float step,
      const char* format,
      const float initial,
      const bool wire = false
    )
    {
      ParamDef p;
      p.name = key;
      p.label = label;
      p.kind = ParamKind::Float;
      p.min = min;
      p.max = max;
      p.step = step;
      p.format = format;
      p.initial = {initial, 0.0f, 0.0f, 0.0f};
      p.wire = wire;
      return p;
    }
    ParamDef Seed()
    {
      ParamDef p = N("seed", "Seed", 0.0f, 9999.0f, 1.0f, "%.0f", 1.0f);
      p.seed = true;
      return p;
    }
    ParamDef C(
      const char* key,
      const char* label,
      std::vector<std::string> ids,
      std::vector<std::string> labels,
      const char* initial
    )
    {
      ParamDef p;
      p.name = key;
      p.label = label;
      p.kind = ParamKind::Choice;
      p.choices = labels.empty() ? ids : std::move(labels);
      p.choiceIds = std::move(ids);
      p.max = static_cast<float>(p.choiceIds.size()) - 1.0f;
      for (std::size_t i = 0; i < p.choiceIds.size(); ++i) {
        if (p.choiceIds[i] == initial) {
          p.initial[0] = static_cast<float>(i);
        }
      }
      return p;
    }
    ParamDef B(
      const char* key,
      const char* label,
      const bool initial
    )
    {
      ParamDef p;
      p.name = key;
      p.label = label;
      p.kind = ParamKind::Bool;
      p.initial[0] = initial ? 1.0f : 0.0f;
      return p;
    }
    ParamDef T(
      const char* key,
      const char* label,
      const char* initial
    )
    {
      ParamDef p;
      p.name = key;
      p.label = label;
      p.kind = ParamKind::Text;
      p.initialText = initial;
      return p;
    }
    PinDef Pin(
      const char* name,
      const PinType type = PinType::Height
    )
    {
      PinDef pin;
      pin.name = name;
      pin.type = type;
      return pin;
    }

    std::vector<ParamDef> NoiseParams(
      const float size = 120.0f
    )
    {
      return {
        Seed(),
        N("scale", "Feature size (units)", 4, 800, 2, "%.0f", size, true),
        N("octaves", "Octaves", 1, 10, 1, "%.0f", 5),
        N("persistence", "Persistence", 0.2f, 0.9f, 0.05f, "%.2f", 0.5f),
      };
    }

    /** Collects the node types: Add() makes one. */
    struct Catalogue
    {
      NodeTypeRegistry& registry;
      std::map<std::string, NodeBehaviour>& behaviours;

      void Add(
        const char* id,
        const char* label,
        const char* category,
        const char* help,
        std::vector<PinDef> inputs,
        std::vector<PinDef> outputs,
        std::vector<ParamDef> params,
        Eval eval,
        const char* output = ""
      )
      {
        NodeType type;
        type.name = id;
        type.title = label;
        type.category = category;
        type.help = help;
        type.inputs = std::move(inputs);
        // A number pin for every number that can be wired.
        for (const ParamDef& p : params) {
          if (p.kind == ParamKind::Float && p.wire) {
            type.inputs.push_back(Pin(p.name.c_str(), PinType::Number));
          }
        }
        type.outputs = std::move(outputs);
        type.params = std::move(params);
        registry.Add(std::move(type));
        behaviours[id] = NodeBehaviour{std::move(eval), output};
      }
    };

    const std::vector<PinDef> kHeightOut = {Pin("out")};
    const std::vector<PinDef> kMaskOut = {Pin("out", PinType::Mask)};
    const std::vector<PinDef> kNumberOut = {Pin("out", PinType::Number)};

    Eval NoiseEval(
      const char* op,
      const double lo,
      const double hi
    )
    {
      return [op, lo, hi](const Env& E, const Values& v, const Inputs&) {
        const field::GridPtr f = E.Op(
          op,
          {{"like", E.like},
           {"seed", E.Seed(v.N("seed"))},
           {"scale", v.N("scale")},
           {"octaves", v.N("octaves")},
           {"persistence", v.N("persistence")},
           {"rotate", 1}}
        );
        return One(E.Fit(f, lo, hi));
      };
    }

    /** A shape filter: the op of the same name on input a with its parameters as they are. */
    void Filter(
      Catalogue& c,
      const char* id,
      const char* label,
      const char* help,
      std::vector<ParamDef> params,
      const std::vector<PinDef>& outputs = kHeightOut
    )
    {
      std::vector<std::string> numbers;
      std::vector<std::string> words;
      for (const ParamDef& p : params) {
        (p.kind == ParamKind::Choice || p.kind == ParamKind::Text ? words : numbers).push_back(p.name);
      }
      const std::string op = id;
      c.Add(
        id,
        label,
        "shape",
        help,
        {Pin("a")},
        outputs,
        std::move(params),
        [op, numbers, words](const Env& E, const Values& v, const Inputs& ins) {
        std::vector<Arg> args = {{"a", In(ins, "a")}};
        for (const std::string& key : numbers) {
          args.emplace_back(key.c_str(), v.N(key));
        }
        for (const std::string& key : words) {
          args.emplace_back(key.c_str(), v.S(key));
        }
        return One(E.Op(op, args));
      }
      );
    }

    /** a op b, or a op a value when b isn't linked. */
    void Binary(
      Catalogue& c,
      const char* id,
      const char* label,
      const char* help
    )
    {
      const std::string op = id;
      c.Add(
        id,
        label,
        "combine",
        help,
        {Pin("a"), Pin("b")},
        kHeightOut,
        {N("value", "Value (when b is not linked)", -300, 600, 0.05f, "%.2f", 0, true)},
        [op](const Env& E, const Values& v, const Inputs& ins) {
        field::GridPtr b = In(ins, "b");
        if (b == nullptr) {
          b = E.Const(v.N("value"));
        }
        return One(E.Op(op, {{"a", In(ins, "a")}, {"b", b}}));
      }
      );
    }

    /** The land-unit classes of the pathable-ground rule (Studio's maskgen.lua CLASSES). */
    struct UnitClass
    {
      const char* kind;
      int window;
      float limit;
    };
    constexpr UnitClass kClasses[] = {
      {"rating", 1, 0.75f},
      {"rating", 2, 0.75f},
      {"rating", 3, 0.75f},
      {"rating", 5, 0.75f},
      {"variation", 2, 1.1f},
    };

    /** Where a share p of a normal distribution lies above, in deviations (Abramowitz and Stegun 26.2.23). */
    double NormalAbove(
      double p
    )
    {
      p = std::clamp(p, 0.001, 0.999);
      const double q = p < 0.5 ? p : 1.0 - p;
      const double t = std::sqrt(-2.0 * std::log(q));
      const double z = t -
        (2.515517 + 0.802853 * t + 0.010328 * t * t) / (1.0 + 1.432788 * t + 0.189269 * t * t + 0.001308 * t * t * t);
      return p < 0.5 ? z : -z;
    }

    /** "x y x y ..." (a curve parameter's text) as numbers. */
    std::vector<double> NumberList(
      const std::string& text
    )
    {
      std::vector<double> out;
      const char* at = text.c_str();
      while (*at != '\0') {
        char* end = nullptr;
        const double value = std::strtod(at, &end);
        if (end == at) {
          ++at;
          continue;
        }
        out.push_back(value);
        at = end;
      }
      return out;
    }

    /**
     * The colour ramp's stops as the op takes them (position, r, g, b, a per stop): a named ramp, or the custom text
     * `pos:#rrggbb;pos:#rrggbb` (an optional alpha byte after the colour); reversed when asked.
     */
    std::vector<double> RampStops(
      const std::string& id,
      const std::string& custom,
      const bool reverse,
      const double alpha
    )
    {
      struct Stop
      {
        double at, r, g, b, a;
      };
      static const std::map<std::string, std::vector<std::array<double, 4>>> kRamps = {
        {"terrain",
         {{0, 0.06, 0.18, 0.4},
          {0.2, 0.2, 0.45, 0.65},
          {0.3, 0.76, 0.7, 0.5},
          {0.4, 0.3, 0.55, 0.2},
          {0.65, 0.5, 0.4, 0.25},
          {0.85, 0.7, 0.68, 0.65},
          {1, 1, 1, 1}}},
        {"heat", {{0, 0, 0, 0}, {0.25, 0.5, 0, 0.1}, {0.5, 0.9, 0.3, 0}, {0.75, 1, 0.85, 0.1}, {1, 1, 1, 0.9}}},
        {"ocean", {{0, 0.02, 0.05, 0.2}, {0.5, 0.1, 0.4, 0.6}, {0.85, 0.5, 0.85, 0.9}, {1, 1, 1, 1}}},
        {"snow", {{0, 0.25, 0.28, 0.33}, {0.5, 0.6, 0.65, 0.72}, {1, 1, 1, 1}}},
        {"viridis",
         {{0, 0.27, 0, 0.33},
          {0.25, 0.23, 0.32, 0.55},
          {0.5, 0.13, 0.57, 0.55},
          {0.75, 0.37, 0.79, 0.38},
          {1, 0.99, 0.91, 0.14}}},
        {"grey", {{0, 0, 0, 0}, {1, 1, 1, 1}}},
        {"lush", {{0, 0.55, 0.45, 0.3}, {0.35, 0.45, 0.55, 0.25}, {0.65, 0.2, 0.5, 0.15}, {1, 0.08, 0.3, 0.12}}},
      };
      std::vector<Stop> stops;
      if (const auto found = kRamps.find(id); id != "custom" && found != kRamps.end()) {
        for (const auto& s : found->second) {
          stops.push_back({s[0], s[1], s[2], s[3], alpha});
        }
      } else {
        std::size_t at = 0;
        while (at < custom.size()) {
          const std::size_t end = std::min(custom.find(';', at), custom.size());
          const std::string item = custom.substr(at, end - at);
          at = end + 1;
          const std::size_t colon = item.find(':');
          if (colon == std::string::npos) {
            continue;
          }
          std::string hex = item.substr(colon + 1);
          hex.erase(std::remove(hex.begin(), hex.end(), '#'), hex.end());
          if (hex.size() < 6) {
            continue;
          }
          const auto byte = [&](const std::size_t i) {
            return static_cast<double>(std::strtol(hex.substr(i, 2).c_str(), nullptr, 16)) / 255.0;
          };
          stops.push_back(
            {std::atof(item.substr(0, colon).c_str()), byte(0), byte(2), byte(4), hex.size() >= 8 ? byte(6) : alpha}
          );
        }
        if (stops.size() < 2) {
          Fail("the custom ramp needs two stops like 0:#103060;1:#ffffff");
        }
      }
      if (reverse) {
        std::reverse(stops.begin(), stops.end());
        for (Stop& s : stops) {
          s.at = 1.0 - s.at;
        }
      }
      std::vector<double> flat;
      for (const Stop& s : stops) {
        flat.insert(flat.end(), {s.at, s.r, s.g, s.b, s.a});
      }
      return flat;
    }

    // ---- paths (FAF Studio's paths.lua): a Catmull-Rom curve through the control points sampled by arc length, the
    // section profiles and the modes, and the number list the path ops read.
    struct PathProfile
    {
      const char* id;
      bool smooth;
      std::vector<double> points; // x, y pairs
    };
    const std::vector<PathProfile>& PathProfiles()
    {
      static const std::vector<PathProfile> kProfiles = {
        {"ramp", true, {0, 1, 1, 1}},
        {"road", true, {0, 1, 0.6, 1, 0.8, 0.55, 1, 0.2}},
        {"v", false, {0, 1, 1, 0}},
        {"u", true, {0, 1, 0.55, 1, 0.8, 0.85, 0.93, 0.35, 1, 0}},
        {"ridge", true, {0, 1, 0.4, 0.45, 1, 0}},
        {"wall", true, {0, 1, 0.85, 1, 1, 0}},
        {"terrace", true, {0, 1, 0.2, 1, 0.28, 0.75, 0.46, 0.75, 0.54, 0.5, 0.72, 0.5, 0.8, 0.25, 0.95, 0.25, 1, 0}},
      };
      return kProfiles;
    }
    const PathProfile& PathProfileOf(
      const std::string& id
    )
    {
      for (const PathProfile& p : PathProfiles()) {
        if (id == p.id) {
          return p;
        }
      }
      return PathProfiles().front();
    }
    /** A mode: the op's mode (offset or target), what it keeps (none, min: only lowering), its own profile. */
    struct PathMode
    {
      const char* id;
      const char* native;
      const char* clip;
      const char* profile;
      bool river;
    };
    const PathMode& PathModeOf(
      const std::string& id
    )
    {
      static const PathMode kModes[] = {
        {"carve", "offset", "none", "u", false},
        {"raise", "offset", "none", "ridge", false},
        {"level", "target", "none", "ramp", false},
        {"ramp", "target", "none", "ramp", false},
        {"road", "target", "none", "road", false},
        {"river", "target", "min", "u", true},
      };
      for (const PathMode& m : kModes) {
        if (id == m.id) {
          return m;
        }
      }
      return kModes[0];
    }

    /** The dense polyline of a path: position, half width, falloff, height (offset or above the ground), the segment
     * and where in it, the arc length; the arc length at every control point. */
    struct PathSamples
    {
      std::vector<float> x, z, w, f, h, t, s;
      std::vector<int> seg;
      std::vector<float> ctrlS;
      [[nodiscard]] std::size_t Count() const noexcept
      {
        return x.size();
      }
    };
    PathSamples SamplePath(
      const TerrainPath& path,
      const float step = 1.0f
    )
    {
      PathSamples S;
      const auto& pts = path.points;
      const int n = static_cast<int>(pts.size());
      if (n == 0) {
        return S;
      }
      // Catmull-Rom handles (tension 1): a sixth of the neighbours' span.
      std::vector<std::array<float, 2>> out(static_cast<std::size_t>(n));
      std::vector<std::array<float, 2>> in(static_cast<std::size_t>(n));
      for (int i = 0; i < n; ++i) {
        const TerrainPath::Point& p = pts[static_cast<std::size_t>(i)];
        const TerrainPath::Point* prev =
          i > 0 ? &pts[static_cast<std::size_t>(i - 1)] : (path.closed && n > 2 ? &pts.back() : nullptr);
        const TerrainPath::Point* next =
          i < n - 1 ? &pts[static_cast<std::size_t>(i + 1)] : (path.closed && n > 2 ? &pts.front() : nullptr);
        const float px = prev != nullptr ? prev->x : p.x;
        const float pz = prev != nullptr ? prev->z : p.z;
        const float qx = next != nullptr ? next->x : p.x;
        const float qz = next != nullptr ? next->z : p.z;
        out[static_cast<std::size_t>(i)] = {(qx - px) / 6.0f, (qz - pz) / 6.0f};
        in[static_cast<std::size_t>(i)] = {-(qx - px) / 6.0f, -(qz - pz) / 6.0f};
      }
      const int segments = path.closed && n > 2 ? n : n - 1;
      float length = 0.0f;
      const auto push = [&](
                          const float x,
                          const float z,
                          const TerrainPath::Point& a,
                          const TerrainPath::Point& b,
                          const float t,
                          const int seg
                        ) {
        if (!S.x.empty()) {
          length += std::hypot(x - S.x.back(), z - S.z.back());
        }
        S.x.push_back(x);
        S.z.push_back(z);
        S.w.push_back(a.width + (b.width - a.width) * t);
        S.f.push_back(a.falloff + (b.falloff - a.falloff) * t);
        S.h.push_back(a.height + (b.height - a.height) * t);
        S.t.push_back(t);
        S.seg.push_back(seg);
        S.s.push_back(length);
      };
      if (segments < 1) {
        push(pts[0].x, pts[0].z, pts[0], pts[0], 0.0f, 0);
        S.ctrlS = {0.0f};
        return S;
      }
      S.ctrlS.assign(static_cast<std::size_t>(segments) + 1, 0.0f);
      for (int i = 0; i < segments; ++i) {
        const int j = (i + 1) % n;
        const TerrainPath::Point& a = pts[static_cast<std::size_t>(i)];
        const TerrainPath::Point& b = pts[static_cast<std::size_t>(j)];
        const float p0x = a.x, p0z = a.z;
        const float p1x = a.x + out[static_cast<std::size_t>(i)][0], p1z = a.z + out[static_cast<std::size_t>(i)][1];
        const float p2x = b.x + in[static_cast<std::size_t>(j)][0], p2z = b.z + in[static_cast<std::size_t>(j)][1];
        const float p3x = b.x, p3z = b.z;
        const float poly =
          std::hypot(p1x - p0x, p1z - p0z) + std::hypot(p2x - p1x, p2z - p1z) + std::hypot(p3x - p2x, p3z - p2z);
        const int count = std::clamp(static_cast<int>(std::ceil(poly / step)), 2, 400);
        const int last = i == segments - 1 ? count : count - 1;
        // The attributes run along the segment's arc length (not the curve parameter, which is fast in the middle).
        std::vector<float> qx(static_cast<std::size_t>(count) + 1), qz(static_cast<std::size_t>(count) + 1),
          cum(static_cast<std::size_t>(count) + 1);
        float total = 0.0f;
        for (int q = 0; q <= count; ++q) {
          const float t = static_cast<float>(q) / static_cast<float>(count);
          const float u = 1.0f - t;
          const float c0 = u * u * u, c1 = 3 * u * u * t, c2 = 3 * u * t * t, c3 = t * t * t;
          qx[static_cast<std::size_t>(q)] = c0 * p0x + c1 * p1x + c2 * p2x + c3 * p3x;
          qz[static_cast<std::size_t>(q)] = c0 * p0z + c1 * p1z + c2 * p2z + c3 * p3z;
          if (q > 0) {
            total += std::hypot(
              qx[static_cast<std::size_t>(q)] - qx[static_cast<std::size_t>(q) - 1],
              qz[static_cast<std::size_t>(q)] - qz[static_cast<std::size_t>(q) - 1]
            );
          }
          cum[static_cast<std::size_t>(q)] = total;
        }
        for (int q = 0; q <= last; ++q) {
          float frac = total > 0.00001f ? cum[static_cast<std::size_t>(q)] / total
                                        : static_cast<float>(q) / static_cast<float>(count);
          if (q == count) {
            frac = 1.0f;
          }
          push(qx[static_cast<std::size_t>(q)], qz[static_cast<std::size_t>(q)], a, b, frac, i);
          if (q == 0) {
            S.ctrlS[static_cast<std::size_t>(i)] = length;
          }
        }
      }
      S.ctrlS[static_cast<std::size_t>(segments)] = length;
      return S;
    }

    /** The path ops' arguments: 8 numbers a sample (x, z, target height, half width, falloff, bank, offset, arc
     * length), the profile, its smoothness. */
    std::vector<Arg> PathArgs(
      const PathSamples& S,
      const std::vector<float>& ys,
      const std::vector<float>& offs,
      const PathProfile& profile
    )
    {
      std::vector<double> flat;
      flat.reserve(S.Count() * 8);
      for (std::size_t k = 0; k < S.Count(); ++k) {
        flat.insert(
          flat.end(),
          {S.x[k], S.z[k], k < ys.size() ? ys[k] : 0.0f, S.w[k], S.f[k], 0.0, k < offs.size() ? offs[k] : 0.0f, S.s[k]}
        );
      }
      return {
        {"pts", std::move(flat)}, {"profile", profile.points}, {"smooth", profile.smooth ? 1 : 0}, {"symmetric", 1}
      };
    }

    /** A seeded hash of (seed, i) in 0..1: the same at every resolution (Studio's wobble). */
    double PathHash(
      const int seed,
      const int i
    )
    {
      double h = std::fmod(std::sin(seed * 12.9898 + i * 78.233) * 43758.5453, 1.0);
      return h < 0.0 ? h + 1.0 : h;
    }

    /** A path from points in map units with the node's width, falloff and height for all of them. */
    std::shared_ptr<TerrainPath> PathFrom(
      const std::vector<std::pair<double, double>>& points,
      const Values& v,
      const bool closed
    )
    {
      auto path = std::make_shared<TerrainPath>();
      path->closed = closed;
      path->mode = v.text.count("mode") != 0 ? v.S("mode") : "carve";
      path->profile = v.text.count("profile") != 0 ? v.S("profile") : PathModeOf(path->mode).profile;
      for (const auto& [x, z] : points) {
        TerrainPath::Point p;
        p.x = static_cast<float>(x);
        p.z = static_cast<float>(z);
        p.width = static_cast<float>(v.num.count("width") != 0 ? v.N("width") : 6.0);
        p.falloff = static_cast<float>(v.num.count("falloff") != 0 ? v.N("falloff") : 4.0);
        p.height = static_cast<float>(v.num.count("height") != 0 ? v.N("height") : 0.0);
        path->points.push_back(p);
      }
      return path;
    }

    std::shared_ptr<const TerrainPath> PathIn(
      const Inputs& ins
    )
    {
      const auto found = ins.find("pts");
      return found != ins.end() && found->second != nullptr ? found->second->path : nullptr;
    }
  } // namespace

  void BuildCatalogue(
    NodeTypeRegistry& registry,
    std::map<std::string, NodeBehaviour>& behaviours
  )
  {
    Catalogue c{registry, behaviours};

    // ---- sources
    c.Add(
      "terrain",
      "Map heights",
      "sources",
      "The heights of the map as they were before the graph was run (a repeated Build starts from the same ground).",
      {},
      kHeightOut,
      {},
      [](const Env& E, const Values&, const Inputs&) {
      return One(E.base());
    }
    );
    c.Add(
      "const",
      "Constant",
      "sources",
      "The same value everywhere.",
      {},
      kHeightOut,
      {N("value", "Value", -200, 600, 0.5f, "%.1f", 30, true)},
      [](const Env& E, const Values& v, const Inputs&) {
      return One(E.Const(v.N("value")));
    }
    );

    // ---- generators
    c.Add(
      "perlin",
      "Perlin noise",
      "gen",
      "Fractal noise, 0..1. The same world position gives the same value at every resolution.",
      {},
      kHeightOut,
      NoiseParams(),
      NoiseEval("perlin", 0.25, 0.75)
    );
    c.Add(
      "simplex",
      "Simplex noise",
      "gen",
      "Fractal simplex noise, 0..1.",
      {},
      kHeightOut,
      NoiseParams(),
      NoiseEval("simplex", 0.1, 0.9)
    );
    c.Add(
      "billow",
      "Billow noise",
      "gen",
      "Rounded hills (absolute value noise), 0..1.",
      {},
      kHeightOut,
      NoiseParams(),
      NoiseEval("billow", 0.0, 0.5)
    );
    {
      std::vector<ParamDef> params = NoiseParams(150);
      params.push_back(C("basis", "Basis noise", {"perlin", "simplex"}, {"Perlin", "Simplex"}, "perlin"));
      c.Add(
        "ridged",
        "Ridged noise",
        "gen",
        "Sharp mountain ridges, 0..1.",
        {},
        kHeightOut,
        std::move(params),
        [](const Env& E, const Values& v, const Inputs&) {
        const field::GridPtr f = E.Op(
          "ridged",
          {{"like", E.like},
           {"seed", E.Seed(v.N("seed"))},
           {"scale", v.N("scale")},
           {"octaves", v.N("octaves")},
           {"persistence", v.N("persistence")},
           {"basis", v.S("basis")},
           {"rotate", 1}}
        );
        return One(E.Fit(f, 0.25, 1.0));
      }
      );
    }
    c.Add(
      "voronoi",
      "Voronoi cells",
      "gen",
      "Cell noise: distance to the nearest cell centre, the edges between cells, a random value per cell or cracks.",
      {},
      kHeightOut,
      {Seed(),
       N("scale", "Cell size (units)", 4, 600, 2, "%.0f", 80, true),
       N("jitter", "Jitter", 0, 1, 0.05f, "%.2f", 1),
       C("mode",
         "Mode",
         {"f1", "f2", "edge", "id", "crack"},
         {"Distance", "Second distance", "Edges", "Value per cell", "Cracks"},
         "f1"),
       N("thickness", "Crack thickness", 0.02f, 0.5f, 0.01f, "%.2f", 0.12f)},
      [](const Env& E, const Values& v, const Inputs&) {
      const field::GridPtr f = E.Op(
        "voronoi",
        {{"like", E.like},
         {"seed", E.Seed(v.N("seed"))},
         {"scale", v.N("scale")},
         {"jitter", v.N("jitter")},
         {"mode", v.S("mode")},
         {"thickness", v.N("thickness")}}
      );
      return One(v.S("mode") == "f1" ? E.Fit(f, 0.0, 0.9) : f);
    }
    );
    c.Add(
      "gradient",
      "Gradient",
      "gen",
      "A linear ramp across the map in a direction.",
      {},
      kHeightOut,
      {N("angle", "Direction (degrees)", 0, 360, 5, "%.0f", 0),
       N("lo", "Start value", -1, 2, 0.05f, "%.2f", 0),
       N("hi", "End value", -1, 2, 0.05f, "%.2f", 1)},
      [](const Env& E, const Values& v, const Inputs&) {
      return One(E.Op("gradient", {{"like", E.like}, {"angle", v.N("angle")}, {"lo", v.N("lo")}, {"hi", v.N("hi")}}));
    }
    );
    c.Add(
      "radial",
      "Radial",
      "gen",
      "Distance from a centre: 0 there, 1 at the radius (and beyond). Invert it for an island.",
      {},
      kHeightOut,
      {N("cx", "Centre x (share of the map)", 0, 1, 0.01f, "%.2f", 0.5f),
       N("cz", "Centre z (share of the map)", 0, 1, 0.01f, "%.2f", 0.5f),
       N("radius", "Radius (units, 0 = half the map)", 0, 6000, 4, "%.0f", 0, true),
       B("invert", "Invert (1 in the middle)", false)},
      [](const Env& E, const Values& v, const Inputs&) {
      const double radius = v.N("radius") > 0.0 ? v.N("radius") : 0.5 * std::min(E.W, E.H);
      field::GridPtr f =
        E.Op("radial", {{"like", E.like}, {"cx", v.N("cx") * E.W}, {"cz", v.N("cz") * E.H}, {"radius", radius}});
      if (v.B("invert")) {
        f = E.Op("affine", {{"a", f}, {"mul", -1.0}, {"add", 1.0}});
      }
      return One(f);
    }
    );
    c.Add(
      "white",
      "White noise",
      "gen",
      "Uncorrelated noise per sample, 0..1.",
      {},
      kHeightOut,
      {Seed()},
      [](const Env& E, const Values& v, const Inputs&) {
      return One(E.Op("white", {{"like", E.like}, {"seed", E.Seed(v.N("seed"))}}));
    }
    );
    c.Add(
      "landform",
      "Landforms (plains and hills)",
      "gen",
      "Flat open plains and clusters of hills with defined flanks: a large noise places the hills over the share of "
      "the "
      "map chosen, the flanks are as wide as set, the hills get ridged detail. out is the height in units, mask the "
      "hills.",
      {},
      {Pin("out"), Pin("mask", PinType::Mask)},
      {Seed(),
       N("base", "Ground height of the plains (units)", 0, 200, 0.5f, "%.1f", 30),
       N("size", "Landform size (units)", 60, 800, 5, "%.0f", 240),
       N("coverage", "Share of the map that is hills", 0.05f, 0.9f, 0.01f, "%.2f", 0.35f),
       N("height", "Hill height above the plains (units)", 1, 120, 0.5f, "%.1f", 16),
       N("edge", "Width of the flanks (units)", 4, 120, 1, "%.0f", 24),
       N("top", "Roundness of the tops", 0, 1, 0.05f, "%.2f", 0.5f),
       N("detail", "Roughness of the hills", 0, 1, 0.05f, "%.2f", 0.5f),
       N("plains", "Unevenness of the plains (units)", 0, 10, 0.1f, "%.1f", 1.5f)},
      [](const Env& E, const Values& v, const Inputs&) {
      const double seed = v.N("seed");
      const double size = v.N("size");
      const field::GridPtr n = E.Fit(
        E.Op(
          "perlin",
          {{"like", E.like},
           {"seed", E.Seed(seed)},
           {"scale", size},
           {"octaves", 4},
           {"persistence", 0.5},
           {"rotate", 1}}
        ),
        0.25,
        0.75
      );
      const double t = 0.5 + 0.16 * NormalAbove(v.N("coverage"));
      const field::GridPtr cut = E.Op("smoothstep", {{"a", n}, {"edge0", t - 0.012}, {"edge1", t + 0.012}});
      const field::GridPtr mask = E.Op("blur", {{"a", cut}, {"radius", E.Units(std::max(2.0, v.N("edge") * 0.5))}});
      const field::GridPtr shaped = E.Op("gamma", {{"a", mask}, {"gamma", 1.6 - v.N("top")}});
      const field::GridPtr ridges = E.Fit(
        E.Op(
          "ridged",
          {{"like", E.like},
           {"seed", E.Seed(seed + 1)},
           {"scale", std::max(20.0, size * 0.35)},
           {"octaves", 5},
           {"persistence", 0.5},
           {"rotate", 1}}
        ),
        0.25,
        1.0
      );
      const double detail = v.N("detail");
      const field::GridPtr factor =
        E.Op("affine", {{"a", ridges}, {"mul", 0.5 * detail}, {"add", 1.0 - 0.25 * detail}});
      const field::GridPtr hills =
        E.Op("mul", {{"a", E.Op("affine", {{"a", shaped}, {"mul", v.N("height")}, {"add", 0.0}})}, {"b", factor}});
      const field::GridPtr p = E.Fit(
        E.Op(
          "perlin",
          {{"like", E.like},
           {"seed", E.Seed(seed + 2)},
           {"scale", size * 1.6},
           {"octaves", 3},
           {"persistence", 0.5},
           {"rotate", 1}}
        ),
        0.25,
        0.75
      );
      const field::GridPtr plains =
        E.Op("affine", {{"a", p}, {"mul", 2.0 * v.N("plains")}, {"add", v.N("base") - v.N("plains")}});
      Outputs out;
      out["out"].grid = E.Op("add", {{"a", plains}, {"b", hills}});
      out["mask"].grid = mask;
      return out;
    }
    );

    // ---- shape
    Filter(c, "blur", "Blur", "Gaussian blur.", {N("radius", "Sigma (units)", 0.5f, 120, 0.5f, "%.1f", 4, true)});
    Filter(
      c, "box", "Box blur", "Box blur (square average).", {N("radius", "Half width (units)", 1, 100, 1, "%.0f", 4)}
    );
    Filter(
      c,
      "clamp",
      "Clamp",
      "Limits the values to a range.",
      {N("lo", "Lowest", -300, 600, 0.05f, "%.2f", 0, true), N("hi", "Highest", -300, 600, 0.05f, "%.2f", 1, true)}
    );
    Filter(
      c,
      "invert",
      "Invert",
      "Turns low into high inside a range.",
      {N("lo", "Low", -300, 600, 0.05f, "%.2f", 0), N("hi", "High", -300, 600, 0.05f, "%.2f", 1)}
    );
    Filter(c, "abs", "Absolute value", "The absolute value (folds negative values up).", {});
    Filter(
      c,
      "gamma",
      "Gamma",
      "A power curve on 0..1: below 1 lifts the lows, above 1 flattens them.",
      {N("gamma", "Gamma", 0.2f, 4, 0.05f, "%.2f", 1.5f, true)}
    );
    Filter(
      c,
      "affine",
      "Scale and offset",
      "value x multiply + add.",
      {N("mul", "Multiply", -300, 600, 0.05f, "%.2f", 1, true), N("add", "Add", -300, 600, 0.5f, "%.1f", 0, true)}
    );
    Filter(
      c,
      "smoothstep",
      "Smooth step",
      "Smooth S curve between two edges: below edge 0 is 0, above edge 1 is 1.",
      {N("edge0", "Edge 0", -300, 600, 0.02f, "%.2f", 0.3f, true),
       N("edge1", "Edge 1", -300, 600, 0.02f, "%.2f", 0.7f, true)}
    );
    Filter(
      c,
      "threshold",
      "Threshold",
      "Hard cut: 1 above the value, 0 below.",
      {N("value", "Threshold", -300, 600, 0.02f, "%.2f", 0.5f, true)},
      kMaskOut
    );
    Filter(
      c,
      "normalize",
      "Normalize",
      "Stretches the lowest and highest value of the field to a range.",
      {N("lo", "Lowest", -300, 600, 0.5f, "%.1f", 0), N("hi", "Highest", -300, 600, 0.5f, "%.1f", 1)}
    );
    Filter(
      c,
      "quantize",
      "Quantize",
      "Rounds values to steps. 0.0078 (1/128) is the map's own height step.",
      {N("step", "Step", 0.0078125f, 20, 0.0078125f, "%.4f", 1)}
    );
    Filter(
      c,
      "levels",
      "Levels",
      "Input range, gamma and output range, like Photoshop levels.",
      {N("in_lo", "In low", -300, 600, 0.02f, "%.2f", 0.2f),
       N("in_hi", "In high", -300, 600, 0.02f, "%.2f", 0.8f),
       N("gamma", "Gamma", 0.2f, 4, 0.05f, "%.2f", 1),
       N("out_lo", "Out low", -300, 600, 0.02f, "%.2f", 0),
       N("out_hi", "Out high", -300, 600, 0.02f, "%.2f", 1)}
    );
    Filter(
      c,
      "terrace",
      "Terrace",
      "Steps the values: flat shelves with steep risers.",
      {N("steps", "Steps", 1, 40, 1, "%.0f", 6),
       N("sharpness", "Sharpness", 0, 1, 0.05f, "%.2f", 0.7f),
       N("lo", "Low", -300, 600, 0.5f, "%.1f", 0),
       N("hi", "High", -300, 600, 0.5f, "%.1f", 1)}
    );
    Filter(
      c,
      "offset",
      "Offset",
      "Moves the field (units).",
      {N("move_x", "Move x (units)", -4000, 4000, 1, "%.0f", 50),
       N("move_z", "Move z (units)", -4000, 4000, 1, "%.0f", 0)}
    );
    Filter(
      c,
      "rotate",
      "Rotate",
      "Turns the field around the middle.",
      {N("angle", "Angle (degrees)", -180, 180, 1, "%.0f", 30)}
    );
    Filter(
      c, "scale", "Zoom", "Zooms the field around the middle.", {N("factor", "Zoom", 0.25f, 4, 0.05f, "%.2f", 1.5f)}
    );
    Filter(
      c,
      "mirror",
      "Mirror / symmetry",
      "Makes the field symmetric by copying one half or quarter over the rest.",
      {C("mode",
         "Mode",
         {"x", "z", "xz", "rot2", "rot4", "diag", "adiag"},
         {"Mirror across x",
          "Mirror across z",
          "Four-fold mirror",
          "Two-fold rotation",
          "Four-fold rotation",
          "Diagonal",
          "Anti-diagonal"},
         "x"),
       N("side", "Source side (0 or 1)", 0, 1, 1, "%.0f", 0)}
    );
    c.Add(
      "range",
      "To height range",
      "shape",
      "Maps 0..1 to a range of heights in world units (a fixed rule, not the min / max of the field).",
      {Pin("a")},
      kHeightOut,
      {N("lo", "Value at 0", -200, 600, 0.5f, "%.1f", 20, true),
       N("hi", "Value at 1", -200, 600, 0.5f, "%.1f", 70, true)},
      [](const Env& E, const Values& v, const Inputs& ins) {
      return One(E.Op("affine", {{"a", In(ins, "a")}, {"mul", v.N("hi") - v.N("lo")}, {"add", v.N("lo")}}));
    }
    );
    {
      ParamDef curve = T("points", "Curve (x y pairs)", "0 0 0.5 0.5 1 1");
      c.Add(
        "remap",
        "Curve (remap)",
        "shape",
        "Maps 0..1 through a curve (monotone, like the Photoshop curves dialog).",
        {Pin("a")},
        kHeightOut,
        {curve, B("smooth", "Smooth curve", true)},
        [](const Env& E, const Values& v, const Inputs& ins) {
        return One(
          E.Op("remap", {{"a", In(ins, "a")}, {"points", NumberList(v.S("points"))}, {"smooth", v.B("smooth") ? 1 : 0}})
        );
      }
      );
    }
    c.Add(
      "warp",
      "Warp",
      "shape",
      "Bends the field by noise (or by two fields linked in).",
      {Pin("a"), Pin("dx"), Pin("dz")},
      kHeightOut,
      {N("strength", "Strength (units)", 0, 400, 1, "%.0f", 30, true),
       N("size", "Noise size (units)", 5, 600, 5, "%.0f", 80),
       Seed()},
      [](const Env& E, const Values& v, const Inputs& ins) {
      field::GridPtr dx = In(ins, "dx");
      field::GridPtr dz = In(ins, "dz");
      const int seed = E.Seed(v.N("seed"));
      if (dx == nullptr) {
        dx = E.Op("perlin", {{"like", E.like}, {"seed", seed}, {"scale", v.N("size")}, {"octaves", 3}});
      }
      if (dz == nullptr) {
        dz = E.Op("perlin", {{"like", E.like}, {"seed", seed + 1}, {"scale", v.N("size")}, {"octaves", 3}});
      }
      return One(E.Op("warp", {{"a", In(ins, "a")}, {"dx", dx}, {"dz", dz}, {"strength", v.N("strength")}}));
    }
    );
    c.Add(
      "height_from_gradient",
      "Height from slopes",
      "shape",
      "Builds the height that has the slopes linked in (x slope in dx, z slope in dz): the Poisson solve.",
      {Pin("dx"), Pin("dz")},
      kHeightOut,
      {B("periodic", "Periodic (tiling)", false)},
      [](const Env& E, const Values& v, const Inputs& ins) {
      return One(E.Op(
        "height_from_gradient", {{"dx", In(ins, "dx")}, {"dz", In(ins, "dz")}, {"periodic", v.B("periodic") ? 1 : 0}}
      ));
    }
    );
    c.Add(
      "img_orient",
      "Turn / flip image",
      "shape",
      "Swaps x and z and / or flips an axis: the eight orientations of a square image.",
      {Pin("a")},
      kHeightOut,
      {B("transpose", "Swap x and z", false), B("flip_x", "Flip x", false), B("flip_z", "Flip z", false)},
      [](const Env& E, const Values& v, const Inputs& ins) {
      return One(E.Op(
        "img_orient",
        {{"a", In(ins, "a")},
         {"transpose", v.B("transpose") ? 1 : 0},
         {"flip_x", v.B("flip_x") ? 1 : 0},
         {"flip_z", v.B("flip_z") ? 1 : 0}}
      ));
    }
    );
    c.Add(
      "flatten",
      "Flatten gentle ground",
      "shape",
      "Smooths the ground where it is gentle and keeps what is steep: flat, open, buildable ground with crisp ridges, "
      "banks and cliffs. mask is the flattened area.",
      {Pin("a")},
      {Pin("out"), Pin("mask", PinType::Mask)},
      {N("below", "Ground gentler than (degrees)", 2, 40, 1, "%.0f", 12, true),
       N("soft", "Transition (degrees)", 1, 20, 1, "%.0f", 6),
       N("measure", "Slope measured over (units)", 2, 60, 1, "%.0f", 12),
       N("radius", "Smoothing distance (units)", 4, 200, 1, "%.0f", 40),
       N("edge", "Softness of the edges (units)", 0, 80, 1, "%.0f", 20),
       N("strength", "Strength", 0, 1, 0.05f, "%.2f", 0.9f, true)},
      [](const Env& E, const Values& v, const Inputs& ins) {
      const field::GridPtr h = In(ins, "a");
      const field::GridPtr seen = E.Op("blur", {{"a", h}, {"radius", E.Units(v.N("measure"))}});
      const field::GridPtr slope = E.Op("slope", {{"a", seen}, {"mode", "degrees"}, {"radius", 1}});
      const double lo = std::max(0.0, v.N("below") - v.N("soft") * 0.5);
      const field::GridPtr steep = E.Op("smoothstep", {{"a", slope}, {"edge0", lo}, {"edge1", lo + v.N("soft")}});
      field::GridPtr flat = E.Op("invert", {{"a", steep}, {"lo", 0.0}, {"hi", 1.0}});
      if (v.N("edge") > 0.0) {
        flat = E.Op("blur", {{"a", flat}, {"radius", E.Units(v.N("edge"))}});
      }
      const field::GridPtr mask = E.Op("affine", {{"a", flat}, {"mul", v.N("strength")}, {"add", 0.0}});
      const field::GridPtr smooth = E.Op("blur", {{"a", h}, {"radius", E.Units(v.N("radius"))}});
      Outputs out;
      out["out"].grid = E.Op("blend", {{"a", h}, {"b", smooth}, {"mask", mask}, {"mode", "normal"}, {"opacity", 1.0}});
      out["mask"].grid = flat;
      return out;
    }
    );

    // ---- combine
    Binary(c, "add", "Add", "a + b (or a + a value).");
    Binary(c, "sub", "Subtract", "a - b (or a - a value).");
    Binary(c, "mul", "Multiply", "a x b (or a x a value). Multiplying by a mask limits an effect to the mask.");
    Binary(c, "min", "Minimum", "The smaller of a and b.");
    Binary(c, "max", "Maximum", "The larger of a and b.");
    c.Add(
      "blend",
      "Blend",
      "combine",
      "Mixes b over a with a blend mode, an opacity and an optional mask.",
      {Pin("a"), Pin("b"), Pin("mask", PinType::Mask)},
      kHeightOut,
      {C("mode",
         "Mode",
         {"normal", "add", "sub", "mul", "screen", "overlay", "min", "max", "diff"},
         {"Normal", "Add", "Subtract", "Multiply", "Screen", "Overlay", "Minimum", "Maximum", "Difference"},
         "normal"),
       N("opacity", "Opacity", 0, 1, 0.05f, "%.2f", 0.5f, true)},
      [](const Env& E, const Values& v, const Inputs& ins) {
      return One(E.Op(
        "blend",
        {{"a", In(ins, "a")},
         {"b", In(ins, "b")},
         {"mask", In(ins, "mask")},
         {"mode", v.S("mode")},
         {"opacity", v.N("opacity")}}
      ));
    }
    );

    // ---- erosion
    c.Add(
      "thermal",
      "Thermal erosion",
      "erosion",
      "Material slides down slopes steeper than the talus angle (rise / run).",
      {Pin("a"), Pin("mask", PinType::Mask)},
      kHeightOut,
      {N("iterations", "Iterations", 1, 400, 1, "%.0f", 30),
       N("talus", "Talus (rise / run)", 0.05f, 2, 0.05f, "%.2f", 0.6f, true),
       N("rate", "Rate", 0.05f, 1, 0.05f, "%.2f", 0.5f)},
      [](const Env& E, const Values& v, const Inputs& ins) {
      const double n = v.N("iterations");
      const double iterations = E.step > 1 ? std::max(1.0, std::floor(n / E.step + 0.5)) : n;
      return One(E.Op(
        "thermal",
        {{"a", In(ins, "a")},
         {"mask", In(ins, "mask")},
         {"iterations", iterations},
         {"talus", v.N("talus")},
         {"rate", v.N("rate")}}
      ));
    }
    );
    for (const ErosionSolver& solver : ErosionSolvers()) {
      std::vector<ParamDef> params;
      for (const ErosionParam& p : solver.params) {
        ParamDef def =
          N(p.key,
            p.label,
            static_cast<float>(p.min),
            static_cast<float>(p.max),
            static_cast<float>(p.step),
            p.format,
            static_cast<float>(p.fallback));
        def.seed = std::string(p.key) == "seed";
        def.help = p.tip != nullptr ? p.tip : "";
        params.push_back(std::move(def));
      }
      const std::string id = std::string("erode_") + solver.id;
      const ErosionSolver* const s = &solver;
      const char* const label = std::string(solver.id) == "hydraulic" ? "Hydraulic erosion"
        : std::string(solver.id) == "droplet"                         ? "Droplet erosion"
                                                                      : "Stream power (rivers)";
      c.Add(
        id.c_str(),
        label,
        "erosion",
        "The solver of the Erosion window over the field linked in: the eroded height and the wear, deposit, flow and "
        "drainage masks.",
        {Pin("a"), Pin("mask", PinType::Mask)},
        {Pin("out"),
         Pin("wear", PinType::Mask),
         Pin("deposit", PinType::Mask),
         Pin("flow", PinType::Mask),
         Pin("accum", PinType::Mask)},
        std::move(params),
        [s](const Env& E, const Values& v, const Inputs& ins) {
        ErosionValues values;
        for (const ErosionParam& p : s->params) {
          values[p.key] = v.N(p.key);
        }
        values = ErosionOpValues(*s, values, E.step);
        values["seed"] = E.Seed(v.N("seed"));
        const bool masks =
          E.wanted.count("wear") + E.wanted.count("deposit") + E.wanted.count("flow") + E.wanted.count("accum") > 0;
        if (!masks) {
          values["masks"] = 0;
        }
        std::vector<Arg> args = {{"a", In(ins, "a")}, {"mask", In(ins, "mask")}};
        for (const auto& [key, value] : values) {
          args.emplace_back(key.c_str(), value);
        }
        std::map<std::string, field::Grid> extra;
        Outputs out;
        out["out"].grid = E.Op(s->op, args, &extra);
        if (masks) {
          const auto put = [&](const char* name, const float gamma) {
            const auto found = extra.find(name);
            if (found == extra.end()) {
              return;
            }
            auto grid = std::make_shared<field::Grid>(found->second);
            if (gamma > 0.0f) {
              grid->v = ErosionNormalised(grid->v, gamma);
            }
            out[name].grid = std::move(grid);
          };
          put("wear", 0.7f);
          put("deposit", 0.7f);
          put("flow", 0.5f);
          put("accum", 0.0f);
        }
        return out;
      }
      );
    }

    // ---- analysis and masks
    c.Add(
      "slope",
      "Slope",
      "analysis",
      "Steepness of the ground: degrees, gradient (rise / run), the engine's unit footprint rating (0.75 blocks land "
      "units) or the structure variation.",
      {Pin("a")},
      kHeightOut,
      {C("mode",
         "Output",
         {"degrees", "gradient", "rating", "variation"},
         {"Degrees", "Gradient (rise / run)", "Unit footprint rating", "Structure variation"},
         "degrees"),
       N("window", "Footprint (units, rating / variation)", 1, 12, 1, "%.0f", 1)},
      [](const Env& E, const Values& v, const Inputs& ins) {
      const std::string& mode = v.S("mode");
      if (mode == "degrees" || mode == "gradient") {
        return One(E.Op("slope", {{"a", In(ins, "a")}, {"mode", mode}, {"radius", 1}}));
      }
      return One(E.Op("slope", {{"a", In(ins, "a")}, {"mode", mode}, {"window", E.Units(v.N("window"))}}));
    }
    );
    c.Add(
      "range_mask",
      "Range mask",
      "analysis",
      "A mask 1 between two values with soft edges: heights in a band, slopes in an angle range, anything.",
      {Pin("a")},
      kMaskOut,
      {N("lo", "From", -300, 900, 0.5f, "%.1f", 20, true),
       N("hi", "To", -300, 900, 0.5f, "%.1f", 40, true),
       N("soft", "Soft edge", 0, 200, 0.5f, "%.1f", 6)},
      [](const Env& E, const Values& v, const Inputs& ins) {
      return One(
        E.Op("height_band", {{"a", In(ins, "a")}, {"lo", v.N("lo")}, {"hi", v.N("hi")}, {"soft", v.N("soft")}})
      );
    }
    );
    c.Add(
      "curvature",
      "Curvature",
      "analysis",
      "Convex ground (ridges) towards 1, concave (gullies) towards 0, flat 0.5.",
      {Pin("a")},
      kMaskOut,
      {N("radius", "Radius (units)", 1, 60, 1, "%.0f", 6), N("gain", "Gain", 1, 300, 1, "%.0f", 25)},
      [](const Env& E, const Values& v, const Inputs& ins) {
      return One(E.Op("curvature", {{"a", In(ins, "a")}, {"radius", E.Units(v.N("radius"))}, {"gain", v.N("gain")}}));
    }
    );
    c.Add(
      "aspect",
      "Aspect (facing)",
      "analysis",
      "How much the ground faces a direction (0.5 across, 1 straight at it): sun-facing slopes.",
      {Pin("a")},
      kMaskOut,
      {N("azimuth", "Facing (degrees, 0 = +x, 90 = +z)", 0, 360, 5, "%.0f", 225),
       N("flat", "Level below (rise / run)", 0.005f, 1, 0.005f, "%.3f", 0.05f)},
      [](const Env& E, const Values& v, const Inputs& ins) {
      return One(
        E.Op("aspect", {{"a", In(ins, "a")}, {"azimuth", v.N("azimuth")}, {"flat", v.N("flat")}, {"radius", 1}})
      );
    }
    );
    c.Add(
      "flow",
      "Flow (drainage)",
      "analysis",
      "Where water collects: log of the drainage area, 0..1.",
      {Pin("a")},
      kMaskOut,
      {N("range", "Catchment that reads 1 (x1000 units squared)", 1, 100000, 10, "%.0f", 1000),
       C("mode", "Scale", {"log", "area", "cells"}, {"Logarithmic", "Area", "Cells"}, "log")},
      [](const Env& E, const Values& v, const Inputs& ins) {
      return One(E.Op("flow", {{"a", In(ins, "a")}, {"mode", v.S("mode")}, {"range", v.N("range") * 1000.0}}));
    }
    );
    struct WaterNode
    {
      const char* id;
      const char* label;
      const char* help;
      bool width;
      bool soft;
    };
    for (const WaterNode& w : {
           WaterNode{
             "water_above",
             "Land above water",
             "Mask of ground above the map's water surface (plus an offset).",
             false,
             true
           },
           WaterNode{
             "water_below", "Under water", "Mask of ground under the water surface (plus an offset).", false, true
           },
           WaterNode{"water_depth", "Water depth", "Depth under the water surface in units (0 on land).", false, false},
           WaterNode{"shore", "Shore band", "A band around the waterline.", true, true},
         }) {
      std::vector<ParamDef> params = {
        N("offset", "Level above the water surface (units)", -100, 300, 0.5f, "%.1f", 0, true)
      };
      if (w.width) {
        params.push_back(N("width", "Half width (units)", 0, 50, 0.5f, "%.1f", 3));
      }
      if (w.soft) {
        params.push_back(N("soft", "Soft edge (units)", 0, 50, 0.5f, "%.1f", 2));
      }
      const std::string op = w.id;
      const bool width = w.width;
      const bool soft = w.soft;
      c.Add(
        w.id,
        w.label,
        "analysis",
        w.help,
        {Pin("a")},
        op == "water_depth" ? kHeightOut : kMaskOut,
        std::move(params),
        [op, width, soft](const Env& E, const Values& v, const Inputs& ins) {
        std::vector<Arg> args = {{"a", In(ins, "a")}, {"level", E.water + v.N("offset")}};
        if (width) {
          args.emplace_back("width", v.N("width"));
        }
        if (soft) {
          args.emplace_back("soft", v.N("soft"));
        }
        return One(E.Op(op, args));
      }
      );
    }
    c.Add(
      "distance",
      "Distance field",
      "analysis",
      "Distance (units) to the nearest value above a threshold. Outside, inside or signed; the range makes it a 0..1 "
      "falloff.",
      {Pin("a")},
      kHeightOut,
      {N("threshold", "Threshold", -300, 900, 0.05f, "%.2f", 0.5f, true),
       C("mode",
         "Measure",
         {"outside", "inside", "signed"},
         {"Outside the shape", "Inside the shape", "Signed"},
         "outside"),
       N("range", "Range (units, 0 = raw distance)", 0, 2000, 1, "%.0f", 0)},
      [](const Env& E, const Values& v, const Inputs& ins) {
      return One(E.Op(
        "distance",
        {{"a", In(ins, "a")}, {"threshold", v.N("threshold")}, {"mode", v.S("mode")}, {"range", v.N("range")}}
      ));
    }
    );
    c.Add(
      "grow",
      "Grow / shrink mask",
      "analysis",
      "Grows or shrinks a mask by a distance (exact Euclidean), with a soft edge.",
      {Pin("a", PinType::Mask)},
      kMaskOut,
      {C(
         "mode", "Mode", {"grow", "shrink", "open", "close"}, {"Grow", "Shrink", "Remove specks", "Fill holes"}, "grow"
       ),
       N("distance", "Distance (units)", 0.5f, 200, 0.5f, "%.1f", 6, true),
       N("soft", "Soft edge (units)", 0, 50, 0.5f, "%.1f", 2)},
      [](const Env& E, const Values& v, const Inputs& ins) {
      const auto grow = [&](const field::GridPtr& m, const double d, const double soft) {
        const field::GridPtr dist = E.Op("distance", {{"a", m}, {"threshold", 0.5}, {"mode", "outside"}});
        return E.Op("max", {{"a", m}, {"b", E.Op("water_below", {{"a", dist}, {"level", d}, {"soft", soft}})}});
      };
      const auto shrink = [&](const field::GridPtr& m, const double d, const double soft) {
        const field::GridPtr dist = E.Op("distance", {{"a", m}, {"threshold", 0.5}, {"mode", "inside"}});
        return E.Op("min", {{"a", m}, {"b", E.Op("water_above", {{"a", dist}, {"level", d}, {"soft", soft}})}});
      };
      const field::GridPtr m = In(ins, "a");
      const double d = v.N("distance");
      const std::string& mode = v.S("mode");
      if (mode == "grow") {
        return One(grow(m, d, v.N("soft")));
      }
      if (mode == "shrink") {
        return One(shrink(m, d, v.N("soft")));
      }
      if (mode == "open") {
        return One(grow(shrink(m, d, 0.0), d, 0.0));
      }
      return One(shrink(grow(m, d, 0.0), d, 0.0));
    }
    );
    c.Add(
      "unit_slope",
      "Pathable ground",
      "analysis",
      "The engine's own slope rule for a unit class: ground it can cross (or the blocked ground).",
      {Pin("a")},
      kMaskOut,
      {C("class",
         "Unit class",
         {"1", "2", "3", "4", "5"},
         {"Land, small (1x1)",
          "Land, medium (2x2)",
          "Land, large (3x3)",
          "Experimental (5x5)",
          "Structure (ground variation)"},
         "1"),
       C("which", "Mask", {"passable", "blocked"}, {"Passable ground", "Blocked ground"}, "passable"),
       N("soft", "Soft edge", 0, 1, 0.01f, "%.2f", 0.05f)},
      [](const Env& E, const Values& v, const Inputs& ins) {
      const int index = std::clamp(std::atoi(v.S("class").c_str()), 1, 5) - 1;
      const UnitClass& cls = kClasses[index];
      const field::GridPtr r =
        E.Op("slope", {{"a", In(ins, "a")}, {"mode", cls.kind}, {"window", E.Units(cls.window)}});
      const field::GridPtr pass =
        E.Op("water_below", {{"a", r}, {"level", static_cast<double>(cls.limit)}, {"soft", v.N("soft")}});
      if (v.S("which") == "blocked") {
        return One(E.Op("invert", {{"a", pass}, {"lo", 0.0}, {"hi", 1.0}}));
      }
      return One(pass);
    }
    );
    c.Add(
      "basins",
      "Closed basins",
      "analysis",
      "Depth of closed depressions (where water would pool): a lake mask when thresholded.",
      {Pin("a")},
      kHeightOut,
      {},
      [](const Env& E, const Values&, const Inputs& ins) {
      return One(E.Op("basin_depth", {{"a", In(ins, "a")}}));
    }
    );
    c.Add(
      "slope_area",
      "Slope-area statistic",
      "analysis",
      "Slope binned by drainage area (a terrain quality statistic, mostly for tuning erosion).",
      {Pin("a")},
      kHeightOut,
      {N("bins", "Bins", 2, 16, 1, "%.0f", 10), N("first", "First bin (log2 cells)", 1, 8, 1, "%.0f", 4)},
      [](const Env& E, const Values& v, const Inputs& ins) {
      return One(E.Op("slope_area", {{"a", In(ins, "a")}, {"bins", v.N("bins")}, {"first", v.N("first")}}));
    }
    );

    // ---- numbers
    c.Add(
      "number",
      "Number",
      "numbers",
      "A single number. Link it into any parameter that has a number pin to drive several nodes from one value.",
      {},
      kNumberOut,
      {N("value", "Value", -10000, 10000, 0.01f, "%.2f", 1)},
      [](const Env&, const Values& v, const Inputs&) {
      return OneNumber(v.N("value"));
    }
    );
    c.Add(
      "water_level",
      "Water level",
      "numbers",
      "The map's water surface elevation (plus an offset), as a number.",
      {},
      kNumberOut,
      {N("offset", "Offset", -100, 100, 0.5f, "%.1f", 0)},
      [](const Env& E, const Values& v, const Inputs&) {
      return OneNumber(E.water + v.N("offset"));
    }
    );
    c.Add(
      "math",
      "Math",
      "numbers",
      "Combines two numbers (a side not linked uses its value).",
      {Pin("a", PinType::Number), Pin("b", PinType::Number)},
      kNumberOut,
      {C("op",
         "Operation",
         {"add", "sub", "mul", "div", "min", "max"},
         {"a + b", "a - b", "a x b", "a / b", "smaller", "larger"},
         "add"),
       N("va", "a (when not linked)", -10000, 10000, 0.01f, "%.2f", 0),
       N("vb", "b (when not linked)", -10000, 10000, 0.01f, "%.2f", 1)},
      [](const Env&, const Values& v, const Inputs& ins) {
      const auto number = [&](const char* pin, const char* fallback) {
        const auto found = ins.find(pin);
        return found != ins.end() && found->second != nullptr && found->second->isNumber ? found->second->number
                                                                                         : v.N(fallback);
      };
      const double a = number("a", "va");
      const double b = number("b", "vb");
      const std::string& op = v.S("op");
      const double r = op == "add" ? a + b
        : op == "sub"              ? a - b
        : op == "mul"              ? a * b
        : op == "div"              ? (b != 0.0 ? a / b : 0.0)
        : op == "min"              ? std::min(a, b)
                                   : std::max(a, b);
      return OneNumber(r);
    }
    );
    c.Add(
      "field_stat",
      "Field statistic",
      "numbers",
      "The lowest, highest and mean value and the spread of a field, as numbers.",
      {Pin("a")},
      {Pin("min", PinType::Number),
       Pin("max", PinType::Number),
       Pin("mean", PinType::Number),
       Pin("sd", PinType::Number)},
      {},
      [](const Env&, const Values&, const Inputs& ins) {
      const field::GridPtr a = In(ins, "a");
      const field::Stats s = field::Measure(*a);
      Outputs out;
      const auto put = [&](const char* name, const double value) {
        out[name].number = value;
        out[name].isNumber = true;
      };
      put("min", s.min);
      put("max", s.max);
      put("mean", s.mean);
      put("sd", s.sd);
      return out;
    }
    );

    // ---- SC terrain
    c.Add(
      "pad_flatten",
      "Base pads",
      "sc",
      "Levels flat square pads with a smooth skirt: under the start positions and resource markers of the map (the SC "
      "tools' rules), or one pad of your own. A cluster shares one height.",
      {Pin("a")},
      {Pin("out"), Pin("core", PinType::Mask), Pin("weight", PinType::Mask)},
      {C("source", "Pads from", {"markers", "one"}, {"The map's markers", "One pad (below)"}, "markers"),
       C("level",
         "Pad height",
         {"0", "1", "2"},
         {"Mean of the ground", "Lowest of the ground", "Highest of the ground"},
         "0"),
       N("strength", "Strength", 0, 1, 0.05f, "%.2f", 1, true),
       N("x", "One pad: x (share of the map)", 0, 1, 0.01f, "%.2f", 0.5f),
       N("z", "One pad: z (share of the map)", 0, 1, 0.01f, "%.2f", 0.5f),
       N("half", "One pad: half size (units)", 1, 100, 0.5f, "%.1f", 8),
       N("skirt", "One pad: skirt (units)", 0, 100, 0.5f, "%.1f", 10),
       N("grid", "Build grid (units)", 1, 8, 1, "%.0f", 1)},
      [](const Env& E, const Values& v, const Inputs& ins) {
      std::vector<double> pads;
      if (v.S("source") == "markers") {
        pads = E.ground->pads;
        if (pads.empty()) {
          Fail("the map has no start positions or resource markers");
        }
      } else {
        pads = {v.N("x") * E.W, v.N("z") * E.H, v.N("half"), v.N("skirt"), 0.0, 0.0};
      }
      std::vector<Arg> args = {
        {"a", In(ins, "a")},
        {"pads", pads},
        {"strength", v.N("strength")},
        {"level", std::atof(v.S("level").c_str())},
        {"grid", v.N("grid")},
        {"snap", 1},
        {"word", 128}
      };
      Outputs out;
      out["out"].grid = E.Op("pad_flatten", args);
      for (const char* name : {"core", "weight"}) {
        if (E.wanted.count(name) != 0) {
          std::vector<Arg> more = args;
          more.emplace_back("output", name);
          out[name].grid = E.Op("pad_flatten", more);
        }
      }
      return out;
    }
    );
    c.Add(
      "symmetrize",
      "Symmetrize",
      "sc",
      "Copies a master part of the map over the rest by a symmetry group (mirrors, diagonals, 2 / 4 / N-fold turns), "
      "with "
      "a soft seam; Average / Larger / Smaller combine all copies instead.",
      {Pin("a")},
      kHeightOut,
      {C("mode",
         "Symmetry",
         {"mirror_x", "mirror_z", "mirror_xz", "diag", "adiag", "diag_both", "rot2", "rot4", "rotn"},
         {"Mirror x",
          "Mirror z",
          "Mirror x and z",
          "Diagonal",
          "Anti-diagonal",
          "Both diagonals",
          "Turn by 180",
          "Turn by 90",
          "N-fold turn"},
         "mirror_x"),
       N("side", "Master part (0 to parts - 1)", 0, 11, 1, "%.0f", 0),
       N("n", "Turns (N-fold)", 2, 12, 1, "%.0f", 3),
       N("angle", "Start angle (turns, degrees)", 0, 360, 1, "%.0f", 0),
       B("centred", "Own centre (otherwise the middle of the map)", false),
       N("cx", "Centre x (share)", 0, 1, 0.01f, "%.2f", 0.5f),
       N("cz", "Centre z (share)", 0, 1, 0.01f, "%.2f", 0.5f),
       C("combine",
         "Where images meet",
         {"copy", "avg", "max", "min"},
         {"Copy the master", "Average", "Larger", "Smaller"},
         "copy"),
       N("seam", "Soft seam (units)", 0, 200, 1, "%.0f", 24),
       B("nearest", "Nearest sample (codes, no blending)", false)},
      [](const Env& E, const Values& v, const Inputs& ins) {
      const std::string& mode = v.S("mode");
      const int count = mode == "mirror_xz" || mode == "diag_both" || mode == "rot4" ? 4
        : mode == "rot2" || mode == "mirror_x" || mode == "mirror_z" || mode == "diag" || mode == "adiag"
        ? 2
        : std::clamp(static_cast<int>(std::floor(v.N("n") + 0.5)), 2, 12);
      const int side = std::clamp(static_cast<int>(std::floor(v.N("side") + 0.5)), 0, count - 1);
      std::vector<Arg> args = {
        {"a", In(ins, "a")},
        {"mode", mode},
        {"side", side},
        {"sector", side},
        {"n", v.N("n")},
        {"angle", v.N("angle")},
        {"combine", v.S("combine")},
        {"seam", v.N("seam")},
        {"nearest", v.B("nearest") ? 1 : 0}
      };
      if (v.B("centred")) {
        args.emplace_back("cx", v.N("cx") * E.W);
        args.emplace_back("cz", v.N("cz") * E.H);
      }
      return One(E.Op("symmetrize", args));
    }
    );
    c.Add(
      "slope_limit",
      "Slope limit (pathable)",
      "sc",
      "Makes every neighbouring pair of samples differ by at most the limit (the engine's 0.75 rule: pathable for "
      "every unit class).",
      {Pin("a"), Pin("mask", PinType::Mask)},
      kHeightOut,
      {N("limit", "Steepest allowed (rise / run)", 0.05f, 3, 0.05f, "%.2f", 0.75f, true),
       C("mode", "Fix by", {"lower", "raise", "both"}, {"Cutting peaks", "Filling valleys", "Both (balanced)"}, "both"),
       N("balance", "Balance (0 raise .. 1 lower)", 0, 1, 0.05f, "%.2f", 0.5f),
       N("margin", "Safety margin", 0, 0.5f, 0.01f, "%.2f", 0.02f),
       N("strength", "Strength", 0, 1, 0.05f, "%.2f", 1, true)},
      [](const Env& E, const Values& v, const Inputs& ins) {
      return One(E.Op(
        "slope_limit",
        {{"a", In(ins, "a")},
         {"mask", In(ins, "mask")},
         {"limit", v.N("limit")},
         {"mode", v.S("mode")},
         {"balance", v.N("balance")},
         {"margin", v.N("margin")},
         {"strength", v.N("strength")}}
      ));
    }
    );
    c.Add(
      "reach",
      "Travel distance",
      "sc",
      "Walking distance (units) over the passable ground from a source point; ground that can't be reached gets the "
      "unreachable value.",
      {Pin("a", PinType::Mask), Pin("b")},
      kHeightOut,
      {N("x", "Source x (share of the map)", 0, 1, 0.01f, "%.2f", 0.1f),
       N("z", "Source z (share of the map)", 0, 1, 0.01f, "%.2f", 0.1f),
       N("snap", "Move the source to passable ground within (samples)", 0, 32, 1, "%.0f", 4),
       N("unreach", "Value where it can't be reached", -100, 100000, 1, "%.0f", -1)},
      [](const Env& E, const Values& v, const Inputs& ins) {
      return One(E.Op(
        "reach",
        {{"a", In(ins, "a")},
         {"b", In(ins, "b")},
         {"src", std::vector<double>{v.N("x") * E.W, v.N("z") * E.H}},
         {"snap", v.N("snap")},
         {"unreach", v.N("unreach")}}
      ));
    }
    );
    c.Add(
      "regions",
      "Connected regions",
      "sc",
      "Labels the connected areas of a passable mask (1..N), or gives every area its size in square units.",
      {Pin("a", PinType::Mask)},
      kHeightOut,
      {C("mode", "Output", {"label", "size"}, {"Region number", "Area of the region"}, "label"),
       C("connectivity", "Neighbours", {"8", "4"}, {"8 (no corner cutting)", "4"}, "8")},
      [](const Env& E, const Values& v, const Inputs& ins) {
      return One(E.Op(
        "regions",
        {{"a", In(ins, "a")}, {"mode", v.S("mode")}, {"connectivity", std::atof(v.S("connectivity").c_str())}}
      ));
    }
    );
    const auto index = [](const double share, const int n) {
      return std::clamp(static_cast<int>(std::floor(share * (n - 1) + 0.5)), 0, n - 1);
    };
    c.Add(
      "rect_mask",
      "Rectangle mask",
      "sc",
      "A mask that is 1 inside a rectangle (shares of the map) with soft borders.",
      {},
      kMaskOut,
      {N("x0", "Left (share)", 0, 1, 0.01f, "%.2f", 0.25f, true),
       N("z0", "Top (share)", 0, 1, 0.01f, "%.2f", 0.25f, true),
       N("x1", "Right (share)", 0, 1, 0.01f, "%.2f", 0.75f, true),
       N("z1", "Bottom (share)", 0, 1, 0.01f, "%.2f", 0.75f, true),
       N("feather", "Soft border (units)", 0, 300, 1, "%.0f", 20),
       C("curve", "Border curve", {"smooth", "linear"}, {"Smooth", "Linear"}, "smooth")},
      [index](const Env& E, const Values& v, const Inputs&) {
      const int w = E.like->w;
      const int h = E.like->h;
      return One(E.Op(
        "rect_mask",
        {{"like", E.like},
         {"x0", index(v.N("x0"), w)},
         {"z0", index(v.N("z0"), h)},
         {"x1", index(v.N("x1"), w)},
         {"z1", index(v.N("z1"), h)},
         {"feather", v.N("feather") / E.cell},
         {"curve", v.S("curve")}}
      ));
    }
    );
    c.Add(
      "points_mask",
      "Points mask (discs)",
      "sc",
      "A disc around every control point of a path (or one point of your own) with a soft edge: rings around bases, "
      "resource spots.",
      {Pin("pts", PinType::Points)},
      kMaskOut,
      {N("x", "One point: x (share of the map)", 0, 1, 0.01f, "%.2f", 0.5f),
       N("z", "One point: z (share of the map)", 0, 1, 0.01f, "%.2f", 0.5f),
       N("radius", "Radius (units)", 0.5f, 600, 0.5f, "%.1f", 30, true),
       N("value", "Value inside", 0, 1, 0.05f, "%.2f", 1),
       N("feather", "Soft edge (units)", 0, 300, 0.5f, "%.1f", 10)},
      [](const Env& E, const Values& v, const Inputs& ins) {
      std::vector<double> pts;
      const auto found = ins.find("pts");
      if (found != ins.end() && found->second != nullptr && found->second->path != nullptr) {
        for (const TerrainPath::Point& p : found->second->path->points) {
          pts.insert(pts.end(), {p.x, p.z, v.N("radius"), v.N("value")});
        }
      } else {
        pts = {v.N("x") * E.W, v.N("z") * E.H, v.N("radius"), v.N("value")};
      }
      return One(E.Op("points_mask", {{"like", E.like}, {"pts", pts}, {"feather", v.N("feather")}}));
    }
    );
    c.Add(
      "img_resample",
      "Fit image to the map",
      "sources",
      "Fits a field of any size (an imported image, a field from another tool) over the map with a proper filter; the "
      "image can cover a rectangle of the map only.",
      {Pin("a")},
      kHeightOut,
      {C("align",
         "Pixels sit",
         {"cell", "corner"},
         {"On the cells (1024 image over a 1025 map)", "On the samples (1025 image = identity)"},
         "cell"),
       C("filter",
         "Filter",
         {"bilinear", "bicubic", "lanczos", "nearest"},
         {"Bilinear", "Bicubic", "Lanczos", "Nearest"},
         "bicubic"),
       N("x0", "Covers: left (share)", 0, 1, 0.01f, "%.2f", 0),
       N("z0", "Covers: top (share)", 0, 1, 0.01f, "%.2f", 0),
       N("x1", "Covers: right (share)", 0, 1, 0.01f, "%.2f", 1),
       N("z1", "Covers: bottom (share)", 0, 1, 0.01f, "%.2f", 1),
       N("outside", "Value outside the rectangle", -300, 600, 0.5f, "%.1f", 0)},
      [index](const Env& E, const Values& v, const Inputs& ins) {
      const int w = E.like->w;
      const int h = E.like->h;
      return One(E.Op(
        "img_resample",
        {{"a", In(ins, "a")},
         {"like", E.like},
         {"x0", index(v.N("x0"), w)},
         {"z0", index(v.N("z0"), h)},
         {"x1", index(v.N("x1"), w)},
         {"z1", index(v.N("z1"), h)},
         {"align", v.S("align")},
         {"filter", v.S("filter")},
         {"outside", v.N("outside")}}
      ));
    }
    );

    // ---- the terrain generators, filters, erosion variants and analysis masks of FAF Studio's stage T7
    // (graphnodes_t7.lua): the field library's newer ops as nodes, three composed presets, the colour ramp.
    {
      const auto iters = [](const Env& E, const double n) {
        return E.step > 1 ? std::max(1.0, std::floor(n / E.step + 0.5)) : n;
      };
      // An op with several results: `out` and the named extras.
      const auto multi =
        [](const Env& E, const char* op, const std::vector<Arg>& args, std::initializer_list<const char*> names) {
        std::map<std::string, field::Grid> extra;
        Outputs out;
        out["out"].grid = E.Op(op, args, &extra);
        for (const char* name : names) {
          const auto found = extra.find(name);
          if (found != extra.end()) {
            out[name].grid = std::make_shared<field::Grid>(std::move(found->second));
          }
        }
        return out;
      };

      // -- generators
      c.Add(
        "fractal",
        "Terrain noise",
        "gen",
        "Gradient noise built to look like land: every octave in its own turned frame, an optional domain warp, "
        "rolling, "
        "rounded or sharp ridged shapes, and finer detail on steep or flat ground. 0..1.",
        {},
        kHeightOut,
        {Seed(),
         N("scale", "Feature size (units)", 8, 1000, 2, "%.0f", 160, true),
         N("octaves", "Octaves", 1, 12, 1, "%.0f", 8),
         N("finest", "Smallest detail (units)", 2, 200, 1, "%.0f", 12),
         N("persistence", "Persistence", 0.2f, 0.9f, 0.05f, "%.2f", 0.5f),
         C("kind",
           "Shape",
           {"fbm", "billow", "ridged"},
           {"Rolling (fBm)", "Rounded hills (billow)", "Sharp crests (ridged)"},
           "fbm"),
         N("sharpness", "Ridge sharpness", 1, 5, 0.1f, "%.1f", 2),
         N("warp", "Warp (units)", 0, 300, 1, "%.0f", 20),
         N("slope_detail", "Detail on slopes (- flat, + steep)", -1, 1, 0.05f, "%.2f", 0),
         N("warp_levels", "Warp passes", 1, 2, 1, "%.0f", 1),
         C("style", "Style", {"classic", "erosive"}, {"Classic", "Eroded (smooth slopes)"}, "classic"),
         N("erosion", "Erosion strength", 0, 6, 0.1f, "%.1f", 1)},
        [](const Env& E, const Values& v, const Inputs&) {
        return One(E.Op(
          "fractal",
          {{"like", E.like},
           {"seed", E.Seed(v.N("seed"))},
           {"scale", v.N("scale")},
           {"octaves", v.N("octaves")},
           {"finest", v.N("finest")},
           {"persistence", v.N("persistence")},
           {"kind", v.S("kind")},
           {"sharpness", v.N("sharpness")},
           {"warp", v.N("warp")},
           {"slope_detail", v.N("slope_detail")},
           {"style", v.S("style")},
           {"erosion", v.N("erosion")},
           {"warp_levels", v.N("warp_levels")}}
        ));
      }
      );
      c.Add(
        "musgrave",
        "Multifractal (Musgrave)",
        "gen",
        "Musgrave multifractals: ridged (sharp crests), hybrid (rough peaks over smooth valleys) and heterogeneous "
        "terrain.",
        {},
        kHeightOut,
        {Seed(),
         N("scale", "Feature size (units)", 8, 1000, 2, "%.0f", 160, true),
         N("octaves", "Octaves", 1, 12, 1, "%.0f", 7),
         N("lacunarity", "Lacunarity", 1.5f, 3.5f, 0.05f, "%.2f", 2),
         N("h", "Roughness exponent (H)", 0, 2, 0.05f, "%.2f", 1),
         N("offset", "Offset", 0.2f, 1.5f, 0.05f, "%.2f", 1),
         N("gain", "Gain", 0.5f, 4, 0.1f, "%.1f", 2),
         C("mode", "Mode", {"ridged", "hybrid", "hetero"}, {"Ridged", "Hybrid", "Heterogeneous"}, "ridged")},
        [](const Env& E, const Values& v, const Inputs&) {
        const field::GridPtr f = E.Op(
          "musgrave",
          {{"like", E.like},
           {"seed", E.Seed(v.N("seed"))},
           {"scale", v.N("scale")},
           {"octaves", v.N("octaves")},
           {"lacunarity", v.N("lacunarity")},
           {"h", v.N("h")},
           {"offset", v.N("offset")},
           {"gain", v.N("gain")},
           {"mode", v.S("mode")},
           {"rotate", 1}}
        );
        const std::string& mode = v.S("mode");
        return One(
          mode == "ridged"     ? E.Fit(f, 0.05, 0.95)
            : mode == "hybrid" ? E.Fit(f, 0.0, 0.6)
                               : E.Fit(f, 0.0, 0.9)
        );
      }
      );
      c.Add(
        "fbm_damped",
        "Eroded noise",
        "gen",
        "Fractal noise that smooths itself where it is steep: smooth valley floors, rough crests, the look of eroded "
        "land. 0..1.",
        {},
        kHeightOut,
        {Seed(),
         N("scale", "Feature size (units)", 8, 1000, 2, "%.0f", 160, true),
         N("octaves", "Octaves", 1, 12, 1, "%.0f", 8),
         N("persistence", "Persistence", 0.2f, 0.9f, 0.05f, "%.2f", 0.5f),
         N("damp", "Slope damping", 0, 8, 0.1f, "%.1f", 1.5f)},
        [](const Env& E, const Values& v, const Inputs&) {
        return One(E.Fit(
          E.Op(
            "fbm_damped",
            {{"like", E.like},
             {"seed", E.Seed(v.N("seed"))},
             {"scale", v.N("scale")},
             {"octaves", v.N("octaves")},
             {"persistence", v.N("persistence")},
             {"damp", v.N("damp")},
             {"rotate", 1}}
          ),
          0.15,
          0.82
        ));
      }
      );
      c.Add(
        "cells",
        "Cells (Voronoi variants)",
        "gen",
        "Cell noise with the usual variants: nearest distances, borders, smooth blends, a level per cell with bevelled "
        "borders "
        "(plates), tilted facets; several distance metrics; domain warp.",
        {},
        kHeightOut,
        {Seed(),
         N("scale", "Cell size (units)", 6, 800, 2, "%.0f", 90, true),
         N("jitter", "Jitter", 0, 1, 0.05f, "%.2f", 1),
         C("mode",
           "Mode",
           {"f1", "f2", "f3", "edge", "crack", "id", "smooth", "border", "plate", "facet"},
           {"Nearest distance",
            "Second distance",
            "Third distance",
            "Edges (f2 - f1)",
            "Cracks",
            "Value per cell",
            "Smooth minimum",
            "Distance to the border",
            "Plates (bevelled)",
            "Facets"},
           "plate"),
         C("metric",
           "Distance metric",
           {"euclid", "manhattan", "chebyshev", "minkowski"},
           {"Euclidean", "Manhattan", "Chebyshev", "Minkowski"},
           "euclid"),
         N("p", "Minkowski exponent", 0.3f, 8, 0.1f, "%.1f", 3),
         N("smooth", "Smooth minimum sharpness", 1, 30, 0.5f, "%.1f", 8),
         N("thickness", "Crack thickness", 0.02f, 0.5f, 0.01f, "%.2f", 0.12f),
         N("bevel", "Plate bevel (share of a cell)", 0.01f, 0.5f, 0.01f, "%.2f", 0.12f),
         N("drop", "Plate bevel depth", 0, 1, 0.05f, "%.2f", 0.4f),
         N("warp", "Domain warp (units)", 0, 300, 1, "%.0f", 0),
         N("warp_scale", "Warp feature size (units)", 8, 600, 2, "%.0f", 160)},
        [](const Env& E, const Values& v, const Inputs&) {
        return One(E.Op(
          "cells",
          {{"like", E.like},
           {"seed", E.Seed(v.N("seed"))},
           {"scale", v.N("scale")},
           {"jitter", v.N("jitter")},
           {"mode", v.S("mode")},
           {"metric", v.S("metric")},
           {"p", v.N("p")},
           {"smooth", v.N("smooth")},
           {"thickness", v.N("thickness")},
           {"bevel", v.N("bevel")},
           {"drop", v.N("drop")},
           {"warp", v.N("warp")},
           {"warp_scale", v.N("warp_scale")}}
        ));
      }
      );
      c.Add(
        "craters",
        "Craters",
        "gen",
        "A scatter of impact craters: a bowl with a raised rim. 0.5 is the ground, bowls go down, rims up.",
        {},
        kHeightOut,
        {Seed(),
         N("scale", "Spacing (units)", 20, 600, 2, "%.0f", 120, true),
         N("density", "Share of cells with a crater", 0, 1, 0.05f, "%.2f", 0.6f),
         N("rmin", "Smallest radius (share of a cell)", 0.02f, 0.5f, 0.01f, "%.2f", 0.15f),
         N("rmax", "Largest radius (share of a cell)", 0.05f, 0.5f, 0.01f, "%.2f", 0.45f),
         N("depth", "Depth", 0, 0.5f, 0.01f, "%.2f", 0.4f),
         N("rim", "Rim height (share of depth)", 0, 1, 0.05f, "%.2f", 0.25f),
         N("shape", "Bowl shape (flat floor above 1)", 0.5f, 6, 0.1f, "%.1f", 1.5f)},
        [](const Env& E, const Values& v, const Inputs&) {
        return One(E.Op(
          "craters",
          {{"like", E.like},
           {"seed", E.Seed(v.N("seed"))},
           {"scale", v.N("scale")},
           {"density", v.N("density")},
           {"rmin", v.N("rmin")},
           {"rmax", v.N("rmax")},
           {"depth", v.N("depth")},
           {"rim", v.N("rim")},
           {"shape", v.N("shape")},
           {"base", 0.5}}
        ));
      }
      );
      c.Add(
        "dunes",
        "Dunes",
        "gen",
        "Asymmetric dune ridges (a gentle windward and a steep slip face) with meandering crests and ripples. 0..1.",
        {},
        kHeightOut,
        {Seed(),
         N("wavelength", "Wavelength (units)", 8, 600, 1, "%.0f", 70, true),
         N("angle", "Wind direction (degrees)", 0, 360, 5, "%.0f", 20),
         N("asym", "Asymmetry", 0, 1.6f, 0.05f, "%.2f", 0.9f),
         N("warp", "Crest meander (units)", 0, 200, 1, "%.0f", 25),
         N("warp_size", "Meander size (units)", 10, 600, 5, "%.0f", 140),
         N("variation", "Crest height variation", 0, 1, 0.05f, "%.2f", 0.4f),
         N("ripples", "Ripples", 0, 0.6f, 0.02f, "%.2f", 0.12f)},
        [](const Env& E, const Values& v, const Inputs&) {
        return One(E.Op(
          "dunes",
          {{"like", E.like},
           {"seed", E.Seed(v.N("seed"))},
           {"wavelength", v.N("wavelength")},
           {"angle", v.N("angle")},
           {"asym", v.N("asym")},
           {"warp", v.N("warp")},
           {"warp_size", v.N("warp_size")},
           {"variation", v.N("variation")},
           {"ripples", v.N("ripples")}}
        ));
      }
      );
      c.Add(
        "cracks",
        "Cracks",
        "gen",
        "A network of cracks (1 in a crack, 0 on the plates), several finer networks, warped. Subtract it from the "
        "ground to cut fissures.",
        {},
        kMaskOut,
        {Seed(),
         N("scale", "Plate size (units)", 8, 800, 2, "%.0f", 90, true),
         N("crack_width", "Crack width (units)", 0.3f, 40, 0.1f, "%.1f", 3),
         N("levels", "Networks (finer each)", 1, 3, 1, "%.0f", 2),
         N("warp", "Warp (units)", 0, 200, 1, "%.0f", 12),
         N("jitter", "Jitter", 0, 1, 0.05f, "%.2f", 0.9f),
         C("profile", "Profile", {"v", "u", "flat"}, {"V (soft)", "U", "Flat (hard edge)"}, "v")},
        [](const Env& E, const Values& v, const Inputs&) {
        return One(E.Op(
          "cracks",
          {{"like", E.like},
           {"seed", E.Seed(v.N("seed"))},
           {"scale", v.N("scale")},
           {"crack_width", v.N("crack_width")},
           {"levels", v.N("levels")},
           {"warp", v.N("warp")},
           {"jitter", v.N("jitter")},
           {"profile", v.S("profile")}}
        ));
      }
      );
      c.Add(
        "island",
        "Island shape",
        "gen",
        "A ragged island: height dome (or a mask, or the distance from the coast) from a disc with noisy coast.",
        {},
        kHeightOut,
        {Seed(),
         N("cx", "Centre x (share of the map)", 0, 1, 0.01f, "%.2f", 0.5f),
         N("cz", "Centre z (share of the map)", 0, 1, 0.01f, "%.2f", 0.5f),
         N("radius", "Radius (units, 0 = half the map)", 0, 6000, 4, "%.0f", 0, true),
         N("aspect", "Aspect (stretch along the angle)", 0.3f, 3, 0.05f, "%.2f", 1),
         N("angle", "Angle (degrees)", 0, 180, 5, "%.0f", 0),
         N("roughness", "Coast roughness", 0, 1, 0.05f, "%.2f", 0.35f),
         N("noise_scale", "Coast feature size (units, 0 = auto)", 0, 2000, 5, "%.0f", 0),
         N("edge", "Coast softness", 0.005f, 0.5f, 0.005f, "%.3f", 0.08f),
         N("power", "Profile exponent", 0.2f, 4, 0.05f, "%.2f", 1.4f),
         C("output",
           "Output",
           {"height", "mask", "distance"},
           {"Height dome", "Land mask", "Distance from the coast"},
           "height")},
        [](const Env& E, const Values& v, const Inputs&) {
        const double radius = v.N("radius") > 0.0 ? v.N("radius") : 0.5 * std::min(E.W, E.H);
        const double noise = v.N("noise_scale") > 0.0 ? v.N("noise_scale") : radius * 0.5;
        return One(E.Op(
          "island",
          {{"like", E.like},
           {"seed", E.Seed(v.N("seed"))},
           {"cx", v.N("cx") * E.W},
           {"cz", v.N("cz") * E.H},
           {"radius", radius},
           {"noise_scale", noise},
           {"aspect", v.N("aspect")},
           {"angle", v.N("angle")},
           {"roughness", v.N("roughness")},
           {"edge", v.N("edge")},
           {"power", v.N("power")},
           {"output", v.S("output")}}
        ));
      }
      );

      // -- composed presets
      c.Add(
        "hills",
        "Hills (preset)",
        "gen",
        "Rolling hills: soft billow and fractal noise blended, gentle slopes. 0..1.",
        {},
        kHeightOut,
        {Seed(),
         N("scale", "Hill size (units)", 30, 1200, 5, "%.0f", 220, true),
         N("roundness", "Roundness", 0, 1, 0.05f, "%.2f", 0.5f),
         N("detail", "Detail", 0, 1, 0.05f, "%.2f", 0.3f)},
        [](const Env& E, const Values& v, const Inputs&) {
        const int seed = E.Seed(v.N("seed"));
        const double scale = v.N("scale");
        const field::GridPtr soft = E.Op(
          "billow",
          {{"like", E.like}, {"seed", seed}, {"scale", scale}, {"octaves", 3}, {"persistence", 0.45}, {"rotate", 1}}
        );
        const field::GridPtr base = E.Op(
          "perlin",
          {{"like", E.like},
           {"seed", seed + 1},
           {"scale", scale * 1.4},
           {"octaves", 4},
           {"persistence", 0.5},
           {"rotate", 1}}
        );
        const field::GridPtr fine = E.Op(
          "perlin",
          {{"like", E.like},
           {"seed", seed + 2},
           {"scale", scale * 0.25},
           {"octaves", 3},
           {"persistence", 0.5},
           {"rotate", 1}}
        );
        const field::GridPtr mix = E.Op(
          "blend",
          {{"a", E.Fit(base, 0.25, 0.75)},
           {"b", E.Fit(soft, 0.0, 0.5)},
           {"mode", "normal"},
           {"opacity", v.N("roundness")}}
        );
        return One(
          E.Op("blend", {{"a", mix}, {"b", E.Fit(fine, 0.25, 0.75)}, {"mode", "overlay"}, {"opacity", v.N("detail")}})
        );
      }
      );
      c.Add(
        "mountains",
        "Mountains (preset)",
        "gen",
        "Mountain ranges: ridged multifractal with a domain warp and sharpened peaks. 0..1.",
        {},
        kHeightOut,
        {Seed(),
         N("scale", "Range size (units)", 60, 1500, 5, "%.0f", 320, true),
         N("octaves", "Octaves", 3, 10, 1, "%.0f", 7),
         N("warp", "Warp (units)", 0, 300, 1, "%.0f", 60),
         N("peaks", "Sharp peaks", 0.5f, 3, 0.05f, "%.2f", 1.5f)},
        [](const Env& E, const Values& v, const Inputs&) {
        const int seed = E.Seed(v.N("seed"));
        const double scale = v.N("scale");
        field::GridPtr f = E.Fit(
          E.Op(
            "musgrave",
            {{"like", E.like},
             {"seed", seed},
             {"scale", scale},
             {"octaves", v.N("octaves")},
             {"mode", "ridged"},
             {"rotate", 1}}
          ),
          0.05,
          0.95
        );
        if (v.N("warp") > 0.0) {
          const field::GridPtr dx = E.Op(
            "perlin", {{"like", E.like}, {"seed", seed + 11}, {"scale", scale * 0.6}, {"octaves", 3}, {"rotate", 1}}
          );
          const field::GridPtr dz = E.Op(
            "perlin", {{"like", E.like}, {"seed", seed + 12}, {"scale", scale * 0.6}, {"octaves", 3}, {"rotate", 1}}
          );
          f = E.Op("warp", {{"a", f}, {"dx", dx}, {"dz", dz}, {"strength", v.N("warp")}});
        }
        return One(E.Op("gamma", {{"a", f}, {"gamma", v.N("peaks")}}));
      }
      );
      c.Add(
        "mesas",
        "Mesas and terraces (preset)",
        "gen",
        "Flat topped hills with stepped sides (a terraced fractal). 0..1.",
        {},
        kHeightOut,
        {Seed(),
         N("scale", "Mesa size (units)", 40, 1200, 5, "%.0f", 240, true),
         N("steps", "Steps", 2, 24, 1, "%.0f", 6),
         N("sharpness", "Sharpness", 0, 1, 0.05f, "%.2f", 0.75f),
         N("roughness", "Roughness", 0, 1, 0.05f, "%.2f", 0.3f)},
        [](const Env& E, const Values& v, const Inputs&) {
        const int seed = E.Seed(v.N("seed"));
        const double scale = v.N("scale");
        field::GridPtr f = E.Fit(
          E.Op(
            "perlin",
            {{"like", E.like}, {"seed", seed}, {"scale", scale}, {"octaves", 4}, {"persistence", 0.5}, {"rotate", 1}}
          ),
          0.25,
          0.75
        );
        f = E.Op(
          "terrace", {{"a", f}, {"steps", v.N("steps")}, {"sharpness", v.N("sharpness")}, {"lo", 0.0}, {"hi", 1.0}}
        );
        const field::GridPtr grit = E.Op(
          "perlin", {{"like", E.like}, {"seed", seed + 5}, {"scale", scale * 0.12}, {"octaves", 3}, {"rotate", 1}}
        );
        return One(
          E.Op("blend", {{"a", f}, {"b", E.Fit(grit, 0.25, 0.75)}, {"mode", "overlay"}, {"opacity", v.N("roughness")}})
        );
      }
      );

      // -- shape
      c.Add(
        "dwarp",
        "Domain warp",
        "shape",
        "Bends a field: by fractal noise (once or twice), a divergence free curl flow, a swirl, ripples or a pinch / "
        "bulge.",
        {Pin("a"), Pin("mask", PinType::Mask)},
        kHeightOut,
        {Seed(),
         C("kind",
           "Kind",
           {"fbm", "curl", "swirl", "ripple", "pinch"},
           {"Noise", "Curl flow", "Swirl", "Ripples", "Pinch / bulge"},
           "fbm"),
         N("strength", "Strength (units; swirl: degrees; pinch: factor)", -400, 400, 0.5f, "%.1f", 40, true),
         N("size", "Size (units; swirl, pinch: radius)", 5, 1500, 5, "%.0f", 120),
         N("octaves", "Octaves", 1, 8, 1, "%.0f", 3),
         N("iterations", "Warp of a warp (1 - 3)", 1, 3, 1, "%.0f", 1),
         N("angle", "Ripple direction (degrees)", 0, 360, 5, "%.0f", 0),
         N("wavelength", "Ripple wavelength (units)", 4, 600, 1, "%.0f", 60),
         N("cx", "Centre x (share)", 0, 1, 0.01f, "%.2f", 0.5f),
         N("cz", "Centre z (share)", 0, 1, 0.01f, "%.2f", 0.5f),
         C("edge", "Edges", {"clamp", "wrap", "mirror"}, {"Clamp", "Wrap", "Mirror"}, "clamp")},
        [](const Env& E, const Values& v, const Inputs& ins) {
        return One(E.Op(
          "dwarp",
          {{"a", In(ins, "a")},
           {"mask", In(ins, "mask")},
           {"seed", E.Seed(v.N("seed"))},
           {"kind", v.S("kind")},
           {"strength", v.N("strength")},
           {"size", v.N("size")},
           {"octaves", v.N("octaves")},
           {"iterations", v.N("iterations")},
           {"angle", v.N("angle")},
           {"wavelength", v.N("wavelength")},
           {"cx", v.N("cx") * E.W},
           {"cz", v.N("cz") * E.H},
           {"edge", v.S("edge")}}
        ));
      }
      );
      // A filter on a and an optional mask, its arguments made from the values.
      using MakeArgs = std::function<std::vector<Arg>(const Values&, const Env&)>;
      const auto shape = [&](
                           const char* id,
                           const char* label,
                           const char* help,
                           std::vector<ParamDef> params,
                           MakeArgs make,
                           const std::vector<PinDef>& outputs = kHeightOut
                         ) {
        const std::string op = id;
        c.Add(
          id,
          label,
          "shape",
          help,
          {Pin("a"), Pin("mask", PinType::Mask)},
          outputs,
          std::move(params),
          [op, make](const Env& E, const Values& v, const Inputs& ins) {
          std::vector<Arg> args = make(v, E);
          args.emplace_back("a", In(ins, "a"));
          args.emplace_back("mask", In(ins, "mask"));
          return One(E.Op(op, args));
        }
        );
      };
      shape(
        "bilateral",
        "Smooth (keep edges)",
        "Averages a window but ignores neighbours that differ by much more than the range: noise goes, cliffs and "
        "ridges stay.",
        {N("radius", "Radius (units)", 1, 40, 0.5f, "%.1f", 6),
         N("sigma_r", "Height range kept (units)", 0.1f, 60, 0.1f, "%.1f", 2, true)},
        [](const Values& v, const Env&) {
        return std::vector<Arg>{{"radius", v.N("radius")}, {"sigma_r", v.N("sigma_r")}};
      }
      );
      shape(
        "diffuse",
        "Smooth (diffusion)",
        "Perona-Malik diffusion: flat ground relaxes, steep faces (above the edge threshold) stay sharp.",
        {N("iterations", "Iterations", 1, 300, 1, "%.0f", 30),
         N("kappa", "Edge threshold (rise / run)", 0.02f, 3, 0.02f, "%.2f", 0.4f, true),
         N("rate", "Rate", 0.02f, 0.25f, 0.01f, "%.2f", 0.2f),
         C("g", "Conduction", {"lorentz", "exp"}, {"Lorentzian", "Exponential (sharper)"}, "lorentz")},
        [iters](const Values& v, const Env& E) {
        return std::vector<Arg>{
          {"iterations", iters(E, v.N("iterations"))}, {"kappa", v.N("kappa")}, {"rate", v.N("rate")}, {"g", v.S("g")}
        };
      }
      );
      shape(
        "unsharp",
        "Sharpen",
        "Unsharp mask: adds back the difference to a blurred copy.",
        {N("radius", "Radius (units)", 0.5f, 80, 0.5f, "%.1f", 4),
         N("amount", "Amount", 0, 4, 0.05f, "%.2f", 1, true),
         N("threshold", "Ignore differences below (units)", 0, 10, 0.05f, "%.2f", 0)},
        [](const Values& v, const Env&) {
        return std::vector<Arg>{{"radius", v.N("radius")}, {"amount", v.N("amount")}, {"threshold", v.N("threshold")}};
      }
      );
      shape(
        "edge",
        "Edge detect",
        "Edge strength: Sobel / Prewitt (rise per run), the Laplacian (creases) or a difference of gaussians. A mask.",
        {C("mode",
           "Method",
           {"sobel", "prewitt", "laplace", "dog"},
           {"Sobel", "Prewitt", "Laplacian", "Difference of gaussians"},
           "sobel"),
         N("gain", "Gain", 0.05f, 100, 0.05f, "%.2f", 2, true),
         N("smooth", "Smooth first (units)", 0, 40, 0.5f, "%.1f", 0),
         N("radius", "Gaussian size (units, DoG)", 0.5f, 60, 0.5f, "%.1f", 3),
         B("signed", "Signed (0.5 = flat)", false)},
        [](const Values& v, const Env&) {
        return std::vector<Arg>{
          {"mode", v.S("mode")},
          {"gain", v.N("gain")},
          {"smooth", v.N("smooth")},
          {"radius", v.N("radius")},
          {"signed", v.B("signed") ? 1 : 0}
        };
      },
        kMaskOut
      );
      shape(
        "morph",
        "Morphology",
        "Grey scale morphology with a square, disc, cross or diamond: dilate, erode, open, close, gradient, top hats.",
        {C("op",
           "Operation",
           {"dilate", "erode", "open", "close", "gradient", "tophat", "bothat"},
           {"Dilate (max)", "Erode (min)", "Open", "Close", "Gradient", "Top hat (peaks)", "Bottom hat (pits)"},
           "open"),
         N("radius", "Radius (units)", 1, 60, 0.5f, "%.1f", 6),
         C("shape", "Shape", {"square", "disc", "cross", "diamond"}, {"Square", "Disc", "Cross", "Diamond"}, "disc")},
        [](const Values& v, const Env&) {
        return std::vector<Arg>{{"op", v.S("op")}, {"radius", v.N("radius")}, {"shape", v.S("shape")}};
      }
      );
      {
        struct Kernel
        {
          const char* id;
          const char* label;
          const char* numbers;
          int normalize;
        };
        static constexpr Kernel kKernels[] = {
          {"identity", "Identity", "0 0 0 0 1 0 0 0 0", 1},
          {"sharpen", "Sharpen", "0 -1 0 -1 5 -1 0 -1 0", 1},
          {"emboss", "Emboss", "-2 -1 0 -1 1 1 0 1 2", 0},
          {"edge", "Edge (Laplacian)", "0 1 0 1 -4 1 0 1 0", 0},
          {"ridge", "Ridge detect", "-1 -1 -1 -1 8 -1 -1 -1 -1", 0},
          {"blur3", "Blur 3 x 3", "1 2 1 2 4 2 1 2 1", 1},
          {"blur5", "Blur 5 x 5", "1 4 6 4 1 4 16 24 16 4 6 24 36 24 6 4 16 24 16 4 1 4 6 4 1", 1},
          {"sobelx", "Sobel x", "-1 0 1 -2 0 2 -1 0 1", 0},
          {"custom", "Custom", "", 1},
        };
        std::vector<std::string> ids;
        std::vector<std::string> labels;
        for (const Kernel& k : kKernels) {
          ids.emplace_back(k.id);
          labels.emplace_back(k.label);
        }
        shape(
          "convolve",
          "Convolution",
          "Convolves with a 3 x 3 or 5 x 5 kernel: presets or your own numbers (rows separated by ;, values by :).",
          {C("preset", "Kernel", ids, labels, "sharpen"),
           T("kernel", "Custom kernel (a:b:c;d:e:f;g:h:i)", "0:-1:0;-1:5:-1;0:-1:0"),
           N("scale", "Multiply", -10, 10, 0.05f, "%.2f", 1),
           N("bias", "Add", -300, 600, 0.5f, "%.1f", 0)},
          [](const Values& v, const Env&) {
          std::string text = v.S("kernel");
          int normalize = 1;
          for (const Kernel& k : kKernels) {
            if (v.S("preset") == k.id && std::string(k.id) != "custom") {
              text = k.numbers;
              normalize = k.normalize;
            }
          }
          std::replace(text.begin(), text.end(), ':', ' ');
          std::replace(text.begin(), text.end(), ';', ' ');
          const std::vector<double> flat = NumberList(text);
          if (flat.size() != 9 && flat.size() != 25 && flat.size() != 49) {
            Fail("the kernel needs 9, 25 or 49 numbers");
          }
          return std::vector<Arg>{
            {"kernel", flat}, {"normalize", normalize}, {"scale", v.N("scale")}, {"bias", v.N("bias")}
          };
        }
        );
      }
      shape(
        "blur_dir",
        "Directional blur",
        "Blurs along a direction: wind-swept streaks, smeared ridges.",
        {N("angle", "Direction (degrees)", 0, 360, 5, "%.0f", 30),
         N("length", "Length (units)", 1, 300, 1, "%.0f", 30, true),
         C("shape", "Weights", {"box", "tri", "gauss"}, {"Even", "Triangle", "Gaussian"}, "tri")},
        [](const Values& v, const Env&) {
        return std::vector<Arg>{{"angle", v.N("angle")}, {"length", v.N("length")}, {"shape", v.S("shape")}};
      }
      );
      shape(
        "blur_slope",
        "Slope blur",
        "Blurs only where the ground is flat (or only where it is steep): smooth plains without softening the cliffs.",
        {N("radius", "Blur radius (units)", 0.5f, 80, 0.5f, "%.1f", 8),
         C("mode", "Blur where", {"flat", "steep"}, {"The ground is flat", "The ground is steep"}, "flat"),
         N("lo", "From slope (rise / run)", 0, 3, 0.02f, "%.2f", 0.2f),
         N("hi", "To slope (rise / run)", 0.02f, 4, 0.02f, "%.2f", 0.6f),
         N("amount", "Amount", 0, 1, 0.05f, "%.2f", 1)},
        [](const Values& v, const Env&) {
        return std::vector<Arg>{
          {"radius", v.N("radius")},
          {"mode", v.S("mode")},
          {"lo", v.N("lo")},
          {"hi", v.N("hi")},
          {"amount", v.N("amount")}
        };
      }
      );
      shape(
        "stratify",
        "Rock layers (stratify)",
        "Pushes the height onto shelves of random thickness: layered cliffs with ledges, optionally dipping and only "
        "on steep ground.",
        {Seed(),
         N("thickness", "Layer thickness (units)", 0.3f, 40, 0.1f, "%.1f", 3, true),
         N("variation", "Thickness variation", 0, 1, 0.05f, "%.2f", 0.5f),
         N("sharpness", "Sharpness", 0, 1, 0.05f, "%.2f", 0.8f),
         N("strength", "Strength", 0, 1, 0.05f, "%.2f", 1),
         N("slope_lo", "Only on slopes from (rise / run)", 0, 3, 0.02f, "%.2f", 0),
         N("slope_hi", "... full strength at", 0, 4, 0.02f, "%.2f", 0),
         N("tilt_x", "Dip along x (rise / run)", -0.5f, 0.5f, 0.005f, "%.3f", 0),
         N("tilt_z", "Dip along z (rise / run)", -0.5f, 0.5f, 0.005f, "%.3f", 0),
         N("warp", "Layer waviness (units)", 0, 40, 0.5f, "%.1f", 0),
         N("warp_size", "Waviness size (units)", 10, 600, 5, "%.0f", 120)},
        [](const Values& v, const Env& E) {
        return std::vector<Arg>{
          {"seed", E.Seed(v.N("seed"))},
          {"thickness", v.N("thickness")},
          {"variation", v.N("variation")},
          {"sharpness", v.N("sharpness")},
          {"strength", v.N("strength")},
          {"slope_lo", v.N("slope_lo")},
          {"slope_hi", v.N("slope_hi")},
          {"tilt_x", v.N("tilt_x")},
          {"tilt_z", v.N("tilt_z")},
          {"warp", v.N("warp")},
          {"warp_size", v.N("warp_size")}
        };
      }
      );

      // -- erosion variants
      c.Add(
        "thermal_map",
        "Thermal (talus map)",
        "erosion",
        "Thermal erosion with a talus angle that varies over the map (link a mask into b: 0 = the soft angle, 1 = the "
        "hard angle). "
        "Outputs the debris (scree) and the moved material as masks.",
        {Pin("a"), Pin("b", PinType::Mask), Pin("mask", PinType::Mask)},
        {Pin("out"), Pin("scree", PinType::Mask), Pin("moved", PinType::Mask)},
        {N("iterations", "Iterations", 1, 400, 1, "%.0f", 30),
         N("talus", "Talus without a map (rise / run)", 0.05f, 2, 0.05f, "%.2f", 0.6f),
         N("talus_lo", "Soft angle (b = 0)", 0.05f, 2, 0.05f, "%.2f", 0.35f),
         N("talus_hi", "Hard angle (b = 1)", 0.05f, 3, 0.05f, "%.2f", 1),
         N("rate", "Rate", 0.05f, 1, 0.05f, "%.2f", 0.5f),
         N("scree_scale", "Material that reads 1 (units)", 0.05f, 20, 0.05f, "%.2f", 1)},
        [iters, multi](const Env& E, const Values& v, const Inputs& ins) {
        return multi(
          E,
          "thermal_map",
          {{"a", In(ins, "a")},
           {"b", In(ins, "b")},
           {"mask", In(ins, "mask")},
           {"iterations", iters(E, v.N("iterations"))},
           {"talus", v.N("talus")},
           {"talus_lo", v.N("talus_lo")},
           {"talus_hi", v.N("talus_hi")},
           {"rate", v.N("rate")},
           {"scree_scale", v.N("scree_scale")}},
          {"scree", "moved"}
        );
      }
      );
      c.Add(
        "erode_rocksoil",
        "Rock and soil",
        "erosion",
        "Two layers: rock weathers into soil, the soil slides off steep ground, the rock holds steeper faces. Outputs "
        "the soil "
        "thickness and a rock exposure mask. Link a soil thickness into b to start from your own.",
        {Pin("a"), Pin("b", PinType::Mask)},
        {Pin("out"), Pin("soil"), Pin("rock", PinType::Mask), Pin("moved", PinType::Mask)},
        {N("iterations", "Iterations", 1, 400, 1, "%.0f", 60),
         N("soil", "Start soil thickness (units)", 0, 20, 0.1f, "%.1f", 0.4f),
         N("weather", "Weathering per step", 0, 0.2f, 0.002f, "%.3f", 0.01f),
         N("depth0", "Weathering slows at soil depth (units)", 0.1f, 10, 0.1f, "%.1f", 1),
         N("soil_talus", "Soil talus (rise / run)", 0.05f, 1.5f, 0.05f, "%.2f", 0.7f),
         N("rock_talus", "Rock talus (0 = rock holds)", 0, 4, 0.05f, "%.2f", 3),
         N("rock_vis", "Rock shows below soil depth (units)", 0.05f, 5, 0.05f, "%.2f", 0.4f),
         N("rate", "Rate", 0.05f, 1, 0.05f, "%.2f", 0.5f)},
        [iters, multi](const Env& E, const Values& v, const Inputs& ins) {
        return multi(
          E,
          "erode_rocksoil",
          {{"a", In(ins, "a")},
           {"b", In(ins, "b")},
           {"iterations", iters(E, v.N("iterations"))},
           {"soil", v.N("soil")},
           {"weather", v.N("weather")},
           {"depth0", v.N("depth0")},
           {"soil_talus", v.N("soil_talus")},
           {"rock_talus", v.N("rock_talus")},
           {"rock_vis", v.N("rock_vis")},
           {"rate", v.N("rate")}},
          {"soil", "rock", "moved"}
        );
      }
      );
      c.Add(
        "erode_snow",
        "Snow and slumping",
        "erosion",
        "Snow lies above the snow line (not on cliffs, optionally only where a mask allows) and slumps downhill. "
        "Outputs ground + "
        "snow, the snow depth and a cover mask for the texture.",
        {Pin("a"), Pin("mask", PinType::Mask)},
        {Pin("out"), Pin("snow"), Pin("cover", PinType::Mask), Pin("moved", PinType::Mask)},
        {N("snowline", "Snow line (height)", -100, 600, 0.5f, "%.1f", 40, true),
         N("band", "Soft band (units)", 0.5f, 120, 0.5f, "%.1f", 10),
         N("amount", "Depth (units)", 0, 30, 0.1f, "%.1f", 3),
         N("steep_lo", "Sheds from slope (rise / run)", 0.1f, 4, 0.05f, "%.2f", 0.8f),
         N("steep_hi", "... all gone at", 0.2f, 5, 0.05f, "%.2f", 1.4f),
         N("snow_talus", "Slump talus (rise / run)", 0.05f, 2, 0.05f, "%.2f", 0.9f),
         N("iterations", "Slump iterations", 0, 300, 1, "%.0f", 40),
         N("rate", "Rate", 0.05f, 1, 0.05f, "%.2f", 0.5f),
         N("cover_depth", "Depth that reads covered (units)", 0.05f, 5, 0.05f, "%.2f", 0.5f)},
        [iters, multi](const Env& E, const Values& v, const Inputs& ins) {
        return multi(
          E,
          "erode_snow",
          {{"a", In(ins, "a")},
           {"mask", In(ins, "mask")},
           {"snowline", v.N("snowline")},
           {"band", v.N("band")},
           {"amount", v.N("amount")},
           {"steep_lo", v.N("steep_lo")},
           {"steep_hi", v.N("steep_hi")},
           {"snow_talus", v.N("snow_talus")},
           {"iterations", iters(E, v.N("iterations"))},
           {"rate", v.N("rate")},
           {"cover_depth", v.N("cover_depth")}},
          {"snow", "cover", "moved"}
        );
      }
      );
      c.Add(
        "erode_wind",
        "Wind erosion",
        "erosion",
        "Wind abrades exposed windward rock into sand, carries it (slowed uphill, free in the lee) and the sand slides "
        "at its "
        "angle of repose. Outputs the sand depth and an abrasion mask.",
        {Pin("a"), Pin("b", PinType::Mask)},
        {Pin("out"), Pin("sand"), Pin("abrasion", PinType::Mask)},
        {N("azimuth", "Wind blows towards (degrees, 0 = +x, 90 = +z)", 0, 360, 5, "%.0f", 20),
         N("iterations", "Iterations", 1, 400, 1, "%.0f", 40),
         N("sand", "Start sand depth (units)", 0, 10, 0.05f, "%.2f", 0.5f),
         N("abrade", "Abrasion per step (units)", 0, 0.3f, 0.002f, "%.3f", 0.02f),
         N("speed", "Carry speed (cells per step)", 0.05f, 0.7f, 0.05f, "%.2f", 0.5f),
         N("drag", "Slowing on windward slopes", 0, 6, 0.1f, "%.1f", 1.5f),
         N("repose", "Sand angle of repose (rise / run)", 0.2f, 1.2f, 0.02f, "%.2f", 0.62f)},
        [iters, multi](const Env& E, const Values& v, const Inputs& ins) {
        return multi(
          E,
          "erode_wind",
          {{"a", In(ins, "a")},
           {"b", In(ins, "b")},
           {"azimuth", v.N("azimuth")},
           {"iterations", iters(E, v.N("iterations"))},
           {"sand", v.N("sand")},
           {"abrade", v.N("abrade")},
           {"speed", v.N("speed")},
           {"drag", v.N("drag")},
           {"repose", v.N("repose")}},
          {"sand", "abrasion"}
        );
      }
      );
      c.Add(
        "erode_glacier",
        "Glacier",
        "erosion",
        "Ice builds above the equilibrium line, flows downhill and grinds the bed where it is thick and fast: valleys "
        "turn U "
        "shaped. Outputs the ice thickness, a cover mask and the depth carved.",
        {Pin("a"), Pin("b", PinType::Mask)},
        {Pin("out"), Pin("ice"), Pin("cover", PinType::Mask), Pin("carve")},
        {N("ela", "Equilibrium line (height)", -100, 600, 0.5f, "%.1f", 40, true),
         N("iterations", "Iterations", 10, 2000, 10, "%.0f", 300),
         N("grad", "Mass balance gradient", 0.001f, 0.2f, 0.001f, "%.3f", 0.02f),
         N("acc_max", "Most accumulation per step", 0, 5, 0.05f, "%.2f", 0.5f),
         N("abl_max", "Most melt per step", 0, 5, 0.05f, "%.2f", 1),
         N("flow", "Flow coefficient", 0.001f, 0.5f, 0.001f, "%.3f", 0.02f),
         N("max_ice", "Thickest ice (units)", 5, 500, 5, "%.0f", 120),
         N("erode", "Erosion strength", 0, 0.01f, 0.0001f, "%.4f", 0.0005f),
         N("erode_pow", "Erosion exponent", 0.5f, 3, 0.05f, "%.2f", 1.5f),
         N("max_cut", "Deepest cut (units)", 0, 100, 0.5f, "%.1f", 25)},
        [iters, multi](const Env& E, const Values& v, const Inputs& ins) {
        return multi(
          E,
          "erode_glacier",
          {{"a", In(ins, "a")},
           {"b", In(ins, "b")},
           {"ela", v.N("ela")},
           {"iterations", iters(E, v.N("iterations"))},
           {"grad", v.N("grad")},
           {"acc_max", v.N("acc_max")},
           {"abl_max", v.N("abl_max")},
           {"flow", v.N("flow")},
           {"max_ice", v.N("max_ice")},
           {"erode", v.N("erode")},
           {"erode_pow", v.N("erode_pow")},
           {"max_cut", v.N("max_cut")}},
          {"ice", "cover", "carve"}
        );
      }
      );
      c.Add(
        "settle",
        "Sediment settling",
        "erosion",
        "Hollows fill with sediment where the ground is flat enough: valley floors and basins level out. Outputs a "
        "deposit mask (alluvium).",
        {Pin("a"), Pin("mask", PinType::Mask)},
        {Pin("out"), Pin("deposit", PinType::Mask)},
        {N("iterations", "Iterations", 1, 300, 1, "%.0f", 20),
         N("rate", "Rate", 0.05f, 1, 0.05f, "%.2f", 0.4f),
         N("cap", "Most per step (units)", 0.02f, 5, 0.02f, "%.2f", 0.5f),
         N("slope_lo", "Fills below slope (rise / run)", 0, 2, 0.02f, "%.2f", 0.2f),
         N("slope_hi", "... nothing above", 0.02f, 3, 0.02f, "%.2f", 0.6f),
         N("deposit_scale", "Fill that reads 1 (units)", 0.05f, 20, 0.05f, "%.2f", 1)},
        [iters, multi](const Env& E, const Values& v, const Inputs& ins) {
        return multi(
          E,
          "settle",
          {{"a", In(ins, "a")},
           {"mask", In(ins, "mask")},
           {"iterations", iters(E, v.N("iterations"))},
           {"rate", v.N("rate")},
           {"cap", v.N("cap")},
           {"slope_lo", v.N("slope_lo")},
           {"slope_hi", v.N("slope_hi")},
           {"deposit_scale", v.N("deposit_scale")}},
          {"deposit"}
        );
      }
      );

      // -- analysis masks
      const auto analysis =
        [&](const char* id, const char* label, const char* help, std::vector<ParamDef> params, MakeArgs make) {
        const std::string op = id;
        c.Add(
          id,
          label,
          "analysis",
          help,
          {Pin("a")},
          kMaskOut,
          std::move(params),
          [op, make](const Env& E, const Values& v, const Inputs& ins) {
          std::vector<Arg> args = make(v, E);
          args.emplace_back("a", In(ins, "a"));
          return One(E.Op(op, args));
        }
        );
      };
      analysis(
        "occlusion",
        "Cavity / occlusion",
        "Ambient occlusion of the surface: how closed the ground is (pits, gullies, crevices), how exposed (ridges), "
        "or both around 0.5.",
        {C("mode",
           "Mask",
           {"cavity", "convex", "both"},
           {"Cavity (concave)", "Exposure (convex)", "Both (0.5 = flat)"},
           "cavity"),
         N("radius", "Radius (units)", 2, 300, 1, "%.0f", 40, true),
         N("directions", "Directions", 4, 32, 1, "%.0f", 12),
         N("gain", "Gain", 0.1f, 10, 0.1f, "%.1f", 2, true)},
        [](const Values& v, const Env&) {
        return std::vector<Arg>{
          {"mode", v.S("mode")}, {"radius", v.N("radius")}, {"directions", v.N("directions")}, {"gain", v.N("gain")}
        };
      }
      );
      analysis(
        "hillshade",
        "Hillshade / lit sides",
        "Sun light on the terrain: the shaded relief, only the sun facing and unshadowed ground (lit), or the cast "
        "shadow.",
        {C("mode",
           "Mask",
           {"shade", "lit", "shadow"},
           {"Shaded relief", "Lit (facing the sun, not shadowed)", "Cast shadow"},
           "shade"),
         N("azimuth", "Towards the sun (degrees, 0 = +x, 90 = +z)", 0, 360, 5, "%.0f", 315),
         N("altitude", "Sun height (degrees)", 1, 89, 1, "%.0f", 40),
         N("z", "Vertical exaggeration", 0.1f, 10, 0.1f, "%.1f", 1),
         B("shadows", "Cast shadows in the shade", false),
         N("shadow_len", "Shadow length (units)", 5, 800, 5, "%.0f", 200),
         N("ambient", "Ambient light", 0, 1, 0.02f, "%.2f", 0.15f)},
        [](const Values& v, const Env&) {
        return std::vector<Arg>{
          {"mode", v.S("mode")},
          {"azimuth", v.N("azimuth")},
          {"altitude", v.N("altitude")},
          {"z", v.N("z")},
          {"shadows", v.B("shadows") ? 1 : 0},
          {"shadow_len", v.N("shadow_len")},
          {"ambient", v.N("ambient")}
        };
      }
      );
      analysis(
        "wetness",
        "Wetness (topographic)",
        "Where water gathers: the topographic wetness index from a multiple flow direction catchment and the slope.",
        {C("mode", "Result", {"wet", "twi", "area"}, {"Wetness 0..1", "Raw index", "Catchment (log)"}, "wet"),
         N("p", "Flow spreading exponent", 0.5f, 6, 0.1f, "%.1f", 1.1f),
         N("lo", "Index that reads 0", -5, 20, 0.5f, "%.1f", 3),
         N("hi", "Index that reads 1", -5, 25, 0.5f, "%.1f", 11),
         N("smooth", "Smooth (units)", 0, 40, 0.5f, "%.1f", 2)},
        [](const Values& v, const Env&) {
        return std::vector<Arg>{
          {"mode", v.S("mode")}, {"p", v.N("p")}, {"lo", v.N("lo")}, {"hi", v.N("hi")}, {"smooth", v.N("smooth")}
        };
      }
      );
      c.Add(
        "rockiness",
        "Rockiness",
        "analysis",
        "Where bare rock shows: steep ground, convex ridges and (when a soil thickness is linked into b) thin soil, "
        "with some noise breakup.",
        {Pin("a"), Pin("b")},
        kMaskOut,
        {Seed(),
         N("slope_lo", "Rock from slope (degrees)", 0, 90, 1, "%.0f", 25),
         N("slope_hi", "... all rock at", 1, 90, 1, "%.0f", 50),
         N("radius", "Convexity radius (units)", 1, 60, 1, "%.0f", 6),
         N("gain", "Convexity gain", 1, 100, 1, "%.0f", 14),
         N("w_slope", "Weight: slope", 0, 2, 0.05f, "%.2f", 1),
         N("w_convex", "Weight: convexity", 0, 2, 0.05f, "%.2f", 0.5f),
         N("w_soil", "Weight: thin soil", 0, 2, 0.05f, "%.2f", 1),
         N("soil_full", "Soil that hides the rock (units)", 0.05f, 10, 0.05f, "%.2f", 1.5f),
         N("breakup", "Noise breakup", 0, 0.6f, 0.01f, "%.2f", 0.15f)},
        [](const Env& E, const Values& v, const Inputs& ins) {
        return One(E.Op(
          "rockiness",
          {{"a", In(ins, "a")},
           {"b", In(ins, "b")},
           {"seed", E.Seed(v.N("seed"))},
           {"slope_lo", v.N("slope_lo")},
           {"slope_hi", v.N("slope_hi")},
           {"radius", v.N("radius")},
           {"gain", v.N("gain")},
           {"w_slope", v.N("w_slope")},
           {"w_convex", v.N("w_convex")},
           {"w_soil", v.N("w_soil")},
           {"soil_full", v.N("soil_full")},
           {"breakup", v.N("breakup")}}
        ));
      }
      );

      // -- numbers
      c.Add(
        "map_share",
        "Map share (units)",
        "numbers",
        "A length as a share of the map width, in units: link it into noise sizes, radii and widths so that a graph "
        "looks the "
        "same on a 256, 512 or 1024 map.",
        {},
        kNumberOut,
        {N("share", "Share of the map width", 0.002f, 2, 0.001f, "%.3f", 0.1f)},
        [](const Env& E, const Values& v, const Inputs&) {
        return OneNumber(v.N("share") * E.W);
      }
      );

      // -- colour: a gradient map into four masks (r, g, b, a) and their bundle
      c.Add(
        "color_ramp",
        "Colour ramp",
        "color",
        "A gradient map: turns a mask (or heights over lo .. hi) into colours. rgba feeds Output: colour image; red, "
        "green, blue "
        "and alpha are the channels as masks.",
        {Pin("a")},
        {Pin("rgba", PinType::Color),
         Pin("red", PinType::Mask),
         Pin("green", PinType::Mask),
         Pin("blue", PinType::Mask),
         Pin("alpha", PinType::Mask)},
        {C("ramp",
           "Ramp",
           {"terrain", "heat", "ocean", "snow", "viridis", "grey", "lush", "custom"},
           {"Terrain", "Heat", "Ocean depth", "Snow and rock", "Viridis", "Grey", "Lush ground", "Custom stops"},
           "terrain"),
         T("stops", "Custom stops (pos:#rrggbb;...)", "0:#103060;0.5:#80a060;1:#ffffff"),
         B("reverse", "Reverse", false),
         N("lo", "Input that reads 0", -300, 900, 0.5f, "%.1f", 0, true),
         N("hi", "Input that reads 1", -300, 900, 0.5f, "%.1f", 1, true),
         C("interp", "Between stops", {"linear", "smooth", "step"}, {"Linear", "Smooth", "Steps"}, "linear"),
         N("alpha", "Alpha", 0, 1, 0.05f, "%.2f", 1)},
        [](const Env& E, const Values& v, const Inputs& ins) {
        const std::vector<double> stops = RampStops(v.S("ramp"), v.S("stops"), v.B("reverse"), v.N("alpha"));
        std::map<std::string, field::Grid> extra;
        const field::GridPtr r = E.Op(
          "color_ramp",
          {{"a", In(ins, "a")}, {"stops", stops}, {"lo", v.N("lo")}, {"hi", v.N("hi")}, {"interp", v.S("interp")}},
          &extra
        );
        const auto take = [&](const char* name) -> field::GridPtr {
          const auto found = extra.find(name);
          return found != extra.end() ? std::make_shared<field::Grid>(std::move(found->second)) : r;
        };
        auto colour = std::make_shared<std::array<field::GridPtr, 4>>(
          std::array<field::GridPtr, 4>{r, take("g"), take("b"), take("a")}
        );
        Outputs out;
        out["rgba"].color = colour;
        out["red"].grid = (*colour)[0];
        out["green"].grid = (*colour)[1];
        out["blue"].grid = (*colour)[2];
        out["alpha"].grid = (*colour)[3];
        return out;
      }
      );
    }

    // ---- outputs (their inputs are what a build writes; FinalHeight folds the height outputs in)
    c.Add(
      "out_height",
      "Output: heights",
      "outputs",
      "Writes the field into the map heights (world units). Replace, add to the ground or blend with a strength and an "
      "optional mask.",
      {Pin("a"), Pin("mask", PinType::Mask)},
      {},
      {C("mode",
         "Mode",
         {"replace", "add", "blend"},
         {"Replace the heights", "Add to the heights", "Blend with the heights"},
         "replace"),
       N("strength", "Strength", 0, 1, 0.05f, "%.2f", 1, true),
       N("gain", "Gain (add mode)", -4, 4, 0.05f, "%.2f", 1)},
      [](const Env&, const Values&, const Inputs&) {
      return Outputs{};
    },
      "height"
    );

    // ---- texturing by the map's shader (FAF Studio's graphnodes_kinds.lua) and the mask generator's presets
    {
      // The shader's facts as numbers.
      c.Add(
        "terrain_shader",
        "Terrain shader",
        "sources",
        "The terrain shader of the map as numbers, so a graph can adapt to it: how many layers it paints (4, 7 or 8), "
        "whether "
        "it is a PBR shader, whether it splats by height (2xx), whether it draws layers 3 and 4 from the side only "
        "(the B "
        "shaders), and which map-wide pictures it reads.",
        {},
        {Pin("layers", PinType::Number),
         Pin("pbr", PinType::Number),
         Pin("splat", PinType::Number),
         Pin("biplanar", PinType::Number),
         Pin("macro", PinType::Number),
         Pin("specular", PinType::Number),
         Pin("roughness", PinType::Number)},
        {},
        [](const Env& E, const Values&, const Inputs&) {
        const TerrainGround& g = *E.ground;
        Outputs out;
        const auto put = [&](const char* name, const double value) {
          out[name].number = value;
          out[name].isNumber = true;
        };
        put("layers", g.painted);
        put("pbr", g.pbr ? 1.0 : 0.0);
        put("splat", g.splat ? 1.0 : 0.0);
        put("biplanar", g.biplanar ? 1.0 : 0.0);
        put("macro", g.macro ? 1.0 : 0.0);
        put("specular", g.specular ? 1.0 : 0.0);
        put("roughness", g.roughness ? 1.0 : 0.0);
        return out;
      }
      );

      // The eight kinds as masks, from the stratum recipe for this map's layers and shader.
      std::vector<PinDef> kindInputs = {
        Pin("a"), Pin("wear", PinType::Mask), Pin("deposit", PinType::Mask), Pin("flow", PinType::Mask)
      };
      std::vector<PinDef> kindOutputs;
      for (const TerrainKind& k : TerrainKinds()) {
        kindOutputs.push_back(Pin(k.id, PinType::Mask));
      }
      for (const TerrainKindVariant& vr : TerrainKindVariants()) {
        kindOutputs.push_back(Pin(vr.id, PinType::Mask));
      }
      std::vector<std::string> styleIds;
      std::vector<std::string> styleNames;
      for (const RecipeStyle& s : RecipeStyles()) {
        styleIds.emplace_back(s.id);
        styleNames.emplace_back(s.name);
      }
      std::vector<ParamDef> kindParams = {
        C("style", "Style", styleIds, styleNames, styleIds.front().c_str()),
        N("erosion", "Erosion masks decide (when linked)", 0, 1, 0.05f, "%.2f", 0.7f)
      };
      const RecipeKnobs defaults;
      for (std::size_t i = 0; i < RecipeKnobList().size(); ++i) {
        const RecipeKnobInfo& info = RecipeKnobList()[i];
        kindParams.push_back(
          N(RecipeKnobKeys()[i], info.label, info.min, info.max, 0.0f, info.format, defaults.*info.member)
        );
      }
      c.Add(
        "ground_kinds",
        "Ground kinds",
        "analysis",
        "Where each of the eight kinds of ground belongs on these heights: the stratum recipe as masks. It follows the "
        "map: "
        "the kinds that have a layer, the base layer, and the shader (a kind on layer 3 or 4 of a B shader gets steep "
        "ground "
        "only). Kinds the map has no layer for come out empty. A slider left at its default takes the value of the "
        "style.",
        kindInputs,
        kindOutputs,
        kindParams,
        [](const Env& E, const Values& v, const Inputs& ins) {
        const field::GridPtr a = In(ins, "a");
        const TerrainGround& g = *E.ground;
        int style = 0;
        for (std::size_t s = 0; s < RecipeStyles().size(); ++s) {
          if (v.S("style") == RecipeStyles()[s].id) {
            style = static_cast<int>(s);
          }
        }
        RecipeKnobs knobs = RecipeKnobsOf(style);
        const RecipeKnobs defaults;
        for (std::size_t i = 0; i < RecipeKnobList().size(); ++i) {
          const RecipeKnobInfo& info = RecipeKnobList()[i];
          const double value = v.N(RecipeKnobKeys()[i]);
          if (std::fabs(value - static_cast<double>(defaults.*info.member)) > 1e-6) {
            knobs.*info.member = static_cast<float>(value);
          }
        }
        MaskGenContext context;
        context.heights = std::make_shared<field::Grid>(*a);
        context.water = E.water;
        const RecipeStats stats = RecipeStatsOf(a->v, E.water, g.waterOn);
        std::vector<RecipeRole> roles;
        std::array<std::vector<float>, 9> selection;
        std::map<std::pair<int, int>, std::vector<float>> variants;
        std::string error;
        if (
          !RecipeRoles(context, g.plan, stats, knobs, style, roles, error) ||
          !RecipeSelections(context, g.plan, roles, knobs, style, selection, variants, error)
        ) {
          Fail(error);
        }
        const auto grid = [&](std::vector<float> values) {
          auto out = std::make_shared<field::Grid>(*a);
          out->v = std::move(values);
          return out;
        };
        // What the erosion did decides too: wear bares rock, sediment settles as dirt, the flow is wet ground.
        if (!RecipeStyles()[static_cast<std::size_t>(style)].erosion && v.N("erosion") > 0.0) {
          const auto lift = [&](const GroundKind kind, const char* pin) {
            const field::GridPtr m = In(ins, pin);
            std::vector<float>& s = selection[static_cast<std::size_t>(kind)];
            if (m == nullptr || s.size() != m->v.size()) {
              return;
            }
            for (std::size_t k = 0; k < s.size(); ++k) {
              s[k] = std::max(s[k], std::clamp(m->v[k] * static_cast<float>(v.N("erosion")), 0.0f, 1.0f));
            }
          };
          lift(GroundKind::Rock, "wear");
          lift(GroundKind::Dirt, "deposit");
          lift(GroundKind::Wet, "flow");
        }
        Outputs out;
        for (const TerrainKind& k : TerrainKinds()) {
          std::vector<float>& s = selection[static_cast<std::size_t>(k.kind)];
          out[k.id].grid = s.size() == a->v.size() ? grid(std::move(s)) : E.Const(g.plan.base == k.kind ? 1.0 : 0.0);
        }
        for (const TerrainKindVariant& vr : TerrainKindVariants()) {
          const auto found = variants.find({static_cast<int>(vr.kind), vr.layer});
          out[vr.id].grid =
            found != variants.end() && found->second.size() == a->v.size() ? grid(found->second) : E.Const(0.0);
        }
        return out;
      }
      );

      // Roughness from the kinds: rock and sand rough, wet ground and snow shiny.
      std::vector<PinDef> roughInputs;
      for (const TerrainKind& k : TerrainKinds()) {
        roughInputs.push_back(Pin(k.id, PinType::Mask));
      }
      c.Add(
        "surface_roughness",
        "Surface roughness",
        "analysis",
        "A roughness mask (0.5 = neutral, lower = shinier, higher = rougher) from the kind masks: dry rock, dark rock "
        "and sand "
        "rough, wet ground and snow shiny; the kinds linked are laid over each other from the lowest priority up.",
        roughInputs,
        kMaskOut,
        {N("contrast", "How far the kinds differ", 0, 1, 0.05f, "%.2f", 0.8f),
         N("base", "Where no kind is linked", 0, 1, 0.05f, "%.2f", 0.5f)},
        [](const Env& E, const Values& v, const Inputs& ins) {
        field::GridPtr current = E.Const(v.N("base"));
        for (const TerrainKind& k : TerrainKinds()) {
          const field::GridPtr m = In(ins, k.id);
          if (m == nullptr) {
            continue;
          }
          const double r = 0.5 + (k.roughness - 0.5) * v.N("contrast");
          current =
            E.Op("blend", {{"a", current}, {"b", E.Const(r)}, {"mask", m}, {"mode", "normal"}, {"opacity", 1.0}});
        }
        return One(current);
      }
      );

      // A ready made mask of the mask generator from the heights linked in.
      std::vector<std::string> presetIds;
      std::vector<std::string> presetNames;
      for (const MaskPreset& p : MaskPresets()) {
        presetIds.emplace_back(p.id);
        presetNames.emplace_back(p.name);
      }
      c.Add(
        "mask_preset",
        "Mask preset",
        "analysis",
        "A ready made mask of the Mask generator (cliffs, beach, snow caps, buildable ground, ground land units cannot "
        "cross "
        "...) from the heights linked in.",
        {Pin("a")},
        kMaskOut,
        {C("preset", "Preset", presetIds, presetNames, "cliffs")},
        [](const Env& E, const Values& v, const Inputs& ins) {
        const field::GridPtr a = In(ins, "a");
        const field::Stats s = field::Measure(*a);
        MaskGenContext context;
        context.heights = std::make_shared<field::Grid>(*a);
        context.water = E.water;
        auto out = std::make_shared<field::Grid>();
        std::string error;
        if (!EvaluateMaskRules(context, MaskPresetRules(v.S("preset"), s.min, s.max), *out, error)) {
          Fail(error);
        }
        return One(out);
      }
      );

      // The outputs that paint (their inputs are what Build writes).
      std::vector<PinDef> outKindInputs;
      for (const TerrainKind& k : TerrainKinds()) {
        outKindInputs.push_back(Pin(k.id, PinType::Mask));
      }
      for (const TerrainKindVariant& vr : TerrainKindVariants()) {
        outKindInputs.push_back(Pin(vr.id, PinType::Mask));
      }
      const Eval none = [](const Env&, const Values&, const Inputs&) {
        return Outputs{};
      };
      c.Add(
        "out_kinds",
        "Output: ground kinds",
        "outputs",
        "Build paints the whole ground from the kind masks: overlaps are settled the way the recipes do (snow over "
        "high rock "
        "over dark rock over rock over wet ground over sand over dirt over grass), every kind goes to the layer that "
        "holds "
        "it whatever the shader, the base layer is what is left, side-mapped layers get steep ground only. A kind with "
        "a "
        "layer but no link is cleared from its layer. One undo step with the rest of the build.",
        outKindInputs,
        {},
        {B("types", "Set the terrain types too", true),
         B("roughness", "Roughness multiplier too (PBR shaders)", true),
         N("amount", "How much the roughness varies", 0, 1, 0.05f, "%.2f", 0.6f)},
        none,
        "kinds"
      );
      std::vector<std::string> kindIds;
      std::vector<std::string> kindNames;
      for (const TerrainKind& k : TerrainKinds()) {
        kindIds.emplace_back(k.id);
        kindNames.emplace_back(RecipeKindLabel(k.kind));
      }
      std::vector<std::string> textureIds = {"keep"};
      std::vector<std::string> textureNames = {"Keep the layer's texture"};
      textureIds.insert(textureIds.end(), kindIds.begin(), kindIds.end());
      textureNames.insert(textureNames.end(), kindNames.begin(), kindNames.end());
      c.Add(
        "out_layer",
        "Output: texture layer",
        "outputs",
        "Writes a mask into the paint mask of a texture layer (1..8). Replace, add (the larger) or subtract, with a "
        "strength.",
        {Pin("a", PinType::Mask)},
        {},
        {N("layer", "Layer", 1, 8, 1, "%.0f", 2),
         C("mode",
           "Mode",
           {"replace", "add", "subtract"},
           {"Replace", "Add to (the larger)", "Subtract from"},
           "replace"),
         N("strength", "Strength", 0, 1, 0.05f, "%.2f", 1, true),
         B("takeAway", "Layers above take away", false),
         C("texture", "Layer texture", textureIds, textureNames, "keep")},
        none,
        "layer"
      );
      c.Add(
        "out_role",
        "Output: ground kind",
        "outputs",
        "Writes a mask into the paint of the layer that holds this kind of ground (found from the textures of the "
        "map), "
        "whatever the layer order and the shader.",
        {Pin("a", PinType::Mask)},
        {},
        {C("role", "Kind of ground", kindIds, kindNames, "rock"),
         C("mode",
           "Mode",
           {"replace", "add", "subtract"},
           {"Replace", "Add to (the larger)", "Subtract from"},
           "replace"),
         N("strength", "Strength", 0, 1, 0.05f, "%.2f", 1, true),
         B("takeAway", "Layers above take away", false),
         B("texture", "Give an empty layer its texture", true)},
        none,
        "layer"
      );
      c.Add(
        "out_types",
        "Output: terrain type",
        "outputs",
        "Sets a terrain type code in the terrain-type grid where the mask is above a threshold.",
        {Pin("a", PinType::Mask)},
        {},
        {N("code", "Type code", 0, 255, 1, "%.0f", 2),
         N("threshold", "Where the mask is above", 0, 1, 0.01f, "%.2f", 0.5f, true)},
        none,
        "types"
      );
      c.Add(
        "out_scatter",
        "Output: scatter props",
        "outputs",
        "Scatters props (or decals) where the density mask allows: Poisson disc sampling with a minimum distance, "
        "seeded, "
        "symmetry aware. Runs on Build only.",
        {Pin("a", PinType::Mask)},
        {},
        {C("kind", "Scatter", {"props", "decals"}, {"Props", "Decals"}, "props"),
         T("entries", "Blueprints (weights)", ""),
         N("count", "Most to place", 1, 20000, 10, "%.0f", 800),
         N("minDist", "Minimum distance (units)", 0.5f, 80, 0.5f, "%.1f", 6),
         N("fill", "Fill (acceptance)", 0, 1, 0.05f, "%.2f", 1),
         N("slopeMax", "Steepest slope (degrees)", 0, 90, 1, "%.0f", 35),
         N("scaleMin", "Smallest scale (%)", 10, 400, 5, "%.0f", 80),
         N("scaleMax", "Largest scale (%)", 10, 400, 5, "%.0f", 120),
         N("margin", "Margin from the edge (units)", 0, 100, 1, "%.0f", 4),
         B("underWater", "Also under water", false),
         Seed()},
        none,
        "scatter"
      );
    }

    // ---- the map-wide textures (FAF Studio's graphnodes_map.lua): normals and baked lighting from heights, the map's
    // light as numbers, and the outputs that make the map-wide textures on Build
    {
      const std::vector<std::string> sizeIds = {"auto", "256", "512", "1024", "2048", "4096", "8192", "grid"};
      const std::vector<std::string> sizeNames = {
        "Map size (at most 1024)",
        "256",
        "512",
        "1024",
        "2048 (big)",
        "4096 (very big)",
        "8192 (huge)",
        "As fine as the finest input"
      };
      c.Add(
        "normal_map",
        "Height to normal map",
        "color",
        "Turns heights into a normal map the way the engine does, one normal per map square. rgba is the picture (R = "
        "x, G = z, "
        "B = y: flat ground is blue); x, y and z are the three parts as masks (0.5 = no lean).",
        {Pin("a")},
        {Pin("rgba", PinType::Color), Pin("x", PinType::Mask), Pin("y", PinType::Mask), Pin("z", PinType::Mask)},
        {N("strength", "Slope strength", 0.1f, 8, 0.1f, "%.1f", 1, true),
         N("span", "Sample distance (units)", 0.5f, 16, 0.5f, "%.1f", 1),
         B("squares", "Place on the map squares", true)},
        [](const Env& E, const Values& v, const Inputs& ins) {
        std::map<std::string, field::Grid> extra;
        const field::GridPtr x = E.Op(
          "normal_map",
          {{"a", In(ins, "a")},
           {"span", v.N("span")},
           {"strength", v.N("strength")},
           {"shift", v.B("squares") ? 0.5 : 0.0}},
          &extra
        );
        const auto take = [&](const char* name) -> field::GridPtr {
          const auto found = extra.find(name);
          return found != extra.end() ? std::make_shared<field::Grid>(std::move(found->second)) : E.Const(0.5);
        };
        const field::GridPtr y = take("y");
        const field::GridPtr z = take("z");
        Outputs out;
        out["rgba"].color =
          std::make_shared<std::array<field::GridPtr, 4>>(std::array<field::GridPtr, 4>{x, z, y, E.Const(1.0)});
        out["x"].grid = x;
        out["y"].grid = y;
        out["z"].grid = z;
        return out;
      }
      );
      c.Add(
        "env_lighting",
        "Environment lighting",
        "numbers",
        "The map's sun and ambient light (the Lighting panel) as numbers: the sun's direction in degrees (azimuth 0 = "
        "+x, 90 = "
        "+z; altitude above the horizon), the brightness multiplier and the sun, ambient and shadow fill colours.",
        {},
        {Pin("azimuth", PinType::Number),
         Pin("altitude", PinType::Number),
         Pin("multiplier", PinType::Number),
         Pin("sun_r", PinType::Number),
         Pin("sun_g", PinType::Number),
         Pin("sun_b", PinType::Number),
         Pin("ambient_r", PinType::Number),
         Pin("ambient_g", PinType::Number),
         Pin("ambient_b", PinType::Number),
         Pin("fill_r", PinType::Number),
         Pin("fill_g", PinType::Number),
         Pin("fill_b", PinType::Number)},
        {},
        [](const Env& E, const Values&, const Inputs&) {
        const TerrainGround& g = *E.ground;
        Outputs out;
        const auto put = [&](const char* name, const double value) {
          out[name].number = value;
          out[name].isNumber = true;
        };
        put("azimuth", g.sunAzimuth);
        put("altitude", g.sunAltitude);
        put("multiplier", g.lightMultiplier);
        const char* const names[3][3] = {
          {"sun_r", "sun_g", "sun_b"}, {"ambient_r", "ambient_g", "ambient_b"}, {"fill_r", "fill_g", "fill_b"}
        };
        const std::array<float, 3>* const colours[3] = {&g.sunColour, &g.ambient, &g.shadowFill};
        for (int k = 0; k < 3; ++k) {
          for (int c3 = 0; c3 < 3; ++c3) {
            put(names[k][c3], (*colours[k])[static_cast<std::size_t>(c3)]);
          }
        }
        return out;
      }
      );
      c.Add(
        "lighting_tex",
        "Lighting texture",
        "analysis",
        "Bakes the sun onto the ground. shadow: 1 where the sun shines, 0 in cast shadow, with soft edges (the sun is "
        "sampled "
        "as a disc). light: shaded relief (angle to the sun times shadow, plus ambient). ao: how open the ground is (1 "
        "= "
        "open). An optional mask limits where shadows and occlusion apply.",
        {Pin("a"), Pin("mask", PinType::Mask)},
        {Pin("shadow", PinType::Mask), Pin("light", PinType::Mask), Pin("ao", PinType::Mask)},
        {B("useMap", "Use the map's sun direction", true),
         N("azimuth", "Towards the sun (degrees, 0 = +x, 90 = +z)", 0, 360, 5, "%.0f", 315, true),
         N("altitude", "Sun height (degrees)", 1, 89, 1, "%.0f", 40, true),
         N("soft", "Softness (size of the sun, degrees)", 0, 8, 0.25f, "%.2f", 1, true),
         C("quality", "Shadow quality", {"1", "5", "9"}, {"Draft (hard edges)", "Normal", "Fine"}, "5"),
         N("reach", "Longest shadow (units)", 20, 1500, 10, "%.0f", 400),
         N("ambient", "Ambient light (light output)", 0, 1, 0.02f, "%.2f", 0.25f),
         N("ao", "Ambient occlusion strength", 0, 1, 0.05f, "%.2f", 0.5f),
         N("aoRadius", "Occlusion radius (units)", 2, 300, 1, "%.0f", 40)},
        [](const Env& E, const Values& v, const Inputs& ins) {
        const field::GridPtr a = In(ins, "a");
        double azimuth = v.N("azimuth");
        double altitude = v.N("altitude");
        if (v.B("useMap")) {
          if (ins.count("azimuth") == 0) {
            azimuth = E.ground->sunAzimuth;
          }
          if (ins.count("altitude") == 0) {
            altitude = E.ground->sunAltitude;
          }
        }
        altitude = std::clamp(altitude, 1.0, 89.0);
        const double soft = v.N("soft");
        const int quality = std::atoi(v.S("quality").c_str());
        std::vector<std::pair<double, double>> suns = {{azimuth, altitude}};
        if (quality >= 5 && soft > 0.0) {
          for (const auto& [da, dl] : {std::pair{soft, 0.0}, {-soft, 0.0}, {0.0, soft}, {0.0, -soft}}) {
            suns.emplace_back(azimuth + da, std::clamp(altitude + dl, 1.0, 89.0));
          }
        }
        if (quality >= 9 && soft > 0.0) {
          const double s = soft * 0.7;
          for (const auto& [da, dl] : {std::pair{s, s}, {s, -s}, {-s, s}, {-s, -s}}) {
            suns.emplace_back(azimuth + da, std::clamp(altitude + dl, 1.0, 89.0));
          }
        }
        // The shadow is 1 where cast: lit is 1 minus its average over the sun's disc.
        auto lit = std::make_shared<field::Grid>(*a);
        std::fill(lit->v.begin(), lit->v.end(), 0.0f);
        for (const auto& [az, alt] : suns) {
          const field::GridPtr shadow = E.Op(
            "hillshade",
            {{"a", a}, {"mode", "shadow"}, {"azimuth", az}, {"altitude", alt}, {"shadow_len", v.N("reach")}}
          );
          for (std::size_t i = 0; i < lit->v.size() && i < shadow->v.size(); ++i) {
            lit->v[i] += shadow->v[i];
          }
        }
        for (float& x : lit->v) {
          x = 1.0f - x / static_cast<float>(suns.size());
        }
        field::GridPtr litOut = lit;
        field::GridPtr ao;
        if (E.wanted.count("ao") != 0) {
          ao = v.N("ao") > 0.0
            ? E.Op(
                "affine",
                {{"a",
                  E.Op(
                    "occlusion",
                    {{"a", a}, {"mode", "cavity"}, {"radius", v.N("aoRadius")}, {"directions", 12}, {"gain", 2}}
                  )},
                 {"mul", -v.N("ao")},
                 {"add", 1.0}}
              )
            : E.Const(1.0);
        }
        if (const field::GridPtr mask = In(ins, "mask")) {
          const field::GridPtr one = E.Const(1.0);
          litOut = E.Op("blend", {{"a", one}, {"b", litOut}, {"mask", mask}, {"mode", "normal"}, {"opacity", 1.0}});
          if (ao != nullptr) {
            ao = E.Op("blend", {{"a", one}, {"b", ao}, {"mask", mask}, {"mode", "normal"}, {"opacity", 1.0}});
          }
        }
        Outputs out;
        out["shadow"].grid = litOut;
        if (E.wanted.count("light") != 0) {
          const field::GridPtr shade = E.Op(
            "hillshade",
            {{"a", a}, {"mode", "shade"}, {"azimuth", azimuth}, {"altitude", altitude}, {"ambient", v.N("ambient")}}
          );
          out["light"].grid = E.Op("mul", {{"a", shade}, {"b", litOut}});
        }
        if (ao != nullptr) {
          out["ao"].grid = ao;
        }
        return out;
      }
      );
      const Eval nothing = [](const Env&, const Values&, const Inputs&) {
        return Outputs{};
      };
      c.Add(
        "out_normalmap",
        "Output: map normal map",
        "outputs",
        "Build gives the whole map a normal map made from the built heights, where the shader reads the map-wide "
        "normal map "
        "(layer 8's normal map; Terrain000 and later). With Use it on the map off, nothing is made.",
        {Pin("normal", PinType::Color)},
        {},
        {C("size", "Texture size (pixels)", sizeIds, sizeNames, "auto"), B("assign", "Use it on the map", true)},
        nothing,
        "mapnormal"
      );
      c.Add(
        "out_macro",
        "Output: macrotexture",
        "outputs",
        "Build makes a macrotexture from the paint and gives it to the Upper layer: the colour the ground has, lighter "
        "and "
        "darker in broad patches, to break up the repetition of the layer textures (TTerrain, TTerrainXP, Terrain000 / "
        "050).",
        {},
        {},
        {C("size", "Texture size (pixels)", sizeIds, sizeNames, "auto"),
         N("scale", "Patch size (units)", 40, 600, 10, "%.0f", 180),
         N("contrast", "Lighter and darker patches", 0, 0.6f, 0.05f, "%.2f", 0.25f),
         N("cavity", "Darker cavities", 0, 1, 0.05f, "%.2f", 0.3f),
         N("opacity", "How much it covers the ground", 0.05f, 0.9f, 0.05f, "%.2f", 0.35f)},
        nothing,
        "mapmacro"
      );
      c.Add(
        "out_specular",
        "Output: specular texture",
        "outputs",
        "Build makes the specular picture of the map from the paint: wet ground, snow and the waterline shine, rock "
        "and sand do "
        "not (Terrain001 and Terrain051 read it from the Upper layer).",
        {},
        {},
        {C("size", "Texture size (pixels)", sizeIds, sizeNames, "auto"),
         N("strength", "How much wet ground and snow shine", 0, 1, 0.05f, "%.2f", 0.8f),
         N("sharpness", "Sharpness of the highlights", 0, 1.5f, 0.05f, "%.2f", 1)},
        nothing,
        "mapspecular"
      );
      c.Add(
        "out_atlas",
        "Output: roughness / height atlas",
        "outputs",
        "Build makes the roughness / height atlas of the Upper layer from the layers' textures and their kinds of "
        "ground (rock stands above grass above wet ground, so the 2xx splatting lets the right layer win); the "
        "Terrain1xx and Terrain2xx shaders read it. It holds one tile per layer, so it follows the textures and the "
        "kinds, not the masks: shape the transitions with the style or the settings, and on the 2xx shaders with the "
        "splat softness / contrast (0 leaves the map's).",
        {},
        {},
        {C("size", "Texture size (pixels)", {"512", "1024"}, {"512", "1024"}, "1024"),
         C("style",
           "Style of the blending",
           {"default", "soft", "patchy", "custom"},
           {"Default", "Soft", "Patchy", "Custom"},
           "default"),
         N("spread", "Height contrast inside a texture", 0.25f, 2.5f, 0.05f, "%.2f", 1),
         N("biasScale", "Height step between the kinds of ground", 0, 2.5f, 0.05f, "%.2f", 1),
         N("cavity", "Relief of the normal map in the heights", 0, 1, 0.05f, "%.2f", 0.35f),
         N("roughDetail", "Roughness from the detail of the texture", 0, 2, 0.05f, "%.2f", 1),
         N("splatSoft", "Splat softness of the shader (0 = leave)", 0, 2, 0.05f, "%.2f", 0),
         N("splatContrast", "Splat height contrast of the shader (0 = leave)", 0, 3, 0.05f, "%.2f", 0)},
        nothing,
        "mapatlas"
      );
      c.Add(
        "out_texalpha",
        "Output: texture alpha",
        "outputs",
        "Build gives the layer textures the alpha their shader reads (copies of the textures beside the map, the "
        "colours as they were; one undo step). TTerrain, TTerrainXP and the 0xx shaders read it as specularity "
        "(TTerrain as 1 - specularity): Generate makes it from the kind of ground (wet ground and snow shiny, rock and "
        "dirt dull) with the texture's detail, Adjust pulls the alpha the texture has towards the kind, Off puts the "
        "original textures back. The shaders whose name ends in 1 or 2 (Terrain1x1, 2x2 ..., 001, 051) lay the base "
        "texture over the map by its alpha: there the base layer gets the opacity below (0 = none).",
        {},
        {},
        {C("mode",
           "Specularity alpha",
           {"generate", "adjust", "off"},
           {"Generate from the kind of ground", "Adjust the alpha the texture has", "Off (original textures)"},
           "generate"),
         N("detail", "Detail of the texture in the alpha", 0, 0.6f, 0.05f, "%.2f", 0.35f),
         N("amount", "Adjust: pull towards the kind of ground", 0, 1, 0.05f, "%.2f", 0.6f),
         N("baseOpacity", "Base texture as macrotexture (Terrain x1 / x2)", 0, 0.9f, 0.05f, "%.2f", 0)},
        nothing,
        "texalpha"
      );
      c.Add(
        "out_roughness",
        "Output: roughness mask",
        "outputs",
        "Build writes the roughness multiplier of layer 8 for the Terrain1xx and Terrain2xx shaders (0.5 = neutral): "
        "rougher "
        "where the mask is above one half, shinier below. Without a link: the roughness of Output: ground kinds.",
        {Pin("a", PinType::Mask)},
        {},
        {N("amount", "How much the roughness varies", 0, 1, 0.05f, "%.2f", 0.6f)},
        nothing,
        "roughness"
      );
      c.Add(
        "out_maplight",
        "Output: map lighting",
        "outputs",
        "Build gives the whole map baked lighting made from the built heights and the map's sun and sea (shadow, "
        "ambient "
        "occlusion, water depth), where the shader reads it (layer 8's albedo; Terrain000 and later).",
        {Pin("shadow", PinType::Mask), Pin("ao", PinType::Mask), Pin("height")},
        {},
        {C("size", "Texture size (pixels)", sizeIds, sizeNames, "auto"), B("assign", "Use it on the map", true)},
        nothing,
        "maplight"
      );
    }

    // ---- paths (FAF Studio's path nodes): a path made from shares of the map with a seeded wobble, and the nodes that
    // make masks and distances from it or shape the heights along it
    {
      const auto pathOut = [](std::shared_ptr<TerrainPath> path) {
        Outputs out;
        out["out"].path = std::move(path);
        return out;
      };
      const std::vector<std::string> profileIds = {"ramp", "road", "v", "u", "ridge", "wall", "terrace"};
      const std::vector<std::string> profileNames = {
        "Ramp", "Road with shoulders", "V valley", "U canyon", "Ridge", "Wall", "Terrace steps"
      };
      const std::vector<std::string> modeIds = {"carve", "raise", "level", "ramp", "road", "river"};
      const std::vector<std::string> modeNames = {"Carve", "Raise", "Level", "Ramp", "Road", "River"};
      c.Add(
        "path_line",
        "Path: line",
        "paths",
        "A curved path from one point to another (shares of the map), with a seeded wobble. Feed it to Path mask or "
        "Path shape.",
        {},
        {Pin("out", PinType::Points)},
        {N("x0", "Start x", 0, 1, 0.01f, "%.2f", 0.1f),
         N("z0", "Start z", 0, 1, 0.01f, "%.2f", 0.1f),
         N("x1", "End x", 0, 1, 0.01f, "%.2f", 0.9f),
         N("z1", "End z", 0, 1, 0.01f, "%.2f", 0.9f),
         N("wobble", "Wobble (share of the length)", 0, 0.5f, 0.01f, "%.2f", 0.08f),
         N("points", "Control points", 2, 24, 1, "%.0f", 7),
         Seed(),
         N("width", "Half width (units)", 1, 100, 0.5f, "%.1f", 8, true),
         N("falloff", "Falloff (units)", 0, 100, 0.5f, "%.1f", 10),
         N("height", "Height / depth (units)", -100, 100, 0.5f, "%.1f", -3)},
        [pathOut](const Env& E, const Values& v, const Inputs&) {
        const double x0 = v.N("x0") * E.W, z0 = v.N("z0") * E.H, x1 = v.N("x1") * E.W, z1 = v.N("z1") * E.H;
        const int n = std::max(1, static_cast<int>(std::floor(v.N("points") + 0.5)) - 1);
        const double dx = x1 - x0, dz = z1 - z0;
        const double len = std::hypot(dx, dz);
        const double nx = -dz / std::max(len, 1e-6), nz = dx / std::max(len, 1e-6);
        const int seed = E.Seed(v.N("seed"));
        std::vector<std::pair<double, double>> pts;
        for (int i = 0; i <= n; ++i) {
          const double t = static_cast<double>(i) / n;
          const double amp = i > 0 && i < n ? (PathHash(seed, i) - 0.5) * 2.0 * v.N("wobble") * len : 0.0;
          pts.emplace_back(x0 + dx * t + nx * amp, z0 + dz * t + nz * amp);
        }
        return pathOut(PathFrom(pts, v, false));
      }
      );
      c.Add(
        "path_ring",
        "Path: ring",
        "paths",
        "A closed loop around a centre (shares of the map) with a seeded wobble.",
        {},
        {Pin("out", PinType::Points)},
        {N("cx", "Centre x", 0, 1, 0.01f, "%.2f", 0.5f),
         N("cz", "Centre z", 0, 1, 0.01f, "%.2f", 0.5f),
         N("radius", "Radius (share of the map)", 0.02f, 0.7f, 0.01f, "%.2f", 0.3f),
         N("wobble", "Wobble (share of the radius)", 0, 0.5f, 0.01f, "%.2f", 0.1f),
         N("points", "Control points", 4, 32, 1, "%.0f", 10),
         Seed(),
         N("width", "Half width (units)", 1, 100, 0.5f, "%.1f", 8, true),
         N("falloff", "Falloff (units)", 0, 100, 0.5f, "%.1f", 10),
         N("height", "Height / depth (units)", -100, 100, 0.5f, "%.1f", 3)},
        [pathOut](const Env& E, const Values& v, const Inputs&) {
        const int n = std::max(3, static_cast<int>(std::floor(v.N("points") + 0.5)));
        const int seed = E.Seed(v.N("seed"));
        const double r0 = v.N("radius") * std::min(E.W, E.H);
        std::vector<std::pair<double, double>> pts;
        for (int i = 0; i < n; ++i) {
          const double a = static_cast<double>(i) / n * 6.2831853;
          const double r = r0 * (1.0 + (PathHash(seed, i) - 0.5) * 2.0 * v.N("wobble"));
          pts.emplace_back(v.N("cx") * E.W + std::cos(a) * r, v.N("cz") * E.H + std::sin(a) * r);
        }
        return pathOut(PathFrom(pts, v, true));
      }
      );
      c.Add(
        "path_drawn",
        "Path: from the Paths tool",
        "paths",
        "A path drawn with the Paths tool (this editor has no Paths tool yet).",
        {},
        {Pin("out", PinType::Points)},
        {N("index", "Path number", 1, 40, 1, "%.0f", 1)},
        [](const Env&, const Values&, const Inputs&) -> Outputs {
        Fail("this editor has no Paths tool yet");
      }
      );
      c.Add(
        "path_mask",
        "Path mask",
        "paths",
        "A mask along a path: the shaping weight, the flat core, the whole reach or just the banks.",
        {Pin("pts", PinType::Points)},
        kMaskOut,
        {C("kind",
           "Mask",
           {"weight", "core", "reach", "bank"},
           {"Shaping weight (profile)", "Core (half width)", "Reach (width and falloff)", "Banks"},
           "weight"),
         N("soft", "Soft edge (units)", 0, 50, 0.5f, "%.1f", 3)},
        [](const Env& E, const Values& v, const Inputs& ins) {
        const auto path = PathIn(ins);
        const PathSamples S = SamplePath(*path);
        if (S.Count() < 1) {
          Fail("the path has no points");
        }
        std::vector<Arg> args = PathArgs(S, {}, {}, PathProfileOf(path->profile));
        args.emplace_back("like", E.like);
        args.emplace_back("kind", v.S("kind"));
        args.emplace_back("soft", v.N("soft"));
        return One(E.Op("path_mask", args));
      }
      );
      c.Add(
        "path_dist",
        "Path distance",
        "paths",
        "Distance of every point to a path (units), or the distance along it.",
        {Pin("pts", PinType::Points)},
        kHeightOut,
        {C("what",
           "Output",
           {"dist", "signed", "along", "u"},
           {"Distance", "Signed distance (left / right)", "Along the path", "Across the path (profile coordinate)"},
           "dist"),
         N("far", "Largest distance (units)", 10, 3000, 10, "%.0f", 300)},
        [](const Env& E, const Values& v, const Inputs& ins) {
        const auto path = PathIn(ins);
        const PathSamples S = SamplePath(*path);
        if (S.Count() < 1) {
          Fail("the path has no points");
        }
        std::vector<Arg> args = PathArgs(S, {}, {}, PathProfileOf(path->profile));
        args.emplace_back("like", E.like);
        const std::string& what = v.S("what");
        if (what == "along") {
          args.emplace_back("normalize", 1);
          return One(E.Op("path_along", args));
        }
        if (what == "u") {
          return One(E.Op("path_u", args));
        }
        args.emplace_back("far", v.N("far"));
        if (what == "signed") {
          args.emplace_back("signed", 1);
        }
        return One(E.Op("path_dist", args));
      }
      );
      c.Add(
        "path_shape",
        "Path shape",
        "paths",
        "Shapes the heights along a path: carve a valley, raise a ridge, level a road, ramp between heights or cut a "
        "river bed. The profile is the cross section.",
        {Pin("a"), Pin("pts", PinType::Points)},
        kHeightOut,
        {C("mode", "Mode", modeIds, modeNames, "carve"),
         C("profile", "Cross section", profileIds, profileNames, "u"),
         N("strength", "Strength", 0, 1, 0.05f, "%.2f", 1, true)},
        [](const Env& E, const Values& v, const Inputs& ins) {
        const field::GridPtr a = In(ins, "a");
        const auto path = PathIn(ins);
        const PathMode& mode = PathModeOf(v.S("mode"));
        const PathSamples S = SamplePath(*path);
        if (S.Count() < 1) {
          Fail("the path has no points");
        }
        // Target heights along the samples (target modes: the ground under each control point plus its height, a
        // river's the water less its depth, never rising), or the offsets (offset modes).
        std::vector<float> ys(S.Count(), 0.0f);
        std::vector<float> offs(S.Count(), 0.0f);
        if (std::string(mode.native) == "offset") {
          offs = S.h;
        } else {
          const int pc = static_cast<int>(path->points.size());
          std::vector<float> yc(static_cast<std::size_t>(pc));
          for (int i = 0; i < pc; ++i) {
            const TerrainPath::Point& p = path->points[static_cast<std::size_t>(i)];
            yc[static_cast<std::size_t>(i)] =
              mode.river ? E.water - p.height : field::SampleWorld(*a, p.x, p.z) + p.height;
          }
          for (std::size_t k = 0; k < S.Count(); ++k) {
            const int s0 = S.seg[k];
            const int s1 = (s0 + 1) % pc;
            ys[k] = yc[static_cast<std::size_t>(s0)] +
              (yc[static_cast<std::size_t>(s1)] - yc[static_cast<std::size_t>(s0)]) * S.t[k];
          }
          if (mode.river) {
            for (std::size_t k = 1; k < ys.size(); ++k) {
              ys[k] = std::min(ys[k], ys[k - 1]);
            }
          }
        }
        std::vector<Arg> args = PathArgs(S, ys, offs, PathProfileOf(v.S("profile")));
        args.emplace_back("a", a);
        args.emplace_back("mode", mode.native);
        args.emplace_back("clip", mode.clip);
        args.emplace_back("strength", v.N("strength"));
        return One(E.Op("path_shape", args));
      }
      );
    }

    // ---- terrain from other tools (FAF Studio's graphnodes_ext.lua) and the map layout (graphnodes_layout.lua)
    {
      c.Add(
        "external_terrain",
        "External terrain (Gaea / World Machine)",
        "sources",
        "The heightmap of the Import / Export window (its file and the mapping of its values to heights, flips, turns) "
        "as a "
        "height field at the graph's resolution. A file typed here replaces the window's. The graph runs again when "
        "the other "
        "tool writes the file.",
        {},
        kHeightOut,
        {T("file", "File (empty: the Import / Export window's)", "")},
        [](const Env& E, const Values& v, const Inputs&) {
        if (!E.ground->loadExternal) {
          Fail("no map to import onto");
        }
        auto full = std::make_shared<field::Grid>();
        std::string error;
        if (!E.ground->loadExternal(v.S("file"), *full, error)) {
          Fail(error);
        }
        return One(E.Op("resample", {{"a", field::GridPtr(full)}, {"like", E.like}}));
      }
      );
      c.Add(
        "external_mask",
        "External mask (Gaea / World Machine)",
        "sources",
        "A named mask imported from another tool (flow, wear, deposit). This editor imports no named masks yet: with "
        "Optional "
        "the output is empty, else the node fails.",
        {},
        kMaskOut,
        {T("name", "Name of the named mask", "wear"), B("optional", "Empty when there is no such mask", true)},
        [](const Env& E, const Values& v, const Inputs&) {
        if (!v.B("optional")) {
          Fail("this editor imports no named masks yet (" + v.S("name") + ")");
        }
        return One(E.Const(0.0));
      }
      );
      const auto layoutOf = [](const Env& E) -> const MapLayout& {
        if (E.ground == nullptr || E.ground->layout == nullptr) {
          Fail("no map layout: open a map and draw it in the Layout workspace");
        }
        return *E.ground->layout;
      };
      c.Add(
        "layout_height",
        "Map layout: heights",
        "sources",
        "The height field the Layout workspace makes from the layers drawn on its canvas (hills, mountains, plateaus, "
        "water, valleys, flat ground, bases), at the graph's resolution, with the layout's ground height and water "
        "level. Carry on with it like any generator: erosion, texturing, props. With Apply the editor symmetry the "
        "result is made symmetric as Generate terrain makes it. Weathering is kept for Studio's graphs but not applied "
        "yet.",
        {},
        kHeightOut,
        {N("weather", "Weathering (gullies)", 0, 1, 0.05f, "%.2f", 0), B("sym", "Apply the editor symmetry", true)},
        [layoutOf](const Env& E, const Values& v, const Inputs&) {
        const MapLayout& layout = layoutOf(E);
        LayoutBuildOptions options;
        if (v.B("sym")) {
          options.symmetry = E.ground->layoutSymmetry;
          options.turns = E.ground->layoutTurns;
          options.cx = E.W * 0.5f;
          options.cz = E.H * 0.5f;
        }
        auto out = std::make_shared<field::Grid>();
        std::string error;
        if (!BuildLayout(layout, *E.like, options, *out, nullptr, error)) {
          Fail(error);
        }
        return One(out);
      }
      );
      c.Add(
        "layout_mask",
        "Map layout: layer mask",
        "sources",
        "The mask of one layer of the layout: 1 where it is drawn, 0 where it isn't, as soft as the layer's own soft "
        "edge (Layer counts the layers of the list from 1, bottom up). A region for erosion, texturing or scatter; a "
        "Free mask layer is drawn for exactly that.",
        {},
        kMaskOut,
        {N("layer", "Layer (its number in the list)", 1, 16, 1, "%.0f", 1),
         B("soft", "Use the soft edge of the layer", true)},
        [layoutOf](const Env& E, const Values& v, const Inputs&) {
        const MapLayout& layout = layoutOf(E);
        const int index = static_cast<int>(std::lround(v.N("layer"))) - 1;
        auto out = std::make_shared<field::Grid>();
        std::string error;
        if (!LayoutLayerMask(layout, *E.like, index, v.B("soft"), *out, error)) {
          Fail(error);
        }
        return One(out);
      }
      );
      c.Add(
        "layout_bases",
        "Map layout: bases",
        "sources",
        "The bases drawn on layers of the kind Base: a mask with a disc around the centre of each blob, and the number "
        "of bases (players) as a number.",
        {},
        {Pin("out", PinType::Mask), Pin("count", PinType::Number)},
        {N("radius", "Disc radius (units)", 2, 200, 1, "%.0f", 30),
         N("edge", "Soft edge (units)", 0, 100, 1, "%.0f", 12)},
        [layoutOf](const Env& E, const Values& v, const Inputs&) {
        const std::vector<LayoutBase> bases = layoutOf(E).BaseCentres();
        std::vector<double> pts;
        for (const LayoutBase& base : bases) {
          pts.insert(pts.end(), {base.x, base.z, v.N("radius"), 1.0});
        }
        Outputs out;
        out["out"].grid = bases.empty()
          ? E.Const(0.0)
          : E.Op("points_mask", {{"like", E.like}, {"pts", pts}, {"feather", v.N("edge")}});
        out["count"].number = static_cast<double>(bases.size());
        out["count"].isNumber = true;
        return out;
      }
      );
    }

    c.Add(
      "out_colormap",
      "Output: colour image",
      "outputs",
      "Writes the colours into a DXT5 DDS file (a texture for a decal or an album cover) on Build.",
      {Pin("rgba", PinType::Color)},
      {},
      {T("path", "File (folder under the editor, .dds)", "graphs/colormap.dds"),
       N("size", "Size (pixels, square)", 32, 2048, 32, "%.0f", 512)},
      [](const Env&, const Values&, const Inputs&) {
      return Outputs{};
    },
      "colormap"
    );

    // ---- organise
    c.Add(
      "frame",
      "Frame (group)",
      "organise",
      "A labelled box behind other nodes (it has no pins and does nothing).",
      {},
      {},
      {T("title", "Title", "Group"),
       N("w", "Width (canvas units)", 160, 4000, 8, "%.0f", 480),
       N("h", "Height (canvas units)", 96, 3000, 8, "%.0f", 320),
       C("color",
         "Colour",
         {"blue", "green", "red", "grey", "yellow"},
         {"Blue", "Green", "Red", "Grey", "Yellow"},
         "blue")},
      [](const Env&, const Values&, const Inputs&) {
      return Outputs{};
    }
    );

    // ---- the field library's other ops, each as a generic node (Studio's raw_<op>): its fields linked in, its
    // parameters typed as key=value,key=value (lists as x:y;x:y).
    std::set<std::string> covered;
    for (const auto& type : registry.All()) {
      covered.insert(type->name);
    }
    for (const char* op :
         {"height_band",
          "basin_depth",
          "path_along",
          "path_dist",
          "path_mask",
          "path_shape",
          "path_u",
          "resample",
          "crop",
          "resize",
          "path_paste",
          "amplitude",
          "keep_side",
          "terrain_mix",
          "erode_hydraulic",
          "erode_droplet",
          "erode_stream"}) {
      covered.insert(op);
    }
    for (const std::string& op : field::OpNames()) {
      if (covered.count(op) != 0) {
        continue;
      }
      c.Add(
        ("raw_" + op).c_str(),
        (op + " (field op)").c_str(),
        "raw",
        "A field op without a node of its own: link the fields it reads (a, b, mask, dx, dz) and type its parameters "
        "as key=value,key=value (lists as x:y;x:y).",
        {Pin("a"), Pin("b"), Pin("mask", PinType::Mask), Pin("dx"), Pin("dz")},
        kHeightOut,
        {T("args", "Parameters (key=value,key=value)", "")},
        [op](const Env& E, const Values& v, const Inputs& ins) {
        std::vector<Arg> args;
        const std::string& text = v.S("args");
        std::size_t at = 0;
        while (at < text.size()) {
          const std::size_t comma = std::min(text.find(',', at), text.size());
          const std::string pair = text.substr(at, comma - at);
          at = comma + 1;
          const std::size_t eq = pair.find('=');
          if (eq == std::string::npos) {
            continue;
          }
          std::string key = pair.substr(0, eq);
          key.erase(0, key.find_first_not_of(' '));
          const std::string value = pair.substr(eq + 1);
          if (value.find_first_of(":;") != std::string::npos) {
            std::string spaced = value;
            std::replace(spaced.begin(), spaced.end(), ':', ' ');
            std::replace(spaced.begin(), spaced.end(), ';', ' ');
            args.emplace_back(key.c_str(), NumberList(spaced));
          } else {
            char* end = nullptr;
            const double number = std::strtod(value.c_str(), &end);
            if (end != value.c_str() && *end == '\0') {
              args.emplace_back(key.c_str(), number);
            } else {
              args.emplace_back(key.c_str(), value);
            }
          }
        }
        for (const char* pin : {"a", "b", "mask", "dx", "dz"}) {
          args.emplace_back(pin, In(ins, pin));
        }
        if (In(ins, "a") == nullptr) {
          args.emplace_back("like", E.like);
        }
        return One(E.Op(op, args));
      }
      );
    }
  }
} // namespace faf::editor::terrain
