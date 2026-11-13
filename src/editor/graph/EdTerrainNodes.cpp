// The terrain graph's node types (FAF Studio's graphnodes.lua and graphnodes_land.lua): their pins, their parameters
// (the inspector's sliders) and their evaluations over the field library's ops. A number parameter marked `wire` also
// has an input pin of its name that overrides it.

#include "editor/graph/EdTerrainEval.h"
#include "editor/tools/EdErosionSuite.h"

#include <algorithm>
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
