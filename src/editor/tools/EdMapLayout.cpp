#include "editor/tools/EdMapLayout.h"

#include "editor/doc/EdJson.h"
#include "editor/tools/EdErosionSuite.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <memory>

namespace faf::editor
{
  namespace
  {
    float Smoothstep(
      const float t
    )
    {
      if (t <= 0.0f) {
        return 0.0f;
      }
      if (t >= 1.0f) {
        return 1.0f;
      }
      return t * t * (3.0f - 2.0f * t);
    }

    using field::Grid;
    using field::GridPtr;

    /** Runs the field ops the generator chains, keeping each result alive for the next. */
    struct Ops
    {
      std::string& error;

      GridPtr Run(
        const char* name,
        field::OpArgs args
      )
      {
        auto out = std::make_shared<Grid>();
        std::string why;
        if (!field::RunOpCpu(name, args, *out, why)) {
          if (error.empty()) {
            error = std::string(name) + ": " + why;
          }
          return nullptr;
        }
        return out;
      }

      GridPtr Const(
        const GridPtr& like,
        const float value
      )
      {
        field::OpArgs a;
        a.in["like"] = like;
        a.p.num["value"] = value;
        return Run("const", a);
      }

      GridPtr Two(
        const char* name,
        const GridPtr& x,
        const GridPtr& y
      )
      {
        if (x == nullptr || y == nullptr) {
          return nullptr;
        }
        field::OpArgs a;
        a.in["a"] = x;
        a.in["b"] = y;
        return Run(name, a);
      }

      GridPtr Affine(
        const GridPtr& x,
        const float mul,
        const float add
      )
      {
        if (x == nullptr) {
          return nullptr;
        }
        field::OpArgs a;
        a.in["a"] = x;
        a.p.num["mul"] = mul;
        a.p.num["add"] = add;
        return Run("affine", a);
      }

      GridPtr Lerp(
        const GridPtr& x,
        const GridPtr& y,
        const GridPtr& mask
      )
      {
        if (x == nullptr || y == nullptr || mask == nullptr) {
          return nullptr;
        }
        field::OpArgs a;
        a.in["a"] = x;
        a.in["b"] = y;
        a.in["mask"] = mask;
        a.p.str["mode"] = "normal";
        a.p.num["opacity"] = 1.0;
        return Run("blend", a);
      }

      GridPtr Noise(
        const GridPtr& like,
        const int seed,
        const float scale,
        const char* kind,
        const float sharpness = 0.0f
      )
      {
        field::OpArgs a;
        a.in["like"] = like;
        a.p.num["seed"] = seed;
        a.p.num["scale"] = scale;
        a.p.num["octaves"] = 6;
        a.p.num["finest"] = std::max(3.0f, scale * 0.05f);
        a.p.num["persistence"] = 0.5;
        a.p.str["kind"] = kind;
        if (sharpness > 0.0f) {
          a.p.num["sharpness"] = sharpness;
        }
        return Run("fractal", a);
      }
    };

    /** The plain mask of a layer on `like`'s grid: the cells spread over the map (bilinear). */
    GridPtr RawMask(
      Ops& ops,
      const MapLayout& layout,
      const GridPtr& like,
      const LayoutLayer& layer
    )
    {
      const LayoutFrame& f = layout.Frame();
      auto cells = std::make_shared<Grid>(f.rw, f.rh, f.cell, f.ox + f.cell * 0.5f, f.oz + f.cell * 0.5f);
      cells->v = layer.data;
      field::OpArgs a;
      a.in["a"] = cells;
      a.in["like"] = like;
      return ops.Run("resample", a);
    }

    /** A mask softened by `soft` units (at least a little more than a cell, so the cells don't show). */
    GridPtr Soften(
      Ops& ops,
      const MapLayout& layout,
      const GridPtr& mask,
      const float soft
    )
    {
      if (mask == nullptr) {
        return nullptr;
      }
      field::OpArgs blur;
      blur.in["a"] = mask;
      blur.p.num["radius"] = std::max(layout.Frame().cell * 0.8f, soft * 0.5f);
      GridPtr blurred = ops.Run("blur", blur);
      if (blurred == nullptr) {
        return nullptr;
      }
      field::OpArgs clamp;
      clamp.in["a"] = blurred;
      clamp.p.num["lo"] = 0.0;
      clamp.p.num["hi"] = 1.0;
      return ops.Run("clamp", clamp);
    }

    float SoftOf(
      const LayoutLayer& layer
    )
    {
      const LayoutKindInfo& info = LayoutKindOf(layer.kind);
      for (const LayoutParamDef& def : info.params) {
        if (std::string(def.key) == "soft" || std::string(def.key) == "edge") {
          return layer.P(def.key);
        }
      }
      return 6.0f;
    }

    std::string Encode(
      const std::vector<float>& data
    )
    {
      std::string out;
      std::size_t i = 0;
      while (i < data.size()) {
        const long q = std::lround(data[i] * 255.0f);
        std::size_t j = i;
        while (j + 1 < data.size() && std::lround(data[j + 1] * 255.0f) == q) {
          ++j;
        }
        if (!out.empty()) {
          out += ',';
        }
        out += std::to_string(q) + "x" + std::to_string(j - i + 1);
        i = j + 1;
      }
      return out;
    }

    bool Decode(
      const std::string& text,
      const std::size_t count,
      std::vector<float>& out
    )
    {
      out.clear();
      out.reserve(count);
      const char* s = text.c_str();
      while (*s != '\0') {
        char* end = nullptr;
        const long q = std::strtol(s, &end, 10);
        if (end == s || *end != 'x') {
          return false;
        }
        s = end + 1;
        const long n = std::strtol(s, &end, 10);
        if (end == s || n < 1 || out.size() + static_cast<std::size_t>(n) > count) {
          return false;
        }
        out.insert(out.end(), static_cast<std::size_t>(n), static_cast<float>(std::clamp(q, 0L, 255L)) / 255.0f);
        s = *end == ',' ? end + 1 : end;
      }
      return out.size() == count;
    }

    std::string Unquote(
      const std::string& text
    )
    {
      // JsonValue gives a string's contents; names are kept free of quotes and backslashes when saved.
      return text;
    }

    LayoutParamDef P(
      const char* key,
      const char* label,
      const float min,
      const float max,
      const float step,
      const char* format,
      const float value
    )
    {
      return LayoutParamDef{key, label, min, max, step, format, value};
    }
  } // namespace

  const std::vector<LayoutKindInfo>& LayoutKinds()
  {
    static const std::vector<LayoutKindInfo> kinds = {
      {LayoutKind::Hills,
       "hills",
       "Hills",
       {118, 196, 92},
       "Rolling ground raised above the base height, with soft edges and a little noise.",
       {P("height", "Height above the ground (units)", 0, 80, 1, "%.0f", 12),
        P("soft", "Soft edge (units)", 2, 120, 1, "%.0f", 30),
        P("rough", "Roughness (units)", 0, 40, 0.5f, "%.1f", 6),
        P("scale", "Feature size (units)", 20, 400, 5, "%.0f", 110)}},
      {LayoutKind::Mountains,
       "mountains",
       "Mountains",
       {226, 226, 236},
       "High ridged ground: steep, with sharp crests and valleys between them.",
       {P("height", "Height above the ground (units)", 10, 200, 1, "%.0f", 70),
        P("soft", "Soft edge (units)", 4, 160, 1, "%.0f", 40),
        P("rough", "Roughness (units)", 0, 60, 0.5f, "%.1f", 14),
        P("scale", "Feature size (units)", 30, 500, 5, "%.0f", 150)}},
      {LayoutKind::Plateau,
       "plateau",
       "Plateau",
       {224, 172, 88},
       "Flat topped high ground with a steep edge (a mesa).",
       {P("height", "Height above the ground (units)", 4, 150, 1, "%.0f", 35),
        P("edge", "Edge width (units)", 1, 60, 1, "%.0f", 6),
        P("rough", "Roughness of the top (units)", 0, 10, 0.25f, "%.2f", 1),
        P("scale", "Feature size (units)", 20, 300, 5, "%.0f", 70)}},
      {LayoutKind::Water,
       "water",
       "Water",
       {72, 140, 232},
       "Lakes, seas and rivers: the ground is dug down below the layout's water level.",
       {P("depth", "Depth under the water (units)", 1, 60, 1, "%.0f", 12),
        P("soft", "Shore width (units)", 2, 100, 1, "%.0f", 14)}},
      {LayoutKind::Valley,
       "valley",
       "Valley",
       {160, 98, 62},
       "A channel or basin dug into the ground (ravines, dry river beds).",
       {P("depth", "Depth (units)", 1, 80, 1, "%.0f", 12), P("soft", "Soft edge (units)", 2, 120, 1, "%.0f", 16)}},
      {LayoutKind::Flat,
       "flat",
       "Flat ground",
       {196, 196, 120},
       "Levels the ground to a height relative to the base height (building areas, ramps between levels).",
       {P("level", "Height relative to the ground (units)", -40, 120, 1, "%.0f", 0),
        P("soft", "Soft edge (units)", 2, 100, 1, "%.0f", 10)}},
      {LayoutKind::Base,
       "base",
       "Base",
       {242, 72, 72},
       "A start base: the ground is levelled at the base height and a start position goes to the middle of each blob.",
       {P("soft", "Soft edge (units)", 2, 100, 1, "%.0f", 14)}},
      {LayoutKind::Mask,
       "mask",
       "Free mask",
       {204, 92, 224},
       "Changes no heights: a mask for the graph's nodes (forests, texture areas, scatter regions).",
       {}},
    };
    return kinds;
  }

  const LayoutKindInfo& LayoutKindOf(
    const LayoutKind kind
  )
  {
    return LayoutKinds()[static_cast<std::size_t>(kind)];
  }

  bool LayoutKindFromId(
    const std::string& id,
    LayoutKind& kind
  )
  {
    for (const LayoutKindInfo& info : LayoutKinds()) {
      if (id == info.id) {
        kind = info.kind;
        return true;
      }
    }
    return false;
  }

  float LayoutLayer::P(
    const std::string& key
  ) const
  {
    if (const auto it = p.find(key); it != p.end()) {
      return it->second;
    }
    for (const LayoutParamDef& def : LayoutKindOf(kind).params) {
      if (key == def.key) {
        return def.value;
      }
    }
    return 0.0f;
  }

  LayoutFrame LayoutFrameFor(
    const int res,
    const float x0,
    const float z0,
    const float x1,
    const float z1
  )
  {
    const float aw = std::max(8.0f, x1 - x0);
    const float ah = std::max(8.0f, z1 - z0);
    LayoutFrame f;
    f.cell = std::max(aw, ah) / static_cast<float>(std::max(1, res));
    f.rw = std::max(1, static_cast<int>(std::floor(aw / f.cell + 0.5f)));
    f.rh = std::max(1, static_cast<int>(std::floor(ah / f.cell + 0.5f)));
    f.ox = x0 + (aw - static_cast<float>(f.rw) * f.cell) / 2.0f;
    f.oz = z0 + (ah - static_cast<float>(f.rh) * f.cell) / 2.0f;
    return f;
  }

  MapLayout::MapLayout()
  {
    New(kDefaultRes, 0.0f, 0.0f, 256.0f, 256.0f);
  }

  std::vector<LayoutKind> MapLayout::DefaultKinds()
  {
    return {
      LayoutKind::Hills,
      LayoutKind::Mountains,
      LayoutKind::Plateau,
      LayoutKind::Water,
      LayoutKind::Valley,
      LayoutKind::Base
    };
  }

  void MapLayout::New(
    const int res,
    const float x0,
    const float z0,
    const float x1,
    const float z1,
    const std::vector<LayoutKind>& kinds
  )
  {
    mRes = std::clamp(res, kMinRes, kMaxRes);
    mFrame = LayoutFrameFor(mRes, x0, z0, x1, z1);
    mLayers.clear();
    mStroking = false;
    base = 25.0f;
    water = 20.0f;
    seed = 1;
    weather = 0.0f;
    for (const LayoutKind kind : kinds) {
      mLayers.push_back(MakeLayer(kind, {}));
    }
    selected = 0;
    Touch();
  }

  LayoutLayer MapLayout::MakeLayer(
    const LayoutKind kind,
    const std::string& name
  )
  {
    const LayoutKindInfo& info = LayoutKindOf(kind);
    LayoutLayer layer;
    layer.id = mNextId++;
    layer.name = name.empty() ? info.label : name;
    layer.kind = kind;
    layer.color = info.color;
    for (const LayoutParamDef& def : info.params) {
      layer.p[def.key] = def.value;
    }
    layer.data.assign(static_cast<std::size_t>(mFrame.rw) * static_cast<std::size_t>(mFrame.rh), 0.0f);
    return layer;
  }

  LayoutLayer* MapLayout::Layer(
    const int i
  )
  {
    return i >= 0 && i < static_cast<int>(mLayers.size()) ? &mLayers[static_cast<std::size_t>(i)] : nullptr;
  }

  const LayoutLayer* MapLayout::Layer(
    const int i
  ) const
  {
    return i >= 0 && i < static_cast<int>(mLayers.size()) ? &mLayers[static_cast<std::size_t>(i)] : nullptr;
  }

  LayoutLayer* MapLayout::LayerById(
    const int id
  )
  {
    for (LayoutLayer& layer : mLayers) {
      if (layer.id == id) {
        return &layer;
      }
    }
    return nullptr;
  }

  void MapLayout::ToWorld(
    const float cx,
    const float cz,
    float& x,
    float& z
  ) const
  {
    x = mFrame.ox + cx * mFrame.cell;
    z = mFrame.oz + cz * mFrame.cell;
  }

  void MapLayout::ToCell(
    const float x,
    const float z,
    float& cx,
    float& cz
  ) const
  {
    cx = (x - mFrame.ox) / mFrame.cell;
    cz = (z - mFrame.oz) / mFrame.cell;
  }

  int MapLayout::AddLayer(
    const LayoutKind kind,
    const std::string& name
  )
  {
    if (static_cast<int>(mLayers.size()) >= kMaxLayers) {
      return -1;
    }
    LayoutLayer layer = MakeLayer(kind, name);
    const auto same = std::count_if(mLayers.begin(), mLayers.end(), [kind](const LayoutLayer& l) {
      return l.kind == kind;
    });
    if (name.empty() && same > 0) {
      layer.name = std::string(LayoutKindOf(kind).label) + " " + std::to_string(same + 1);
    }
    mLayers.push_back(std::move(layer));
    selected = static_cast<int>(mLayers.size()) - 1;
    Touch();
    return selected;
  }

  bool MapLayout::RemoveLayer(
    const int i
  )
  {
    if (Layer(i) == nullptr || mLayers.size() <= 1) {
      return false;
    }
    mLayers.erase(mLayers.begin() + i);
    selected = std::min(selected, static_cast<int>(mLayers.size()) - 1);
    Touch();
    return true;
  }

  bool MapLayout::MoveLayer(
    const int i,
    const int dir
  )
  {
    const int j = i + dir;
    if (Layer(i) == nullptr || Layer(j) == nullptr) {
      return false;
    }
    std::swap(mLayers[static_cast<std::size_t>(i)], mLayers[static_cast<std::size_t>(j)]);
    if (selected == i) {
      selected = j;
    } else if (selected == j) {
      selected = i;
    }
    Touch();
    return true;
  }

  bool MapLayout::BeginStroke(
    const int i
  )
  {
    const LayoutLayer* layer = Layer(i);
    if (layer == nullptr) {
      return false;
    }
    mStroke = LayoutStroke{layer->id, layer->data, {}};
    mStroking = true;
    return true;
  }

  bool MapLayout::EndStroke(
    LayoutStroke& out
  )
  {
    if (!mStroking) {
      return false;
    }
    mStroking = false;
    const LayoutLayer* layer = LayerById(mStroke.layerId);
    if (layer == nullptr || layer->data == mStroke.before) {
      return false;
    }
    mStroke.after = layer->data;
    out = std::move(mStroke);
    mStroke = {};
    Touch();
    return true;
  }

  bool MapLayout::SetCells(
    const int layerId,
    const std::vector<float>& data
  )
  {
    LayoutLayer* layer = LayerById(layerId);
    if (layer == nullptr || data.size() != layer->data.size()) {
      return false;
    }
    layer->data = data;
    Touch();
    return true;
  }

  std::vector<std::pair<float, float>> MapLayout::CellImages(
    const float cx,
    const float cz
  ) const
  {
    if (!mImages) {
      return {{cx, cz}};
    }
    float wx = 0.0f;
    float wz = 0.0f;
    ToWorld(cx, cz, wx, wz);
    std::vector<std::pair<float, float>> out;
    for (const auto& [x, z] : mImages(wx, wz)) {
      float ix = 0.0f;
      float iz = 0.0f;
      ToCell(x, z, ix, iz);
      out.emplace_back(ix, iz);
    }
    if (out.empty()) {
      out.emplace_back(cx, cz);
    }
    return out;
  }

  void MapLayout::Dab(
    const int i,
    const float cx,
    const float cz,
    const float r,
    const float hardness,
    const float strength,
    const bool erase
  )
  {
    LayoutLayer* layer = Layer(i);
    if (layer == nullptr || r <= 0.0f) {
      return;
    }
    const int rw = mFrame.rw;
    const int rh = mFrame.rh;
    std::vector<float>& data = layer->data;
    for (const auto& [ix, iz] : CellImages(cx, cz)) {
      const int x0 = std::max(0, static_cast<int>(std::floor(ix - r)));
      const int x1 = std::min(rw - 1, static_cast<int>(std::ceil(ix + r)));
      const int z0 = std::max(0, static_cast<int>(std::floor(iz - r)));
      const int z1 = std::min(rh - 1, static_cast<int>(std::ceil(iz + r)));
      for (int z = z0; z <= z1; ++z) {
        const float dz = static_cast<float>(z) + 0.5f - iz;
        for (int x = x0; x <= x1; ++x) {
          const float dx = static_cast<float>(x) + 0.5f - ix;
          const float d = std::sqrt(dx * dx + dz * dz);
          if (d > r) {
            continue;
          }
          const float t = d / std::max(r, 0.001f);
          const float fall =
            t <= hardness ? 1.0f : 1.0f - Smoothstep((t - hardness) / std::max(1.0f - hardness, 0.001f));
          const float v = fall * strength;
          float& cell = data[static_cast<std::size_t>(z) * static_cast<std::size_t>(rw) + static_cast<std::size_t>(x)];
          if (erase) {
            cell = std::max(0.0f, cell - v);
          } else if (v > cell) {
            cell = v;
          }
        }
      }
    }
  }

  void MapLayout::Line(
    const int i,
    const float x0,
    const float z0,
    const float x1,
    const float z1,
    const float r,
    const float hardness,
    const float strength,
    const bool erase
  )
  {
    const float len = std::hypot(x1 - x0, z1 - z0);
    const int steps = std::max(1, static_cast<int>(std::ceil(len / std::max(0.5f, r * 0.35f))));
    for (int s = 0; s <= steps; ++s) {
      const float t = static_cast<float>(s) / static_cast<float>(steps);
      Dab(i, x0 + (x1 - x0) * t, z0 + (z1 - z0) * t, r, hardness, strength, erase);
    }
  }

  template <typename Inside>
  int MapLayout::FillWhere(
    const int i,
    const float x0,
    const float z0,
    const float x1,
    const float z1,
    Inside inside,
    const float strength,
    const bool erase
  )
  {
    LayoutLayer* layer = Layer(i);
    if (layer == nullptr) {
      return 0;
    }
    const int rw = mFrame.rw;
    const int rh = mFrame.rh;
    std::vector<float>& data = layer->data;
    int n = 0;
    const auto put = [&](const int ix, const int iz) {
      if (ix < 0 || iz < 0 || ix >= rw || iz >= rh) {
        return;
      }
      float& cell = data[static_cast<std::size_t>(iz) * static_cast<std::size_t>(rw) + static_cast<std::size_t>(ix)];
      if (erase) {
        if (cell != 0.0f) {
          cell = 0.0f;
          ++n;
        }
      } else if (cell < strength) {
        cell = strength;
        ++n;
      }
    };
    const int zs = std::max(0, static_cast<int>(std::floor(z0)));
    const int ze = std::min(rh - 1, static_cast<int>(std::ceil(z1)));
    const int xs = std::max(0, static_cast<int>(std::floor(x0)));
    const int xe = std::min(rw - 1, static_cast<int>(std::ceil(x1)));
    for (int z = zs; z <= ze; ++z) {
      for (int x = xs; x <= xe; ++x) {
        const float px = static_cast<float>(x) + 0.5f;
        const float pz = static_cast<float>(z) + 0.5f;
        if (!inside(px, pz)) {
          continue;
        }
        if (!mImages) {
          put(x, z);
          continue;
        }
        for (const auto& [ix, iz] : CellImages(px, pz)) {
          put(static_cast<int>(std::floor(ix)), static_cast<int>(std::floor(iz)));
        }
      }
    }
    return n;
  }

  int MapLayout::FillRect(
    const int i,
    const float x0,
    const float z0,
    const float x1,
    const float z1,
    const float strength,
    const bool erase
  )
  {
    const float ax = std::min(x0, x1);
    const float bx = std::max(x0, x1);
    const float az = std::min(z0, z1);
    const float bz = std::max(z0, z1);
    return FillWhere(i, ax, az, bx, bz, [&](const float x, const float z) {
      return x >= ax && x <= bx && z >= az && z <= bz;
    }, strength, erase);
  }

  int MapLayout::FillEllipse(
    const int i,
    const float x0,
    const float z0,
    const float x1,
    const float z1,
    const float strength,
    const bool erase
  )
  {
    const float ax = std::min(x0, x1);
    const float bx = std::max(x0, x1);
    const float az = std::min(z0, z1);
    const float bz = std::max(z0, z1);
    const float cx = (ax + bx) / 2.0f;
    const float cz = (az + bz) / 2.0f;
    const float rx = std::max(0.5f, (bx - ax) / 2.0f);
    const float rz = std::max(0.5f, (bz - az) / 2.0f);
    return FillWhere(i, ax, az, bx, bz, [&](const float x, const float z) {
      const float dx = (x - cx) / rx;
      const float dz = (z - cz) / rz;
      return dx * dx + dz * dz <= 1.0f;
    }, strength, erase);
  }

  int MapLayout::FillPolygon(
    const int i,
    const std::vector<std::pair<float, float>>& points,
    const float strength,
    const bool erase
  )
  {
    const std::size_t n = points.size();
    if (n < 3) {
      return 0;
    }
    float x0 = points[0].first;
    float x1 = x0;
    float z0 = points[0].second;
    float z1 = z0;
    for (const auto& [x, z] : points) {
      x0 = std::min(x0, x);
      x1 = std::max(x1, x);
      z0 = std::min(z0, z);
      z1 = std::max(z1, z);
    }
    return FillWhere(i, x0, z0, x1, z1, [&](const float x, const float z) {
      bool in = false;
      std::size_t j = n - 1;
      for (std::size_t k = 0; k < n; ++k) {
        const auto& a = points[k];
        const auto& b = points[j];
        if (
          (a.second > z) != (b.second > z) && x < (b.first - a.first) * (z - a.second) / (b.second - a.second) + a.first
        ) {
          in = !in;
        }
        j = k;
      }
      return in;
    }, strength, erase);
  }

  void MapLayout::Fill(
    const int i,
    const float value
  )
  {
    if (LayoutLayer* layer = Layer(i)) {
      std::fill(layer->data.begin(), layer->data.end(), value);
    }
  }

  void MapLayout::Smooth(
    const int i
  )
  {
    LayoutLayer* layer = Layer(i);
    if (layer == nullptr) {
      return;
    }
    const int rw = mFrame.rw;
    const int rh = mFrame.rh;
    const std::vector<float> old = layer->data;
    for (int z = 0; z < rh; ++z) {
      for (int x = 0; x < rw; ++x) {
        float sum = 0.0f;
        int count = 0;
        for (int dz = -1; dz <= 1; ++dz) {
          for (int dx = -1; dx <= 1; ++dx) {
            const int xx = x + dx;
            const int zz = z + dz;
            if (xx >= 0 && zz >= 0 && xx < rw && zz < rh) {
              sum += old[static_cast<std::size_t>(zz) * static_cast<std::size_t>(rw) + static_cast<std::size_t>(xx)];
              ++count;
            }
          }
        }
        layer->data[static_cast<std::size_t>(z) * static_cast<std::size_t>(rw) + static_cast<std::size_t>(x)] =
          sum / static_cast<float>(count);
      }
    }
  }

  void MapLayout::Invert(
    const int i
  )
  {
    if (LayoutLayer* layer = Layer(i)) {
      for (float& v : layer->data) {
        v = 1.0f - v;
      }
    }
  }

  int MapLayout::ImportPicture(
    const int i,
    const std::vector<float>& grey,
    const int w,
    const int h,
    const LayoutPictureOptions& o
  )
  {
    LayoutLayer* layer = Layer(i);
    if (
      layer == nullptr || w < 1 || h < 1 || grey.size() != static_cast<std::size_t>(w) * static_cast<std::size_t>(h)
    ) {
      return -1;
    }
    float lo = 0.0f;
    float hi = 1.0f;
    if (o.stretch) {
      const auto [mn, mx] = std::minmax_element(grey.begin(), grey.end());
      lo = *mn;
      hi = *mx;
    }
    const float rw = static_cast<float>(mFrame.rw);
    const float rh = static_cast<float>(mFrame.rh);
    // The picture's rectangle on the drawing (cells): the whole of it, or fitted inside with its aspect.
    float x0 = 0.0f, z0 = 0.0f, pw = rw, ph = rh;
    if (o.contain) {
      const float scale = std::min(rw / static_cast<float>(w), rh / static_cast<float>(h));
      pw = static_cast<float>(w) * scale;
      ph = static_cast<float>(h) * scale;
      x0 = (rw - pw) / 2.0f;
      z0 = (rh - ph) / 2.0f;
    }
    const auto at = [&](const int x, const int z) {
      return grey
        [static_cast<std::size_t>(std::clamp(z, 0, h - 1)) * static_cast<std::size_t>(w) +
         static_cast<std::size_t>(std::clamp(x, 0, w - 1))];
    };
    int changed = 0;
    for (int cz = 0; cz < mFrame.rh; ++cz) {
      for (int cx = 0; cx < mFrame.rw; ++cx) {
        float u = (static_cast<float>(cx) + 0.5f - x0) / pw;
        float v = (static_cast<float>(cz) + 0.5f - z0) / ph;
        float value = 0.0f;
        if (u >= 0.0f && v >= 0.0f && u <= 1.0f && v <= 1.0f) {
          u = o.flipX ? 1.0f - u : u;
          v = o.flipZ ? 1.0f - v : v;
          const float fx = u * static_cast<float>(w) - 0.5f;
          const float fz = v * static_cast<float>(h) - 0.5f;
          const int ix = static_cast<int>(std::floor(fx));
          const int iz = static_cast<int>(std::floor(fz));
          const float tx = fx - static_cast<float>(ix);
          const float tz = fz - static_cast<float>(iz);
          value = (at(ix, iz) * (1.0f - tx) + at(ix + 1, iz) * tx) * (1.0f - tz) +
            (at(ix, iz + 1) * (1.0f - tx) + at(ix + 1, iz + 1) * tx) * tz;
          if (o.stretch && hi > lo) {
            value = (value - lo) / (hi - lo);
          }
          value = std::clamp(value, 0.0f, 1.0f);
          if (o.invert) {
            value = 1.0f - value;
          }
        } else if (o.invert) {
          value = 0.0f; // outside the picture stays empty
        }
        if (o.hard) {
          value = value > 0.5f ? 1.0f : 0.0f;
        }
        float& cell =
          layer
            ->data[static_cast<std::size_t>(cz) * static_cast<std::size_t>(mFrame.rw) + static_cast<std::size_t>(cx)];
        if (o.add) {
          value = std::max(value, cell);
        }
        value = std::round(value * 255.0f) / 255.0f;
        if (cell != value) {
          ++changed;
          cell = value;
        }
      }
    }
    Touch();
    return changed;
  }

  bool MapLayout::Drawn() const
  {
    for (const LayoutLayer& layer : mLayers) {
      for (const float v : layer.data) {
        if (v != 0.0f) {
          return true;
        }
      }
    }
    return false;
  }

  bool MapLayout::Stale(
    const float x0,
    const float z0,
    const float x1,
    const float z1
  ) const
  {
    const LayoutFrame f = LayoutFrameFor(mRes, x0, z0, x1, z1);
    return f.rw != mFrame.rw || f.rh != mFrame.rh || std::fabs(f.cell - mFrame.cell) >= 0.001f ||
      std::fabs(f.ox - mFrame.ox) >= 0.01f || std::fabs(f.oz - mFrame.oz) >= 0.01f;
  }

  bool MapLayout::Refit(
    const int res,
    const float x0,
    const float z0,
    const float x1,
    const float z1
  )
  {
    const int want = std::clamp(res, kMinRes, kMaxRes);
    const LayoutFrame f = LayoutFrameFor(want, x0, z0, x1, z1);
    if (want == mRes && !Stale(x0, z0, x1, z1)) {
      return false;
    }
    const LayoutFrame old = mFrame;
    mRes = want;
    mFrame = f;
    for (LayoutLayer& layer : mLayers) {
      std::vector<float> out(static_cast<std::size_t>(f.rw) * static_cast<std::size_t>(f.rh), 0.0f);
      const auto at = [&](const int x, const int z) -> float {
        if (x < 0 || z < 0 || x >= old.rw || z >= old.rh) {
          return 0.0f;
        }
        return layer.data[static_cast<std::size_t>(z) * static_cast<std::size_t>(old.rw) + static_cast<std::size_t>(x)];
      };
      for (int z = 0; z < f.rh; ++z) {
        for (int x = 0; x < f.rw; ++x) {
          const float wx = f.ox + (static_cast<float>(x) + 0.5f) * f.cell;
          const float wz = f.oz + (static_cast<float>(z) + 0.5f) * f.cell;
          const float fx = (wx - old.ox) / old.cell - 0.5f;
          const float fz = (wz - old.oz) / old.cell - 0.5f;
          float v = 0.0f;
          if (
            fx >= -0.5f && fz >= -0.5f && fx <= static_cast<float>(old.rw) - 0.5f &&
            fz <= static_cast<float>(old.rh) - 0.5f
          ) {
            const int ix = static_cast<int>(std::floor(fx));
            const int iz = static_cast<int>(std::floor(fz));
            const float tx = fx - static_cast<float>(ix);
            const float tz = fz - static_cast<float>(iz);
            const float a = at(ix, iz) * (1.0f - tx) + at(ix + 1, iz) * tx;
            const float b = at(ix, iz + 1) * (1.0f - tx) + at(ix + 1, iz + 1) * tx;
            v = a * (1.0f - tz) + b * tz;
          }
          out[static_cast<std::size_t>(z) * static_cast<std::size_t>(f.rw) + static_cast<std::size_t>(x)] =
            v < 0.0005f ? 0.0f : std::min(1.0f, v);
        }
      }
      layer.data = std::move(out);
    }
    Touch();
    return true;
  }

  std::vector<LayoutBase> MapLayout::BaseCentres() const
  {
    const int rw = mFrame.rw;
    const int rh = mFrame.rh;
    const std::size_t count = static_cast<std::size_t>(rw) * static_cast<std::size_t>(rh);
    std::vector<std::uint8_t> on(count, 0);
    bool any = false;
    for (const LayoutLayer& layer : mLayers) {
      if (layer.kind == LayoutKind::Base && layer.visible) {
        for (std::size_t k = 0; k < count; ++k) {
          if (layer.data[k] >= 0.5f) {
            on[k] = 1;
            any = true;
          }
        }
      }
    }
    std::vector<LayoutBase> list;
    if (!any) {
      return list;
    }
    std::vector<std::uint8_t> seen(count, 0);
    std::vector<std::size_t> stack;
    for (std::size_t start = 0; start < count; ++start) {
      if (on[start] == 0 || seen[start] != 0) {
        continue;
      }
      seen[start] = 1;
      stack.assign(1, start);
      double sx = 0.0;
      double sz = 0.0;
      int n = 0;
      while (!stack.empty()) {
        const std::size_t cur = stack.back();
        stack.pop_back();
        const int cz = static_cast<int>(cur / static_cast<std::size_t>(rw));
        const int cx = static_cast<int>(cur % static_cast<std::size_t>(rw));
        sx += cx + 0.5;
        sz += cz + 0.5;
        ++n;
        static const int dxs[4] = {1, -1, 0, 0};
        static const int dzs[4] = {0, 0, 1, -1};
        for (int d = 0; d < 4; ++d) {
          const int nx = cx + dxs[d];
          const int nz = cz + dzs[d];
          if (nx >= 0 && nz >= 0 && nx < rw && nz < rh) {
            const std::size_t na =
              static_cast<std::size_t>(nz) * static_cast<std::size_t>(rw) + static_cast<std::size_t>(nx);
            if (on[na] != 0 && seen[na] == 0) {
              seen[na] = 1;
              stack.push_back(na);
            }
          }
        }
      }
      if (n >= 3) {
        LayoutBase b;
        b.x = mFrame.ox + static_cast<float>(sx / n) * mFrame.cell;
        b.z = mFrame.oz + static_cast<float>(sz / n) * mFrame.cell;
        b.cells = n;
        list.push_back(b);
      }
    }
    std::sort(list.begin(), list.end(), [](const LayoutBase& a, const LayoutBase& b) {
      return a.cells != b.cells ? a.cells > b.cells : a.x < b.x;
    });
    return list;
  }

  void MapLayout::Pixels(
    std::vector<std::uint8_t>& rgba,
    const int only
  ) const
  {
    const std::size_t n = static_cast<std::size_t>(mFrame.rw) * static_cast<std::size_t>(mFrame.rh);
    std::vector<float> px(n * 3);
    for (std::size_t k = 0; k < n; ++k) {
      px[k * 3 + 0] = 28.0f;
      px[k * 3 + 1] = 32.0f;
      px[k * 3 + 2] = 38.0f;
    }
    for (std::size_t li = 0; li < mLayers.size(); ++li) {
      const LayoutLayer& layer = mLayers[li];
      if (!layer.visible) {
        continue;
      }
      const float af = only >= 0 ? (static_cast<int>(li) == only ? 0.95f : 0.4f) : 0.85f;
      for (std::size_t k = 0; k < n; ++k) {
        const float v = layer.data[k];
        if (v > 0.004f) {
          const float a = v * af;
          for (int c = 0; c < 3; ++c) {
            float& p = px[k * 3 + static_cast<std::size_t>(c)];
            p += (static_cast<float>(layer.color[static_cast<std::size_t>(c)]) - p) * a;
          }
        }
      }
    }
    rgba.resize(n * 4);
    for (std::size_t k = 0; k < n; ++k) {
      for (int c = 0; c < 3; ++c) {
        rgba[k * 4 + static_cast<std::size_t>(c)] =
          static_cast<std::uint8_t>(std::clamp(std::lround(px[k * 3 + static_cast<std::size_t>(c)]), 0L, 255L));
      }
      rgba[k * 4 + 3] = 255;
    }
  }

  const std::vector<MapLayout::TemplateInfo>& MapLayout::Templates()
  {
    static const std::vector<TemplateInfo> list = {
      {"duel",
       "Duel",
       "rot2",
       "Two bases facing each other across a winding ridge, a lake beside each base (turned by 180 degrees)."},
      {"four",
       "Four players",
       "mirror_xz",
       "A base in each corner, ridges between the corners and a plateau in the middle (mirrored both ways)."},
      {"river", "River", "mirror_x", "A river down the middle with two bases on each bank (mirrored left to right)."},
      {"islands",
       "Islands",
       "rot2",
       "Open water with an island for each base and a small islet between them (turned by 180 degrees)."},
    };
    return list;
  }

  bool MapLayout::ApplyTemplate(
    const std::string& id,
    std::string& symmetry
  )
  {
    const TemplateInfo* t = nullptr;
    for (const TemplateInfo& info : Templates()) {
      if (id == info.id) {
        t = &info;
      }
    }
    if (t == nullptr) {
      return false;
    }
    symmetry = t->symmetry;
    std::vector<LayoutKind> kinds;
    if (id == "islands") {
      kinds.push_back(LayoutKind::Water);
    }
    for (const LayoutKind k : DefaultKinds()) {
      if (std::find(kinds.begin(), kinds.end(), k) == kinds.end()) {
        kinds.push_back(k);
      }
    }
    mLayers.clear();
    for (const LayoutKind k : kinds) {
      mLayers.push_back(MakeLayer(k, {}));
    }
    selected = 0;
    // Painted in fractions of the canvas, the master part only: the symmetry draws the rest (images set by the caller
    // to the template's symmetry, or none: then the template's own copies below).
    const float rw = static_cast<float>(mFrame.rw);
    const float rh = static_cast<float>(mFrame.rh);
    const float shortSide = std::min(rw, rh);
    const auto index = [&](const LayoutKind kind) {
      for (std::size_t i = 0; i < mLayers.size(); ++i) {
        if (mLayers[i].kind == kind) {
          return static_cast<int>(i);
        }
      }
      return 0;
    };
    const auto dab = [&](LayoutKind kind, float x, float z, float r, float v) {
      Dab(index(kind), x * rw, z * rh, r * shortSide, 0.8f, v, false);
    };
    const auto line = [&](LayoutKind kind, float x0, float z0, float x1, float z1, float r, float v) {
      Line(index(kind), x0 * rw, z0 * rh, x1 * rw, z1 * rh, r * shortSide, 0.8f, v, false);
    };
    const auto ellipse = [&](LayoutKind kind, float x0, float z0, float x1, float z1, float v) {
      FillEllipse(index(kind), x0 * rw, z0 * rh, x1 * rw, z1 * rh, v, false);
    };
    if (id == "duel") {
      ellipse(LayoutKind::Hills, 0.05f, 0.2f, 0.42f, 0.8f, 0.9f);
      line(LayoutKind::Mountains, 0.46f, 0.08f, 0.54f, 0.5f, 0.05f, 1.0f);
      ellipse(LayoutKind::Water, 0.27f, 0.12f, 0.39f, 0.25f, 1.0f);
      dab(LayoutKind::Base, 0.2f, 0.5f, 0.07f, 1.0f);
    } else if (id == "four") {
      ellipse(LayoutKind::Hills, 0.04f, 0.04f, 0.42f, 0.42f, 0.9f);
      line(LayoutKind::Mountains, 0.5f, 0.04f, 0.5f, 0.32f, 0.045f, 1.0f);
      line(LayoutKind::Mountains, 0.04f, 0.5f, 0.32f, 0.5f, 0.045f, 1.0f);
      ellipse(LayoutKind::Plateau, 0.4f, 0.4f, 0.6f, 0.6f, 1.0f);
      dab(LayoutKind::Base, 0.17f, 0.17f, 0.065f, 1.0f);
    } else if (id == "river") {
      ellipse(LayoutKind::Hills, 0.02f, 0.1f, 0.42f, 0.9f, 0.8f);
      line(LayoutKind::Water, 0.5f, -0.05f, 0.5f, 1.05f, 0.035f, 1.0f);
      dab(LayoutKind::Mountains, 0.3f, 0.5f, 0.06f, 1.0f);
      dab(LayoutKind::Base, 0.2f, 0.28f, 0.06f, 1.0f);
      dab(LayoutKind::Base, 0.2f, 0.72f, 0.06f, 1.0f);
    } else {
      Fill(index(LayoutKind::Water), 1.0f);
      ellipse(LayoutKind::Hills, 0.1f, 0.25f, 0.4f, 0.75f, 1.0f);
      dab(LayoutKind::Mountains, 0.27f, 0.42f, 0.05f, 1.0f);
      ellipse(LayoutKind::Hills, 0.42f, 0.1f, 0.52f, 0.2f, 0.7f);
      dab(LayoutKind::Base, 0.22f, 0.58f, 0.06f, 1.0f);
    }
    Touch();
    return true;
  }

  std::string MapLayout::Save() const
  {
    if (!Drawn() && generated.empty()) {
      return {};
    }
    std::string out = "{\n";
    const auto num = [&](const char* key, const float v) {
      out += std::string("  \"") + key + "\": " + JsonNumber(v) + ",\n";
    };
    num("res", static_cast<float>(mRes));
    num("rw", static_cast<float>(mFrame.rw));
    num("rh", static_cast<float>(mFrame.rh));
    num("cell", mFrame.cell);
    num("ox", mFrame.ox);
    num("oz", mFrame.oz);
    num("base", base);
    num("water", water);
    num("seed", static_cast<float>(seed));
    num("weather", weather);
    num("sel", static_cast<float>(selected));
    out += "  \"layers\": [\n";
    for (std::size_t i = 0; i < mLayers.size(); ++i) {
      const LayoutLayer& layer = mLayers[i];
      std::string name;
      for (const char c : layer.name) {
        if (c != '"' && c != '\\') {
          name += c;
        }
      }
      out += "    {\"id\": " + std::to_string(layer.id) + ", \"name\": " + JsonQuoted(name) + ", \"kind\": \"" +
        LayoutKindOf(layer.kind).id + "\", \"visible\": " + (layer.visible ? "true" : "false") + ", \"color\": [" +
        std::to_string(layer.color[0]) + ", " + std::to_string(layer.color[1]) + ", " + std::to_string(layer.color[2]) +
        "], \"p\": {";
      bool first = true;
      for (const auto& [key, value] : layer.p) {
        out += std::string(first ? "" : ", ") + "\"" + key + "\": " + JsonNumber(value);
        first = false;
      }
      out += "}, \"data\": \"" + Encode(layer.data) + "\"}" + (i + 1 < mLayers.size() ? ",\n" : "\n");
    }
    out += "  ]";
    if (!generated.empty()) {
      out += ",\n  \"generated\": [\n";
      for (std::size_t i = 0; i < generated.size(); ++i) {
        std::string name;
        for (const char c : generated[i].name) {
          if (c != '"' && c != '\\') {
            name += c;
          }
        }
        out += "    {\"name\": " + JsonQuoted(name) + ", \"x\": " + JsonNumber(generated[i].x) +
          ", \"z\": " + JsonNumber(generated[i].z) + "}" + (i + 1 < generated.size() ? ",\n" : "\n");
      }
      out += "  ]";
    }
    out += "\n}\n";
    return out;
  }

  bool MapLayout::Load(
    const std::string& text,
    std::string& error
  )
  {
    std::string layersText;
    if (!JsonValue(text, "layers", layersText)) {
      error = "no layers";
      return false;
    }
    float res = static_cast<float>(kDefaultRes);
    float rw = 0.0f;
    float rh = 0.0f;
    float cell = 0.0f;
    float ox = 0.0f;
    float oz = 0.0f;
    // The top level is read up to the layers (their keys are other names).
    const std::string head = text.substr(0, text.find("\"layers\""));
    (void)JsonFloat(head, "res", res);
    (void)JsonFloat(head, "rw", rw);
    (void)JsonFloat(head, "rh", rh);
    (void)JsonFloat(head, "cell", cell);
    (void)JsonFloat(head, "ox", ox);
    (void)JsonFloat(head, "oz", oz);
    if (rw < 1.0f || rh < 1.0f || cell <= 0.0f || rw * rh > 4.0e6f) {
      error = "the drawing's grid is missing";
      return false;
    }
    MapLayout loaded;
    loaded.mRes = std::clamp(static_cast<int>(res), kMinRes, kMaxRes);
    loaded.mFrame = LayoutFrame{static_cast<int>(rw), static_cast<int>(rh), cell, ox, oz};
    loaded.mLayers.clear();
    (void)JsonFloat(head, "base", loaded.base);
    (void)JsonFloat(head, "water", loaded.water);
    float seedValue = 1.0f;
    (void)JsonFloat(head, "seed", seedValue);
    loaded.seed = static_cast<int>(seedValue);
    (void)JsonFloat(head, "weather", loaded.weather);
    float sel = 0.0f;
    (void)JsonFloat(head, "sel", sel);
    const std::size_t count = static_cast<std::size_t>(rw) * static_cast<std::size_t>(rh);
    for (const std::string& object : JsonObjects(layersText)) {
      std::string kindId;
      LayoutKind kind = LayoutKind::Hills;
      if (!JsonValue(object, "kind", kindId) || !LayoutKindFromId(kindId, kind)) {
        continue;
      }
      std::string name;
      (void)JsonValue(object, "name", name);
      LayoutLayer layer = loaded.MakeLayer(kind, Unquote(name));
      float id = 0.0f;
      if (JsonFloat(object, "id", id) && id >= 1.0f) {
        layer.id = static_cast<int>(id);
        loaded.mNextId = std::max(loaded.mNextId, layer.id + 1);
      }
      std::string visible;
      layer.visible = !(JsonValue(object, "visible", visible) && visible == "false");
      std::string color;
      if (JsonValue(object, "color", color)) {
        int r = 0, g = 0, b = 0;
        if (std::sscanf(color.c_str(), "[%d , %d , %d]", &r, &g, &b) == 3) {
          layer.color = {
            static_cast<std::uint8_t>(std::clamp(r, 0, 255)),
            static_cast<std::uint8_t>(std::clamp(g, 0, 255)),
            static_cast<std::uint8_t>(std::clamp(b, 0, 255))
          };
        }
      }
      std::string params;
      if (JsonValue(object, "p", params)) {
        for (const LayoutParamDef& def : LayoutKindOf(kind).params) {
          float v = def.value;
          if (JsonFloat(params, def.key, v)) {
            layer.p[def.key] = std::clamp(v, def.min, def.max);
          }
        }
      }
      std::string data;
      std::vector<float> cells;
      if (JsonValue(object, "data", data) && Decode(data, count, cells)) {
        layer.data = std::move(cells);
      }
      loaded.mLayers.push_back(std::move(layer));
    }
    if (loaded.mLayers.empty()) {
      error = "no layer of a known kind";
      return false;
    }
    loaded.selected = std::clamp(static_cast<int>(sel), 0, static_cast<int>(loaded.mLayers.size()) - 1);
    std::string generatedText;
    if (JsonValue(text, "generated", generatedText)) {
      for (const std::string& object : JsonObjects(generatedText)) {
        Generated g;
        if (JsonValue(object, "name", g.name) && JsonFloat(object, "x", g.x) && JsonFloat(object, "z", g.z)) {
          loaded.generated.push_back(std::move(g));
        }
      }
    }
    LayoutImages images = std::move(mImages);
    const std::uint64_t rev = revision;
    *this = std::move(loaded);
    mImages = std::move(images);
    revision = rev + 1;
    return true;
  }

  bool LayoutLayerHas(
    const LayoutLayer& layer,
    const float level
  )
  {
    return std::any_of(layer.data.begin(), layer.data.end(), [level](const float v) {
      return v > level;
    });
  }

  bool LayoutLayerMask(
    const MapLayout& layout,
    const field::Grid& like,
    const int i,
    const bool soft,
    field::Grid& out,
    std::string& error
  )
  {
    const LayoutLayer* layer = layout.Layer(i);
    if (layer == nullptr) {
      error = "the layout has no layer " + std::to_string(i + 1);
      return false;
    }
    Ops ops{error};
    const GridPtr likePtr = std::make_shared<Grid>(like);
    GridPtr mask = RawMask(ops, layout, likePtr, *layer);
    if (soft) {
      mask = Soften(ops, layout, mask, SoftOf(*layer));
    }
    if (mask == nullptr) {
      return false;
    }
    out = *mask;
    return true;
  }

  bool BuildLayout(
    const MapLayout& layout,
    const field::Grid& like,
    const LayoutBuildOptions& options,
    field::Grid& height,
    std::vector<field::Grid>* masks,
    std::string& error
  )
  {
    Ops ops{error};
    const GridPtr likePtr = std::make_shared<Grid>(like);
    const float base = layout.base;
    GridPtr h = ops.Const(likePtr, base);
    if (masks != nullptr) {
      masks->clear();
    }
    for (std::size_t i = 0; i < layout.Layers().size() && h != nullptr; ++i) {
      const LayoutLayer& layer = layout.Layers()[i];
      const int seed = layout.seed + static_cast<int>(i + 1) * 17;
      const GridPtr m = Soften(ops, layout, RawMask(ops, layout, likePtr, layer), SoftOf(layer));
      if (m == nullptr) {
        return false;
      }
      if (masks != nullptr) {
        masks->push_back(*m);
      }
      if (!layer.visible) {
        continue;
      }
      switch (layer.kind) {
      case LayoutKind::Hills: {
        const float rough = layer.P("rough");
        const GridPtr bump =
          ops.Affine(ops.Noise(likePtr, seed, layer.P("scale"), "fbm"), 2.0f * rough, layer.P("height") - rough);
        h = ops.Two("add", h, ops.Two("mul", m, bump));
        break;
      }
      case LayoutKind::Mountains: {
        const float height = layer.P("height");
        const float rough = layer.P("rough");
        const GridPtr ridges =
          ops.Affine(ops.Noise(likePtr, seed, layer.P("scale"), "ridged", 2.2f), height, height * 0.3f);
        const GridPtr detail =
          ops.Affine(ops.Noise(likePtr, seed + 3, layer.P("scale") * 0.6f, "fbm"), 2.0f * rough, -rough);
        field::OpArgs gamma;
        gamma.in["a"] = m;
        gamma.p.num["gamma"] = 1.4;
        h = ops.Two("add", h, ops.Two("mul", ops.Run("gamma", gamma), ops.Two("add", ridges, detail)));
        break;
      }
      case LayoutKind::Plateau: {
        const float rough = layer.P("rough");
        const GridPtr top =
          ops.Affine(ops.Noise(likePtr, seed, layer.P("scale"), "fbm"), 2.0f * rough, base + layer.P("height") - rough);
        h = ops.Lerp(h, top, m);
        break;
      }
      case LayoutKind::Water: {
        const GridPtr bed = ops.Const(likePtr, layout.water - layer.P("depth"));
        h = ops.Two("min", h, ops.Lerp(h, bed, m));
        break;
      }
      case LayoutKind::Valley:
        h = ops.Two("sub", h, ops.Affine(m, layer.P("depth"), 0.0f));
        break;
      case LayoutKind::Flat:
        h = ops.Lerp(h, ops.Const(likePtr, base + layer.P("level")), m);
        break;
      case LayoutKind::Base:
        h = ops.Lerp(h, ops.Const(likePtr, base), m);
        break;
      case LayoutKind::Mask:
        break;
      }
    }
    // Weathering: droplet erosion over the result (Studio's settings for it), on the run's grid.
    if (h != nullptr && options.weather > 0.01f) {
      if (const ErosionSolver* solver = FindErosionSolver("droplet"); solver != nullptr) {
        ErosionValues values = ErosionDefaults(*solver);
        const float w = std::min(1.0f, options.weather);
        const std::map<std::string, double> mine = {
          {"density", 0.3 + 2.5 * w},
          {"lifetime", 70},
          {"inertia", 0.25},
          {"capacity", 6},
          {"erode", 0.45},
          {"deposit", 0.12},
          {"gravity", 5},
          {"thermal", 0.4},
          {"thermal_steps", 3},
          {"talus", 0.9},
          {"drop_vary", 0.6},
          {"radius", 2},
          {"creep", 1.5},
          {"seed", layout.seed + 101},
        };
        for (const auto& [key, value] : mine) {
          if (values.count(key) != 0) {
            values[key] = value;
          }
        }
        field::OpArgs args;
        const int step = std::max(1, static_cast<int>(std::lround(like.cell)));
        for (const auto& [key, value] : ErosionOpValues(*solver, values, step)) {
          args.p.num[key] = value;
        }
        args.in["a"] = h;
        std::map<std::string, Grid> extra;
        args.extra = &extra;
        h = ops.Run(solver->op, args);
      }
    }
    if (h != nullptr && !options.symmetry.empty() && options.symmetry != "none") {
      field::OpArgs sym;
      sym.in["a"] = h;
      sym.p.str["mode"] = options.symmetry;
      sym.p.num["side"] = 0;
      sym.p.str["combine"] = "copy";
      sym.p.num["seam"] = 12;
      sym.p.num["cx"] = options.cx;
      sym.p.num["cz"] = options.cz;
      sym.p.num["n"] = std::clamp(options.turns, 2, 16);
      h = ops.Run("symmetrize", sym);
    }
    if (h == nullptr) {
      return false;
    }
    field::OpArgs clamp;
    clamp.in["a"] = h;
    clamp.p.num["lo"] = 0.0;
    clamp.p.num["hi"] = 400.0;
    const GridPtr result = ops.Run("clamp", clamp);
    if (result == nullptr) {
      return false;
    }
    height = *result;
    return true;
  }
} // namespace faf::editor
