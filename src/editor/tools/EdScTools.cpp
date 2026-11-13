#include "editor/tools/EdScTools.h"

#include "editor/terrain/EdFieldCore.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <memory>
#include <numeric>

namespace faf::editor
{
  namespace
  {
    bool IsStart(
      const std::string& name
    )
    {
      if (name.rfind("ARMY_", 0) != 0 || name.size() == 5) {
        return false;
      }
      return std::all_of(name.begin() + 5, name.end(), [](const char c) {
        return c >= '0' && c <= '9';
      });
    }

    float Distance(
      const Pad& a,
      const Pad& b
    )
    {
      return std::hypot(a.x - b.x, a.z - b.z);
    }

    /** A sub-grid of the heights in map units, samples [x0, x1] x [z0, z1]. */
    std::shared_ptr<field::Grid> HeightGrid(
      const std::uint16_t* heights,
      const int width,
      const float scale,
      const int x0,
      const int z0,
      const int x1,
      const int z1
    )
    {
      auto grid =
        std::make_shared<field::Grid>(x1 - x0 + 1, z1 - z0 + 1, 1.0f, static_cast<float>(x0), static_cast<float>(z0));
      for (int z = z0; z <= z1; ++z) {
        for (int x = x0; x <= x1; ++x) {
          grid->At(x - x0, z - z0) = static_cast<float>(heights[static_cast<std::size_t>(z) * width + x]) * scale;
        }
      }
      return grid;
    }

    std::uint16_t Word(
      const float units,
      const float scale
    )
    {
      return static_cast<std::uint16_t>(std::clamp(std::lround(units / scale), 0L, 65535L));
    }

    bool Run(
      const char* const op,
      field::OpArgs& args,
      field::Grid& out,
      std::string& error
    )
    {
      return field::RunOpCpu(op, args, out, error);
    }
  } // namespace

  std::vector<Pad> CollectPads(
    const std::vector<PadMarker>& markers,
    const PadSettings& settings
  )
  {
    std::vector<PadMarker> sorted = markers;
    std::sort(sorted.begin(), sorted.end(), [](const PadMarker& a, const PadMarker& b) {
      return a.name < b.name;
    });
    std::vector<Pad> starts;
    std::vector<Pad> resources;
    for (const PadMarker& m : sorted) {
      Pad pad;
      pad.name = m.name;
      pad.x = m.x;
      pad.z = m.z;
      if (IsStart(m.name)) {
        if (!settings.startPads) {
          continue;
        }
        pad.kind = Pad::Kind::Start;
        pad.half = settings.startHalf;
        pad.skirt = settings.startSkirt;
        starts.push_back(pad);
      } else if (m.type == "Mass" && settings.massPads) {
        pad.kind = Pad::Kind::Mass;
        pad.half = settings.massHalf;
        pad.skirt = settings.massSkirt;
        resources.push_back(pad);
      } else if (m.type == "Hydrocarbon" && settings.hydroPads) {
        pad.kind = Pad::Kind::Hydro;
        pad.half = settings.hydroHalf;
        pad.skirt = settings.hydroSkirt;
        resources.push_back(pad);
      }
    }
    // Groups: a start and the resources around it (the ring), then clusters of the rest.
    int nextGroup = 0;
    std::vector<std::size_t> free;
    for (std::size_t r = 0; r < resources.size(); ++r) {
      Pad* best = nullptr;
      float bestDistance = settings.ringRadius;
      if (settings.ring) {
        for (Pad& start : starts) {
          const float d = Distance(start, resources[r]);
          if (d <= bestDistance) {
            best = &start;
            bestDistance = d;
          }
        }
      }
      if (best != nullptr) {
        if (best->group == 0) {
          best->group = ++nextGroup;
        }
        resources[r].group = best->group;
      } else {
        free.push_back(r);
      }
    }
    if (settings.cluster) {
      std::vector<std::size_t> parent(free.size());
      std::iota(parent.begin(), parent.end(), std::size_t{0});
      const auto find = [&](std::size_t i) {
        while (parent[i] != i) {
          parent[i] = parent[parent[i]];
          i = parent[i];
        }
        return i;
      };
      for (std::size_t i = 0; i < free.size(); ++i) {
        for (std::size_t j = i + 1; j < free.size(); ++j) {
          const Pad& a = resources[free[i]];
          const Pad& b = resources[free[j]];
          if (a.kind == b.kind && Distance(a, b) <= settings.clusterDist) {
            const std::size_t ra = find(i);
            const std::size_t rb = find(j);
            if (ra != rb) {
              parent[std::max(ra, rb)] = std::min(ra, rb);
            }
          }
        }
      }
      std::vector<int> size(free.size(), 0);
      for (std::size_t i = 0; i < free.size(); ++i) {
        ++size[find(i)];
      }
      std::vector<int> groupOf(free.size(), 0);
      for (std::size_t i = 0; i < free.size(); ++i) {
        const std::size_t root = find(i);
        if (size[root] >= 2) {
          if (groupOf[root] == 0) {
            groupOf[root] = ++nextGroup;
          }
          resources[free[i]].group = groupOf[root];
        }
      }
    }
    std::vector<Pad> out = starts;
    for (const Pad& r : resources) {
      if (r.kind == Pad::Kind::Hydro) {
        out.push_back(r);
      }
    }
    for (const Pad& r : resources) {
      if (r.kind == Pad::Kind::Mass) {
        out.push_back(r);
      }
    }
    return out;
  }

  std::string PadSignature(
    const std::vector<Pad>& pads,
    const PadSettings& s
  )
  {
    std::string text;
    char part[128];
    for (const Pad& p : pads) {
      (void)std::snprintf(
        part,
        sizeof(part),
        "%s:%.2f:%.2f:%d|",
        p.name.c_str(),
        static_cast<double>(p.x),
        static_cast<double>(p.z),
        p.group
      );
      text += part;
    }
    (void)std::snprintf(
      part,
      sizeof(part),
      "#%d%d%d%d%d.%g.%g.%g.%g.%g.%g.%g.%g.%g.%d",
      s.startPads ? 1 : 0,
      s.massPads ? 1 : 0,
      s.hydroPads ? 1 : 0,
      s.ring ? 1 : 0,
      s.cluster ? 1 : 0,
      static_cast<double>(s.startHalf),
      static_cast<double>(s.startSkirt),
      static_cast<double>(s.massHalf),
      static_cast<double>(s.massSkirt),
      static_cast<double>(s.hydroHalf),
      static_cast<double>(s.hydroSkirt),
      static_cast<double>(s.ringRadius),
      static_cast<double>(s.clusterDist),
      static_cast<double>(s.strength),
      s.level
    );
    return text + part;
  }

  int ApplyPads(
    std::uint16_t* const heights,
    const int width,
    const int height,
    const float scale,
    const std::vector<Pad>& pads,
    const PadSettings& settings,
    const PadResult& previous,
    PadResult& result,
    std::string& error
  )
  {
    if (heights == nullptr || width < 2 || height < 2) {
      error = "no heights";
      return -1;
    }
    if (pads.empty()) {
      error = "no start positions or resource markers (or every pad kind is off)";
      return -1;
    }
    // The pads' rect, with the previous result's: taking it off may change ground outside the new pads.
    float fx0 = 1e9f, fz0 = 1e9f, fx1 = -1e9f, fz1 = -1e9f;
    std::vector<double> flat;
    for (const Pad& p : pads) {
      flat.insert(flat.end(), {p.x, p.z, p.half, p.skirt, 0.0, static_cast<double>(p.group)});
      const float r = p.half + p.skirt + 2.0f;
      fx0 = std::min(fx0, p.x - r);
      fz0 = std::min(fz0, p.z - r);
      fx1 = std::max(fx1, p.x + r);
      fz1 = std::max(fz1, p.z + r);
    }
    int x0 = std::clamp(static_cast<int>(std::floor(fx0)), 0, width - 1);
    int z0 = std::clamp(static_cast<int>(std::floor(fz0)), 0, height - 1);
    int x1 = std::clamp(static_cast<int>(std::ceil(fx1)), 0, width - 1);
    int z1 = std::clamp(static_cast<int>(std::ceil(fz1)), 0, height - 1);
    if (!previous.Empty()) {
      x0 = std::min(x0, previous.x0);
      z0 = std::min(z0, previous.z0);
      x1 = std::max(x1, previous.x1);
      z1 = std::max(z1, previous.z1);
    }
    if (x1 <= x0 || z1 <= z0) {
      error = "the pads lie outside the map";
      return -1;
    }
    auto base = HeightGrid(heights, width, scale, x0, z0, x1, z1);
    if (!previous.Empty()) {
      const int pw = previous.x1 - previous.x0 + 1;
      for (int z = previous.z0; z <= previous.z1; ++z) {
        for (int x = previous.x0; x <= previous.x1; ++x) {
          base->At(x - x0, z - z0) -=
            previous.delta[static_cast<std::size_t>(z - previous.z0) * pw + static_cast<std::size_t>(x - previous.x0)];
        }
      }
    }
    field::OpArgs args;
    args.in["a"] = base;
    args.p.arr["pads"] = flat;
    args.p.num["strength"] = settings.strength;
    args.p.num["level"] = settings.level;
    args.p.num["grid"] = 1.0;
    args.p.num["snap"] = 1.0;
    args.p.num["word"] = 1.0 / scale;
    field::Grid flattened;
    if (!Run("pad_flatten", args, flattened, error)) {
      return -1;
    }
    result = PadResult{};
    result.x0 = x0;
    result.z0 = z0;
    result.x1 = x1;
    result.z1 = z1;
    result.signature = PadSignature(pads, settings);
    result.delta.resize(base->Count());
    int changed = 0;
    for (int z = z0; z <= z1; ++z) {
      for (int x = x0; x <= x1; ++x) {
        const std::size_t k = static_cast<std::size_t>(z - z0) * (x1 - x0 + 1) + static_cast<std::size_t>(x - x0);
        // Quantised to a word, and the change measured from the ground without pads.
        const std::uint16_t word = Word(flattened.v[k], scale);
        result.delta[k] = static_cast<float>(word) * scale - base->v[k];
        std::uint16_t& at = heights[static_cast<std::size_t>(z) * width + x];
        changed += at != word ? 1 : 0;
        at = word;
      }
    }
    return changed;
  }

  int RemovePads(
    std::uint16_t* const heights,
    const int width,
    const int height,
    const float scale,
    const PadResult& result
  )
  {
    if (heights == nullptr || result.Empty() || result.x1 >= width || result.z1 >= height) {
      return 0;
    }
    int changed = 0;
    const int w = result.x1 - result.x0 + 1;
    for (int z = result.z0; z <= result.z1; ++z) {
      for (int x = result.x0; x <= result.x1; ++x) {
        std::uint16_t& at = heights[static_cast<std::size_t>(z) * width + x];
        const float d =
          result.delta[static_cast<std::size_t>(z - result.z0) * w + static_cast<std::size_t>(x - result.x0)];
        const std::uint16_t word = Word(static_cast<float>(at) * scale - d, scale);
        changed += at != word ? 1 : 0;
        at = word;
      }
    }
    return changed;
  }

  const std::vector<SlopeClass>& SlopeClasses()
  {
    static const std::vector<SlopeClass> classes = {
      {"Land, small (1x1)", 1},
      {"Land, medium (2x2)", 2},
      {"Land, large (3x3)", 3},
      {"Experimental (5x5)", 5},
    };
    return classes;
  }

  std::vector<float> BlockedShares(
    const std::uint16_t* const heights,
    const int width,
    const int height,
    const float scale,
    const float limit
  )
  {
    std::vector<float> shares;
    if (heights == nullptr || width < 2 || height < 2) {
      return shares;
    }
    const auto h = HeightGrid(heights, width, scale, 0, 0, width - 1, height - 1);
    for (const SlopeClass& cls : SlopeClasses()) {
      field::OpArgs args;
      args.in["a"] = h;
      args.p.str["mode"] = "rating";
      args.p.num["window"] = cls.window;
      field::Grid rating;
      std::string error;
      if (!Run("slope", args, rating, error) || rating.v.empty()) {
        shares.push_back(0.0f);
        continue;
      }
      std::size_t blocked = 0;
      for (const float v : rating.v) {
        blocked += v > limit ? 1u : 0u;
      }
      shares.push_back(static_cast<float>(blocked) / static_cast<float>(rating.v.size()));
    }
    return shares;
  }

  int LimitSlopes(
    std::uint16_t* const heights,
    const int width,
    const int height,
    const float scale,
    const SlopeLimitSettings& settings,
    std::string& error
  )
  {
    if (heights == nullptr || width < 2 || height < 2) {
      error = "no heights";
      return -1;
    }
    field::OpArgs args;
    args.in["a"] = HeightGrid(heights, width, scale, 0, 0, width - 1, height - 1);
    args.p.num["limit"] = settings.limit;
    args.p.str["mode"] = settings.mode;
    args.p.num["balance"] = settings.balance;
    args.p.num["margin"] = settings.margin;
    args.p.num["strength"] = settings.strength;
    field::Grid out;
    if (!Run("slope_limit", args, out, error)) {
      return -1;
    }
    int changed = 0;
    for (std::size_t k = 0; k < out.v.size(); ++k) {
      const std::uint16_t word = Word(out.v[k], scale);
      changed += heights[k] != word ? 1 : 0;
      heights[k] = word;
    }
    return changed;
  }

  RampReport RampProfile(
    const std::uint16_t* const heights,
    const int width,
    const int height,
    const float scale,
    const std::vector<std::pair<float, float>>& points,
    float step,
    float run,
    const float limit
  )
  {
    RampReport report;
    if (heights == nullptr || points.size() < 2) {
      return report;
    }
    step = std::max(0.25f, step);
    run = std::max(step, run);
    // The ground's bilinear height at (x, z).
    const auto sample = [&](float x, float z) {
      x = std::clamp(x, 0.0f, static_cast<float>(width - 1));
      z = std::clamp(z, 0.0f, static_cast<float>(height - 1));
      const int i = std::min(width - 2, static_cast<int>(x));
      const int j = std::min(height - 2, static_cast<int>(z));
      const float fx = x - static_cast<float>(i);
      const float fz = z - static_cast<float>(j);
      const auto h = [&](const int a, const int b) {
        return static_cast<float>(heights[static_cast<std::size_t>(b) * width + a]) * scale;
      };
      return (h(i, j) * (1.0f - fx) + h(i + 1, j) * fx) * (1.0f - fz) +
        (h(i, j + 1) * (1.0f - fx) + h(i + 1, j + 1) * fx) * fz;
    };
    std::vector<float> xs, zs, hs, ss;
    float distance = 0.0f;
    report.minHeight = 1e9f;
    report.maxHeight = -1e9f;
    const auto add = [&](const float x, const float z, const float s) {
      const float h = sample(x, z);
      xs.push_back(x);
      zs.push_back(z);
      hs.push_back(h);
      ss.push_back(s);
      report.minHeight = std::min(report.minHeight, h);
      report.maxHeight = std::max(report.maxHeight, h);
    };
    add(points[0].first, points[0].second, 0.0f);
    for (std::size_t i = 1; i < points.size(); ++i) {
      const auto [ax, az] = points[i - 1];
      const auto [bx, bz] = points[i];
      const float length = std::hypot(bx - ax, bz - az);
      const int n = std::max(1, static_cast<int>(std::ceil(length / step)));
      for (int k = 1; k <= n; ++k) {
        const float t = static_cast<float>(k) / static_cast<float>(n);
        add(ax + (bx - ax) * t, az + (bz - az) * t, distance + length * t);
      }
      distance += length;
    }
    report.length = distance;
    const std::size_t n = xs.size();
    float sum = 0.0f;
    float overLength = 0.0f;
    RampReport::Run* current = nullptr;
    for (std::size_t i = 0; i < n; ++i) {
      // The grade over a window centred on the sample, clipped at the ends.
      std::size_t j0 = i, j1 = i;
      while (j0 > 0 && ss[i] - ss[j0] < run * 0.5f) {
        --j0;
      }
      while (j1 + 1 < n && ss[j1] - ss[i] < run * 0.5f) {
        ++j1;
      }
      const float d = ss[j1] - ss[j0];
      const float grade = d > 0.0f ? std::fabs(hs[j1] - hs[j0]) / d : 0.0f;
      report.maxGrade = std::max(report.maxGrade, grade);
      sum += grade;
      const float length = i + 1 < n ? ss[i + 1] - ss[i] : 0.0f;
      if (grade > limit) {
        overLength += length;
        if (current == nullptr) {
          report.runs.push_back({ss[i], ss[i], xs[i], zs[i], grade});
          current = &report.runs.back();
        }
        current->to = ss[i];
        if (grade > current->grade) {
          current->grade = grade;
          current->x = xs[i];
          current->z = zs[i];
        }
      } else {
        current = nullptr;
      }
    }
    report.meanGrade = n > 0 ? sum / static_cast<float>(n) : 0.0f;
    report.over = distance > 0.0f ? overLength / distance : 0.0f;
    return report;
  }
} // namespace faf::editor
