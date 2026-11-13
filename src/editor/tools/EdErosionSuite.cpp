#include "editor/tools/EdErosionSuite.h"

#include "editor/terrain/EdFieldCore.h"

#include <algorithm>
#include <cmath>
#include <memory>

namespace faf::editor
{
  namespace
  {
    /** The settings every solver shares: they add variation and keep the terrain's character. */
    std::vector<ErosionParam> Shared()
    {
      return {
        {"vary",
         "Hardness variation",
         0,
         1,
         0.05,
         "%.2f",
         0.4,
         "Hard and soft ground side by side: the erodibility follows a noise pattern, so the erosion is uneven "
         "instead of the same everywhere. 0 = uniform."},
        {"vary_scale",
         "Hardness feature size (units)",
         8,
         400,
         2,
         "%.0f",
         60,
         "Size of the hard and soft patches, and of the rain variation, in map units."},
        {"rain_vary",
         "Rain variation",
         0,
         1,
         0.05,
         "%.2f",
         0.5,
         "The water differs from place to place, so channels and gullies come in different sizes. 0 = even rain."},
        {"protect",
         "Protect ridges",
         0,
         1,
         0.05,
         "%.2f",
         0.5,
         "Ridges and summits are harder than the slopes: they keep their height and shape while the flanks are carved."},
        {"keep_range",
         "Keep height range (0 / 1)",
         0,
         1,
         1,
         "%.0f",
         1,
         "1 = the result is stretched so its lowest and highest ground match the input again."},
        {"max_change",
         "Largest change (units, 0 = off)",
         0,
         80,
         0.5,
         "%.1f",
         0,
         "No sample moves further than this from the input height, up or down. 0 = unlimited."},
        {"conserve",
         "Keep volume",
         0,
         1,
         0.05,
         "%.2f",
         0,
         "Puts the share of the removed material that left the map back where sediment settles, so the terrain keeps "
         "its mass. 0 = off."},
      };
    }

    std::vector<ErosionSolver> MakeSolvers()
    {
      std::vector<ErosionSolver> solvers = {
        {"hydraulic",
         "erode_hydraulic",
         "Hydraulic (grid)",
         {
           {"iterations", "Iterations", 10, 2000, 10, "%.0f", 60, nullptr},
           {"rain", "Rain per step (units)", 0.0005, 0.05, 0.0005, "%.4f", 0.004, nullptr},
           {"evaporation", "Evaporation", 0.002, 0.15, 0.002, "%.3f", 0.02, nullptr},
           {"gain", "Water speed (pipe gain)", 0.01, 0.25, 0.01, "%.2f", 0.08, nullptr},
           {"capacity", "Sediment capacity", 0.05, 4, 0.05, "%.2f", 1, nullptr},
           {"erosion", "Dissolving rate", 0.01, 0.6, 0.01, "%.2f", 0.08, nullptr},
           {"deposition", "Settling rate", 0.01, 0.6, 0.01, "%.2f", 0.05, nullptr},
           {"depth_max", "Full capacity depth (units)", 0.01, 0.5, 0.01, "%.2f", 0.05, nullptr},
           {"min_slope", "Minimum slope", 0, 0.2, 0.005, "%.3f", 0.02, nullptr},
           {"cut_limit", "Cut limit (0 = off)", 0, 1, 0.05, "%.2f", 0.5, nullptr},
           {"thermal", "Thermal slides", 0, 1, 0.05, "%.2f", 0, nullptr},
           {"talus", "Talus (rise / run)", 0.1, 2, 0.05, "%.2f", 0.8, nullptr},
           {"thermal_every", "Slide every n steps", 1, 10, 1, "%.0f", 2, nullptr},
           {"smooth", "Cell noise filter", 0, 1, 0.05, "%.2f", 1, nullptr},
           {"smooth_passes", "Filter passes", 0, 4, 1, "%.0f", 1, nullptr},
           {"seed", "Seed", 0, 9999, 1, "%.0f", 1, "The random seed of the hardness and rain variation."},
         }},
        {"droplet",
         "erode_droplet",
         "Droplets (particles)",
         {
           {"density", "Droplets per cell", 0.05, 8, 0.05, "%.2f", 2, nullptr},
           {"lifetime", "Droplet life (steps)", 5, 120, 1, "%.0f", 40, nullptr},
           {"inertia", "Inertia", 0, 0.5, 0.01, "%.2f", 0.05, nullptr},
           {"capacity", "Sediment capacity", 0.5, 16, 0.25, "%.2f", 4, nullptr},
           {"erode", "Dissolving rate", 0.02, 1, 0.02, "%.2f", 0.3, nullptr},
           {"deposit", "Settling rate", 0.02, 1, 0.02, "%.2f", 0.3, nullptr},
           {"evaporate", "Evaporation", 0, 0.1, 0.005, "%.3f", 0.01, nullptr},
           {"gravity", "Gravity", 0.5, 16, 0.5, "%.1f", 4, nullptr},
           {"radius", "Erosion radius (cells)", 1, 6, 1, "%.0f", 3, nullptr},
           {"min_slope", "Minimum slope", 0, 0.2, 0.005, "%.3f", 0.01, nullptr},
           {"drain_pits", "Drain basins (0 = fill them)", 0, 1, 1, "%.0f", 1, nullptr},
           {"thermal", "Thermal slides", 0, 1, 0.05, "%.2f", 0, nullptr},
           {"thermal_steps", "Slide steps", 0, 50, 1, "%.0f", 0, nullptr},
           {"talus", "Talus (rise / run)", 0.1, 2, 0.05, "%.2f", 0.8, nullptr},
           {"smooth", "Cell noise filter", 0, 1, 0.05, "%.2f", 1, nullptr},
           {"smooth_passes", "Filter passes", 0, 4, 1, "%.0f", 1, nullptr},
           {"seed", "Seed", 0, 9999, 1, "%.0f", 1, nullptr},
           {"accel",
            "Downhill acceleration",
            0,
            1,
            0.05,
            "%.2f",
            1,
            "How much a drop speeds up going downhill. 1 = like a real drop (fast on steep ground, so it digs there)."},
           {"drop_vary",
            "Droplet variation",
            0,
            1,
            0.05,
            "%.2f",
            0.5,
            "Every drop gets its own size, lifetime, inertia and load, so the gullies are not evenly spaced copies."},
           {"creep",
            "Hillslope creep",
            0,
            8,
            0.1,
            "%.1f",
            2,
            "After every round the ground slumps a little, so grooves widen into rounded valleys. 0 = off."},
           {"rounds",
            "Feedback rounds",
            1,
            64,
            1,
            "%.0f",
            32,
            "The droplets fall in this many rounds; later drops follow the valleys earlier ones dug."},
         }},
        {"stream",
         "erode_stream",
         "Stream power (rivers)",
         {
           {"iterations", "Iterations", 1, 60, 1, "%.0f", 20, nullptr},
           {"k",
            "Erodibility",
            0.01,
            4,
            0.01,
            "%.2f",
            0.05,
            "Rivers cut faster the bigger their catchment. Low = only big rivers cut, high = every channel cuts."},
           {"m", "Drainage exponent", 0.1, 1, 0.05, "%.2f", 0.5, nullptr},
           {"area_min", "Smallest river (catchment cells)", 1, 600, 1, "%.0f", 40, nullptr},
           {"spread", "Flow spreading (low = wide)", 0.3, 4, 0.1, "%.1f", 1, nullptr},
           {"max_cut", "Cut per step (share)", 0.05, 1, 0.05, "%.2f", 0.5, nullptr},
           {"widen", "Channel widening", 0, 6, 1, "%.0f", 1, nullptr},
           {"width_vary",
            "Valley width growth",
            0,
            1,
            0.05,
            "%.2f",
            1,
            "Bigger rivers get wider valleys; small streams stay narrow gullies."},
           {"route_every",
            "Recompute rivers every n steps",
            1,
            8,
            1,
            "%.0f",
            3,
            "The drainage network is rebuilt this often; 3 is nearly identical to 1 at a third of the time."},
           {"diffusion", "Hillslope diffusion", 0, 1, 0.05, "%.2f", 0.2, nullptr},
           {"talus", "Talus (rise / run)", 0.1, 2, 0.05, "%.2f", 0.7, nullptr},
           {"uplift", "Uplift per step (units)", 0, 2, 0.05, "%.2f", 0, nullptr},
           {"seed", "Seed", 0, 9999, 1, "%.0f", 1, "The random seed of the flow jitter and the variation."},
           {"jitter",
            "Flow jitter",
            0,
            1.5,
            0.05,
            "%.2f",
            0.4,
            "The water is routed over the ground plus a little smooth noise: rivers branch and bend."},
         }},
      };
      for (ErosionSolver& solver : solvers) {
        for (const ErosionParam& shared : Shared()) {
          solver.params.push_back(shared);
        }
      }
      return solvers;
    }
  } // namespace

  const std::vector<ErosionSolver>& ErosionSolvers()
  {
    static const std::vector<ErosionSolver> solvers = MakeSolvers();
    return solvers;
  }

  const ErosionSolver* FindErosionSolver(
    const std::string& id
  )
  {
    for (const ErosionSolver& solver : ErosionSolvers()) {
      if (id == solver.id) {
        return &solver;
      }
    }
    return nullptr;
  }

  const std::vector<ErosionPreset>& ErosionPresets()
  {
    // Studio's presets: the values that give each its look; the rest are the solver's defaults.
    static const std::vector<ErosionPreset> presets = {
      {"mountain",
       "Mountain",
       "droplet",
       {{"density", 3},
        {"lifetime", 60},
        {"inertia", 0.3},
        {"capacity", 8},
        {"erode", 0.45},
        {"deposit", 0.15},
        {"gravity", 5},
        {"thermal", 0.4},
        {"thermal_steps", 3},
        {"talus", 0.9},
        {"vary", 0.55},
        {"protect", 0.7},
        {"drop_vary", 0.6},
        {"creep", 1},
        {"max_change", 25}}},
      {"hills",
       "Hills",
       "hydraulic",
       {{"iterations", 100}, {"rain", 0.006}, {"deposition", 0.08}, {"thermal", 0.25}, {"talus", 0.9}}},
      {"canyon",
       "Canyon",
       "stream",
       {{"iterations", 14},
        {"k", 1.5},
        {"max_cut", 0.7},
        {"diffusion", 0.05},
        {"widen", 2},
        {"talus", 1.2},
        {"area_min", 40},
        {"jitter", 0.3},
        {"protect", 0.6},
        {"vary", 0.5}}},
      {"alpine",
       "Alpine",
       "droplet",
       {{"density", 2.5},
        {"lifetime", 80},
        {"inertia", 0.2},
        {"capacity", 6},
        {"erode", 0.4},
        {"deposit", 0.05},
        {"gravity", 6},
        {"thermal", 0.6},
        {"thermal_steps", 6},
        {"talus", 0.7},
        {"vary", 0.6},
        {"protect", 0.8},
        {"drop_vary", 0.7},
        {"creep", 0.75},
        {"max_change", 30}}},
      {"desert",
       "Desert",
       "droplet",
       {{"density", 0.6},
        {"lifetime", 60},
        {"capacity", 6},
        {"erode", 0.4},
        {"deposit", 0.2},
        {"thermal", 0.6},
        {"thermal_steps", 6},
        {"talus", 0.7},
        {"vary", 0.3},
        {"rain_vary", 0.8},
        {"protect", 0.3},
        {"drop_vary", 0.8}}},
      {"river",
       "River valley",
       "stream",
       {{"iterations", 20},
        {"k", 0.5},
        {"m", 0.5},
        {"diffusion", 0.3},
        {"widen", 2},
        {"area_min", 60},
        {"talus", 0.5},
        {"jitter", 0.5},
        {"vary", 0.3},
        {"protect", 0.3}}},
    };
    return presets;
  }

  ErosionValues ErosionDefaults(
    const ErosionSolver& solver
  )
  {
    ErosionValues values;
    for (const ErosionParam& param : solver.params) {
      values[param.key] = param.fallback;
    }
    return values;
  }

  ErosionValues ErosionPresetValues(
    const ErosionPreset& preset
  )
  {
    const ErosionSolver* const solver = FindErosionSolver(preset.solver);
    ErosionValues values = solver != nullptr ? ErosionDefaults(*solver) : ErosionValues{};
    for (const auto& [key, value] : preset.values) {
      values[key] = value;
    }
    return values;
  }

  ErosionValues ErosionOpValues(
    const ErosionSolver& solver,
    const ErosionValues& values,
    const int step
  )
  {
    ErosionValues p = values;
    const auto get = [&](const char* key, const double fallback) {
      const auto found = p.find(key);
      return found != p.end() ? found->second : fallback;
    };
    if (step > 1) {
      const double s = static_cast<double>(step);
      const std::string id = solver.id;
      if (id == "hydraulic") {
        p["iterations"] = std::max(10.0, std::floor(get("iterations", 60) / s + 0.5));
        p["rain"] = get("rain", 0.004) * s;
        p["erosion"] = std::min(0.9, get("erosion", 0.08) * s);
        p["deposition"] = std::min(0.9, get("deposition", 0.05) * s);
      } else if (id == "droplet") {
        p["lifetime"] = std::max(5.0, std::floor(get("lifetime", 40) / s + 0.5));
        p["radius"] = std::max(1.0, std::floor(get("radius", 3) / s + 0.5));
        p["density"] = std::max(0.05, get("density", 2) / (1.5 * s));
        p["thermal_steps"] = std::max(0.0, std::floor(get("thermal_steps", 0) / s + 0.5));
        p["creep"] = get("creep", 2) * 1.5 / s;
      }
      if (id != "stream") {
        p["smooth_passes"] = step >= 4 ? 0.0 : std::max(0.0, get("smooth_passes", 1) - 1.0);
      }
      p["masks"] = 0; // a preview needs no wear, deposit or flow
    }
    return p;
  }

  int ErosionPreviewStep(
    const int width,
    const int height,
    const int most
  )
  {
    const int span = std::max(width, height) - 1;
    int step = 1;
    while (span / step + 1 > most) {
      ++step;
    }
    for (int s = step; s <= step + 3; ++s) {
      if ((width - 1) % s == 0 && (height - 1) % s == 0) {
        return s;
      }
    }
    return step;
  }

  bool ErodeHeights(
    std::uint16_t* const heights,
    const int width,
    const int height,
    const float scale,
    const ErosionSolver& solver,
    const ErosionValues& values,
    int step,
    std::string& error
  )
  {
    if (heights == nullptr || width < 3 || height < 3 || !(scale > 0.0f)) {
      error = "no heights";
      return false;
    }
    step = std::max(1, step);
    const int cw = (width - 1) / step + 1;
    const int ch = (height - 1) / step + 1;
    auto base = std::make_shared<field::Grid>(cw, ch, static_cast<float>(step), 0.0f, 0.0f);
    for (int j = 0; j < ch; ++j) {
      const int z = std::min(height - 1, j * step);
      for (int i = 0; i < cw; ++i) {
        const int x = std::min(width - 1, i * step);
        base->At(i, j) = static_cast<float>(heights[static_cast<std::size_t>(z) * width + x]) * scale;
      }
    }
    field::OpArgs args;
    for (const auto& [key, value] : ErosionOpValues(solver, values, step)) {
      args.p.num[key] = value;
    }
    args.in["a"] = base;
    std::map<std::string, field::Grid> extra;
    args.extra = &extra;
    field::Grid out;
    if (!field::RunOpCpu(solver.op, args, out, error)) {
      return false;
    }
    if (out.w != cw || out.h != ch) {
      error = "the solver gave a grid of another size";
      return false;
    }
    const auto toWord = [scale](const float units) {
      return static_cast<std::uint16_t>(std::clamp(std::lround(units / scale), 0L, 65535L));
    };
    if (step == 1) {
      for (std::size_t k = 0; k < out.v.size(); ++k) {
        heights[k] = toWord(out.v[k]);
      }
      return true;
    }
    // A coarse run: its change, upsampled (bilinear), on top of the full heights.
    for (int z = 0; z < height; ++z) {
      const float v = std::min(static_cast<float>(ch - 1), static_cast<float>(z) / static_cast<float>(step));
      const int j0 = std::min(ch - 2, static_cast<int>(v));
      const float fv = v - static_cast<float>(j0);
      for (int x = 0; x < width; ++x) {
        const float u = std::min(static_cast<float>(cw - 1), static_cast<float>(x) / static_cast<float>(step));
        const int i0 = std::min(cw - 2, static_cast<int>(u));
        const float fu = u - static_cast<float>(i0);
        const auto d = [&](const int i, const int j) {
          return out.At(i, j) - base->At(i, j);
        };
        const float change = (d(i0, j0) * (1.0f - fu) + d(i0 + 1, j0) * fu) * (1.0f - fv) +
          (d(i0, j0 + 1) * (1.0f - fu) + d(i0 + 1, j0 + 1) * fu) * fv;
        std::uint16_t& word = heights[static_cast<std::size_t>(z) * width + x];
        word = toWord(static_cast<float>(word) * scale + change);
      }
    }
    return true;
  }
} // namespace faf::editor
