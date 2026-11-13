#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * The Erosion window (the consolidated design's Terrain > Erosion; FAF Studio's erosion.lua): three solvers of the
   * field library (terrain/EdErosion.cpp: erode_hydraulic, erode_droplet, erode_stream) with their settings, six
   * presets, a coarse preview on the map and a full-resolution Apply.
   */
  struct ErosionParam
  {
    const char* key;
    const char* label;
    double min;
    double max;
    double step;
    const char* format;
    double fallback; // the default
    const char* tip;
  };

  struct ErosionSolver
  {
    const char* id;    // "hydraulic", "droplet", "stream"
    const char* op;    // the field op
    const char* label; // "Hydraulic (grid)"
    std::vector<ErosionParam> params;
  };

  struct ErosionPreset
  {
    const char* id;
    const char* label;
    const char* solver;
    std::map<std::string, double> values; // the ones that differ from the solver's defaults
  };

  /** The three solvers, each with its own settings and the ones they share (variation, ridges, range, volume). */
  [[nodiscard]] const std::vector<ErosionSolver>& ErosionSolvers();
  [[nodiscard]] const ErosionSolver* FindErosionSolver(const std::string& id);
  /** Mountain, Hills, Canyon, Alpine, Desert, River valley. */
  [[nodiscard]] const std::vector<ErosionPreset>& ErosionPresets();

  using ErosionValues = std::map<std::string, double>;
  /** A solver's settings at their defaults. */
  [[nodiscard]] ErosionValues ErosionDefaults(const ErosionSolver& solver);
  /** A preset's settings: the solver's defaults with the preset's own on top. */
  [[nodiscard]] ErosionValues ErosionPresetValues(const ErosionPreset& preset);

  /**
   * The op's settings for a run on every `step`-th sample: the coarse grid moves water and droplets `step` times
   * further per iteration, so iterations, rain, rates, lifetime, radius and density are scaled to give much the same
   * result at a fraction of the cost (Studio's OpParams).
   */
  [[nodiscard]] ErosionValues ErosionOpValues(const ErosionSolver& solver, const ErosionValues& values, int step);

  /** The preview's step: the smallest that keeps the coarse grid within `most` samples a side, one dividing the map's
   * cells when one of the next three does. */
  [[nodiscard]] int ErosionPreviewStep(int width, int height, int most = 257);

  /**
   * The solver run on height words (`width` x `height`, `scale` map units a word, as the height field keeps them),
   * written back in place. Step 1 is the full run; a larger step runs every step-th sample and adds the change it
   * made, upsampled, to the full heights (the terrain's fine detail stays). False with `error` when the op fails.
   */
  /**
   * What a full run leaves besides the heights, each 0..1 over the map's samples (`width` x `height`): where ground was
   * worn away, where sediment settled, where water ran, and the drainage (where rivers gather). Wear and deposit are
   * scaled to their mean plus three deviations and curved by 0.7, flow by 0.5 (Studio's Normalised); the drainage is
   * the solver's own 0..1. A list is empty when the solver made none.
   */
  struct ErosionMasks
  {
    std::vector<float> wear;
    std::vector<float> deposit;
    std::vector<float> flow;
    std::vector<float> accum;
  };

  /** Raw amounts as a 0..1 mask: over their mean plus three deviations, clamped, then to the power `gamma`. */
  [[nodiscard]] std::vector<float> ErosionNormalised(const std::vector<float>& raw, float gamma);

  bool ErodeHeights(
    std::uint16_t* heights,
    int width,
    int height,
    float scale,
    const ErosionSolver& solver,
    const ErosionValues& values,
    int step,
    std::string& error,
    ErosionMasks* masks = nullptr
  );
} // namespace faf::editor
