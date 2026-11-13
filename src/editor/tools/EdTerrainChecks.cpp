#include "editor/tools/EdTerrainChecks.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <memory>

namespace faf::editor
{
  namespace
  {
    bool Op(
      const char* name,
      field::OpArgs& args,
      field::Grid& out
    )
    {
      std::string error;
      return field::RunOpCpu(name, args, out, error);
    }

    field::GridPtr Shared(
      const field::Grid& grid
    )
    {
      return std::make_shared<field::Grid>(grid);
    }

    /** A grid's value at the sample nearest (x, z), or the first value `accept` takes within `radius` samples, nearest
     * first; false when none. */
    template <typename Accept>
    bool Nearest(
      const field::Grid& g,
      const float x,
      const float z,
      const int radius,
      Accept accept,
      float& value
    )
    {
      const int cx = static_cast<int>(std::floor(x + 0.5f));
      const int cz = static_cast<int>(std::floor(z + 0.5f));
      float best = 1e30f;
      bool found = false;
      for (int j = std::max(0, cz - radius); j <= std::min(g.h - 1, cz + radius); ++j) {
        for (int i = std::max(0, cx - radius); i <= std::min(g.w - 1, cx + radius); ++i) {
          const float v = g.At(i, j);
          const float d = static_cast<float>((i - cx) * (i - cx) + (j - cz) * (j - cz));
          if (accept(v) && d < best) {
            best = d;
            value = v;
            found = true;
          }
        }
      }
      return found;
    }
  } // namespace

  std::vector<CheckIssue> CheckTerrainGround(
    const field::Grid& heights,
    const std::vector<TerrainCheckPoint>& starts,
    const std::vector<TerrainCheckPoint>& resources,
    const TerrainCheckSettings& s
  )
  {
    std::vector<CheckIssue> issues;
    if (heights.w < 3 || heights.h < 3) {
      return issues;
    }
    const field::GridPtr h = Shared(heights);
    // Steep ground: the engine's rating over the footprint, above the limit.
    field::OpArgs ratingArgs;
    ratingArgs.in["a"] = h;
    ratingArgs.p.str["mode"] = "rating";
    ratingArgs.p.num["window"] = s.window;
    field::Grid rating;
    if (!Op("slope", ratingArgs, rating)) {
      return issues;
    }
    const float radius = std::max(2.0f, s.startRadius);
    for (const TerrainCheckPoint& start : starts) {
      int all = 0;
      int blocked = 0;
      const int r = static_cast<int>(std::ceil(radius));
      const int cx = static_cast<int>(std::floor(start.x + 0.5f));
      const int cz = static_cast<int>(std::floor(start.z + 0.5f));
      for (int j = std::max(0, cz - r); j <= std::min(rating.h - 1, cz + r); ++j) {
        for (int i = std::max(0, cx - r); i <= std::min(rating.w - 1, cx + r); ++i) {
          if (static_cast<float>((i - cx) * (i - cx) + (j - cz) * (j - cz)) <= radius * radius) {
            ++all;
            blocked += rating.At(i, j) > s.limit ? 1 : 0;
          }
        }
      }
      const float share = all > 0 ? static_cast<float>(blocked) / static_cast<float>(all) : 0.0f;
      if (share > s.blockedShare) {
        CheckIssue issue;
        issue.level = CheckIssue::Level::Warning;
        issue.marker = start.name;
        issue.x = start.x;
        issue.z = start.z;
        char text[160];
        (void)std::snprintf(
          text,
          sizeof(text),
          "%.0f%% of the base area (radius %.0f) is too steep for land units (%d x %d)",
          static_cast<double>(share * 100.0f),
          static_cast<double>(radius),
          s.window,
          s.window
        );
        issue.text = text;
        issues.push_back(std::move(issue));
      }
    }
    // Under the resources: the structure rule's ground variation over a 2 x 2 footprint, 1.1 at most.
    field::OpArgs variationArgs;
    variationArgs.in["a"] = h;
    variationArgs.p.str["mode"] = "variation";
    variationArgs.p.num["window"] = 2;
    field::Grid variation;
    if (!Op("slope", variationArgs, variation)) {
      return issues;
    }
    for (const TerrainCheckPoint& resource : resources) {
      float worst = 0.0f;
      const int cx = static_cast<int>(std::floor(resource.x));
      const int cz = static_cast<int>(std::floor(resource.z));
      for (int j = std::max(0, cz - 1); j <= std::min(variation.h - 1, cz + 1); ++j) {
        for (int i = std::max(0, cx - 1); i <= std::min(variation.w - 1, cx + 1); ++i) {
          worst = std::max(worst, variation.At(i, j));
        }
      }
      if (worst > 1.1f) {
        CheckIssue issue;
        issue.level = CheckIssue::Level::Warning;
        issue.marker = resource.name;
        issue.x = resource.x;
        issue.z = resource.z;
        char text[160];
        (void)std::snprintf(
          text,
          sizeof(text),
          "the ground under the structure varies by %.2f (a structure takes 1.1 at most)",
          static_cast<double>(worst)
        );
        issue.text = text;
        issues.push_back(std::move(issue));
      }
    }
    return issues;
  }

  std::vector<CheckIssue> CheckTerrainRoutes(
    const field::Grid& heights,
    const float water,
    const std::vector<TerrainCheckPoint>& starts,
    const TerrainCheckSettings& s
  )
  {
    std::vector<CheckIssue> issues;
    if (heights.w < 3 || heights.h < 3 || starts.size() < 2) {
      return issues;
    }
    const field::GridPtr h = Shared(heights);
    // The ground land units cross: the rating within the limit, the water no deeper than they wade.
    field::OpArgs ratingArgs;
    ratingArgs.in["a"] = h;
    ratingArgs.p.str["mode"] = "rating";
    ratingArgs.p.num["window"] = s.window;
    field::Grid rating;
    if (!Op("slope", ratingArgs, rating)) {
      return issues;
    }
    auto passable = std::make_shared<field::Grid>(rating);
    for (std::size_t k = 0; k < passable->v.size(); ++k) {
      const bool dry = heights.v[k] >= water - s.wade;
      passable->v[k] = rating.v[k] <= s.limit && dry ? 1.0f : 0.0f;
    }
    field::OpArgs regionArgs;
    regionArgs.in["a"] = passable;
    field::Grid labels;
    if (!Op("regions", regionArgs, labels)) {
      return issues;
    }
    const auto onGround = [](const float v) {
      return v > 0.5f;
    };
    float first = 0.0f;
    if (!Nearest(labels, starts[0].x, starts[0].z, 6, onGround, first)) {
      return issues; // the pathing check says the first start stands on ground land units can't cross
    }
    field::OpArgs reachArgs;
    reachArgs.in["a"] = passable;
    reachArgs.p.arr["src"] = {starts[0].x, starts[0].z};
    reachArgs.p.num["snap"] = 6;
    field::Grid distance;
    if (!Op("reach", reachArgs, distance)) {
      return issues;
    }
    for (std::size_t i = 1; i < starts.size(); ++i) {
      const TerrainCheckPoint& to = starts[i];
      float label = 0.0f;
      if (!Nearest(labels, to.x, to.z, 6, onGround, label) || label != first) {
        continue; // separate ground: the pathing check reports it
      }
      float route = 0.0f;
      if (!Nearest(distance, to.x, to.z, 6, [](const float v) {
        return v >= 0.0f;
      }, route)) {
        continue;
      }
      const float straight = std::hypot(to.x - starts[0].x, to.z - starts[0].z);
      const float ratio = straight > 1.0f ? route / straight : 1.0f;
      CheckIssue issue;
      issue.level = ratio > s.detour ? CheckIssue::Level::Warning : CheckIssue::Level::Note;
      issue.marker = to.name;
      issue.x = to.x;
      issue.z = to.z;
      char text[200];
      (void)std::snprintf(
        text,
        sizeof(text),
        "route from %s by land: %.0f units, straight %.0f (x%.2f)%s",
        starts[0].name.c_str(),
        static_cast<double>(route),
        static_cast<double>(straight),
        static_cast<double>(ratio),
        ratio > s.detour ? ": a long detour" : ""
      );
      issue.text = text;
      issues.push_back(std::move(issue));
    }
    return issues;
  }
} // namespace faf::editor
