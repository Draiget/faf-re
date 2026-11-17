#pragma once

// The detail pass (FAF Studio's detail.lua, GRAPH_TEXTURING.md "Operation Citadel"): the small things on top of the
// painted map, in classes by size and slope. Operation Citadel carries 12,625 props and 971 decals on 20 km; measured
// against the slope under them: small rocks at about 4 degrees in clusters, big cliff rocks at 16 degrees, crevice
// decals of 25 units on gentle ground, rock ground decals of 36 units on steeper ground. Each class is one scatter run
// with its own entries (the environment's props and decals that exist), slope window, clustering noise and density per
// 1,000 square units. Measure reads the same numbers off a map that is already detailed (a reference).
//
// Engine independent (tests/editor/DetailPassTests.cpp).

#include "editor/terrain/EdFieldCore.h"
#include "editor/tools/EdMaskGen.h"

#include <expected>
#include <functional>
#include <string>
#include <vector>

namespace faf::editor
{
  struct DetailClass
  {
    std::string id;
    std::string label;
    bool decals = false;
    float slopeMin = 0.0f; // degrees
    float slopeMax = 90.0f;
    float per1000 = 1.0f; // how many per 1,000 square units at density 1
    float minDist = 6.0f;
    float scaleMin = 1.0f; // share of the model's size (decals: of decalSize)
    float scaleMax = 1.0f;
    float decalSize = 0.0f;
    /** Clustering: noise of `clusterSize` units whose top `clusterShare` of the map takes the density. */
    float clusterSize = 70.0f;
    float clusterShare = 0.5f;
    /** Along the water (stones): the drainage network between these flow values; 0, 0: no. */
    float flowFrom = 0.0f;
    float flowTo = 0.0f;
    /** The paths that exist (prop blueprints or decal textures). */
    std::vector<std::string> entries;
  };

  /** The environments with their props and decals (Studio's Sets): id and label. */
  struct DetailEnvironment
  {
    const char* id;
    const char* label;
  };
  [[nodiscard]] const std::vector<DetailEnvironment>& DetailEnvironments();
  /** The environment a map most likely is, from its layers' textures (`/env/<name>/...`); "evergreen" when unsure. */
  [[nodiscard]] std::string GuessDetailEnvironment(const std::vector<std::string>& layerTextures);

  /**
   * The classes of an environment with the entries that exist: prop names resolved by `findProp(group, name)` (the
   * blueprint path or empty), decal textures kept when `exists(path)`. Classes without an entry are left out.
   */
  [[nodiscard]] std::vector<DetailClass> DetailClasses(
    const std::string& environment,
    const std::function<std::string(const std::string&, const std::string&)>& findProp,
    const std::function<bool(const std::string&)>& exists
  );
  /** A blueprint path among `blueprints` in `/env/<group>/` named `<name>_prop.bp` (any case), or empty. */
  [[nodiscard]] std::string
  FindEnvironmentProp(const std::vector<std::string>& blueprints, const std::string& group, const std::string& name);

  /** What a run asks: the environment, the density multiplier, the seed, the classes (empty: all), under the water. */
  struct DetailRun
  {
    std::string environment = "evergreen";
    float density = 1.0f;
    int seed = 1;
    bool underWater = false;
    std::vector<std::string> only;
  };

  /** How many of a class a map of `area` square units gets at `density` (at least 1). */
  [[nodiscard]] int DetailCount(const DetailClass& c, double area, float density);

  /** The class's density mask on the heights' grid (the mask generator's noise, flow and grow rules). */
  [[nodiscard]] std::expected<void, std::string>
  DetailDensity(MaskGenContext& context, const DetailClass& c, int seed, field::Grid& out);

  /** One thing on a map, for Measure: a prop (blueprint) or a decal (texture, size), where. */
  struct DetailThing
  {
    std::string path;
    bool decal = false;
    float x = 0.0f;
    float z = 0.0f;
    float size = 0.0f;
  };
  /** What Measure found per class: how many, per 1,000 square units, the mean slope under them, the mean decal size. */
  struct DetailMeasure
  {
    std::string id;
    std::string label;
    int count = 0;
    float per1000 = 0.0f;
    float meanSlope = 0.0f;
    float meanSize = 0.0f;
  };
  /**
   * The map's props and decals sorted into the classes by their names (the environment's lists, any environment), with
   * the slope under them (`slope(x, z)` in degrees).
   */
  [[nodiscard]] std::vector<DetailMeasure>
  MeasureDetail(const std::vector<DetailThing>& things, double area, const std::function<float(float, float)>& slope);
} // namespace faf::editor
