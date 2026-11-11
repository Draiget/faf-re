// The map editor's layer files (src/editor/doc/EdLayerPreset.cpp): FAForeverMapEditor's `.scmsl` (one layer) and
// `.scmst` (the shader and all ten), read and written.

#include "editor/doc/EdLayerPreset.h"

#include <gtest/gtest.h>

namespace
{
  using faf::editor::LayerSettings;

  // As FAFME's ExportStratum writes it (JsonUtility, pretty, the textures as Unity object references).
  const char* const kScmsl = R"({
    "Albedo": {
        "instanceID": 29514
    },
    "Normal": {
        "instanceID": 29516
    },
    "Tilling": {
        "x": 1.0,
        "y": 1.0
    },
    "AlbedoPath": "/env/evergreen/layers/eg_gravel005_albedo.dds",
    "NormalPath": "/env/evergreen/layers/eg_gravel005_normals.dds",
    "AlbedoScale": 4.0,
    "NormalScale": 2.0
})";

  TEST(
    LayerPreset,
    ReadsFafmesLayerFile
  )
  {
    LayerSettings layer;
    std::string error;
    ASSERT_TRUE(faf::editor::LayerFromScmsl(kScmsl, layer, error)) << error;
    EXPECT_EQ(layer.albedo, "/env/evergreen/layers/eg_gravel005_albedo.dds");
    EXPECT_EQ(layer.normals, "/env/evergreen/layers/eg_gravel005_normals.dds");
    EXPECT_FLOAT_EQ(layer.albedoSize, 4.0f);
    EXPECT_FLOAT_EQ(layer.normalsSize, 2.0f);
    LayerSettings again;
    ASSERT_TRUE(faf::editor::LayerFromScmsl(faf::editor::LayerToScmsl(layer), again, error)) << error;
    EXPECT_TRUE(again == layer);
    EXPECT_FALSE(faf::editor::LayerFromScmsl("{ \"LightingMultiplier\": 1 }", again, error));
  }

  TEST(
    LayerPreset,
    ASetKeepsTheShaderAndAllTenLayers
  )
  {
    std::vector<LayerSettings> layers(10);
    for (std::size_t i = 0; i < 10; ++i) {
      layers[i].albedo = i == 3 ? "" : "/env/x/layers/l" + std::to_string(i) + "_albedo.dds";
      layers[i].normals = i % 2 == 0 ? "/env/x/layers/l" + std::to_string(i) + "_normals.dds" : "";
      layers[i].albedoSize = 1.5f + static_cast<float>(i);
      layers[i].normalsSize = 2.5f * static_cast<float>(i + 1);
    }
    const std::string text = faf::editor::LayersToScmst("TTerrainXP", layers);
    std::string shader;
    std::vector<LayerSettings> read;
    std::string error;
    ASSERT_TRUE(faf::editor::LayersFromScmst(text, shader, read, error)) << error;
    EXPECT_EQ(shader, "TTerrainXP");
    ASSERT_EQ(read.size(), 10u);
    for (std::size_t i = 0; i < 10; ++i) {
      EXPECT_TRUE(read[i] == layers[i]) << "layer " << i;
    }
    // A layer file isn't a set.
    EXPECT_FALSE(faf::editor::LayersFromScmst(kScmsl, shader, read, error));
  }
} // namespace
