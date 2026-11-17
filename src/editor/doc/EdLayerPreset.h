#pragma once

#include <expected>
#include <string>
#include <vector>

namespace faf::editor
{
  /** One terrain layer as the `.scmap` keeps it: albedo and normal map paths and their sizes. */
  struct LayerSettings
  {
    std::string albedo;
    std::string normals;
    float albedoSize = 4.0f;
    float normalsSize = 4.0f;

    bool operator==(
      const LayerSettings& other
    ) const
    {
      return albedo == other.albedo && normals == other.normals && albedoSize == other.albedoSize &&
        normalsSize == other.normalsSize;
    }
  };

  /**
   * FAForeverMapEditor's layer file (`.scmsl`, JsonUtility's dump of its ScmapEditor.TerrainTexture): the paths and
   * scales, with its Unity-only fields (the loaded textures, written as instance id 0, and a tiling of 1, 1).
   */
  std::string LayerToScmsl(const LayerSettings& layer);
  [[nodiscard]] std::expected<void, std::string> LayerFromScmsl(const std::string& text, LayerSettings& layer);

  /**
   * FAFME's layer set (`.scmst`, its StratumTemplate): the terrain shader's name and the ten layers, Stratum0 the lower
   * one to Stratum9 the upper one. Reading needs all ten.
   */
  std::string LayersToScmst(const std::string& shader, const std::vector<LayerSettings>& layers);
  [[nodiscard]] std::expected<void, std::string>
  LayersFromScmst(const std::string& text, std::string& shader, std::vector<LayerSettings>& layers);
} // namespace faf::editor
