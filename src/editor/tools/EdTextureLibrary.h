#pragma once

#include <cstdint>
#include <array>
#include <deque>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace faf::editor
{
  /** One terrain layer texture the game data has. */
  struct LayerTexture
  {
    /** The game path, as a map names it (`/env/evergreen/layers/grass001_albedo.dds`). */
    std::string path;
    /** Its normal map beside it (`..._normals.dds`), or empty. */
    std::string normals;
    /** The biome folder (`evergreen`), for grouping. */
    std::string biome;
    /** The file name without `_albedo.dds`, for display and search. */
    std::string name;
  };

  /**
   * The terrain layer textures the file system can see (every `.dds` under `/env/<biome>/layers/`, the
   * normal maps paired with their albedo), and thumbnails of them for the panels, decoded a few a frame.
   */
  class EdTextureLibrary
  {
  public:
    ~EdTextureLibrary();

    /** Lists the textures (once; again after Refresh). */
    const std::vector<LayerTexture>& Textures();
    void Refresh()
    {
      mListed = false;
    }

    /**
     * The thumbnail of a texture for ImGui::Image, or 0 while it waits its turn; asks for it either way. Opaque by
     * default (a layer's alpha is its specular, not its shape); `withAlpha` keeps it (a decal's alpha is its shape).
     */
    std::uint64_t Thumbnail(const std::string& path, bool withAlpha = false);
    /** A normal map's thumbnail as a lit relief (NormalRelief) instead of its raw colours. */
    std::uint64_t Relief(
      const std::string& normals
    )
    {
      return normals.empty() ? 0U : Thumbnail(std::string(kReliefPrefix) + normals);
    }
    static constexpr const char* kReliefPrefix = "relief:";

    /** Decodes up to `count` asked-for thumbnails; called once a frame. */
    void Pump(int count);

    /** A texture's average colour (0..1 r, g, b), decoded now and kept; false when it can't be read. */
    bool AverageColour(const std::string& path, float (&rgb)[3]);

    /** Thumbnails are this many pixels on a side. */
    static constexpr int kThumbnail = 64;

  private:
    std::vector<LayerTexture> mTextures;
    bool mListed = false;
    std::unordered_map<std::string, std::uint64_t> mThumbnails; // 0: asked, not decoded (or failed)
    std::deque<std::string> mWanted;
    std::set<std::string> mWithAlpha;
    std::unordered_map<std::string, std::array<float, 3>> mAverages; // r < 0: couldn't be read
  };

  /** Every `.dds` the game's files have under `folder` (its sub-folders too), sorted, each once. */
  [[nodiscard]] std::vector<std::string> ListGameTextures(const std::string& folder);

  /** "grass001" from ".../grass001_albedo.dds"; "(empty)" for none. */
  std::string LayerTextureName(const std::string& path);
} // namespace faf::editor
