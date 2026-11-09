#pragma once

#include <cstdint>
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
    void Refresh() { mListed = false; }

    /**
     * The thumbnail of a texture for ImGui::Image, or 0 while it waits its turn; asks for it either way. Opaque by
     * default (a layer's alpha is its specular, not its shape); `withAlpha` keeps it (a decal's alpha is its shape).
     */
    std::uint64_t Thumbnail(const std::string& path, bool withAlpha = false);

    /** Decodes up to `count` asked-for thumbnails; called once a frame. */
    void Pump(int count);

    /** Thumbnails are this many pixels on a side. */
    static constexpr int kThumbnail = 64;

  private:
    std::vector<LayerTexture> mTextures;
    bool mListed = false;
    std::unordered_map<std::string, std::uint64_t> mThumbnails; // 0: asked, not decoded (or failed)
    std::deque<std::string> mWanted;
    std::set<std::string> mWithAlpha;
  };

  /** "grass001" from ".../grass001_albedo.dds"; "(empty)" for none. */
  std::string LayerTextureName(const std::string& path);
} // namespace faf::editor
