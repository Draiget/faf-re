#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace faf::editor
{
  struct EdUnitInfo;
  struct DecalTexture;
  struct MarkerType;
  struct LayerTexture;

  /**
   * The asset browser's catalogue (FAF Studio's assetcat, design §8 Assets and mods): one list per kind of every thing
   * the editor can place or use, each entry with the facets it filters by (faction, tech, environment, type...), a
   * search text, and the favourites and recently used kept between runs.
   */
  enum class AssetKind : std::uint8_t
  {
    Units,
    Props,
    Decals,
    Markers,
    Textures,
    Effects,
  };
  inline constexpr int kAssetKindCount = 6;
  [[nodiscard]] const char* AssetKindName(AssetKind kind);

  struct AssetEntry
  {
    AssetKind kind = AssetKind::Units;
    std::string key;                         // what it is: a unit id, a blueprint or texture path, a marker type
    std::string name;                        // what the tile says
    std::string sub;                         // the line under it
    std::map<std::string, std::string> tags; // facet -> value
    std::string search;                      // lower case: key, name, sub and tags
  };

  struct AssetFacet
  {
    const char* id;
    const char* label;
  };
  /** The facets a kind filters by, in the browser's order. */
  [[nodiscard]] const std::vector<AssetFacet>& AssetFacets(AssetKind kind);
  /** The values a facet has in the entries, sorted. */
  [[nodiscard]] std::vector<std::string>
  AssetFacetValues(const std::vector<AssetEntry>& entries, const std::string& facet);

  /** Favourites and recently used, by `kind:key`; kept as text (a line each: `f kind:key` or `r kind:key`). */
  class AssetMarks
  {
  public:
    static constexpr std::size_t kRecent = 40;

    [[nodiscard]] static std::string Id(const AssetEntry& entry);
    [[nodiscard]] bool Favourite(const AssetEntry& entry) const;
    void ToggleFavourite(const AssetEntry& entry);
    /** Used now: first in the recent list (once). */
    void Used(const AssetEntry& entry);
    /** Its place in the recent list (0 the latest), or -1. */
    [[nodiscard]] int RecentRank(const AssetEntry& entry) const;
    [[nodiscard]] std::string Save() const;
    void Load(const std::string& text);
    [[nodiscard]] std::size_t FavouriteCount() const noexcept
    {
      return mFavourites.size();
    }

  private:
    std::set<std::string> mFavourites;
    std::deque<std::string> mRecent;
  };

  struct AssetQuery
  {
    std::string text;                           // words, each must be in the entry's search text
    std::map<std::string, std::string> filters; // facet -> value (empty value: any)
    bool onlyFavourites = false;
    bool recent = false; // only the recently used, the latest first
  };
  /** The entries passing the query, by index: favourites first, then in list order (recent: the latest first). */
  [[nodiscard]] std::vector<std::size_t>
  FindAssets(const std::vector<AssetEntry>& entries, const AssetQuery& query, const AssetMarks& marks);

  // ---- entries from what the editor lists
  [[nodiscard]] AssetEntry UnitAsset(const EdUnitInfo& unit);
  /** A prop blueprint (`/env/evergreen/props/trees/pine06_prop.bp`): environment from its folder, type from its words.
   */
  [[nodiscard]] AssetEntry PropAsset(const std::string& blueprint);
  [[nodiscard]] AssetEntry DecalAsset(const DecalTexture& texture);
  [[nodiscard]] AssetEntry MarkerAsset(const MarkerType& type);
  [[nodiscard]] AssetEntry TextureAsset(const LayerTexture& texture);
  /** A game effect file (`/effects/emitters/x_emit.bp`): faction and what it's for from its name, its file kind. */
  [[nodiscard]] AssetEntry EffectAsset(const std::string& path);

  /**
   * The browser's pictures kept on disk (FAF Studio's assetthumbs): a picture's file in a cache folder by its key (a
   * hash of the key, so any path is a file name), as a small header and 32-bit BGRA pixels.
   */
  [[nodiscard]] std::filesystem::path ThumbCacheFile(const std::filesystem::path& folder, const std::string& key);
  bool WriteThumbFile(const std::filesystem::path& file, int width, int height, const std::uint32_t* pixels);
  bool ReadThumbFile(const std::filesystem::path& file, int& width, int& height, std::vector<std::uint32_t>& pixels);
} // namespace faf::editor
