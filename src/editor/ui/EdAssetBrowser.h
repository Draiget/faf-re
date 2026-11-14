#pragma once

#include "editor/tools/EdAssetCatalog.h"

#include <array>
#include <cstdio>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

namespace faf::editor
{
  class EdTools;

  /**
   * Asset browser (Objects and Units workspaces): every unit, prop, decal, marker, terrain texture and game effect as
   * tiles with their pictures, a tab per kind; search words, the kind's facets (faction, tech, environment, type...),
   * favourites first (right-click a tile: star) and a Recent view. A click makes the asset the tool's: the unit, prop,
   * decal or marker to place; an effect opens in the particle editor; a texture's path is shown to use on a layer.
   */
  class EdAssetBrowser
  {
  public:
    explicit EdAssetBrowser(EdTools& tools);

    void Draw(bool& open);

    /** Where favourites and recent are kept (empty: not kept, as in test runs). Read once when set. */
    void SetMarksFile(const std::filesystem::path& file);
    /** The entries of a kind (listed the first time they are asked for). */
    [[nodiscard]] const std::vector<AssetEntry>& Entries(AssetKind kind);
    /** What a click does (the tool's asset), and the entry used. */
    void Pick(const AssetEntry& entry);
    /** An effect picked: its game path for the particle editor (taken once). */
    [[nodiscard]] bool TakeEffectAsk(std::string& path);
    [[nodiscard]] AssetMarks& Marks() noexcept
    {
      return mMarks;
    }
    /** Test runs: the shown kind and search. */
    void Show(
      const AssetKind kind,
      const std::string& search
    )
    {
      mKind = kind;
      mShowAsked = true;
      std::snprintf(mSearch, sizeof(mSearch), "%s", search.c_str());
    }
    [[nodiscard]] const std::string& Status() const noexcept
    {
      return mStatus;
    }

  private:
    [[nodiscard]] std::uint64_t Picture(const AssetEntry& entry);
    void SaveMarks();

    EdTools& mTools;
    std::array<std::vector<AssetEntry>, kAssetKindCount> mEntries;
    std::array<bool, kAssetKindCount> mListed{};
    AssetMarks mMarks;
    std::filesystem::path mMarksFile;
    AssetKind mKind = AssetKind::Props;
    bool mShowAsked = false;
    char mSearch[96] = {};
    bool mFavourites = false;
    bool mRecent = false;
    std::map<std::string, std::string> mFilters; // per kind: "<kind>.<facet>" -> value
    std::string mEffectAsk;
    std::string mStatus;
  };
} // namespace faf::editor
