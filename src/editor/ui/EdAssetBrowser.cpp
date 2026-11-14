#include "editor/ui/EdAssetBrowser.h"

#include "editor/EdTools.h"
#include "editor/tools/EdDecals.h"
#include "editor/tools/EdMarkers.h"
#include "editor/tools/EdTextureLibrary.h"
#include "editor/ui/EdControls.h"
#include "editor/ui/EdIconFont.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdWorkspaces.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <sstream>

namespace faf::editor
{
  namespace
  {
    const char* KindIcon(
      const AssetKind kind
    )
    {
      switch (kind) {
      case AssetKind::Units:
        return ICON_UNIT;
      case AssetKind::Props:
        return ICON_PROPS;
      case AssetKind::Decals:
        return ICON_DECAL;
      case AssetKind::Markers:
        return ICON_FLAG;
      case AssetKind::Textures:
        return ICON_TEXTURE;
      default:
        return ICON_PARTICLES;
      }
    }
  } // namespace

  EdAssetBrowser::EdAssetBrowser(
    EdTools& tools
  )
    : mTools(tools)
  {}

  void EdAssetBrowser::SetMarksFile(
    const std::filesystem::path& file
  )
  {
    mMarksFile = file;
    std::ifstream in(file, std::ios::binary);
    if (in) {
      std::ostringstream text;
      text << in.rdbuf();
      mMarks.Load(text.str());
    }
  }

  void EdAssetBrowser::SaveMarks()
  {
    if (mMarksFile.empty()) {
      return;
    }
    std::ofstream out(mMarksFile, std::ios::binary | std::ios::trunc);
    out << mMarks.Save();
  }

  const std::vector<AssetEntry>& EdAssetBrowser::Entries(
    const AssetKind kind
  )
  {
    const std::size_t k = static_cast<std::size_t>(kind);
    if (mListed[k]) {
      return mEntries[k];
    }
    std::vector<AssetEntry>& out = mEntries[k];
    switch (kind) {
    case AssetKind::Units:
      if (mTools.UnitInfos().empty()) {
        return out; // the rules aren't built yet: asked again next frame
      }
      for (const EdUnitInfo& unit : mTools.UnitInfos()) {
        out.push_back(UnitAsset(unit));
      }
      break;
    case AssetKind::Props:
      if (!mTools.HasPropBlueprints()) {
        return out;
      }
      for (const std::string& blueprint : mTools.PropBlueprints()) {
        out.push_back(PropAsset(blueprint));
      }
      break;
    case AssetKind::Decals:
      for (const DecalTexture& texture : ListDecalTextures()) {
        out.push_back(DecalAsset(texture));
      }
      break;
    case AssetKind::Markers:
      for (const MarkerType& type : MarkerTypes()) {
        out.push_back(MarkerAsset(type));
      }
      break;
    case AssetKind::Textures:
      for (const LayerTexture& texture : mTools.Library().Textures()) {
        out.push_back(TextureAsset(texture));
      }
      break;
    case AssetKind::Effects:
      if (moho::CVirtualFileSystem* vfs = moho::DISK_GetVFS(); vfs != nullptr) {
        fa::vector<fa::string> found;
        vfs->EnumerateFiles("/effects", "*.bp", true, &found);
        for (const fa::string& file : found) {
          out.push_back(EffectAsset(file.c_str()));
        }
      }
      break;
    }
    std::sort(out.begin(), out.end(), [](const AssetEntry& a, const AssetEntry& b) {
      return a.name < b.name;
    });
    mListed[k] = true;
    gpg::Logf("editor: asset browser: %zu %s", out.size(), AssetKindName(kind));
    return out;
  }

  std::uint64_t EdAssetBrowser::Picture(
    const AssetEntry& e
  )
  {
    switch (e.kind) {
    case AssetKind::Units: {
      std::string lower = e.key;
      std::transform(lower.begin(), lower.end(), lower.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return mTools.Library().Thumbnail("/textures/ui/common/icons/units/" + lower + "_icon.dds", true);
    }
    case AssetKind::Props:
      return mTools.PropPicture(e.key);
    case AssetKind::Decals:
      return mTools.Library().Thumbnail(e.key, true);
    case AssetKind::Textures:
      return mTools.Library().Thumbnail(e.key);
    default:
      return 0U;
    }
  }

  void EdAssetBrowser::Pick(
    const AssetEntry& e
  )
  {
    switch (e.kind) {
    case AssetKind::Units:
      mTools.SetUnitTool(e.key, mTools.UnitArmy(), false);
      mStatus = "Units tool: places " + e.key;
      break;
    case AssetKind::Props:
      mTools.SetPropTool(e.key, 0);
      mStatus = "Props tool: places " + e.name;
      break;
    case AssetKind::Decals:
      mTools.SetDecalTool(e.key, 0);
      mStatus = "Decals tool: places " + e.name;
      break;
    case AssetKind::Markers:
      mTools.SetMarkerTool(e.key);
      mStatus = "Markers tool: places " + e.key;
      break;
    case AssetKind::Textures:
      mStatus = e.key + " (use it on a layer in Layers)";
      ImGui::SetClipboardText(e.key.c_str());
      break;
    case AssetKind::Effects:
      mEffectAsk = e.key;
      mStatus = "Opened " + e.name + " in the particle editor";
      break;
    }
    mMarks.Used(e);
    SaveMarks();
    gpg::Logf("editor: asset browser: picked %s %s", AssetKindName(e.kind), e.key.c_str());
  }

  bool EdAssetBrowser::TakeEffectAsk(
    std::string& path
  )
  {
    if (mEffectAsk.empty()) {
      return false;
    }
    path = std::exchange(mEffectAsk, std::string());
    return true;
  }

  void EdAssetBrowser::Draw(
    bool& open
  )
  {
    if (!ImGui::Begin(Panel("Assets###AssetBrowser"), &open)) {
      ImGui::End();
      return;
    }
    if (ImGui::BeginTabBar("##assetkinds")) {
      for (int k = 0; k < kAssetKindCount; ++k) {
        const AssetKind kind = static_cast<AssetKind>(k);
        const std::string label =
          std::string(KindIcon(kind)) + " " + AssetKindName(kind) + "###kind" + std::to_string(k);
        const ImGuiTabItemFlags flags = mShowAsked && kind == mKind ? ImGuiTabItemFlags_SetSelected : 0;
        if (ImGui::BeginTabItem(label.c_str(), nullptr, flags)) {
          if (!mShowAsked) {
            mKind = kind;
          }
          ImGui::EndTabItem();
        }
      }
      mShowAsked = false;
      ImGui::EndTabBar();
    }
    const std::vector<AssetEntry>& entries = Entries(mKind);
    // Search, favourites, recent.
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - Em(150.0f));
    ImGui::InputTextWithHint("##assetsearch", ICON_SEARCH " Search", mSearch, sizeof(mSearch));
    ImGui::SameLine();
    ImGui::Checkbox(ICON_STAR "##fav", &mFavourites);
    EdSetItemTooltip("Only the favourites (right-click a tile to star it)");
    ImGui::SameLine();
    ImGui::Checkbox(ICON_HISTORY "##recent", &mRecent);
    EdSetItemTooltip("Only the ones used lately, the latest first");
    // The kind's facets.
    AssetQuery query;
    query.text = mSearch;
    query.onlyFavourites = mFavourites;
    query.recent = mRecent;
    const std::vector<AssetFacet>& facets = AssetFacets(mKind);
    const float facetWidth =
      (ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x * (facets.size() - 1)) /
      static_cast<float>(facets.size());
    for (std::size_t f = 0; f < facets.size(); ++f) {
      if (f > 0) {
        ImGui::SameLine();
      }
      const std::string slot = std::string(AssetKindName(mKind)) + "." + facets[f].id;
      std::string& value = mFilters[slot];
      ImGui::SetNextItemWidth(facetWidth);
      const std::string shown = value.empty() ? std::string(facets[f].label) + ": any" : value;
      if (EdBeginCombo(("##" + slot).c_str(), shown.c_str())) {
        if (ImGui::Selectable("any", value.empty())) {
          value.clear();
        }
        for (const std::string& v : AssetFacetValues(entries, facets[f].id)) {
          if (ImGui::Selectable(v.c_str(), v == value)) {
            value = v;
          }
        }
        ImGui::EndCombo();
      }
      query.filters[facets[f].id] = value;
    }
    const std::vector<std::size_t> found = FindAssets(entries, query, mMarks);
    ImGui::TextDisabled("%zu of %zu %s", found.size(), entries.size(), AssetKindName(mKind));
    if (!mStatus.empty()) {
      ImGui::SameLine();
      ImGui::TextDisabled(" %s", mStatus.c_str());
    }
    if (entries.empty()) {
      ImGui::TextDisabled("Nothing listed yet (the game's rules are still being built).");
    }
    // The tiles.
    ImGui::BeginChild("##assettiles", ImVec2(0.0f, 0.0f), false);
    const float tile = Em(76.0f);
    const float gap = ImGui::GetStyle().ItemSpacing.x;
    // A tile is the picture and the button's frame on both sides.
    const float cell = tile + ImGui::GetStyle().FramePadding.x * 2.0f;
    const int columns = std::max(1, static_cast<int>((ImGui::GetContentRegionAvail().x + gap) / (cell + gap)));
    const int rows = static_cast<int>((found.size() + static_cast<std::size_t>(columns) - 1) / columns);
    const float rowHeight = tile + ImGui::GetTextLineHeightWithSpacing() + ImGui::GetStyle().ItemSpacing.y;
    ImGuiListClipper clipper;
    clipper.Begin(rows, rowHeight);
    while (clipper.Step()) {
      for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
        for (int c = 0; c < columns; ++c) {
          const std::size_t at = static_cast<std::size_t>(row) * columns + c;
          if (at >= found.size()) {
            break;
          }
          const AssetEntry& e = entries[found[at]];
          if (c > 0) {
            ImGui::SameLine();
          }
          ImGui::PushID(static_cast<int>(found[at]));
          ImGui::BeginGroup();
          const ImVec2 corner = ImGui::GetCursorScreenPos();
          const std::uint64_t picture = Picture(e);
          bool clicked = false;
          if (picture != 0U) {
            clicked = ImGui::ImageButton("##tile", static_cast<ImTextureID>(picture), ImVec2(tile, tile));
          } else {
            clicked = ImGui::Button(
              KindIcon(e.kind),
              ImVec2(tile + ImGui::GetStyle().FramePadding.x * 2.0f, tile + ImGui::GetStyle().FramePadding.y * 2.0f)
            );
          }
          if (clicked) {
            Pick(e);
          }
          if (ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
            mMarks.ToggleFavourite(e);
            SaveMarks();
          }
          if (ImGui::IsItemHovered()) {
            EdSetTooltip("%s\n%s\n%s", e.name.c_str(), e.sub.c_str(), e.key.c_str());
          }
          if (mMarks.Favourite(e)) {
            ImGui::GetWindowDrawList()->AddText(
              ImVec2(corner.x + 4.0f, corner.y + 2.0f), IM_COL32(255, 205, 80, 255), ICON_STAR
            );
          }
          ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + tile);
          std::string name = e.name;
          if (name.size() > 14) {
            name = name.substr(0, 13) + "~";
          }
          ImGui::TextUnformatted(name.c_str());
          ImGui::PopTextWrapPos();
          ImGui::EndGroup();
          ImGui::PopID();
        }
      }
    }
    ImGui::EndChild();
    ImGui::End();
  }
} // namespace faf::editor
