// The Info panel (what the open map is) and the Markers panel (its markers as a tree), EdShell's right-hand panels.

#include "editor/EdShell.h"

#include <algorithm>
#include <array>
#include <functional>
#include <cctype>
#include <cstdio>
#include <map>

#include "editor/EdPlay.h"
#include "moho/terrain/CWldTerrainRes.h"
#include "moho/sim/SFootprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/RRuleGameRules.h"
#include "editor/tools/EdPathing.h"
#include "gpg/core/utils/Logging.h"
#include "moho/sim/CWldMap.h"
#include <cmath>
#include "editor/doc/EdDocument.h"
#include "editor/tools/EdMarkers.h"
#include "imgui.h"
#include "imgui_internal.h"

namespace faf::editor
{
  namespace
  {
    constexpr const char* kMapWindow = "Map";
    constexpr const char* kInfoWindow = "Info";
    constexpr const char* kMarkersWindow = "Markers";

    constexpr ImU32 kChipFill = IM_COL32(48, 56, 68, 255);
    constexpr ImU32 kCardFill = IM_COL32(36, 42, 52, 255);
    constexpr ImU32 kCardLine = IM_COL32(58, 66, 78, 255);
    constexpr ImU32 kAccent = IM_COL32(232, 145, 60, 255);

    /** ARGB (the saves' colours) to ImGui's ABGR. */
    ImU32 FromArgb(const std::uint32_t argb)
    {
      return IM_COL32((argb >> 16) & 0xFF, (argb >> 8) & 0xFF, argb & 0xFF, 255);
    }

    /** A rounded label inline with the text, wrapping to the next line when the row is full. */
    void Chip(const char* const text, const ImU32 fill = kChipFill, const ImU32 ink = 0)
    {
      const ImVec2 padding(7.0f, 2.0f);
      const ImVec2 size = ImGui::CalcTextSize(text);
      const ImVec2 box(size.x + padding.x * 2.0f, size.y + padding.y * 2.0f);
      ImGui::Dummy(box);
      const ImVec2 min = ImGui::GetItemRectMin();
      ImDrawList* const draw = ImGui::GetWindowDrawList();
      draw->AddRectFilled(min, ImVec2(min.x + box.x, min.y + box.y), fill, box.y * 0.5f);
      draw->AddText(ImVec2(min.x + padding.x, min.y + padding.y), ink != 0 ? ink : ImGui::GetColorU32(ImGuiCol_Text), text);
    }

    /** The next chip on the same row if it fits, else on the next. */
    void ChipSpacing(const char* const next)
    {
      const float width = ImGui::CalcTextSize(next).x + 14.0f;
      const float right = ImGui::GetItemRectMax().x + ImGui::GetStyle().ItemSpacing.x + width;
      if (right < ImGui::GetCurrentWindow()->WorkRect.Max.x) {
        ImGui::SameLine();
      }
    }

    void Chips(const std::vector<std::string>& texts, const ImU32 fill = kChipFill, const ImU32 ink = 0)
    {
      for (std::size_t i = 0; i < texts.size(); ++i) {
        if (i > 0) {
          ChipSpacing(texts[i].c_str());
        }
        Chip(texts[i].c_str(), fill, ink);
      }
    }

    /** A diamond as the view draws markers. */
    void Diamond(ImDrawList* const draw, const ImVec2 centre, const float r, const ImU32 color, const bool filled = true)
    {
      const ImVec2 points[4] = {{centre.x, centre.y - r}, {centre.x + r, centre.y}, {centre.x, centre.y + r}, {centre.x - r, centre.y}};
      if (filled) {
        draw->AddConvexPolyFilled(points, 4, color);
      } else {
        draw->AddPolyline(points, 4, color, ImDrawFlags_Closed, 1.5f);
      }
    }

    /** An eye (shown) or a struck eye (hidden), as a small button; true when clicked. */
    bool EyeButton(const char* const id, const bool hidden)
    {
      const float size = ImGui::GetFrameHeight();
      const bool clicked = ImGui::InvisibleButton(id, ImVec2(size, size));
      const ImVec2 min = ImGui::GetItemRectMin();
      const ImVec2 c(min.x + size * 0.5f, min.y + size * 0.5f);
      ImDrawList* const draw = ImGui::GetWindowDrawList();
      const ImU32 ink = ImGui::GetColorU32(ImGui::IsItemHovered() ? ImGuiCol_Text : (hidden ? ImGuiCol_TextDisabled : ImGuiCol_Text));
      const float w = size * 0.34f;
      const float h = size * 0.2f;
      draw->PathArcTo(ImVec2(c.x, c.y + h * 1.6f), w * 1.25f, -IM_PI * 0.78f, -IM_PI * 0.22f, 10);
      draw->PathArcTo(ImVec2(c.x, c.y - h * 1.6f), w * 1.25f, IM_PI * 0.22f, IM_PI * 0.78f, 10);
      draw->PathStroke(ink, ImDrawFlags_Closed, 1.4f);
      draw->AddCircleFilled(c, h * 0.75f, ink);
      if (hidden) {
        draw->AddLine(ImVec2(c.x - w, c.y + w * 0.8f), ImVec2(c.x + w, c.y - w * 0.8f), ink, 1.6f);
      }
      if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
        ImGui::SetTooltip(hidden ? "Hidden in the view (not drawn, not picked). Click to show." : "Shown in the view. Click to hide.");
      }
      return clicked;
    }

    /** "Evergreen2 · grass005" from "/env/evergreen2/layers/evgrass005_albedo.dds". */
    std::string ReadableLayer(const std::string& path)
    {
      std::string biome;
      const std::size_t env = path.find("/env/");
      if (env != std::string::npos) {
        const std::size_t end = path.find('/', env + 5);
        biome = path.substr(env + 5, end == std::string::npos ? std::string::npos : end - env - 5);
        if (!biome.empty()) {
          biome[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(biome[0])));
        }
      }
      const std::string name = LayerTextureName(path);
      return biome.empty() ? name : biome + "  \xC2\xB7  " + name;
    }

    std::string FileName(const std::string& path)
    {
      const std::size_t slash = path.find_last_of('/');
      return slash == std::string::npos ? path : path.substr(slash + 1);
    }
  } // namespace

  void EdShell::DrawInfoPanel()
  {
    // A layout saved before this panel existed has no place for it: it goes beside the Map panel.
    if (const ImGuiWindow* const map = ImGui::FindWindowByName(kMapWindow); map != nullptr && map->DockId != 0) {
      ImGui::SetNextWindowDockID(map->DockId, ImGuiCond_FirstUseEver);
    }
    // A map that starts opening (the Map panel's button, `/open`) brings this tab to the front once, after the
    // first frames: on those the saved layout picks each dock's front tab and would override it.
    if (!mDocument.Path().empty() && mDocument.Path() != mInfoShownFor && ImGui::GetFrameCount() > 3) {
      mInfoShownFor = mDocument.Path();
      mShowInfo = true;
      ImGui::SetNextWindowFocus();
    }
    if (!ImGui::Begin(kInfoWindow, &mShowInfo)) {
      ImGui::End();
      return;
    }
    switch (mDocument.GetState()) {
    case EdDocument::State::Empty:
      ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
      ImGui::TextWrapped("No map open. Double-click one in the Map panel, or pick it and press Open.");
      ImGui::PopStyleColor();
      ImGui::End();
      return;
    case EdDocument::State::Loading:
      ImGui::Text("Opening %s ...", MapDisplayName(mDocument.Path()).c_str());
      ImGui::End();
      return;
    case EdDocument::State::Failed:
      ImGui::TextColored(ImVec4(0.95f, 0.45f, 0.40f, 1.0f), "%s did not open", MapDisplayName(mDocument.Path()).c_str());
      ImGui::TextWrapped("%s", mDocument.Error().c_str());
      ImGui::End();
      return;
    case EdDocument::State::Open:
      break;
    }

    const MapFacts& facts = mDocument.Facts();
    // The title, larger, and where it comes from.
    ImGui::PushFont(nullptr, ImGui::GetFontSize() * 1.35f);
    ImGui::TextWrapped("%s", facts.name.empty() ? MapDisplayName(facts.scenarioPath).c_str() : facts.name.c_str());
    ImGui::PopFont();
    if (facts.mapVersion > 0) {
      ImGui::TextDisabled("%s  \xC2\xB7  version %d  \xC2\xB7  opened in %.2f s", MapDisplayName(facts.scenarioPath).c_str(),
                          facts.mapVersion, facts.loadSeconds);
    } else {
      ImGui::TextDisabled("%s  \xC2\xB7  opened in %.2f s", MapDisplayName(facts.scenarioPath).c_str(), facts.loadSeconds);
    }
    if (!mDocument.Error().empty()) {
      ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.30f, 1.0f), "%s", mDocument.Error().c_str());
    }

    // What kind of map, as chips.
    ImGui::Spacing();
    {
      std::vector<std::string> chips;
      char text[96];
      (void)std::snprintf(text, sizeof(text), "%.0f x %.0f km", facts.sizeX / 51.2, facts.sizeZ / 51.2);
      chips.emplace_back(text);
      if (!facts.type.empty()) {
        chips.push_back(facts.type);
      }
      const std::vector<std::string> armies = mDocument.Armies();
      (void)std::snprintf(text, sizeof(text), "%zu players", armies.size());
      chips.emplace_back(text);
      if (facts.water) {
        (void)std::snprintf(text, sizeof(text), "water at %.1f", static_cast<double>(facts.waterElevation));
      } else {
        (void)std::snprintf(text, sizeof(text), "no water");
      }
      chips.emplace_back(text);
      static constexpr const char* kSymmetryNames[] = {"no symmetry", "left-right", "top-bottom", "diagonal \\", "diagonal /",
                                                       "half turn",   "both axes",  "both diagonals", "quarter turns", "n-way"};
      if (facts.symmetry.symmetry == Symmetry::NWay) {
        (void)std::snprintf(text, sizeof(text), "%d-way turn", facts.symmetry.turns);
        chips.emplace_back(text);
      } else {
        chips.emplace_back(kSymmetryNames[static_cast<int>(facts.symmetry.symmetry)]);
      }
      Chips(chips);
    }
    if (!facts.description.empty()) {
      ImGui::Spacing();
      ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
      ImGui::TextWrapped("%s", facts.description.c_str());
      ImGui::PopStyleColor();
    }

    // The counts as cards: the number large, what it counts under it.
    ImGui::Spacing();
    {
      const int markers = static_cast<int>(mDocument.SaveData().Markers().size());
      const std::array<std::pair<const char*, int>, 4> cards = {{{"props", facts.props},
                                                                 {"decals", facts.decals},
                                                                 {"markers", markers > 0 ? markers : facts.markerCount},
                                                                 {"armies", static_cast<int>(mDocument.Armies().size())}}};
      const float gap = ImGui::GetStyle().ItemSpacing.x;
      const int columns = ImGui::GetContentRegionAvail().x > 360.0f ? 4 : 2;
      const float width = (ImGui::GetContentRegionAvail().x - gap * static_cast<float>(columns - 1)) / static_cast<float>(columns);
      const float big = ImGui::GetFontSize() * 1.5f;
      const float height = big + ImGui::GetFontSize() + 14.0f;
      for (std::size_t i = 0; i < cards.size(); ++i) {
        if (i % static_cast<std::size_t>(columns) != 0) {
          ImGui::SameLine();
        }
        ImGui::Dummy(ImVec2(width, height));
        const ImVec2 min = ImGui::GetItemRectMin();
        ImDrawList* const draw = ImGui::GetWindowDrawList();
        draw->AddRectFilled(min, ImVec2(min.x + width, min.y + height), kCardFill, 6.0f);
        draw->AddRect(min, ImVec2(min.x + width, min.y + height), kCardLine, 6.0f);
        char number[32];
        (void)std::snprintf(number, sizeof(number), "%d", cards[i].second);
        draw->AddText(ImGui::GetFont(), big, ImVec2(min.x + 10.0f, min.y + 6.0f), ImGui::GetColorU32(ImGuiCol_Text), number);
        draw->AddText(ImVec2(min.x + 10.0f, min.y + 8.0f + big), ImGui::GetColorU32(ImGuiCol_TextDisabled), cards[i].first);
      }
    }

    // Terrain: shader, height field, and the layers with their thumbnails.
    ImGui::Spacing();
    ImGui::SeparatorText("Terrain");
    ImGui::TextDisabled("Shader");
    ImGui::SameLine(110.0f);
    ImGui::TextUnformatted(facts.terrainShader.c_str());
    ImGui::TextDisabled("Height field");
    ImGui::SameLine(110.0f);
    ImGui::Text("%d x %d samples", facts.fieldWidth, facts.fieldHeight);
    ImGui::Spacing();
    {
      static constexpr const char* kSlots[] = {"Lower", "1", "2", "3", "4", "5", "6", "7", "8", "Upper"};
      EdTextureLibrary& library = mTools.Library();
      library.Pump(2);
      const float thumb = ImGui::GetFrameHeight() * 1.5f;
      int empty = 0;
      for (std::size_t i = 0; i < facts.layers.size() && i < std::size(kSlots); ++i) {
        if (facts.layers[i].empty()) {
          ++empty;
          continue;
        }
        ImGui::PushID(static_cast<int>(i));
        const ImVec2 at = ImGui::GetCursorScreenPos();
        if (const std::uint64_t image = library.Thumbnail(facts.layers[i]); image != 0U) {
          ImGui::Image(static_cast<ImTextureID>(image), ImVec2(thumb, thumb));
        } else {
          ImGui::Dummy(ImVec2(thumb, thumb));
          ImGui::GetWindowDrawList()->AddRectFilled(at, ImVec2(at.x + thumb, at.y + thumb), kChipFill, 3.0f);
        }
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
          ImGui::SetTooltip("%s", facts.layers[i].c_str());
        }
        ImGui::SameLine();
        ImGui::BeginGroup();
        ImGui::Dummy(ImVec2(0.0f, (thumb - ImGui::GetTextLineHeight() * 2.0f) * 0.25f));
        ImGui::TextUnformatted(ReadableLayer(facts.layers[i]).c_str());
        ImGui::TextDisabled(i == 0 ? "lower layer" : (i == 9 ? "upper layer" : "stratum %s"), kSlots[i]);
        ImGui::EndGroup();
        ImGui::PopID();
      }
      if (empty > 0) {
        ImGui::TextDisabled("%d empty slot%s", empty, empty == 1 ? "" : "s");
      }
    }

    // Armies: the players, then the extra (neutral, civilian) armies dimmer.
    ImGui::Spacing();
    ImGui::SeparatorText("Armies");
    Chips(mDocument.Armies(), IM_COL32(52, 74, 60, 255));
    if (const std::vector<std::string> extra = mDocument.ExtraArmies(); !extra.empty()) {
      Chips(extra, kChipFill, ImGui::GetColorU32(ImGuiCol_TextDisabled));
    }

    // Markers: the kinds and their counts, with the tree in its own panel.
    ImGui::Spacing();
    ImGui::SeparatorText("Markers");
    {
      std::array<int, kMarkerGroupCount> counts{};
      for (const SaveEntry& marker : mDocument.SaveData().Markers()) {
        ++counts[static_cast<std::size_t>(MarkerGroupOf(marker))];
      }
      std::vector<std::string> chips;
      for (int g = 0; g < kMarkerGroupCount; ++g) {
        if (counts[static_cast<std::size_t>(g)] > 0) {
          chips.push_back(std::to_string(counts[static_cast<std::size_t>(g)]) + "  " + MarkerGroupName(static_cast<MarkerGroup>(g)));
        }
      }
      Chips(chips);
      if (ImGui::SmallButton("Show the Markers panel")) {
        mShowMarkers = true;
        mFocusMarkers = true;
      }
    }

    // Files: the name, the full path on hover.
    ImGui::Spacing();
    ImGui::SeparatorText("Files");
    for (const std::string* const path : {&facts.scenarioPath, &facts.mapPath, &facts.savePath, &facts.scriptPath}) {
      if (path->empty()) {
        continue;
      }
      ImGui::TextUnformatted(FileName(*path).c_str());
      if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
        ImGui::SetTooltip("%s", path->c_str());
      }
    }
    ImGui::TextDisabled("in %s", MapDisplayName(facts.scenarioPath).c_str());
    ImGui::End();
  }

  void EdShell::DrawMarkersPanel()
  {
    // Docked with the Map and Info panels in a layout saved before it existed.
    if (const ImGuiWindow* const map = ImGui::FindWindowByName(kMapWindow); map != nullptr && map->DockId != 0) {
      ImGui::SetNextWindowDockID(map->DockId, ImGuiCond_FirstUseEver);
    }
    if (mFocusMarkers) {
      mFocusMarkers = false;
      ImGui::SetNextWindowFocus();
    }
    if (!ImGui::Begin(kMarkersWindow, &mShowMarkers)) {
      ImGui::End();
      return;
    }
    if (mDocument.GetState() != EdDocument::State::Open) {
      ImGui::TextDisabled("No map open.");
      ImGui::End();
      return;
    }
    const std::vector<SaveEntry>& markers = mDocument.SaveData().Markers();
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##markerfilter", "Filter by name or type", mMarkerFilter, sizeof(mMarkerFilter));

    DrawChains();

    // Group, then type, then the markers in the save's order.
    std::array<std::map<std::string, std::vector<std::size_t>>, kMarkerGroupCount> tree;
    for (std::size_t i = 0; i < markers.size(); ++i) {
      const std::string type = MarkerTypeOf(markers[i]);
      if (mMarkerFilter[0] != '\0' && ImStristr(markers[i].name.c_str(), nullptr, mMarkerFilter, nullptr) == nullptr &&
          ImStristr(type.c_str(), nullptr, mMarkerFilter, nullptr) == nullptr) {
        continue;
      }
      tree[static_cast<std::size_t>(MarkerGroupOf(markers[i]))][type].push_back(i);
    }
    std::vector<std::string> selected;
    for (const SaveEntry& marker : mTools.MarkerSelection()) {
      selected.push_back(marker.name);
    }
    std::set<std::string>& hidden = mTools.HiddenMarkerTypes();
    const bool filtering = mMarkerFilter[0] != '\0';
    const ImGuiIO& io = ImGui::GetIO();

    ImGui::BeginChild("##markertree", ImVec2(0.0f, 0.0f), ImGuiChildFlags_None);
    for (int g = 0; g < kMarkerGroupCount; ++g) {
      const auto& types = tree[static_cast<std::size_t>(g)];
      if (types.empty()) {
        continue;
      }
      std::size_t count = 0;
      for (const auto& [type, list] : types) {
        count += list.size();
      }
      const char* const groupName = MarkerGroupName(static_cast<MarkerGroup>(g));
      ImGui::PushID(g);
      if (filtering) {
        ImGui::SetNextItemOpen(true, ImGuiCond_Always);
      }
      const bool groupOpen = ImGui::TreeNodeEx("##group", ImGuiTreeNodeFlags_Framed | ImGuiTreeNodeFlags_SpanAvailWidth |
                                                              (g == 0 ? ImGuiTreeNodeFlags_DefaultOpen : 0),
                                               "%s", groupName);
      // The count at the header's right.
      {
        char text[16];
        (void)std::snprintf(text, sizeof(text), "%zu", count);
        const ImVec2 max = ImGui::GetItemRectMax();
        const ImVec2 size = ImGui::CalcTextSize(text);
        ImGui::GetWindowDrawList()->AddText(ImVec2(max.x - size.x - 10.0f, ImGui::GetItemRectMin().y + ImGui::GetStyle().FramePadding.y),
                                            ImGui::GetColorU32(ImGuiCol_TextDisabled), text);
      }
      if (groupOpen) {
        for (const auto& [type, list] : types) {
          ImGui::PushID(type.c_str());
          const bool typeHidden = hidden.count(type) != 0;
          // A type row: its eye, its colour, its name and count; open it for the markers.
          if (EyeButton("##eye", typeHidden)) {
            if (typeHidden) {
              hidden.erase(type);
            } else {
              hidden.insert(type);
            }
          }
          ImGui::SameLine(0.0f, 2.0f);
          const ImVec2 swatch = ImGui::GetCursorScreenPos();
          ImGui::Dummy(ImVec2(ImGui::GetFrameHeight() * 0.7f, ImGui::GetFrameHeight()));
          Diamond(ImGui::GetWindowDrawList(), ImVec2(swatch.x + ImGui::GetFrameHeight() * 0.3f, swatch.y + ImGui::GetFrameHeight() * 0.5f),
                  ImGui::GetFrameHeight() * 0.22f, FromArgb(MarkerColor(markers[list.front()])));
          ImGui::SameLine(0.0f, 2.0f);
          ImGui::AlignTextToFramePadding();
          if (filtering) {
            ImGui::SetNextItemOpen(true, ImGuiCond_Always);
          }
          // The save's type, but start positions by what they are.
          const char* const label = type == "Blank Marker" ? "Start position" : type.c_str();
          const bool typeOpen = ImGui::TreeNodeEx("##type",
                                                  ImGuiTreeNodeFlags_SpanAvailWidth | ImGuiTreeNodeFlags_OpenOnArrow |
                                                    (types.size() == 1 ? ImGuiTreeNodeFlags_DefaultOpen : 0),
                                                  "%s  (%zu)", label, list.size());
          // A click on the type's name selects all its markers.
          if (ImGui::IsItemClicked() && !ImGui::IsItemToggledOpen()) {
            std::vector<std::string> names;
            for (const std::size_t i : list) {
              names.push_back(markers[i].name);
            }
            mTools.AskMarkerSelect(std::move(names), io.KeyCtrl);
          }
          if (typeOpen) {
            for (const std::size_t i : list) {
              const SaveEntry& marker = markers[i];
              const bool isSelected = std::find(selected.begin(), selected.end(), marker.name) != selected.end();
              ImGui::PushID(static_cast<int>(i));
              const ImVec2 row = ImGui::GetCursorScreenPos();
              if (ImGui::Selectable("##marker", isSelected, ImGuiSelectableFlags_AllowDoubleClick | ImGuiSelectableFlags_SpanAvailWidth)) {
                mTools.AskMarkerSelect({marker.name}, io.KeyCtrl);
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                  mTools.AskMarkerFrame(marker.name);
                }
              }
              if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
                ImGui::SetTooltip("%s\nClick selects (Ctrl adds), double-click goes to it", marker.name.c_str());
              }
              ImDrawList* const draw = ImGui::GetWindowDrawList();
              const float line = ImGui::GetTextLineHeight();
              Diamond(draw, ImVec2(row.x + line * 0.45f, row.y + line * 0.5f), line * 0.28f, FromArgb(MarkerColor(marker)), !typeHidden);
              draw->AddText(ImVec2(row.x + line * 1.2f, row.y), isSelected ? kAccent : ImGui::GetColorU32(ImGuiCol_Text), marker.name.c_str());
              float x = 0.0f, y = 0.0f, z = 0.0f;
              if (MarkerPosition(marker, x, y, z)) {
                char where[48];
                (void)std::snprintf(where, sizeof(where), "%.0f, %.0f", static_cast<double>(x), static_cast<double>(z));
                const float width = ImGui::CalcTextSize(where).x;
                draw->AddText(ImVec2(ImGui::GetItemRectMax().x - width - 6.0f, row.y), ImGui::GetColorU32(ImGuiCol_TextDisabled), where);
              }
              ImGui::PopID();
            }
            ImGui::TreePop();
          }
          ImGui::PopID();
        }
        ImGui::TreePop();
      }
      ImGui::PopID();
    }
    ImGui::EndChild();
    ImGui::End();
  }
  void EdShell::DrawChains()
  {
    std::vector<MarkerChain>& chains = mDocument.SaveData().Chains();
    char header[64];
    (void)std::snprintf(header, sizeof(header), "Chains (%zu)###chains", chains.size());
    if (!ImGui::CollapsingHeader(header)) {
      return;
    }
    // Each change is one undo step: the save as it was, the change, then the step.
    const auto change = [this](const std::function<void(std::vector<MarkerChain>&)>& edit, const char* const what) {
      EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
      edit(mDocument.SaveData().Chains());
      if (before.chains != mDocument.SaveData().Chains()) {
        mDocument.SaveDataEdited(std::move(before));
        gpg::Logf("editor: chains: %s (%zu chains)", what, mDocument.SaveData().Chains().size());
      }
    };
    std::vector<std::string> selected;
    for (const SaveEntry& marker : mTools.MarkerSelection()) {
      selected.push_back(marker.name);
    }
    for (std::size_t c = 0; c < chains.size(); ++c) {
      ImGui::PushID(static_cast<int>(c));
      const bool open = ImGui::TreeNodeEx("##chain", ImGuiTreeNodeFlags_SpanAvailWidth, "%s  (%zu)", chains[c].name.c_str(), chains[c].markers.size());
      if (ImGui::IsItemClicked() && !ImGui::IsItemToggledOpen()) {
        mTools.AskMarkerSelect(chains[c].markers, ImGui::GetIO().KeyCtrl);
      }
      if (open) {
        for (std::size_t m = 0; m < chains[c].markers.size(); ++m) {
          ImGui::PushID(static_cast<int>(m));
          ImGui::Text("%zu  %s", m + 1, chains[c].markers[m].c_str());
          const float buttons = ImGui::GetFrameHeight() * 3.0f + ImGui::GetStyle().ItemSpacing.x * 2.0f;
          ImGui::SameLine(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x - buttons);
          ImGui::BeginDisabled(m == 0);
          if (ImGui::ArrowButton("##up", ImGuiDir_Up)) {
            change([&](std::vector<MarkerChain>& all) { std::swap(all[c].markers[m], all[c].markers[m - 1]); }, "a marker moved up");
          }
          ImGui::EndDisabled();
          ImGui::SameLine();
          ImGui::BeginDisabled(m + 1 == chains[c].markers.size());
          if (ImGui::ArrowButton("##down", ImGuiDir_Down)) {
            change([&](std::vector<MarkerChain>& all) { std::swap(all[c].markers[m], all[c].markers[m + 1]); }, "a marker moved down");
          }
          ImGui::EndDisabled();
          ImGui::SameLine();
          if (ImGui::Button("x", ImVec2(ImGui::GetFrameHeight(), 0.0f))) {
            change([&](std::vector<MarkerChain>& all) { all[c].markers.erase(all[c].markers.begin() + static_cast<std::ptrdiff_t>(m)); },
                   "a marker taken out");
          }
          ImGui::PopID();
          if (c >= chains.size() || m >= chains[c].markers.size()) {
            break;
          }
        }
        ImGui::BeginDisabled(selected.empty());
        if (ImGui::SmallButton("Add the selected")) {
          change(
            [&](std::vector<MarkerChain>& all) {
              for (const std::string& name : selected) {
                if (std::find(all[c].markers.begin(), all[c].markers.end(), name) == all[c].markers.end()) {
                  all[c].markers.push_back(name);
                }
              }
            },
            "markers added");
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::SmallButton("Delete chain")) {
          change([&](std::vector<MarkerChain>& all) { all.erase(all.begin() + static_cast<std::ptrdiff_t>(c)); }, "a chain deleted");
          ImGui::TreePop();
          ImGui::PopID();
          break;
        }
        char name[128];
        (void)std::snprintf(name, sizeof(name), "%s", chains[c].name.c_str());
        ImGui::SetNextItemWidth(-1.0f);
        if (ImGui::InputText("##rename", name, sizeof(name), ImGuiInputTextFlags_EnterReturnsTrue) && name[0] != '\0') {
          const std::string wanted = name;
          const bool taken = std::any_of(chains.begin(), chains.end(), [&](const MarkerChain& other) { return other.name == wanted; });
          if (!taken) {
            change([&](std::vector<MarkerChain>& all) { all[c].name = wanted; }, "a chain renamed");
          }
        }
        ImGui::TreePop();
      }
      ImGui::PopID();
    }
    // A new chain, from the selected markers in their selection order.
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize("New chain").x - ImGui::GetStyle().FramePadding.x * 4.0f);
    ImGui::InputTextWithHint("##newchain", "chain name", mNewChainName, sizeof(mNewChainName));
    ImGui::SameLine();
    const std::string wanted = mNewChainName;
    const bool taken = std::any_of(chains.begin(), chains.end(), [&](const MarkerChain& other) { return other.name == wanted; });
    ImGui::BeginDisabled(wanted.empty() || taken);
    if (ImGui::Button("New chain")) {
      change([&](std::vector<MarkerChain>& all) { all.push_back({wanted, selected}); }, "a chain made");
      mNewChainName[0] = '\0';
    }
    ImGui::EndDisabled();
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
    ImGui::TextWrapped("A chain is a route scripts and the AI follow (Naval_Chain_Left on Seton's Clutch). A new one takes the selected "
                       "markers; a click on a chain selects its markers. Renaming or deleting a marker updates the chains.");
    ImGui::PopStyleColor();
    ImGui::Separator();
  }

  namespace
  {
    float CheckGround(const void* const context, const float x, const float z)
    {
      auto* const terrain = const_cast<moho::IWldTerrainRes*>(static_cast<const moho::IWldTerrainRes*>(context));
      return terrain->GetHeightAt(static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z)));
    }
  } // namespace

  void EdShell::CheckPathing(const MarkerCheckInput& input)
  {
    moho::CWldMap* const map = mDocument.Map();
    const moho::CHeightField* const field = map != nullptr && map->mTerrainRes != nullptr ? map->mTerrainRes->GetHeightField() : nullptr;
    if (field == nullptr) {
      return;
    }
    // The units' footprints from their blueprints (a T1 tank and a T1 frigate; fallbacks when the rules lack them).
    const auto footprintOf = [](const char* const unitId, PathFootprint fallback) {
      const char* from = "a fallback: the rules aren't built yet or lack it";
      if (moho::RRuleGameRules* const rules = moho::RULE_PeekKept(); rules != nullptr) {
        moho::RResId id{};
        id.name.assign(unitId);
        if (const moho::RUnitBlueprint* const blueprint = rules->GetUnitBlueprint(id);
            blueprint != nullptr && blueprint->Physics.ResolvedFootprint != nullptr) {
          const moho::SFootprint& footprint = *blueprint->Physics.ResolvedFootprint;
          fallback.caps = static_cast<std::uint8_t>(footprint.mOccupancyCaps);
          fallback.maxSlope = footprint.mMaxSlope;
          fallback.minWaterDepth = footprint.mMinWaterDepth;
          fallback.maxWaterDepth = footprint.mMaxWaterDepth;
          from = "its blueprint";
        }
      }
      gpg::Logf("editor: pathing as %s (%s): caps 0x%02x, max slope %.2f, water depth %.2f to %.2f", unitId, from, fallback.caps,
                static_cast<double>(fallback.maxSlope), static_cast<double>(fallback.minWaterDepth), static_cast<double>(fallback.maxWaterDepth));
      return fallback;
    };
    const char* const unitId = "uel0201";
    const char* const shipId = "ues0103";
    const PathFootprint land = footprintOf(unitId, PathFootprint{0x1, 0.75f, 0.0f, 0.0f});
    const PathFootprint ship = footprintOf(shipId, PathFootprint{0x8, 0.0f, 1.5f, 0.0f});
    const int cellsX = field->width - 1;
    const int cellsZ = field->height - 1;
    const std::vector<std::uint8_t> cells = PassableCells(field->data, field->width, field->height, input.water, input.waterLevel, land);
    std::vector<int> areas;
    const int areaCount = ConnectAreas(cells, cellsX, cellsZ, areas);

    // Each start's land area, and the resources reached in it.
    struct Start
    {
      const SaveEntry* marker;
      float x;
      float z;
      int area;
      int mass;
      int hydro;
    };
    std::vector<Start> starts;
    int massTotal = 0;
    int hydroTotal = 0;
    for (const SaveEntry& marker : *input.markers) {
      const std::string type = MarkerTypeOf(marker);
      float x = 0.0f, y = 0.0f, z = 0.0f;
      if (!MarkerPosition(marker, x, y, z)) {
        continue;
      }
      if (type == "Blank Marker") {
        starts.push_back({&marker, x, z, AreaNear(areas, cellsX, cellsZ, x, z, 1), 0, 0});
      }
      massTotal += type == "Mass" ? 1 : 0;
      hydroTotal += type == "Hydrocarbon" ? 1 : 0;
    }
    for (const SaveEntry& marker : *input.markers) {
      const std::string type = MarkerTypeOf(marker);
      float x = 0.0f, y = 0.0f, z = 0.0f;
      if ((type != "Mass" && type != "Hydrocarbon") || !MarkerPosition(marker, x, y, z)) {
        continue;
      }
      const int area = AreaNear(areas, cellsX, cellsZ, x, z, 3);
      for (Start& start : starts) {
        if (area != 0 && area == start.area) {
          ++(type == "Mass" ? start.mass : start.hydro);
        }
      }
    }
    int bestMass = 0;
    std::vector<int> startAreas;
    for (const Start& start : starts) {
      bestMass = std::max(bestMass, start.mass);
      if (start.area != 0 && std::find(startAreas.begin(), startAreas.end(), start.area) == startAreas.end()) {
        startAreas.push_back(start.area);
      }
    }
    for (const Start& start : starts) {
      CheckIssue issue;
      issue.marker = start.marker->name;
      issue.x = start.x;
      issue.z = start.z;
      if (start.area == 0) {
        issue.level = CheckIssue::Level::Error;
        issue.text = std::string("start position is on ground a ") + unitId + " can't stand on";
        mCheckIssues.push_back(issue);
        continue;
      }
      char text[200];
      (void)std::snprintf(text, sizeof(text), "reaches %d of %d mass and %d of %d hydrocarbon points by land%s", start.mass, massTotal, start.hydro,
                          hydroTotal, startAreas.size() > 1 ? " (the starts are on more than one land area)" : "");
      issue.level = start.mass < bestMass ? CheckIssue::Level::Warning : CheckIssue::Level::Note;
      issue.text = text;
      mCheckIssues.push_back(issue);
    }

    // Naval: the ship water nearest each start (within 64 units), and whether the starts' waters meet.
    const std::vector<std::uint8_t> shipCells = PassableCells(field->data, field->width, field->height, input.water, input.waterLevel, ship);
    std::vector<int> shipAreas;
    const int shipAreaCount = ConnectAreas(shipCells, cellsX, cellsZ, shipAreas);
    std::vector<int> startWaters;
    std::vector<int> waterOfStart;
    for (const Start& start : starts) {
      const int water = AreaNear(shipAreas, cellsX, cellsZ, start.x, start.z, 64);
      waterOfStart.push_back(water);
      if (water != 0 && std::find(startWaters.begin(), startWaters.end(), water) == startWaters.end()) {
        startWaters.push_back(water);
      }
    }
    const std::size_t withWater = static_cast<std::size_t>(std::count_if(waterOfStart.begin(), waterOfStart.end(), [](const int w) { return w != 0; }));
    if (withWater > 0) {
      for (std::size_t i = 0; i < starts.size(); ++i) {
        CheckIssue issue;
        issue.marker = starts[i].marker->name;
        issue.x = starts[i].x;
        issue.z = starts[i].z;
        if (waterOfStart[i] == 0) {
          issue.level = CheckIssue::Level::Warning;
          issue.text = std::string("no water a ") + shipId + " can use within 64 units, while " + std::to_string(withWater) + " of " +
                       std::to_string(starts.size()) + " starts have some";
        } else {
          issue.level = startWaters.size() > 1 ? CheckIssue::Level::Warning : CheckIssue::Level::Note;
          issue.text = std::string("has water a ") + shipId + " can use within 64 units" +
                       (startWaters.size() > 1 ? "; the starts' waters don't all meet (" + std::to_string(startWaters.size()) + " separate)" : ", joined with the other starts'");
        }
        mCheckIssues.push_back(issue);
      }
    }

    // The overlay: blocks of up to 256 a side, red where the land unit can't go, amber where it can but no start reaches.
    const int block = std::max(1, (std::max(cellsX, cellsZ) + 255) / 256);
    std::vector<EdTools::PathQuad> quads;
    for (int bz = 0; bz < cellsZ; bz += block) {
      for (int bx = 0; bx < cellsX; bx += block) {
        int blocked = 0;
        int lone = 0;
        int total = 0;
        for (int z = bz; z < std::min(bz + block, cellsZ); ++z) {
          for (int x = bx; x < std::min(bx + block, cellsX); ++x) {
            const int area = areas[static_cast<std::size_t>(z) * static_cast<std::size_t>(cellsX) + static_cast<std::size_t>(x)];
            ++total;
            if (area == 0) {
              ++blocked;
            } else if (std::find(startAreas.begin(), startAreas.end(), area) == startAreas.end()) {
              ++lone;
            }
          }
        }
        const float x0 = static_cast<float>(bx);
        const float z0 = static_cast<float>(bz);
        const float x1 = static_cast<float>(std::min(bx + block, cellsX));
        const float z1 = static_cast<float>(std::min(bz + block, cellsZ));
        if (blocked * 2 >= total) {
          quads.push_back({x0, z0, x1, z1, 0x60FF3020u});
        } else if (lone * 2 >= total) {
          quads.push_back({x0, z0, x1, z1, 0x50FFB020u});
        }
      }
    }
    // Ships: blue where they can go in a start's water, purple where they can go but no start's ships get to.
    std::vector<EdTools::PathQuad> shipQuads;
    for (int bz = 0; bz < cellsZ; bz += block) {
      for (int bx = 0; bx < cellsX; bx += block) {
        int used = 0;
        int lone = 0;
        int total = 0;
        for (int z = bz; z < std::min(bz + block, cellsZ); ++z) {
          for (int x = bx; x < std::min(bx + block, cellsX); ++x) {
            const int area = shipAreas[static_cast<std::size_t>(z) * static_cast<std::size_t>(cellsX) + static_cast<std::size_t>(x)];
            ++total;
            if (area == 0) {
              continue;
            }
            ++(std::find(startWaters.begin(), startWaters.end(), area) != startWaters.end() ? used : lone);
          }
        }
        const float x0 = static_cast<float>(bx);
        const float z0 = static_cast<float>(bz);
        const float x1 = static_cast<float>(std::min(bx + block, cellsX));
        const float z1 = static_cast<float>(std::min(bz + block, cellsZ));
        if (used * 2 >= total) {
          shipQuads.push_back({x0, z0, x1, z1, 0x503C8CFFu});
        } else if (lone * 2 >= total) {
          shipQuads.push_back({x0, z0, x1, z1, 0x50B048E0u});
        }
      }
    }
    const std::size_t landBlocks = quads.size();
    const std::size_t shipBlocks = shipQuads.size();
    mTools.SetPathing(std::move(quads), std::move(shipQuads));
    gpg::Logf("editor: pathing: %d land areas, starts on %zu of them; %d ship areas, %zu starts with ship water in %zu of them; %zu land and %zu ship overlay "
              "blocks of %d cells",
              areaCount, startAreas.size(), shipAreaCount, withWater, startWaters.size(), landBlocks, shipBlocks, block);
  }

  void EdShell::RunCheck()
  {
    mCheckIssues.clear();
    mCheckRan = true;
    mCheckedPath = mDocument.Path();
    moho::CWldMap* const map = mDocument.Map();
    if (map == nullptr || map->mTerrainRes == nullptr) {
      return;
    }
    const MapFacts& facts = mDocument.Facts();
    MarkerCheckInput input;
    input.markers = &mDocument.SaveData().Markers();
    if (const std::optional<EdDocument::PlayableRect> area = mDocument.PlayableArea()) {
      input.playable = std::array<int, 4>{area->x0, area->z0, area->x1, area->z1};
    }
    input.water = facts.water;
    input.waterLevel = facts.waterElevation;
    input.groundAt = &CheckGround;
    input.groundContext = map->mTerrainRes;
    const HeightBrush brush = mTools.CurrentHeightBrush();
    input.symmetry = brush.symmetry;
    input.turns = brush.turns;
    input.width = facts.fieldWidth;
    input.height = facts.fieldHeight;
    mCheckIssues = CheckMarkers(input);
    CheckPathing(input);
    // The scripts' syntax, as the files are now (edits included).
    for (CheckIssue& issue : mDocument.CheckScripts()) {
      mCheckIssues.insert(mCheckIssues.begin(), std::move(issue));
    }
    std::vector<EdTools::CheckPin> pins;
    int counts[3] = {0, 0, 0};
    for (const CheckIssue& issue : mCheckIssues) {
      if (issue.file.empty()) {
        pins.push_back({issue.x, issue.z, static_cast<int>(issue.level)});
      }
      ++counts[static_cast<int>(issue.level)];
    }
    mTools.SetCheckPins(std::move(pins));
    gpg::Logf("editor: check: %d errors, %d warnings, %d notes", counts[0], counts[1], counts[2]);
    for (const CheckIssue& issue : mCheckIssues) {
      if (!issue.file.empty()) {
        gpg::Logf("editor: check %s: %s line %d: %s", CheckLevelName(issue.level), issue.file.c_str(), issue.line, issue.text.c_str());
      } else {
        gpg::Logf("editor: check %s: %s: %s", CheckLevelName(issue.level), issue.marker.c_str(), issue.text.c_str());
      }
    }
  }

  void EdShell::DrawCheckPanel()
  {
    if (const ImGuiWindow* const map = ImGui::FindWindowByName(kMapWindow); map != nullptr && map->DockId != 0) {
      ImGui::SetNextWindowDockID(map->DockId, ImGuiCond_FirstUseEver);
    }
    // A requested run (`/check`) happens whether or not the tab is in front, and brings it there.
    // ... once the rules are built, so the pathing goes by the units' own footprints.
    if (mRunCheck && mDocument.GetState() == EdDocument::State::Open && moho::RULE_PeekKept() != nullptr) {
      mRunCheck = false;
      RunCheck();
      ImGui::SetNextWindowFocus();
    }
    if (!ImGui::Begin("Check", &mShowCheck)) {
      ImGui::End();
      return;
    }
    if (mDocument.GetState() != EdDocument::State::Open) {
      ImGui::TextDisabled("No map open.");
      ImGui::End();
      return;
    }
    // A run belongs to the map it ran on.
    if (mCheckRan && mCheckedPath != mDocument.Path()) {
      mCheckRan = false;
      mCheckIssues.clear();
      mTools.SetCheckPins({});
    }
    if (ImGui::Button("Run the check", ImVec2(-1.0f, 0.0f))) {
      RunCheck();
    }
    // The test run: the map played for a few seconds, its Lua errors collected.
    ImGui::BeginDisabled(mTestRunStep != 0 || mPlay.Active());
    if (ImGui::Button(mTestRunStep == 0 ? "Test run" : "Test run: playing...", ImVec2(-1.0f, 0.0f))) {
      RequestTestRun();
    }
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled | ImGuiHoveredFlags_DelayShort)) {
      ImGui::SetTooltip("Plays the map as saved (solo, the Map panel's setup) for 8 s of game time, then stops; the warnings logged meanwhile "
                        "join the findings: errors that name the map's folder, warnings from other Lua, the rest as notes. Save first to test edits.");
    }
    if (!mTestRunSummary.empty()) {
      ImGui::TextDisabled("%s", mTestRunSummary.c_str());
    }
    ImGui::Checkbox("Show pathing", &mTools.ShowPathing());
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
      ImGui::SetTooltip("After a run. Land: red where a T1 tank (uel0201) can't go (too steep, too deep), amber where it can but no start "
                        "reaches. Ships: blue where a T1 frigate (ues0103) can go in a start's water, purple where it can but no start's ships get to.");
    }
    ImGui::SameLine();
    ImGui::RadioButton("Land", &mTools.PathingLayer(), 0);
    ImGui::SameLine();
    ImGui::RadioButton("Ships", &mTools.PathingLayer(), 1);
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
    ImGui::TextWrapped("The scripts' syntax (_scenario.lua, _save.lua, _script.lua as edited), then start positions and mass and "
                       "hydrocarbon points: off the playable area, under water, without a partner at their symmetric copies (the Tools "
                       "panel's symmetry), or overlapping; then pathing for a T1 tank: what each start reaches by land.");
    ImGui::PopStyleColor();
    if (mTestRunDone && !mTestRunIssues.empty()) {
      // The test run's findings at the top of the list (merged once).
      for (CheckIssue& issue : mTestRunIssues) {
        mCheckIssues.insert(mCheckIssues.begin(), std::move(issue));
      }
      mTestRunIssues.clear();
      mTestRunDone = false;
      mCheckRan = true;
      mCheckedPath = mDocument.Path();
    }
    if (!mCheckRan) {
      ImGui::End();
      return;
    }
    if (mCheckIssues.empty()) {
      ImGui::TextColored(ImVec4(0.55f, 0.80f, 0.55f, 1.0f), "Nothing found.");
      ImGui::End();
      return;
    }
    static const ImVec4 kColors[3] = {ImVec4(0.95f, 0.40f, 0.35f, 1.0f), ImVec4(0.95f, 0.75f, 0.30f, 1.0f), ImVec4(0.55f, 0.70f, 0.95f, 1.0f)};
    int counts[3] = {0, 0, 0};
    for (const CheckIssue& issue : mCheckIssues) {
      ++counts[static_cast<int>(issue.level)];
    }
    ImGui::Text("%d errors, %d warnings, %d notes", counts[0], counts[1], counts[2]);
    ImGui::BeginChild("##checkresults", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders);
    for (std::size_t i = 0; i < mCheckIssues.size(); ++i) {
      const CheckIssue& issue = mCheckIssues[i];
      ImGui::PushID(static_cast<int>(i));
      const ImVec2 row = ImGui::GetCursorScreenPos();
      const float line = ImGui::GetTextLineHeight();
      if (ImGui::Selectable("##issue", false, ImGuiSelectableFlags_SpanAvailWidth, ImVec2(0.0f, line * 2.0f + 2.0f))) {
        if (!issue.file.empty()) {
          // A script's error: its text in the Script panel, at the line.
          mShowScript = true;
          mFocusScript = true;
          mScriptErrorLine = issue.line;
          mScriptMessage = issue.file + " line " + std::to_string(issue.line) + ": " + issue.text;
        } else if (!issue.marker.empty()) {
          mTools.AskMarkerSelect({issue.marker}, false);
          mTools.AskMarkerFrame(issue.marker);
        }
      }
      if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
        ImGui::SetTooltip("%s: %s\n%s\nClick to go to it", CheckLevelName(issue.level), issue.marker.c_str(), issue.text.c_str());
      }
      ImDrawList* const draw = ImGui::GetWindowDrawList();
      draw->AddCircleFilled(ImVec2(row.x + line * 0.4f, row.y + line * 0.5f), line * 0.28f, ImGui::GetColorU32(kColors[static_cast<int>(issue.level)]));
      const std::string title = issue.file.empty() ? issue.marker : issue.file + " line " + std::to_string(issue.line);
      draw->AddText(ImVec2(row.x + line * 1.1f, row.y), ImGui::GetColorU32(ImGuiCol_Text), title.c_str());
      draw->PushClipRect(row, ImVec2(ImGui::GetItemRectMax().x, row.y + line * 2.0f + 2.0f), true);
      draw->AddText(ImVec2(row.x + line * 1.1f, row.y + line), ImGui::GetColorU32(ImGuiCol_TextDisabled), issue.text.c_str());
      draw->PopClipRect();
      ImGui::PopID();
    }
    ImGui::EndChild();
    ImGui::End();
  }
  namespace
  {
    /** ImGui's text callback growing a std::string as the text grows. */
    int GrowString(ImGuiInputTextCallbackData* const data)
    {
      if (data->EventFlag == ImGuiInputTextFlags_CallbackResize) {
        auto* const text = static_cast<std::string*>(data->UserData);
        text->resize(static_cast<std::size_t>(data->BufTextLen));
        data->Buf = text->data();
      }
      return 0;
    }
  } // namespace

  void EdShell::DrawScriptPanel()
  {
    if (const ImGuiWindow* const map = ImGui::FindWindowByName(kMapWindow); map != nullptr && map->DockId != 0) {
      ImGui::SetNextWindowDockID(map->DockId, ImGuiCond_FirstUseEver);
    }
    if (mFocusScript) {
      mFocusScript = false;
      ImGui::SetNextWindowFocus();
    }
    if (!ImGui::Begin("Script", &mShowScript)) {
      ImGui::End();
      return;
    }
    if (mDocument.GetState() != EdDocument::State::Open) {
      ImGui::TextDisabled("No map open.");
      ImGui::End();
      return;
    }
    // The panel's copy follows the document until it is edited, and again after Apply or Revert.
    const bool edited = mScriptFor == mDocument.Path() && mScriptBuffer != mDocument.Script();
    if (mScriptFor != mDocument.Path()) {
      mScriptFor = mDocument.Path();
      mScriptBuffer = mDocument.Script();
      mScriptMessage.clear();
    }
    ImGui::TextDisabled("%s", MapDisplayName(mDocument.Facts().scriptPath).c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("%s", mDocument.Facts().scriptPath.c_str());
    ImGui::BeginDisabled(!edited);
    if (ImGui::Button("Apply")) {
      EdDocument::SaveSnapshot before = mDocument.SaveDataNow();
      mDocument.Script() = mScriptBuffer;
      mDocument.SaveDataEdited(std::move(before));
      mScriptMessage = "applied (one undo step)";
      gpg::Logf("editor: script applied, %zu bytes", mScriptBuffer.size());
    }
    ImGui::SameLine();
    if (ImGui::Button("Revert")) {
      mScriptBuffer = mDocument.Script();
      mScriptMessage.clear();
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Check")) {
      // The panel's text as it would be applied.
      const std::string kept = mDocument.Script();
      mDocument.Script() = mScriptBuffer;
      const std::vector<CheckIssue> issues = mDocument.CheckScripts();
      mDocument.Script() = kept;
      mScriptMessage = "compiles";
      mScriptErrorLine = 0;
      for (const CheckIssue& issue : issues) {
        if (issue.file == MapDisplayName(mDocument.Facts().scriptPath) || issue.file.find("_script.lua") != std::string::npos) {
          mScriptMessage = "line " + std::to_string(issue.line) + ": " + issue.text;
          mScriptErrorLine = issue.line;
        }
      }
      gpg::Logf("editor: script check: %s", mScriptMessage.c_str());
    }
    if (!mScriptMessage.empty()) {
      ImGui::PushTextWrapPos(0.0f);
      ImGui::TextColored(mScriptErrorLine > 0 ? ImVec4(0.95f, 0.45f, 0.40f, 1.0f) : ImVec4(0.55f, 0.80f, 0.55f, 1.0f), "%s", mScriptMessage.c_str());
      ImGui::PopTextWrapPos();
    }
    if (mScriptErrorLine > 0) {
      // The line in question, under the buttons.
      std::size_t start = 0;
      for (int line = 1; line < mScriptErrorLine && start != std::string::npos; ++line) {
        start = mScriptBuffer.find('\n', start);
        start = start == std::string::npos ? start : start + 1;
      }
      if (start != std::string::npos) {
        const std::size_t end = mScriptBuffer.find('\n', start);
        ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.30f, 1.0f), "%d: %s", mScriptErrorLine,
                           mScriptBuffer.substr(start, end == std::string::npos ? std::string::npos : end - start).c_str());
      }
    }
    ImGui::InputTextMultiline("##script", mScriptBuffer.data(), mScriptBuffer.capacity() + 1, ImVec2(-1.0f, -1.0f),
                              ImGuiInputTextFlags_AllowTabInput | ImGuiInputTextFlags_CallbackResize, &GrowString, &mScriptBuffer);
    ImGui::End();
  }
  void EdShell::DrawLightingPanel()
  {
    if (const ImGuiWindow* const map = ImGui::FindWindowByName(kMapWindow); map != nullptr && map->DockId != 0) {
      ImGui::SetNextWindowDockID(map->DockId, ImGuiCond_FirstUseEver);
    }
    if (!ImGui::Begin("Lighting", &mShowLighting)) {
      ImGui::End();
      return;
    }
    if (mDocument.GetState() != EdDocument::State::Open) {
      ImGui::TextDisabled("No map open.");
      ImGui::End();
      return;
    }
    // The panel's copy follows the map until a control is held; a change is on the map at once, and one undo step
    // when the drag (or the edit) ends.
    if (!mLightingEditing) {
      mLighting = mDocument.LightingNow();
    }
    bool active = false;
    bool changed = false;
    bool finished = false;
    const auto watch = [&](const bool edited) {
      active = active || ImGui::IsItemActive();
      changed = changed || edited;
      finished = finished || ImGui::IsItemDeactivatedAfterEdit();
    };
    ImGui::SeparatorText("Sun");
    ImGui::SetNextItemWidth(-1.0f);
    watch(ImGui::DragFloat("##multiplier", &mLighting.multiplier, 0.01f, 0.0f, 10.0f, "Light multiplier %.2f"));
    ImGui::SetNextItemWidth(-1.0f);
    watch(ImGui::DragFloat3("##sundirection", mLighting.sunDirection, 0.005f, -1.0f, 1.0f, "%.3f"));
    ImGui::TextDisabled("Direction (x, y, z)");
    ImGui::SetNextItemWidth(-1.0f);
    watch(ImGui::ColorEdit3("##suncolor", mLighting.sunColor, ImGuiColorEditFlags_Float | ImGuiColorEditFlags_HDR));
    ImGui::TextDisabled("Sun colour");
    ImGui::SetNextItemWidth(-1.0f);
    watch(ImGui::ColorEdit3("##ambience", mLighting.sunAmbience, ImGuiColorEditFlags_Float | ImGuiColorEditFlags_HDR));
    ImGui::TextDisabled("Ambience");
    ImGui::SetNextItemWidth(-1.0f);
    watch(ImGui::ColorEdit3("##shadow", mLighting.shadowFill, ImGuiColorEditFlags_Float | ImGuiColorEditFlags_HDR));
    ImGui::TextDisabled("Shadow fill");
    ImGui::SetNextItemWidth(-1.0f);
    watch(ImGui::ColorEdit4("##specular", mLighting.specular, ImGuiColorEditFlags_Float | ImGuiColorEditFlags_HDR));
    ImGui::TextDisabled("Specular");
    ImGui::SetNextItemWidth(-1.0f);
    watch(ImGui::DragFloat("##bloom", &mLighting.bloom, 0.005f, 0.0f, 5.0f, "Bloom %.3f"));
    ImGui::SeparatorText("Fog");
    ImGui::SetNextItemWidth(-1.0f);
    watch(ImGui::ColorEdit3("##fogcolor", mLighting.fogColor, ImGuiColorEditFlags_Float));
    ImGui::SetNextItemWidth(-1.0f);
    watch(ImGui::DragFloat("##fogstart", &mLighting.fogStart, 1.0f, -1000.0f, 10000.0f, "Start %.0f"));
    ImGui::SetNextItemWidth(-1.0f);
    watch(ImGui::DragFloat("##fogend", &mLighting.fogEnd, 1.0f, -1000.0f, 10000.0f, "End %.0f"));
    if (changed) {
      if (!mLightingEditing) {
        mLightingBefore = mDocument.LightingNow();
      }
      mLightingEditing = true;
      mDocument.ApplyLighting(mLighting);
    }
    if (finished || (mLightingEditing && !active)) {
      mLightingEditing = false;
      if (!(mLightingBefore == mDocument.LightingNow())) {
        mDocument.LightingEdited(mLightingBefore);
        gpg::Logf("editor: lighting: multiplier %.2f, bloom %.3f, fog %.0f to %.0f", static_cast<double>(mLighting.multiplier),
                  static_cast<double>(mLighting.bloom), static_cast<double>(mLighting.fogStart), static_cast<double>(mLighting.fogEnd));
      }
    }
    ImGui::SeparatorText("From another map");
    {
      // Any map the game lists: its lighting read from its .scmap, as FAForeverMapEditor's retail presets are.
      const std::vector<std::string>& maps = mPlay.Maps();
      const std::vector<std::string>& titles = mPlay.Titles();
      ImGui::SetNextItemWidth(-1.0f);
      ImGui::InputTextWithHint("##lightingfromfilter", "search maps", mLightingFromFilter, sizeof(mLightingFromFilter));
      std::string filter = mLightingFromFilter;
      for (char& c : filter) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      if (ImGui::BeginChild("##lightingfrom", ImVec2(0.0f, ImGui::GetTextLineHeightWithSpacing() * 6.0f), ImGuiChildFlags_Borders)) {
        for (std::size_t i = 0; i < maps.size(); ++i) {
          const std::string folder = MapDisplayName(maps[i]);
          const std::string title = i < titles.size() && !titles[i].empty() ? titles[i] : folder;
          std::string key = folder + " " + title;
          for (char& c : key) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
          }
          if (!filter.empty() && key.find(filter) == std::string::npos) {
            continue;
          }
          ImGui::PushID(static_cast<int>(i));
          if (ImGui::Selectable(title.c_str())) {
            mLightingFromMap = maps[i];
          }
          ImGui::SameLine();
          ImGui::TextDisabled("%s", folder.c_str());
          ImGui::PopID();
        }
      }
      ImGui::EndChild();
      ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
      ImGui::TextWrapped("A click takes that map's sun, ambience, shadow, specular, bloom and fog, as one undo step.");
      ImGui::PopStyleColor();
    }
    ImGui::SeparatorText("Settings file");
    if (ImGui::Button("Import .scmlighting...")) {
      mLightingImport = true;
    }
    ImGui::SameLine();
    if (ImGui::Button("Export...")) {
      mLightingExport = true;
    }
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
    ImGui::TextWrapped("FAForeverMapEditor's lighting settings file: the sun, ambience, shadow, specular, bloom and fog.");
    ImGui::PopStyleColor();
    ImGui::SeparatorText("Sky");
    {
      const SkyboxState sky = mDocument.SkyboxNow();
      ImGui::Text("Dome %.0f across, %d x %d segments", static_cast<double>(sky.scale), sky.subdivisionsAxis, sky.subdivisionsHeight);
      ImGui::ColorButton("##horizon", ImVec4(sky.horizonColor[0], sky.horizonColor[1], sky.horizonColor[2], 1.0f), ImGuiColorEditFlags_NoTooltip);
      ImGui::SameLine();
      ImGui::TextUnformatted("horizon");
      ImGui::SameLine();
      ImGui::ColorButton("##zenith", ImVec4(sky.zenithColor[0], sky.zenithColor[1], sky.zenithColor[2], 1.0f), ImGuiColorEditFlags_NoTooltip);
      ImGui::SameLine();
      ImGui::TextUnformatted("zenith");
      ImGui::Text("%zu planet%s, cirrus %s", sky.planets.size(), sky.planets.size() == 1 ? "" : "s",
                  sky.cirrusTexture.empty() ? "(none)" : sky.cirrusTexture.substr(sky.cirrusTexture.find_last_of('/') + 1).c_str());
    }
    if (ImGui::Button("Import .scmskybox...")) {
      mSkyboxImport = true;
    }
    ImGui::SameLine();
    if (ImGui::Button("Export##sky")) {
      mSkyboxExport = true;
    }
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
    ImGui::TextWrapped("FAForeverMapEditor's sky file: the dome, horizon and zenith colours, planets and cirrus. An import is one "
                       "undo step and is saved with the map.");
    ImGui::PopStyleColor();
    ImGui::End();
  }
} // namespace faf::editor
