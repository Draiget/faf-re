// The Info panel (what the open map is) and the Markers panel (its markers as a tree), EdShell's right-hand panels.

#include "editor/EdShell.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <map>

#include "editor/EdPlay.h"
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
  namespace
  {
    float CheckGround(const void* const context, const float x, const float z)
    {
      auto* const terrain = const_cast<moho::IWldTerrainRes*>(static_cast<const moho::IWldTerrainRes*>(context));
      return terrain->GetHeightAt(static_cast<std::int32_t>(std::lround(x)), static_cast<std::int32_t>(std::lround(z)));
    }
  } // namespace

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
    std::vector<EdTools::CheckPin> pins;
    int counts[3] = {0, 0, 0};
    for (const CheckIssue& issue : mCheckIssues) {
      pins.push_back({issue.x, issue.z, static_cast<int>(issue.level)});
      ++counts[static_cast<int>(issue.level)];
    }
    mTools.SetCheckPins(std::move(pins));
    gpg::Logf("editor: check: %d errors, %d warnings, %d notes", counts[0], counts[1], counts[2]);
    for (const CheckIssue& issue : mCheckIssues) {
      gpg::Logf("editor: check %s: %s: %s", CheckLevelName(issue.level), issue.marker.c_str(), issue.text.c_str());
    }
  }

  void EdShell::DrawCheckPanel()
  {
    if (const ImGuiWindow* const map = ImGui::FindWindowByName(kMapWindow); map != nullptr && map->DockId != 0) {
      ImGui::SetNextWindowDockID(map->DockId, ImGuiCond_FirstUseEver);
    }
    // A requested run (`/check`) happens whether or not the tab is in front, and brings it there.
    if (mRunCheck && mDocument.GetState() == EdDocument::State::Open) {
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
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
    ImGui::TextWrapped("Start positions and mass and hydrocarbon points: off the playable area, under water, without a partner at "
                       "their symmetric copies (the Tools panel's symmetry), or overlapping. Scripts and pathing come next.");
    ImGui::PopStyleColor();
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
        if (!issue.marker.empty()) {
          mTools.AskMarkerSelect({issue.marker}, false);
          mTools.AskMarkerFrame(issue.marker);
        }
      }
      if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
        ImGui::SetTooltip("%s: %s\n%s\nClick to go to it", CheckLevelName(issue.level), issue.marker.c_str(), issue.text.c_str());
      }
      ImDrawList* const draw = ImGui::GetWindowDrawList();
      draw->AddCircleFilled(ImVec2(row.x + line * 0.4f, row.y + line * 0.5f), line * 0.28f, ImGui::GetColorU32(kColors[static_cast<int>(issue.level)]));
      draw->AddText(ImVec2(row.x + line * 1.1f, row.y), ImGui::GetColorU32(ImGuiCol_Text), issue.marker.c_str());
      draw->PushClipRect(row, ImVec2(ImGui::GetItemRectMax().x, row.y + line * 2.0f + 2.0f), true);
      draw->AddText(ImVec2(row.x + line * 1.1f, row.y + line), ImGui::GetColorU32(ImGuiCol_TextDisabled), issue.text.c_str());
      draw->PopClipRect();
      ImGui::PopID();
    }
    ImGui::EndChild();
    ImGui::End();
  }
} // namespace faf::editor
