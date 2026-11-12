// The Particle Browser (View > Particle Browser): the game's effects in a grid, previewed live; part of the particle
// editor (it shares its preview and opens effects in it).

#include "editor/ui/EdParticleEditor.h"
#include "editor/ui/EdWorkspaces.h"
#include "editor/ui/EdUiScale.h"

#include "editor/doc/EdMapFile.h"
#include "imgui.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <iterator>

namespace faf::editor
{
  namespace
  {
    std::string LowerText(
      std::string text
    )
    {
      std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return text;
    }

    const char* const kTypes[] = {"All types", "Emitters", "Beams", "Trails"};
    const ImU32 kTypeColors[] = {
      IM_COL32(120, 120, 120, 255),
      IM_COL32(240, 170, 80, 255),
      IM_COL32(110, 160, 255, 255),
      IM_COL32(120, 220, 140, 255)
    };
  } // namespace

  void EdParticleEditor::ListEffects()
  {
    if (mEffectsListed) {
      return;
    }
    mEffectsListed = true;
    moho::CVirtualFileSystem* vfs = moho::DISK_GetVFS();
    if (vfs == nullptr) {
      return;
    }
    fa::vector<fa::string> found;
    vfs->EnumerateFiles("/effects", "*.bp", true, &found);
    for (const fa::string& file : found) {
      EffectInfo info;
      info.path = file.c_str();
      info.name = info.path.substr(info.path.find_last_of('/') + 1);
      if (const std::size_t dot = info.name.rfind(".bp"); dot != std::string::npos) {
        info.name = info.name.substr(0, dot);
      }
      info.faction = EffectFaction(info.path);
      info.kind = EffectKind(info.path);
      mEffects.push_back(std::move(info));
    }
    std::sort(mEffects.begin(), mEffects.end(), [](const EffectInfo& a, const EffectInfo& b) {
      return LowerText(a.name) < LowerText(b.name);
    });
  }

  void EdParticleEditor::TestBrowse(
    const std::string& search
  )
  {
    ListEffects();
    (void)std::snprintf(mGridFilter, sizeof(mGridFilter), "%s", search.c_str());
    const std::string filter = LowerText(search);
    for (const EffectInfo& info : mEffects) {
      if (LowerText(info.name).find(filter) != std::string::npos && OpenGameEmitter(info.path)) {
        mBrowserPick = info.path;
        return;
      }
    }
  }

  void EdParticleEditor::ReadEffect(
    EffectInfo& info
  )
  {
    // Its type and textures, from its file, once (only for the tiles that show).
    info.read = true;
    std::string text;
    if (!ReadGameFile(info.path, text)) {
      return;
    }
    EmitterBlueprint emitter;
    std::string error;
    if (ParseEmitter(text, emitter, error)) {
      info.type = 1;
      info.texture = emitter.texture;
      info.ramp = emitter.rampTexture;
      info.blendMode = static_cast<int>(emitter.blendMode);
      return;
    }
    FlatBlueprint flat;
    if (ParseFlatBlueprint(text, flat, error)) {
      const bool beam = flat.kind == "BeamBlueprint";
      info.type = beam ? 2 : 3;
      info.texture = flat.Text(beam ? "TextureName" : "RepeatTexture");
      info.ramp = beam ? std::string() : flat.Text("RampTexture");
    }
  }

  void EdParticleEditor::DrawBrowserWindow(
    bool& open
  )
  {
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowSize(ImVec2(viewport->WorkSize.x * 0.8f, viewport->WorkSize.y * 0.75f), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowPos(
      ImVec2(viewport->WorkPos.x + viewport->WorkSize.x * 0.5f, viewport->WorkPos.y + viewport->WorkSize.y * 0.5f),
      ImGuiCond_FirstUseEver,
      ImVec2(0.5f, 0.5f)
    );
    ImGui::SetNextWindowCollapsed(false, ImGuiCond_Always);
    if (!ImGui::Begin(Panel("Particle Browser"), &open, ImGuiWindowFlags_NoCollapse)) {
      ImGui::End();
      return;
    }
    ListEffects();
    if (
      ImGui::BeginTable(
        "##browser", 2, ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV, ImGui::GetContentRegionAvail()
      )
    ) {
      ImGui::TableSetupColumn(
        "preview", ImGuiTableColumnFlags_WidthFixed, std::max(ImGui::GetContentRegionAvail().x * 0.35f, 300.0f)
      );
      ImGui::TableSetupColumn("grid", ImGuiTableColumnFlags_WidthStretch);
      ImGui::TableNextRow();

      // The live preview of the picked effect, and what it is.
      ImGui::TableSetColumnIndex(0);
      DrawPreviewPane();
      ImGui::SeparatorText(mBrowserPick.empty() ? "Pick an effect" : mName.c_str());
      if (!mBrowserPick.empty()) {
        ImGui::TextDisabled("%s", mBrowserPick.c_str());
        ImGui::Text("%s", mFlatMode ? (mFlat.kind == "BeamBlueprint" ? "Beam" : "Trail") : "Emitter");
        if (!mFlatMode) {
          char life[32];
          (void)std::snprintf(life, sizeof(life), "%.1f ticks", static_cast<double>(mEmitter.lifetime));
          ImGui::Text(
            "Lifetime %s, blend %s",
            mEmitter.lifetime < 0.0f ? "endless" : life,
            kEmitterBlendModes[std::clamp(static_cast<int>(mEmitter.blendMode), 0, 5)]
          );
        }
        ImGui::Spacing();
        if (ImGui::Button("Edit in the Particle Editor", ImVec2(-1.0f, 0.0f))) {
          mOpenEditorAsk = true; // the editor opens and this browser closes (EdShell)
        }
        ImGui::SetItemTooltip(
          "Opens it in the Particle Editor to change (this browser closes); Save there writes a copy into the map's "
          "folder"
        );
        if (ImGui::Button("Place on the map", ImVec2(-1.0f, 0.0f))) {
          mPlaceAsk = mBrowserPick;
        }
        ImGui::SetItemTooltip(
          "An effect decoration at the middle of the map's view (an Effect marker: move it with the Markers tool; "
          "the map's script plays it in the game)"
        );
      } else {
        ImGui::TextWrapped(
          "Click an effect to play it here (and at the middle of the map's view). The wheel over the preview zooms."
        );
      }

      // The grid: filters, then a tile per effect.
      ImGui::TableSetColumnIndex(1);
      ImGui::SetNextItemWidth(Em(130.0f));
      (void)ImGui::Combo("##faction", &mBrowseFaction, kEffectFactions, static_cast<int>(std::size(kEffectFactions)));
      ImGui::SameLine();
      ImGui::SetNextItemWidth(Em(130.0f));
      (void)ImGui::Combo("##kind", &mBrowseKind, kEffectKinds, static_cast<int>(std::size(kEffectKinds)));
      ImGui::SameLine();
      ImGui::SetNextItemWidth(Em(110.0f));
      (void)ImGui::Combo("##type", &mBrowseType, kTypes, 4);
      ImGui::SetItemTooltip("Types are read from the files as their tiles show");
      ImGui::SameLine();
      ImGui::SetNextItemWidth(-1.0f);
      ImGui::InputTextWithHint("##search", "Search names", mGridFilter, sizeof(mGridFilter));
      const std::string filter = LowerText(mGridFilter);
      std::vector<EffectInfo*> shown;
      for (EffectInfo& info : mEffects) {
        if (
          (mBrowseFaction != 0 && info.faction != mBrowseFaction) || (mBrowseKind != 0 && info.kind != mBrowseKind) ||
          (mBrowseType != 0 && info.read && info.type != mBrowseType) ||
          (!filter.empty() && LowerText(info.name).find(filter) == std::string::npos)
        ) {
          continue;
        }
        shown.push_back(&info);
      }
      ImGui::TextDisabled("%zu of %zu effects", shown.size(), mEffects.size());
      if (ImGui::BeginChild("##tiles", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders)) {
        constexpr float kTile = 112.0f;
        const float pad = ImGui::GetStyle().ItemSpacing.x;
        const int columns = std::max(1, static_cast<int>((ImGui::GetContentRegionAvail().x + pad) / (kTile + pad)));
        const int rows = (static_cast<int>(shown.size()) + columns - 1) / columns;
        const float rowHeight = kTile + ImGui::GetTextLineHeightWithSpacing() * 2.0f + 14.0f;
        int reads = 0;
        ImGuiListClipper clipper;
        clipper.Begin(rows, rowHeight);
        while (clipper.Step()) {
          for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            for (int column = 0; column < columns; ++column) {
              const int index = row * columns + column;
              if (index >= static_cast<int>(shown.size())) {
                break;
              }
              EffectInfo& info = *shown[static_cast<std::size_t>(index)];
              // A few files read a frame, so scrolling stays smooth.
              if (!info.read && reads < 24) {
                ReadEffect(info);
                ++reads;
              }
              if (column > 0) {
                ImGui::SameLine();
              }
              ImGui::PushID(index);
              ImGui::BeginGroup();
              const ImVec2 at = ImGui::GetCursorScreenPos();
              const bool picked = ImGui::InvisibleButton("##tile", ImVec2(kTile, kTile + 10.0f));
              const bool hovered = ImGui::IsItemHovered();
              ImDrawList* dl = ImGui::GetWindowDrawList();
              const bool selected = info.path == mBrowserPick;
              dl->AddRectFilled(at, ImVec2(at.x + kTile, at.y + kTile), IM_COL32(12, 12, 16, 255), 4.0f);
              // The particle texture over a dark ground (additive ones show as they would at night), the ramp under it.
              if (const std::uint64_t image = mLibrary.Thumbnail(info.texture, true); image != 0) {
                dl->AddImage(
                  ImTextureRef(static_cast<ImTextureID>(image)),
                  ImVec2(at.x + 8.0f, at.y + 8.0f),
                  ImVec2(at.x + kTile - 8.0f, at.y + kTile - 8.0f)
                );
              }
              if (const std::uint64_t ramp = mLibrary.Thumbnail(info.ramp, true); ramp != 0) {
                dl->AddImage(
                  ImTextureRef(static_cast<ImTextureID>(ramp)),
                  ImVec2(at.x, at.y + kTile + 2.0f),
                  ImVec2(at.x + kTile, at.y + kTile + 9.0f)
                );
              }
              dl->AddRect(
                at,
                ImVec2(at.x + kTile, at.y + kTile),
                selected    ? IM_COL32(250, 200, 80, 255)
                  : hovered ? IM_COL32(200, 200, 200, 255)
                            : IM_COL32(50, 50, 56, 255),
                4.0f,
                0,
                selected ? 2.0f : 1.0f
              );
              // The type as a corner mark.
              dl->AddRectFilled(
                ImVec2(at.x + kTile - 14.0f, at.y + 4.0f),
                ImVec2(at.x + kTile - 4.0f, at.y + 14.0f),
                kTypeColors[std::clamp(info.type, 0, 3)],
                2.0f
              );
              ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + kTile);
              ImGui::TextUnformatted(info.name.c_str());
              ImGui::PopTextWrapPos();
              ImGui::EndGroup();
              if (hovered) {
                ImGui::SetTooltip(
                  "%s\n%s, %s, %s\nClick to play it in the preview",
                  info.path.c_str(),
                  kEffectFactions[info.faction],
                  kEffectKinds[info.kind],
                  info.read ? kTypes[std::clamp(info.type, 0, 3)] + 0 : "..."
                );
              }
              if (picked && info.path == mBrowserPick) {
                RestartPreview(); // the one open again: played from its start, its edits kept
              } else if (picked) {
                // Another effect in place of the open one: asks first when that one has unsaved edits.
                OpenOther([this, path = info.path] {
                  if (OpenGameEmitter(path)) {
                    mBrowserPick = path;
                  }
                });
              }
              ImGui::PopID();
            }
          }
        }
        mLibrary.Pump(8);
      }
      ImGui::EndChild();
      ImGui::EndTable();
    }
    DrawUnsavedModal();
    ImGui::End();
  }
} // namespace faf::editor
