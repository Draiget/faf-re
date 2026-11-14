// Two panels of the Assets and mods area: Images (FAF Studio's panels_images: every picture the map holds, one list,
// export and import each, export all) and Mesh terrain (FAF Studio's mesh import, as a preview: the game draws height
// fields only).

#include "editor/EdShell.h"
#include "editor/doc/EdDocument.h"
#include "editor/ui/EdControls.h"
#include "editor/ui/EdHelp.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdWorkspaces.h"
#include "imgui.h"

#include <cstdio>

namespace faf::editor
{
  void EdShell::DrawImagesPanel()
  {
    ImGui::SetNextWindowSize(ImVec2(Em(380.0f), Em(460.0f)), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(Panel("Images###Images"), &mShowImages)) {
      ImGui::End();
      return;
    }
    if (mDocument.Map() == nullptr) {
      ImGui::TextDisabled("Open a map to see its pictures.");
      ImGui::End();
      return;
    }
    const auto row = [this](const char* label, const std::string& what, const bool canImport, const char* tip) {
      ImGui::PushID(what.c_str());
      ImGui::AlignTextToFramePadding();
      ImGui::TextUnformatted(label);
      if (tip != nullptr && ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
        EdSetTooltip("%s", tip);
      }
      ImGui::SameLine(Em(170.0f));
      if (ImGui::SmallButton("Export...")) {
        mImageAsks.push_back(ImageAsk{what, true});
      }
      if (canImport) {
        ImGui::SameLine();
        if (ImGui::SmallButton("Import...")) {
          mImageAsks.push_back(ImageAsk{what, false});
        }
      }
      ImGui::PopID();
    };
    row("Height map", "heights", true, "16-bit grey, the map's size; an import is one undo step");
    row("Lobby picture", "preview", false, "The picture the lobby shows (Map > Regenerate preview draws it anew)");
    for (int layer = 1; layer <= 8; ++layer) {
      char label[32];
      (void)std::snprintf(label, sizeof(label), "Layer %d's mask", layer);
      row(label, "mask" + std::to_string(layer), true, "The paint of a stratum layer, as the shader shows it");
    }
    row("Water foam", "water0", true, "The water's foam mask, a cell every 2 units");
    row("Water flatness", "water1", true, "The water's flatness mask");
    row("Water depth bias", "water2", true, "The water's depth bias mask");
    ImGui::Separator();
    if (ImGui::Button("Export all into the map's images folder")) {
      mImageAsks.push_back(ImageAsk{"all", true});
    }
    EdSetItemTooltip("heights.png, preview.png, mask1-8.png and the water masks in <map folder>/images");
    if (!mImageStatus.empty()) {
      ImGui::TextWrapped("%s", mImageStatus.c_str());
    }
    ImGui::End();
  }

  void EdShell::DrawMeshPanel()
  {
    ImGui::SetNextWindowSize(ImVec2(Em(380.0f), Em(460.0f)), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin(Panel("Mesh terrain###MeshTerrain"), &mShowMesh)) {
      ImGui::End();
      return;
    }
    HelpNote(
      "A mesh terrain map (FAF Studio's: its scenario says TerrainSystem = 'mesh' and names terrain/terrain.lua) has "
      "its ground in .scm patches. Import cuts an OBJ into such patches; the view draws them over or in place of the "
      "height field, things placed stand on the mesh, and Check looks at the patches' normals, tangent frames, "
      "degenerate triangles, light mask coordinates and coverage."
    );
    {
      static const char* const kModes[3] = {"Height field", "Mesh", "Both (mesh over the field's wires)"};
      RowLabel("The view shows");
      ImGui::SetNextItemWidth(-1.0f);
      (void)EdCombo("##meshmode", &mMeshMode, kModes, 3);
      if (ImGui::Button("Load the map's mesh again")) {
        mMeshAskMore = 1;
      }
      ImGui::SameLine();
      if (ImGui::Button("Check the patches")) {
        mMeshAskMore = 2;
      }
      for (const std::string& f : mMeshFindings) {
        ImGui::TextWrapped("%s", f.c_str());
      }
      ImGui::Separator();
    }
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##meshfile", "OBJ file", mMeshFile, sizeof(mMeshFile));
    ImGui::SetNextItemWidth(-1.0f);
    FillDragFloat("##meshscale", &mMeshOptions.scale, 0.01f, 0.001f, 1000.0f, "Scale %.3f (to map units)");
    ImGui::Checkbox("Mirror X", &mMeshOptions.flipX);
    ImGui::SameLine();
    ImGui::Checkbox("Mirror Z", &mMeshOptions.flipZ);
    ImGui::SetNextItemWidth(-1.0f);
    FillDragFloat("##meshtile", &mMeshOptions.tile, 1.0f, 16.0f, 4096.0f, "Tiles of %.0f units");
    ImGui::BeginDisabled(mMeshFile[0] == '\0' || mDocument.Map() == nullptr);
    if (ImGui::Button("Import")) {
      mMeshAsk = MeshAsk{true, mMeshFile, mMeshOptions, mMeshMakeMap};
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::Checkbox("Make it a mesh terrain map", &mMeshMakeMap);
    EdSetItemTooltip("The scenario names the patches (TerrainSystem = 'mesh', TerrainMesh), one undo step");
    ImGui::SameLine();
    ImGui::Checkbox("Show over the map", &mMeshShown);
    if (!mMeshStatus.empty()) {
      ImGui::TextWrapped("%s", mMeshStatus.c_str());
    }
    ImGui::End();
  }
} // namespace faf::editor
