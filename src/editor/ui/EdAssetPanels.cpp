// Two panels of the Assets and mods area: Images (FAF Studio's panels_images: every picture the map holds, one list,
// export and import each, export all) and Mesh terrain (FAF Studio's mesh import, as a preview: the game draws height
// fields only).

#include "editor/EdShell.h"
#include "editor/EdTools.h"
#include "editor/ui/EdImGuiRenderer.h"
#include "editor/ui/EdThemeColors.h"
#include "editor/tools/EdTextureLibrary.h"
#include "editor/doc/EdDocument.h"
#include "editor/doc/EdScenarioInfo.h"
#include "editor/ui/EdControls.h"
#include "editor/ui/EdHelp.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdWorkspaces.h"
#include "imgui.h"

#include <cmath>
#include <cstdio>
#include <ranges>

namespace faf::editor
{
  void EdShell::ClearImageThumbs()
  {
    for (const auto& [what, image] : mImageThumbs) {
      if (image != 0U) {
        EdImGuiRenderer::DestroyImage(image);
      }
    }
    mImageThumbs.clear();
    mImageThumbWanted.clear();
  }

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
    // Each row: its preview (FAF Studio's 96 px; made one a frame for the rows on screen, again after edits), its
    // name, Export... and Import....
    mImageThumbWanted.clear();
    const float thumb = std::floor(ImGui::GetFrameHeight() * 1.6f);
    const auto picture = [this, thumb](const std::string& what) {
      const ImVec2 at = ImGui::GetCursorScreenPos();
      const auto found = mImageThumbs.find(what);
      if (found != mImageThumbs.end() && found->second != 0U) {
        ImGui::Image(static_cast<ImTextureID>(found->second), ImVec2(thumb, thumb));
      } else {
        ImGui::Dummy(ImVec2(thumb, thumb));
        ImGui::GetWindowDrawList()->AddRectFilled(at, ImVec2(at.x + thumb, at.y + thumb), ChipU32(), 3.0f);
        if (found == mImageThumbs.end() && ImGui::IsItemVisible()) {
          mImageThumbWanted.push_back(what);
        }
      }
      ImGui::SameLine();
    };
    const auto row = [this,
                      &picture](const char* label, const std::string& what, const bool canImport, const char* tip) {
      ImGui::PushID(what.c_str());
      if (what != "preview") {
        picture(what);
      } else {
        ImGui::Dummy(ImVec2(std::floor(ImGui::GetFrameHeight() * 1.6f), 1.0f));
        ImGui::SameLine();
      }
      ImGui::AlignTextToFramePadding();
      ImGui::TextUnformatted(label);
      if (tip != nullptr && ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
        EdSetTooltip("%s", tip);
      }
      ImGui::SameLine(Em(210.0f));
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
    row(
      "Terrain types",
      "types",
      true,
      "The terrain type of each cell (its id as the grey value); an import of the same size is one undo step"
    );
    row("Lobby picture", "preview", false, "The picture the lobby shows (Map > Regenerate preview draws it anew)");
    for (int layer = 1; layer <= 8; ++layer) {
      char label[32];
      (void)std::snprintf(label, sizeof(label), "Layer %d's mask", layer);
      row(label, "mask" + std::to_string(layer), true, "The paint of a stratum layer, as the shader shows it");
    }
    row("Water foam", "water0", true, "The water's foam mask, a cell every 2 units");
    row("Water flatness", "water1", true, "The water's flatness mask");
    row("Water depth bias", "water2", true, "The water's depth bias mask");
    // The map-wide textures (the Layers panel's): export and import each the shader reads.
    {
      static constexpr const char* kKinds[4] = {"Normal map", "Lighting map", "Specular map", "Macrotexture"};
      bool any = false;
      for (int kind = 0; kind < 4; ++kind) {
        const EdTools::MapTextureRow& state = mTools.MapTextureState(kind);
        if (!state.available) {
          continue;
        }
        if (!any) {
          ImGui::SeparatorText("Map-wide textures");
          any = true;
        }
        ImGui::PushID(1000 + kind);
        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted(kKinds[kind]);
        if (!state.state.empty() && ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
          EdSetTooltip("%s", state.state.c_str());
        }
        ImGui::SameLine(Em(210.0f));
        ImGui::BeginDisabled(!state.present);
        if (ImGui::SmallButton("Export...")) {
          mTools.AskMapTexture(kind, EdTools::MapTextureOp::Export);
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::SmallButton("Import...")) {
          mTools.AskMapTexture(kind, EdTools::MapTextureOp::Import);
        }
        ImGui::PopID();
      }
    }
    // The layers' textures (game files: shown, not exported).
    {
      const MapFacts& facts = mDocument.Facts();
      if (!facts.layers.empty()) {
        ImGui::SeparatorText("Layer textures");
        EdTextureLibrary& library = mTools.Library();
        library.Pump(2);
        const float side = std::floor(ImGui::GetFrameHeight() * 1.6f);
        int shown = 0;
        for (std::size_t i = 0; i < facts.layers.size(); ++i) {
          if (facts.layers[i].empty()) {
            continue;
          }
          if (shown++ > 0) {
            SameLineIfFits(side);
          }
          const ImVec2 at = ImGui::GetCursorScreenPos();
          if (const std::uint64_t image = library.Thumbnail(facts.layers[i]); image != 0U) {
            ImGui::Image(static_cast<ImTextureID>(image), ImVec2(side, side));
          } else {
            ImGui::Dummy(ImVec2(side, side));
            ImGui::GetWindowDrawList()->AddRectFilled(at, ImVec2(at.x + side, at.y + side), ChipU32(), 3.0f);
          }
          if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
            EdSetTooltip("%s", facts.layers[i].c_str());
          }
        }
      }
    }
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
    ImGui::SameLine();
    ImGui::Checkbox("Z up", &mMeshOptions.zUp);
    ImGui::SameLine();
    ImGui::Checkbox("Flip winding", &mMeshOptions.flipWinding);
    ImGui::SameLine();
    ImGui::Checkbox("Flip V", &mMeshOptions.flipV);
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::DragFloat3("##meshoffset", mMeshOptions.offset, 0.5f, -10000.0f, 10000.0f, "%.1f");
    EdSetItemTooltip("Offset X / Y / Z after the scale, in map units");
    static constexpr const char* kNormals[] = {
      "Normals: the file's (smooth where none)", "Normals: smooth", "Normals: flat"
    };
    ImGui::SetNextItemWidth(Em(160.0f));
    (void)EdCombo("##meshnormals", &mMeshOptions.normals, kNormals, 3);
    EdSetItemTooltip("Smooth: each corner the area-weighted normal of its faces; flat: every triangle its own");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(Em(120.0f));
    FillDragFloat(
      "##meshuv",
      &mMeshOptions.uvRepeat,
      1.0f,
      0.0f,
      4096.0f,
      mMeshOptions.uvRepeat > 0.0f ? "UV every %.0f" : "UV: the file's"
    );
    EdSetItemTooltip(
      "A file without texture coordinates gets them from the ground plan, repeating every so many units"
    );
    static constexpr const char* kMaterialsBy[] = {
      "Materials: the OBJ's (usemtl)", "Materials: by o / g group", "Materials: one for all"
    };
    ImGui::SetNextItemWidth(Em(200.0f));
    (void)EdCombo("##meshmaterials", &mMeshOptions.materialsBy, kMaterialsBy, 3);
    EdSetItemTooltip("A material in the manifest for each, reused when one of that name is there");
    ImGui::SameLine();
    static constexpr const char* kLightMaskUv[] = {"Light mask uv: over the map", "Light mask uv: the texture's"};
    ImGui::SetNextItemWidth(-1.0f);
    (void)EdCombo("##meshuv2", &mMeshOptions.lightMaskUv, kLightMaskUv, 2);
    EdSetItemTooltip(
      "The second texture coordinates, which the light masks use: x, z over the map's size, or the texture's own"
    );
    ImGui::Checkbox("A patch for each object / group", &mMeshOptions.byGroup);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(Em(110.0f));
    ImGui::DragInt("##meshmaxv", &mMeshOptions.maxVertices, 100.0f, 300, 65535, "%d corners a patch");
    ImGui::SetNextItemWidth(-1.0f);
    FillDragFloat("##meshtile", &mMeshOptions.tile, 1.0f, 16.0f, 4096.0f, "Tiles of %.0f units");
    ImGui::BeginDisabled(mMeshFile[0] == '\0' || mDocument.Map() == nullptr);
    if (ImGui::Button("Import")) {
      mMeshAsk = MeshAsk{true, mMeshFile, mMeshOptions, mMeshMakeMap};
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::Checkbox("Replace the existing patches", &mMeshOptions.replace);
    EdSetItemTooltip("Off: the new patches join the manifest's; on: its ground patches go first (sky pieces stay)");
    ImGui::SameLine();
    ImGui::Checkbox("Make it a mesh terrain map", &mMeshMakeMap);
    EdSetItemTooltip("The scenario names the patches (TerrainSystem = 'mesh', TerrainMesh); undoable");
    ImGui::SameLine();
    ImGui::Checkbox("Show over the map", &mMeshShown);
    // The loaded mesh map: its materials, its patches and its settings, edited in place; Save writes the manifest.
    if (
      edmesh::MeshMap* const mesh = mMeshMapView; mesh != nullptr && (mesh->Loaded() || !mesh->manifestPath.empty())
    ) {
      if (Section("Materials", false)) {
        static constexpr const char* kSlots[edmesh::kSlots] = {
          "Diffuse A",
          "Diffuse B",
          "Light mask 0",
          "Light mask 1",
          "Light mask 2",
          "Normal A",
          "Normal B",
          "Specular A",
          "Specular B"
        };
        for (std::size_t m = 0; m < mesh->materials.size(); ++m) {
          if (
            ImGui::Selectable(
              (std::to_string(m + 1) + " " + mesh->materials[m].name).c_str(), mMeshMaterial == static_cast<int>(m)
            )
          ) {
            mMeshMaterial = static_cast<int>(m);
          }
        }
        if (ImGui::SmallButton("+ Material")) {
          edmesh::Material material;
          material.name = "Material" + std::to_string(mesh->materials.size() + 1);
          mesh->materials.push_back(material);
          mMeshMaterial = static_cast<int>(mesh->materials.size()) - 1;
        }
        if (mMeshMaterial >= 0 && mMeshMaterial < static_cast<int>(mesh->materials.size())) {
          edmesh::Material& material = mesh->materials[static_cast<std::size_t>(mMeshMaterial)];
          char buffer[260];
          (void)std::snprintf(buffer, sizeof(buffer), "%s", material.name.c_str());
          ImGui::SetNextItemWidth(-1.0f);
          if (ImGui::InputText("##matname", buffer, sizeof(buffer))) {
            material.name = buffer;
          }
          for (int k = 0; k < edmesh::kSlots; ++k) {
            (void)std::snprintf(buffer, sizeof(buffer), "%s", material.files[k].c_str());
            ImGui::SetNextItemWidth(-1.0f);
            if (
              ImGui::InputTextWithHint(
                (std::string("##slot") + std::to_string(k)).c_str(), kSlots[k], buffer, sizeof(buffer)
              )
            ) {
              material.files[k] = buffer;
            }
          }
          ImGui::Checkbox("Blending", &material.blending);
          ImGui::SameLine();
          ImGui::Checkbox("Glow", &material.glow);
          ImGui::SameLine();
          ImGui::Checkbox("Highlight", &material.highlight);
          ImGui::SameLine();
          ImGui::Checkbox("Additive", &material.additive);
          bool alphaTest = material.alphaTest >= 0.0f;
          if (ImGui::Checkbox("Alpha test", &alphaTest)) {
            material.alphaTest = alphaTest ? 128.0f : -1.0f;
          }
          EdSetItemTooltip("SC2's ALPHA_TEST: a pixel is drawn where its alpha x 255 is above the reference");
          if (alphaTest) {
            ImGui::SameLine();
            ImGui::SetNextItemWidth(-1.0f);
            FillSliderFloat("##alpharef", &material.alphaTest, 0.0f, 255.0f, "Reference %.0f");
          }
        }
      }
      if (Section("Patches", false)) {
        int remove = -1;
        auto names = mesh->materials | std::views::transform([&](const edmesh::Material& material) {
          return material.name;
        }) |
          std::ranges::to<std::vector<std::string>>();
        for (std::size_t p = 0; p < mesh->patches.size(); ++p) {
          edmesh::Patch& patch = mesh->patches[p];
          ImGui::PushID(static_cast<int>(p));
          ImGui::TextUnformatted(patch.file.c_str());
          ImGui::SameLine(Em(160.0f));
          ImGui::SetNextItemWidth(Em(120.0f));
          if (
            EdBeginCombo(
              "##material",
              patch.material >= 0 && patch.material < static_cast<int>(names.size())
                ? names[static_cast<std::size_t>(patch.material)].c_str()
                : "(none)"
            )
          ) {
            for (std::size_t m = 0; m < names.size(); ++m) {
              if (ImGui::Selectable(names[m].c_str(), patch.material == static_cast<int>(m))) {
                patch.material = static_cast<int>(m);
              }
            }
            ImGui::EndCombo();
          }
          ImGui::SameLine();
          ImGui::Checkbox("Sky", &patch.sky);
          EdSetItemTooltip("A sky piece (SC2's): it follows the camera, unlit, instead of being ground");
          ImGui::SameLine();
          if (ImGui::SmallButton("Remove")) {
            remove = static_cast<int>(p);
          }
          ImGui::PopID();
        }
        if (remove >= 0) {
          mesh->patches.erase(mesh->patches.begin() + remove);
        }
      }
      if (Section("The mesh map's settings", false)) {
        // FAF Studio's list: every manifest setting, its value or "-" when the manifest leaves it out; the chosen
        // one's meaning, its value (a number by a slider, a file name typed) and Set / unset.
        edmesh::Settings& s = mesh->settings;
        const std::vector<edmesh::SettingKey>& keys = edmesh::SettingKeys();
        mMeshSetting = std::clamp(mMeshSetting, 0, static_cast<int>(keys.size()) - 1);
        if (ImGui::BeginChild("##meshsettings", ImVec2(0.0f, Em(150.0f)), ImGuiChildFlags_Borders)) {
          for (std::size_t k = 0; k < keys.size(); ++k) {
            const edmesh::SettingKey& key = keys[k];
            char value[96] = "-";
            if (edmesh::SettingSet(s, key.key)) {
              if (const std::string* text = edmesh::SettingText(s, key.key)) {
                (void)std::snprintf(value, sizeof(value), "%s", text->c_str());
              } else if (const float* number = edmesh::SettingNumber(s, key.key)) {
                (void)std::snprintf(
                  value, sizeof(value), "%.*f", std::max(0, key.decimals), static_cast<double>(*number)
                );
              }
            }
            ImGui::PushID(static_cast<int>(k));
            if (ImGui::Selectable(key.key, mMeshSetting == static_cast<int>(k))) {
              mMeshSetting = static_cast<int>(k);
            }
            ImGui::SameLine(Em(180.0f));
            ImGui::TextDisabled("%s", value);
            ImGui::PopID();
          }
        }
        ImGui::EndChild();
        const edmesh::SettingKey& key = keys[static_cast<std::size_t>(mMeshSetting)];
        ImGui::TextDisabled("%s: %s", key.key, key.help);
        if (std::string* text = edmesh::SettingText(s, key.key)) {
          char buffer[260];
          (void)std::snprintf(buffer, sizeof(buffer), "%s", text->c_str());
          ImGui::SetNextItemWidth(-Em(110.0f));
          if (ImGui::InputTextWithHint("##meshsettingtext", "file name beside terrain.lua", buffer, sizeof(buffer))) {
            *text = buffer;
            edmesh::SetSettingGiven(s, key.key, !text->empty());
          }
        } else if (float* number = edmesh::SettingNumber(s, key.key)) {
          float shown = edmesh::SettingSet(s, key.key) ? *number : key.min;
          char format[32];
          (void)std::snprintf(format, sizeof(format), "Value %%.%df", std::max(0, key.decimals));
          ImGui::SetNextItemWidth(-Em(110.0f));
          if (FillSliderFloat("##meshsettingvalue", &shown, key.min, key.max, format)) {
            *number = key.decimals == -1 ? std::round(shown) : shown;
            edmesh::SetSettingGiven(s, key.key, true);
          }
          EdSetItemTooltip("The value of %s; a setting the manifest leaves out uses the game's default", key.key);
        }
        ImGui::SameLine();
        if (
          ImGui::Button(edmesh::SettingSet(s, key.key) ? "Unset##meshsetting" : "Set##meshsetting", ImVec2(-1.0f, 0.0f))
        ) {
          edmesh::SetSettingGiven(s, key.key, !edmesh::SettingSet(s, key.key));
        }
        if (ImGui::Button("Sync map")) {
          mMeshAskMore = 6;
        }
        EdSetItemTooltip("Size, playable area, water, the ground's lowest and highest point and the sun from the map");
      }
      if (PrimaryButton("Save the manifest")) {
        mMeshAskMore = 3;
      }
      EdSetItemTooltip("Writes terrain.lua as edited here and reads the mesh again");
      ImGui::SameLine();
      if (ImGui::Button("Load (read it again)")) {
        mMeshAskMore = 1;
      }
    }
    // FAF Studio's "Mesh map in scenario" and New, whatever the panel holds: the scenario's TerrainSystem names the
    // mesh (its ground the patches) or not (the height field); undoable, and the view draws the manifest the panel
    // holds.
    if (mDocument.Map() != nullptr) {
      std::string system;
      bool meshMap = ReadScenarioField(mDocument.Scenario(), "TerrainSystem", system) && system == "mesh";
      if (ImGui::Checkbox("Mesh map in scenario (the map's terrain/terrain.lua is its ground)", &meshMap)) {
        mMeshAskMore = meshMap ? 5 : 4;
      }
      EdSetItemTooltip(
        "On: the scenario says TerrainSystem = 'mesh' and names terrain/terrain.lua; off: the height field is the "
        "ground (undoable); the view draws the manifest the panel holds, its unsaved edits too"
      );
      if (ImGui::Button("New manifest from the map")) {
        mMeshAskMore = 7;
      }
      EdSetItemTooltip("A manifest with the map's size, playable area, water, heights and sun, no patches yet");
    }
    if (!mMeshStatus.empty()) {
      ImGui::TextWrapped("%s", mMeshStatus.c_str());
    }
    ImGui::End();
  }
} // namespace faf::editor
