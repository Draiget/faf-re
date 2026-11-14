#include "editor/ui/EdUnitViewer.h"

#include "editor/doc/EdModProject.h"
#include "editor/graph/EdTextureBake.h"
#include "editor/tools/EdUnitIcon.h"
#include "editor/ui/EdControls.h"
#include "editor/ui/EdIconFont.h"
#include "editor/ui/EdModPanel.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdUnitLabPanel.h"
#include "editor/ui/EdWorkspaces.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"
#include "moho/mesh/MeshThumbnailRenderer.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/RRuleGameRules.h"

#include <cmath>
#include <cstring>
#include <utility>

namespace faf::editor
{
  namespace
  {
    constexpr int kViewSide = 384;
    constexpr int kIconRender = 256;
    constexpr int kIconSide = 64;
    constexpr int kSheetFormat = 2; // as the prop pictures (CMauiMesh)

    const moho::RUnitBlueprint* UnitBlueprint(
      const std::string& id
    )
    {
      moho::RRuleGameRules* const rules = moho::RULE_PeekKept();
      if (rules == nullptr) {
        return nullptr;
      }
      moho::RResId resId{};
      resId.name.assign(id.c_str());
      return rules->GetUnitBlueprint(resId);
    }

    const moho::RMeshBlueprint* MeshOf(
      const moho::RUnitBlueprint* unit
    )
    {
      moho::RRuleGameRules* const rules = moho::RULE_PeekKept();
      return unit != nullptr && rules != nullptr ? rules->GetMeshBlueprint(unit->Display.MeshBlueprint) : nullptr;
    }

    /** Copies a sheet's pixels (32-bit), false when it can't be locked. */
    bool ReadSheet(
      moho::CD3DDynamicTextureSheet& sheet,
      const int side,
      std::vector<std::uint32_t>& pixels
    )
    {
      std::uint32_t pitch = 0;
      void* bits = nullptr;
      if (!sheet.Lock(&pitch, &bits)) {
        return false;
      }
      pixels.assign(static_cast<std::size_t>(side) * side, 0U);
      for (int y = 0; y < side; ++y) {
        std::memcpy(
          pixels.data() + static_cast<std::size_t>(y) * side,
          static_cast<const std::uint8_t*>(bits) + static_cast<std::size_t>(y) * pitch,
          static_cast<std::size_t>(side) * 4
        );
      }
      (void)sheet.Unlock();
      return true;
    }
  } // namespace

  EdUnitViewer::EdUnitViewer(
    EdUnitLabPanel& lab,
    EdModPanel& project
  )
    : mLab(lab)
    , mProject(project)
  {}

  bool EdUnitViewer::Request(
    boost::shared_ptr<moho::CD3DDynamicTextureSheet>& sheet,
    const int side,
    const std::string& unit
  )
  {
    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    const moho::RMeshBlueprint* const mesh = MeshOf(UnitBlueprint(unit));
    if (device == nullptr || device->GetResources() == nullptr || mesh == nullptr) {
      return false;
    }
    if (!sheet) {
      moho::ID3DDeviceResources::DynamicTextureSheetHandle made;
      (void)device->GetResources()->NewDynamicTextureSheet(made, side, side, kSheetFormat);
      if (!made) {
        return false;
      }
      sheet = made;
    }
    std::uint32_t pitch = 0;
    void* bits = nullptr;
    if (sheet->Lock(&pitch, &bits)) {
      std::memset(bits, 0, static_cast<std::size_t>(sheet->GetTextureSizeInBytes()));
      (void)sheet->Unlock();
    }
    // Heading about the vertical, then pitch about the across axis (w, x, y, z).
    const float h = 0.5f * mHeading * 3.14159265f / 180.0f;
    const float p = 0.5f * mPitch * 3.14159265f / 180.0f;
    const Wm3::Quatf heading(std::cos(h), 0.0f, std::sin(h), 0.0f);
    const Wm3::Quatf tilt(std::cos(p), std::sin(p), 0.0f, 0.0f);
    (void)moho::REN_RequestThumbnail(
      mesh, tilt * heading, 0xFFFFFFFFu, Wm3::Vec3f{1.0f, 1.0f, 1.0f}, sheet, gpg::Rect2f{0.0f, 0.0f, 1.0f, 1.0f}
    );
    return true;
  }

  bool EdUnitViewer::AskIcon(
    std::string& error
  )
  {
    ModProject* const project = mProject.Project();
    const std::string unit = mLab.Unit();
    if (project == nullptr || unit.empty()) {
      error = "open a mod project and pick a unit in the unit lab";
      return false;
    }
    if (!Request(mIconSheet, kIconRender, ModSourceUnit(*project, unit))) {
      error = "the game's rules or the renderer aren't ready, or the unit has no model";
      return false;
    }
    mIconUnit = unit;
    mIconFrames = 0;
    mStatus = "drawing the icon of " + unit + "...";
    return true;
  }

  void EdUnitViewer::Frame()
  {
    if (++mSinceAsked == 4 && mSheet) {
      std::vector<std::uint32_t> pixels;
      mDrawnPixels = 0;
      if (ReadSheet(*mSheet, kViewSide, pixels)) {
        for (const std::uint32_t pixel : pixels) {
          mDrawnPixels += (pixel & 0x00FFFFFFu) != 0U ? 1 : 0; // (lit pixels: the background is opaque black)
        }
      }
    }
    if (mIconFrames < 0 || ++mIconFrames < 4 || !mIconSheet) {
      return;
    }
    std::vector<std::uint32_t> pixels;
    const bool read = ReadSheet(*mIconSheet, kIconRender, pixels);
    const std::string problem = read ? IconRenderProblem(pixels.data(), kIconRender, 0.08f) : "the sheet can't be read";
    if (!problem.empty()) {
      if (mIconFrames < 30 && problem == "the model drew nothing") {
        return; // not drawn yet
      }
      // The game's model thumbnail renderer draws units unlit on an opaque background: such a render isn't written as
      // an icon (the build menu would show a dark square); the base unit's icon stays.
      mIconFrames = -1;
      mStatus = "no icon: " + problem;
      gpg::Warnf("editor: unit viewer: %s", mStatus.c_str());
      return;
    }
    const std::vector<float> icon = IconPixels(pixels.data(), kIconRender, kIconSide, 0.9f);
    mIconFrames = -1;
    TexImage image;
    image.Reset(kIconSide, 4);
    std::memcpy(image.data.data(), icon.data(), icon.size() * sizeof(float));
    std::vector<std::uint8_t> dds;
    std::string error;
    ModProject* const project = mProject.Project();
    if (
      project == nullptr || !EncodeDds(image, DdsKind::Bc3, dds, error) ||
      !ModWriteBinary(
        *project, mProject.Folder(), ModUnitIconFile(mIconUnit), std::string(dds.begin(), dds.end()), error
      )
    ) {
      mStatus = "no icon: " + (error.empty() ? std::string("no project") : error);
      gpg::Warnf("editor: unit viewer: %s", mStatus.c_str());
      return;
    }
    mProject.Touch(); // (the project's file list changed)
    // A derived unit names its icon in the hook.
    if (auto d = project->derived.find(mIconUnit); d != project->derived.end() && !d->second.icon) {
      const ModChanges before = ModChangesOf(*project);
      d->second.icon = true;
      (void)mProject.History().Record("icon of " + mIconUnit, before, ModChangesOf(*project), "", ImGui::GetTime());
      mProject.Touch();
    }
    mStatus = "wrote " + ModUnitIconFile(mIconUnit) + " (" + std::to_string(dds.size()) + " bytes)";
    gpg::Logf("editor: unit viewer: %s into %s", mStatus.c_str(), mProject.Folder().string().c_str());
  }

  void EdUnitViewer::Draw(
    bool& open
  )
  {
    if (std::exchange(mFocus, false)) {
      ImGui::SetNextWindowFocus();
    }
    if (!ImGui::Begin(Panel("Unit viewer###UnitViewer"), &open)) {
      ImGui::End();
      return;
    }
    const ModProject* const project = mProject.Project();
    const std::string unit = mLab.Unit();
    const std::string source = project != nullptr && !unit.empty() ? ModSourceUnit(*project, unit) : unit;
    const moho::RUnitBlueprint* const bp = source.empty() ? nullptr : UnitBlueprint(source);
    if (bp == nullptr) {
      ImGui::TextDisabled("Pick a unit in the unit lab to see it here.");
      ImGui::End();
      return;
    }
    // Asked again when the unit or the angles change.
    char key[160];
    std::snprintf(key, sizeof(key), "%s %.1f %.1f", source.c_str(), mHeading, mPitch);
    if (mShown != key && Request(mSheet, kViewSide, source)) {
      mShown = key;
      mSinceAsked = 0;
    }
    const float side = std::min(ImGui::GetContentRegionAvail().x, Em(300.0f));
    if (mSheet) {
      moho::ID3DTextureSheet::TextureHandle texture;
      (void)mSheet->GetTexture(texture);
      ImGui::Image(static_cast<ImTextureID>(reinterpret_cast<std::uintptr_t>(texture.get())), ImVec2(side, side));
      if (ImGui::IsItemActive() && ImGui::IsMouseDragging(ImGuiMouseButton_Left, 0.0f)) {
        const ImVec2 delta = ImGui::GetIO().MouseDelta;
        mHeading = std::fmod(mHeading + delta.x * 0.6f + 360.0f, 360.0f);
        mPitch = std::clamp(mPitch + delta.y * 0.4f, -80.0f, 80.0f);
      }
      if (ImGui::IsItemHovered()) {
        EdSetTooltip("Drag to turn it");
      }
    }
    ImGui::SetNextItemWidth(Em(140.0f));
    (void)FillDragFloat("##heading", &mHeading, 1.0f, 0.0f, 360.0f, "Heading %.0f");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(Em(140.0f));
    (void)FillDragFloat("##pitch", &mPitch, 1.0f, -80.0f, 80.0f, "Pitch %.0f");
    ImGui::SameLine();
    if (ImGui::SmallButton("Front")) {
      mHeading = 0.0f;
      mPitch = 0.0f;
    }
    ImGui::Text("%s%s", source.c_str(), source != unit ? (" (base of " + unit + ")").c_str() : "");
    ImGui::TextDisabled("Mesh %s, scale %.3f", bp->Display.MeshBlueprint.name.c_str(), bp->Display.UniformScale);
    if (const moho::RMeshBlueprint* const mesh = MeshOf(bp); mesh != nullptr) {
      for (std::size_t l = 0; l < mesh->mLods.size(); ++l) {
        ImGui::TextDisabled("  LOD %zu: to %.0f, %s", l, mesh->mLods[l].mLodCutoff, mesh->mLods[l].mMeshName.c_str());
      }
    }
    ImGui::BeginDisabled(project == nullptr || mIconFrames >= 0);
    if (ImGui::Button(ICON_IMAGE " Make icon")) {
      std::string error;
      if (!AskIcon(error)) {
        mStatus = "no icon: " + error;
      }
    }
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      EdSetTooltip(
        "A 64 x 64 icon of this unit into the mod project (icons/units/<id>_icon.dds), as the build menu "
        "shows it; a derived unit names it"
      );
    }
    if (!mStatus.empty()) {
      ImGui::TextWrapped("%s", mStatus.c_str());
    }
    ImGui::End();
  }
} // namespace faf::editor
