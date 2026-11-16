#include "editor/ui/EdUnitViewer.h"

#include "editor/doc/EdModProject.h"
#include "editor/graph/EdTextureBake.h"
#include "editor/tools/EdUnitIcon.h"
#include "moho/mesh/Mesh.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "editor/ui/EdControls.h"
#include "editor/ui/EdIconFont.h"
#include "editor/ui/EdImGuiRenderer.h"
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

#include <algorithm>
#include <cmath>
#include <cstdio>
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
    std::shared_ptr<moho::CD3DDynamicTextureSheet>& sheet,
    const int side,
    const std::string& unit,
    const int projectileOf
  )
  {
    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    const moho::RUnitBlueprint* const unitBlueprint = UnitBlueprint(unit);
    const moho::RMeshBlueprint* mesh = MeshOf(unitBlueprint);
    // A weapon's projectile instead: its blueprint's mesh (a projectile without one shows nothing).
    if (projectileOf >= 0 && unitBlueprint != nullptr) {
      const auto& weapons = unitBlueprint->Weapons.WeaponBlueprints;
      moho::RRuleGameRules* const rules = moho::RULE_PeekKept();
      mesh = nullptr;
      if (rules != nullptr && static_cast<std::size_t>(projectileOf) < weapons.size()) {
        const moho::RUnitBlueprintWeapon& weapon = weapons[static_cast<std::size_t>(projectileOf)];
        const moho::RProjectileBlueprint* const projectile = rules->GetProjectileBlueprint(weapon.ProjectileId);
        if (projectile != nullptr) {
          mesh = rules->GetMeshBlueprint(projectile->Display.MeshBlueprint);
        }
        gpg::Logf(
          "editor: unit viewer: %s weapon %d: projectile %s (%s), its mesh %s",
          unit.c_str(),
          projectileOf,
          weapon.ProjectileId.name.c_str(),
          projectile != nullptr ? "in the rules" : "not in the rules",
          mesh != nullptr ? mesh->mBlueprintId.c_str() : "none"
        );
      }
    }
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
    // Heading about the vertical, then pitch about the across axis (w, x, y, z); an icon by its own recipe.
    const float h = 0.5f * (mIconRequest ? mIconHeading : mHeading) * 3.14159265f / 180.0f;
    const float p = 0.5f * (mIconRequest ? mIconPitch : mPitch) * 3.14159265f / 180.0f;
    const Wm3::Quatf heading(std::cos(h), 0.0f, std::sin(h), 0.0f);
    const Wm3::Quatf tilt(std::cos(p), std::sin(p), 0.0f, 0.0f);
    moho::ren_ThumbnailFov = mIconRequest ? mIconFov : 0.0f;
    (void)moho::REN_RequestThumbnail(
      mesh, tilt * heading, 0xFFFFFFFFu, Wm3::Vec3f{1.0f, 1.0f, 1.0f}, sheet, gpg::Rect2f{0.0f, 0.0f, 1.0f, 1.0f}
    );
    moho::ren_ThumbnailFov = 0.0f;
    return true;
  }

  std::expected<void, std::string> EdUnitViewer::AskIcon()
  {
    return AskIconFor(mLab.Unit());
  }

  void EdUnitViewer::AskBatch()
  {
    ModProject* const project = mProject.Project();
    if (project == nullptr) {
      mStatus = "open a mod project first";
      return;
    }
    mBatch.clear();
    for (const auto& [id, keys] : project->edits) {
      mBatch.push_back(id);
    }
    for (const auto& [id, d] : project->derived) {
      if (std::find(mBatch.begin(), mBatch.end(), id) == mBatch.end()) {
        mBatch.push_back(id);
      }
    }
    mBatchTotal = static_cast<int>(mBatch.size());
    mStatus = "making " + std::to_string(mBatchTotal) + " icons...";
  }

  std::expected<void, std::string> EdUnitViewer::AskIconFor(
    const std::string& unit
  )
  {
    ModProject* const project = mProject.Project();
    if (project == nullptr || unit.empty()) {
      return std::unexpected("open a mod project and pick a unit in the unit lab");
    }
    mIconRequest = true;
    const bool asked = Request(mIconSheet, kIconRender, ModSourceUnit(*project, unit));
    mIconRequest = false;
    if (!asked) {
      return std::unexpected("the game's rules or the renderer aren't ready, or the unit has no model");
    }
    mIconUnit = unit;
    mIconFrames = 0;
    mIconPass = 0;
    moho::ren_ThumbnailClearColor = 0xFF000000u;
    mStatus = "drawing the icon of " + unit + "...";
    return {};
  }

  void EdUnitViewer::SetIconPicture(
    const int which,
    const std::vector<std::uint32_t>& bgra
  )
  {
    if (mIconPictures[which] != 0U) {
      mRetiredPictures.emplace_back(mIconPictures[which], 0);
    }
    mIconPictures[which] = bgra.size() == static_cast<std::size_t>(kIconSide) * kIconSide
      ? EdImGuiRenderer::CreateImage(kIconSide, kIconSide, bgra.data())
      : 0U;
  }

  void EdUnitViewer::Frame()
  {
    // Pictures replaced a few frames ago: no draw list holds them any more.
    for (auto it = mRetiredPictures.begin(); it != mRetiredPictures.end();) {
      if (++it->second > 3) {
        EdImGuiRenderer::DestroyImage(it->first);
        it = mRetiredPictures.erase(it);
      } else {
        ++it;
      }
    }
    if (++mSinceAsked == 4 && mSheet) {
      std::vector<std::uint32_t> pixels;
      mDrawnPixels = 0;
      if (ReadSheet(*mSheet, kViewSide, pixels)) {
        for (const std::uint32_t pixel : pixels) {
          mDrawnPixels += (pixel & 0x00FFFFFFu) != 0U ? 1 : 0; // (lit pixels: the background is opaque black)
        }
      }
    }
    // A batch: the next unit once the last icon is done.
    if (mIconFrames < 0 && !mBatch.empty()) {
      const std::string next = mBatch.front();
      mBatch.erase(mBatch.begin());
      if (const auto asked = AskIconFor(next); !asked) {
        gpg::Warnf("editor: unit viewer: batch: %s: %s", next.c_str(), asked.error().c_str());
      }
      return;
    }
    if (mIconFrames < 0 || ++mIconFrames < 4 || !mIconSheet) {
      return;
    }
    std::vector<std::uint32_t> pixels;
    bool read = ReadSheet(*mIconSheet, kIconRender, pixels);
    // Two passes (FAF Studio's): on black, then on white; the difference keys the background out.
    if (read && mIconPass == 0 && !AlphaBox(pixels.data(), kIconRender).empty) {
      ModProject* const project = mProject.Project();
      mIconOnBlack = pixels;
      moho::ren_ThumbnailClearColor = 0xFFFFFFFFu;
      mIconRequest = true;
      const bool asked = project != nullptr && Request(mIconSheet, kIconRender, ModSourceUnit(*project, mIconUnit));
      mIconRequest = false;
      if (asked) {
        mIconPass = 1;
        mIconFrames = 0;
        return;
      }
      moho::ren_ThumbnailClearColor = 0xFF000000u;
    }
    if (mIconPass == 1) {
      if (read && AlphaBox(pixels.data(), kIconRender).empty && mIconFrames < 30) {
        return; // the white render isn't drawn yet
      }
      moho::ren_ThumbnailClearColor = 0xFF000000u;
      if (read && mIconOnBlack.size() == pixels.size()) {
        pixels = KeyedIcon(mIconOnBlack.data(), pixels.data(), kIconRender, 0.45f);
      }
      mIconPass = 0;
    }
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
    std::vector<float> icon = IconPixels(pixels.data(), kIconRender, kIconSide, mIconFill);
    mIconFrames = -1;
    // Beside the icon the game ships (Studio's Icons panel): the silhouettes' overlap and the colours, and what the
    // faction's tone fit learns from it; the fit applied when asked.
    {
      std::vector<std::uint8_t> made(icon.size());
      for (std::size_t i = 0; i < icon.size(); ++i) {
        made[i] = static_cast<std::uint8_t>(std::clamp(icon[i] * 255.0f + 0.5f, 0.0f, 255.0f));
      }
      ModProject* const p = mProject.Project();
      const std::string source = p != nullptr ? ModSourceUnit(*p, mIconUnit) : mIconUnit;
      const std::string faction = IconFactionOf(source);
      std::vector<std::uint8_t> shipped;
      if (
        loadGameIcon && loadGameIcon("/textures/ui/common/icons/units/" + source + "_icon.dds", kIconSide, shipped) &&
        shipped.size() == made.size()
      ) {
        const IconMetrics m = CompareIcons(made.data(), shipped.data(), kIconSide);
        mTone.Add(faction, made.data(), shipped.data(), kIconSide);
        char text[220];
        (void)std::snprintf(
          text,
          sizeof(text),
          "Beside the game's icon of %s: silhouettes overlap %.0f%% (%d / %d pixels), colour off by %.0f, tint by "
          "%.0f, "
          "blocks by %.0f",
          source.c_str(),
          static_cast<double>(m.iou * 100.0f),
          m.areaA,
          m.areaB,
          static_cast<double>(m.colour),
          static_cast<double>(m.tint),
          static_cast<double>(m.coarse)
        );
        mCompare = text;
        mShipped = shipped;
        mMade = made;
        gpg::Logf("editor: unit viewer: %s", text);
      } else {
        mCompare = "The game ships no icon for " + source + " to compare with.";
      }
      float gains[3] = {1.0f, 1.0f, 1.0f};
      if (mToneOn && mTone.Gains(faction, gains)) {
        ApplyIconTone(made, gains);
        for (std::size_t i = 0; i < icon.size(); ++i) {
          icon[i] = static_cast<float>(made[i]) / 255.0f;
        }
      }
    }
    // The light edge (Studio's), then the pictures: the icon as written, the game's, their silhouettes' difference.
    IconLightEdge(icon, kIconSide, mIconEdge, mIconEdge > 0.0f ? 3.5f : 0.0f);
    {
      const auto toBgra = [](const std::vector<std::uint8_t>& rgba) {
        std::vector<std::uint32_t> out(rgba.size() / 4);
        for (std::size_t i = 0; i < out.size(); ++i) {
          out[i] = (static_cast<std::uint32_t>(rgba[i * 4 + 3]) << 24) |
            (static_cast<std::uint32_t>(rgba[i * 4]) << 16) | (static_cast<std::uint32_t>(rgba[i * 4 + 1]) << 8) |
            rgba[i * 4 + 2];
        }
        return out;
      };
      std::vector<std::uint8_t> written(icon.size());
      for (std::size_t i = 0; i < icon.size(); ++i) {
        written[i] = static_cast<std::uint8_t>(std::clamp(icon[i] * 255.0f + 0.5f, 0.0f, 255.0f));
      }
      SetIconPicture(0, toBgra(written));
      const bool shippedHere = mShipped.size() == written.size() && mCompare.starts_with("Beside");
      SetIconPicture(1, shippedHere ? toBgra(mShipped) : std::vector<std::uint32_t>{});
      SetIconPicture(
        2, shippedHere ? IconDifference(written.data(), mShipped.data(), kIconSide) : std::vector<std::uint32_t>{}
      );
    }
    TexImage image;
    image.Reset(kIconSide, 4);
    std::memcpy(image.data.data(), icon.data(), icon.size() * sizeof(float));
    ModProject* const project = mProject.Project();
    const auto encoded =
      project != nullptr ? EncodeDds(image, DdsKind::Bc3) : std::expected<std::vector<std::uint8_t>, std::string>();
    if (project == nullptr || !encoded) {
      mStatus =
        "no icon: " + (project == nullptr || encoded.error().empty() ? std::string("no project") : encoded.error());
      gpg::Warnf("editor: unit viewer: %s", mStatus.c_str());
      return;
    }
    const std::vector<std::uint8_t>& dds = *encoded;
    if (
      const auto written =
        ModWriteBinary(*project, mProject.Folder(), ModUnitIconFile(mIconUnit), std::string(dds.begin(), dds.end()));
      !written
    ) {
      mStatus = "no icon: " + (written.error().empty() ? std::string("no project") : written.error());
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
    // The unit, or one of its weapons' projectiles.
    {
      const auto& weapons = bp->Weapons.WeaponBlueprints;
      if (mShowWeapon >= static_cast<int>(weapons.size())) {
        mShowWeapon = -1;
      }
      const auto weaponName = [&](const int i) {
        const moho::RUnitBlueprintWeapon& w = weapons[static_cast<std::size_t>(i)];
        std::string name = w.Label.c_str();
        name += std::string(" (") + (w.ProjectileId.name.empty() ? "no projectile" : w.ProjectileId.name.c_str()) + ")";
        return name;
      };
      ImGui::SetNextItemWidth(-1.0f);
      if (EdBeginCombo("##viewwhat", mShowWeapon < 0 ? "The unit" : weaponName(mShowWeapon).c_str())) {
        if (ImGui::Selectable("The unit", mShowWeapon < 0)) {
          mShowWeapon = -1;
        }
        for (int i = 0; i < static_cast<int>(weapons.size()); ++i) {
          ImGui::PushID(i);
          if (ImGui::Selectable(weaponName(i).c_str(), mShowWeapon == i)) {
            mShowWeapon = i;
          }
          ImGui::PopID();
        }
        ImGui::EndCombo();
      }
      EdSetItemTooltip("The unit's model, or the projectile one of its weapons fires");
    }
    std::snprintf(key, sizeof(key), "%s %.1f %.1f %d", source.c_str(), mHeading, mPitch, mShowWeapon);
    if (mShown != key && mFailed != key) {
      if (Request(mSheet, kViewSide, source, mShowWeapon)) {
        mShown = key;
        mSinceAsked = 0;
      } else {
        mFailed = key; // (asked once: the log says why)
      }
    }
    if (mFailed == key) {
      ImGui::TextDisabled(
        mShowWeapon >= 0 ? "This weapon's projectile has no model of its own (its effects draw it), or it fires none."
                         : "The unit has no model the viewer can draw."
      );
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
      if (const auto asked = AskIcon(); !asked) {
        mStatus = "no icon: " + asked.error();
      }
    }
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
      EdSetTooltip(
        "A 64 x 64 icon of this unit into the mod project (icons/units/<id>_icon.dds), as the build menu "
        "shows it; a derived unit names it"
      );
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(project == nullptr || mIconFrames >= 0 || !mBatch.empty());
    if (ImGui::Button("Icons of every project unit")) {
      AskBatch();
    }
    ImGui::EndDisabled();
    ImGui::Checkbox("Fit the tone per faction (learned from the comparisons)", &mToneOn);
    EdSetItemTooltip(
      "Each faction's colour gains from the made icons against the game's (Studio's tone fit), applied when an icon is "
      "written"
    );
    if (!mBatch.empty()) {
      ImGui::TextDisabled("Batch: %d of %d left", static_cast<int>(mBatch.size()), mBatchTotal);
    }
    if (ImGui::TreeNode("Icon recipe")) {
      ImGui::SetNextItemWidth(-1.0f);
      (void)FillSliderFloat("##iconheading", &mIconHeading, 0.0f, 360.0f, "Heading %.0f deg");
      ImGui::SetNextItemWidth(-1.0f);
      (void)FillSliderFloat("##iconpitch", &mIconPitch, 0.0f, 85.0f, "Pitch %.0f deg");
      ImGui::SetNextItemWidth(-1.0f);
      (void)FillSliderFloat(
        "##iconfov",
        &mIconFov,
        0.0f,
        70.0f,
        mIconFov > 0.0f ? "Field of view %.0f deg" : "Field of view: flat (the game's)"
      );
      EdSetItemTooltip("0 draws the model flat, as the game's thumbnails; a field of view draws it in perspective");
      ImGui::SetNextItemWidth(-1.0f);
      (void)FillSliderFloat("##iconfill", &mIconFill, 0.4f, 1.0f, "Fill %.2f of the icon");
      ImGui::SetNextItemWidth(-1.0f);
      (void)FillSliderFloat(
        "##iconedge", &mIconEdge, 0.0f, 6.0f, mIconEdge > 0.0f ? "Light edge %.1f px" : "Light edge: off"
      );
      EdSetItemTooltip("A white halo round the unit, as the game's icons have");
      if (ImGui::Button("As the view##iconasview")) {
        mIconHeading = mHeading;
        mIconPitch = mPitch;
      }
      EdSetItemTooltip("The icon turned as the unit is in the view");
      ImGui::TreePop();
    }
    if (mIconPictures[0] != 0U) {
      // The render, the game's icon, their difference (Studio's three pictures).
      const float side = std::min(Em(96.0f), (ImGui::GetContentRegionAvail().x - Em(16.0f)) / 3.0f);
      static constexpr const char* kCaptions[] = {"Render", "Game", "Difference"};
      for (int k = 0; k < 3; ++k) {
        if (k > 0) {
          ImGui::SameLine();
        }
        ImGui::BeginGroup();
        ImGui::TextDisabled("%s", kCaptions[k]);
        if (mIconPictures[k] != 0U) {
          ImGui::Image(static_cast<ImTextureID>(mIconPictures[k]), ImVec2(side, side));
        } else {
          ImGui::Dummy(ImVec2(side, side));
        }
        ImGui::EndGroup();
      }
      ImGui::TextDisabled("Difference: green both, red only the render, blue only the game's");
    }
    if (!mCompare.empty()) {
      ImGui::TextWrapped("%s", mCompare.c_str());
    }
    if (!mStatus.empty()) {
      ImGui::TextWrapped("%s", mStatus.c_str());
    }
    DrawInView(source);
    ImGui::End();
  }

  void EdUnitViewer::DrawInView(
    const std::string& source
  )
  {
    UnitPreviewState& p = mPreview;
    if (!Section("In the view, animated", false)) {
      return;
    }
    if (ImGui::Checkbox("Show the unit in the view", &p.active)) {
      p.time = 0.0f;
    }
    EdSetItemTooltip("The unit stands at the camera's target, drawn by the game's renderer with its animations");
    if (p.unit != source) {
      p.unit = source;
      p.animation.clear();
      p.animations.clear();
    }
    if (!p.active) {
      return;
    }
    ImGui::SetNextItemWidth(-1.0f);
    if (EdBeginCombo("##anim", p.animation.empty() ? "Rest pose" : p.animation.c_str())) {
      if (ImGui::Selectable("Rest pose", p.animation.empty())) {
        p.animation.clear();
      }
      for (const std::string& a : p.animations) {
        if (ImGui::Selectable(a.c_str(), a == p.animation)) {
          p.animation = a;
          p.playing = true;
        }
      }
      ImGui::EndCombo();
    }
    char path[256];
    (void)std::snprintf(path, sizeof(path), "%s", p.animation.c_str());
    ImGui::SetNextItemWidth(-1.0f);
    if (
      ImGui::InputTextWithHint(
        "##animpath", "or any .sca of the game", path, sizeof(path), ImGuiInputTextFlags_EnterReturnsTrue
      )
    ) {
      p.animation = path;
    }
    if (ImGui::Button(p.playing ? "Pause" : "Play")) {
      p.playing = !p.playing;
      if (p.playing && !p.loop && p.time >= p.duration) {
        p.time = 0.0f;
      }
    }
    ImGui::SameLine();
    ImGui::Checkbox("Loop", &p.loop);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-1.0f);
    (void)FillSliderFloat("##rate", &p.rate, 0.05f, 4.0f, "Rate %.2f");
    ImGui::SetNextItemWidth(-1.0f);
    if (FillSliderFloat("##time", &p.time, 0.0f, std::max(0.01f, p.duration), "Time %.2f s")) {
      p.scrubbed = true;
      p.playing = false;
    }
    ImGui::Checkbox("Bones", &p.bones);
    ImGui::SameLine();
    ImGui::Checkbox("Collision box", &p.hitbox);
    ImGui::SameLine();
    ImGui::Checkbox("Footprint", &p.footprint);
    ImGui::Checkbox("Weapon ranges", &p.ranges);
    ImGui::SameLine();
    ImGui::Checkbox("Senses", &p.senses);
    ImGui::SetNextItemWidth(-1.0f);
    (void)FillSliderInt("##army", &p.army, 0, 7, "Army colour %d");
    // Studio's viewer: the LOD to look at, the empty stage, the light.
    {
      const std::string shown = p.lod < 0 ? std::string("LOD: as the camera is") : "LOD " + std::to_string(p.lod);
      ImGui::SetNextItemWidth(Em(170.0f));
      if (EdBeginCombo("##lod", shown.c_str())) {
        if (ImGui::Selectable("As the camera is", p.lod < 0)) {
          p.lod = -1;
        }
        for (std::size_t l = 0; l < p.lodCutoffs.size(); ++l) {
          char label[64];
          (void)std::snprintf(label, sizeof(label), "LOD %zu (to %.0f)", l, static_cast<double>(p.lodCutoffs[l]));
          if (ImGui::Selectable(label, p.lod == static_cast<int>(l))) {
            p.lod = static_cast<int>(l);
          }
        }
        ImGui::EndCombo();
      }
      EdSetItemTooltip("Puts the camera at the middle of that LOD's distance: the mesh the game shows there");
      ImGui::SameLine();
      ImGui::Checkbox("Empty stage", &p.stage);
      EdSetItemTooltip("The map's terrain, sky, water and border aren't drawn while the unit is shown");
      if (p.stage) {
        ImGui::SameLine();
        ImGui::Checkbox("Grid", &p.grid);
      }
      // Studio's camera presets.
      for (const char* frame : {"Iso", "Front", "Side", "Back", "Top", "Fit", "Range"}) {
        if (std::string(frame) != "Iso") {
          SameLineIfFits(ImGui::CalcTextSize(frame).x + ImGui::GetStyle().FramePadding.x * 2.0f);
        }
        if (ImGui::SmallButton(frame)) {
          std::string key = frame;
          for (char& c : key) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
          }
          p.frame = key;
        }
      }
      // A bone to look at: its axes drawn (x red, y green, z blue).
      ImGui::SetNextItemWidth(Em(170.0f));
      const std::string boneShown = p.bone < 0 || static_cast<std::size_t>(p.bone) >= p.boneNames.size()
        ? std::string("Bone: none")
        : "Bone: " + p.boneNames[static_cast<std::size_t>(p.bone)];
      if (EdBeginCombo("##bone", boneShown.c_str())) {
        if (ImGui::Selectable("None", p.bone < 0)) {
          p.bone = -1;
        }
        for (std::size_t b = 0; b < p.boneNames.size(); ++b) {
          ImGui::PushID(static_cast<int>(b));
          if (ImGui::Selectable(p.boneNames[b].c_str(), p.bone == static_cast<int>(b))) {
            p.bone = static_cast<int>(b);
          }
          ImGui::PopID();
        }
        ImGui::EndCombo();
      }
      EdSetItemTooltip("Picks a bone: its axes are drawn on the unit (x red, y green, z blue)");
      ImGui::SameLine();
      ImGui::SetNextItemWidth(Em(140.0f));
      if (EdBeginCombo("##colour", ("Colour: " + p.colour).c_str())) {
        for (const char* name : {"Army", "Red", "Blue", "Green", "Yellow", "White", "Black"}) {
          if (ImGui::Selectable(name, p.colour == name)) {
            p.colour = name;
          }
        }
        ImGui::EndCombo();
      }
      EdSetItemTooltip("Studio's team colours; Army uses the army colour slider");
      ImGui::SetNextItemWidth(Em(170.0f));
      if (EdBeginCombo("##light", ("Light: " + p.light).c_str())) {
        for (const char* name : {"Map", "Noon", "Evening", "Overcast", "Night", "Icon"}) {
          if (ImGui::Selectable(name, p.light == name)) {
            p.light = name;
          }
        }
        ImGui::EndCombo();
      }
      EdSetItemTooltip("A light for the map (one undo step); Map puts back the map's own");
      // Fire (Studio's Effects panel): one of the unit's weapons sends its projectile from the unit.
      moho::RRuleGameRules* const rules = moho::RULE_PeekKept();
      moho::RResId id{};
      id.name.assign(p.unit.c_str());
      const moho::RUnitBlueprint* const bp = rules != nullptr ? rules->GetUnitBlueprint(id) : nullptr;
      if (bp != nullptr && !bp->Weapons.WeaponBlueprints.empty()) {
        const auto& weapons = bp->Weapons.WeaponBlueprints;
        p.fireWeapon = std::clamp(p.fireWeapon, 0, static_cast<int>(weapons.size()) - 1);
        ImGui::SameLine();
        ImGui::SetNextItemWidth(Em(150.0f));
        if (EdBeginCombo("##fireweapon", weapons[static_cast<std::size_t>(p.fireWeapon)].Label.c_str())) {
          for (int i = 0; i < static_cast<int>(weapons.size()); ++i) {
            ImGui::PushID(i);
            if (ImGui::Selectable(weapons[static_cast<std::size_t>(i)].Label.c_str(), i == p.fireWeapon)) {
              p.fireWeapon = i;
            }
            ImGui::PopID();
          }
          ImGui::EndCombo();
        }
        ImGui::SameLine();
        if (ImGui::Button("Fire")) {
          p.fire = true;
        }
        EdSetItemTooltip("The weapon's projectile flies from the unit at its muzzle speed (on its arc) to its range");
        if (!p.fireStatus.empty()) {
          ImGui::TextDisabled("%s", p.fireStatus.c_str());
        }
      }
    }
    if (!p.status.empty()) {
      ImGui::TextDisabled("%s", p.status.c_str());
    }
  }
} // namespace faf::editor
