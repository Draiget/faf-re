// The unit viewer's animated unit in the view (FAF Studio's unitview.lua): the unit's mesh drawn by the game's mesh
// renderer at the camera's target, posed every frame from its animation (EdScaAnim: the frame's bone keys set as the
// pose's local transforms, by bone name), and its bones, collision box, footprint and skirt, weapon ranges and senses
// drawn over it with the batcher.

#include "editor/view/EdMapScene.h"

#include "editor/doc/EdDocument.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/console/CConCommand.h"
#include "lua/LuaTableIterator.h"
#include "moho/animation/CAniPose.h"
#include "moho/animation/CAniSkel.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/mesh/Mesh.h"
#include "moho/render/camera/VTransform.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/STIMap.h"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace faf::editor
{
  namespace
  {
    constexpr float kPreviewPi = 3.14159265f;

    /** The army colours the game gives slots 1-8 (ARGB). */
    std::uint32_t ArmyColour(
      const int army
    )
    {
      static const std::uint32_t kColours[8] = {
        0xFF2929E1u,
        0xFFE80A0Au,
        0xFF436EEEu,
        0xFF616D7Eu,
        0xFFFF873Eu,
        0xFF9161FFu,
        0xFF2F9E5Eu,
        0xFFFFD100u,
      };
      return kColours[std::clamp(army, 0, 7)];
    }

    moho::CD3DPrimBatcher::Vertex V(
      const float x,
      const float y,
      const float z,
      const std::uint32_t c
    )
    {
      moho::CD3DPrimBatcher::Vertex v{};
      v.mX = x;
      v.mY = y;
      v.mZ = z;
      v.mColor = c;
      return v;
    }

    void Ring(
      moho::CD3DPrimBatcher& b,
      const float x,
      const float y,
      const float z,
      const float r,
      const std::uint32_t c
    )
    {
      constexpr int kSegments = 72;
      for (int s = 0; s < kSegments; ++s) {
        const float a0 = 2.0f * kPreviewPi * static_cast<float>(s) / kSegments;
        const float a1 = 2.0f * kPreviewPi * static_cast<float>(s + 1) / kSegments;
        b.DrawLine(
          V(x + std::cos(a0) * r, y, z + std::sin(a0) * r, c), V(x + std::cos(a1) * r, y, z + std::sin(a1) * r, c)
        );
      }
    }
  } // namespace

  void EdMapScene::SetPreviewStage(
    const bool on
  )
  {
    if (on == mPreviewStageOn) {
      return;
    }
    mPreviewStageOn = on;
    // Studio's viewer stage (unitview.lua Flags): the engine's switches, process wide, put back when it is off.
    for (const char* name : {"ren_Terrain", "ren_SkyDome", "ren_Water", "ren_WorldBorder"}) {
      moho::CON_Executef("%s %s", name, on ? "false" : "true");
    }
    gpg::Logf("editor: unit view: the empty stage %s", on ? "on (terrain, sky, water and border not drawn)" : "off");
  }

  void EdMapScene::SetPreviewLight(
    const std::string& name
  )
  {
    // Studio's light presets (unitview.lua Lights): the map's sun, ambience and shadow fill, one undo step each; Map
    // puts back the light the map had before the first preset.
    struct Preset
    {
      const char* name;
      float mult;
      float sun[3];
      float colour[3];
      float ambient[3];
      float fill[3];
    };
    static constexpr Preset kPresets[] = {
      {"Noon", 1.5f, {0.2f, 0.95f, -0.2f}, {1.0f, 1.0f, 1.0f}, {0.3f, 0.3f, 0.3f}, {0.7f, 0.7f, 0.7f}},
      {"Evening", 1.5f, {0.9f, 0.25f, -0.3f}, {1.0f, 0.7f, 0.45f}, {0.25f, 0.22f, 0.3f}, {0.5f, 0.45f, 0.55f}},
      {"Overcast", 1.2f, {0.0f, 1.0f, 0.0f}, {0.6f, 0.6f, 0.62f}, {0.55f, 0.55f, 0.58f}, {0.8f, 0.8f, 0.82f}},
      {"Night", 0.7f, {-0.3f, 0.6f, 0.4f}, {0.35f, 0.45f, 0.8f}, {0.15f, 0.18f, 0.3f}, {0.3f, 0.35f, 0.5f}},
      {"Icon", 2.0f, {-0.5f, 0.7f, 0.5f}, {1.0f, 1.0f, 1.0f}, {0.35f, 0.35f, 0.4f}, {0.9f, 0.9f, 0.95f}},
    };
    mPreviewLight = name;
    const LightingState before = mDocument.LightingNow();
    LightingState next = before;
    if (name == "Map") {
      if (!mPreviewHasMapLight) {
        return; // nothing was changed
      }
      next = mPreviewMapLight;
      mPreviewHasMapLight = false;
    } else {
      const Preset* found = nullptr;
      for (const Preset& p : kPresets) {
        if (name == p.name) {
          found = &p;
        }
      }
      if (found == nullptr) {
        return;
      }
      if (!mPreviewHasMapLight) {
        mPreviewMapLight = before;
        mPreviewHasMapLight = true;
      }
      const float len =
        std::sqrt(found->sun[0] * found->sun[0] + found->sun[1] * found->sun[1] + found->sun[2] * found->sun[2]);
      next.multiplier = found->mult;
      for (int i = 0; i < 3; ++i) {
        next.sunDirection[i] = len > 0.0f ? found->sun[i] / len : found->sun[i];
        next.sunColor[i] = found->colour[i];
        next.sunAmbience[i] = found->ambient[i];
        next.shadowFill[i] = found->fill[i];
      }
    }
    if (next == before) {
      return;
    }
    mDocument.ApplyLighting(next);
    mDocument.LightingEdited(before);
    mDocument.SetModified(true);
    gpg::Logf("editor: unit view: light %s (one undo step)", name.c_str());
  }

  void EdMapScene::DropUnitPreview()
  {
    if (mPreviewInstance != nullptr && moho::MeshRenderer::GetInstance() != nullptr) {
      delete mPreviewInstance;
    }
    mPreviewInstance = nullptr;
    mPreviewPose.reset();
    mPreviewKey.clear();
    mPreviewBoneMap.clear();
  }

  void EdMapScene::TickUnitPreview(
    const float frameSeconds
  )
  {
    UnitPreviewState* const s = mUnitPreview;
    // The stage and the light follow the panel even while no unit is shown (the map comes back when it is off).
    SetPreviewStage(s != nullptr && s->active && s->stage && mMap != nullptr);
    if (s != nullptr && mMap != nullptr && s->light != mPreviewLight) {
      SetPreviewLight(s->light);
    }
    if (s == nullptr || !s->active || s->unit.empty() || mMap == nullptr) {
      if (mPreviewInstance != nullptr) {
        DropUnitPreview();
      }
      return;
    }
    moho::RRuleGameRules* const rules = Rules();
    moho::MeshRenderer* const renderer = moho::MeshRenderer::GetInstance();
    if (rules == nullptr || renderer == nullptr) {
      s->status = "The game's rules aren't loaded yet.";
      return;
    }
    moho::RResId resId{};
    resId.name.assign(s->unit.c_str());
    const moho::RUnitBlueprint* const bp = rules->GetUnitBlueprint(resId);
    if (bp == nullptr) {
      s->status = "The game has no unit " + s->unit + ".";
      DropUnitPreview();
      return;
    }
    // The instance: made again when the unit or the army colour changed.
    const std::string key = s->unit + "|" + std::to_string(s->army);
    if (key != mPreviewKey) {
      DropUnitPreview();
      const moho::RMeshBlueprint* const mesh = rules->GetMeshBlueprint(bp->Display.MeshBlueprint);
      if (mesh == nullptr) {
        s->status = s->unit + " has no mesh blueprint.";
        return;
      }
      const float scale = bp->Display.UniformScale;
      mPreviewInstance = renderer->CreateMeshInstance(
        0,
        static_cast<std::int32_t>(ArmyColour(s->army)),
        mesh,
        Wm3::Vec3f{scale, scale, scale},
        true,
        std::shared_ptr<moho::MeshMaterial>()
      );
      if (mPreviewInstance == nullptr) {
        s->status = "The mesh renderer made no instance of " + s->unit + ".";
        return;
      }
      mPreviewKey = key;
      mPreviewAnimPath.clear();
      // The mesh's LODs, by their cutoff distances (the panel's LOD choice).
      s->lodCutoffs.clear();
      for (const auto& lod : mesh->mLods) {
        s->lodCutoffs.push_back(lod.mLodCutoff);
      }
      mPreviewLodShown = -1;
      // The animations the blueprint names (Display.Animation*, and the death animations' Animation).
      s->animations.clear();
      if (LuaPlus::LuaState* const state = static_cast<moho::RRuleGameRulesImpl*>(rules)->mLuaState; state != nullptr) {
        const LuaPlus::LuaObject table = bp->GetLuaBlueprint(state);
        const LuaPlus::LuaObject display = table.IsTable() ? table.GetByName("Display") : LuaPlus::LuaObject();
        if (display.IsTable()) {
          for (LuaPlus::LuaTableIterator it(display, 1); it; it.Next()) {
            const LuaPlus::LuaObject k = it.GetKey();
            const LuaPlus::LuaObject v = it.GetValue();
            if (!k.IsString() || std::strncmp(k.GetString(), "Animation", 9) != 0) {
              continue;
            }
            if (v.IsString()) {
              s->animations.emplace_back(v.GetString());
            } else if (v.IsTable()) {
              for (LuaPlus::LuaTableIterator e(v, 1); e; e.Next()) {
                const LuaPlus::LuaObject entry = e.GetValue();
                const LuaPlus::LuaObject a = entry.IsTable() ? entry.GetByName("Animation") : LuaPlus::LuaObject();
                if (a.IsString()) {
                  s->animations.emplace_back(a.GetString());
                }
              }
            }
          }
        }
      }
      std::sort(s->animations.begin(), s->animations.end());
      s->animations.erase(std::unique(s->animations.begin(), s->animations.end()), s->animations.end());
      gpg::Logf("editor: unit view: %s in the view, %zu animations named", s->unit.c_str(), s->animations.size());
    }
    // The animation: read again when its path changed.
    if (s->animation != mPreviewAnimPath) {
      mPreviewAnimPath = s->animation;
      mPreviewAnim = ScaAnimation{};
      mPreviewBoneMap.clear();
      s->duration = 0.0f;
      s->time = 0.0f;
      if (!s->animation.empty()) {
        std::string bytes;
        std::string error;
        if (!readGameFile || !readGameFile(s->animation, bytes)) {
          s->status = "The game has no file " + s->animation + ".";
        } else if (!ReadSca(std::vector<std::uint8_t>(bytes.begin(), bytes.end()), mPreviewAnim, error)) {
          s->status = s->animation + ": " + error;
        } else {
          s->duration = mPreviewAnim.duration;
          s->status = s->animation + ": " + std::to_string(mPreviewAnim.frames.size()) + " frames, " +
            std::to_string(mPreviewAnim.bones.size()) + " bones";
        }
      }
    }
    // A chosen LOD: the camera at the middle of its distance range (Studio's ShowLOD; the engine picks the LOD by the
    // camera's distance, so this is what the game shows at that distance).
    if (s->lod != mPreviewLodShown) {
      mPreviewLodShown = s->lod;
      if (s->lod >= 0 && static_cast<std::size_t>(s->lod) < s->lodCutoffs.size()) {
        const float from = s->lod == 0 ? 0.0f : s->lodCutoffs[static_cast<std::size_t>(s->lod) - 1];
        const float cutoff = s->lodCutoffs[static_cast<std::size_t>(s->lod)];
        float target = cutoff > from ? (from + cutoff) * 0.5f : from * 1.33f;
        if (s->lod == 0) {
          target = std::max(1.0f, cutoff * 0.5f);
        }
        mDistance = std::max(target, 2.0f);
        gpg::Logf(
          "editor: unit view: LOD %d of %s: the camera at %.0f (its range %.0f to %.0f)",
          s->lod,
          s->unit.c_str(),
          static_cast<double>(mDistance),
          static_cast<double>(from),
          static_cast<double>(cutoff)
        );
      }
    }
    // Where it stands: the camera's target (the camera follows it while locked).
    mPreviewPos[0] = mTargetX;
    mPreviewPos[2] = mTargetZ;
    mPreviewPos[1] = GroundHeightAt(mTargetX, mTargetZ);
    // The time.
    if (s->playing && !s->scrubbed && s->duration > 0.0f) {
      s->time += frameSeconds * s->rate;
      if (s->loop) {
        s->time = std::fmod(s->time, s->duration);
        if (s->time < 0.0f) {
          s->time += s->duration;
        }
      } else if (s->time >= s->duration) {
        s->time = s->duration;
        s->playing = false;
      }
    }
    s->scrubbed = false;
    // The pose: the skeleton of the mesh's first level, the animation's keys by bone name.
    moho::VTransform where{};
    where.pos_ = Wm3::Vec3f{mPreviewPos[0], mPreviewPos[1], mPreviewPos[2]};
    where.orient_ = Wm3::Quatf(1.0f, 0.0f, 0.0f, 0.0f);
    std::shared_ptr<moho::Mesh> mesh = mPreviewInstance->GetMesh();
    std::shared_ptr<moho::RScmResource> resource = mesh != nullptr ? mesh->GetResource(0) : nullptr;
    std::shared_ptr<const moho::CAniSkel> skeleton = resource != nullptr ? resource->GetSkeleton() : nullptr;
    if (skeleton == nullptr) {
      mPreviewInstance->SetStance(where, where);
      return;
    }
    if (mPreviewPose == nullptr) {
      mPreviewPose = std::make_shared<moho::CAniPose>(skeleton, bp->Display.UniformScale);
    }
    if (mPreviewBoneMap.size() != mPreviewAnim.bones.size()) {
      mPreviewBoneMap.assign(mPreviewAnim.bones.size(), -1);
      for (std::size_t i = 0; i < mPreviewAnim.bones.size(); ++i) {
        mPreviewBoneMap[i] = skeleton->FindBoneIndex(mPreviewAnim.bones[i].c_str());
      }
    }
    // The rest pose first, then the animation's keys on the bones it has.
    const std::size_t boneCount = skeleton->mBones.size();
    for (std::size_t i = 0; i < boneCount && i < mPreviewPose->mBones.size(); ++i) {
      mPreviewPose->mBones[i].SetLocalTransform(skeleton->mBones[i].mLocalTransform);
    }
    if (!mPreviewAnim.frames.empty()) {
      const std::vector<ScaKey> keys = SampleSca(mPreviewAnim, s->time, s->loop);
      for (std::size_t i = 0; i < keys.size() && i < mPreviewBoneMap.size(); ++i) {
        const int b = mPreviewBoneMap[i];
        if (b < 0 || static_cast<std::size_t>(b) >= mPreviewPose->mBones.size()) {
          continue;
        }
        moho::VTransform local{};
        local.pos_ = Wm3::Vec3f{keys[i].position[0], keys[i].position[1], keys[i].position[2]};
        local.orient_ = Wm3::Quatf(keys[i].rotation[0], keys[i].rotation[1], keys[i].rotation[2], keys[i].rotation[3]);
        mPreviewPose->mBones[static_cast<std::size_t>(b)].SetLocalTransform(local);
      }
    }
    mPreviewPose->SetWorldTransform(where);
    mPreviewPose->UpdateBones();
    mPreviewInstance->SetStance(where, where, true, mPreviewPose, mPreviewPose);
    mPreviewInstance->isHidden = 0;
  }

  void EdMapScene::DrawUnitPreview(
    moho::CD3DPrimBatcher& batcher
  )
  {
    UnitPreviewState* const s = mUnitPreview;
    if (s == nullptr || !s->active || mPreviewInstance == nullptr) {
      return;
    }
    moho::RRuleGameRules* const rules = Rules();
    if (rules == nullptr) {
      return;
    }
    moho::RResId resId{};
    resId.name.assign(s->unit.c_str());
    const moho::RUnitBlueprint* const bp = rules->GetUnitBlueprint(resId);
    if (bp == nullptr) {
      return;
    }
    const float x = mPreviewPos[0];
    const float y = mPreviewPos[1];
    const float z = mPreviewPos[2];
    // The bones: each joined to its parent (the pose's composite transforms).
    if (s->bones && mPreviewPose != nullptr) {
      constexpr std::uint32_t kBone = 0xFF40FFFFu;
      for (std::size_t i = 0; i < mPreviewPose->mBones.size(); ++i) {
        const moho::CAniPoseBone& bone = mPreviewPose->mBones[i];
        const moho::VTransform& t = bone.GetCompositeTransform();
        const int parent = bone.mParent != nullptr ? bone.mParent->mIdx : -1;
        const float bx = t.pos_.x;
        const float by = t.pos_.y;
        const float bz = t.pos_.z;
        if (parent >= 0 && static_cast<std::size_t>(parent) < mPreviewPose->mBones.size()) {
          const moho::VTransform& p = mPreviewPose->mBones[static_cast<std::size_t>(parent)].GetCompositeTransform();
          batcher.DrawLine(V(p.pos_.x, p.pos_.y, p.pos_.z, kBone), V(bx, by, bz, kBone));
        }
        batcher.DrawLine(V(bx - 0.08f, by, bz, kBone), V(bx + 0.08f, by, bz, kBone));
        batcher.DrawLine(V(bx, by - 0.08f, bz, kBone), V(bx, by + 0.08f, bz, kBone));
      }
    }
    // The collision box (SizeX / SizeY / SizeZ about the collision offset).
    if (s->hitbox) {
      constexpr std::uint32_t kBox = 0xFFFF6060u;
      const float hx = bp->mSizeX * 0.5f;
      const float hz = bp->mSizeZ * 0.5f;
      const float cx = x + bp->mCollisionOffsetX;
      const float cz = z + bp->mCollisionOffsetZ;
      const float y0 = y + bp->mCollisionOffsetY;
      const float y1 = y0 + bp->mSizeY;
      const float xs[2] = {cx - hx, cx + hx};
      const float zs[2] = {cz - hz, cz + hz};
      for (const float yy : {y0, y1}) {
        batcher.DrawLine(V(xs[0], yy, zs[0], kBox), V(xs[1], yy, zs[0], kBox));
        batcher.DrawLine(V(xs[1], yy, zs[0], kBox), V(xs[1], yy, zs[1], kBox));
        batcher.DrawLine(V(xs[1], yy, zs[1], kBox), V(xs[0], yy, zs[1], kBox));
        batcher.DrawLine(V(xs[0], yy, zs[1], kBox), V(xs[0], yy, zs[0], kBox));
      }
      for (const float xx : xs) {
        for (const float zz : zs) {
          batcher.DrawLine(V(xx, y0, zz, kBox), V(xx, y1, zz, kBox));
        }
      }
    }
    // The footprint (whole cells) and the skirt.
    if (s->footprint) {
      constexpr std::uint32_t kFoot = 0xFF60FF60u;
      constexpr std::uint32_t kSkirt = 0xFF60A0FFu;
      const float fx = static_cast<float>(bp->mFootprint.mSizeX) * 0.5f;
      const float fz = static_cast<float>(bp->mFootprint.mSizeZ) * 0.5f;
      const float lift = y + 0.1f;
      const auto rect = [&](const float x0, const float z0, const float x1, const float z1, const std::uint32_t c) {
        batcher.DrawLine(V(x0, lift, z0, c), V(x1, lift, z0, c));
        batcher.DrawLine(V(x1, lift, z0, c), V(x1, lift, z1, c));
        batcher.DrawLine(V(x1, lift, z1, c), V(x0, lift, z1, c));
        batcher.DrawLine(V(x0, lift, z1, c), V(x0, lift, z0, c));
      };
      rect(x - fx, z - fz, x + fx, z + fz, kFoot);
      if (bp->Physics.SkirtSizeX > 0.0f && bp->Physics.SkirtSizeZ > 0.0f) {
        const float sx0 = x - fx + bp->Physics.SkirtOffsetX;
        const float sz0 = z - fz + bp->Physics.SkirtOffsetZ;
        rect(sx0, sz0, sx0 + bp->Physics.SkirtSizeX, sz0 + bp->Physics.SkirtSizeZ, kSkirt);
      }
    }
    // Weapon ranges (max and min) and the senses.
    const float lift = y + 0.2f;
    if (s->ranges) {
      for (const moho::RUnitBlueprintWeapon& w : bp->Weapons.WeaponBlueprints) {
        if (w.MaxRadius > 0.0f) {
          Ring(batcher, x, lift, z, w.MaxRadius, 0xFFFF4040u);
        }
        if (w.MinRadius > 0.0f) {
          Ring(batcher, x, lift, z, w.MinRadius, 0xA0FF8080u);
        }
      }
    }
    if (s->senses) {
      if (bp->Intel.VisionRadius > 0) {
        Ring(batcher, x, lift, z, static_cast<float>(bp->Intel.VisionRadius), 0xFFFFFFFFu);
      }
      if (bp->Intel.RadarRadius > 0) {
        Ring(batcher, x, lift, z, static_cast<float>(bp->Intel.RadarRadius), 0xFF60FF60u);
      }
      if (bp->Intel.SonarRadius > 0) {
        Ring(batcher, x, lift, z, static_cast<float>(bp->Intel.SonarRadius), 0xFF60A0FFu);
      }
      if (bp->Intel.OmniRadius > 0) {
        Ring(batcher, x, lift, z, static_cast<float>(bp->Intel.OmniRadius), 0xFFC080FFu);
      }
    }
  }
} // namespace faf::editor
