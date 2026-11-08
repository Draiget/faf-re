#include "moho/mesh/MeshPrivate.h"

#include <algorithm>
#include <cstring>

#include "moho/console/CConCommand.h"

namespace moho
{

  [[nodiscard]] float REN_GetSimDeltaSeconds();

  /**
   * Address: 0x007E6CE0 (FUN_007E6CE0)
   *
   * What it does:
   * Refreshes interpolation state and copies `MeshInstance::curPose` into one
   * shared-pose out lane while retaining the copied control block.
   */
  boost::shared_ptr<CAniPose>* CaptureMeshInstanceCurrentPose(
    boost::shared_ptr<CAniPose>* const outPose,
    MeshInstance* const meshInstance
  )
  {
    if (outPose == nullptr || meshInstance == nullptr) {
      return outPose;
    }

    meshInstance->UpdateInterpolatedFields();
    *outPose = meshInstance->curPose;
    return outPose;
  }
}

namespace
{
  [[nodiscard]] float NanValue() noexcept
  {
    return std::numeric_limits<float>::quiet_NaN();
  }

  [[nodiscard]] bool FloatEqual(const float lhs, const float rhs) noexcept
  {
    return lhs == rhs;
  }

  [[nodiscard]] bool Vec3EqualExact(const Wm3::Vec3f& lhs, const Wm3::Vec3f& rhs) noexcept
  {
    return FloatEqual(lhs.x, rhs.x) && FloatEqual(lhs.y, rhs.y) && FloatEqual(lhs.z, rhs.z);
  }

  [[nodiscard]] bool QuatEqualExact(const Wm3::Quatf& lhs, const Wm3::Quatf& rhs) noexcept
  {
    return FloatEqual(lhs.w, rhs.w) && FloatEqual(lhs.x, rhs.x) && FloatEqual(lhs.y, rhs.y) && FloatEqual(lhs.z, rhs.z);
  }

  [[nodiscard]] float Clamp01(const float value) noexcept
  {
    return std::clamp(value, 0.0f, 1.0f);
  }

  /**
   * Address: 0x007DAC10 (FUN_007DAC10, sub_7DAC10)
   *
   * What it does:
   * Multiplies local mesh bounds by per-axis instance scale.
   */
  [[nodiscard]] Wm3::AxisAlignedBox3f ScaleLocalMeshBounds(
    const Wm3::Vec3f& scale,
    const Wm3::AxisAlignedBox3f& localBounds
  ) noexcept
  {
    Wm3::AxisAlignedBox3f scaled{};
    scaled.Min.x = scale.x * localBounds.Min.x;
    scaled.Min.y = scale.y * localBounds.Min.y;
    scaled.Min.z = scale.z * localBounds.Min.z;
    scaled.Max.x = scale.x * localBounds.Max.x;
    scaled.Max.y = scale.y * localBounds.Max.y;
    scaled.Max.z = scale.z * localBounds.Max.z;
    return scaled;
  }

  /**
   * Address: 0x007DAB00 (FUN_007DAB00, sub_7DAB00)
   *
   * What it does:
   * Merges two AABB lanes into one min/min + max/max result.
   */
  [[nodiscard]] Wm3::AxisAlignedBox3f MergeAxisAlignedBounds(
    const Wm3::AxisAlignedBox3f& first,
    const Wm3::AxisAlignedBox3f& second
  ) noexcept
  {
    Wm3::AxisAlignedBox3f merged = second;
    merged.Min.x = std::min(first.Min.x, merged.Min.x);
    merged.Min.y = std::min(first.Min.y, merged.Min.y);
    merged.Min.z = std::min(first.Min.z, merged.Min.z);
    merged.Max.x = std::max(first.Max.x, merged.Max.x);
    merged.Max.y = std::max(first.Max.y, merged.Max.y);
    merged.Max.z = std::max(first.Max.z, merged.Max.z);
    return merged;
  }

  /**
   * Address: 0x00472CF0 (FUN_00472CF0, sub_472CF0)
   *
   * IDA signature:
   * float* __usercall sub_472CF0@<eax>(Wm3::Quaternionf* a1@<ecx>,
   *                                   float* localAabb@<esi>,
   *                                   Wm3::Box3f* dest@<edx>);
   *
   * What it does:
   * Builds a world-space oriented box from a quaternion + a local AABB
   * (`[xMin, yMin, zMin, xMax, yMax, zMax]` packed as 6 floats) plus the
   * world-space position lane that follows the quaternion in memory
   * (interpolated mesh position). Result is `Box3f{ center, vX, vY, vZ,
   * halfExtents }` written into `dest`.
   *
   * Used by `MeshInstance::UpdateInterpolatedFields` and
   * `MeshInstance::GetSweptAlignedBox` to derive the renderer-facing
   * oriented box from the current interpolated stance.
   */
  void BuildOrientedBoxFromLocalAabb(
    const Wm3::Quaternionf& orientation,
    const Wm3::Vec3f& worldPosition,
    const float xMinL,
    const float yMinL,
    const float zMinL,
    const float xMaxL,
    const float yMaxL,
    const float zMaxL,
    Wm3::Box3f& dest
  ) noexcept
  {
    moho::VAxes3 axes{orientation};

    const float halfX = (xMaxL - xMinL) * 0.5f;
    const float halfY = (yMaxL - yMinL) * 0.5f;
    const float halfZ = (zMaxL - zMinL) * 0.5f;

    const float centerLX = (xMinL + xMaxL) * 0.5f;
    const float centerLY = (yMinL + yMaxL) * 0.5f;
    const float centerLZ = (zMinL + zMaxL) * 0.5f;

    const float worldOffsetX = axes.vZ.x * centerLZ + axes.vY.x * centerLY + axes.vX.x * centerLX;
    const float worldOffsetY = axes.vZ.y * centerLZ + axes.vY.y * centerLY + axes.vX.y * centerLX;
    const float worldOffsetZ = axes.vZ.z * centerLZ + axes.vY.z * centerLY + axes.vX.z * centerLX;

    dest.Center.x = worldPosition.x + worldOffsetX;
    dest.Center.y = worldPosition.y + worldOffsetY;
    dest.Center.z = worldPosition.z + worldOffsetZ;

    dest.Axis[0] = axes.vX;
    dest.Axis[1] = axes.vY;
    dest.Axis[2] = axes.vZ;

    dest.Extent[0] = halfX;
    dest.Extent[1] = halfY;
    dest.Extent[2] = halfZ;
  }

  constexpr std::int32_t kMeshSpatialDbRoutingMask = 0x800;

  [[nodiscard]] moho::VTransform IdentityTransform() noexcept
  {
    moho::VTransform transform{};
    transform.orient_.w = 1.0f;
    transform.orient_.x = 0.0f;
    transform.orient_.y = 0.0f;
    transform.orient_.z = 0.0f;
    transform.pos_.x = 0.0f;
    transform.pos_.y = 0.0f;
    transform.pos_.z = 0.0f;
    return transform;
  }

  [[nodiscard]] boost::shared_ptr<const moho::CAniSkel>
  ResolveInitialPoseSkeleton(const boost::shared_ptr<moho::Mesh>& mesh, const bool isStaticPose)
  {
    if (!isStaticPose || !mesh) {
      return moho::CAniSkel::GetDefaultSkeleton();
    }

    const boost::shared_ptr<moho::RScmResource> resource = mesh->GetResource(0);
    if (!resource) {
      return moho::CAniSkel::GetDefaultSkeleton();
    }

    const boost::shared_ptr<const moho::CAniSkel> skeleton = resource->GetSkeleton();
    if (skeleton) {
      return skeleton;
    }

    return moho::CAniSkel::GetDefaultSkeleton();
  }

  [[nodiscard]] float ComputeSpatialDissolveCutoff(const boost::shared_ptr<moho::Mesh>& mesh)
  {
    if (!mesh) {
      return -1.0f;
    }

    moho::MeshLOD* const* const begin = mesh->lods.begin();
    moho::MeshLOD* const* const end = mesh->lods.end();
    if (!begin || !end || begin == end) {
      return -1.0f;
    }

    const moho::MeshLOD* const lastLod = *(end - 1);
    if (!lastLod || lastLod->cutoff <= 0.0f) {
      return -1.0f;
    }

    return lastLod->cutoff + moho::ren_MeshDissolve;
  }
}

namespace moho
{

  std::uint8_t MeshInstance::sFrameCounter = 0;
  float MeshInstance::sCurrentInterpolant = 0.0f;

  /**
   * Address: 0x007DE6A0 (FUN_007DE6A0, ?SetCurrentInterpolant@MeshInstance@Moho@@SAXM@Z)
   *
   * What it does:
   * Advances the global mesh frame counter and snapshots the current render
   * frame interpolation value.
   */
  void MeshInstance::SetCurrentInterpolant()
  {
    ++sFrameCounter;
    sCurrentInterpolant = REN_GetSimDeltaSeconds();
  }

  /**
   * Address: 0x007DE060 (FUN_007DE060,
   * ??0MeshInstance@Moho@@QAE@PAV?$SpatialDB@VMeshInstance@Moho@@@1@HIV?$shared_ptr@VMesh@Moho@@@boost@@ABV?$Vector3@M@Wm3@@_N@Z)
   */
  MeshInstance::MeshInstance(
    const Wm3::Vec3f& scaleArg,
    SpatialDB<MeshInstance>* const spatialDbStorage,
    const std::int32_t gameTickArg,
    const std::int32_t colorArg,
    const bool isStaticPoseArg,
    const boost::shared_ptr<Mesh> meshArg
  )
    : TDatListItem<MeshInstance, void>()
    , db()
    , mesh(meshArg)
    , color(colorArg)
    , meshColor(0.0f)
    , visibilityCamera(nullptr)
    , isHidden(0)
    , isReflected(1)
    , pad_2A_2B{}
    , gameTick(gameTickArg)
    , uniformScale(1.0f)
    , scale(scaleArg)
    , endTransform(IdentityTransform())
    , startTransform(IdentityTransform())
    , curOrientation(1.0f, 0.0f, 0.0f, 0.0f)
    , interpolatedPosition(0.0f, 0.0f, 0.0f)
    , scroll1(0.0f, 0.0f)
    , scroll2(0.0f, 0.0f)
    , hasStanceUpdatePending(1)
    , isStaticPose(static_cast<std::uint8_t>(isStaticPoseArg ? 1 : 0))
    , isLocked(0)
    , poseStill(0)
    , startPose()
    , endPose()
    , curPose()
    , dissolve(1.0f)
    , parameters(0.0f)
    , fractionCompleteParameter(1.0f)
    , fractionHealthParameter(1.0f)
    , lifetimeParameter(0.0f)
    , auxiliaryParameter(0.0f)
    , frameCounter(0xFFu)
    , interpolationStateFresh(0)
    , pad_DA_DB{}
    , currInterpolant(-1.0f)
    , sphere{}
    , xMin(NanValue())
    , yMin(NanValue())
    , zMin(NanValue())
    , xMax(NanValue())
    , yMax(NanValue())
    , zMax(NanValue())
    , box{}
    , renderMinX(NanValue())
    , renderMinY(NanValue())
    , renderMinZ(NanValue())
    , renderMaxX(NanValue())
    , renderMaxY(NanValue())
    , renderMaxZ(NanValue())
    , boundsValid(1)
    , pad_15D_15F{}
  {
    sphere.Center = {NanValue(), NanValue(), NanValue()};
    sphere.Radius = NanValue();
    const boost::shared_ptr<const CAniSkel> skeleton = ResolveInitialPoseSkeleton(meshArg, isStaticPoseArg);
    curPose.reset(new CAniPose(skeleton, 1.0f));

    db.Register(spatialDbStorage, this, kMeshSpatialDbRoutingMask);
    const float dissolveCutoff = ComputeSpatialDissolveCutoff(meshArg);
    db.UpdateDissolveCutoff(dissolveCutoff);
  }

  /**
   * Address: 0x007DE550 (FUN_007DE550, ??1MeshInstance@Moho@@UAE@XZ)
   * Address: 0x007DE510 (FUN_007DE510, the scalar deleting destructor in
   * vftable 0xE3F48C's only slot: this body, then `operator delete` on flag
   * bit 0. `delete instance` reaches it; it was hand-written as a virtual
   * `Release(int)`.)
   */
  MeshInstance::~MeshInstance()
  {
    // The rest is member destruction, as 0x007DE550 is: the pose and mesh
    // shared_ptrs in reverse order, `db` (its inlined `if (mDb)` unregister at
    // 0x007DE663), then the TDatListItem base's unlink.
  }

  /**
   * Address: 0x007DADD0 (FUN_007DADD0, ?GetMesh@MeshInstance@Moho@@QBE?AV?$shared_ptr@VMesh@Moho@@@boost@@XZ)
   */
  boost::shared_ptr<Mesh> MeshInstance::GetMesh() const
  {
    return mesh;
  }

  /**
   * Address: 0x007DE6C0 (FUN_007DE6C0, ?Cull@MeshInstance@Moho@@QAEX_N@Z)
   *
   * What it does:
   * Stores one per-instance hidden/cull visibility flag.
   */
  void MeshInstance::Cull(const bool hidden)
  {
    isHidden = hidden ? 1u : 0u;
  }

  /**
   * Address: 0x007DE6D0 (FUN_007DE6D0, ?Reflect@MeshInstance@Moho@@QAEX_N@Z)
   *
   * What it does:
   * Clears one per-instance reflection-visibility flag.
   */
  void MeshInstance::Reflect([[maybe_unused]] const bool reflected)
  {
    isReflected = 0u;
  }

  /**
   * Address: 0x007DE880 (FUN_007DE880, ?SetParameter@MeshInstance@Moho@@QAEXW4PARAM@MeshMaterial@2@M@Z)
   *
   * What it does:
   * Writes one shader parameter lane selected by `MeshMaterial::PARAM`.
   */
  void MeshInstance::SetParameter(const MeshMaterial::PARAM parameter, const float value)
  {
    switch (parameter) {
    case MeshMaterial::PARAM_GENERIC:
      parameters = value;
      break;
    case MeshMaterial::PARAM_FRACTION_COMPLETE:
      fractionCompleteParameter = value;
      break;
    case MeshMaterial::PARAM_FRACTION_HEALTH:
      fractionHealthParameter = value;
      break;
    case MeshMaterial::PARAM_LIFETIME:
      lifetimeParameter = value;
      break;
    case MeshMaterial::PARAM_AUXILIARY:
      auxiliaryParameter = value;
      break;
    default:
      break;
    }
  }

  /**
   * Address: 0x007DE850 (FUN_007DE850, ?SetInterpolantScale@MeshInstance@Moho@@QAEXM@Z)
   *
   * What it does:
   * Stores one per-instance interpolation scale and invalidates cached
   * interpolant lane for refresh.
   */
  void MeshInstance::SetInterpolantScale(const float interpolantScale)
  {
    uniformScale = interpolantScale;
    frameCounter = sFrameCounter;
    currInterpolant = -1.0f;
  }

  /**
   * Address: 0x007DE8C0 (FUN_007DE8C0, ?SetScale@MeshInstance@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z)
   *
   * What it does:
   * Stores one per-instance render scale vector.
   */
  void MeshInstance::SetScale(const Wm3::Vec3f& scaleArg)
  {
    scale = scaleArg;
  }

  /**
   * Address: 0x007DE8E0 (FUN_007DE8E0, ?SetColor@MeshInstance@Moho@@QAEXI@Z)
   *
   * What it does:
   * Stores one packed per-instance color value.
   */
  void MeshInstance::SetColor(const std::uint32_t colorArg)
  {
    color = static_cast<std::int32_t>(colorArg);
  }

  /**
   * Address: 0x007DE900 (FUN_007DE900, ?SetScroll@MeshInstance@Moho@@QAEXABV?$Vector2@M@Wm3@@0@Z)
   *
   * What it does:
   * Stores two texture-scroll vector lanes for this mesh instance.
   */
  void MeshInstance::SetScroll(const Wm3::Vec2f& scroll1Arg, const Wm3::Vec2f& scroll2Arg)
  {
    scroll1 = scroll1Arg;
    scroll2 = scroll2Arg;
  }

  /**
   * Address: 0x007DF140 (FUN_007DF140, ?ResetBatches@MeshInstance@Moho@@QAEXXZ)
   *
   * What it does:
   * Resets mesh LOD batch handles for this instance when a mesh owner exists.
   */
  void MeshInstance::ResetBatches()
  {
    Mesh* const meshObject = mesh.get();
    if (meshObject != nullptr) {
      meshObject->ResetBatches();
    }
  }

  /**
   * Address: 0x007DE890 (FUN_007DE890, ?SetDissolve@MeshInstance@Moho@@QAEXM@Z)
   *
   * What it does:
   * Clamps and stores dissolve value in `[0.0f, 1.0f]`.
   */
  void MeshInstance::SetDissolve(const float dissolveAmount)
  {
    float clampedValue = 1.0f;
    if (dissolveAmount < 1.0f) {
      clampedValue = dissolveAmount;
    }

    if (clampedValue < 0.0f) {
      dissolve = 0.0f;
      return;
    }
    dissolve = clampedValue;
  }

  /**
   * Address: 0x007DE930 (FUN_007DE930, ?SetStance@MeshInstance@Moho@@QAEXABVVTransform@2@0@Z)
   *
   * What it does:
   * Applies start/end stance transforms, flags interpolation refresh, and
   * marks stance/bounds state dirty when transform data changed.
   */
  void MeshInstance::SetStance(const VTransform& startTransformArg, const VTransform& endTransformArg)
  {
    // Same republish as the pose overload, at 0x007DEA0B..0x007DEA1A.
    if (ApplyStance(startTransformArg, endTransformArg)) {
      RepublishStanceBounds();
    }
  }

  bool MeshInstance::ApplyStance(const VTransform& startTransformArg, const VTransform& endTransformArg)
  {
    const bool changed = !Vec3EqualExact(endTransform.pos_, endTransformArg.pos_) ||
      !QuatEqualExact(endTransform.orient_, endTransformArg.orient_) ||
      !Vec3EqualExact(startTransform.pos_, startTransformArg.pos_) ||
      !QuatEqualExact(startTransform.orient_, startTransformArg.orient_);
    if (!changed) {
      hasStanceUpdatePending = 0;
      return false;
    }

    hasStanceUpdatePending = 1;
    endTransform = endTransformArg;
    startTransform = startTransformArg;
    frameCounter = sFrameCounter;
    currInterpolant = -1.0f;
    boundsValid = 1;
    return true;
  }

  void MeshInstance::RepublishStanceBounds()
  {
    db.UpdateBounds(GetSweptAlignedBox());
  }

  /**
   * Address: 0x007DE6E0 (FUN_007DE6E0, ?LockPose@MeshInstance@Moho@@QAEX_N@Z)
   *
   * What it does:
   * Toggles static-pose lock state; when locking, snapshots `curPose` into
   * `endPose`, and when unlocking, invalidates interpolation cache lanes.
   */
  void MeshInstance::LockPose(const bool lockPose)
  {
    const std::uint8_t lockValue = lockPose ? 1u : 0u;
    if (isLocked == lockValue) {
      return;
    }

    isLocked = lockValue;
    if (lockValue != 0u) {
      CAniPose* const endPoseValue = endPose.get();
      if (endPoseValue != nullptr) {
        endPoseValue->CopyPose(curPose.get(), true);
      }
      return;
    }

    frameCounter = sFrameCounter;
    currInterpolant = -1.0f;
    poseStill = 0;
  }

  /**
   * Address: 0x007DEA30 (FUN_007DEA30,
   * ?SetStance@MeshInstance@Moho@@QAEXABVVTransform@2@0V?$shared_ptr@VCAniPose@Moho@@@boost@@1@Z)
   *
   * What it does:
   * Applies the static-pose stance lane used by UserEntity updates, including
   * pose-handle assignment and optional transform/bounds refresh.
   */
  void MeshInstance::SetStance(
    const VTransform& startTransformArg,
    const VTransform& endTransformArg,
    const bool forceRefresh,
    boost::shared_ptr<CAniPose> startPoseArg,
    boost::shared_ptr<CAniPose> endPoseArg
  )
  {
    // Republish the swept bounds into this instance's spatial-db entry
    // (0x007DEBD4..0x007DEBE4: set the dirty byte, GetSweptAlignedBox, then
    // UpdateBounds on `this + 0x0C`, which is `db`). Without it the entry keeps
    // the NaN box the ctor gave it, `MeshRenderer::Batch`'s
    // CollectAllInVolume never matches the instance, and the mesh is never
    // drawn at all.
    if (ApplyStance(startTransformArg, endTransformArg, forceRefresh, startPoseArg, endPoseArg)) {
      RepublishStanceBounds();
    }
  }

  bool MeshInstance::ApplyStance(
    const VTransform& startTransformArg,
    const VTransform& endTransformArg,
    const bool forceRefresh,
    const boost::shared_ptr<CAniPose>& startPoseArg,
    const boost::shared_ptr<CAniPose>& endPoseArg
  )
  {
    if (isStaticPose == 0) {
      return ApplyStance(startTransformArg, endTransformArg);
    }

    startPose = startPoseArg;
    endPose = endPoseArg;

    frameCounter = sFrameCounter;
    currInterpolant = -1.0f;
    hasStanceUpdatePending = 1;
    poseStill = 0;

    const bool changed = !Vec3EqualExact(endTransform.pos_, endTransformArg.pos_) ||
      !QuatEqualExact(endTransform.orient_, endTransformArg.orient_) ||
      !Vec3EqualExact(startTransform.pos_, startTransformArg.pos_) ||
      !QuatEqualExact(startTransform.orient_, startTransformArg.orient_);
    if (!changed && !forceRefresh) {
      return false;
    }

    endTransform = endTransformArg;
    startTransform = startTransformArg;
    boundsValid = 1;
    return true;
  }

  bool ren_MeshPoseStill = true;
  namespace
  {
    TConVar<bool> gTConVar_ren_MeshPoseStill(
      "ren_MeshPoseStill",
      "A unit's pose is blended once while its start and end poses match (1, the default), or each frame (0). Read when a "
      "pose is blended.",
      &ren_MeshPoseStill
    );

    /// Whether blending the two poses gives the same result at any interpolant.
    [[nodiscard]] bool PosesMatch(const CAniPose& first, const CAniPose& second, const std::int32_t bones)
    {
      if (&first == &second) {
        return true;
      }
      if (first.mMaxOffset != second.mMaxOffset || std::memcmp(&first.mLocalTransform, &second.mLocalTransform, sizeof(VTransform)) != 0) {
        return false;
      }
      const std::int32_t count = std::min({
        static_cast<std::int32_t>(first.mBones.end() - first.mBones.begin()),
        static_cast<std::int32_t>(second.mBones.end() - second.mBones.begin()),
        bones,
      });
      for (std::int32_t index = 0; index < count; ++index) {
        const CAniPoseBone& a = first.mBones.begin()[index];
        const CAniPoseBone& b = second.mBones.begin()[index];
        if (a.mCompositeIsLocal != b.mCompositeIsLocal || a.mVisible != b.mVisible ||
            std::memcmp(&a.mLocalTransform, &b.mLocalTransform, sizeof(VTransform)) != 0) {
          return false;
        }
      }
      return true;
    }
  } // namespace

  /**
   * Address: 0x007DEC80 (FUN_007DEC80, ?UpdateInterpolatedFields@MeshInstance@Moho@@ABEXXZ)
   *
   * What it does:
   * Recomputes interpolated transform fields for the current global
   * interpolant. When a stance update is pending, also re-blends the
   * skinned pose (`curPose`) from `startPose`/`endPose` for static-pose
   * (unit) instances that are not locked, and rebuilds the world
   * sphere/oriented-box/AABB from the mesh resource's own local bounds.
   */
  void MeshInstance::UpdateInterpolatedFields()
  {
    // Ground truth (FUN_007DEC80.c) enters when the interpolant changed AND
    // (the frame counter is stale OR interpolation state isn't fresh yet
    // this frame) - i.e. it returns early only when NEITHER half fired.
    // SetStance resets currInterpolant to -1.0f but leaves frameCounter/
    // interpolationStateFresh untouched, so the second half is what lets a
    // fresh stance be picked up even on a call where sCurrentInterpolant
    // already happens to equal that reset sentinel.
    if (sCurrentInterpolant == currInterpolant ||
        (frameCounter == sFrameCounter && interpolationStateFresh != 0u)) {
      return;
    }

    float interpolation = uniformScale * sCurrentInterpolant;
    currInterpolant = sCurrentInterpolant;
    interpolationStateFresh = 1;
    interpolation = Clamp01(interpolation);

    const Wm3::Vec3f startPos = startTransform.pos_;
    const Wm3::Vec3f endPos = endTransform.pos_;
    interpolatedPosition.x = endPos.x + (startPos.x - endPos.x) * interpolation;
    interpolatedPosition.y = endPos.y + (startPos.y - endPos.y) * interpolation;
    interpolatedPosition.z = endPos.z + (startPos.z - endPos.z) * interpolation;

    Wm3::Quatf blendedOrientation{};
    QuatLERP(&startTransform.orient_, &endTransform.orient_, &blendedOrientation, interpolation);
    curOrientation = blendedOrientation;

    if (hasStanceUpdatePending == 0) {
      return;
    }

    // Ground truth reads the LOD-0 mesh resource unconditionally here and
    // dereferences it with no null check; `mesh` is set once at construction
    // and never cleared, so this should never actually be empty on a live
    // instance. Guarded anyway, matching GetSweptAlignedBox's own established
    // pattern in this class.
    const boost::shared_ptr<RScmResource> resource = mesh ? mesh->GetResource(0) : boost::shared_ptr<RScmResource>{};
    if (!resource) {
      return;
    }

    // Re-blend the skinned pose from start/end at the current interpolant so
    // `curPose` - which HardwareMeshBatch::FillBatch reads directly to fill
    // the GPU skinning palette (FillInstanceBonePalettes) - tracks the
    // instance's live animation state. Only static-pose (real unit)
    // instances that are not locked carry start/end pose handles (see
    // MeshInstance::SetStance's pose-carrying overload).
    //
    // Engine change (ren_MeshPoseStill): a unit that stands still gets two matching poses from the sim, and
    // blending those gives the same pose every frame. One blend per stance is enough, which also keeps the
    // bones' composite transforms from being rebuilt. The sim never writes a pose it has published.
    // Engine addition, server mode: a server session's client gets no poses until the pose lane (plan WP8.3), so a
    // unit's start and end pose can be null; it keeps the pose it has.
    if (isStaticPose != 0u && isLocked == 0u && (poseStill == 0u || !ren_MeshPoseStill) && startPose && endPose && curPose) {
      const std::int32_t skinBoneCount = static_cast<std::int32_t>(resource->mFile->mSkinBoneCount);
      curPose->InterpolatePose(interpolation, startPose.get(), endPose.get(), skinBoneCount);
      poseStill = (ren_MeshPoseStill && PosesMatch(*startPose, *endPose, skinBoneCount)) ? 1u : 0u;
    }

    float maxScale = scale.x;
    if (scale.y > maxScale) {
      maxScale = scale.y;
    }
    if (scale.z > maxScale) {
      maxScale = scale.z;
    }

    float radius = maxScale * resource->mSize * 0.5f;
    const float maxOffset = curPose->mMaxOffset;
    if (maxOffset > radius) {
      radius = maxOffset;
    }
    // curPose->mMaxOffset starts at -infinity (CAniPose's ctor default) and is
    // only ever raised by InterpolatePose, so this really tests "has a pose
    // blend ever actually run for this instance".
    const bool maxOffsetUnset = maxOffset <= gpg::nInf;

    sphere.Center = interpolatedPosition;
    if (!maxOffsetUnset) {
      sphere.Center.y += maxOffset;
    }
    sphere.Radius = radius;

    // Rebuild the world oriented box (and its derived AABB) from the mesh
    // resource's own local bounds scaled by the instance, not by recentering
    // whatever xMin..zMax happened to hold before - this is what ground
    // truth actually does (FUN_007DAC10 + FUN_00472CF0 chained together),
    // matching MeshInstance::GetSweptAlignedBox's already-correct pattern.
    const Wm3::AxisAlignedBox3f scaledLocalBounds = ScaleLocalMeshBounds(scale, resource->mBounds);
    BuildOrientedBoxFromLocalAabb(
      curOrientation, interpolatedPosition,
      scaledLocalBounds.Min.x, scaledLocalBounds.Min.y, scaledLocalBounds.Min.z,
      scaledLocalBounds.Max.x, scaledLocalBounds.Max.y, scaledLocalBounds.Max.z,
      box
    );

    Wm3::AxisAlignedBox3f fromOrientedBox{};
    fromOrientedBox = moho::AxisAlignedBoundsFromBox(box);
    xMin = fromOrientedBox.Min.x;
    yMin = fromOrientedBox.Min.y;
    zMin = fromOrientedBox.Min.z;
    xMax = fromOrientedBox.Max.x;
    yMax = fromOrientedBox.Max.y;
    zMax = fromOrientedBox.Max.z;
  }

  /**
   * Address: 0x007DAE20 (FUN_007DAE20, Moho::MeshInstance::GetInterpolatedPos)
   *
   * What it does:
   * Refreshes interpolation state and copies current interpolated position.
   */
  Wm3::Vec3f MeshInstance::GetInterpolatedPos() const
  {
    MeshInstance& self = *const_cast<MeshInstance*>(this);
    self.UpdateInterpolatedFields();
    return self.interpolatedPosition;
  }

  /**
   * Address: 0x007DE730 (FUN_007DE730, ?GetDebugBoneCount@MeshInstance@Moho@@QBEHXZ)
   *
   * What it does:
   * Returns zero for dynamic meshes; static meshes report SCM bone count.
   */
  std::int32_t MeshInstance::GetDebugBoneCount() const
  {
    if (isStaticPose == 0u) {
      return 0;
    }

    const boost::shared_ptr<RScmResource> resource = mesh->GetResource(0);
    return static_cast<std::int32_t>(resource->mFile->mBoneTotalCount);
  }

  /**
   * Address: 0x007DE7A0 (FUN_007DE7A0,
   * ?ComputeDebugPose@MeshInstance@Moho@@QAE?AV?$shared_ptr@VCAniPose@Moho@@@boost@@XZ)
   * Mangled: ?ComputeDebugPose@MeshInstance@Moho@@QAE?AV?$shared_ptr@VCAniPose@Moho@@@boost@@XZ
   *
   * IDA signature:
   * boost::shared_ptr_CAniPose* __userpurge Moho::MeshInstance::ComputeDebugPose@<eax>(
   *   Moho::MeshInstance* a1@<eax>, boost::shared_ptr_CAniPose* a2);
   *
   * What it does:
   * Refreshes the skeleton-debug pose and returns it as an additional
   * shared reference. For static-pose, unlocked meshes: fetches the
   * backing mesh's LOD-0 `RScmResource`, calls
   * `CAniPose::InterpolatePose(currInterpolant, startPose, endPose,
   * resource.mFile.mBoneCount)` on `curPose`, then returns one shared
   * handle to `curPose` to the caller. For non-static or locked meshes
   * returns an empty shared handle so skeleton-debug callers can render
   * nothing. The binary path bypasses any `shared_ptr` swap by hand and
   * inlines the control-block `use_count` bump; the typed return here
   * preserves the same semantics.
   */
  boost::shared_ptr<CAniPose> MeshInstance::ComputeDebugPose()
  {
    if (isStaticPose == 0u || isLocked != 0u) {
      return boost::shared_ptr<CAniPose>{};
    }

    const boost::shared_ptr<RScmResource> resource = mesh->GetResource(0);
    const std::int32_t boneCount = static_cast<std::int32_t>(resource->mFile->mBoneTotalCount);

    curPose->InterpolatePose(currInterpolant, startPose.get(), endPose.get(), boneCount);
    return curPose;
  }

  /**
   * Address: 0x007DEFC0 (FUN_007DEFC0,
   * ?GetSweptAlignedBox@MeshInstance@Moho@@QBE?AV?$AxisAlignedBox3@M@Wm3@@XZ)
   *
   * What it does:
   * Returns cached swept AABB lanes; when stale, rebuilds sweep from start/end
   * stance OBBs using scaled mesh-resource bounds.
   */
  Wm3::AxisAlignedBox3f MeshInstance::GetSweptAlignedBox() const
  {
    MeshInstance& self = *const_cast<MeshInstance*>(this);
    if (self.boundsValid != 0u) {
      const boost::shared_ptr<RScmResource> resource = self.mesh ? self.mesh->GetResource(0) : boost::shared_ptr<RScmResource>{};
      if (resource) {
        const Wm3::AxisAlignedBox3f scaledLocalBounds = ScaleLocalMeshBounds(self.scale, resource->mBounds);

        Wm3::Box3f endOriented{};
        BuildOrientedBoxFromLocalAabb(
          self.endTransform.orient_,
          self.endTransform.pos_,
          scaledLocalBounds.Min.x,
          scaledLocalBounds.Min.y,
          scaledLocalBounds.Min.z,
          scaledLocalBounds.Max.x,
          scaledLocalBounds.Max.y,
          scaledLocalBounds.Max.z,
          endOriented
        );

        Wm3::Box3f startOriented{};
        BuildOrientedBoxFromLocalAabb(
          self.startTransform.orient_,
          self.startTransform.pos_,
          scaledLocalBounds.Min.x,
          scaledLocalBounds.Min.y,
          scaledLocalBounds.Min.z,
          scaledLocalBounds.Max.x,
          scaledLocalBounds.Max.y,
          scaledLocalBounds.Max.z,
          startOriented
        );

        Wm3::AxisAlignedBox3f endBounds{};
        endBounds = moho::AxisAlignedBoundsFromBox(endOriented);

        Wm3::AxisAlignedBox3f startBounds{};
        startBounds = moho::AxisAlignedBoundsFromBox(startOriented);

        const Wm3::AxisAlignedBox3f sweptBounds = MergeAxisAlignedBounds(endBounds, startBounds);
        self.renderMinX = sweptBounds.Min.x;
        self.renderMinY = sweptBounds.Min.y;
        self.renderMinZ = sweptBounds.Min.z;
        self.renderMaxX = sweptBounds.Max.x;
        self.renderMaxY = sweptBounds.Max.y;
        self.renderMaxZ = sweptBounds.Max.z;
      }

      self.boundsValid = 0u;
    }

    Wm3::AxisAlignedBox3f result{};
    result.Min.x = self.renderMinX;
    result.Min.y = self.renderMinY;
    result.Min.z = self.renderMinZ;
    result.Max.x = self.renderMaxX;
    result.Max.y = self.renderMaxY;
    result.Max.z = self.renderMaxZ;
    return result;
  }
}

