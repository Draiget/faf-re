#include "moho/entity/UserEntity.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>

#include "moho/animation/CAniPose.h"
#include "moho/animation/CAniSkel.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/entity/EntityId.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/mesh/Mesh.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/resource/RScmResource.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/EAllianceTypeInfo.h"
#include "moho/sim/UserArmy.h"
#include "moho/unit/core/UserUnit.h"

namespace
{
  // Spatial-db routing classes chosen from packed entity-id family.
  constexpr std::uint32_t kSpatialDbClassLandLike = 0x100u;
  constexpr std::uint32_t kSpatialDbClassProjectile = 0x400u;
  constexpr std::uint32_t kSpatialDbClassProp = 0x200u;
  constexpr std::uint32_t kSpatialDbClassOther = 0x800u;

  struct NullRumbleSoundBinding
  {
    void* unk0;
    void* unk4;
    moho::CSndParams* current;
  };

  NullRumbleSoundBinding gNullRumbleSoundBinding{};

  [[nodiscard]] std::int32_t
  BuildSpatialDbRoutingMaskFromEntityId(const std::uint32_t entityId, const std::uint8_t sourceIndex) noexcept
  {
    // Family routes object class; low byte preserves source index.
    switch (moho::ClassifyEntityIdFamily(entityId)) {
    case moho::EEntityIdFamily::Unit:
    case moho::EEntityIdFamily::ShieldLike:
      return static_cast<std::int32_t>(sourceIndex | kSpatialDbClassLandLike);
    case moho::EEntityIdFamily::Projectile:
      return static_cast<std::int32_t>(sourceIndex | kSpatialDbClassProjectile);
    case moho::EEntityIdFamily::Prop:
      return static_cast<std::int32_t>(sourceIndex | kSpatialDbClassProp);
    default:
      return static_cast<std::int32_t>(sourceIndex | kSpatialDbClassOther);
    }
  }

  void InitializeSpatialDbEntry(
    moho::UserEntitySpatialDbEntry& entry,
    void* const sessionSpatialDbStorage,
    void* const owner,
    const std::int32_t spatialDbMask
  )
  {
    // Address: 0x00501A80 (sub_501A80)
    auto* const meshEntry = reinterpret_cast<moho::SpatialDB_MeshInstance*>(&entry);
    meshEntry->Register(sessionSpatialDbStorage, owner, spatialDbMask);
  }

  // 0x00416F60
  [[nodiscard]] bool ContainsCell(const moho::VisibilityRect& rect, const std::int32_t x, const std::int32_t z)
  {
    return x >= rect.minX && x < rect.maxX && z >= rect.minZ && z < rect.maxZ;
  }

  // 0x0063CA40
  void CreateCAniPoseSharedPtr(moho::CAniPose* const pose, boost::shared_ptr<moho::CAniPose>& out)
  {
    out.reset(pose);
  }

  void ResetLinkChain(moho::UserEntityLinkNode*& head) noexcept
  {
    // 0x004DFC50 / 0x00406560: unlink chain head by nulling each node's prev/next.
    while (head) {
      moho::UserEntityLinkNode* const next = head->mNext;
      head->mPrev = nullptr;
      head->mNext = nullptr;
      head = next;
    }
  }

  void DestroySpatialDbMeshInstanceStorage(moho::UserEntitySpatialDbEntry& storage)
  {
    // 0x008B8790: guard wrapper used by UserEntity dtor unwind path.
    if (!storage.mSpatialDb) {
      return;
    }

    auto* const meshInstance = reinterpret_cast<moho::SpatialDB_MeshInstance*>(&storage);
    meshInstance->ClearRegistration();
  }

  [[nodiscard]] float ClampUnitInterval(const float value) noexcept
  {
    return std::clamp(value, 0.0f, 1.0f);
  }

  [[nodiscard]] bool NearlyEqual(const float lhs, const float rhs, const float epsilon = 1.0e-6f) noexcept
  {
    return std::fabs(lhs - rhs) <= epsilon;
  }

  [[nodiscard]] bool AreQuaternionsNearlyEqual(const Wm3::Quatf& lhs, const Wm3::Quatf& rhs) noexcept
  {
    return NearlyEqual(lhs.w, rhs.w) && NearlyEqual(lhs.x, rhs.x) && NearlyEqual(lhs.y, rhs.y) &&
      NearlyEqual(lhs.z, rhs.z);
  }

  [[nodiscard]] Wm3::Quatf LerpQuaternionShortestPathNormalized(
    const Wm3::Quatf& current, const Wm3::Quatf& previous, const float alpha
  ) noexcept
  {
    if (AreQuaternionsNearlyEqual(current, previous)) {
      return previous;
    }

    Wm3::Quatf adjustedCurrent = current;
    if (Wm3::Quatf::Dot(previous, current) < 0.0f) {
      adjustedCurrent.w = -adjustedCurrent.w;
      adjustedCurrent.x = -adjustedCurrent.x;
      adjustedCurrent.y = -adjustedCurrent.y;
      adjustedCurrent.z = -adjustedCurrent.z;
    }

    const float keepWeight = 1.0f - alpha;
    Wm3::Quatf blended{
      previous.w * keepWeight + adjustedCurrent.w * alpha,
      previous.x * keepWeight + adjustedCurrent.x * alpha,
      previous.y * keepWeight + adjustedCurrent.y * alpha,
      previous.z * keepWeight + adjustedCurrent.z * alpha,
    };

    const float lengthSq =
      blended.w * blended.w + blended.x * blended.x + blended.y * blended.y + blended.z * blended.z;
    if (lengthSq <= 1.0e-6f) {
      return Wm3::Quatf{0.0f, 0.0f, 0.0f, 0.0f};
    }

    const float inverseLength = 1.0f / std::sqrt(lengthSq);
    blended.w *= inverseLength;
    blended.x *= inverseLength;
    blended.y *= inverseLength;
    blended.z *= inverseLength;
    return blended;
  }

  [[nodiscard]] moho::EAlliance
  ResolveSelectionAlliance(const moho::UserArmy* const viewingArmy, const moho::UserArmy* const targetArmy) noexcept
  {
    if (!viewingArmy || !targetArmy) {
      return moho::ALLIANCE_Neutral;
    }

    if (viewingArmy->mArmyIndex == targetArmy->mArmyIndex) {
      return moho::ALLIANCE_Ally;
    }

    const std::uint32_t targetArmyIndex = targetArmy->mArmyIndex;
    if (viewingArmy->mVarDat.mNeutrals.Contains(targetArmyIndex)) {
      return moho::ALLIANCE_Neutral;
    }

    if (viewingArmy->mVarDat.mAllies.Contains(targetArmyIndex)) {
      return moho::ALLIANCE_Ally;
    }

    if (viewingArmy->mVarDat.mEnemies.Contains(targetArmyIndex)) {
      return moho::ALLIANCE_Enemy;
    }

    return moho::ALLIANCE_Neutral;
  }

  constexpr std::uint32_t kSelectionBracketEnemyVisibleMask = 0x10u;
  constexpr const char* kSelectionBracketNeutralTexture = "/textures/ui/common/game/selection/selection_brackets_neutral.dds";
  constexpr const char* kSelectionBracketEnemyTexture = "/textures/ui/common/game/selection/selection_brackets_enemy.dds";
  constexpr const char* kSelectionBracketAlliedTexture =
    "/textures/ui/common/game/selection/selection_brackets_player_highlighted.dds";
} // namespace

namespace moho
{
  /**
   * Address: 0x008B85E0 (FUN_008B85E0, ??0UserEntity@Moho@@QAE@AAVCWldSession@1@ABUSCreateEntityParams@1@@Z)
   */
  UserEntity::UserEntity(CWldSession& session, const SCreateEntityParams& createParams)
    : mWeakObjectRuntimeHead(nullptr)
    , mIUnitChainHead(nullptr)
    , mSession(&session)
    , mSpatialDbEntry{nullptr, 0}
    , mAuxRuntimeHandle(nullptr)
    , mPosePrimary()
    , mPoseSecondary()
    , mMeshInstance(nullptr)
    , mRuntimeLinkHead(nullptr)
    , mRuntimeSelectionToken(-1)
    , mCachedAmbientSound(nullptr)
    , mRumbleSoundBinding(nullptr)
    , mLastFocusDamageGameTick(-1000)
    , mParams(createParams)
    , mVariableData()
    , pad_00FC_0120{}
    , mArmy(nullptr)
    , mTransform()
    , mLastInterpAmt(-1.0f)
    , mHasInitialUpdate(0)
    , mHasRuntimePose(0)
    , pad_0146_0147{0, 0}
  {
    mTransform.orient_.w = 1.0f;
    mTransform.orient_.x = 0.0f;
    mTransform.orient_.y = 0.0f;
    mTransform.orient_.z = 0.0f;
    mTransform.pos_.x = 0.0f;
    mTransform.pos_.y = 0.0f;
    mTransform.pos_.z = 0.0f;

    const std::uint8_t sourceIndex = moho::ExtractEntityIdSourceIndex(mParams.mEntityId);
    if (sourceIndex != moho::kEntityIdSourceIndexInvalid) {
      UserArmy* const* const userArmyList = mSession->userArmies.data();
      if (userArmyList) {
        mArmy = userArmyList[sourceIndex];
      }
    }

    const std::int32_t spatialDbMask = BuildSpatialDbRoutingMaskFromEntityId(mParams.mEntityId, sourceIndex);
    InitializeSpatialDbEntry(mSpatialDbEntry, mSession->GetEntitySpatialDbStorage(), this, spatialDbMask);

    mRumbleSoundBinding = &gNullRumbleSoundBinding;
  }

  /**
   * Address: 0x008B87A0 (FUN_008B87A0, ??1UserEntity@Moho@@UAE@XZ)
   */
  UserEntity::~UserEntity()
  {
    DestroyMeshInstance();
    // Member teardown invokes SSTIEntityVariableData::~SSTIEntityVariableData
    // (0x00560310) during standard C++ member destruction.

    // Matches the two intrusive-list teardown loops at +0x30 and +0x08.
    ResetLinkChain(mRuntimeLinkHead);

    if (mAuxRuntimeHandle) {
      mAuxRuntimeHandle->Release(1);
      mAuxRuntimeHandle = nullptr;
    }

    DestroySpatialDbMeshInstanceStorage(mSpatialDbEntry);
    ResetLinkChain(mIUnitChainHead);
  }

  /**
   * Address: 0x008B8760 (FUN_008B8760, scalar deleting destructor thunk)
   *
   * What it does:
   * Calls `UserEntity::~UserEntity` and conditionally invokes `operator delete`
   * when the low bit of `flags` is set.
   */
  [[maybe_unused]] UserEntity* UserEntityDeletingDestructorThunk(UserEntity* self, const std::uint8_t flags)
  {
    self->~UserEntity();
    if ((flags & 0x01u) != 0u) {
      ::operator delete(self);
    }
    return self;
  }

  /**
   * Address: 0x008B8CD0 (FUN_008B8CD0, ?Tick@UserEntity@Moho@@UAEXVCSeqNo@2@@Z)
   */
  void UserEntity::Tick(const std::int32_t /*seqNo*/) {}

  /**
   * Address: 0x008B84D0 (FUN_008B84D0, ?IsUserUnit@UserEntity@Moho@@UBEPBVUserUnit@2@XZ)
   */
  const UserUnit* UserEntity::IsUserUnit() const
  {
    return nullptr;
  }

  /**
   * Address: 0x008B84C0 (FUN_008B84C0, ?IsUserUnit@UserEntity@Moho@@UAEPAVUserUnit@2@XZ)
   */
  UserUnit* UserEntity::IsUserUnit()
  {
    return nullptr;
  }

  /**
   * Address: 0x008B84E0 (FUN_008B84E0, ?GetUniformScale@UserEntity@Moho@@UBEMXZ)
   */
  float UserEntity::GetUniformScale() const
  {
    return 1.0f;
  }

  /**
   * Address: 0x008B8510 (FUN_008B8510, ?GetCommandQueue@UserEntity@Moho@@UBEPBVUserCommandQueue@2@XZ)
   */
  const UserCommandQueue* UserEntity::GetCommandQueue() const
  {
    return nullptr;
  }

  /**
   * Address: 0x008B84F0 (FUN_008B84F0, ?GetCommandQueue@UserEntity@Moho@@UAEPAVUserCommandQueue@2@XZ)
   */
  UserCommandQueue* UserEntity::GetCommandQueue()
  {
    return nullptr;
  }

  /**
   * Address: 0x008B8520 (FUN_008B8520, ?GetFactoryCommandQueue@UserEntity@Moho@@UBEPBVUserCommandQueue@2@XZ)
   */
  const UserCommandQueue* UserEntity::GetFactoryCommandQueue() const
  {
    return nullptr;
  }

  /**
   * Address: 0x008B8500 (FUN_008B8500, ?GetFactoryCommandQueue@UserEntity@Moho@@UAEPAVUserCommandQueue@2@XZ)
   */
  UserCommandQueue* UserEntity::GetFactoryCommandQueue()
  {
    return nullptr;
  }

  /**
   * Address: 0x008B8CF0 (FUN_008B8CF0, ?GetInterpolatedTransform@UserEntity@Moho@@QBE?AVVTransform@2@M@Z)
   *
   * What it does:
   * Updates the cached transform when interpolation input changes by blending
   * current/last replicated transforms, then returns cached transform by value.
   */
  VTransform UserEntity::GetInterpolatedTransform(const float interpolationAlpha) const
  {
    if (interpolationAlpha != mLastInterpAmt) {
      const float clampedAlpha = ClampUnitInterval(mVariableData.mCurImpactValue * interpolationAlpha);
      UserEntity* const mutableThis = const_cast<UserEntity*>(this);

      const VTransform& previous = mVariableData.mLastTransform;
      const VTransform& current = mVariableData.mCurTransform;
      mutableThis->mTransform.pos_.x = previous.pos_.x + (current.pos_.x - previous.pos_.x) * clampedAlpha;
      mutableThis->mTransform.pos_.y = previous.pos_.y + (current.pos_.y - previous.pos_.y) * clampedAlpha;
      mutableThis->mTransform.pos_.z = previous.pos_.z + (current.pos_.z - previous.pos_.z) * clampedAlpha;
      mutableThis->mTransform.orient_ =
        LerpQuaternionShortestPathNormalized(current.orient_, previous.orient_, clampedAlpha);
      mutableThis->mLastInterpAmt = clampedAlpha;
    }

    return mTransform;
  }

  /**
   * Address: 0x008B8530 (FUN_008B8530, ?RequiresUIRefresh@UserEntity@Moho@@UBE_NXZ)
   */
  bool UserEntity::RequiresUIRefresh() const
  {
    return mVariableData.mRequestRefreshUI != 0;
  }

  /**
   * Address: 0x008B8540 (FUN_008B8540, ?IsSelectable@UserEntity@Moho@@UBE_NXZ)
   */
  bool UserEntity::IsSelectable() const
  {
    const msvc8::string selectableCategory("SELECTABLE", 10u);
    return IsInCategory(selectableCategory);
  }

  /**
   * Address: 0x008B85C0 (FUN_008B85C0, ?IsBeingBuilt@UserEntity@Moho@@UBE_NXZ)
   */
  bool UserEntity::IsBeingBuilt() const
  {
    return mVariableData.mIsBeingBuilt != 0;
  }

  /**
   * Address: 0x008B85D0 (FUN_008B85D0, ?NotifyFocusArmyUnitDamaged@UserEntity@Moho@@UAEXXZ)
   */
  void UserEntity::NotifyFocusArmyUnitDamaged() {}

  /**
   * Address: 0x008B88D0 (FUN_008B88D0, ?CreateMeshInstance@UserEntity@Moho@@MAEX_N@Z)
   *
   * What it does:
   * Builds mesh instance from current mesh blueprint/scale and, for unit-pose
   * paths, creates primary/secondary CAniPose instances from the mesh skeleton.
   */
  void UserEntity::CreateMeshInstance(const bool forUnitPose)
  {
    mMeshInstance = MeshRenderer::GetInstance()->CreateMeshInstance(
      mSession->mGameTick,
      -1,
      static_cast<const RMeshBlueprint*>(mVariableData.mMeshBlueprint),
      mVariableData.mScale,
      forUnitPose,
      boost::shared_ptr<MeshMaterial>{}
    );

    if (mMeshInstance) {
      mMeshInstance->isReflected = 0;
    }

    if (!forUnitPose) {
      return;
    }

    const boost::shared_ptr<Mesh> mesh = mMeshInstance->GetMesh();
    const boost::shared_ptr<RScmResource> resource = mesh->GetResource(0);
    const boost::shared_ptr<const CAniSkel> skeleton = resource->GetSkeleton();

    auto* const primaryPose = new CAniPose(skeleton, mVariableData.mCurImpactValue);
    CreateCAniPoseSharedPtr(primaryPose, mPosePrimary);

    auto* const secondaryPose = new CAniPose(skeleton, mVariableData.mCurImpactValue);
    CreateCAniPoseSharedPtr(secondaryPose, mPoseSecondary);
  }

  /**
   * Address: 0x008B8B10 (FUN_008B8B10, ?DestroyMeshInstance@UserEntity@Moho@@MAEXXZ)
   */
  void UserEntity::DestroyMeshInstance()
  {
    if (mMeshInstance) {
      mMeshInstance->Release(1);
    }

    mMeshInstance = nullptr;
    mPosePrimary.reset();
    mPoseSecondary.reset();
  }

  /**
   * Address: 0x007FD3F0 (FUN_007FD3F0, Moho::UserEntity::GetSelectionBracketTexture)
   *
   * What it does:
   * Selects one selection-bracket texture from alliance relation, and suppresses
   * enemy brackets when the user-unit intel-state visibility bit is clear.
   */
  boost::shared_ptr<CD3DBatchTexture> UserEntity::GetSelectionBracketTexture(const UserArmy* const viewingArmy) const
  {
    const EAlliance alliance = ResolveSelectionAlliance(viewingArmy, mArmy);

    if (alliance == ALLIANCE_Ally) {
      return CD3DBatchTexture::FromFile(kSelectionBracketAlliedTexture, 1u);
    }

    if (alliance == ALLIANCE_Enemy) {
      const UserUnit* const userUnit = IsUserUnit();
      if (userUnit == nullptr || (userUnit->mIntelStateFlags & kSelectionBracketEnemyVisibleMask) != 0u) {
        return CD3DBatchTexture::FromFile(kSelectionBracketEnemyTexture, 1u);
      }

      return {};
    }

    return CD3DBatchTexture::FromFile(kSelectionBracketNeutralTexture, 1u);
  }

  /**
   * Address: 0x008B9580 (FUN_008B9580, ?UpdateVisibility@UserEntity@Moho@@UAEXXZ)
   */
  void UserEntity::UpdateVisibility()
  {
    auto* const meshInstance = mMeshInstance;
    if (!meshInstance) {
      return;
    }

    switch (mVariableData.mVisibilityMode) {
    case EUserEntityVisibilityMode::Hidden:
      meshInstance->isHidden = 1;
      return;

    case EUserEntityVisibilityMode::MapPlayableRect: {
      const auto cellX = static_cast<std::int32_t>(mVariableData.mCurTransform.pos_.x);
      const auto cellZ = static_cast<std::int32_t>(mVariableData.mCurTransform.pos_.z);
      VisibilityRect visibleRect{};
      mSession->TryGetPlayableMapRect(visibleRect);
      meshInstance->isHidden = ContainsCell(visibleRect, cellX, cellZ) ? 0 : 1;
      return;
    }

    case EUserEntityVisibilityMode::ReconGrid: {
      const UserArmy* const focusArmy = mSession->GetFocusUserArmy();
      if (!focusArmy) {
        meshInstance->isHidden = 0;
        return;
      }

      const UserArmy::EReconGridMask gridMask =
        mVariableData.UsesUnderwaterReconGrid() ? UserArmy::EReconGridMask::Fog : UserArmy::EReconGridMask::Explored;
      const bool canSee = focusArmy->CanSeePoint(mVariableData.mCurTransform.pos_, gridMask);
      meshInstance->isHidden = canSee ? 0 : 1;
      return;
    }

    default:
      return;
    }
  }

  /**
   * Address: 0x008B97C0 (FUN_008B97C0,
   * ?IsInCategory@UserEntity@Moho@@QBE_NABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
   */
  bool UserEntity::IsInCategory(const msvc8::string& category) const
  {
    if (!mSession || !mParams.mBlueprint) {
      return false;
    }

    const EntityCategoryLookupResolver* const resolver = mSession->GetCategoryLookupResolver();
    if (!resolver) {
      return false;
    }

    const char* const categoryName = category.raw_data_unsafe();
    const CategoryWordRangeView* const range = resolver->GetEntityCategory(categoryName);
    if (!range) {
      return false;
    }

    const std::uint32_t categoryBitIndex = mParams.mBlueprint->mCategoryBitIndex;
    const auto wordIt = range->FindWord(categoryBitIndex >> 5u);
    if (wordIt == range->cend()) {
      return false;
    }

    const std::uint32_t categoryBits = *wordIt;
    return ((categoryBits >> (categoryBitIndex & 0x1Fu)) & 1u) != 0u;
  }
} // namespace moho
