#include "moho/entity/UserEntity.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <typeinfo>

#include "moho/animation/CAniPose.h"
#include "moho/animation/CAniSkel.h"
#include "moho/audio/CSndParams.h"
#include "moho/console/CVarAccess.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/entity/EntityId.h"
#include "moho/entity/REntityBlueprint.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/math/MathReflection.h"
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
  constexpr std::uint32_t kIntelRangeMagnitudeMask = 0x7FFFFFFFu;
  constexpr std::uint32_t kIntelEnabledBit = 0x80000000u;

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

  /**
   * Address: 0x008C6520 (FUN_008C6520)
   *
   * What it does:
   * Lazily resolves and caches one reflection type lane for `moho::UserEntity`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* ResolveUserEntityTypeCacheLane()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(moho::UserEntity));
    }
    return cached;
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

  /**
   * Address: 0x0089E520 (FUN_0089E520)
   *
   * What it does:
   * Register-shape adapter that forwards one spatial DB entry construction
   * request into the canonical `InitializeSpatialDbEntry` helper and returns
   * the destination entry pointer.
   */
  [[maybe_unused]] moho::UserEntitySpatialDbEntry* InitializeSpatialDbEntryAdapterLane(
    moho::UserEntitySpatialDbEntry* const destinationEntry,
    void* const sessionSpatialDbStorage,
    void* const owner,
    const std::int32_t spatialDbMask
  )
  {
    InitializeSpatialDbEntry(*destinationEntry, sessionSpatialDbStorage, owner, spatialDbMask);
    return destinationEntry;
  }

  // 0x00416F60
  [[nodiscard]] bool ContainsCell(const moho::VisibilityRect& rect, const std::int32_t x, const std::int32_t z)
  {
    return x >= rect.minX && x < rect.maxX && z >= rect.minZ && z < rect.maxZ;
  }

  /**
   * Address: 0x0063CA40 (FUN_0063CA40, boost::shared_ptr<Moho::CAniPose> helper)
   *
   * What it does:
   * Rebinds one `boost::shared_ptr<CAniPose>` to the supplied pose pointer.
   */
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

  [[nodiscard]] bool IsFinite(const float value) noexcept
  {
    return std::isfinite(value);
  }

  [[nodiscard]] bool HasFiniteMeshBounds(const moho::MeshInstance& mesh) noexcept
  {
    return IsFinite(mesh.xMin) && IsFinite(mesh.yMin) && IsFinite(mesh.zMin) && IsFinite(mesh.xMax) &&
      IsFinite(mesh.yMax) && IsFinite(mesh.zMax);
  }

  void CopyPoseState(moho::CAniPose& dst, const moho::CAniPose& src)
  {
    dst.mScale = src.mScale;
    dst.mLocalTransform = src.mLocalTransform;
    dst.mMaxOffset = src.mMaxOffset;

    const moho::CAniPoseBone* const srcBegin = src.mBones.begin();
    const moho::CAniPoseBone* const srcEnd = src.mBones.end();
    moho::CAniPoseBone* const dstBegin = dst.mBones.begin();
    moho::CAniPoseBone* const dstEnd = dst.mBones.end();
    if (!srcBegin || !srcEnd || !dstBegin || !dstEnd) {
      return;
    }

    const std::ptrdiff_t srcCount = srcEnd - srcBegin;
    const std::ptrdiff_t dstCount = dstEnd - dstBegin;
    if (srcCount <= 0 || dstCount <= 0) {
      return;
    }

    const std::ptrdiff_t copyCount = std::min(srcCount, dstCount);
    for (std::ptrdiff_t i = 0; i < copyCount; ++i) {
      moho::CAniPoseBone& dstBone = dstBegin[i];
      const moho::CAniPoseBone& srcBone = srcBegin[i];
      dstBone.mVisible = srcBone.mVisible;
      dstBone.mSkipNextInterp = srcBone.mSkipNextInterp;
      dstBone.mLocalTransform = srcBone.mLocalTransform;
      dstBone.mCompositeIsLocal = srcBone.mCompositeIsLocal;
      dstBone.mCompositeDirty = 1u;
    }
  }

  [[nodiscard]] bool TryRestorePose(
    const boost::shared_ptr<moho::CAniPose>& destination,
    const boost::shared_ptr<moho::CAniPose>& source
  )
  {
    if (!destination || !source) {
      return false;
    }

    const boost::shared_ptr<const moho::CAniSkel> dstSkeleton = destination->GetSkeleton();
    const boost::shared_ptr<const moho::CAniSkel> srcSkeleton = source->GetSkeleton();
    if (!dstSkeleton || !srcSkeleton || dstSkeleton.get() != srcSkeleton.get()) {
      return false;
    }

    CopyPoseState(*destination, *source);
    return true;
  }

  [[nodiscard]] std::uint32_t GetVisionRange(const moho::SSTIEntityVariableData& variableData) noexcept
  {
    return variableData.mIntelAttributes.vision & kIntelRangeMagnitudeMask;
  }

  [[nodiscard]] bool IsVisionEnabled(const moho::SSTIEntityVariableData& variableData) noexcept
  {
    return (variableData.mIntelAttributes.vision & kIntelEnabledBit) != 0u;
  }

  struct SessionVisionRuntimeView
  {
    std::uint8_t pad_0000_03C8[0x3C8];
    moho::VisionDB visionDb; // +0x3C8
  };
  static_assert(
    offsetof(SessionVisionRuntimeView, visionDb) == 0x3C8,
    "SessionVisionRuntimeView::visionDb offset must be 0x3C8"
  );

  struct SessionEntityMapNodeRuntimeView
  {
    SessionEntityMapNodeRuntimeView* mLeft;   // +0x00
    SessionEntityMapNodeRuntimeView* mParent; // +0x04
    SessionEntityMapNodeRuntimeView* mRight;  // +0x08
    std::uint32_t mEntityId;                  // +0x0C
    moho::UserEntity* mEntity;                // +0x10
    std::uint8_t pad_14_17[0x04];
    std::uint8_t mColor;      // +0x18
    std::uint8_t mIsSentinel; // +0x19
    std::uint8_t pad_1A[0x02];
  };

  static_assert(sizeof(SessionEntityMapNodeRuntimeView) == 0x1C, "SessionEntityMapNodeRuntimeView size must be 0x1C");
  static_assert(
    offsetof(SessionEntityMapNodeRuntimeView, mEntityId) == 0x0C,
    "SessionEntityMapNodeRuntimeView::mEntityId offset must be 0x0C"
  );
  static_assert(
    offsetof(SessionEntityMapNodeRuntimeView, mEntity) == 0x10,
    "SessionEntityMapNodeRuntimeView::mEntity offset must be 0x10"
  );

  struct SessionEntityMapRuntimeView
  {
    void* mAllocProxy;                      // +0x00
    SessionEntityMapNodeRuntimeView* mHead; // +0x04
    std::uint32_t mSize;                    // +0x08
  };

  static_assert(sizeof(SessionEntityMapRuntimeView) == 0x0C, "SessionEntityMapRuntimeView size must be 0x0C");
  static_assert(
    offsetof(SessionEntityMapRuntimeView, mHead) == 0x04,
    "SessionEntityMapRuntimeView::mHead offset must be 0x04"
  );

  [[nodiscard]] SessionEntityMapRuntimeView* GetSessionEntityMapRuntimeView(moho::CWldSession* const session) noexcept
  {
    static_assert(offsetof(moho::CWldSession, mUnknownOwner44) == 0x44, "CWldSession::mUnknownOwner44 offset must be 0x44");
    return reinterpret_cast<SessionEntityMapRuntimeView*>(&session->mUnknownOwner44);
  }

  [[nodiscard]] SessionEntityMapNodeRuntimeView*
  FindSessionEntityMapNodeById(SessionEntityMapRuntimeView& map, const std::uint32_t entityId) noexcept
  {
    SessionEntityMapNodeRuntimeView* const head = map.mHead;
    if (head == nullptr) {
      return nullptr;
    }

    SessionEntityMapNodeRuntimeView* node = head->mParent;
    while (node != nullptr && node != head) {
      if (entityId < node->mEntityId) {
        node = node->mLeft;
        continue;
      }
      if (node->mEntityId < entityId) {
        node = node->mRight;
        continue;
      }
      return node;
    }

    return nullptr;
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
    , mVisionHandle(nullptr)
    , mPosePrimary()
    , mPoseSecondary()
    , mMeshInstance(nullptr)
    , mRuntimeLinkHead(nullptr)
    , mRuntimeSelectionToken(-1)
    , mCachedAmbientSound(nullptr)
    , mRumbleLoopHandle(nullptr)
    , mLastFocusDamageGameTick(-1000)
    , mParams(createParams)
    , mVariableData()
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

    mRumbleLoopHandle = SND_GetSharedAmbientHandle(nullptr);
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

    if (mVisionHandle) {
      delete mVisionHandle;
      mVisionHandle = nullptr;
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
   * Address: 0x008B8EB0 (FUN_008B8EB0, ?UpdateEntityData@UserEntity@Moho@@UAEXABUSSTIEntityVariableData@2@@Z)
   *
   * What it does:
   * Applies one replicated variable-data snapshot, refreshes mesh/pose and
   * spatial-db state, then updates fog-of-war vision handle tracking.
   */
  void UserEntity::UpdateEntityData(const SSTIEntityVariableData& variableData)
  {
    const bool requiresMeshRebuild =
      (mMeshInstance == nullptr && variableData.mMeshBlueprint != nullptr) ||
      (variableData.mMeshBlueprint != mVariableData.mMeshBlueprint) ||
      (variableData.mScmResource.get() != mVariableData.mScmResource.get());

    const bool scaleChanged = mMeshInstance != nullptr && mMeshInstance->isStaticPose == 0u &&
      Wm3::Vector3f::Compare(&mMeshInstance->scale, &variableData.mScale);

    const bool transformChanged = Wm3::Vector3f::Compare(&variableData.mCurTransform.pos_, &mVariableData.mCurTransform.pos_) ||
      !AreQuaternionsNearlyEqual(mVariableData.mCurTransform.orient_, variableData.mCurTransform.orient_) ||
      Wm3::Vector3f::Compare(&variableData.mLastTransform.pos_, &mVariableData.mLastTransform.pos_) ||
      !AreQuaternionsNearlyEqual(mVariableData.mLastTransform.orient_, variableData.mLastTransform.orient_) ||
      !NearlyEqual(variableData.mCurImpactValue, mVariableData.mCurImpactValue);

    if (IsUserUnit() != nullptr && mVariableData.mHealth > variableData.mHealth) {
      if (mArmy != nullptr && mSession != nullptr && mArmy == mSession->GetFocusUserArmy()) {
        mLastFocusDamageGameTick = mSession->mGameTick;
        NotifyFocusArmyUnitDamaged();
      }
    }

    const EUserEntityVisibilityMode previousVisibility = mVariableData.mVisibilityMode;
    const EUserEntityVisibilityMode nextVisibility = variableData.mVisibilityMode;
    if (mSession != nullptr && previousVisibility != nextVisibility) {
      if (nextVisibility == EUserEntityVisibilityMode::ReconGrid) {
        mSession->AddToVizUpdate(this);
      } else if (previousVisibility == EUserEntityVisibilityMode::ReconGrid) {
        mSession->RemoveFromVizUpdate(this);
      }
    }

    mVariableData = variableData;
    if (mVariableData.mAmbientSound != mCachedAmbientSound) {
      mCachedAmbientSound = mVariableData.mAmbientSound;
    }
    if (mRumbleLoopHandle == nullptr || mVariableData.mRumbleSound != mRumbleLoopHandle->mParams) {
      mRumbleLoopHandle = SND_GetSharedAmbientHandle(mVariableData.mRumbleSound);
    }

    bool restoredPrimaryPose = false;
    if (requiresMeshRebuild) {
      if (mMeshInstance != nullptr && variableData.mMeshBlueprint != nullptr) {
        const boost::shared_ptr<CAniPose> oldPrimaryPose = mPosePrimary;
        const boost::shared_ptr<CAniPose> oldSecondaryPose = mPoseSecondary;
        DestroyMeshInstance();

        if (variableData.mScmResource.get() != nullptr) {
          CreateMeshInstance(IsUserUnit() != nullptr);
          restoredPrimaryPose = TryRestorePose(mPosePrimary, oldPrimaryPose);
          (void)TryRestorePose(mPoseSecondary, oldSecondaryPose);
        }
      } else {
        DestroyMeshInstance();
        if (variableData.mMeshBlueprint != nullptr && variableData.mScmResource.get() != nullptr) {
          CreateMeshInstance(IsUserUnit() != nullptr);
        }
      }
    }

    const bool stanceOrSpatialUpdateNeeded = transformChanged || scaleChanged;
    if (mMeshInstance != nullptr) {
      if (scaleChanged) {
        mMeshInstance->scale = mVariableData.mScale;
      }

      mMeshInstance->scroll1.x = variableData.mScroll0U;
      mMeshInstance->scroll1.y = variableData.mScroll0V;
      mMeshInstance->scroll2.x = variableData.mScroll1U;
      mMeshInstance->scroll2.y = variableData.mScroll1V;

      if (mMeshInstance->isStaticPose != 0u) {
        mMeshInstance->SetStance(
          variableData.mCurTransform,
          variableData.mLastTransform,
          restoredPrimaryPose || stanceOrSpatialUpdateNeeded,
          mPosePrimary,
          mPoseSecondary
        );
      } else if (stanceOrSpatialUpdateNeeded) {
        mMeshInstance->SetStance(variableData.mCurTransform, variableData.mLastTransform);
      }
    }

    UpdateVisibility();

    if (stanceOrSpatialUpdateNeeded) {
      mLastInterpAmt = -1.0f;
      Wm3::AxisAlignedBox3f spatialBounds{};
      if (mMeshInstance != nullptr && HasFiniteMeshBounds(*mMeshInstance)) {
        spatialBounds.Min.x = mMeshInstance->xMin;
        spatialBounds.Min.y = mMeshInstance->yMin;
        spatialBounds.Min.z = mMeshInstance->zMin;
        spatialBounds.Max.x = mMeshInstance->xMax;
        spatialBounds.Max.y = mMeshInstance->yMax;
        spatialBounds.Max.z = mMeshInstance->zMax;
      } else {
        spatialBounds.Min = variableData.mCurTransform.pos_;
        spatialBounds.Max = variableData.mCurTransform.pos_;
      }
      reinterpret_cast<SpatialDB_MeshInstance*>(&mSpatialDbEntry)->UpdateBounds(spatialBounds);
    }

    if (mMeshInstance != nullptr) {
      mMeshInstance->fractionCompleteParameter = mVariableData.mFractionComplete;
      const float maxHealth = mVariableData.mMaxHealth;
      mMeshInstance->fractionHealthParameter = (maxHealth > 0.0f) ? (mVariableData.mHealth / maxHealth) : 1.0f;
    }

    if (!console::RenderFogOfWarEnabled() || mSession == nullptr) {
      return;
    }

    const std::uint32_t visionRange = GetVisionRange(mVariableData);
    if (visionRange != 0u && mVisionHandle == nullptr) {
      const Wm3::Vector2f zero(0.0f, 0.0f);
      auto* const sessionView = reinterpret_cast<SessionVisionRuntimeView*>(mSession);
      mVisionHandle = sessionView->visionDb.NewHandle(zero, zero);
    }

    if (mVisionHandle == nullptr || IsUserUnit() != nullptr) {
      return;
    }

    bool alliedVisibility = false;
    if (const UserArmy* const focusArmy = mSession->GetFocusUserArmy(); focusArmy != nullptr && mArmy != nullptr) {
      alliedVisibility = IsVisionEnabled(mVariableData) && focusArmy->IsAlly(mArmy->mArmyIndex);
    }

    const Wm3::Vector2f currentPosition(mVariableData.mCurTransform.pos_.x, mVariableData.mCurTransform.pos_.z);
    const Wm3::Vector2f previousPosition(mVariableData.mLastTransform.pos_.x, mVariableData.mLastTransform.pos_.z);
    mVisionHandle->Update(currentPosition, previousPosition, static_cast<float>(visionRange), alliedVisibility);
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
   * Address: 0x008B8E40 (FUN_008B8E40, UserEntity interpolated scroll lane)
   *
   * What it does:
   * Computes one interpolated `(u,v)` texture-scroll pair by blending the two
   * variable-data scroll lanes using clamped impact-weighted alpha.
   */
  UserEntity* UserEntity::GetInterpolatedScroll(
    float* const outScrollV,
    float* const outScrollU,
    const float interpolationAlpha
  )
  {
    const float clampedAlpha = ClampUnitInterval(mVariableData.mCurImpactValue * interpolationAlpha);

    if (outScrollU != nullptr) {
      *outScrollU = mVariableData.mScroll0U + ((mVariableData.mScroll1U - mVariableData.mScroll0U) * clampedAlpha);
    }

    if (outScrollV != nullptr) {
      *outScrollV = mVariableData.mScroll0V + ((mVariableData.mScroll1V - mVariableData.mScroll0V) * clampedAlpha);
    }

    return this;
  }

  /**
   * Address: 0x007EC2F0 (FUN_007EC2F0, ?GetInterpolatedPosition@UserEntity@Moho@@QBE?AV?$Vector3@M@Wm3@@M@Z)
   *
   * What it does:
   * Returns interpolated world-position lanes extracted from
   * `GetInterpolatedTransform(interpolationAlpha)`.
   */
  Wm3::Vec3f UserEntity::GetInterpolatedPosition(const float interpolationAlpha) const
  {
    const VTransform interpolated = GetInterpolatedTransform(interpolationAlpha);
    return interpolated.pos_;
  }

  /**
   * Address: 0x008B9740 (FUN_008B9740, ?GetRenderSphere@UserEntity@Moho@@QBE?AV?$Sphere3@M@Wm3@@M@Z)
   *
   * What it does:
   * Returns current render-oriented bounds from mesh interpolation state when
   * mesh data exists, otherwise synthesizes a transform-aligned half-unit box.
   */
  Wm3::Box3f UserEntity::GetRenderSphere(const float interpolationAlpha) const
  {
    if (mMeshInstance != nullptr) {
      mMeshInstance->UpdateInterpolatedFields();
      return mMeshInstance->box;
    }

    const VTransform interpolated = GetInterpolatedTransform(interpolationAlpha);
    const moho::VAxes3 axes(interpolated.orient_);
    return Wm3::Box3f(interpolated.pos_, axes.vX, axes.vY, axes.vZ, 0.5f, 0.5f, 0.5f);
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
   * Address: 0x008B8BB0 (FUN_008B8BB0, ?GetMeshInstance@UserEntity@Moho@@QBEPAVMeshInstance@2@XZ)
   *
   * What it does:
   * Returns the current mesh-instance pointer lane.
   */
  MeshInstance* UserEntity::GetMeshInstance() const
  {
    return mMeshInstance;
  }

  /**
   * Address: 0x008B8BC0 (FUN_008B8BC0, ?SetPose@UserEntity@Moho@@QAEXABV?$shared_ptr@VCAniPose@Moho@@@boost@@@Z)
   *
   * What it does:
   * Rebinds primary/secondary pose handles from one shared pose, upgrades
   * dynamic meshes to static-pose mode when required, then updates mesh stance
   * and spatial-db swept bounds.
   */
  void UserEntity::SetPose(const boost::shared_ptr<CAniPose>& pose)
  {
    if (mMeshInstance == nullptr) {
      return;
    }

    bool forceRefresh = false;
    if (mMeshInstance->isStaticPose == 0u) {
      DestroyMeshInstance();
      CreateMeshInstance(true);
      forceRefresh = true;
    }

    mPosePrimary = pose;
    mPoseSecondary = pose;

    mMeshInstance->SetStance(
      mVariableData.mCurTransform,
      mVariableData.mLastTransform,
      forceRefresh,
      mPosePrimary,
      mPoseSecondary
    );

    const Wm3::AxisAlignedBox3f sweptBounds = mMeshInstance->GetSweptAlignedBox();
    reinterpret_cast<SpatialDB_MeshInstance*>(&mSpatialDbEntry)->UpdateBounds(sweptBounds);
  }

  /**
   * Address: 0x00838030 (FUN_00838030, ?GetAttachmentParent@UserEntity@Moho@@QAEPAV12@XZ)
   * Mangled: ?GetAttachmentParent@UserEntity@Moho@@QAEPAV12@XZ
   *
   * What it does:
   * Resolves one attachment-parent entity id against the owning session
   * entity-map tree and returns the live parent entity pointer when present.
   */
  UserEntity* UserEntity::GetAttachmentParent()
  {
    if (mSession == nullptr) {
      return nullptr;
    }

    SessionEntityMapRuntimeView* const entityMap = GetSessionEntityMapRuntimeView(mSession);
    if (entityMap == nullptr || entityMap->mHead == nullptr) {
      return nullptr;
    }

    SessionEntityMapNodeRuntimeView* const node = FindSessionEntityMapNodeById(*entityMap, mVariableData.mAttachmentParentRef);
    return node != nullptr ? node->mEntity : nullptr;
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
   * Address: 0x0085B050 (FUN_0085B050, Moho::WeakPtr_CD3DBatchTexture::WeakPtr_CD3DBatchTexture)
   *
   * What it does:
   * Returns one retained shared owner lane for this entity's strategic-underlay
   * texture payload.
   */
  boost::shared_ptr<CD3DBatchTexture> UserEntity::GetStrategicUnderlayTexture() const
  {
    return boost::static_pointer_cast<CD3DBatchTexture>(mVariableData.mUnderlayTexture);
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
   * Address: 0x008B9670 (FUN_008B9670, ?OrphanUpdate@UserEntity@Moho@@QAEXXZ)
   *
   * What it does:
   * Deletes this orphan entity when focus-army visibility conditions are met.
   */
  void UserEntity::OrphanUpdate()
  {
    const std::int32_t focusArmyIndex = mSession->FocusArmy;
    UserArmy* focusArmy = nullptr;

    if (focusArmyIndex >= 0) {
      UserArmy* const* const userArmies = mSession->userArmies.data();
      if (userArmies != nullptr) {
        focusArmy = userArmies[focusArmyIndex];
      }
    }

    if (
      focusArmyIndex < 0 || focusArmy == nullptr ||
      (mVariableData.mLayerMask & kUserEntityUnderwaterLayerMaskBits) != 0u ||
      focusArmy->CanSeePoint(mVariableData.mCurTransform.pos_, UserArmy::EReconGridMask::Explored)
    ) {
      delete this;
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
