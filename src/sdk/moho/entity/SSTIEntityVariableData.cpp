#include "moho/entity/SSTIEntityVariableData.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/entity/EntityId.h"

namespace
{
  constexpr std::uint32_t kAttachmentParentSentinel = moho::ToRaw(moho::EEntityIdSentinel::Invalid);
  constexpr moho::EUserEntityVisibilityMode kDefaultVisibilityMode = moho::EUserEntityVisibilityMode::MapPlayableRect;
} // namespace

namespace moho
{
  gpg::RType* SSTIEntityVariableData::sType = nullptr;

  void SSTIInlineUIntVector::ResetToInlineStorage() noexcept
  {
    mInlineBegin = &mInlineStorage0;
    mBegin = mInlineBegin;
    mEnd = mInlineBegin;
    mCapacityEnd = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(mInlineStorage0));
  }

  void SSTIInlineUIntVector::ReleaseDynamicStorage() noexcept
  {
    if (mBegin != mInlineBegin) {
      delete[] mBegin;
      mBegin = mInlineBegin;
      mCapacityEnd = reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(mInlineStorage0));
    }
    mEnd = mBegin;
  }

  void SSTIInlineUIntVector::AssignFrom(const SSTIInlineUIntVector& rhs)
  {
    if (this == &rhs) {
      return;
    }

    const std::size_t srcCount = rhs.Size();
    if (Capacity() < srcCount) {
      std::uint32_t* const newStorage = new std::uint32_t[srcCount];
      if (mBegin == mInlineBegin) {
        mInlineStorage0 = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(mCapacityEnd));
      } else {
        delete[] mBegin;
      }
      mBegin = newStorage;
      mCapacityEnd = newStorage + srcCount;
    }

    if (srcCount != 0u) {
      std::memcpy(mBegin, rhs.mBegin, srcCount * sizeof(std::uint32_t));
    }
    mEnd = mBegin + srcCount;
  }

  std::size_t SSTIInlineUIntVector::Size() const noexcept
  {
    if (!mBegin || !mEnd || mEnd < mBegin) {
      return 0u;
    }
    return static_cast<std::size_t>(mEnd - mBegin);
  }

  std::size_t SSTIInlineUIntVector::Capacity() const noexcept
  {
    if (!mBegin || !mCapacityEnd || mCapacityEnd < mBegin) {
      return 0u;
    }
    return static_cast<std::size_t>(mCapacityEnd - mBegin);
  }

  /**
   * Address: 0x00558760 (FUN_00558760, ??0SSTIEntityVariableData@Moho@@QAE@XZ)
   */
  SSTIEntityVariableData::SSTIEntityVariableData()
    : mScmResource()
    , mMeshBlueprint(nullptr)
    , mScale{1.0f, 1.0f, 1.0f}
    , mHealth(0.0f)
    , mMaxHealth(0.0f)
    , mIsBeingBuilt(0)
    , mIsDead(0)
    , mRequestRefreshUI(0)
    , pad_0023(0)
    , mCurTransform()
    , mLastTransform()
    , mCurImpactValue(1.0f)
    , mFractionComplete(1.0f)
    , mAttachmentParentRef(kAttachmentParentSentinel)
    , mAuxValueVector()
    , mScroll0U(0.0f)
    , mScroll0V(0.0f)
    , mScroll1U(0.0f)
    , mScroll1V(0.0f)
    , mAmbientSound(nullptr)
    , mRumbleSound(nullptr)
    , mVisibilityHidden(0)
    , pad_0099_009B{0, 0, 0}
    , mVisibilityMode(kDefaultVisibilityMode)
    , mLayerMask(0)
    , mUsingAltFootprint(0)
    , pad_00A5_00A7{0, 0, 0}
    , mUnderlayTexture()
    , mIntelAttributes{0, 0, 0, 0, 0, 0, 0, 0}
  {
    mAuxValueVector.mInlineStorage0 =
      static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&mAuxValueVector.mInlineStorage1));
    mAuxValueVector.ResetToInlineStorage();
  }

  /**
   * Address: 0x00560310 (FUN_00560310, ??1SSTIEntityVariableData@Moho@@QAE@XZ)
   */
  SSTIEntityVariableData::~SSTIEntityVariableData()
  {
    mUnderlayTexture.reset();
    mAuxValueVector.ReleaseDynamicStorage();
    mScmResource.reset();
  }

  /**
   * Address: 0x0067A3E0 (FUN_0067A3E0, ??4SSTIEntityVariableData@Moho@@QAEAAU01@ABU01@@Z)
   */
  SSTIEntityVariableData& SSTIEntityVariableData::operator=(const SSTIEntityVariableData& rhs)
  {
    if (this == &rhs) {
      return *this;
    }

    mScmResource = rhs.mScmResource;
    mMeshBlueprint = rhs.mMeshBlueprint;
    mScale = rhs.mScale;
    mHealth = rhs.mHealth;
    mMaxHealth = rhs.mMaxHealth;
    mIsBeingBuilt = rhs.mIsBeingBuilt;
    mIsDead = rhs.mIsDead;
    mRequestRefreshUI = rhs.mRequestRefreshUI;
    mCurTransform = rhs.mCurTransform;
    mLastTransform = rhs.mLastTransform;
    mCurImpactValue = rhs.mCurImpactValue;
    mFractionComplete = rhs.mFractionComplete;
    mAttachmentParentRef = rhs.mAttachmentParentRef;
    mAuxValueVector.AssignFrom(rhs.mAuxValueVector);
    mScroll0U = rhs.mScroll0U;
    mScroll0V = rhs.mScroll0V;
    mScroll1U = rhs.mScroll1U;
    mScroll1V = rhs.mScroll1V;
    mAmbientSound = rhs.mAmbientSound;
    mRumbleSound = rhs.mRumbleSound;
    mVisibilityHidden = rhs.mVisibilityHidden;
    mVisibilityMode = rhs.mVisibilityMode;
    mLayerMask = rhs.mLayerMask;
    mUsingAltFootprint = rhs.mUsingAltFootprint;
    mUnderlayTexture = rhs.mUnderlayTexture;
    mIntelAttributes = rhs.mIntelAttributes;
    return *this;
  }

  std::uint32_t SSTIEntityVariableData::GetVisibilityGridMask() const noexcept
  {
    return mLayerMask;
  }

  void SSTIEntityVariableData::SetVisibilityGridMask(const std::uint32_t gridMask) noexcept
  {
    mLayerMask = gridMask;
  }

  bool SSTIEntityVariableData::UsesUnderwaterReconGrid() const noexcept
  {
    return (mLayerMask & kUserEntityUnderwaterLayerMaskBits) != 0u;
  }

  /**
   * Address: 0x00558E40 (FUN_00558E40, sub_558E40)
   */
  void SSTIEntityVariableDataSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* type = SSTIEntityVariableData::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(SSTIEntityVariableData));
      SSTIEntityVariableData::sType = type;
    }

    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }

  /**
   * Address: 0x005586B0 (FUN_005586B0, sub_5586B0)
   */
  SSTIEntityVariableDataTypeInfo::~SSTIEntityVariableDataTypeInfo() = default;

  /**
   * Address: 0x005586A0 (FUN_005586A0, Moho::SSTIEntityVariableDataTypeInfo::GetName)
   */
  const char* SSTIEntityVariableDataTypeInfo::GetName() const
  {
    return "SSTIEntityVariableData";
  }

  /**
   * Address: 0x00558680 (FUN_00558680, Moho::SSTIEntityVariableDataTypeInfo::Init)
   */
  void SSTIEntityVariableDataTypeInfo::Init()
  {
    size_ = sizeof(SSTIEntityVariableData);
    gpg::RType::Init();
    version_ = 2;
    Finish();
  }
} // namespace moho
