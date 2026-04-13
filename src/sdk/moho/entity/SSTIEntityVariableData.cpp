#include "moho/entity/SSTIEntityVariableData.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <typeinfo>

#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "moho/audio/CSndParams.h"
#include "moho/entity/EntityId.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/RScmResource.h"

namespace
{
  constexpr std::uint32_t kAttachmentParentSentinel = moho::ToRaw(moho::EEntityIdSentinel::Invalid);
  constexpr moho::EUserEntityVisibilityMode kDefaultVisibilityMode = moho::EUserEntityVisibilityMode::MapPlayableRect;

  [[nodiscard]] gpg::RType* ResolveTypeByAnyName(const std::initializer_list<const char*> names)
  {
    for (const char* const name : names) {
      if (!name) {
        continue;
      }

      if (gpg::RType* const type = gpg::REF_FindTypeNamed(name)) {
        return type;
      }
    }

    return nullptr;
  }

  [[nodiscard]] gpg::RType* ResolveRScmResourceType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = ResolveTypeByAnyName({"RScmResource", "Moho::RScmResource"});
      if (!sType) {
        sType = gpg::LookupRType(typeid(moho::RScmResource));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveRMeshBlueprintType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = ResolveTypeByAnyName({"RMeshBlueprint", "Moho::RMeshBlueprint"});
      if (!sType) {
        sType = gpg::LookupRType(typeid(moho::RMeshBlueprint));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveVector3fType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(Wm3::Vec3f));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveVTransformType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::VTransform));
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveEntIdType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = ResolveTypeByAnyName({"EntId", "Moho::EntId", "int", "signed int"});
      if (!sType) {
        sType = gpg::LookupRType(typeid(int));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveAttachInfoVectorType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = ResolveTypeByAnyName(
        {
          "fastvector<SSTIEntityAttachInfo>",
          "gpg::fastvector<Moho::SSTIEntityAttachInfo>",
          "gpg::fastvector<SSTIEntityAttachInfo>",
        }
      );
      if (!sType) {
        sType = gpg::LookupRType(typeid(moho::SSTIInlineUIntVector));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveCSndParamsType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = ResolveTypeByAnyName({"CSndParams", "Moho::CSndParams"});
      if (!sType) {
        sType = gpg::LookupRType(typeid(moho::CSndParams));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveVisibilityModeType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = ResolveTypeByAnyName({"EVisibilityMode", "Moho::EVisibilityMode"});
      if (!sType) {
        sType = gpg::LookupRType(typeid(int));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveLayerType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = ResolveTypeByAnyName({"ELayer", "Moho::ELayer"});
      if (!sType) {
        sType = gpg::LookupRType(typeid(int));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveEntityAttributesType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = ResolveTypeByAnyName({"EntityAttributes", "Moho::EntityAttributes"});
      if (!sType) {
        sType = gpg::LookupRType(typeid(moho::SSTIIntelAttributes));
      }
    }
    return sType;
  }

  template <typename TObject>
  [[nodiscard]] gpg::RRef MakeObjectRef(TObject* const object, gpg::RType* const type)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = type;
    return ref;
  }
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

  /**
   * Address: 0x00560150 (FUN_00560150, Moho::SSTIEntityVariableData::cpy)
   */
  SSTIEntityVariableData* SSTIEntityVariableData::cpy(SSTIEntityVariableData* const destination) const
  {
    if (destination == nullptr) {
      return nullptr;
    }

    if (destination == this) {
      return destination;
    }

    destination->mScmResource = mScmResource;
    destination->mMeshBlueprint = mMeshBlueprint;
    destination->mScale = mScale;
    destination->mHealth = mHealth;
    destination->mMaxHealth = mMaxHealth;
    destination->mIsBeingBuilt = mIsBeingBuilt;
    destination->mIsDead = mIsDead;
    destination->mRequestRefreshUI = mRequestRefreshUI;
    destination->mCurTransform = mCurTransform;
    destination->mLastTransform = mLastTransform;
    destination->mCurImpactValue = mCurImpactValue;
    destination->mFractionComplete = mFractionComplete;
    destination->mAttachmentParentRef = mAttachmentParentRef;
    destination->mAuxValueVector.AssignFrom(mAuxValueVector);
    destination->mScroll0U = mScroll0U;
    destination->mScroll0V = mScroll0V;
    destination->mScroll1U = mScroll1U;
    destination->mScroll1V = mScroll1V;
    destination->mAmbientSound = mAmbientSound;
    destination->mRumbleSound = mRumbleSound;
    destination->mVisibilityHidden = mVisibilityHidden;
    destination->mVisibilityMode = mVisibilityMode;
    destination->mLayerMask = mLayerMask;
    destination->mUsingAltFootprint = mUsingAltFootprint;
    destination->mUnderlayTexture = mUnderlayTexture;
    destination->mIntelAttributes = mIntelAttributes;
    return destination;
  }

  /**
   * Address: 0x00559E00 (FUN_00559E00, Moho::SSTIEntityVariableData::MemberSerialize)
   */
  void SSTIEntityVariableData::MemberSerialize(gpg::WriteArchive* const archive, const int version)
  {
    if (version < 2) {
      throw gpg::SerializationError("Unsupported version.");
    }

    const gpg::RRef ownerRef{};

    gpg::RType* const scmType = ResolveRScmResourceType();
    GPG_ASSERT(scmType != nullptr);
    gpg::WriteRawPointer(
      archive,
      MakeObjectRef(const_cast<RScmResource*>(mScmResource.get()), scmType),
      gpg::TrackedPointerState::Shared,
      ownerRef
    );

    gpg::RType* const meshType = ResolveRMeshBlueprintType();
    GPG_ASSERT(meshType != nullptr);
    gpg::WriteRawPointer(
      archive,
      MakeObjectRef(const_cast<RMeshBlueprint*>(mMeshBlueprint), meshType),
      gpg::TrackedPointerState::Unowned,
      ownerRef
    );

    gpg::RType* const vector3Type = ResolveVector3fType();
    GPG_ASSERT(vector3Type != nullptr);
    archive->Write(vector3Type, &mScale, ownerRef);
    archive->WriteFloat(mHealth);
    archive->WriteFloat(mMaxHealth);
    archive->WriteBool(mIsBeingBuilt != 0u);
    archive->WriteBool(mIsDead != 0u);
    archive->WriteBool(mRequestRefreshUI != 0u);

    gpg::RType* const transformType = ResolveVTransformType();
    GPG_ASSERT(transformType != nullptr);
    archive->Write(transformType, &mCurTransform, ownerRef);
    archive->Write(transformType, &mLastTransform, ownerRef);
    archive->WriteFloat(mCurImpactValue);
    archive->WriteFloat(mFractionComplete);

    gpg::RType* const entIdType = ResolveEntIdType();
    GPG_ASSERT(entIdType != nullptr);
    archive->Write(entIdType, &mAttachmentParentRef, ownerRef);

    gpg::RType* const attachInfoType = ResolveAttachInfoVectorType();
    GPG_ASSERT(attachInfoType != nullptr);
    archive->Write(attachInfoType, &mAuxValueVector, ownerRef);

    archive->WriteFloat(mScroll0U);
    archive->WriteFloat(mScroll0V);
    archive->WriteFloat(mScroll1U);
    archive->WriteFloat(mScroll1V);

    gpg::RType* const soundType = ResolveCSndParamsType();
    GPG_ASSERT(soundType != nullptr);
    gpg::WriteRawPointer(
      archive,
      MakeObjectRef(mAmbientSound, soundType),
      gpg::TrackedPointerState::Unowned,
      ownerRef
    );
    gpg::WriteRawPointer(
      archive,
      MakeObjectRef(mRumbleSound, soundType),
      gpg::TrackedPointerState::Unowned,
      ownerRef
    );

    archive->WriteBool(mVisibilityHidden != 0u);

    gpg::RType* const visibilityModeType = ResolveVisibilityModeType();
    GPG_ASSERT(visibilityModeType != nullptr);
    archive->Write(visibilityModeType, &mVisibilityMode, ownerRef);

    gpg::RType* const layerType = ResolveLayerType();
    GPG_ASSERT(layerType != nullptr);
    archive->Write(layerType, &mLayerMask, ownerRef);

    archive->WriteBool(mUsingAltFootprint != 0u);

    gpg::RType* const attributesType = ResolveEntityAttributesType();
    GPG_ASSERT(attributesType != nullptr);
    archive->Write(attributesType, &mIntelAttributes, ownerRef);
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

  // Static cached RType slot for the recovered placeholder
  // `SSTIEntityAttachInfo` type. Populated by the first
  // `gpg::RRef_SSTIEntityAttachInfo` call via cached lookup; no
  // additional registration is required because the binary's only
  // observed access to `sType` is through the same RRef helper.
  gpg::RType* SSTIEntityAttachInfo::sType = nullptr;
} // namespace moho
