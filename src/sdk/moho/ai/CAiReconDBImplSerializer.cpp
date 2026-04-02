#include "moho/ai/CAiReconDBImplSerializer.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/reflection/SerializationError.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/ai/CAiReconDBImplTypeInfo.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityFastVectorReflection.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CInfluenceMap.h"
#include "moho/sim/CIntelGrid.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"

using namespace moho;

namespace
{
  alignas(SReconKeyTypeInfo) unsigned char gSReconKeyTypeInfoStorage[sizeof(SReconKeyTypeInfo)] = {};
  alignas(SReconKeySerializer) unsigned char gSReconKeySerializerStorage[sizeof(SReconKeySerializer)] = {};
  bool gSReconKeySerializerConstructed = false;

  alignas(CAiReconDBImplSerializer) unsigned char
    gCAiReconDBImplSerializerStorage[sizeof(CAiReconDBImplSerializer)] = {};
  bool gCAiReconDBImplSerializerConstructed = false;

  gpg::RType* gWeakPtrEntityType = nullptr;
  gpg::RType* gEntIdType = nullptr;
  gpg::RType* gReconBlipMapStorageType = nullptr;
  gpg::RType* gReconBlipVectorType = nullptr;
  gpg::RType* gCArmyImplType = nullptr;
  gpg::RType* gSTIMapType = nullptr;
  gpg::RType* gSimType = nullptr;
  gpg::RType* gCInfluenceMapType = nullptr;
  gpg::RType* gCIntelGridType = nullptr;
  gpg::RType* gVisibleToReconCategoryType = nullptr;

  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  [[nodiscard]] SReconKeySerializer* AcquireSReconKeySerializer()
  {
    if (!gSReconKeySerializerConstructed) {
      new (gSReconKeySerializerStorage) SReconKeySerializer();
      gSReconKeySerializerConstructed = true;
    }

    return reinterpret_cast<SReconKeySerializer*>(gSReconKeySerializerStorage);
  }

  [[nodiscard]] CAiReconDBImplSerializer* AcquireCAiReconDBImplSerializer()
  {
    if (!gCAiReconDBImplSerializerConstructed) {
      new (gCAiReconDBImplSerializerStorage) CAiReconDBImplSerializer();
      gCAiReconDBImplSerializerConstructed = true;
    }

    return reinterpret_cast<CAiReconDBImplSerializer*>(gCAiReconDBImplSerializerStorage);
  }

  [[nodiscard]] SReconKeyTypeInfo* SReconKeyTypeInfoStorageRef()
  {
    return reinterpret_cast<SReconKeyTypeInfo*>(gSReconKeyTypeInfoStorage);
  }

  /**
   * Address: 0x005BFD90 (FUN_005BFD90, PreregisterSReconKeyTypeInfo)
   *
   * What it does:
   * Constructs startup `SReconKeyTypeInfo` storage and preregisters RTTI.
   */
  [[nodiscard]] gpg::RType* PreregisterSReconKeyTypeInfo()
  {
    auto* const typeInfo = new (gSReconKeyTypeInfoStorage) SReconKeyTypeInfo();
    gpg::PreRegisterRType(typeid(SReconKey), typeInfo);
    return typeInfo;
  }

  [[nodiscard]] gpg::RType* ResolveWeakPtrEntityType()
  {
    if (!gWeakPtrEntityType) {
      gWeakPtrEntityType = gpg::LookupRType(typeid(WeakPtr<Entity>));
      if (!gWeakPtrEntityType) {
        gWeakPtrEntityType = moho::register_WeakPtr_Entity_Type_00();
      }
    }
    return gWeakPtrEntityType;
  }

  [[nodiscard]] gpg::RType* ResolveEntIdType()
  {
    return CachedType<std::int32_t>(gEntIdType);
  }

  [[nodiscard]] gpg::RType* ResolveReconBlipMapStorageType()
  {
    if (!gReconBlipMapStorageType) {
      gReconBlipMapStorageType = gpg::LookupRType(typeid(SReconBlipMapStorage));
      if (!gReconBlipMapStorageType) {
        (void)moho::register_RMultiMapType_SReconKey_ReconBlipPtr();
        gReconBlipMapStorageType = gpg::LookupRType(typeid(SReconBlipMapStorage));
      }
    }
    return gReconBlipMapStorageType;
  }

  [[nodiscard]] gpg::RType* ResolveReconBlipVectorType()
  {
    if (!gReconBlipVectorType) {
      gReconBlipVectorType = gpg::LookupRType(typeid(msvc8::vector<ReconBlip*>));
      if (!gReconBlipVectorType) {
        (void)moho::register_RVectorType_ReconBlipPtr();
        gReconBlipVectorType = gpg::LookupRType(typeid(msvc8::vector<ReconBlip*>));
      }
    }
    return gReconBlipVectorType;
  }

  [[nodiscard]] gpg::RType* ResolveCArmyImplType()
  {
    if (!gCArmyImplType) {
      gCArmyImplType = CArmyImpl::sType ? CArmyImpl::sType : gpg::LookupRType(typeid(CArmyImpl));
    }
    return gCArmyImplType;
  }

  [[nodiscard]] gpg::RType* ResolveSTIMapType()
  {
    return CachedType<STIMap>(gSTIMapType);
  }

  [[nodiscard]] gpg::RType* ResolveSimType()
  {
    if (!gSimType) {
      gSimType = Sim::sType ? Sim::sType : gpg::LookupRType(typeid(Sim));
    }
    return gSimType;
  }

  [[nodiscard]] gpg::RType* ResolveCInfluenceMapType()
  {
    if (!gCInfluenceMapType) {
      gCInfluenceMapType = CInfluenceMap::sType ? CInfluenceMap::sType : gpg::LookupRType(typeid(CInfluenceMap));
    }
    return gCInfluenceMapType;
  }

  [[nodiscard]] gpg::RType* ResolveCIntelGridType()
  {
    if (!gCIntelGridType) {
      gCIntelGridType = CIntelGrid::sType ? CIntelGrid::sType : gpg::LookupRType(typeid(CIntelGrid));
    }
    return gCIntelGridType;
  }

  [[nodiscard]] gpg::RType* ResolveVisibleToReconCategoryType()
  {
    return CachedType<CategoryWordRangeView>(gVisibleToReconCategoryType);
  }

  struct ReflectedObjectDeleter
  {
    gpg::RType::delete_func_t deleteFunc = nullptr;

    void operator()(void* const object) const noexcept
    {
      if (deleteFunc) {
        deleteFunc(object);
      }
    }
  };

  template <class TObject>
  [[nodiscard]] TObject* DecodeTrackedPointer(
    const gpg::TrackedPointerInfo& tracked, gpg::RType* const expectedType, const char* const mismatchMessage
  )
  {
    if (!tracked.object) {
      return nullptr;
    }

    if (tracked.type && expectedType) {
      gpg::RRef source{};
      source.mObj = tracked.object;
      source.mType = tracked.type;
      const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
      if (!upcast.mObj) {
        throw gpg::SerializationError(mismatchMessage ? mismatchMessage : "Archive pointer type mismatch");
      }
      return static_cast<TObject*>(upcast.mObj);
    }

    return static_cast<TObject*>(tracked.object);
  }

  void EnsureTrackedPointerSharedOwnership(gpg::TrackedPointerInfo& tracked)
  {
    if (tracked.state == gpg::TrackedPointerState::Unowned) {
      if (!tracked.type || !tracked.type->deleteFunc_) {
        throw gpg::SerializationError("Ownership conflict while loading archive");
      }

      auto* const control = new boost::detail::sp_counted_impl_pd<void*, ReflectedObjectDeleter>(
        tracked.object, ReflectedObjectDeleter{tracked.type->deleteFunc_}
      );
      tracked.sharedObject = tracked.object;
      tracked.sharedControl = control;
      tracked.state = gpg::TrackedPointerState::Shared;
      return;
    }

    if (tracked.state != gpg::TrackedPointerState::Shared || !tracked.sharedObject || !tracked.sharedControl) {
      throw gpg::SerializationError("Can't mix boost::shared_ptr with other shared pointers.");
    }
  }

  template <class TObject>
  void ReadPointerUnowned(
    TObject*& outPointer,
    gpg::ReadArchive* const archive,
    const gpg::RRef& ownerRef,
    gpg::RType* const expectedType,
    const char* const mismatchMessage
  )
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    outPointer = DecodeTrackedPointer<TObject>(tracked, expectedType, mismatchMessage);
  }

  template <class TObject>
  void ReadPointerShared(
    boost::SharedPtrRaw<TObject>& outPointer,
    gpg::ReadArchive* const archive,
    const gpg::RRef& ownerRef,
    gpg::RType* const expectedType,
    const char* const mismatchMessage
  )
  {
    gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      outPointer.release();
      return;
    }

    EnsureTrackedPointerSharedOwnership(tracked);
    TObject* const casted = DecodeTrackedPointer<TObject>(tracked, expectedType, mismatchMessage);

    boost::SharedPtrRaw<TObject> source{};
    source.px = casted;
    source.pi = tracked.sharedControl;
    outPointer.assign_retain(source);
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef MakeTypedRef(TObject* const object, gpg::RType* const staticType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = staticType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType && staticType && dynamicType->IsDerivedFrom(staticType, &baseOffset);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType ? dynamicType : staticType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  template <class TObject>
  void WritePointerWithType(
    gpg::WriteArchive* const archive,
    TObject* const object,
    gpg::RType* const staticType,
    const gpg::TrackedPointerState state,
    const gpg::RRef& ownerRef
  )
  {
    const gpg::RRef objectRef = MakeTypedRef(object, staticType);
    gpg::WriteRawPointer(archive, objectRef, state, ownerRef);
  }

  /**
   * Address: 0x005CCBE0 (FUN_005CCBE0, Moho::CAiReconDBImp::MemberDeserialize)
   *
   * What it does:
   * Deserializes CAiReconDBImpl reflected member lanes in binary order.
   */
  void DeserializeCAiReconDBImplMembers(CAiReconDBImpl* const object, gpg::ReadArchive* const archive)
  {
    if (!object || !archive) {
      return;
    }

    const gpg::RRef ownerRef{};

    gpg::RType* const mapType = ResolveReconBlipMapStorageType();
    GPG_ASSERT(mapType != nullptr);
    if (!mapType) {
      return;
    }
    archive->Read(mapType, &object->mBlipMap, ownerRef);

    gpg::RType* const blipVectorType = ResolveReconBlipVectorType();
    GPG_ASSERT(blipVectorType != nullptr);
    if (!blipVectorType) {
      return;
    }
    archive->Read(blipVectorType, &object->mBblips, ownerRef);
    archive->Read(blipVectorType, &object->mTempBlips, ownerRef);

    ReadPointerUnowned(object->mArmy, archive, ownerRef, ResolveCArmyImplType(), "CAiReconDBImpl::mArmy type mismatch");
    ReadPointerUnowned(object->mMapData, archive, ownerRef, ResolveSTIMapType(), "CAiReconDBImpl::mMapData type mismatch");
    ReadPointerUnowned(object->mSim, archive, ownerRef, ResolveSimType(), "CAiReconDBImpl::mSim type mismatch");
    ReadPointerUnowned(
      object->mIMap, archive, ownerRef, ResolveCInfluenceMapType(), "CAiReconDBImpl::mIMap type mismatch"
    );
    ReadPointerShared(
      object->mVisionGrid, archive, ownerRef, ResolveCIntelGridType(), "CAiReconDBImpl::mVisionGrid type mismatch"
    );
    ReadPointerShared(
      object->mWaterGrid, archive, ownerRef, ResolveCIntelGridType(), "CAiReconDBImpl::mWaterGrid type mismatch"
    );
    ReadPointerShared(
      object->mRadarGrid, archive, ownerRef, ResolveCIntelGridType(), "CAiReconDBImpl::mRadarGrid type mismatch"
    );
    ReadPointerShared(
      object->mSonarGrid, archive, ownerRef, ResolveCIntelGridType(), "CAiReconDBImpl::mSonarGrid type mismatch"
    );
    ReadPointerShared(
      object->mOmniGrid, archive, ownerRef, ResolveCIntelGridType(), "CAiReconDBImpl::mOmniGrid type mismatch"
    );
    ReadPointerShared(
      object->mRCIGrid, archive, ownerRef, ResolveCIntelGridType(), "CAiReconDBImpl::mRCIGrid type mismatch"
    );
    ReadPointerShared(
      object->mSCIGrid, archive, ownerRef, ResolveCIntelGridType(), "CAiReconDBImpl::mSCIGrid type mismatch"
    );
    ReadPointerShared(
      object->mVCIGrid, archive, ownerRef, ResolveCIntelGridType(), "CAiReconDBImpl::mVCIGrid type mismatch"
    );

    archive->ReadBool(reinterpret_cast<bool*>(&object->mFogOfWar));

    gpg::RType* const visibleToReconCategoryType = ResolveVisibleToReconCategoryType();
    GPG_ASSERT(visibleToReconCategoryType != nullptr);
    if (!visibleToReconCategoryType) {
      return;
    }
    archive->Read(visibleToReconCategoryType, &object->mVisibleToReconCategory, ownerRef);
  }

  /**
   * Address: 0x005CCDE0 (FUN_005CCDE0, Moho::CAiReconDBImp::MemberSerialize)
   *
   * What it does:
   * Serializes CAiReconDBImpl reflected member lanes in binary order.
   */
  void SerializeCAiReconDBImplMembers(const CAiReconDBImpl* const object, gpg::WriteArchive* const archive)
  {
    if (!object || !archive) {
      return;
    }

    const gpg::RRef ownerRef{};

    gpg::RType* const mapType = ResolveReconBlipMapStorageType();
    GPG_ASSERT(mapType != nullptr);
    if (!mapType) {
      return;
    }
    archive->Write(mapType, &object->mBlipMap, ownerRef);

    gpg::RType* const blipVectorType = ResolveReconBlipVectorType();
    GPG_ASSERT(blipVectorType != nullptr);
    if (!blipVectorType) {
      return;
    }
    archive->Write(blipVectorType, &object->mBblips, ownerRef);
    archive->Write(blipVectorType, &object->mTempBlips, ownerRef);

    WritePointerWithType(
      archive, object->mArmy, ResolveCArmyImplType(), gpg::TrackedPointerState::Unowned, ownerRef
    );
    WritePointerWithType(archive, object->mMapData, ResolveSTIMapType(), gpg::TrackedPointerState::Unowned, ownerRef);
    WritePointerWithType(archive, object->mSim, ResolveSimType(), gpg::TrackedPointerState::Unowned, ownerRef);
    WritePointerWithType(
      archive, object->mIMap, ResolveCInfluenceMapType(), gpg::TrackedPointerState::Unowned, ownerRef
    );
    WritePointerWithType(
      archive, object->mVisionGrid.px, ResolveCIntelGridType(), gpg::TrackedPointerState::Shared, ownerRef
    );
    WritePointerWithType(
      archive, object->mWaterGrid.px, ResolveCIntelGridType(), gpg::TrackedPointerState::Shared, ownerRef
    );
    WritePointerWithType(
      archive, object->mRadarGrid.px, ResolveCIntelGridType(), gpg::TrackedPointerState::Shared, ownerRef
    );
    WritePointerWithType(
      archive, object->mSonarGrid.px, ResolveCIntelGridType(), gpg::TrackedPointerState::Shared, ownerRef
    );
    WritePointerWithType(
      archive, object->mOmniGrid.px, ResolveCIntelGridType(), gpg::TrackedPointerState::Shared, ownerRef
    );
    WritePointerWithType(
      archive, object->mRCIGrid.px, ResolveCIntelGridType(), gpg::TrackedPointerState::Shared, ownerRef
    );
    WritePointerWithType(
      archive, object->mSCIGrid.px, ResolveCIntelGridType(), gpg::TrackedPointerState::Shared, ownerRef
    );
    WritePointerWithType(
      archive, object->mVCIGrid.px, ResolveCIntelGridType(), gpg::TrackedPointerState::Shared, ownerRef
    );

    archive->WriteBool(object->mFogOfWar != 0u);

    gpg::RType* const visibleToReconCategoryType = ResolveVisibleToReconCategoryType();
    GPG_ASSERT(visibleToReconCategoryType != nullptr);
    if (!visibleToReconCategoryType) {
      return;
    }
    archive->Write(visibleToReconCategoryType, &object->mVisibleToReconCategory, ownerRef);
  }

  /**
   * Address: 0x00BF7960 (FUN_00BF7960, cleanup_SReconKeyTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `SReconKeyTypeInfo` reflection storage.
   */
  void cleanup_SReconKeyTypeInfo()
  {
    static_cast<gpg::RType*>(SReconKeyTypeInfoStorageRef())->~RType();
  }

  /**
   * Address: 0x00BF79C0 (FUN_00BF79C0, cleanup_SReconKeySerializer)
   *
   * What it does:
   * Unlinks startup SReconKey serializer helper node and rewires it to
   * self-linked inert state.
   */
  void cleanup_SReconKeySerializer()
  {
    if (!gSReconKeySerializerConstructed) {
      return;
    }

    SReconKeySerializer* const serializer = AcquireSReconKeySerializer();
    if (serializer->mNext && serializer->mPrev) {
      serializer->mNext->mPrev = serializer->mPrev;
      serializer->mPrev->mNext = serializer->mNext;
    }

    serializer->mNext = reinterpret_cast<gpg::SerHelperBase*>(serializer);
    serializer->mPrev = reinterpret_cast<gpg::SerHelperBase*>(serializer);
  }

  /**
   * Address: 0x00BF7AB0 (FUN_00BF7AB0, Moho::CAiReconDBImplSerializer::~CAiReconDBImplSerializer)
   *
   * What it does:
   * Unlinks startup CAiReconDBImpl serializer helper node and rewires it to
   * self-linked inert state.
   */
  void cleanup_CAiReconDBImplSerializer()
  {
    if (!gCAiReconDBImplSerializerConstructed) {
      return;
    }

    CAiReconDBImplSerializer* const serializer = AcquireCAiReconDBImplSerializer();
    if (serializer->mNext && serializer->mPrev) {
      serializer->mNext->mPrev = serializer->mPrev;
      serializer->mPrev->mNext = serializer->mNext;
    }

    serializer->mNext = reinterpret_cast<gpg::SerHelperBase*>(serializer);
    serializer->mPrev = reinterpret_cast<gpg::SerHelperBase*>(serializer);
  }

  struct CAiReconDBSerializerBootstrap
  {
    CAiReconDBSerializerBootstrap()
    {
      (void)moho::register_SReconKeyTypeInfo();
      moho::register_SReconKeySerializer();
      moho::register_CAiReconDBImplSerializer();
    }
  };

  [[maybe_unused]] CAiReconDBSerializerBootstrap gCAiReconDBSerializerBootstrap;
} // namespace

/**
 * Address: 0x005BFE20 (FUN_005BFE20, Moho::SReconKeyTypeInfo::dtr)
 */
SReconKeyTypeInfo::~SReconKeyTypeInfo() = default;

/**
 * Address: 0x005BFE10 (FUN_005BFE10, Moho::SReconKeyTypeInfo::GetName)
 */
const char* SReconKeyTypeInfo::GetName() const
{
  return "SReconKey";
}

/**
 * Address: 0x005BFDF0 (FUN_005BFDF0, Moho::SReconKeyTypeInfo::Init)
 */
void SReconKeyTypeInfo::Init()
{
  size_ = sizeof(SReconKey);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x005C90F0 (FUN_005C90F0, Moho::SReconKey::MemberDeserialize)
 */
void SReconKey::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  gpg::RType* const weakPtrEntityType = ResolveWeakPtrEntityType();
  GPG_ASSERT(weakPtrEntityType != nullptr);
  if (!weakPtrEntityType) {
    return;
  }

  archive->Read(weakPtrEntityType, &sourceUnit, ownerRef);

  gpg::RType* const entIdType = ResolveEntIdType();
  GPG_ASSERT(entIdType != nullptr);
  if (!entIdType) {
    return;
  }
  archive->Read(entIdType, &sourceEntityId, ownerRef);
}

/**
 * Address: 0x005C9170 (FUN_005C9170, Moho::SReconKey::MemberSerialize)
 */
void SReconKey::MemberSerialize(gpg::WriteArchive* const archive) const
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  gpg::RType* const weakPtrEntityType = ResolveWeakPtrEntityType();
  GPG_ASSERT(weakPtrEntityType != nullptr);
  if (!weakPtrEntityType) {
    return;
  }

  archive->Write(weakPtrEntityType, &sourceUnit, ownerRef);

  gpg::RType* const entIdType = ResolveEntIdType();
  GPG_ASSERT(entIdType != nullptr);
  if (!entIdType) {
    return;
  }
  archive->Write(entIdType, &sourceEntityId, ownerRef);
}

/**
 * Address: 0x005BFED0 (FUN_005BFED0, Moho::SReconKeySerializer::Deserialize)
 */
void SReconKeySerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const key = reinterpret_cast<SReconKey*>(objectPtr);
  if (!key) {
    return;
  }

  key->MemberDeserialize(archive);
}

/**
 * Address: 0x005BFEE0 (FUN_005BFEE0, Moho::SReconKeySerializer::Serialize)
 */
void SReconKeySerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
{
  auto* const key = reinterpret_cast<SReconKey*>(objectPtr);
  if (!key) {
    return;
  }

  key->MemberSerialize(archive);
}

/**
 * Address: 0x005C4450 (FUN_005C4450)
 */
void SReconKeySerializer::RegisterSerializeFunctions()
{
  gpg::RType* type = SReconKey::sType;
  if (!type) {
    type = gpg::LookupRType(typeid(SReconKey));
    SReconKey::sType = type;
  }

  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mSerLoadFunc);
  type->serLoadFunc_ = mSerLoadFunc;
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerSaveFunc);
  type->serSaveFunc_ = mSerSaveFunc;
}

/**
 * Address: 0x00BCDD20 (FUN_00BCDD20, register_SReconKeyTypeInfo)
 */
int moho::register_SReconKeyTypeInfo()
{
  (void)PreregisterSReconKeyTypeInfo();
  return std::atexit(&cleanup_SReconKeyTypeInfo);
}

/**
 * Address: 0x00BCDD40 (FUN_00BCDD40, register_SReconKeySerializer)
 */
void moho::register_SReconKeySerializer()
{
  SReconKeySerializer* const serializer = AcquireSReconKeySerializer();
  serializer->mNext = reinterpret_cast<gpg::SerHelperBase*>(serializer);
  serializer->mPrev = reinterpret_cast<gpg::SerHelperBase*>(serializer);
  serializer->mSerLoadFunc = &SReconKeySerializer::Deserialize;
  serializer->mSerSaveFunc = &SReconKeySerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  (void)std::atexit(&cleanup_SReconKeySerializer);
}

/**
 * Address: 0x005C2910 (FUN_005C2910, Moho::CAiReconDBImplSerializer::Deserialize)
 */
void CAiReconDBImplSerializer::Deserialize(
  gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const
)
{
  auto* const object = reinterpret_cast<CAiReconDBImpl*>(static_cast<std::uintptr_t>(objectPtr));
  DeserializeCAiReconDBImplMembers(object, archive);
}

/**
 * Address: 0x005C2920 (FUN_005C2920, Moho::CAiReconDBImplSerializer::Serialize)
 */
void CAiReconDBImplSerializer::Serialize(
  gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const
)
{
  auto* const object = reinterpret_cast<CAiReconDBImpl*>(static_cast<std::uintptr_t>(objectPtr));
  SerializeCAiReconDBImplMembers(object, archive);
}

/**
 * Address: 0x005C4EE0 (FUN_005C4EE0)
 */
void CAiReconDBImplSerializer::RegisterSerializeFunctions()
{
  gpg::RType* type = CAiReconDBImpl::sType;
  if (!type) {
    type = gpg::LookupRType(typeid(CAiReconDBImpl));
    CAiReconDBImpl::sType = type;
  }

  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mSerLoadFunc);
  type->serLoadFunc_ = mSerLoadFunc;
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerSaveFunc);
  type->serSaveFunc_ = mSerSaveFunc;
}

/**
 * Address: 0x00BCDDC0 (FUN_00BCDDC0, register_CAiReconDBImplSerializer)
 *
 * What it does:
 * Constructs startup serializer helper storage for CAiReconDBImpl and binds
 * archive load/save callbacks.
 */
void moho::register_CAiReconDBImplSerializer()
{
  CAiReconDBImplSerializer* const serializer = AcquireCAiReconDBImplSerializer();
  serializer->mNext = reinterpret_cast<gpg::SerHelperBase*>(serializer);
  serializer->mPrev = reinterpret_cast<gpg::SerHelperBase*>(serializer);
  serializer->mSerLoadFunc = &CAiReconDBImplSerializer::Deserialize;
  serializer->mSerSaveFunc = &CAiReconDBImplSerializer::Serialize;
  serializer->RegisterSerializeFunctions();
  (void)std::atexit(&cleanup_CAiReconDBImplSerializer);
}
