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
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  // Address: 0x010AF89C -- process-global `SReconKeySerializer` singleton.
  // Constructing it runs SReconKeySerializer::SReconKeySerializer()
  // (0x00BCDD40), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~SReconKeySerializer,
  // 0x00BF79C0) runs at normal static-duration teardown.
  moho::SReconKeySerializer gSReconKeySerializer;

  // Address: 0x010AF824 -- process-global `CAiReconDBImplSerializer`
  // singleton. Same construction/teardown shape as `gSReconKeySerializer`
  // above, via CAiReconDBImplSerializer::CAiReconDBImplSerializer()
  // (0x00BCDDC0) and ~CAiReconDBImplSerializer() (0x00BF7AB0).
  moho::CAiReconDBImplSerializer gCAiReconDBImplSerializer;

  /**
   * Address: 0x005BFD90 (FUN_005BFD90, PreregisterSReconKeyTypeInfo)
   * Address: 0x00BF7960 (FUN_00BF7960, atexit destructor of the SReconKeyTypeInfo object)
   *
   * What it does:
   * Constructs the startup `SReconKeyTypeInfo` object and preregisters RTTI.
   */
  [[nodiscard]] gpg::RType* PreregisterSReconKeyTypeInfo()
  {
    static SReconKeyTypeInfo sInstance;
    gpg::PreRegisterRType(typeid(SReconKey), &sInstance);
    return &sInstance;
  }

  /**
   * Address: 0x005CCBE0 (FUN_005CCBE0, Moho::CAiReconDBImp::MemberDeserialize)
   *
   * What it does:
   * Deserializes CAiReconDBImpl reflected member lanes in binary order.
   */
  void DeserializeCAiReconDBImplMembers(CAiReconDBImpl* const object, gpg::ReadArchive* const archive)
  {
    const gpg::RRef ownerRef{};
    archive->Read(gpg::RTypeOf<ReconBlipMap>(), &object->mBlipMap, ownerRef);
    archive->Read(gpg::RTypeOf<msvc8::vector<ReconBlip*>>(), &object->mBblips, ownerRef);
    archive->Read(gpg::RTypeOf<msvc8::vector<ReconBlip*>>(), &object->mTempBlips, ownerRef);
    archive->ReadPointer(&object->mArmy, &ownerRef);
    archive->ReadPointer(&object->mMapData, &ownerRef);
    archive->ReadPointer(&object->mSim, &ownerRef);
    archive->ReadPointer(&object->mIMap, &ownerRef);
    archive->ReadPointerShared(&object->mVisionGrid, &ownerRef);
    archive->ReadPointerShared(&object->mWaterGrid, &ownerRef);
    archive->ReadPointerShared(&object->mRadarGrid, &ownerRef);
    archive->ReadPointerShared(&object->mSonarGrid, &ownerRef);
    archive->ReadPointerShared(&object->mOmniGrid, &ownerRef);
    archive->ReadPointerShared(&object->mRCIGrid, &ownerRef);
    archive->ReadPointerShared(&object->mSCIGrid, &ownerRef);
    archive->ReadPointerShared(&object->mVCIGrid, &ownerRef);
    archive->ReadBool(reinterpret_cast<bool*>(&object->mFogOfWar));
    archive->Read(gpg::RTypeOf<EntityCategorySet>(), &object->mVisibleToReconCategory, ownerRef);
  }

  /**
   * Address: 0x005CCDE0 (FUN_005CCDE0, Moho::CAiReconDBImp::MemberSerialize)
   *
   * What it does:
   * Serializes CAiReconDBImpl reflected member lanes in binary order.
   */
  void SerializeCAiReconDBImplMembers(const CAiReconDBImpl* const object, gpg::WriteArchive* const archive)
  {
    const gpg::RRef ownerRef{};
    archive->Write(gpg::RTypeOf<ReconBlipMap>(), &object->mBlipMap, ownerRef);
    archive->Write(gpg::RTypeOf<msvc8::vector<ReconBlip*>>(), &object->mBblips, ownerRef);
    archive->Write(gpg::RTypeOf<msvc8::vector<ReconBlip*>>(), &object->mTempBlips, ownerRef);
    archive->WritePointer(object->mArmy, gpg::TrackedPointerState::Unowned, ownerRef);
    archive->WritePointer(object->mMapData, gpg::TrackedPointerState::Unowned, ownerRef);
    archive->WritePointer(object->mSim, gpg::TrackedPointerState::Unowned, ownerRef);
    archive->WritePointer(object->mIMap, gpg::TrackedPointerState::Unowned, ownerRef);
    archive->WritePointer(object->mVisionGrid.px, gpg::TrackedPointerState::Shared, ownerRef);
    archive->WritePointer(object->mWaterGrid.px, gpg::TrackedPointerState::Shared, ownerRef);
    archive->WritePointer(object->mRadarGrid.px, gpg::TrackedPointerState::Shared, ownerRef);
    archive->WritePointer(object->mSonarGrid.px, gpg::TrackedPointerState::Shared, ownerRef);
    archive->WritePointer(object->mOmniGrid.px, gpg::TrackedPointerState::Shared, ownerRef);
    archive->WritePointer(object->mRCIGrid.px, gpg::TrackedPointerState::Shared, ownerRef);
    archive->WritePointer(object->mSCIGrid.px, gpg::TrackedPointerState::Shared, ownerRef);
    archive->WritePointer(object->mVCIGrid.px, gpg::TrackedPointerState::Shared, ownerRef);
    archive->WriteBool(object->mFogOfWar != 0u);
    archive->Write(gpg::RTypeOf<EntityCategorySet>(), &object->mVisibleToReconCategory, ownerRef);
  }

  // Addresses 0x005C98D0/0x005CB6C0 (the "ThunkA"/"ThunkB" save-lane
  // duplicates formerly modeled here) are dead: zero data_refs/call_edges
  // for both, and no source-level caller anywhere in src/sdk/**.
  // `CAiReconDBImplSerializer::Serialize` below already calls
  // `SerializeCAiReconDBImplMembers` above directly.

  // Addresses 0x005BFF20/0x005BFF50 ("StartupThunkA"/"StartupThunkB" for
  // `SReconKeySerializer`) and 0x005C2960/0x005C2990 (same pair for
  // `CAiReconDBImplSerializer`) formerly modeled here are dead: zero
  // data_refs/call_edges for all four, and no source-level caller anywhere
  // in src/sdk/**. The real teardown paths are `SReconKeySerializer::
  // ~SReconKeySerializer` / `CAiReconDBImplSerializer::
  // ~CAiReconDBImplSerializer` below, both C++-guaranteed to run at
  // static-duration teardown of their respective globals and both already
  // calling `ResetLinks()` directly.

  struct CAiReconDBSerializerBootstrap
  {
    CAiReconDBSerializerBootstrap()
    {
      moho::register_SReconKeyTypeInfo();
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
  const gpg::RRef ownerRef{};
  archive->Read(gpg::RTypeOf<WeakPtr<Entity>>(), &sourceEntity, ownerRef);
  archive->Read(gpg::RTypeOf<EntId>(), &sourceEntityId, ownerRef);
}

/**
 * Address: 0x005C9170 (FUN_005C9170, Moho::SReconKey::MemberSerialize)
 */
void SReconKey::MemberSerialize(gpg::WriteArchive* const archive) const
{
  const gpg::RRef ownerRef{};
  archive->Write(gpg::RTypeOf<WeakPtr<Entity>>(), &sourceEntity, ownerRef);
  archive->Write(gpg::RTypeOf<EntId>(), &sourceEntityId, ownerRef);
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
 * Address: 0x00BCDD40 (FUN_00BCDD40, dynamic initializer for the global
 * `SReconKeySerializer` singleton)
 */
SReconKeySerializer::SReconKeySerializer()
  : mSerLoadFunc(&SReconKeySerializer::Deserialize)
  , mSerSaveFunc(&SReconKeySerializer::Serialize)
{}

SReconKeySerializer::~SReconKeySerializer() = default;

/**
 * Address: 0x005C4450 (FUN_005C4450, Moho::SReconKeySerializer::Init)
 */
void SReconKeySerializer::Init()
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
void moho::register_SReconKeyTypeInfo()
{
  (void)PreregisterSReconKeyTypeInfo();
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
 * Address: 0x00BCDDC0 (FUN_00BCDDC0, dynamic initializer for the global
 * `CAiReconDBImplSerializer` singleton)
 */
CAiReconDBImplSerializer::CAiReconDBImplSerializer()
  : mSerLoadFunc(&CAiReconDBImplSerializer::Deserialize)
  , mSerSaveFunc(&CAiReconDBImplSerializer::Serialize)
{}

CAiReconDBImplSerializer::~CAiReconDBImplSerializer() = default;

/**
 * Address: 0x005C4EE0 (FUN_005C4EE0, Moho::CAiReconDBImplSerializer::Init)
 */
void CAiReconDBImplSerializer::Init()
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


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SReconKeyTypeInfo_e639f8, moho::register_SReconKeyTypeInfo)

GPG_PREREGISTER_INIT(PreregisterSReconKeyTypeInfo_e639f8, PreregisterSReconKeyTypeInfo)
