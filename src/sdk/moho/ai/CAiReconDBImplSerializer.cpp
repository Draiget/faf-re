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
#include "gpg/core/reflection/Reflection.h"

using namespace moho;

namespace
{

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
 * Address: 0x00BCDD20 (FUN_00BCDD20, register_SReconKeyTypeInfo)
 */
void moho::register_SReconKeyTypeInfo()
{
  (void)PreregisterSReconKeyTypeInfo();
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SReconKeyTypeInfo_e639f8, moho::register_SReconKeyTypeInfo)

GPG_PREREGISTER_INIT(PreregisterSReconKeyTypeInfo_e639f8, PreregisterSReconKeyTypeInfo)

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SReconKey>`, vtable 0x00E1DAA4.
   *
   * Address: 0x00BCDD40 (FUN_00BCDD40 -- constructs the global and registers its destructor.)
   * Address: 0x00BF79C0 (FUN_00BF79C0 -- the global's destructor.)
   * Address: 0x005C4450 (FUN_005C4450 -- `Init`.)
   * Address: 0x005BFED0 (FUN_005BFED0 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x005BFEE0 (FUN_005BFEE0 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct SReconKeySerializer : gpg::SerSaveLoadHelper<SReconKey>
  {};
} // namespace moho

namespace
{
  // Address: 0x010AF89C -- process-global `SReconKeySerializer` singleton.
  moho::SReconKeySerializer gSReconKeySerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x005CCBE0 (FUN_005CCBE0, Moho::CAiReconDBImp::MemberDeserialize)
   *
   * What it does:
   * Deserializes CAiReconDBImpl reflected member lanes in binary order.
   */
  void CAiReconDBImpl::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    const gpg::RRef ownerRef{};
    archive->Read(gpg::RTypeOf<ReconBlipMap>(), &mBlipMap, ownerRef);
    archive->Read(gpg::RTypeOf<msvc8::vector<ReconBlip*>>(), &mBblips, ownerRef);
    archive->Read(gpg::RTypeOf<msvc8::vector<ReconBlip*>>(), &mTempBlips, ownerRef);
    archive->ReadPointer(&mArmy, &ownerRef);
    archive->ReadPointer(&mMapData, &ownerRef);
    archive->ReadPointer(&mSim, &ownerRef);
    archive->ReadPointer(&mIMap, &ownerRef);
    archive->ReadPointerShared(&mVisionGrid, &ownerRef);
    archive->ReadPointerShared(&mWaterGrid, &ownerRef);
    archive->ReadPointerShared(&mRadarGrid, &ownerRef);
    archive->ReadPointerShared(&mSonarGrid, &ownerRef);
    archive->ReadPointerShared(&mOmniGrid, &ownerRef);
    archive->ReadPointerShared(&mRCIGrid, &ownerRef);
    archive->ReadPointerShared(&mSCIGrid, &ownerRef);
    archive->ReadPointerShared(&mVCIGrid, &ownerRef);
    archive->ReadBool(reinterpret_cast<bool*>(&mFogOfWar));
    archive->Read(gpg::RTypeOf<EntityCategorySet>(), &mVisibleToReconCategory, ownerRef);
  }

  /**
   * Address: 0x005CCDE0 (FUN_005CCDE0, Moho::CAiReconDBImp::MemberSerialize)
   *
   * What it does:
   * Serializes CAiReconDBImpl reflected member lanes in binary order.
   */
  void CAiReconDBImpl::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    const gpg::RRef ownerRef{};
    archive->Write(gpg::RTypeOf<ReconBlipMap>(), &mBlipMap, ownerRef);
    archive->Write(gpg::RTypeOf<msvc8::vector<ReconBlip*>>(), &mBblips, ownerRef);
    archive->Write(gpg::RTypeOf<msvc8::vector<ReconBlip*>>(), &mTempBlips, ownerRef);
    archive->WritePointer(mArmy, gpg::TrackedPointerState::Unowned, ownerRef);
    archive->WritePointer(mMapData, gpg::TrackedPointerState::Unowned, ownerRef);
    archive->WritePointer(mSim, gpg::TrackedPointerState::Unowned, ownerRef);
    archive->WritePointer(mIMap, gpg::TrackedPointerState::Unowned, ownerRef);
    archive->WritePointer(mVisionGrid.px, gpg::TrackedPointerState::Shared, ownerRef);
    archive->WritePointer(mWaterGrid.px, gpg::TrackedPointerState::Shared, ownerRef);
    archive->WritePointer(mRadarGrid.px, gpg::TrackedPointerState::Shared, ownerRef);
    archive->WritePointer(mSonarGrid.px, gpg::TrackedPointerState::Shared, ownerRef);
    archive->WritePointer(mOmniGrid.px, gpg::TrackedPointerState::Shared, ownerRef);
    archive->WritePointer(mRCIGrid.px, gpg::TrackedPointerState::Shared, ownerRef);
    archive->WritePointer(mSCIGrid.px, gpg::TrackedPointerState::Shared, ownerRef);
    archive->WritePointer(mVCIGrid.px, gpg::TrackedPointerState::Shared, ownerRef);
    archive->WriteBool(mFogOfWar != 0u);
    archive->Write(gpg::RTypeOf<EntityCategorySet>(), &mVisibleToReconCategory, ownerRef);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<CAiReconDBImpl>`, vtable 0x00E1DB44.
   *
   * Address: 0x00BCDDC0 (FUN_00BCDDC0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF7AB0 (FUN_00BF7AB0 -- the global's destructor.)
   * Address: 0x005C4EE0 (FUN_005C4EE0 -- `Init`.)
   * Address: 0x005C2910 (FUN_005C2910 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x005C2920 (FUN_005C2920 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CAiReconDBImplSerializer : gpg::SerSaveLoadHelper<CAiReconDBImpl>
  {};
} // namespace moho

namespace
{
  // Address: 0x010AF824 -- process-global `CAiReconDBImplSerializer` singleton.
  moho::CAiReconDBImplSerializer gCAiReconDBImplSerializer;
} // namespace
