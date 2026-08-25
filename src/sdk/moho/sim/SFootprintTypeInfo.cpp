#include "moho/sim/SFootprintTypeInfo.h"

#include <cstdlib>
#include <cstring>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/SFootprint.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  alignas(moho::SFootprintTypeInfo) unsigned char gSFootprintTypeInfoStorage[sizeof(moho::SFootprintTypeInfo)];
  bool gSFootprintTypeInfoConstructed = false;

  [[nodiscard]] moho::SFootprintTypeInfo& SFootprintTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::SFootprintTypeInfo*>(gSFootprintTypeInfoStorage);
  }

  void CleanupSFootprintTypeInfoAtExit()
  {
    if (!gSFootprintTypeInfoConstructed) {
      return;
    }

    SFootprintTypeInfoStorageRef().~SFootprintTypeInfo();
    gSFootprintTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  gpg::RType* SFootprint::sType = nullptr;

  /**
   * Address: 0x0050AEE0 (FUN_0050AEE0)
   *
   * What it does:
   * Returns whether two footprint payload lanes are byte-identical across the
   * full 0x10-byte `SFootprint` layout.
   */
  [[maybe_unused]] [[nodiscard]] bool AreSFootprintBytesEqual(
    const SFootprint& lhs,
    const SFootprint& rhs
  ) noexcept
  {
    return std::memcmp(&lhs, &rhs, sizeof(SFootprint)) == 0;
  }

  /**
   * Address: 0x0050C410 (FUN_0050C410, Moho::SFootprintTypeInfo::SFootprintTypeInfo)
   *
   * What it does:
   * Preregisters the `SFootprint` RTTI descriptor with the reflection map.
   */
  SFootprintTypeInfo::SFootprintTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SFootprint), this);
  }

  /**
   * Address: 0x0050C4A0 (FUN_0050C4A0, Moho::SFootprintTypeInfo::dtr)
   *
   * What it does:
   * Releases the reflected field and base vector storage.
   */
  SFootprintTypeInfo::~SFootprintTypeInfo() = default;

  /**
   * Address: 0x0050C490 (FUN_0050C490, Moho::SFootprintTypeInfo::GetName)
   *
   * What it does:
   * Returns the reflected type label for `SFootprint`.
   */
  const char* SFootprintTypeInfo::GetName() const
  {
    return "SFootprint";
  }

  /**
   * Address: 0x0050C470 (FUN_0050C470, Moho::SFootprintTypeInfo::Init)
   *
   * What it does:
   * Sets the reflected size, installs field metadata, and finalizes the type.
   */
  void SFootprintTypeInfo::Init()
  {
    size_ = sizeof(SFootprint);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x0050C540 (FUN_0050C540, Moho::SFootprintTypeInfo::AddFields)
   *
   * What it does:
   * Registers reflected lanes for all `SFootprint` members in binary order.
   */
  void SFootprintTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(!typeInfo->initFinished_);
    typeInfo->AddFieldUChar("SizeX", 0x00);
    typeInfo->AddFieldUChar("SizeZ", 0x01);
    typeInfo->AddFieldFloat("MaxSlope", 0x04);
    typeInfo->AddFieldFloat("MinWaterDepth", 0x08);
    typeInfo->AddFieldUChar("OccupancyCaps", 0x02);
    typeInfo->AddFieldUChar("Flags", 0x03);
  }

  /**
   * Address: 0x0050D090 (FUN_0050D090, Moho::SFootprint::MemberDeserialize)
   *
   * What it does:
   * Loads the footprint fields in the exact binary archive order.
   */
  void SFootprint::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    archive->ReadUByte(&mSizeX);
    archive->ReadUByte(&mSizeZ);
    archive->ReadFloat(&mMaxSlope);
    archive->ReadFloat(&mMinWaterDepth);
    archive->ReadUByte(reinterpret_cast<unsigned char*>(&mOccupancyCaps));
    archive->ReadUByte(reinterpret_cast<unsigned char*>(&mFlags));
  }

  /**
   * Address: 0x0050D0E0 (FUN_0050D0E0, Moho::SFootprint::MemberSerialize)
   *
   * What it does:
   * Writes the footprint fields in the exact binary archive order.
   */
  void SFootprint::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    archive->WriteUByte(mSizeX);
    archive->WriteUByte(mSizeZ);
    archive->WriteFloat(mMaxSlope);
    archive->WriteFloat(mMinWaterDepth);
    archive->WriteUByte(static_cast<unsigned char>(mOccupancyCaps));
    archive->WriteUByte(static_cast<unsigned char>(mFlags));
  }

  /**
   * Address: 0x0050C5A0 (FUN_0050C5A0, Moho::SFootprintSerializer::Deserialize)
   *
   * What it does:
   * Forwards archive loading to `SFootprint::MemberDeserialize`.
   */
  void SFootprintSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*
  )
  {
    auto* const footprint = reinterpret_cast<SFootprint*>(objectPtr);
    GPG_ASSERT(footprint != nullptr);
    GPG_ASSERT(archive != nullptr);
    footprint->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0050C5B0 (FUN_0050C5B0, Moho::SFootprintSerializer::Serialize)
   *
   * What it does:
   * Forwards archive saving to `SFootprint::MemberSerialize`.
   */
  void SFootprintSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*
  )
  {
    auto* const footprint = reinterpret_cast<SFootprint*>(objectPtr);
    GPG_ASSERT(footprint != nullptr);
    GPG_ASSERT(archive != nullptr);
    footprint->MemberSerialize(archive);
  }

  /**
   * Address: 0x0050C9B0 (FUN_0050C9B0, shared Init() body -- also serves the
   * dead SerSaveLoadHelper<SFootprint> duplicate's vtable slot 0)
   */
  void SFootprintSerializer::Init()
  {
    if (SFootprint::sType == nullptr) {
      SFootprint::sType = gpg::LookupRType(typeid(SFootprint));
    }

    gpg::RType* const type = SFootprint::sType;
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BC7E40 (FUN_00BC7E40, register_SFootprintTypeInfo)
   *
   * What it does:
   * Installs the static `SFootprintTypeInfo` instance and its shutdown hook.
   */
  void register_SFootprintTypeInfo()
  {
    if (!gSFootprintTypeInfoConstructed) {
      new (gSFootprintTypeInfoStorage) SFootprintTypeInfo();
      gSFootprintTypeInfoConstructed = true;
    }

    (void)std::atexit(&CleanupSFootprintTypeInfoAtExit);
  }

  /**
   * Address: 0x00BC7E60 (FUN_00BC7E60, dynamic initializer for the global
   * `SFootprintSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  SFootprintSerializer::SFootprintSerializer()
    : mDeserialize(&SFootprintSerializer::Deserialize)
    , mSerialize(&SFootprintSerializer::Serialize)
  {}

  SFootprintSerializer::~SFootprintSerializer() noexcept
  {
    ResetLinks();
  }
} // namespace moho

namespace
{
  // Address: 0x010AA42C -- process-global `SFootprintSerializer` singleton.
  // (SFootprintTypeInfo's own registration is independently __xc_a-reachable
  // through GPG_PREREGISTER_INIT below; the two are unrelated hierarchies.)
  moho::SFootprintSerializer gSFootprintSerializer;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SFootprintTypeInfo_d68759, moho::register_SFootprintTypeInfo)
