#include "moho/sim/SFootprintTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/SFootprint.h"

#pragma init_seg(lib)

namespace
{
  alignas(moho::SFootprintTypeInfo) unsigned char gSFootprintTypeInfoStorage[sizeof(moho::SFootprintTypeInfo)];
  bool gSFootprintTypeInfoConstructed = false;

  alignas(moho::SFootprintSerializer) unsigned char
    gSFootprintSerializerStorage[sizeof(moho::SFootprintSerializer)];
  bool gSFootprintSerializerConstructed = false;

  [[nodiscard]] moho::SFootprintTypeInfo& SFootprintTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::SFootprintTypeInfo*>(gSFootprintTypeInfoStorage);
  }

  [[nodiscard]] moho::SFootprintSerializer& SFootprintSerializerStorageRef() noexcept
  {
    return *reinterpret_cast<moho::SFootprintSerializer*>(gSFootprintSerializerStorage);
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  void CleanupSFootprintTypeInfoAtExit()
  {
    if (!gSFootprintTypeInfoConstructed) {
      return;
    }

    SFootprintTypeInfoStorageRef().~SFootprintTypeInfo();
    gSFootprintTypeInfoConstructed = false;
  }

  void CleanupSFootprintSerializerAtExit()
  {
    if (!gSFootprintSerializerConstructed) {
      return;
    }

    SFootprintSerializerStorageRef().~SFootprintSerializer();
    gSFootprintSerializerConstructed = false;
  }
} // namespace

namespace moho
{
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
  void SFootprintSerializer::Deserialize(gpg::ReadArchive* const archive, SFootprint* const footprint)
  {
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
  void SFootprintSerializer::Serialize(gpg::WriteArchive* const archive, SFootprint* const footprint)
  {
    GPG_ASSERT(footprint != nullptr);
    GPG_ASSERT(archive != nullptr);
    footprint->MemberSerialize(archive);
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
   * Address: 0x00BC7E60 (FUN_00BC7E60, register_SFootprintSerializer)
   *
   * What it does:
   * Installs the serializer helper node and binds the member archive lanes.
   */
  void register_SFootprintSerializer()
  {
    if (!gSFootprintSerializerConstructed) {
      new (gSFootprintSerializerStorage) SFootprintSerializer();
      gSFootprintSerializerConstructed = true;
    }

    InitializeHelperNode(SFootprintSerializerStorageRef());
    SFootprintSerializerStorageRef().mDeserialize =
      reinterpret_cast<gpg::RType::load_func_t>(&SFootprintSerializer::Deserialize);
    SFootprintSerializerStorageRef().mSerialize =
      reinterpret_cast<gpg::RType::save_func_t>(&SFootprintSerializer::Serialize);
    (void)std::atexit(&CleanupSFootprintSerializerAtExit);
  }

  SFootprintSerializer::~SFootprintSerializer() noexcept = default;
} // namespace moho

namespace
{
  struct SFootprintBootstrap
  {
    SFootprintBootstrap()
    {
      moho::register_SFootprintTypeInfo();
      moho::register_SFootprintSerializer();
    }
  };

  [[maybe_unused]] SFootprintBootstrap gSFootprintBootstrap;
} // namespace
