#pragma once
#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"
#include "Wm3Quaternion.h"

namespace moho
{
  struct REntityBlueprint;

  struct SSTICommandConstantData
  {
    static gpg::RType* sType;

    int32_t cmd;
    void* unk0;
    Wm3::Quatf origin;
    float unk1;
    REntityBlueprint* blueprint;
    msvc8::string unk2;

    /**
     * Address: 0x00554630 (FUN_00554630, Moho::SSTICommandConstantData::MemberDeserialize)
     *
     * What it does:
     * Loads one command-constant payload lane from archive storage.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005546C0 (FUN_005546C0, Moho::SSTICommandConstantData::MemberSerialize)
     *
     * What it does:
     * Stores one command-constant payload lane to archive storage.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  class SSTICommandConstantDataSerializer
  {
  public:
    /**
     * Address: 0x00552810 (FUN_00552810, Moho::SSTICommandConstantDataSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive-load callback flow into `SSTICommandConstantData::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00552820 (FUN_00552820, Moho::SSTICommandConstantDataSerializer::Serialize)
     *
     * What it does:
     * Forwards archive-save callback flow into `SSTICommandConstantData::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00552E00 (FUN_00552E00, gpg::SerSaveLoadHelper_SSTICommandConstantData::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into `SSTICommandConstantData` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  static_assert(offsetof(SSTICommandConstantData, cmd) == 0x00, "SSTICommandConstantData::cmd offset must be 0x00");
  static_assert(offsetof(SSTICommandConstantData, unk0) == 0x04, "SSTICommandConstantData::unk0 offset must be 0x04");
  static_assert(
    offsetof(SSTICommandConstantData, origin) == 0x08, "SSTICommandConstantData::origin offset must be 0x08"
  );
  static_assert(offsetof(SSTICommandConstantData, unk1) == 0x18, "SSTICommandConstantData::unk1 offset must be 0x18");
  static_assert(
    offsetof(SSTICommandConstantData, blueprint) == 0x1C, "SSTICommandConstantData::blueprint offset must be 0x1C"
  );
  static_assert(
    offsetof(SSTICommandConstantData, unk2) == 0x20, "SSTICommandConstantData::unk2 offset must be 0x20"
  );
  static_assert(sizeof(SSTICommandConstantData) == 0x3C, "SSTICommandConstantData size must be 0x3C");
  static_assert(
    offsetof(SSTICommandConstantDataSerializer, mHelperNext) == 0x04,
    "SSTICommandConstantDataSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SSTICommandConstantDataSerializer, mHelperPrev) == 0x08,
    "SSTICommandConstantDataSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SSTICommandConstantDataSerializer, mSerLoadFunc) == 0x0C,
    "SSTICommandConstantDataSerializer::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(SSTICommandConstantDataSerializer, mSerSaveFunc) == 0x10,
    "SSTICommandConstantDataSerializer::mSerSaveFunc offset must be 0x10"
  );
  static_assert(
    sizeof(SSTICommandConstantDataSerializer) == 0x14, "SSTICommandConstantDataSerializer size must be 0x14"
  );

  /**
   * Address: 0x00552630 (FUN_00552630, preregister_SSTICommandConstantDataTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTICommandConstantData`.
   */
  [[nodiscard]] gpg::RType* preregister_SSTICommandConstantDataTypeInfo();
} // namespace moho
