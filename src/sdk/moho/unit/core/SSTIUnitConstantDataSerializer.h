#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
}

namespace moho
{
  struct SSTIUnitConstantData;

  /**
   * VFTABLE: 0x00E1881C
   * COL: 0x00E73818
   */
  class SSTIUnitConstantDataSerializer
  {
  public:
    /**
     * Address: 0x0055C550 (FUN_0055C550, Moho::SSTIUnitConstantDataSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load flow into `SSTIUnitConstantData::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0055C570 (FUN_0055C570, Moho::SSTIUnitConstantDataSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save flow into `SSTIUnitConstantData::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0055CB80 (FUN_0055CB80, gpg::SerSaveLoadHelper<Moho::SSTIUnitConstantData>::Init lane)
     *
     * What it does:
     * Binds serializer load/save callbacks into `SSTIUnitConstantData` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(SSTIUnitConstantDataSerializer, mHelperNext) == 0x04,
    "SSTIUnitConstantDataSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SSTIUnitConstantDataSerializer, mHelperPrev) == 0x08,
    "SSTIUnitConstantDataSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SSTIUnitConstantDataSerializer, mDeserialize) == 0x0C,
    "SSTIUnitConstantDataSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(SSTIUnitConstantDataSerializer, mSerialize) == 0x10,
    "SSTIUnitConstantDataSerializer::mSerialize offset must be 0x10"
  );
  static_assert(
    sizeof(SSTIUnitConstantDataSerializer) == 0x14,
    "SSTIUnitConstantDataSerializer size must be 0x14"
  );

  /**
   * Address: 0x0055C410 (FUN_0055C410, preregister_SSTIUnitConstantDataTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTIUnitConstantData`.
   */
  [[nodiscard]] gpg::RType* preregister_SSTIUnitConstantDataTypeInfo();

  /**
   * Address: 0x00BF5420 (FUN_00BF5420, Moho::SSTIUnitConstantDataSerializer::~SSTIUnitConstantDataSerializer)
   *
   * What it does:
   * Unlinks the serializer helper node from the intrusive helper list and
   * restores self-links.
   */
  void cleanup_SSTIUnitConstantDataSerializer();

  /**
   * Address: 0x00BCA640 (FUN_00BCA640, register_SSTIUnitConstantDataSerializer)
   *
   * What it does:
   * Initializes serializer callback pointers, vftable lane, and atexit cleanup.
   */
  void register_SSTIUnitConstantDataSerializer();
} // namespace moho
