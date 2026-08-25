#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  struct SSTIUnitConstantData;

  /**
   * VFTABLE: 0x00E1881C
   * COL: 0x00E73818
   *
   * RTTI Class Hierarchy Descriptor shows this class's base chain running
   * through `.?AU?$SerSaveLoadHelper@USSTIUnitConstantData@Moho@@@gpg@@`
   * before `gpg::SerHelperBase` (same pattern observed on every
   * `PrimitiveSerHelper<T,int>` instantiation this session). Not converted
   * to a naked `gpg::SerSaveLoadHelper<SSTIUnitConstantData>` alias: that
   * template's generic `Deserialize`/`Serialize` call
   * `T::MemberDeserialize(archive)`/`T::MemberSerialize(archive)` with no
   * `version` parameter, but `SSTIUnitConstantData::MemberDeserialize`/
   * `MemberSerialize` require `version` (real body throws on
   * `version < 1`). Same situation already documented for
   * `Rect2iSerializer`/`Rect2fSerializer` above: this stays a concrete
   * `SerHelperBase`-derived class with its own `Deserialize`/`Serialize`
   * static methods that thread `version` through.
   */
  class SSTIUnitConstantDataSerializer final : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCA640 (FUN_00BCA640, register_SSTIUnitConstantDataSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    SSTIUnitConstantDataSerializer();

    /**
     * Address: 0x00BF5420 (FUN_00BF5420, Moho::SSTIUnitConstantDataSerializer::~SSTIUnitConstantDataSerializer)
     *
     * What it does:
     * Unlinks the serializer helper node from the intrusive helper list and
     * restores self-links.
     */
    ~SSTIUnitConstantDataSerializer();

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
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

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
} // namespace moho
