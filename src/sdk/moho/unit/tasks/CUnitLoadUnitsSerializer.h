#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitLoadUnits;

  /**
   * VFTABLE: 0x00E20E6C
   * COL: 0x00E7A364
   */
  class CUnitLoadUnitsSerializer final : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD1CB0 (FUN_00BD1CB0, register_CUnitLoadUnitsSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CUnitLoadUnitsSerializer();

    /**
     * Address: 0x00BFA5B0 (FUN_00BFA5B0, cleanup_CUnitLoadUnitsSerializer)
     *
     * What it does:
     * Unlinks the serializer helper node from the intrusive helper list and
     * restores self-links.
     */
    ~CUnitLoadUnitsSerializer();

    /**
     * Address: 0x00624FF0 (FUN_00624FF0, Moho::CUnitLoadUnitsSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load flow into `CUnitLoadUnits::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00625000 (FUN_00625000, Moho::CUnitLoadUnitsSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save flow into `CUnitLoadUnits::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00626F90 (FUN_00626F90, gpg::SerSaveLoadHelper<Moho::CUnitLoadUnits>::Init)
     *
     * What it does:
     * Binds this helper's load/save callbacks into `CUnitLoadUnits` RTTI.
     * Previously mis-cited in `ArchiveSerialization.cpp` as a generic
     * `InstallSerSaveLoadHelperCallbacksByTypeName` dispatch (same
     * mis-citation family already caught this session for several other
     * classes); real body caches on `CUnitLoadUnits::sType` directly.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(CUnitLoadUnitsSerializer, mDeserialize) == 0x0C,
    "CUnitLoadUnitsSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitLoadUnitsSerializer, mSerialize) == 0x10,
    "CUnitLoadUnitsSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(CUnitLoadUnitsSerializer) == 0x14, "CUnitLoadUnitsSerializer size must be 0x14");
} // namespace moho

