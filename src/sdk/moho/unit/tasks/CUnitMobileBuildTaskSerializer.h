#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitMobileBuildTask;

  /**
   * VFTABLE: 0x00E1FA2C (??_7CUnitMobileBuildTaskSerializer@Moho@@6B@)
   * COL: 0x00E1FA34 (??_7?$SerSaveLoadHelper@VCUnitMobileBuildTask@Moho@@@gpg@@6B@)
   *
   * Helper owner that wires the `CUnitMobileBuildTask` archive load/save lanes
   * into its reflected `gpg::RType`.
   */
  class CUnitMobileBuildTaskSerializer final : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCF890 (FUN_00BCF890, register_CUnitMobileBuildTaskSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CUnitMobileBuildTaskSerializer();

    /**
     * Address: 0x00BF9330 (FUN_00BF9330, Moho::CUnitMobileBuildTaskSerializer::~CUnitMobileBuildTaskSerializer)
     *
     * What it does:
     * Unlinks the `CUnitMobileBuildTaskSerializer` helper node from the intrusive
     * serializer-helper list and restores one self-linked node lane.
     */
    ~CUnitMobileBuildTaskSerializer();

    /**
     * Address: 0x005F6A10 (FUN_005F6A10, Moho::CUnitMobileBuildTaskSerializer::Deserialize)
     *
     * What it does:
     * Forwards one archive load callback into
     * `CUnitMobileBuildTask::MemberDeserialize` on the supplied object pointer.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005F6A20 (FUN_005F6A20, Moho::CUnitMobileBuildTaskSerializer::Serialize)
     *
     * What it does:
     * Forwards one archive save callback into
     * `CUnitMobileBuildTask::MemberSerialize` on the supplied object pointer.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005FBBA0 (FUN_005FBBA0, gpg::SerSaveLoadHelper<Moho::CUnitMobileBuildTask>::Init)
     *
     * What it does:
     * Binds the serializer load/save callbacks into the reflected
     * `CUnitMobileBuildTask` type descriptor. Previously mis-cited in
     * `ArchiveSerialization.cpp` as a generic
     * `InstallSerSaveLoadHelperCallbacksByTypeName` dispatch (same
     * mis-citation family already caught this session for several other
     * classes); real body caches on `CUnitMobileBuildTask::sType` directly.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(CUnitMobileBuildTaskSerializer, mDeserialize) == 0x0C,
    "CUnitMobileBuildTaskSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitMobileBuildTaskSerializer, mSerialize) == 0x10,
    "CUnitMobileBuildTaskSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(CUnitMobileBuildTaskSerializer) == 0x14, "CUnitMobileBuildTaskSerializer size must be 0x14");
} // namespace moho
