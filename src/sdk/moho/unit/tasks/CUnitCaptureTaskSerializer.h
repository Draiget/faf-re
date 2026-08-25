#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitCaptureTask;

  /**
   * VFTABLE: 0x00E1FF54 (??_7CUnitCaptureTaskSerializer@Moho@@6B@)
   * COL: 0x00E1FF5C (??_7?$SerSaveLoadHelper@VCUnitCaptureTask@Moho@@@gpg@@6B@)
   *
   * Helper owner that wires the `CUnitCaptureTask` archive load/save lanes
   * into its reflected `gpg::RType`.
   */
  class CUnitCaptureTaskSerializer final : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCFFD0 (FUN_00BCFFD0, register_CUnitCaptureTaskSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CUnitCaptureTaskSerializer();

    /**
     * Address: 0x00BF9880 (FUN_00BF9880, Moho::CUnitCaptureTaskSerializer::~CUnitCaptureTaskSerializer)
     *
     * What it does:
     * Unlinks the serializer helper from the intrusive helper list.
     */
    ~CUnitCaptureTaskSerializer();

    /**
     * Address: 0x006042B0 (FUN_006042B0, Moho::CUnitCaptureTaskSerializer::Deserialize)
     *
     * What it does:
     * Forwards one archive load callback into `CUnitCaptureTask::MemberDeserialize`
     * on the supplied object pointer. Real body is an unconditional call
     * with no null guard.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006042C0 (FUN_006042C0, Moho::CUnitCaptureTaskSerializer::Serialize)
     *
     * What it does:
     * Forwards one archive save callback into `CUnitCaptureTask::MemberSerialize`
     * on the supplied object pointer. Real body is an unconditional call
     * with no null guard.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00605320 (FUN_00605320, gpg::SerSaveLoadHelper<Moho::CUnitCaptureTask>::Init)
     *
     * What it does:
     * Binds the serializer load/save callbacks into the reflected
     * `CUnitCaptureTask` type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(CUnitCaptureTaskSerializer, mDeserialize) == 0x0C,
    "CUnitCaptureTaskSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitCaptureTaskSerializer, mSerialize) == 0x10,
    "CUnitCaptureTaskSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(CUnitCaptureTaskSerializer) == 0x14, "CUnitCaptureTaskSerializer size must be 0x14");
} // namespace moho
