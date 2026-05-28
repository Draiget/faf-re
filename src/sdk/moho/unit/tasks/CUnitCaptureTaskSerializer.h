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
  class CUnitCaptureTaskSerializer
  {
  public:
    /**
     * Address: 0x006042B0 (FUN_006042B0, Moho::CUnitCaptureTaskSerializer::Deserialize)
     *
     * What it does:
     * Forwards one archive load callback into `CUnitCaptureTask::MemberDeserialize`
     * on the supplied object pointer.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006042C0 (FUN_006042C0, Moho::CUnitCaptureTaskSerializer::Serialize)
     *
     * What it does:
     * Forwards one archive save callback into `CUnitCaptureTask::MemberSerialize`
     * on the supplied object pointer.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * What it does:
     * Binds the serializer load/save callbacks into the reflected
     * `CUnitCaptureTask` type descriptor.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;    // +0x10
  };

  static_assert(
    offsetof(CUnitCaptureTaskSerializer, mHelperNext) == 0x04,
    "CUnitCaptureTaskSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CUnitCaptureTaskSerializer, mHelperPrev) == 0x08,
    "CUnitCaptureTaskSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CUnitCaptureTaskSerializer, mDeserialize) == 0x0C,
    "CUnitCaptureTaskSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitCaptureTaskSerializer, mSerialize) == 0x10,
    "CUnitCaptureTaskSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(CUnitCaptureTaskSerializer) == 0x14, "CUnitCaptureTaskSerializer size must be 0x14");

  /**
   * Address: 0x00604300 (FUN_00604300, cleanup_CUnitCaptureTaskSerializerNodePrimary)
   *
   * What it does:
   * Unlinks the `CUnitCaptureTaskSerializer` helper node from the intrusive
   * serializer-helper list and restores one self-linked node lane.
   */
  gpg::SerHelperBase* cleanup_CUnitCaptureTaskSerializer();

  /**
   * Address: 0x00BCFFD0 (FUN_00BCFFD0, register_CUnitCaptureTaskSerializer)
   *
   * What it does:
   * Constructs the global `CUnitCaptureTaskSerializer` helper, installs the
   * archive load/save callbacks, and schedules helper-node teardown at
   * process exit.
   */
  void register_CUnitCaptureTaskSerializer();
} // namespace moho
