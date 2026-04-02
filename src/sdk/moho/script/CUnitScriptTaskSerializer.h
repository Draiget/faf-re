#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E20C98
   * COL: 0x00E79F40
   */
  class CUnitScriptTaskSerializer
  {
  public:
    /**
     * Address: 0x00622EA0 (FUN_00622EA0, Moho::CUnitScriptTaskSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load flow into `CUnitScriptTask::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00622EC0 (FUN_00622EC0, Moho::CUnitScriptTaskSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save flow into `CUnitScriptTask::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00623BB0 (FUN_00623BB0)
     *
     * What it does:
     * Binds load/save serializer callbacks into CUnitScriptTask RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CUnitScriptTaskSerializer, mHelperNext) == 0x04,
    "CUnitScriptTaskSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CUnitScriptTaskSerializer, mHelperPrev) == 0x08,
    "CUnitScriptTaskSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CUnitScriptTaskSerializer, mLoadCallback) == 0x0C,
    "CUnitScriptTaskSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitScriptTaskSerializer, mSaveCallback) == 0x10,
    "CUnitScriptTaskSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CUnitScriptTaskSerializer) == 0x14, "CUnitScriptTaskSerializer size must be 0x14");

  /**
   * Address: 0x00BFA470 (FUN_00BFA470)
   *
   * What it does:
   * Unlinks static `CUnitScriptTaskSerializer` helper node from the intrusive
   * serializer helper list and restores self-links.
   */
  gpg::SerHelperBase* cleanup_CUnitScriptTaskSerializer();

  /**
   * Address: 0x00BD19A0 (FUN_00BD19A0)
   *
   * What it does:
   * Initializes serializer callbacks for CUnitScriptTask and schedules
   * process-exit helper unlink cleanup.
   */
  void register_CUnitScriptTaskSerializer();
} // namespace moho
