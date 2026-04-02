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
   * VFTABLE: 0x00E1B408
   * COL:  0x00E70384
   */
  class IAiCommandDispatchImplSerializer
  {
  public:
    /**
     * Address: 0x005993C0 (FUN_005993C0, Moho::IAiCommandDispatchImplSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `IAiCommandDispatchImpl::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005993D0 (FUN_005993D0, Moho::IAiCommandDispatchImplSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `IAiCommandDispatchImpl::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005996D0 (FUN_005996D0)
     *
     * What it does:
     * Binds load/save serializer callbacks into IAiCommandDispatchImpl RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(IAiCommandDispatchImplSerializer, mHelperNext) == 0x04,
    "IAiCommandDispatchImplSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(IAiCommandDispatchImplSerializer, mHelperPrev) == 0x08,
    "IAiCommandDispatchImplSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(IAiCommandDispatchImplSerializer, mLoadCallback) == 0x0C,
    "IAiCommandDispatchImplSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(IAiCommandDispatchImplSerializer, mSaveCallback) == 0x10,
    "IAiCommandDispatchImplSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(IAiCommandDispatchImplSerializer) == 0x14, "IAiCommandDispatchImplSerializer size must be 0x14");

  /**
   * Address: 0x00BCBF00 (FUN_00BCBF00, register_IAiCommandDispatchImplSerializer)
   *
   * What it does:
   * Initializes recovered serializer helper storage/callback lanes and installs
   * process-exit unlink cleanup.
   */
  void register_IAiCommandDispatchImplSerializer();

  /**
   * Address: 0x00BCBF40 (FUN_00BCBF40, register_IAiCommandDispatchImplStartupStatsCleanup)
   *
   * What it does:
   * Registers an atexit cleanup thunk for one startup-owned engine-stats slot.
   */
  int register_IAiCommandDispatchImplStartupStatsCleanup();
} // namespace moho
