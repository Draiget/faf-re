#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
}

namespace moho
{
  /**
   * VFTABLE: 0x00E07658
   * COL: 0x00E62088
   */
  class PrefetchHandleBaseSerializer
  {
  public:
    /**
     * Address: 0x004ABD30 (FUN_004ABD30, Moho::PrefetchHandleBaseSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `PrefetchHandleBase::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004ABD40 (FUN_004ABD40)
     *
     * What it does:
     * Writes prefetch payload path and reflected type handle lane.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004ACCF0 (FUN_004ACCF0)
     *
     * What it does:
     * Registers prefetch-handle save/load callbacks in reflected RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(PrefetchHandleBaseSerializer, mHelperNext) == 0x04,
    "PrefetchHandleBaseSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(PrefetchHandleBaseSerializer, mHelperPrev) == 0x08,
    "PrefetchHandleBaseSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(PrefetchHandleBaseSerializer, mLoadCallback) == 0x0C,
    "PrefetchHandleBaseSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(PrefetchHandleBaseSerializer, mSaveCallback) == 0x10,
    "PrefetchHandleBaseSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(PrefetchHandleBaseSerializer) == 0x14, "PrefetchHandleBaseSerializer size must be 0x14");

  /**
   * Address: 0x004ABD20 (FUN_004ABD20, nullsub_694)
   */
  void nullsub_694();

  /**
   * Address: 0x004ABDA0 (FUN_004ABDA0)
   */
  gpg::SerHelperBase* ResetPrefetchHandleBaseSerializerLinksVariant1();

  /**
   * Address: 0x004ABDD0 (FUN_004ABDD0)
   */
  gpg::SerHelperBase* ResetPrefetchHandleBaseSerializerLinksVariant2();
} // namespace moho
