#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E07658
   * COL: 0x00E62088
   */
  class PrefetchHandleBaseSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC5BE0 (FUN_00BC5BE0, register_PrefetchHandleBaseSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    PrefetchHandleBaseSerializer();

    /**
     * Address: 0x00BF0620 (FUN_00BF0620, Moho::PrefetchHandleBaseSerializer::~PrefetchHandleBaseSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state. The real ctor
     * pushes this mangled destructor symbol as its atexit target.
     */
    ~PrefetchHandleBaseSerializer();

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
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(PrefetchHandleBaseSerializer, mLoadCallback) == 0x0C,
    "PrefetchHandleBaseSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(PrefetchHandleBaseSerializer, mSaveCallback) == 0x10,
    "PrefetchHandleBaseSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(PrefetchHandleBaseSerializer) == 0x14, "PrefetchHandleBaseSerializer size must be 0x14");
} // namespace moho
