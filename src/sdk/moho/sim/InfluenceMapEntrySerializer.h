#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E317AC
   */
  class InfluenceMapEntrySerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDA720 (FUN_00BDA720, dynamic initializer for the global
     * `InfluenceMapEntrySerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields. The ctor's atexit target is a plain
     * unlink thunk, not a mangled destructor, so it is modeled as the
     * compiler's implicit static-destructor registration rather than an
     * explicit call.
     */
    InfluenceMapEntrySerializer();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~InfluenceMapEntrySerializer();

    /**
     * Address: 0x00718C00 (FUN_00718C00, gpg::SerSaveLoadHelper_InfluenceMapEntry::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into InfluenceMapEntry RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(InfluenceMapEntrySerializer, mLoadCallback) == 0x0C,
    "InfluenceMapEntrySerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(InfluenceMapEntrySerializer, mSaveCallback) == 0x10,
    "InfluenceMapEntrySerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(InfluenceMapEntrySerializer) == 0x14, "InfluenceMapEntrySerializer size must be 0x14");
} // namespace moho
