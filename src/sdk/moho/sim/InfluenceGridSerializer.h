#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E31914
   */
  class InfluenceGridSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDA7E0 (FUN_00BDA7E0, dynamic initializer for the global
     * `InfluenceGridSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields. The ctor's atexit target is a plain
     * unlink thunk, not a mangled destructor, so it is modeled as the
     * compiler's implicit static-destructor registration rather than an
     * explicit call.
     */
    InfluenceGridSerializer();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~InfluenceGridSerializer();

    /**
     * Address: 0x00719410 (FUN_00719410, gpg::SerSaveLoadHelper_InfluenceGrid::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into InfluenceGrid RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(InfluenceGridSerializer, mLoadCallback) == 0x0C,
    "InfluenceGridSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(InfluenceGridSerializer, mSaveCallback) == 0x10,
    "InfluenceGridSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(InfluenceGridSerializer) == 0x14, "InfluenceGridSerializer size must be 0x14");
} // namespace moho
