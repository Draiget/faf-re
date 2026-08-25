#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E3176C
   */
  class CInfluenceMapSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDA6C0 (FUN_00BDA6C0, dynamic initializer for the global
     * `CInfluenceMapSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields. Prior to this recovery, this class was
     * never given a real constructor at all -- `register_CInfluenceMapSerializer()`
     * only set the raw struct's fields directly without ever running
     * `gpg::SerHelperBase::SerHelperBase()`, so this helper was never
     * spliced into `sNewHelpers` and `CInfluenceMap`'s load/save callbacks
     * were never installed under any code path.
     */
    CInfluenceMapSerializer();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CInfluenceMapSerializer();

    /**
     * Address: 0x00718B60 (FUN_00718B60, gpg::SerSaveLoadHelper_CInfluenceMap::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into CInfluenceMap RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CInfluenceMapSerializer, mLoadCallback) == 0x0C,
    "CInfluenceMapSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CInfluenceMapSerializer, mSaveCallback) == 0x10,
    "CInfluenceMapSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CInfluenceMapSerializer) == 0x14, "CInfluenceMapSerializer size must be 0x14");
} // namespace moho
