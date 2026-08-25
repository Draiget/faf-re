#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E00584
   */
  class CMersenneTwisterSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC3320 (FUN_00BC3320, register_CMersenneTwisterSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the load/save callback fields. Confirmed from raw
     * disassembly: calls `gpg::SerHelperBase::SerHelperBase()` directly,
     * then installs `??_7CMersenneTwisterSerializer@Moho@@6B@` -- no eager
     * `Init()` call exists here. Prior to this recovery, this class was
     * never given a real constructor: the old raw struct's fields were set
     * directly by a namespace-scope bootstrap struct without ever running
     * `gpg::SerHelperBase::SerHelperBase()`, so this helper was never
     * spliced into `sNewHelpers` and `CMersenneTwister`'s load/save
     * callbacks were never installed under any code path.
     */
    CMersenneTwisterSerializer();

    /**
     * Address: 0x00BEE6F0 (FUN_00BEE6F0, Moho::CMersenneTwisterSerializer::~CMersenneTwisterSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CMersenneTwisterSerializer();

    /**
     * Address: 0x0040F2C0 (FUN_0040F2C0, gpg::SerSaveLoadHelper<class Moho::CMersenneTwister>::Init)
     *
     * What it does:
     * Binds CMersenneTwister load/save callbacks into reflected RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CMersenneTwisterSerializer, mLoadCallback) == 0x0C,
    "CMersenneTwisterSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CMersenneTwisterSerializer, mSaveCallback) == 0x10,
    "CMersenneTwisterSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CMersenneTwisterSerializer) == 0x14, "CMersenneTwisterSerializer size must be 0x14");
} // namespace moho
