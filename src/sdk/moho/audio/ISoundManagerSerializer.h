#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E35A40
   * COL: 0x00E8F218
   */
  class ISoundManagerSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDC4C0 (FUN_00BDC4C0, register_ISoundManagerSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list) and
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7ISoundManagerSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here. The `push offset ~ISoundManagerSerializer; call _atexit`
     * sequence visible in the real ctor's tail is the compiler's own
     * implicit static-destructor registration for a global with a
     * non-trivial destructor (it pushes the mangled
     * `??1ISoundManagerSerializer@Moho@@QAE@@Z` symbol directly, not a call
     * the 2007 source wrote), so it is not reproduced explicitly here --
     * declaring a real destructor below is sufficient for the compiler to
     * emit the same registration.
     */
    ISoundManagerSerializer();

    /**
     * Address: 0x00C014D0 (FUN_00C014D0, Moho::ISoundManagerSerializer::~ISoundManagerSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~ISoundManagerSerializer();

    /**
     * Address: 0x00760BD0 (FUN_00760BD0, Moho::ISoundManagerSerializer::Deserialize)
     *
     * What it does:
     * Placeholder deserialize lane for `ISoundManager` (no payload fields).
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00760BE0 (FUN_00760BE0, Moho::ISoundManagerSerializer::Serialize)
     *
     * What it does:
     * Placeholder serialize lane for `ISoundManager` (no payload fields).
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00761BE0 (FUN_00761BE0, gpg::SerSaveLoadHelper_ISoundManager::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into `ISoundManager` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(ISoundManagerSerializer, mLoadCallback) == 0x0C,
    "ISoundManagerSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(ISoundManagerSerializer, mSaveCallback) == 0x10,
    "ISoundManagerSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(ISoundManagerSerializer) == 0x14, "ISoundManagerSerializer size must be 0x14");
} // namespace moho
