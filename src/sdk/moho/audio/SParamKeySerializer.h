#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/audio/SParamKey.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E0B9E0
   */
  class SParamKeySerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC6860 (FUN_00BC6860, register_SParamKeySerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list) and
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7SParamKeySerializer@Moho@@6B@` -- no eager `Init()` call exists
     * here. The `push offset ~SParamKeySerializer; call _atexit` sequence
     * visible in the real ctor's tail is the compiler's own implicit
     * static-destructor registration for a global with a non-trivial
     * destructor (it pushes the mangled
     * `??1SParamKeySerializer@Moho@@QAE@@Z` symbol directly, not a call the
     * 2007 source wrote), so it is not reproduced explicitly here --
     * declaring a real destructor below is sufficient for the compiler to
     * emit the same registration.
     */
    SParamKeySerializer();

    /**
     * Address: 0x00BF0E50 (FUN_00BF0E50, Moho::SParamKeySerializer::~SParamKeySerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SParamKeySerializer() noexcept;

    /**
     * Address: 0x004DEFD0 (FUN_004DEFD0, Moho::SParamKeySerializer::Deserialize)
     *
     * What it does:
     * Reflection load-callback facade for `SParamKey`. Reads the four
     * string fields (cue name, bank name, LOD-cutoff variable name,
     * RPC-loop variable name) directly through the archive.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004DF010 (FUN_004DF010, Moho::SParamKeySerializer::Serialize)
     *
     * What it does:
     * Reflection save-callback facade for `SParamKey`. Writes the four
     * string fields directly through the archive.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004E1600 (FUN_004E1600, gpg::SerSaveLoadHelper_SParamKey::Init)
     *
     * What it does:
     * Binds `SParamKey` RTTI serializer callbacks (`serLoadFunc_` / `serSaveFunc_`).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(SParamKeySerializer, mDeserialize) == 0x0C, "SParamKeySerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(SParamKeySerializer, mSerialize) == 0x10, "SParamKeySerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(SParamKeySerializer) == 0x14, "SParamKeySerializer size must be 0x14");
} // namespace moho
