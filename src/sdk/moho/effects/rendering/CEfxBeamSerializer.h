#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CEfxBeamSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD3F50 (FUN_00BD3F50, register_CEfxBeamSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list) and
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CEfxBeamSerializer@Moho@@6B@` -- no eager `Init()` call and no
     * call to `register_CEfxBeamTypeInfo_AtExit()` exist here (both were
     * fabricated in the prior recovery). The `push offset ~CEfxBeamSerializer;
     * call _atexit` sequence visible in the real ctor's tail is the
     * compiler's own implicit static-destructor registration for a global
     * with a non-trivial destructor (it pushes the mangled
     * `??1CEfxBeamSerializer@Moho@@QAE@@Z` symbol directly, not a call the
     * 2007 source wrote), so it is not reproduced explicitly here --
     * declaring a real destructor below is sufficient for the compiler to
     * emit the same registration.
     */
    CEfxBeamSerializer();

    /**
     * Address: 0x00BFB910 (FUN_00BFB910, Moho::CEfxBeamSerializer::~CEfxBeamSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CEfxBeamSerializer();

    /**
     * Address: 0x00657B80 (FUN_00657B80, gpg::SerSaveLoadHelper_CEfxBeam::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into `CEfxBeam` RTTI.
     */
    void Init() override;

  public:
    /**
     * Address: 0x00655F60 (FUN_00655F60, Moho::CEfxBeamSerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00655F70 (FUN_00655F70, Moho::CEfxBeamSerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CEfxBeamSerializer, mLoadCallback) == 0x0C, "CEfxBeamSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CEfxBeamSerializer, mSaveCallback) == 0x10, "CEfxBeamSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CEfxBeamSerializer) == 0x14, "CEfxBeamSerializer size must be 0x14");
} // namespace moho
