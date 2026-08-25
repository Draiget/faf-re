#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E241C0
   */
  class CEfxEmitterSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD4310 (FUN_00BD4310, register_CEfxEmitterSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list) and
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CEfxEmitterSerializer@Moho@@6B@` -- no eager `Init()` call exists
     * here. The `push offset ~CEfxEmitterSerializer; call _atexit` sequence
     * visible in the real ctor's tail is the compiler's own implicit
     * static-destructor registration for a global with a non-trivial
     * destructor (it pushes the mangled
     * `??1CEfxEmitterSerializer@Moho@@QAE@@Z` symbol directly, not a call
     * the 2007 source wrote), so it is not reproduced explicitly here --
     * declaring a real destructor below is sufficient for the compiler to
     * emit the same registration.
     */
    CEfxEmitterSerializer();

    /**
     * Address: 0x00BFBDB0 (FUN_00BFBDB0, Moho::CEfxEmitterSerializer::~CEfxEmitterSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CEfxEmitterSerializer();

    /**
     * Address: 0x0065E140 (FUN_0065E140, Moho::CEfxEmitterSerializer::Deserialize)
     *
     * What it does:
     * Forwards the reflected object pointer to `CEfxEmitter::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0065E150 (FUN_0065E150, Moho::CEfxEmitterSerializer::Serialize)
     *
     * What it does:
     * Forwards the reflected object pointer to `CEfxEmitter::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0065F150 (FUN_0065F150, gpg::SerSaveLoadHelper_CEfxEmitter::Init)
     *
     * What it does:
     * Lazily resolves `CEfxEmitter` RTTI and installs load/save callbacks
     * from this helper object into the type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CEfxEmitterSerializer, mLoadCallback) == 0x0C, "CEfxEmitterSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CEfxEmitterSerializer, mSaveCallback) == 0x10, "CEfxEmitterSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CEfxEmitterSerializer) == 0x14, "CEfxEmitterSerializer size must be 0x14");
} // namespace moho
