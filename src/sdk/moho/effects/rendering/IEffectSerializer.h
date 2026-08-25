#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E36BC4
   * COL: 0x00E900F4
   */
  class IEffectSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDCF00 (FUN_00BDCF00, register_IEffectSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list) and
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7IEffectSerializer@Moho@@6B@` -- no eager `Init()` call exists
     * here. Its atexit target (0x00C020E0) is a plain unmangled free
     * function doing a bare unlink with no prior recovered name; declaring
     * a real destructor below is sufficient for the compiler to emit the
     * same implicit static-destructor registration.
     */
    IEffectSerializer();

    /**
     * Address: 0x00C020E0 (FUN_00C020E0, Moho::IEffectSerializer::~IEffectSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~IEffectSerializer();

    /**
     * Address: 0x007712D0 (FUN_007712D0, gpg::SerSaveLoadHelper_IEffect::Init)
     *
     * IDA signature:
     * void (__cdecl *__thiscall gpg::SerSaveLoadHelper_IEffect::Init(_DWORD *this))
     * (gpg::ReadArchive *, int, int, gpg::RRef *);
     *
     * What it does:
     * Binds load/save serializer callbacks into `IEffect` RTTI.
     */
    void Init() override;

  public:
    /**
     * Address: 0x007711E0 (FUN_007711E0, Moho::IEffectSerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x007711F0 (FUN_007711F0, Moho::IEffectSerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(IEffectSerializer, mLoadCallback) == 0x0C, "IEffectSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(IEffectSerializer, mSaveCallback) == 0x10, "IEffectSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(IEffectSerializer) == 0x14, "IEffectSerializer size must be 0x14");
} // namespace moho
