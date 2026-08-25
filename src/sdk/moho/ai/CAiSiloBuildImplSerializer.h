#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E1DD94
   * COL:  0x00E749D0
   */
  class SSiloBuildInfoSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x005CEC70 (FUN_005CEC70, Moho::SSiloBuildInfoSerializer::Deserialize)
     *
     * What it does:
     * Forwards one `SSiloBuildInfo` load callback into member deserialize
     * logic.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005CEC80 (FUN_005CEC80, Moho::SSiloBuildInfoSerializer::Serialize)
     *
     * What it does:
     * Forwards one `SSiloBuildInfo` save callback into member serialize logic.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00BCE0B0 (FUN_00BCE0B0, dynamic initializer for the global
     * `SSiloBuildInfoSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7SSiloBuildInfoSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here.
     */
    SSiloBuildInfoSerializer();

    /**
     * Address: 0x00BF7EA0 (FUN_00BF7EA0, ??1SSiloBuildInfoSerializer@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SSiloBuildInfoSerializer();

    /**
     * Address: 0x005CFB60 (FUN_005CFB60)
     *
     * What it does:
     * Binds load/save serializer callbacks into `SSiloBuildInfo` RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(SSiloBuildInfoSerializer, mLoadCallback) == 0x0C,
    "SSiloBuildInfoSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SSiloBuildInfoSerializer, mSaveCallback) == 0x10,
    "SSiloBuildInfoSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(SSiloBuildInfoSerializer) == 0x14, "SSiloBuildInfoSerializer size must be 0x14");

  /**
   * VFTABLE: 0x00E1DE48
   * COL:  0x00E747F8
   */
  class CAiSiloBuildImplSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x005CF8D0 (FUN_005CF8D0, Moho::CAiSiloBuildImplSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiSiloBuildImpl::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005CF8E0 (FUN_005CF8E0, Moho::CAiSiloBuildImplSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiSiloBuildImpl::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00BCE150 (FUN_00BCE150, dynamic initializer for the global
     * `CAiSiloBuildImplSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), binds
     * the load/save callback fields, then explicitly registers
     * `atexit(&sub_BF7F60)`. Confirmed from raw disassembly: calls
     * `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CAiSiloBuildImplSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here, and (unlike `SSiloBuildInfoSerializer` above) this class
     * has no user-declared destructor, so the real binary registers its
     * `atexit` unlink callback explicitly rather than relying on an implicit
     * non-trivial-destructor registration.
     */
    CAiSiloBuildImplSerializer();

    /**
     * Address: 0x005CFF30 (FUN_005CFF30)
     *
     * void ()
     *
     * IDA signature:
     * void (__cdecl *__thiscall sub_5CFF30(_DWORD *this))(gpg::ReadArchive *, int, int, gpg::RRef *);
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiSiloBuildImpl RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CAiSiloBuildImplSerializer, mLoadCallback) == 0x0C,
    "CAiSiloBuildImplSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiSiloBuildImplSerializer, mSaveCallback) == 0x10,
    "CAiSiloBuildImplSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiSiloBuildImplSerializer) == 0x14, "CAiSiloBuildImplSerializer size must be 0x14");

  /**
   * Address: 0x00BCE0B0 caller lane (`CAiSiloBuildImplTypeInfo.cpp`'s
   * reflection bootstrap sequence)
   *
   * What it does:
   * Historically forced construction of the (then lazily-constructed)
   * `SSiloBuildInfoSerializer` singleton from an explicit registration
   * sequence. `gSSiloBuildInfoSerializer` is now a genuine namespace-scope
   * global, so its constructor already runs unconditionally at static-init
   * time; this call is kept only so `CAiSiloBuildImplTypeInfo.cpp`'s
   * existing bootstrap sequence does not need editing.
   */
  int register_SSiloBuildInfoSerializer();

  /**
   * Address: 0x00BCE150 caller lane (`CAiSiloBuildImplTypeInfo.cpp`'s
   * reflection bootstrap sequence)
   *
   * What it does:
   * Historically forced construction of the (then lazily-constructed)
   * `CAiSiloBuildImplSerializer` singleton from an explicit registration
   * sequence. `gCAiSiloBuildImplSerializer` is now a genuine namespace-scope
   * global, so its constructor already runs unconditionally at static-init
   * time; this call is kept only so `CAiSiloBuildImplTypeInfo.cpp`'s
   * existing bootstrap sequence does not need editing.
   */
  int register_CAiSiloBuildImplSerializer();
} // namespace moho
