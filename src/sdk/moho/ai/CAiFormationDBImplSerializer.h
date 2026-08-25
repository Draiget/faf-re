#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CAiFormationDBImplSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCC1D0 (FUN_00BCC1D0, dynamic initializer for the global
     * `CAiFormationDBImplSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CAiFormationDBImplSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here.
     */
    CAiFormationDBImplSerializer();

    /**
     * Address: 0x00BF6890 (FUN_00BF6890, Moho::CAiFormationDBImplSerializer::~CAiFormationDBImplSerializer)
     * Address: 0x0059C6C0 (FUN_0059C6C0), Address: 0x0059C6F0 (FUN_0059C6F0)
     * -- duplicate emissions of the same unlink/self-link sequence hardcoded
     * to the identical global; zero callers and zero incoming xrefs in the
     * callgraph index.
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently sits
     * in and restores a self-linked sentinel state. Registered by the real
     * dynamic initializer (0x00BCC1D0) as the global's `atexit` teardown.
     */
    ~CAiFormationDBImplSerializer();

    /**
     * Address: 0x0059C670 (FUN_0059C670, Moho::CAiFormationDBImplSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiFormationDBImpl::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0059C680 (FUN_0059C680, Moho::CAiFormationDBImplSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiFormationDBImpl::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0059CBA0 (FUN_0059CBA0)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiFormationDBImpl RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CAiFormationDBImplSerializer, mLoadCallback) == 0x0C,
    "CAiFormationDBImplSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiFormationDBImplSerializer, mSaveCallback) == 0x10,
    "CAiFormationDBImplSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiFormationDBImplSerializer) == 0x14, "CAiFormationDBImplSerializer size must be 0x14");
} // namespace moho
