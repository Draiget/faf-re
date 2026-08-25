#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CAiFormationInstanceSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCC150 (FUN_00BCC150, dynamic initializer for the global
     * `CAiFormationInstanceSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CAiFormationInstanceSerializer@Moho@@6B@` -- no eager `Init()`
     * call exists here.
     */
    CAiFormationInstanceSerializer();

    /**
     * Address: 0x00BF67A0 (FUN_00BF67A0, Moho::CAiFormationInstanceSerializer::~CAiFormationInstanceSerializer)
     * Address: 0x0059BF40 (FUN_0059BF40), Address: 0x0059BF70 (FUN_0059BF70)
     * -- duplicate emissions of the same unlink/self-link sequence hardcoded
     * to the identical global; zero callers and zero incoming xrefs in the
     * callgraph index.
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently sits
     * in and restores a self-linked sentinel state. Registered by the real
     * dynamic initializer (0x00BCC150) as the global's `atexit` teardown.
     */
    ~CAiFormationInstanceSerializer();

    /**
     * Address: 0x0059BEE0 (FUN_0059BEE0, Moho::CAiFormationInstanceSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiFormationInstance::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0059BEF0 (FUN_0059BEF0, Moho::CAiFormationInstanceSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiFormationInstance::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0059C820 (FUN_0059C820)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiFormationInstance RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CAiFormationInstanceSerializer, mLoadCallback) == 0x0C,
    "CAiFormationInstanceSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiFormationInstanceSerializer, mSaveCallback) == 0x10,
    "CAiFormationInstanceSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiFormationInstanceSerializer) == 0x14, "CAiFormationInstanceSerializer size must be 0x14");
} // namespace moho
