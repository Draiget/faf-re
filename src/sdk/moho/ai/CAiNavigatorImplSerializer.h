#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1C0A8
   * COL:  0x00E71774
   */
  class CAiNavigatorImplSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCC720 (FUN_00BCC720, dynamic initializer for the global
     * `CAiNavigatorImplSerializer` singleton)
     * Address: 0x005A3A30 (FUN_005A3A30) -- duplicate emission of the same
     * base-ctor-call + field-set + vtable-install sequence on the identical
     * global (`Moho__CAiNavigatorImplSerializer` at 0x010AE79C in both
     * bodies), ending in `retn` instead of the `atexit` registration this
     * ctor performs. Zero callers and zero incoming xrefs in the callgraph
     * index; not a distinct source-level call site.
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CAiNavigatorImplSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here.
     */
    CAiNavigatorImplSerializer();

    /**
     * Address: 0x00BF6DA0 (FUN_00BF6DA0, Moho::CAiNavigatorImplSerializer::~CAiNavigatorImplSerializer)
     * Address: 0x005A3A60 (FUN_005A3A60), Address: 0x005A3A90 (FUN_005A3A90)
     * -- duplicate emissions of the same unlink/self-link sequence on the
     * identical global; zero callers and zero incoming xrefs in the
     * callgraph index.
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently sits
     * in and restores a self-linked sentinel state. Registered by the real
     * dynamic initializer (0x00BCC720) as the global's `atexit` teardown.
     */
    ~CAiNavigatorImplSerializer();

    /**
     * Address: 0x005A39F0 (FUN_005A39F0, Moho::CAiNavigatorImplSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiNavigatorImpl::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005A3A10 (FUN_005A3A10, Moho::CAiNavigatorImplSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiNavigatorImpl::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005A72A0 (FUN_005A72A0)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiNavigatorImpl RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CAiNavigatorImplSerializer, mLoadCallback) == 0x0C,
    "CAiNavigatorImplSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiNavigatorImplSerializer, mSaveCallback) == 0x10,
    "CAiNavigatorImplSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiNavigatorImplSerializer) == 0x14, "CAiNavigatorImplSerializer size must be 0x14");
} // namespace moho
