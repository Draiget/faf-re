#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1C150
   * COL:  0x00E713D8
   */
  class CAiNavigatorAirSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCC880 (FUN_00BCC880, dynamic initializer for the global
     * `CAiNavigatorAirSerializer` singleton)
     * Address: 0x005A5700 (FUN_005A5700) -- duplicate emission of the same
     * base-ctor-call + field-set + vtable-install sequence on the identical
     * global (`Moho__CAiNavigatorAirSerializer` at 0x010AEC28 in both
     * bodies), ending in `retn` instead of the `atexit` registration this
     * ctor performs. Zero callers and zero incoming xrefs in the callgraph
     * index; not a distinct source-level call site.
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CAiNavigatorAirSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here.
     */
    CAiNavigatorAirSerializer();

    /**
     * Address: 0x00BF6F70 (FUN_00BF6F70, Moho::CAiNavigatorAirSerializer::~CAiNavigatorAirSerializer)
     * Address: 0x005A5730 (FUN_005A5730), Address: 0x005A5760 (FUN_005A5760)
     * -- duplicate emissions of the same unlink/self-link sequence on the
     * identical global; zero callers and zero incoming xrefs in the
     * callgraph index.
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently sits
     * in and restores a self-linked sentinel state. Registered by the real
     * dynamic initializer (0x00BCC880) as the global's `atexit` teardown.
     */
    ~CAiNavigatorAirSerializer();

    /**
     * Address: 0x005A56D0 (FUN_005A56D0, Moho::CAiNavigatorAirSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiNavigatorAir::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005A56E0 (FUN_005A56E0, Moho::CAiNavigatorAirSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiNavigatorAir::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005A7550 (FUN_005A7550)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiNavigatorAir RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CAiNavigatorAirSerializer, mLoadCallback) == 0x0C,
    "CAiNavigatorAirSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiNavigatorAirSerializer, mSaveCallback) == 0x10,
    "CAiNavigatorAirSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiNavigatorAirSerializer) == 0x14, "CAiNavigatorAirSerializer size must be 0x14");
} // namespace moho
