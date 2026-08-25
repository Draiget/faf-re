#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1C40C
   * COL:  0x00E72058
   */
  class CAiPathFinderSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCCD70 (FUN_00BCCD70, dynamic initializer for the global
     * `CAiPathFinderSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CAiPathFinderSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here.
     */
    CAiPathFinderSerializer();

    /**
     * Address: 0x00BF7240 (FUN_00BF7240, Moho::CAiPathFinderSerializer::~CAiPathFinderSerializer)
     * Address: 0x005AAC80 (FUN_005AAC80), Address: 0x005AACB0 (FUN_005AACB0)
     * -- duplicate emissions of the same unlink/self-link sequence hardcoded
     * to the identical global. A further cluster of zero-caller, zero-xref
     * fragments in this address range (0x005AAED0, 0x005AAEE0, 0x005AB1A0,
     * 0x005AB280, 0x005AB2A0, 0x005AB590, 0x005AB5C0, 0x005AB6C0,
     * 0x005AB6D0, 0x005AB830, 0x005AB840) implement the same generic
     * "unlink/self-link a `gpg::SerHelperBase*` node passed in a register"
     * primitive as `gpg::SerHelperBase::ResetLinks()` (canonical body
     * 0x004027D0) -- not hardcoded to this global, so not specific to this
     * class; a prior recovery pass mis-attributed them here as bespoke
     * per-file helpers. None have any caller or incoming xref in the
     * callgraph index.
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently sits
     * in and restores a self-linked sentinel state. Registered by the real
     * dynamic initializer (0x00BCCD70) as the global's `atexit` teardown.
     */
    ~CAiPathFinderSerializer();

    /**
     * Address: 0x005AAC30 (FUN_005AAC30, Moho::CAiPathFinderSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiPathFinder::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005AAC40 (FUN_005AAC40, Moho::CAiPathFinderSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiPathFinder::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005AB210 (FUN_005AB210)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiPathFinder RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CAiPathFinderSerializer, mLoadCallback) == 0x0C,
    "CAiPathFinderSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiPathFinderSerializer, mSaveCallback) == 0x10,
    "CAiPathFinderSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiPathFinderSerializer) == 0x14, "CAiPathFinderSerializer size must be 0x14");
} // namespace moho
