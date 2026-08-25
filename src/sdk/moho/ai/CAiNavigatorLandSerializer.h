#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1C100
   * COL:  0x00E71580
   */
  class CAiNavigatorLandSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCC7E0 (FUN_00BCC7E0, dynamic initializer for the global
     * `CAiNavigatorLandSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CAiNavigatorLandSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here.
     */
    CAiNavigatorLandSerializer();

    /**
     * Address: 0x00BF6EB0 (FUN_00BF6EB0, Moho::CAiNavigatorLandSerializer::~CAiNavigatorLandSerializer)
     * Address: 0x005A4820 (FUN_005A4820), Address: 0x005A4850 (FUN_005A4850)
     * -- duplicate emissions of the same unlink/self-link sequence hardcoded
     * to the identical global; zero callers and zero incoming xrefs in the
     * callgraph index.
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently sits
     * in and restores a self-linked sentinel state. Registered by the real
     * dynamic initializer (0x00BCC7E0) as the global's `atexit` teardown.
     */
    ~CAiNavigatorLandSerializer();

    /**
     * Address: 0x005A47D0 (FUN_005A47D0, Moho::CAiNavigatorLandSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiNavigatorLand::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005A47E0 (FUN_005A47E0, Moho::CAiNavigatorLandSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiNavigatorLand::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005A7430 (FUN_005A7430)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiNavigatorLand RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CAiNavigatorLandSerializer, mLoadCallback) == 0x0C,
    "CAiNavigatorLandSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiNavigatorLandSerializer, mSaveCallback) == 0x10,
    "CAiNavigatorLandSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiNavigatorLandSerializer) == 0x14, "CAiNavigatorLandSerializer size must be 0x14");
} // namespace moho
