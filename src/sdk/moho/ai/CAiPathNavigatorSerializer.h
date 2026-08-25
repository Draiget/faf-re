#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1C6E4
   * COL:  0x00E723F0
   */
  class CAiPathNavigatorSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCD040 (FUN_00BCD040, dynamic initializer for the global
     * `CAiPathNavigatorSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CAiPathNavigatorSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here.
     */
    CAiPathNavigatorSerializer();

    /**
     * Address: 0x00BF73C0 (FUN_00BF73C0, Moho::CAiPathNavigatorSerializer::~CAiPathNavigatorSerializer)
     * Address: 0x005AFC50 (FUN_005AFC50), Address: 0x005AFC80 (FUN_005AFC80)
     * -- duplicate emissions of the same unlink/self-link sequence hardcoded
     * to the identical global; zero callers and zero incoming xrefs in the
     * callgraph index.
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently sits
     * in and restores a self-linked sentinel state. Registered by the real
     * dynamic initializer (0x00BCD040) as the global's `atexit` teardown.
     */
    ~CAiPathNavigatorSerializer();

    /**
     * Address: 0x005AFBE0 (FUN_005AFBE0, Moho::CAiPathNavigatorSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiPathNavigator::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005AFC00 (FUN_005AFC00, Moho::CAiPathNavigatorSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiPathNavigator::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005B0130 (FUN_005B0130)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiPathNavigator RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CAiPathNavigatorSerializer, mLoadCallback) == 0x0C,
    "CAiPathNavigatorSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiPathNavigatorSerializer, mSaveCallback) == 0x10,
    "CAiPathNavigatorSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiPathNavigatorSerializer) == 0x14, "CAiPathNavigatorSerializer size must be 0x14");
} // namespace moho
