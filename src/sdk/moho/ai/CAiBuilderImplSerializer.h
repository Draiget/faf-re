#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1B80C
   * COL:  0x00E70C9C
   */
  class CAiBuilderImplSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCC320 (FUN_00BCC320, dynamic initializer for the global
     * `CAiBuilderImplSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CAiBuilderImplSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here.
     */
    CAiBuilderImplSerializer();

    /**
     * Address: 0x00BF6AF0 (FUN_00BF6AF0, Moho::CAiBuilderImplSerializer::~CAiBuilderImplSerializer)
     * Address: 0x0059FE70 (FUN_0059FE70), Address: 0x0059FEA0 (FUN_0059FEA0)
     * -- duplicate emissions of the same unlink/self-link sequence hardcoded
     * to the identical global; zero callers and zero incoming xrefs in the
     * callgraph index.
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently sits
     * in and restores a self-linked sentinel state. Registered by the real
     * dynamic initializer (0x00BCC320) as the global's `atexit` teardown.
     */
    ~CAiBuilderImplSerializer();

    /**
     * Address: 0x0059FE20 (FUN_0059FE20, Moho::CAiBuilderImplSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiBuilderImpl::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0059FE30 (FUN_0059FE30, Moho::CAiBuilderImplSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiBuilderImpl::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005A06D0 (FUN_005A06D0)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiBuilderImpl RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CAiBuilderImplSerializer, mLoadCallback) == 0x0C,
    "CAiBuilderImplSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiBuilderImplSerializer, mSaveCallback) == 0x10,
    "CAiBuilderImplSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiBuilderImplSerializer) == 0x14, "CAiBuilderImplSerializer size must be 0x14");
} // namespace moho
