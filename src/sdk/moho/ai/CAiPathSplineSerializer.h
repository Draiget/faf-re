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
   * VFTABLE: 0x00E1C8DC
   * COL:  0x00E726A8
   */
  class CAiPathSplineSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCD350 (FUN_00BCD350, dynamic initializer for the global
     * `CAiPathSplineSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CAiPathSplineSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here.
     */
    CAiPathSplineSerializer();

    /**
     * Address: 0x00BF7540 (FUN_00BF7540, Moho::CAiPathSplineSerializer::~CAiPathSplineSerializer)
     * Address: 0x005B24F0 (FUN_005B24F0), Address: 0x005B2520 (FUN_005B2520)
     * -- duplicate emissions of the same unlink/self-link sequence hardcoded
     * to the identical global; zero callers and zero incoming xrefs in the
     * callgraph index.
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently sits
     * in and restores a self-linked sentinel state. Registered by the real
     * dynamic initializer (0x00BCD350) as the global's `atexit` teardown.
     */
    ~CAiPathSplineSerializer();

    /**
     * Address: 0x005B24A0 (FUN_005B24A0, Moho::CAiPathSplineSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `CAiPathSpline::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005B24B0 (FUN_005B24B0, Moho::CAiPathSplineSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `CAiPathSpline::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005B48E0 (FUN_005B48E0)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiPathSpline RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(offsetof(CAiPathSplineSerializer, mLoadCallback) == 0x0C, "CAiPathSplineSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(CAiPathSplineSerializer, mSaveCallback) == 0x10, "CAiPathSplineSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(CAiPathSplineSerializer) == 0x14, "CAiPathSplineSerializer size must be 0x14");
} // namespace moho
