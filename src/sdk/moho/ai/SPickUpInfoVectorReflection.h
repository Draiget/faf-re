#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  struct SPickUpInfo;
}

namespace gpg
{
  /**
   * VFTABLE: 0x00E20DEC (primary, 11 slots) / 0x00E20E1C (RIndexed subobject @ +0x64, 4 slots)
   * COL: gpg::RVectorType<Moho::SPickUpInfo> (reflection of vector<SPickUpInfo>)
   *
   * Reflected descriptor for the intrusive-weak vector `vector<SPickUpInfo>`
   * (element stride 12: WeakPtr<Unit> @+0x00, float @+0x08). The complete-object
   * layout is byte-identical to `RVectorType_ResourceDeposit` (bases
   * `RType`/`RObject`(via RType)/`RIndexed`; size 0x68), but this is a DISTINCT
   * binary class with its own primary + RIndexed vtables and RTTI.
   *
   * Slot map (from rtti_dump_all.hpp @ 0xE20DEC / 0xE20E1C):
   *  primary   0 GetClass            0x401370  (RType base, inherited)
   *  primary   1 GetDerivedObjectRef 0x401390  (RType base, inherited)
   *  primary   2 dtor                0x00628450 (override, defaulted ~RType)
   *  primary   3 GetName             0x00626BA0 (override)
   *  primary   4 GetLexical          0x00626C60 (override)
   *  primary   5 SetLexical          0x8D86E0   (RType base, inherited)
   *  primary   6 IsIndexed           0x00626CF0 (override)
   *  primary   7 IsPointer           0x4013C0   (RType base, inherited)
   *  primary   8 IsEnumType          0x4013D0   (RType base, inherited)
   *  primary   9 Init                0x00626C40 (override)
   *  primary  10 Finish              0x8DF4A0   (RType base, inherited)
   *  secondary 0 SubscriptIndex      0x00626D60 (override)
   *  secondary 1 GetCount            0x00626D00 (override)
   *  secondary 2 SetCount            0x00626D30 (override)
   *  secondary 3 AssignPointer       0x401320   (RIndexed base, inherited)
   */
  class RVectorType_SPickUpInfo final : public RType, public RIndexed
  {
  public:
    /**
     * Address: 0x00626BA0 (FUN_00626BA0, gpg::RVectorType_SPickUpInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00626C60 (FUN_00626C60, gpg::RVectorType_SPickUpInfo::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x00626CF0 (FUN_00626CF0, gpg::RVectorType_SPickUpInfo::IsIndexed)
     */
    [[nodiscard]] const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x00626C40 (FUN_00626C40, gpg::RVectorType_SPickUpInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x006270E0 (FUN_006270E0, gpg::RVectorType_SPickUpInfo::SerLoad)
     */
    static void SerLoad(ReadArchive* archive, int objectPtr, int version, RRef* ownerRef);

    /**
     * Address: 0x00627240 (FUN_00627240, gpg::RVectorType_SPickUpInfo::SerSave)
     */
    static void SerSave(WriteArchive* archive, int objectPtr, int version, RRef* ownerRef);

    /**
     * Address: 0x00626D60 (FUN_00626D60, gpg::RVectorType_SPickUpInfo::SubscriptIndex)
     */
    [[nodiscard]] RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x00626D00 (FUN_00626D00, gpg::RVectorType_SPickUpInfo::GetCount)
     */
    [[nodiscard]] size_t GetCount(void* obj) const override;

    /**
     * Address: 0x00626D30 (FUN_00626D30, gpg::RVectorType_SPickUpInfo::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(RVectorType_SPickUpInfo) == 0x68, "RVectorType_SPickUpInfo size must be 0x68");
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x00628350 (FUN_00628350, preregister_VectorSPickUpInfoType)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for the intrusive-weak
   * `vector<moho::SPickUpInfo>` reflected descriptor.
   */
  [[nodiscard]] gpg::RType* preregister_VectorSPickUpInfoType();

  /**
   * Address: 0x00BD1D50 (FUN_00BD1D50, CRT static-init bootstrap thunk)
   *
   * What it does:
   * Runs the vector<SPickUpInfo> preregistration at process static-init and
   * registers the descriptor teardown with `atexit`.
   */
  int register_VectorSPickUpInfoTypeAtexit();
} // namespace moho
