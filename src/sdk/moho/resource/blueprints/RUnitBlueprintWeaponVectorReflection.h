#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  struct RUnitBlueprintWeapon;
}

namespace gpg
{
  /**
   * VFTABLE: 0x00E15A58
   * COL: 0x00E6B59C
   */
  class RVectorType_RUnitBlueprintWeapon final : public RType, public RIndexed
  {
  public:
    /**
     * Address: 0x00523490 (FUN_00523490, gpg::RVectorType_RUnitBlueprintWeapon::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00523550 (FUN_00523550, gpg::RVectorType_RUnitBlueprintWeapon::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x005235E0 (FUN_005235E0, gpg::RVectorType_RUnitBlueprintWeapon::IsIndexed)
     */
    [[nodiscard]] const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x00523530 (FUN_00523530, gpg::RVectorType_RUnitBlueprintWeapon::Init)
     */
    void Init() override;

    /**
     * Address: 0x00523D50 (FUN_00523D50, gpg::RVectorType_RUnitBlueprintWeapon::SerLoad)
     */
    static void SerLoad(ReadArchive* archive, int objectPtr, int version, RRef* ownerRef);

    /**
     * Address: 0x00523E80 (FUN_00523E80, gpg::RVectorType_RUnitBlueprintWeapon::SerSave)
     */
    static void SerSave(WriteArchive* archive, int objectPtr, int version, RRef* ownerRef);

    /**
     * Address: 0x00523650 (FUN_00523650, gpg::RVectorType_RUnitBlueprintWeapon::SubscriptIndex)
     */
    [[nodiscard]] RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x005235F0 (FUN_005235F0, gpg::RVectorType_RUnitBlueprintWeapon::GetCount)
     */
    [[nodiscard]] size_t GetCount(void* obj) const override;

    /**
     * Address: 0x00523620 (FUN_00523620, gpg::RVectorType_RUnitBlueprintWeapon::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(RVectorType_RUnitBlueprintWeapon) == 0x68, "RVectorType_RUnitBlueprintWeapon size must be 0x68");
} // namespace gpg

namespace moho
{
  [[nodiscard]] gpg::RType* preregister_VectorRUnitBlueprintWeaponType();

  /**
   * Address: 0x00BC8D30 (FUN_00BC8D30, register_VectorRUnitBlueprintWeaponTypeAtexit)
   *
   * What it does:
   * Startup lane that preregisters `vector<RUnitBlueprintWeapon>` reflection
   * metadata and installs teardown callback.
   */
  int register_VectorRUnitBlueprintWeaponTypeAtexit();
} // namespace moho

