#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Owns reflection metadata for `RPropBlueprint`.
   */
  class RPropBlueprintTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0051D950 (FUN_0051D950, Moho::RPropBlueprintTypeInfo::RPropBlueprintTypeInfo)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `RPropBlueprint`.
     */
    RPropBlueprintTypeInfo();

    /**
     * Address: 0x0051DA20 (FUN_0051DA20, Moho::RPropBlueprintTypeInfo::dtr)
     * Slot: 2
     *
     * What it does:
     * Releases base/field reflection vectors and tears down this typeinfo.
     */
    ~RPropBlueprintTypeInfo() override;

    /**
     * Address: 0x0051DA10 (FUN_0051DA10, Moho::RPropBlueprintTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0051D9B0 (FUN_0051D9B0, Moho::RPropBlueprintTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Sets `RPropBlueprint` size, registers `REntityBlueprint` base metadata,
     * and publishes `Display`/`Defense`/`Economy` section fields.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0051DEA0 (FUN_0051DEA0, Moho::RPropBlueprintTypeInfo::AddBase_REntityBlueprint)
     *
     * What it does:
     * Adds `REntityBlueprint` as the reflected base class lane.
     */
    static void AddBaseREntityBlueprint(gpg::RType* typeInfo);

    /**
     * Address: 0x0051DF00 (FUN_0051DF00, gpg::RType::AddField_RPropBlueprintDisplay_0x17CDisplay)
     *
     * What it does:
     * Appends the `Display` reflected field entry (`+0x17C`).
     */
    static gpg::RField* AddFieldDisplay(gpg::RType* typeInfo);

    /**
     * Address: 0x0051DF80 (FUN_0051DF80, gpg::RType::AddField_RPropBlueprintDefense_0x19CDefense)
     *
     * What it does:
     * Appends the `Defense` reflected field entry (`+0x19C`).
     */
    static gpg::RField* AddFieldDefense(gpg::RType* typeInfo);

    /**
     * Address: 0x0051E000 (FUN_0051E000, gpg::RType::AddField_RPropBlueprintEconomy_0x1A4Economy)
     *
     * What it does:
     * Appends the `Economy` reflected field entry (`+0x1A4`).
     */
    static gpg::RField* AddFieldEconomy(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00BC8810 (FUN_00BC8810, register_RPropBlueprintTypeInfo)
   *
   * What it does:
   * Materializes and startup-registers `RPropBlueprintTypeInfo`.
   */
  void register_RPropBlueprintTypeInfo();

  static_assert(sizeof(RPropBlueprintTypeInfo) == 0x64, "RPropBlueprintTypeInfo size must be 0x64");
} // namespace moho
