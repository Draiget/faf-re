#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E2A694
   * COL: 0x00E83C2C
   */
  class UnitTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x006AD090 (FUN_006AD090, Moho::UnitTypeInfo::UnitTypeInfo)
     *
     * What it does:
     * Preregisters RTTI metadata for `Unit` and prepares the type descriptor
     * for startup initialization.
     */
    UnitTypeInfo();

    /**
     * Address: 0x006AD130 (FUN_006AD130, Moho::UnitTypeInfo::dtr)
     *
     * What it does:
     * Releases reflected base/field vectors and tears down the descriptor.
     */
    ~UnitTypeInfo() override;

    /**
     * Address: 0x006AD120 (FUN_006AD120, Moho::UnitTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type name for `Unit`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006AD0F0 (FUN_006AD0F0, Moho::UnitTypeInfo::Init)
     *
     * What it does:
     * Sets reflected size/version metadata, adds `Entity` and `IUnit` bases,
     * and finalizes the RTTI descriptor.
     */
    void Init() override;

  private:
    /**
     * Address: 0x006B0F50 (FUN_006B0F50, Moho::UnitTypeInfo::AddBase_Entity)
     *
     * What it does:
     * Adds `Entity` as a reflected base at offset `8`.
     */
    static void AddBase_Entity(gpg::RType* typeInfo);

    /**
     * Address: 0x006B0FB0 (FUN_006B0FB0, Moho::UnitTypeInfo::AddBase_IUnit)
     *
     * What it does:
     * Adds `IUnit` as a reflected base at offset `0`.
     */
    static void AddBase_IUnit(gpg::RType* typeInfo);
  };

  static_assert(sizeof(UnitTypeInfo) == 0x64, "UnitTypeInfo size must be 0x64");

  /**
   * Address: 0x00BD6AD0 (FUN_00BD6AD0, register_UnitTypeInfo)
   *
   * What it does:
   * Constructs the global `UnitTypeInfo` storage and schedules process-exit
   * cleanup.
   */
  void register_UnitTypeInfo();

  /**
   * Address: 0x00BFD970 (FUN_00BFD970, cleanup_UnitTypeInfo)
   *
   * What it does:
   * Tears down the global `UnitTypeInfo` storage at process exit.
   */
  void cleanup_UnitTypeInfo();
} // namespace moho
