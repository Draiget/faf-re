#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitCommandTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x006E7E90 (FUN_006E7E90, ??0CUnitCommandTypeInfo@Moho@@QAE@@Z)
     *
     * What it does:
     * Constructs and preregisters reflection metadata for `CUnitCommand`.
     */
    CUnitCommandTypeInfo();

    /**
     * Address: 0x006E7F30 (FUN_006E7F30, Moho::CUnitCommandTypeInfo::dtr)
     */
    ~CUnitCommandTypeInfo() override;

    /**
     * Address: 0x006E7F20 (FUN_006E7F20, Moho::CUnitCommandTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006E7EF0 (FUN_006E7EF0, Moho::CUnitCommandTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x006EB600 (FUN_006EB600, Moho::CUnitCommandTypeInfo::AddBase_CScriptObject)
     */
    static void AddBase_CScriptObject(gpg::RType* typeInfo);

    /**
     * Address: 0x006EB660 (FUN_006EB660, Moho::CUnitCommandTypeInfo::AddBase_Broadcaster_ECommandEvent)
     */
    static void AddBase_Broadcaster_ECommandEvent(gpg::RType* typeInfo);

    /**
     * Address: 0x006E7FD0 (FUN_006E7FD0, sub_6E7FD0)
     *
     * What it does:
     * Applies the recovered base registration pair and version lane.
     */
    static void ApplyLegacyBaseVersionLane(gpg::RType* typeInfo);
  };

  static_assert(sizeof(CUnitCommandTypeInfo) == 0x64, "CUnitCommandTypeInfo size must be 0x64");

  /**
   * Address: 0x00BD8F30 (FUN_00BD8F30, register_CUnitCommandTypeInfo)
   *
   * What it does:
   * Ensures `CUnitCommandTypeInfo` is constructed and registers teardown.
   */
  int register_CUnitCommandTypeInfo();
} // namespace moho
