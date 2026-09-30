#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class SerConstructResult;
  class SerSaveConstructArgsResult;
} // namespace gpg

namespace moho
{
  class CUnitCommandQueueTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x006EDAA0 (FUN_006EDAA0, ??0CUnitCommandQueueTypeInfo@Moho@@QAE@@Z)
     */
    CUnitCommandQueueTypeInfo();

    /**
     * Address: 0x006EDB30 (FUN_006EDB30, Moho::CUnitCommandQueueTypeInfo::dtr)
     */
    ~CUnitCommandQueueTypeInfo() override;

    /**
     * Address: 0x006EDB20 (FUN_006EDB20, Moho::CUnitCommandQueueTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006EDB00 (FUN_006EDB00, Moho::CUnitCommandQueueTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x006F8C50 (FUN_006F8C50, Moho::CUnitCommandQueueTypeInfo::AddBase_Broadcaster_EUnitCommandQueueStatus)
     */
    static void AddBase_Broadcaster_EUnitCommandQueueStatus(gpg::RType* typeInfo);
  };

  static_assert(sizeof(CUnitCommandQueueTypeInfo) == 0x64, "CUnitCommandQueueTypeInfo size must be 0x64");

  /**
   * Address: 0x00BD9280 (FUN_00BD9280, register_CUnitCommandQueueTypeInfo)
   */
  void register_CUnitCommandQueueTypeInfo();
} // namespace moho
