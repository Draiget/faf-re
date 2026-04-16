#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CameraImplTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x007AAF30 (FUN_007AAF30, Moho::CameraImplTypeInfo::CameraImplTypeInfo)
     */
    CameraImplTypeInfo();

    /**
     * Address: 0x007AAFD0 (FUN_007AAFD0, scalar deleting thunk)
     */
    ~CameraImplTypeInfo() override;

    /**
     * Address: 0x007AAFC0 (FUN_007AAFC0, Moho::CameraImplTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x007AAF90 (FUN_007AAF90, Moho::CameraImplTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(CameraImplTypeInfo) == 0x64, "CameraImplTypeInfo size must be 0x64");

  /**
   * Address: 0x00BDF5C0 (FUN_00BDF5C0, register_CameraImplTypeInfo)
   */
  void register_CameraImplTypeInfoStartup();
} // namespace moho
