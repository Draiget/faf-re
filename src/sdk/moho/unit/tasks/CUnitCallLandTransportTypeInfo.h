#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitCallLandTransport;

  class CUnitCallLandTransportTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x006005A0 (FUN_006005A0)
     *
     * What it does:
     * Preregisters RTTI metadata for `CUnitCallLandTransport`.
     */
    CUnitCallLandTransportTypeInfo();

    /**
     * Address: 0x00600650 (FUN_00600650, scalar deleting destructor thunk)
     */
    ~CUnitCallLandTransportTypeInfo() override;

    /**
     * Address: 0x00600640 (FUN_00600640)
     *
     * What it does:
     * Returns the reflected type name literal for `CUnitCallLandTransport`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00600600 (FUN_00600600)
     *
     * What it does:
     * Sets reflected size/callbacks and binds `CCommandTask` as base type.
     */
    void Init() override;

    /**
     * Address: 0x00602E20 (FUN_00602E20, AddBase_CCommandTask)
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x00602880 (FUN_00602880)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00602920 (FUN_00602920)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00602900 (FUN_00602900)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00602990 (FUN_00602990)
     */
    static void Destruct(void* objectStorage);
  };

  /**
   * Address: 0x00BF9650 (FUN_00BF9650, cleanup_CUnitCallLandTransportTypeInfo)
   *
   * What it does:
   * Releases reflected base/field buffers of the global type-info owner.
   */
  void cleanup_CUnitCallLandTransportTypeInfo();

  /**
   * Address: 0x00BCFCA0 (FUN_00BCFCA0, register_CUnitCallLandTransportTypeInfo)
   *
   * What it does:
   * Constructs the global type-info owner and schedules process-exit cleanup.
   */
  int register_CUnitCallLandTransportTypeInfo();

  static_assert(sizeof(CUnitCallLandTransportTypeInfo) == 0x64, "CUnitCallLandTransportTypeInfo size must be 0x64");
} // namespace moho

