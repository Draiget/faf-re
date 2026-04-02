#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitCallTransport;

  class CUnitCallTransportTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005FF990 (FUN_005FF990)
     *
     * What it does:
     * Preregisters RTTI metadata for `CUnitCallTransport`.
     */
    CUnitCallTransportTypeInfo();

    /**
     * Address: 0x005FFA40 (FUN_005FFA40, scalar deleting destructor thunk)
     */
    ~CUnitCallTransportTypeInfo() override;

    /**
     * Address: 0x005FFA30 (FUN_005FFA30)
     *
     * What it does:
     * Returns the reflected type name literal for `CUnitCallTransport`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005FF9F0 (FUN_005FF9F0)
     *
     * What it does:
     * Sets reflected size/callbacks and binds `CCommandTask` as base type.
     */
    void Init() override;

    /**
     * Address: 0x00602C20 (FUN_00602C20, AddBase_CCommandTask)
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x00602760 (FUN_00602760)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00602800 (FUN_00602800)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x006027E0 (FUN_006027E0)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00602870 (FUN_00602870)
     */
    static void Destruct(void* objectStorage);
  };

  /**
   * Address: 0x00BF95C0 (FUN_00BF95C0, cleanup_CUnitCallTransportTypeInfo)
   *
   * What it does:
   * Releases reflected base/field buffers of the global type-info owner.
   */
  void cleanup_CUnitCallTransportTypeInfo();

  /**
   * Address: 0x00BCFC40 (FUN_00BCFC40, register_CUnitCallTransportTypeInfo)
   *
   * What it does:
   * Constructs the global type-info owner and schedules process-exit cleanup.
   */
  int register_CUnitCallTransportTypeInfo();

  static_assert(sizeof(CUnitCallTransportTypeInfo) == 0x64, "CUnitCallTransportTypeInfo size must be 0x64");
} // namespace moho

