#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitRefuel;

  class CUnitRefuelTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00621270 (FUN_00621270, sub_621270)
     *
     * What it does:
     * Preregisters `CUnitRefuel` RTTI into the reflection lookup table.
     */
    CUnitRefuelTypeInfo();

    /**
     * Address: 0x00621320 (FUN_00621320, Moho::CUnitRefuelTypeInfo::dtr)
     */
    ~CUnitRefuelTypeInfo() override;

    /**
     * Address: 0x00621310 (FUN_00621310, Moho::CUnitRefuelTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006212D0 (FUN_006212D0, Moho::CUnitRefuelTypeInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x00622400 (FUN_00622400, Moho::CUnitRefuelTypeInfo::AddBase_CCommandTask)
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x006222C0 (FUN_006222C0, Moho::CUnitRefuelTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00622370 (FUN_00622370, Moho::CUnitRefuelTypeInfo::CtrRef)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00622350 (FUN_00622350, Moho::CUnitRefuelTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x006223F0 (FUN_006223F0, Moho::CUnitRefuelTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);
  };

  /**
   * Address: 0x00BFA360 (FUN_00BFA360)
   *
   * What it does:
   * Releases reflected base/field buffers for global `CUnitRefuelTypeInfo`
   * storage.
   */
  void cleanup_CUnitRefuelTypeInfo();

  /**
   * Address: 0x00BD1890 (FUN_00BD1890, sub_BD1890)
   *
   * What it does:
   * Constructs startup-owned `CUnitRefuelTypeInfo` and schedules process exit
   * cleanup.
   */
  int register_CUnitRefuelTypeInfo();

  static_assert(sizeof(CUnitRefuelTypeInfo) == 0x64, "CUnitRefuelTypeInfo size must be 0x64");
} // namespace moho

