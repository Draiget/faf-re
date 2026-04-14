#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitTeleportTask;

  /**
   * VFTABLE: 0x00E20318
   */
  class CUnitTeleportTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0060A8B0 (FUN_0060A8B0)
     */
    CUnitTeleportTaskTypeInfo();

    /**
     * Address: 0x0060A960 (FUN_0060A960, scalar deleting thunk)
     */
    ~CUnitTeleportTaskTypeInfo() override;

    /**
     * Address: 0x0060A950 (FUN_0060A950)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0060A910 (FUN_0060A910)
     */
    void Init() override;

    /**
     * Address: 0x0060C510 (FUN_0060C510, Moho::CUnitTeleportTaskTypeInfo::AddBase_CCommandTask)
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x0060BF50 (FUN_0060BF50, Moho::CUnitTeleportTaskTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x0060C010 (FUN_0060C010, Moho::CUnitTeleportTaskTypeInfo::CtrRef)
     *
     * What it does:
     * Placement-constructs one teleport-task runtime lane in caller storage
     * and returns typed reflection reference.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x0060BFF0 (FUN_0060BFF0, Moho::CUnitTeleportTaskTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x0060C0A0 (FUN_0060C0A0, Moho::CUnitTeleportTaskTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);
  };

  int register_CUnitTeleportTaskTypeInfo();

  static_assert(sizeof(CUnitTeleportTaskTypeInfo) == 0x64, "CUnitTeleportTaskTypeInfo size must be 0x64");
} // namespace moho

