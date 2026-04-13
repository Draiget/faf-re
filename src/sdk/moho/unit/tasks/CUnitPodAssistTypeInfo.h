#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitPodAssist;

  class CUnitPodAssistTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0061D5A0 (FUN_0061D5A0, sub_61D5A0)
     *
     * What it does:
     * Preregisters `CUnitPodAssist` RTTI into the reflection lookup table.
     */
    CUnitPodAssistTypeInfo();

    /**
     * Address: 0x0061D650 (FUN_0061D650, Moho::CUnitPodAssistTypeInfo::dtr)
     */
    ~CUnitPodAssistTypeInfo() override;

    /**
     * Address: 0x0061D640 (FUN_0061D640, Moho::CUnitPodAssistTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0061D600 (FUN_0061D600, Moho::CUnitPodAssistTypeInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x0061E6F0 (FUN_0061E6F0, Moho::CUnitPodAssistTypeInfo::AddBase_CCommandTask)
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x0061E5B0 (FUN_0061E5B0, Moho::CUnitPodAssistTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x0061E660 (FUN_0061E660, Moho::CUnitPodAssistTypeInfo::CtrRef)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x0061E640 (FUN_0061E640, Moho::CUnitPodAssistTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x0061E6E0 (FUN_0061E6E0, Moho::CUnitPodAssistTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);
  };

  /**
   * Address: 0x00BFA200 (FUN_00BFA200)
   *
   * What it does:
   * Releases reflected base/field buffers for global `CUnitPodAssistTypeInfo`
   * storage.
   */
  void cleanup_CUnitPodAssistTypeInfo();

  /**
   * Address: 0x00BD1570 (FUN_00BD1570, sub_BD1570)
   *
   * What it does:
   * Constructs startup-owned `CUnitPodAssistTypeInfo` and schedules process
   * exit cleanup.
   */
  int register_CUnitPodAssistTypeInfo();

  static_assert(sizeof(CUnitPodAssistTypeInfo) == 0x64, "CUnitPodAssistTypeInfo size must be 0x64");
} // namespace moho

