#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitGuardTask;

  /**
   * Type-info owner for `CUnitGuardTask`.
   */
  class CUnitGuardTaskTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00610F30 (FUN_00610F30, Moho::CUnitGuardTaskTypeInfo::Init)
     *
     * What it does:
     * Sets reflected object size/callback lanes, then registers
     * `CCommandTask` and `Listener<ECommandEvent>` bases.
     */
    void Init() override;

    /**
     * Address: 0x00614950 (FUN_00614950, Moho::CUnitGuardTaskTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CUnitGuardTask` and returns a typed reflection ref.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x006149F0 (FUN_006149F0, Moho::CUnitGuardTaskTypeInfo::CtrRef)
     *
     * What it does:
     * Constructs one `CUnitGuardTask` in caller-provided storage and returns a
     * typed reflection ref.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x006149D0 (FUN_006149D0, Moho::CUnitGuardTaskTypeInfo::Delete)
     *
     * What it does:
     * Deletes one heap-owned `CUnitGuardTask`.
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00614A60 (FUN_00614A60, Moho::CUnitGuardTaskTypeInfo::Destruct)
     *
     * What it does:
     * Runs the in-place `CUnitGuardTask` destructor on placement storage.
     */
    static void Destruct(void* objectStorage);

    /**
     * Address: 0x00614A70 (FUN_00614A70, Moho::CUnitGuardTaskTypeInfo::AddBase_CCommandTask)
     *
     * What it does:
     * Registers `CCommandTask` as the primary reflection base.
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x00614AD0 (FUN_00614AD0, Moho::CUnitGuardTaskTypeInfo::AddBase_Listener_ECommandEvent)
     *
     * What it does:
     * Registers `Listener<ECommandEvent>` as the secondary reflection base at
     * offset `0x34`.
     */
    static void __stdcall AddBase_Listener_ECommandEvent(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00610ED0 (FUN_00610ED0, preregister_CUnitGuardTaskTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the startup `CUnitGuardTaskTypeInfo` reflection
   * lane.
   */
  [[nodiscard]] gpg::RType* preregister_CUnitGuardTaskTypeInfo();

  static_assert(sizeof(CUnitGuardTaskTypeInfo) == 0x64, "CUnitGuardTaskTypeInfo size must be 0x64");
} // namespace moho
