#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitCaptureTask;

  /**
   * Type-info owner for `CUnitCaptureTask`.
   */
  class CUnitCaptureTaskTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006041A0 (FUN_006041A0, Moho::CUnitCaptureTaskTypeInfo::Init)
     *
     * What it does:
     * Sets reflected object size/callback lanes, then registers
     * `CCommandTask` and `Listener<ECommandEvent>` bases.
     */
    void Init() override;

    /**
     * Address: 0x00605400 (FUN_00605400, Moho::CUnitCaptureTaskTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CUnitCaptureTask` and returns a typed reflection ref.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x006054A0 (FUN_006054A0, Moho::CUnitCaptureTaskTypeInfo::CtrRef)
     *
     * What it does:
     * Constructs one `CUnitCaptureTask` in caller-provided storage and returns
     * a typed reflection ref.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00605480 (FUN_00605480, Moho::CUnitCaptureTaskTypeInfo::Delete)
     *
     * What it does:
     * Deletes one heap-owned `CUnitCaptureTask`.
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x00605510 (FUN_00605510, Moho::CUnitCaptureTaskTypeInfo::Destruct)
     *
     * What it does:
     * Runs the in-place `CUnitCaptureTask` destructor on placement storage.
     */
    static void Destruct(void* objectStorage);

    /**
     * Address: 0x00605520 (FUN_00605520, Moho::CUnitCaptureTaskTypeInfo::AddBase_CCommandTask)
     *
     * What it does:
     * Registers `CCommandTask` as the primary reflection base.
     */
    static void __stdcall AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x00605580 (FUN_00605580, Moho::CUnitCaptureTaskTypeInfo::AddBase_Listener_ECommandEvent)
     *
     * What it does:
     * Registers `Listener<ECommandEvent>` as the secondary reflection base at
     * offset `0x34`.
     */
    static void __stdcall AddBase_Listener_ECommandEvent(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00604140 (FUN_00604140, preregister_CUnitCaptureTaskTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the startup `CUnitCaptureTaskTypeInfo`
   * reflection lane.
   */
  [[nodiscard]] gpg::RType* preregister_CUnitCaptureTaskTypeInfo();

  static_assert(sizeof(CUnitCaptureTaskTypeInfo) == 0x64, "CUnitCaptureTaskTypeInfo size must be 0x64");
} // namespace moho
