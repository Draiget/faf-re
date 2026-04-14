#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitFormAndMoveTask;

  /**
   * Type-info owner for `CUnitFormAndMoveTask`.
   */
  class CUnitFormAndMoveTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00619850 (FUN_00619850, typeinfo ctor lane)
     *
     * What it does:
     * Constructs one type-info owner and preregisters
     * `CUnitFormAndMoveTask` RTTI binding.
     */
    CUnitFormAndMoveTaskTypeInfo();

    /**
     * Address: 0x00619910 (FUN_00619910, scalar deleting thunk)
     */
    ~CUnitFormAndMoveTaskTypeInfo() override;

    /**
     * Address: 0x00619900 (FUN_00619900, Moho::CUnitFormAndMoveTaskTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type-name literal for `CUnitFormAndMoveTask`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006198B0 (FUN_006198B0, Moho::CUnitFormAndMoveTaskTypeInfo::Init)
     *
     * What it does:
     * Sets reflected size/callback lanes, registers reflected base slices, and
     * finalizes type-info initialization.
     */
    void Init() override;

    /**
     * Address: 0x0061A1B0 (FUN_0061A1B0)
     *
     * What it does:
     * Registers `CCommandTask` as the reflected primary base.
     */
    static void AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x0061A210 (FUN_0061A210)
     *
     * What it does:
     * Registers `Listener<EAiNavigatorEvent>` as reflected secondary base at
     * offset `0x34`.
     */
    static void AddBase_Listener_EAiNavigatorEvent(gpg::RType* typeInfo);

    /**
     * Address: 0x0061A270 (FUN_0061A270)
     *
     * What it does:
     * Registers `Listener<EFormationdStatus>` as reflected secondary base at
     * offset `0x44`.
     */
    static void AddBase_Listener_EFormationdStatus(gpg::RType* typeInfo);

    /**
     * Address: 0x0061A2D0 (FUN_0061A2D0)
     *
     * What it does:
     * Registers `Listener<ECommandEvent>` as reflected secondary base at
     * offset `0x54`.
     */
    static void AddBase_Listener_ECommandEvent(gpg::RType* typeInfo);

    /**
     * Address: 0x00619EF0 (FUN_00619EF0, Moho::CUnitFormAndMoveTaskTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CUnitFormAndMoveTask` and returns a typed reflection ref.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00619F90 (FUN_00619F90, Moho::CUnitFormAndMoveTaskTypeInfo::CtrRef)
     *
     * What it does:
     * Placement-constructs one `CUnitFormAndMoveTask` in caller storage and
     * returns a typed reflection ref.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00619F70 (FUN_00619F70, Moho::CUnitFormAndMoveTaskTypeInfo::Delete)
     *
     * What it does:
     * Deletes one heap-owned `CUnitFormAndMoveTask`.
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x0061A000 (FUN_0061A000, Moho::CUnitFormAndMoveTaskTypeInfo::Destruct)
     *
     * What it does:
     * Runs in-place destructor for one `CUnitFormAndMoveTask` without
     * deallocating storage.
     */
    static void Destruct(void* objectStorage);
  };

  /**
   * Address: 0x00BD1090 (FUN_00BD1090, register_CUnitFormAndMoveTaskTypeInfo)
   *
   * What it does:
   * Constructs the global type-info owner and schedules process-exit cleanup.
   */
  int register_CUnitFormAndMoveTaskTypeInfo();

  static_assert(sizeof(CUnitFormAndMoveTaskTypeInfo) == 0x64, "CUnitFormAndMoveTaskTypeInfo size must be 0x64");
} // namespace moho
