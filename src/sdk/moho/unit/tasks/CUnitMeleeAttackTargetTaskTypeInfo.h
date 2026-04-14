#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CUnitMeleeAttackTargetTask;

  /**
   * Type-info owner for `CUnitMeleeAttackTargetTask`.
   */
  class CUnitMeleeAttackTargetTaskTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00615270 (FUN_00615270)
     *
     * What it does:
     * Preregisters `CUnitMeleeAttackTargetTask` RTTI into the reflection
     * lookup table.
     */
    CUnitMeleeAttackTargetTaskTypeInfo();

    /**
     * Address: 0x00615330 (FUN_00615330, scalar deleting thunk)
     */
    ~CUnitMeleeAttackTargetTaskTypeInfo() override;

    /**
     * Address: 0x00615320 (FUN_00615320)
     *
     * What it does:
     * Returns the reflected type name literal for
     * `CUnitMeleeAttackTargetTask`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006152D0 (FUN_006152D0, Moho::CUnitMeleeAttackTargetTaskTypeInfo::Init)
     *
     * What it does:
     * Sets reflected size (0x90), wires allocator callbacks, registers base
     * lanes, then finalizes reflection metadata.
     */
    void Init() override;

    /**
     * Address: 0x006179C0 (FUN_006179C0, Moho::CUnitMeleeAttackTargetTaskTypeInfo::AddBase_CCommandTask)
     *
     * What it does:
     * Registers `CCommandTask` as the primary reflection base.
     */
    static void AddBase_CCommandTask(gpg::RType* typeInfo);

    /**
     * Address: 0x00617A20 (FUN_00617A20, Moho::CUnitMeleeAttackTargetTaskTypeInfo::AddBase_Listener_EAiAttackerEvent)
     *
     * What it does:
     * Registers `Listener<EAiAttackerEvent>` as a secondary base at offset
     * `0x34`.
     */
    static void AddBase_Listener_EAiAttackerEvent(gpg::RType* typeInfo);

    /**
     * Address: 0x00617A80 (FUN_00617A80, Moho::CUnitMeleeAttackTargetTaskTypeInfo::AddBase_Listener_ECommandEvent)
     *
     * What it does:
     * Registers `Listener<ECommandEvent>` as a secondary base at offset
     * `0x44`.
     */
    static void AddBase_Listener_ECommandEvent(gpg::RType* typeInfo);

    /**
     * Address: 0x006178A0 (FUN_006178A0, Moho::CUnitMeleeAttackTargetTaskTypeInfo::NewRef)
     *
     * What it does:
     * Allocates one `CUnitMeleeAttackTargetTask` and returns a typed reflection ref.
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x00617940 (FUN_00617940, Moho::CUnitMeleeAttackTargetTaskTypeInfo::CtrRef)
     *
     * What it does:
     * Placement-constructs one `CUnitMeleeAttackTargetTask` in caller-provided
     * storage and returns typed reflection ref.
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x00617920 (FUN_00617920, Moho::CUnitMeleeAttackTargetTaskTypeInfo::Delete)
     *
     * What it does:
     * Deletes one heap-owned `CUnitMeleeAttackTargetTask`.
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x006179B0 (FUN_006179B0, Moho::CUnitMeleeAttackTargetTaskTypeInfo::Destruct)
     *
     * What it does:
     * Runs in-place destructor for one `CUnitMeleeAttackTargetTask` without
     * deallocating storage.
     */
    static void Destruct(void* objectStorage);
  };

  static_assert(sizeof(CUnitMeleeAttackTargetTaskTypeInfo) == 0x64, "CUnitMeleeAttackTargetTaskTypeInfo size must be 0x64");
} // namespace moho
