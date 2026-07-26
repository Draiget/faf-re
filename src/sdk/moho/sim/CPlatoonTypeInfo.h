#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Reflection type descriptor for the AI platoon aggregate `moho::CPlatoon`.
   */
  class CPlatoonTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00724A60 (FUN_00724A60, construct-and-preregister worker)
     *
     * What it does:
     * Preregisters `CPlatoon` RTTI so lookup resolves to this type helper.
     */
    CPlatoonTypeInfo();

    /**
     * Address: 0x00724AF0 (FUN_00724AF0, scalar deleting thunk)
     * Slot: 2
     */
    ~CPlatoonTypeInfo() override;

    /**
     * Address: 0x00724AE0 (FUN_00724AE0)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type name literal for CPlatoon.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00724AC0 (FUN_00724AC0)
     * Slot: 9
     *
     * What it does:
     * Writes `size_` for CPlatoon, runs base-init, registers the
     * `CScriptObject` reflected base, then finalizes the descriptor.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0072ABD0 (FUN_0072ABD0,
     * ?AddBase_CSCcriptObject@CPlatoonTypeInfo@Moho@@ — the retail symbol
     * carries the doubled-C typo)
     *
     * What it does:
     * Resolves (and caches) the `CScriptObject` reflection type, then appends
     * it as a zero-offset reflected base of this descriptor.
     */
    void AddBaseCScriptObject();
  };

  static_assert(sizeof(CPlatoonTypeInfo) == 0x64, "CPlatoonTypeInfo size must be 0x64");

  /**
   * Address: 0x00BDAC60 (FUN_00BDAC60, register_CPlatoonTypeInfo)
   *
   * What it does:
   * Registers the `CPlatoon` type-info object and installs process-exit cleanup.
   */
  int register_CPlatoonTypeInfo();
} // namespace moho
