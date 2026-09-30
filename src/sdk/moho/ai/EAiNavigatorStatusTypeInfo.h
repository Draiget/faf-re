#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1BFD4
   * COL:  0x00E71A88
   */
  class EAiNavigatorStatusTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005A2EB0 (FUN_005A2EB0, Moho::EAiNavigatorStatusTypeInfo::EAiNavigatorStatusTypeInfo)
     *
     * What it does:
     * Runs the `gpg::REnumType` base constructor, installs this descriptor's
     * vftable (0x00E1BFD4) and pre-registers it against
     * `typeid(EAiNavigatorStatus)` so `gpg::LookupRType` can resolve the enum.
     *
     * The class previously declared no constructor at all, so the implicit one
     * built the base and stopped - the `PreRegisterRType` call at 0x005A2EF3
     * never happened and the descriptor stayed invisible to reflection.
     */
    EAiNavigatorStatusTypeInfo();

    /**
     * Address: 0x005A2F40 (FUN_005A2F40, scalar deleting thunk)
     */
    ~EAiNavigatorStatusTypeInfo() override;

    /**
     * Address: 0x005A2F30 (FUN_005A2F30)
     *
     * What it does:
     * Returns the reflection type name literal for EAiNavigatorStatus.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005A2F10 (FUN_005A2F10)
     *
     * What it does:
     * Writes enum width, registers enum values, then finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x005A2F70 (FUN_005A2F70)
     *
     * What it does:
     * Registers EAiNavigatorStatus enum option names/values.
     */
    void AddEnums();
  };

  static_assert(sizeof(EAiNavigatorStatusTypeInfo) == 0x78, "EAiNavigatorStatusTypeInfo size must be 0x78");


  /**
   * Address: 0x00BCC5E0 (FUN_00BCC5E0, register_EAiNavigatorStatusTypeInfo)
   *
   * What it does:
   * Preregisters startup construction for the `EAiNavigatorStatus` enum RTTI
   * descriptor and installs exit-time teardown.
   */
  void register_EAiNavigatorStatusTypeInfo();
} // namespace moho
