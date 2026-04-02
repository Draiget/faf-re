#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CAiFormationDBImplTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x0059C510 (FUN_0059C510, ctor)
     *
     * What it does:
     * Preregisters `CAiFormationDBImpl` RTTI so lookup resolves to this type
     * helper.
     */
    CAiFormationDBImplTypeInfo();

    /**
     * Address: 0x0059C5C0 (FUN_0059C5C0, scalar deleting thunk)
     */
    ~CAiFormationDBImplTypeInfo() override;

    /**
     * Address: 0x0059C5B0 (FUN_0059C5B0, ?GetName@CAiFormationDBImplTypeInfo@Moho@@UBEPBDXZ)
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0059C570 (FUN_0059C570, ?Init@CAiFormationDBImplTypeInfo@Moho@@UAEXXZ)
     */
    void Init() override;
  };

  static_assert(sizeof(CAiFormationDBImplTypeInfo) == 0x64, "CAiFormationDBImplTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCC1B0 (FUN_00BCC1B0, register_CAiFormationDBImplTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `CAiFormationDBImplTypeInfo` storage and installs
   * process-exit cleanup.
   */
  void register_CAiFormationDBImplTypeInfo();

  /**
   * Address: 0x00BCC210 (FUN_00BCC210, register_FastVectorIFormationInstanceTypeAtexit)
   *
   * What it does:
   * Preregisters reflected `gpg::fastvector<IFormationInstance*>` type info
   * and installs process-exit cleanup for that descriptor storage.
   */
  int register_FastVectorIFormationInstanceTypeAtexit();

  /**
   * Address: 0x00BCC230 (FUN_00BCC230, register_CAiFormationDBImplStartupStatsCleanup)
   *
   * What it does:
   * Installs process-exit cleanup for one startup-owned engine-stats slot used
   * by this lane.
   */
  int register_CAiFormationDBImplStartupStatsCleanup();
} // namespace moho
