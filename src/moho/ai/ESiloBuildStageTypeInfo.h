#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiSiloBuildImpl.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1DD24
   * COL:  0x00E74BD0
   */
  class ESiloBuildStageTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005CEA80 (FUN_005CEA80, scalar deleting thunk)
     */
    ~ESiloBuildStageTypeInfo() override;

    /**
     * Address: 0x005CEA70 (FUN_005CEA70, ?GetName@ESiloBuildStageTypeInfo@Moho@@UBEPBDXZ)
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005CEA50 (FUN_005CEA50, ?Init@ESiloBuildStageTypeInfo@Moho@@UAEXXZ)
     */
    void Init() override;
  };


  /**
   * Address: 0x00BCE030 (FUN_00BCE030, register_ESiloBuildStageTypeInfo)
   *
   * What it does:
   * Registers `ESiloBuildStage` enum type-info.
   */
  void register_ESiloBuildStageTypeInfo();

  static_assert(sizeof(ESiloBuildStageTypeInfo) == 0x78, "ESiloBuildStageTypeInfo size must be 0x78");
} // namespace moho
