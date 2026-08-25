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
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::ESiloBuildStage,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4ESiloBuildStage@Moho@@H@gpg'`):
   * `FUN_00BCE050` (real, `__xc_a`-reachable, sole writer -- no dead
   * duplicate ctor found). Confirmed via raw asm: default-constructs
   * `gpg::SerHelperBase`, binds `mLoadCallback`/`mSaveCallback` to
   * `FUN_005CFFB0`/`FUN_005CFFD0`, installs the
   * `PrimitiveSerHelper<ESiloBuildStage,int>` vtable, and pushes plain
   * unmangled `FUN_00BF7E10` (bare unlink-then-self-link shape, matching
   * `SerHelperBase::ResetLinks()`) as its `atexit` target -- modeled by the
   * template's own real destructor, no explicit `atexit` call needed.
   *
   * The previous recovery modeled this as a hand-rolled raw-struct mimic of
   * `SerHelperBase` plus a fabricated `register_ESiloBuildStagePrimitiveSerializer()`
   * free function eagerly invoked a second time from this file's own
   * `ESiloBuildStageReflectionBootstrap` constructor -- absent from the
   * real ctor's disassembly; removed.
   */
  using ESiloBuildStagePrimitiveSerializer = gpg::PrimitiveSerHelper<ESiloBuildStage, int>;

  /**
   * Address: 0x00BCE030 (FUN_00BCE030, register_ESiloBuildStageTypeInfo)
   *
   * What it does:
   * Registers `ESiloBuildStage` enum type-info and installs process-exit
   * cleanup.
   */
  int register_ESiloBuildStageTypeInfo();

  static_assert(sizeof(ESiloBuildStageTypeInfo) == 0x78, "ESiloBuildStageTypeInfo size must be 0x78");
} // namespace moho
