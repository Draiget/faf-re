#pragma once

#include <cstdint>

#include "legacy/containers/Vector.h"
#include "moho/misc/WeakPtr.h"
#include "moho/sim/SOCellPos.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class RType;
} // namespace gpg

namespace moho
{
  class CUnitCommand;
  class Unit;
  struct RUnitBlueprint;

  /**
   * VFTABLE: 0x00E1B6AC
   * COL:  0x00E70F1C
   */
  class IAiBuilder
  {
  public:
    /**
     * Address: 0x0059ED60 (FUN_0059ED60, ??0IAiBuilder@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes the IAiBuilder interface base lane for derived builders.
     */
    IAiBuilder();

    /**
     * Address: 0x0059ED70 (FUN_0059ED70, scalar deleting thunk)
     *
     * VFTable SLOT: 0
     */
    virtual ~IAiBuilder();

    /**
     * Address: 0x0059FAA0 (FUN_0059FAA0, ?BuilderIsFactory@CAiBuilderImpl@Moho@@UBE_NXZ)
     *
     * VFTable SLOT: 1
     */
    [[nodiscard]]
    virtual bool BuilderIsFactory() const = 0;

    /**
     * Address: 0x0059FA90 (FUN_0059FA90, ?BuilderSetIsFactory@CAiBuilderImpl@Moho@@UAEX_N@Z)
     *
     * VFTable SLOT: 2
     */
    virtual void BuilderSetIsFactory(bool isFactory) = 0;

    /**
     * Address: 0x0059EEF0 (FUN_0059EEF0, ?BuilderSetUpInitialRally@CAiBuilderImpl@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 3
     */
    virtual void BuilderSetUpInitialRally() = 0;

    /**
     * Address: 0x0059F220 (FUN_0059F220, ?BuilderValidateFactoryCommandQueue@CAiBuilderImpl@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 4
     */
    virtual void BuilderValidateFactoryCommandQueue() = 0;

    /**
     * Address: 0x0059F440 (FUN_0059F440, ?BuilderIsFactoryQueueEmpty@CAiBuilderImpl@Moho@@UBE_NXZ)
     *
     * VFTable SLOT: 5
     */
    [[nodiscard]]
    virtual bool BuilderIsFactoryQueueEmpty() const = 0;

    /**
     * Address: 0x0059EED0 (FUN_0059EED0, ?BuilderIsFactoryQueueDirty@CAiBuilderImpl@Moho@@UBE_NXZ)
     *
     * VFTable SLOT: 6
     */
    [[nodiscard]]
    virtual bool BuilderIsFactoryQueueDirty() const = 0;

    /**
     * Address: 0x0059EEE0 (FUN_0059EEE0, ?BuilderSetFactoryQueueDirty@CAiBuilderImpl@Moho@@UAEX_N@Z)
     *
     * VFTable SLOT: 7
     */
    virtual void BuilderSetFactoryQueueDirty(bool dirty) = 0;

    /**
     * Address: 0x0059F470 (FUN_0059F470,
     * ?BuilderGetFactoryCommandQueue@CAiBuilderImpl@Moho@@UAEAAV?$vector@V?$WeakPtr@VCUnitCommand@Moho@@@Moho@@V?$allocator@V?$WeakPtr@VCUnitCommand@Moho@@@Moho@@@std@@@std@@XZ)
     *
     * VFTable SLOT: 8
     */
    [[nodiscard]]
    virtual msvc8::vector<WeakPtr<CUnitCommand>>& BuilderGetFactoryCommandQueue() = 0;

    /**
     * Address: 0x0059F480 (FUN_0059F480, ?BuilderIsBusy@CAiBuilderImpl@Moho@@UBE_NXZ)
     *
     * VFTable SLOT: 9
     */
    [[nodiscard]]
    virtual bool BuilderIsBusy() const = 0;

    /**
     * Address: 0x0059F4D0 (FUN_0059F4D0, ?BuilderAddFactoryCommand@CAiBuilderImpl@Moho@@UAEXPAVCUnitCommand@2@H@Z)
     *
     * VFTable SLOT: 10
     */
    virtual void BuilderAddFactoryCommand(CUnitCommand* command, int index) = 0;

    /**
     * Address: 0x0059F500 (FUN_0059F500, ?BuilderContainsCommand@CAiBuilderImpl@Moho@@UAE_NPAVCUnitCommand@2@@Z)
     *
     * VFTable SLOT: 11
     */
    [[nodiscard]]
    virtual bool BuilderContainsCommand(CUnitCommand* command) = 0;

    /**
     * Address: 0x0059F540 (FUN_0059F540, ?BuilderGetFactoryCommand@CAiBuilderImpl@Moho@@UAEPAVCUnitCommand@2@H@Z)
     *
     * VFTable SLOT: 12
     */
    [[nodiscard]]
    virtual CUnitCommand* BuilderGetFactoryCommand(int index) = 0;

    /**
     * Address: 0x0059F580 (FUN_0059F580, ?BuilderRemoveFactoryCommand@CAiBuilderImpl@Moho@@UAEXPAVCUnitCommand@2@@Z)
     *
     * VFTable SLOT: 13
     */
    virtual void BuilderRemoveFactoryCommand(CUnitCommand* command) = 0;

    /**
     * Address: 0x0059F5A0 (FUN_0059F5A0, ?BuilderClearFactoryCommandQueue@CAiBuilderImpl@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 14
     */
    virtual void BuilderClearFactoryCommandQueue() = 0;

    /**
     * Address: 0x0059F600 (FUN_0059F600, ?BuilderSetAimTarget@CAiBuilderImpl@Moho@@UAEXV?$Vector3@M@Wm3@@@Z)
     *
     * VFTable SLOT: 15
     */
    virtual void BuilderSetAimTarget(Wm3::Vector3f target) = 0;

    /**
     * Address: 0x0059F650 (FUN_0059F650, ?BuilderGetAimTarget@CAiBuilderImpl@Moho@@UBE?AV?$Vector3@M@Wm3@@XZ)
     *
     * VFTable SLOT: 16
     */
    [[nodiscard]]
    virtual Wm3::Vector3f BuilderGetAimTarget() const = 0;

    /**
     * Address: 0x0059F670 (FUN_0059F670, ?BuilderSetOnTarget@CAiBuilderImpl@Moho@@UAEX_N@Z)
     *
     * VFTable SLOT: 17
     */
    virtual void BuilderSetOnTarget(bool onTarget) = 0;

    /**
     * Address: 0x0059F680 (FUN_0059F680, ?BuilderGetOnTarget@CAiBuilderImpl@Moho@@UBE_NXZ)
     *
     * VFTable SLOT: 18
     */
    [[nodiscard]]
    virtual bool BuilderGetOnTarget() const = 0;

    /**
     * Address: 0x0059F690 (FUN_0059F690,
     * ?BuilderAddRebuildStructure@CAiBuilderImpl@Moho@@UAEXABUSOCellPos@2@PBVRUnitBlueprint@2@@Z)
     *
     * VFTable SLOT: 19
     */
    virtual void BuilderAddRebuildStructure(const SOCellPos& cellPos, const RUnitBlueprint* blueprint) = 0;

    /**
     * Address: 0x0059F6C0 (FUN_0059F6C0, ?BuilderRemoveRebuildStructure@CAiBuilderImpl@Moho@@UAEXABUSOCellPos@2@@Z)
     *
     * VFTable SLOT: 20
     */
    virtual void BuilderRemoveRebuildStructure(const SOCellPos& cellPos) = 0;

    /**
     * Address: 0x0059F710 (FUN_0059F710, ?BuilderClearRebuildStructure@CAiBuilderImpl@Moho@@UAEXXZ)
     *
     * VFTable SLOT: 21
     */
    virtual void BuilderClearRebuildStructure() = 0;

    /**
     * Address: 0x0059F740 (FUN_0059F740,
     * ?BuilderGetNextRebuildStructure@CAiBuilderImpl@Moho@@UAEPBVRUnitBlueprint@2@AAUSOCellPos@2@@Z)
     *
     * VFTable SLOT: 22
     */
    [[nodiscard]]
    virtual const RUnitBlueprint* BuilderGetNextRebuildStructure(SOCellPos& outCellPos) = 0;

  public:
    static gpg::RType* sType;
  };

  /**
   * Address: 0x0059FED0 (FUN_0059FED0, ?AI_CreateBuilder@Moho@@YAPAVIAiBuilder@1@PAVUnit@1@@Z)
   *
   * What it does:
   * Allocates one `CAiBuilderImpl` for `unit` and returns it as the
   * `IAiBuilder` interface pointer, preserving null-on-allocation-failure
   * behavior.
   */
  [[nodiscard]] IAiBuilder* AI_CreateBuilder(Unit* unit);

  static_assert(sizeof(IAiBuilder) == 0x04, "IAiBuilder size must be 0x04");
} // namespace moho
