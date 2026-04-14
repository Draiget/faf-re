#include "moho/unit/core/SUnitConstructionParams.h"

namespace moho
{
  /**
   * Address: 0x00585AB0 (FUN_00585AB0, Moho::SUnitConstructionParams::SUnitConstructionParams)
   * Mangled: ??0SUnitConstructionParams@Moho@@QAE@HABUdeprecated_struct_VecQuatB@@PAVCArmyImpl@1@PAVRUnitBlueprint@1@PAVUnit@1@E@Z
   *
   * What it does:
   * Initializes one unit-construction payload from full transform/layer/owner
   * inputs and disables fixed-elevation only for zero layer.
   */
  SUnitConstructionParams::SUnitConstructionParams(
    const std::int32_t layer,
    const VTransform& transform,
    CArmyImpl* const army,
    const RUnitBlueprint* const blueprint,
    Unit* const linkSourceUnit,
    const bool complete
  )
    : mArmy(army)
    , mBlueprint(blueprint)
    , mTransform(transform)
    , mUseLayerOverride(1)
    , mFixElevation(1)
    , pad_26{0, 0}
    , mLayer(layer)
    , mLinkSourceUnit(linkSourceUnit)
    , mComplete(complete ? 1u : 0u)
    , pad_31{0, 0, 0}
  {
    if (layer == 0) {
      mFixElevation = 0;
    }
  }

  /**
   * Address: 0x005F54D0 (FUN_005F54D0, Moho::SUnitConstructionParams::SUnitConstructionParams)
   * Mangled: ??0SUnitConstructionParams@Moho@@QAE@@Z_0
   *
   * What it does:
   * Initializes one unit-construction payload with identity orientation,
   * caller position/layer, and source-unit completion metadata.
   */
  SUnitConstructionParams::SUnitConstructionParams(
    const std::int32_t layer,
    const Wm3::Vector3f& position,
    CArmyImpl* const army,
    const RUnitBlueprint* const blueprint,
    Unit* const linkSourceUnit,
    const bool complete
  )
    : mArmy(army)
    , mBlueprint(blueprint)
    , mTransform{}
    , mUseLayerOverride(0)
    , mFixElevation(1)
    , pad_26{0, 0}
    , mLayer(layer)
    , mLinkSourceUnit(linkSourceUnit)
    , mComplete(complete ? 1u : 0u)
    , pad_31{0, 0, 0}
  {
    mTransform.orient_ = Wm3::Quatf::Identity();
    mTransform.pos_ = position;
    if (layer == 0) {
      mFixElevation = 0;
    }
  }
} // namespace moho
