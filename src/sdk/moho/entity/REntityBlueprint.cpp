#include "moho/entity/REntityBlueprint.h"

#include <cmath>

#include "lua/LuaObject.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RBlueprint.h"

namespace moho
{
  gpg::RType* REntityBlueprint::sType = nullptr;

  REntityBlueprint::REntityBlueprint()
    : REntityBlueprint(nullptr, RResId{})
  {}

  /**
   * Address: 0x00511C30 (FUN_00511C30)
   * Mangled: ??0REntityBlueprint@Moho@@QAE@@Z
   *
   * What it does:
   * Runs base blueprint construction and seeds entity-blueprint physical,
   * footprint, life-bar, selection, and strategic-icon defaults.
   */
  REntityBlueprint::REntityBlueprint(RRuleGameRules* const owner, const RResId& resId)
    : mVTable(nullptr)
    , mOwner(nullptr)
    , mBlueprintId()
    , mBlueprintLabel()
    , mSource()
    , mCategoryBitIndex(0)
    , mCategories()
    , mScriptModule()
    , mScriptClass()
    , mCollisionShape(ECollisionShape::COLSHAPE_Box)
    , mSizeX(1.0f)
    , mSizeY(1.0f)
    , mSizeZ(1.0f)
    , mAverageDensity(0.49000001f)
    , mInertiaTensorX(0.0f)
    , mInertiaTensorY(0.0f)
    , mInertiaTensorZ(0.0f)
    , mCollisionOffsetX(0.0f)
    , mCollisionOffsetY(0.0f)
    , mCollisionOffsetZ(0.0f)
    , mDesiredShooterCap(3)
    , mFootprint{0, 0, static_cast<EOccupancyCaps>(0), EFootprintFlags::FPFLAG_None, 0.0f, 0.0f, 0.0f}
    , mAltFootprint{0, 0, static_cast<EOccupancyCaps>(0), EFootprintFlags::FPFLAG_None, 0.0f, 0.0f, 0.0f}
    , mLifeBarRender(0)
    , mLifeBarPadding00F9_00FB{0, 0, 0}
    , mLifeBarOffset(0.0f)
    , mLifeBarSize(1.0f)
    , mLifeBarHeight(0.1f)
    , mSelectionSizeX(1.0f)
    , mSelectionSizeY(1.0f)
    , mSelectionSizeZ(1.0f)
    , mSelectionCenterOffsetX(0.0f)
    , mSelectionCenterOffsetY(0.0f)
    , mSelectionCenterOffsetZ(0.0f)
    , mSelectionYOffset(0.5f)
    , mSelectionMeshScaleX(1.0f)
    , mSelectionMeshScaleY(1.0f)
    , mSelectionMeshScaleZ(1.0f)
    , mSelectionMeshUseTopAmount(0.0f)
    , mSelectionThickness(0.0f)
    , mUseOOBTestZoom(0.0f)
    , mStrategicIconName()
    , mStrategicIconRuntimeWord(0)
    , mStrategicIconRest()
    , mStrategicIconSelected()
    , mStrategicIconOver()
    , mStrategicIconSelectedOver()
  {
    if (owner) {
      const RBlueprint base(owner, resId);
      mOwner = base.mOwner;
      mBlueprintId = base.mBlueprintId;
      mBlueprintLabel = base.mDescription;
      mSource = base.mSource;
      mCategoryBitIndex = static_cast<std::uint32_t>(base.mBlueprintOrdinal);
    } else {
      mOwner = nullptr;
      mBlueprintId.clear();
      mBlueprintLabel.clear();
      mSource.clear();
      mCategoryBitIndex = 0;
    }
  }

  /**
   * Address: 0x00511E80 (FUN_00511E80)
   * Mangled: ??1REntityBlueprint@Moho@@QAE@@Z
   *
   * What it does:
   * Releases strategic-icon weak-pointer lanes, destroys derived entity
   * string/vector fields, then tears down base blueprint ownership lanes.
   */
  REntityBlueprint::~REntityBlueprint() = default;

  namespace
  {
    [[nodiscard]] std::uint8_t RoundExtentUpToCellCount(const float extent) noexcept
    {
      return static_cast<std::uint8_t>(static_cast<int>(std::ceil(static_cast<double>(extent))));
    }
  } // namespace

  /**
   * Address: 0x00512060 (FUN_00512060)
   *
   * What it does:
   * Initializes default footprint extents and inertia tensor values for
   * entity blueprints before derived blueprint init code runs.
   */
  void REntityBlueprint::OnInitBlueprint()
  {
    if (mFootprint.mSizeX == 0) {
      mFootprint.mSizeX = RoundExtentUpToCellCount(mSizeX);
    }
    if (mFootprint.mSizeZ == 0) {
      mFootprint.mSizeZ = RoundExtentUpToCellCount(mSizeZ);
    }
    if (mAltFootprint.mSizeX == 0) {
      mAltFootprint.mSizeX = RoundExtentUpToCellCount(mSizeX);
    }
    if (mAltFootprint.mSizeZ == 0) {
      mAltFootprint.mSizeZ = RoundExtentUpToCellCount(mSizeZ);
    }

    if ((mInertiaTensorX * mInertiaTensorY * mInertiaTensorZ) == 0.0f) {
      const float sizeX2 = mSizeX * mSizeX;
      const float sizeY2 = mSizeY * mSizeY;
      const float sizeZ2 = mSizeZ * mSizeZ;
      constexpr float kOneTwelfth = 0.083333336f;

      mInertiaTensorX = (sizeY2 + sizeZ2) * kOneTwelfth;
      mInertiaTensorY = (sizeX2 + sizeZ2) * kOneTwelfth;
      mInertiaTensorZ = (sizeX2 + sizeY2) * kOneTwelfth;
    }

    // NOTE:
    // The strategic icon load path in this function (0x00512230..0x00512717)
    // depends on the render-resource chain rooted at:
    // - 0x00511B80 (FUN_00511B80, helper `func_LoadStratIcon`)
    // - CD3DBatchTexture::FromFile(...)
    // That dependency chain is still under reconstruction.
  }

  /**
   * Address: 0x00511B60 (FUN_00511B60)
   *
   * What it does:
   * Base entity-blueprint mobility query. Returns false for the base type.
   */
  bool REntityBlueprint::IsMobile() const
  {
    return false;
  }

  /**
   * Address: 0x00511B70 (FUN_00511B70)
   *
   * What it does:
   * Base entity-blueprint unit cast hook. Returns nullptr for the base type.
   */
  const RUnitBlueprint* REntityBlueprint::IsUnitBlueprint() const
  {
    return nullptr;
  }

  LuaPlus::LuaObject REntityBlueprint::GetLuaBlueprint(LuaPlus::LuaState* const state) const
  {
    const auto* const baseBlueprint = reinterpret_cast<const RBlueprint*>(this);
    return baseBlueprint->GetLuaBlueprint(state);
  }
} // namespace moho
