#include "moho/entity/REntityBlueprint.h"

#include <cmath>

#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/textures/CD3DBatchTexture.h"
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
    : mOwner(nullptr)
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
    , mStrategicIconSortPriority(0)
    , mStrategicIconSortPriorityPad0159_015B{}
    , mStrategicIconRest()
    , mStrategicIconSelected()
    , mStrategicIconOver()
    , mStrategicIconSelectedOver()
  {
    if (owner) {
      // The binary runs RBlueprint's constructor on this very object, whose
      // prefix is the base sub-object. Building a temporary base here and
      // copying out of it counted an extra instance and, worse, ran the base
      // destructor on an object whose vtable word was still null.
      std::int32_t blueprintOrdinal = 0;
      RBlueprint::InitIdentity(owner, resId, mBlueprintId, blueprintOrdinal);
      mOwner = owner;
      mCategoryBitIndex = static_cast<std::uint32_t>(blueprintOrdinal);
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
   * Address: 0x00511E60 (FUN_00511E60, vtable-slot-2 scalar deleting
   * destructor: tail-calls `Moho::REntityBlueprint::~REntityBlueprint(this)`
   * then conditionally frees the object -- ordinary C++ `delete` semantics,
   * not modeled as a separate function here)
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

    /** Where a non-absolute `StrategicIconName` is resolved from. */
    constexpr const char* kStrategicIconDirectory = "/textures/ui/common/game/strategicicons/";

    /**
     * Address: 0x00511B80 (FUN_00511B80, func_LoadStratIcon)
     *
     * IDA signature:
     * boost::shared_ptr_CD3DBatchTexture *__usercall func_LoadStratIcon@<eax>(
     *     std::string *path@<edi>, boost::shared_ptr_CD3DBatchTexture *out, std::string *label);
     *
     * What it does:
     * Loads one strategic-icon texture and names the variant in the failure
     * log. `label` is the quoted variant word the caller passes -- `'rest'`,
     * `'selected'`, `'over'`, `'selected over'` -- so a missing icon reports
     * which of the four it was.
     *
     * The binary returns the out-parameter it was handed; the shared_ptr comes
     * back by value here, which is the same net result now that
     * `CD3DBatchTexture::FromFile` returns one directly.
     */
    [[nodiscard]] boost::shared_ptr<moho::CD3DBatchTexture> LoadStrategicIconTexture(
      const msvc8::string& iconPath,
      const msvc8::string& variantLabel
    )
    {
      boost::shared_ptr<moho::CD3DBatchTexture> icon = moho::CD3DBatchTexture::FromFile(iconPath.c_str(), 0u);
      if (!icon) {
        gpg::Logf("Failed to load %s icon %s", variantLabel.c_str(), iconPath.c_str());
      }

      return icon;
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

    // 0x00512230..0x00512717. Both guards are the binary's: the name has to be
    // non-empty, and an absolute name is left alone entirely -- there is no
    // else branch, so a blueprint naming an absolute icon path simply gets no
    // icons from here.
    if (mStrategicIconName.empty() || FILE_IsAbsolute(mStrategicIconName.c_str())) {
      return;
    }

    const msvc8::string iconBasePath = msvc8::string(kStrategicIconDirectory) + mStrategicIconName;

    mStrategicIconRest = LoadStrategicIconTexture(iconBasePath + "_rest.dds", msvc8::string("'rest'"));
    mStrategicIconSelected =
      LoadStrategicIconTexture(iconBasePath + "_selected.dds", msvc8::string("'selected'"));
    mStrategicIconOver = LoadStrategicIconTexture(iconBasePath + "_over.dds", msvc8::string("'over'"));
    mStrategicIconSelectedOver =
      LoadStrategicIconTexture(iconBasePath + "_selectedover.dds", msvc8::string("'selected over'"));
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
   * Base entity-blueprint unit cast hook. Returns nullptr for the base type;
   * `RUnitBlueprint` overrides it to return itself.
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
