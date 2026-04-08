#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/weak_ptr.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/collision/ECollisionShape.h"
#include "moho/sim/SFootprint.h"

namespace gpg
{
  class RType;
}

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
}

namespace moho
{
  class CD3DBatchTexture;
  class RRuleGameRules;
  struct RUnitBlueprint;

  /**
   * Recovered layout prefix for Moho::REntityBlueprint.
   *
   * Verified from constructor/users:
   * - 0x00677360 (`func_FindBlueprintScriptModule`) for script-id/module/class strings
   * - 0x00678370 (`Entity::StandardInit`) for display/name strings
   * - 0x0067AE70 (`Entity::RefreshCollisionShapeFromBlueprint`) for collision block
   * - 0x00678880 (`Entity::GetFootprint`) for footprint offsets
   * - 0x0067B050 (`Entity::IsInCategory`) for category bit index
   */
  struct REntityBlueprint
  {
    void* mVTable;                                            // +0x00
    RRuleGameRules* mOwner;                                   // +0x04 (owner game-rules pointer)
    msvc8::string mBlueprintId;                               // +0x08
    msvc8::string mBlueprintLabel;                            // +0x24 (optional label used by unique-name formatting)
    msvc8::string mSource;                                    // +0x40 (source blueprint path/id string)
    std::uint32_t mCategoryBitIndex;                          // +0x5C
    msvc8::vector<msvc8::string> mCategories;                // +0x60
    msvc8::string mScriptModule;                              // +0x70
    msvc8::string mScriptClass;                               // +0x8C
    ECollisionShape mCollisionShape;                          // +0xA8
    float mSizeX;                                             // +0xAC
    float mSizeY;                                             // +0xB0
    float mSizeZ;                                             // +0xB4
    float mAverageDensity;                                    // +0xB8
    float mInertiaTensorX;                                    // +0xBC
    float mInertiaTensorY;                                    // +0xC0
    float mInertiaTensorZ;                                    // +0xC4
    float mCollisionOffsetX;                                  // +0xC8
    float mCollisionOffsetY;                                  // +0xCC
    float mCollisionOffsetZ;                                  // +0xD0
    std::int32_t mDesiredShooterCap;                          // +0xD4
    SFootprint mFootprint;                                    // +0xD8
    SFootprint mAltFootprint;                                 // +0xE8
    std::uint8_t pad_00F8_013C[0x44];                         // +0xF8
    msvc8::string mStrategicIconName;                         // +0x13C
    std::uint32_t mStrategicIconRuntimeWord;                  // +0x158 (runtime word; semantics unresolved)
    boost::weak_ptr<CD3DBatchTexture> mStrategicIconRest;     // +0x15C
    boost::weak_ptr<CD3DBatchTexture> mStrategicIconSelected; // +0x164
    boost::weak_ptr<CD3DBatchTexture> mStrategicIconOver;     // +0x16C
    boost::weak_ptr<CD3DBatchTexture> mStrategicIconSelectedOver; // +0x174

    static gpg::RType* sType;

    /**
     * Address: 0x00511E80 (FUN_00511E80)
     * Mangled: ??1REntityBlueprint@Moho@@QAE@@Z
     *
     * What it does:
     * Releases strategic-icon weak-pointer lanes, destroys derived entity
     * string/vector fields, then tears down base blueprint ownership lanes.
     */
    ~REntityBlueprint();

    /**
     * Address: 0x00512060 (FUN_00512060)
     *
     * What it does:
     * Initializes default footprint extents and inertia tensor values for
     * entity blueprints before derived blueprint init code runs.
     */
    void OnInitBlueprint();

    /**
     * Address: 0x00511B60 (FUN_00511B60)
     *
     * What it does:
     * Base entity-blueprint mobility query. Returns false for the base type.
     */
    [[nodiscard]] bool IsMobile() const;

    /**
     * Address: 0x00511B70 (FUN_00511B70)
     *
     * What it does:
     * Base entity-blueprint unit cast hook. Returns nullptr for the base type.
     */
    [[nodiscard]] const RUnitBlueprint* IsUnitBlueprint() const;

    /**
     * Address: 0x0050DF90 (FUN_0050DF90, Moho::RBlueprint::GetLuaBlueprint)
     *
     * What it does:
     * Returns `__blueprints[BlueprintOrdinal]` through the base `RBlueprint`
     * layout prefix shared by `REntityBlueprint`.
     */
    [[nodiscard]] LuaPlus::LuaObject GetLuaBlueprint(LuaPlus::LuaState* state) const;
  };

  static_assert(offsetof(REntityBlueprint, mOwner) == 0x04, "REntityBlueprint::mOwner offset must be 0x04");
  static_assert(offsetof(REntityBlueprint, mBlueprintId) == 0x08, "REntityBlueprint::mBlueprintId offset must be 0x08");
  static_assert(
    offsetof(REntityBlueprint, mBlueprintLabel) == 0x24, "REntityBlueprint::mBlueprintLabel offset must be 0x24"
  );
  static_assert(offsetof(REntityBlueprint, mSource) == 0x40, "REntityBlueprint::mSource offset must be 0x40");
  static_assert(
    offsetof(REntityBlueprint, mCategoryBitIndex) == 0x5C, "REntityBlueprint::mCategoryBitIndex offset must be 0x5C"
  );
  static_assert(
    offsetof(REntityBlueprint, mCategories) == 0x60, "REntityBlueprint::mCategories offset must be 0x60"
  );
  static_assert(
    offsetof(REntityBlueprint, mScriptModule) == 0x70, "REntityBlueprint::mScriptModule offset must be 0x70"
  );
  static_assert(offsetof(REntityBlueprint, mScriptClass) == 0x8C, "REntityBlueprint::mScriptClass offset must be 0x8C");
  static_assert(
    offsetof(REntityBlueprint, mCollisionShape) == 0xA8, "REntityBlueprint::mCollisionShape offset must be 0xA8"
  );
  static_assert(offsetof(REntityBlueprint, mSizeX) == 0xAC, "REntityBlueprint::mSizeX offset must be 0xAC");
  static_assert(offsetof(REntityBlueprint, mSizeY) == 0xB0, "REntityBlueprint::mSizeY offset must be 0xB0");
  static_assert(offsetof(REntityBlueprint, mSizeZ) == 0xB4, "REntityBlueprint::mSizeZ offset must be 0xB4");
  static_assert(
    offsetof(REntityBlueprint, mCollisionOffsetX) == 0xC8, "REntityBlueprint::mCollisionOffsetX offset must be 0xC8"
  );
  static_assert(
    offsetof(REntityBlueprint, mDesiredShooterCap) == 0xD4, "REntityBlueprint::mDesiredShooterCap offset must be 0xD4"
  );
  static_assert(offsetof(REntityBlueprint, mFootprint) == 0xD8, "REntityBlueprint::mFootprint offset must be 0xD8");
  static_assert(
    offsetof(REntityBlueprint, mAltFootprint) == 0xE8, "REntityBlueprint::mAltFootprint offset must be 0xE8"
  );
  static_assert(
    offsetof(REntityBlueprint, mStrategicIconName) == 0x13C, "REntityBlueprint::mStrategicIconName offset must be 0x13C"
  );
  static_assert(
    offsetof(REntityBlueprint, mStrategicIconRuntimeWord) == 0x158,
    "REntityBlueprint::mStrategicIconRuntimeWord offset must be 0x158"
  );
  static_assert(
    offsetof(REntityBlueprint, mStrategicIconRest) == 0x15C, "REntityBlueprint::mStrategicIconRest offset must be 0x15C"
  );
  static_assert(
    offsetof(REntityBlueprint, mStrategicIconSelected) == 0x164,
    "REntityBlueprint::mStrategicIconSelected offset must be 0x164"
  );
  static_assert(
    offsetof(REntityBlueprint, mStrategicIconOver) == 0x16C, "REntityBlueprint::mStrategicIconOver offset must be 0x16C"
  );
  static_assert(
    offsetof(REntityBlueprint, mStrategicIconSelectedOver) == 0x174,
    "REntityBlueprint::mStrategicIconSelectedOver offset must be 0x174"
  );
  static_assert(sizeof(REntityBlueprint) == 0x17C, "REntityBlueprint size must be 0x17C");
} // namespace moho
