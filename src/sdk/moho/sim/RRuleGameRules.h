#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "legacy/containers/Tree.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/sim/SRuleFootprintsBlueprint.h"

namespace LuaPlus
{
  class LuaState;
  class LuaObject;
}

namespace gpg
{
  class RType;
}

namespace moho
{
  struct RResId;

  struct RBlueprint;
  struct REntityBlueprint;
  struct RUnitBlueprint;
  struct RPropBlueprint;
  struct RMeshBlueprint;
  struct RProjectileBlueprint;
  struct REmitterBlueprint;
  struct RBeamBlueprint;
  struct RTrailBlueprint;
  struct REffectBlueprint;

  struct RRuleGameRulesBlueprintNode : msvc8::Tree<RRuleGameRulesBlueprintNode>
  {
    msvc8::string mBlueprintId; // +0x0C
    void* mBlueprint;           // +0x28
    std::uint8_t mColor;        // +0x2C
    std::uint8_t mIsSentinel;   // +0x2D
    std::uint8_t pad_2E[2];
  };

  static_assert(sizeof(RRuleGameRulesBlueprintNode) == 0x30, "RRuleGameRulesBlueprintNode size must be 0x30");
  static_assert(
    offsetof(RRuleGameRulesBlueprintNode, mBlueprintId) == 0x0C,
    "RRuleGameRulesBlueprintNode::mBlueprintId offset must be 0x0C"
  );
  static_assert(
    offsetof(RRuleGameRulesBlueprintNode, mBlueprint) == 0x28,
    "RRuleGameRulesBlueprintNode::mBlueprint offset must be 0x28"
  );
  static_assert(
    offsetof(RRuleGameRulesBlueprintNode, mIsSentinel) == 0x2D,
    "RRuleGameRulesBlueprintNode::mIsSentinel offset must be 0x2D"
  );

  struct RRuleGameRulesBlueprintMap
  {
    void* mAllocProxy;                  // +0x00
    RRuleGameRulesBlueprintNode* mHead; // +0x04
    std::uint32_t mSize;                // +0x08
  };

  static_assert(sizeof(RRuleGameRulesBlueprintMap) == 0x0C, "RRuleGameRulesBlueprintMap size must be 0x0C");
  static_assert(
    offsetof(RRuleGameRulesBlueprintMap, mHead) == 0x04, "RRuleGameRulesBlueprintMap::mHead offset must be 0x04"
  );
  static_assert(
    offsetof(RRuleGameRulesBlueprintMap, mSize) == 0x08, "RRuleGameRulesBlueprintMap::mSize offset must be 0x08"
  );

  struct RRuleGameRulesLuaExportBinding
  {
    LuaPlus::LuaState* mRootState; // +0x00
    std::uint32_t mReserved04;     // +0x04
    void* mTaskListSentinel;       // +0x08
    std::uint32_t mTaskListSize;   // +0x0C
  };

  static_assert(sizeof(RRuleGameRulesLuaExportBinding) == 0x10, "RRuleGameRulesLuaExportBinding size must be 0x10");

  struct RRuleGameRulesLuaExportBindingArray
  {
    void* mProxy;                                 // +0x00
    RRuleGameRulesLuaExportBinding* mBegin;       // +0x04
    RRuleGameRulesLuaExportBinding* mEnd;         // +0x08
    RRuleGameRulesLuaExportBinding* mCapacityEnd; // +0x0C
  };

  static_assert(
    sizeof(RRuleGameRulesLuaExportBindingArray) == 0x10, "RRuleGameRulesLuaExportBindingArray size must be 0x10"
  );
  static_assert(
    offsetof(RRuleGameRulesLuaExportBindingArray, mBegin) == 0x04,
    "RRuleGameRulesLuaExportBindingArray::mBegin offset must be 0x04"
  );

  /**
   * VFTABLE: 0x00E1610C
   * COL:  0x00E6A514
   */
  class RRuleGameRules
  {
  public:
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00528080
     * Slot: 0
     */
    virtual ~RRuleGameRules() = default;

    /**
     * Address: 0x00529F70
     * Slot: 1
     */
    virtual void ExportToLuaState(LuaPlus::LuaState*);

    /**
     * Address: 0x0052A3D0
     * Slot: 2
     */
    virtual void UpdateLuaState(LuaPlus::LuaState*);

    /**
     * Address: 0x0052AA20
     * Slot: 3
     */
    virtual void CancelExport(LuaPlus::LuaState*);

    /**
     * Address: 0x005282C0
     * Slot: 4
     */
    virtual int AssignNextOrdinal();

    /**
     * Address: 0x0052B1A0
     * Slot: 5
     */
    virtual RBlueprint* GetBlueprintFromOrdinal(int ordinal) const;

    /**
     * Address: 0x005282E0
     * Slot: 6
     */
    virtual const SRuleFootprintsBlueprint* GetFootprints() const;

    /**
     * Address: 0x0052AAE0
     * Slot: 7
     */
    virtual const SNamedFootprint* FindFootprint(const SFootprint& footprint, const char* name) const;

    /**
     * Address: 0x005282F0
     * Slot: 8
     */
    virtual const RRuleGameRulesBlueprintMap& GetUnitBlueprints();

    /**
     * Address: 0x00528300
     * Slot: 9
     */
    virtual const RRuleGameRulesBlueprintMap& GetPropBlueprints();

    /**
     * Address: 0x00528320
     * Slot: 10
     */
    virtual const RRuleGameRulesBlueprintMap& GetProjectileBlueprints();

    /**
     * Address: 0x00528310
     * Slot: 11
     */
    virtual const RRuleGameRulesBlueprintMap& GetMeshBlueprints();

    /**
     * Address: 0x0052AEB0
     * Slot: 12
     */
    virtual REntityBlueprint* GetEntityBlueprint(const RResId&);

    /**
     * Address: 0x0052AB70
     * Slot: 13
     */
    virtual RUnitBlueprint* GetUnitBlueprint(const RResId&);

    /**
     * Address: 0x0052AD10
     * Slot: 14
     */
    virtual RPropBlueprint* GetPropBlueprint(const RResId&);

    /**
     * Address: 0x0052ADE0
     * Slot: 15
     */
    virtual RMeshBlueprint* GetMeshBlueprint(const RResId&);

    /**
     * Address: 0x0052AC40
     * Slot: 16
     */
    virtual RProjectileBlueprint* GetProjectileBlueprint(const RResId&);

    /**
     * Address: 0x0052AEF0
     * Slot: 17
     */
    virtual REmitterBlueprint* GetEmitterBlueprint(const RResId&);

    /**
     * Address: 0x0052AFC0
     * Slot: 18
     */
    virtual RBeamBlueprint* GetBeamBlueprint(const RResId&);

    /**
     * Address: 0x0052B090
     * Slot: 19
     */
    virtual RTrailBlueprint* GetTrailBlueprint(const RResId&);

    /**
     * Address: 0x0052B160
     * Slot: 20
     */
    virtual REffectBlueprint* GetEffectBlueprint(const RResId&);

    /**
     * Address: 0x00528330
     * Slot: 21
     */
    virtual unsigned int GetUnitCount() const;

    /**
     * Address: 0x0052B1E0
     * Slot: 22
     */
    virtual const CategoryWordRangeView* GetEntityCategory(const char*) const;

    /**
     * Address: 0x0052B280
     * Slot: 23
     */
    virtual CategoryWordRangeView ParseEntityCategory(const char*) const;

    /**
     * Address: 0x0052B2B0
     * Slot: 24
     */
    virtual void UpdateChecksum(void* md5Context, void* fileHandle);

    /**
     * Address: 0x0051CF90 callsite family (func_GetPropBlueprint)
     *
     * What it does:
     * Adapter overload for callsites that still pass a normalized string id.
     */
    RPropBlueprint* GetPropBlueprint(const msvc8::string& blueprintId);
  };

  /**
   * VFTABLE: 0x00E16174
   * COL:  0x00E6A444
   *
   * Recovered concrete runtime rules object used by session/sim pointers.
   */
  class RRuleGameRulesImpl : public RRuleGameRules
  {
  public:
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00529510 (FUN_00529510)
     */
    ~RRuleGameRulesImpl() override;

    /**
     * Address: 0x00529F70 (FUN_00529F70)
     */
    void ExportToLuaState(LuaPlus::LuaState* luaState) override;

    /**
     * Address: 0x0052A3D0 (FUN_0052A3D0)
     */
    void UpdateLuaState(LuaPlus::LuaState* luaState) override;

    /**
     * Address: 0x0052AA20 (FUN_0052AA20)
     */
    void CancelExport(LuaPlus::LuaState* luaState) override;

    /**
     * Address: 0x005282C0 (FUN_005282C0)
     */
    int AssignNextOrdinal() override;

    /**
     * Address: 0x0052B1A0 (FUN_0052B1A0)
     */
    RBlueprint* GetBlueprintFromOrdinal(int ordinal) const override;

    /**
     * Address: 0x005282E0 (FUN_005282E0)
     */
    const SRuleFootprintsBlueprint* GetFootprints() const override;

    /**
     * Address: 0x0052AAE0 (FUN_0052AAE0)
     */
    const SNamedFootprint* FindFootprint(const SFootprint& footprint, const char* name) const override;

    /**
     * Address: 0x005282F0 (FUN_005282F0)
     */
    const RRuleGameRulesBlueprintMap& GetUnitBlueprints() override;

    /**
     * Address: 0x00528300 (FUN_00528300)
     */
    const RRuleGameRulesBlueprintMap& GetPropBlueprints() override;

    /**
     * Address: 0x00528320 (FUN_00528320)
     */
    const RRuleGameRulesBlueprintMap& GetProjectileBlueprints() override;

    /**
     * Address: 0x00528310 (FUN_00528310)
     */
    const RRuleGameRulesBlueprintMap& GetMeshBlueprints() override;

    /**
     * Address: 0x0052AEB0 (FUN_0052AEB0)
     */
    REntityBlueprint* GetEntityBlueprint(const RResId& resId) override;

    /**
     * Address: 0x0052AB70 (FUN_0052AB70)
     */
    RUnitBlueprint* GetUnitBlueprint(const RResId& resId) override;

    /**
     * Address: 0x0052AD10 (FUN_0052AD10)
     */
    RPropBlueprint* GetPropBlueprint(const RResId& resId) override;

    /**
     * Address: 0x0052ADE0 (FUN_0052ADE0)
     */
    RMeshBlueprint* GetMeshBlueprint(const RResId& resId) override;

    /**
     * Address: 0x0052AC40 (FUN_0052AC40)
     */
    RProjectileBlueprint* GetProjectileBlueprint(const RResId& resId) override;

    /**
     * Address: 0x0052AEF0 (FUN_0052AEF0)
     */
    REmitterBlueprint* GetEmitterBlueprint(const RResId& resId) override;

    /**
     * Address: 0x0052AFC0 (FUN_0052AFC0)
     */
    RBeamBlueprint* GetBeamBlueprint(const RResId& resId) override;

    /**
     * Address: 0x0052B090 (FUN_0052B090)
     */
    RTrailBlueprint* GetTrailBlueprint(const RResId& resId) override;

    /**
     * Address: 0x0052B160 (FUN_0052B160)
     */
    REffectBlueprint* GetEffectBlueprint(const RResId& resId) override;

    /**
     * Address: 0x00528330 (FUN_00528330)
     */
    unsigned int GetUnitCount() const override;

    /**
     * Address: 0x0052B1E0 (FUN_0052B1E0)
     */
    const CategoryWordRangeView* GetEntityCategory(const char* categoryName) const override;

    /**
     * Address: 0x0052B280 (FUN_0052B280)
     */
    CategoryWordRangeView ParseEntityCategory(const char* categoryExpression) const override;

    /**
     * Address: 0x0052B2B0 (FUN_0052B2B0)
     */
    void UpdateChecksum(void* md5Context, void* fileHandle) override;

  public:
    std::uint8_t pad_0004[0x34];                      // +0x04
    std::uint8_t mLockStorage[0x08];                  // +0x38
    LuaPlus::LuaState* mLuaState;                     // +0x40
    RRuleGameRulesLuaExportBindingArray mLuaExports;  // +0x44
    SRuleFootprintsBlueprint mFootprints;             // +0x54
    RRuleGameRulesBlueprintMap mUnitBlueprints;       // +0x60
    RRuleGameRulesBlueprintMap mProjectileBlueprints; // +0x6C
    RRuleGameRulesBlueprintMap mPropBlueprints;       // +0x78
    RRuleGameRulesBlueprintMap mMeshBlueprints;       // +0x84
    RRuleGameRulesBlueprintMap mEmitterBlueprints;    // +0x90
    RRuleGameRulesBlueprintMap mBeamBlueprints;       // +0x9C
    RRuleGameRulesBlueprintMap mTrailBlueprints;      // +0xA8
    void* mUnknownB4;                                 // +0xB4
    RBlueprint** mBlueprintByOrdinalBegin;            // +0xB8
    RBlueprint** mBlueprintByOrdinalEnd;              // +0xBC
    RBlueprint** mBlueprintByOrdinalCapacity;         // +0xC0
    void* mEntityCategoryLookup;                      // +0xC4
    void* mPendingBlueprintReloadNext;                // +0xC8
    void* mPendingBlueprintReloadPrev;                // +0xCC
  };

  static_assert(offsetof(RRuleGameRulesImpl, mLuaState) == 0x40, "RRuleGameRulesImpl::mLuaState offset must be 0x40");
  static_assert(
    offsetof(RRuleGameRulesImpl, mLuaExports) == 0x44, "RRuleGameRulesImpl::mLuaExports offset must be 0x44"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mFootprints) == 0x54, "RRuleGameRulesImpl::mFootprints offset must be 0x54"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mUnitBlueprints) == 0x60, "RRuleGameRulesImpl::mUnitBlueprints offset must be 0x60"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mProjectileBlueprints) == 0x6C,
    "RRuleGameRulesImpl::mProjectileBlueprints offset must be 0x6C"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mPropBlueprints) == 0x78, "RRuleGameRulesImpl::mPropBlueprints offset must be 0x78"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mMeshBlueprints) == 0x84, "RRuleGameRulesImpl::mMeshBlueprints offset must be 0x84"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mEmitterBlueprints) == 0x90,
    "RRuleGameRulesImpl::mEmitterBlueprints offset must be 0x90"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mBeamBlueprints) == 0x9C, "RRuleGameRulesImpl::mBeamBlueprints offset must be 0x9C"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mTrailBlueprints) == 0xA8, "RRuleGameRulesImpl::mTrailBlueprints offset must be 0xA8"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mBlueprintByOrdinalBegin) == 0xB8,
    "RRuleGameRulesImpl::mBlueprintByOrdinalBegin offset must be 0xB8"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mBlueprintByOrdinalEnd) == 0xBC,
    "RRuleGameRulesImpl::mBlueprintByOrdinalEnd offset must be 0xBC"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mEntityCategoryLookup) == 0xC4,
    "RRuleGameRulesImpl::mEntityCategoryLookup offset must be 0xC4"
  );
  static_assert(
    offsetof(RRuleGameRulesImpl, mPendingBlueprintReloadNext) == 0xC8,
    "RRuleGameRulesImpl::mPendingBlueprintReloadNext offset must be 0xC8"
  );
  static_assert(sizeof(RRuleGameRulesImpl) == 0xD0, "RRuleGameRulesImpl size must be 0xD0");

  /**
   * Address: 0x0052B960 (FUN_0052B960, ?RULE_GetDefaultPlayerOptions@Moho@@YA?AVLuaObject@LuaPlus@@PAVLuaState@3@@Z)
   *
   * What it does:
   * Imports `/lua/ui/lobby/lobbyComm.lua` and returns `GetDefaultPlayerOptions()` result.
   */
  [[nodiscard]] LuaPlus::LuaObject RULE_GetDefaultPlayerOptions(LuaPlus::LuaState* state);
} // namespace moho
