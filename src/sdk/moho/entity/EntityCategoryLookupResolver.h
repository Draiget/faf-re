#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/entity/EntityCategoryReflection.h"

namespace moho
{
  struct SFootprint;
  struct SNamedFootprint;
  struct SRuleFootprintsBlueprint;

  /**
   * Interface view for Sim::mRules vtable walk used by Entity::IsInCategory.
   *
   * Cross-evidence:
   * - Entity::IsInCategory uses vtbl offset +0x58.
   * - emit/RTTI for RRuleGameRulesImpl maps slot22 to GetEntityCategory(char const*).
   */
  class EntityCategoryLookupResolver
  {
  public:
    /**
     * Address: 0x00529510 (RRuleGameRulesImpl dtr)
     * VTable slot: 0
     */
    virtual ~EntityCategoryLookupResolver() = default;

    /**
     * Address: 0x00529F70
     * VTable slot: 1
     */
    virtual void ExportToLuaState(void* luaState) = 0;

    /**
     * Address: 0x0052A3D0
     * VTable slot: 2
     */
    virtual void UpdateLuaState(void* luaState) = 0;

    /**
     * Address: 0x0052AA20
     * VTable slot: 3
     */
    virtual void CancelExport(void* luaState) = 0;

    /**
     * Address: 0x005282C0
     * VTable slot: 4
     */
    virtual int AssignNextOrdinal() = 0;

    /**
     * Address: 0x0052B1A0
     * VTable slot: 5
     */
    virtual void* GetBlueprintFromOrdinal(int ordinal) const = 0;

    /**
     * Address: 0x005282E0
     * VTable slot: 6
     */
    virtual const SRuleFootprintsBlueprint* GetFootprints() const = 0;

    /**
     * Address: 0x0052AAE0
     * VTable slot: 7
     */
    virtual const SNamedFootprint* FindFootprint(const SFootprint& footprint, const char* name) const = 0;

    /**
     * Address: 0x00528300
     * VTable slot: 8
     */
    virtual const void* GetUnitBlueprints() = 0;

    /**
     * Address: 0x00528300
     * VTable slot: 9
     */
    virtual const void* GetPropBlueprints() = 0;

    /**
     * Address: 0x00528320
     * VTable slot: 10
     */
    virtual const void* GetProjectileBlueprints() = 0;

    /**
     * Address: 0x00528310
     * VTable slot: 11
     */
    virtual const void* GetMeshBlueprints() = 0;

    /**
     * Address: 0x0052AEB0
     * VTable slot: 12
     */
    virtual void* GetEntityBlueprint(const void* resId) = 0;

    /**
     * Address: 0x0052AB70
     * VTable slot: 13
     */
    virtual void* GetUnitBlueprint(const void* resId) = 0;

    /**
     * Address: 0x0052AD10
     * VTable slot: 14
     */
    virtual void* GetPropBlueprint(const void* resId) = 0;

    /**
     * Address: 0x0052ADE0
     * VTable slot: 15
     */
    virtual void* GetMeshBlueprint(const void* resId) = 0;

    /**
     * Address: 0x0052AC40
     * VTable slot: 16
     */
    virtual void* GetProjectileBlueprint(const void* resId) = 0;

    /**
     * Address: 0x0052AEF0
     * VTable slot: 17
     */
    virtual void* GetEmitterBlueprint(const void* resId) = 0;

    /**
     * Address: 0x0052AFC0
     * VTable slot: 18
     */
    virtual void* GetBeamBlueprint(const void* resId) = 0;

    /**
     * Address: 0x0052B090
     * VTable slot: 19
     */
    virtual void* GetTrailBlueprint(const void* resId) = 0;

    /**
     * Address: 0x0052B160
     * VTable slot: 20
     */
    virtual void* GetEffectBlueprint(const void* resId) = 0;

    /**
     * Address: 0x00528330
     * VTable slot: 21
     */
    virtual unsigned int GetUnitCount() const = 0;

    /**
     * Address: 0x0052B1E0
     * VTable slot: 22 (offset +0x58).
     *
     * IDA signature:
     * char* __thiscall sub_52B1E0(_DWORD* this, char* source);
     *
     * What it does:
     * Resolves category text to a precomputed category-word range view from
     * RRuleGameRulesImpl category lookup map.
     */
    virtual const CategoryWordRangeView* GetEntityCategory(const char*) const;

    /**
     * Address: 0x0052B280 (FUN_0052B280)
     * VTable slot: 23
     *
     * IDA signature:
     * int __thiscall sub_52B280(_DWORD* this, int out, int source);
     *
     * What it does:
     * Parses category expression into a category-word range set.
     */
    virtual CategoryWordRangeView ParseEntityCategory(const char*) const;

    /**
     * Address: 0x0052B2B0
     * VTable slot: 24
     */
    virtual void UpdateChecksum(void* md5Context, void* fileHandle) = 0;
  };
} // namespace moho
