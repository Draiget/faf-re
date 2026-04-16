#pragma once

#include <cstddef>

#include "../../gpg/core/containers/FastVector.h"
#include "moho/containers/TDatList.h"

namespace moho
{
  class Entity;
  class Unit;
  template <class T>
  class EntitySetTemplate;

  /**
   * Address: 0x00582EB0 (FUN_00582EB0, func_GetUnitIdPosInVec_BinarySearch)
   *
   * What it does:
   * Returns the lower-bound insertion cursor for `unit` in one sorted
   * `Entity*` span ordered by entity id.
   */
  [[nodiscard]]
  Entity** LowerBoundUnitEntityById(Unit* unit, Entity** vecStart, Entity** vecEnd) noexcept;

  [[nodiscard]]
  Entity* const* LowerBoundUnitEntityById(const Unit* unit, Entity* const* vecStart, Entity* const* vecEnd) noexcept;

  /**
   * Address context:
   * - 0x0057DDD0 (FUN_0057DDD0, Moho::EntitySetTemplate_Unit::Add)
   * - 0x005E8960 (FUN_005E8960, Moho::EntitySetTemplate_Unit::Remove)
   * - 0x00700A00 (FUN_00700A00)
   * - 0x00700E20 (FUN_00700E20)
   * - 0x00700E70 (FUN_00700E70)
   *
   * What it does:
   * Per-category unit/entity set with intrusive links (TDatList base) and sorted inline-vector storage.
   */
  struct SEntitySetTemplateUnit : TDatList<SEntitySetTemplateUnit, void>
  {
    SEntitySetTemplateUnit() = default;

    /**
     * Address: 0x00579500 (FUN_00579500, copy-construct lane)
     *
     * What it does:
     * Reinitializes intrusive links to singleton state and copies entity-set
     * vector storage from `other`.
     */
    SEntitySetTemplateUnit(const SEntitySetTemplateUnit& other);

    [[nodiscard]] static Unit* UnitFromEntry(Entity* entity) noexcept;
    [[nodiscard]] static const Unit* UnitFromEntry(const Entity* entity) noexcept;

    /**
     * Address: 0x005796A0 (FUN_005796A0, Moho::EntitySetTemplate_Entity::~EntitySetTemplate_Entity)
     *
     * What it does:
     * Releases heap-backed set storage (if any), restores inline-vector lanes,
     * and unlinks this intrusive node from its current ring.
     */
    ~SEntitySetTemplateUnit() noexcept;

    [[nodiscard]] bool Empty() const noexcept;
    [[nodiscard]] std::size_t Size() const noexcept;
    void Clear() noexcept;

    [[nodiscard]] bool ContainsEntity(const Entity* entity) const noexcept;
    void AppendUniqueEntity(Entity* entity);

    /**
     * Address: 0x005E89E0 (FUN_005E89E0)
     *
     * What it does:
     * Binary-searches one candidate by unit/entity id and returns true only
     * on exact pointer match.
     */
    [[nodiscard]] bool ContainsUnit(const Unit* unit) const noexcept;
    /**
     * Address: 0x0057DDD0 (FUN_0057DDD0, Moho::EntitySetTemplate_Unit::Add)
     *
     * What it does:
     * Binary-searches one insertion point by entity id, inserts the unit lane
     * (including null-lane sentinel behavior), and reports whether insertion
     * occurred.
     */
    [[nodiscard]] bool AddUnit(Unit* unit);
    /**
     * Address: 0x005E8960 (FUN_005E8960, Moho::EntitySetTemplate_Unit::Remove)
     *
     * What it does:
     * Binary-searches one unit lane by `Entity::id_`, removes one exact unit
     * pointer match when present, and compacts trailing slots.
     */
    [[nodiscard]] bool RemoveUnit(Unit* unit);

    /**
     * Address: 0x006EEC40 (FUN_006EEC40, Moho::EntitySetTemplate_Entity::Same)
     *
     * What it does:
     * Compares two sorted entity-set storages for exact membership equality by
     * lower-bound lookup and exact pointer identity match.
     */
    [[nodiscard]] bool Same(const SEntitySetTemplateUnit& other) const noexcept;

    /**
     * Address: 0x00704070 (FUN_00704070, Moho::EntitySetTemplate_Entity::AddRange)
     *
     * What it does:
     * Iterates one `Entity*` range, resolves live `Unit*` owners, and inserts
     * them into this sorted unit set.
     */
    void AddRange(Entity* const* start, Entity* const* end);

    void AddUnits(const EntitySetTemplate<Unit>& source);
    void CopyTo(EntitySetTemplate<Unit>& out) const;
    [[nodiscard]] unsigned int CountLiveUnits() const;
    void CopyLiveUnitsTo(EntitySetTemplate<Unit>& out) const;

    gpg::fastvector_n<Entity*, 4> mVec; // +0x08
  };

  static_assert(offsetof(SEntitySetTemplateUnit, mVec) == 0x08, "SEntitySetTemplateUnit::mVec offset must be 0x08");
  static_assert(sizeof(SEntitySetTemplateUnit) == 0x28, "SEntitySetTemplateUnit size must be 0x28");
} // namespace moho
