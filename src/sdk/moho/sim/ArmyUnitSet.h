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
   * Address context:
   * - 0x0057DDD0 (FUN_0057DDD0, Moho::EntitySetTemplate_Entity::Add)
   * - 0x005E8960 (FUN_005E8960, Moho::EntitySetTemplate_Unit::Contains)
   * - 0x00700A00 (FUN_00700A00)
   * - 0x00700E20 (FUN_00700E20)
   * - 0x00700E70 (FUN_00700E70)
   *
   * What it does:
   * Per-category unit/entity set with intrusive links (TDatList base) and sorted inline-vector storage.
   */
  struct SEntitySetTemplateUnit : TDatList<SEntitySetTemplateUnit, void>
  {
    [[nodiscard]] static Unit* UnitFromEntry(Entity* entity) noexcept;
    [[nodiscard]] static const Unit* UnitFromEntry(const Entity* entity) noexcept;

    [[nodiscard]] bool Empty() const noexcept;
    [[nodiscard]] std::size_t Size() const noexcept;
    void Clear() noexcept;

    [[nodiscard]] bool ContainsEntity(const Entity* entity) const noexcept;
    void AppendUniqueEntity(Entity* entity);

    [[nodiscard]] bool ContainsUnit(const Unit* unit) const noexcept;
    [[nodiscard]] bool AddUnit(Unit* unit);
    [[nodiscard]] bool RemoveUnit(Unit* unit);

    void AddUnits(const EntitySetTemplate<Unit>& source);
    void CopyTo(EntitySetTemplate<Unit>& out) const;
    [[nodiscard]] unsigned int CountLiveUnits() const;
    void CopyLiveUnitsTo(EntitySetTemplate<Unit>& out) const;

    gpg::fastvector_n<Entity*, 4> mVec; // +0x08
  };

  static_assert(offsetof(SEntitySetTemplateUnit, mVec) == 0x08, "SEntitySetTemplateUnit::mVec offset must be 0x08");
  static_assert(sizeof(SEntitySetTemplateUnit) == 0x28, "SEntitySetTemplateUnit size must be 0x28");
} // namespace moho
