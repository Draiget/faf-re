#include "moho/sim/ArmyUnitSet.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "moho/entity/Entity.h"
#include "moho/unit/core/Unit.h"

namespace moho
{
  namespace
  {
    constexpr std::uintptr_t kEntitySetInvalidEntry = 0x8u;

    [[nodiscard]] bool IsInvalidEntitySetEntry(const Entity* const entity) noexcept
    {
      return !entity || reinterpret_cast<std::uintptr_t>(entity) == kEntitySetInvalidEntry;
    }

    [[nodiscard]] std::uint32_t EntitySetSortKey(const Entity* const entity) noexcept
    {
      if (IsInvalidEntitySetEntry(entity)) {
        return 0u;
      }
      return static_cast<std::uint32_t>(entity->id_);
    }

    /**
     * Address: 0x0057D3F0 (FUN_0057D3F0, gpg::fastvector_n4_Entity::cpy)
     *
     * What it does:
     * Rebinds one destination inline fast-vector lane and copies all entity
     * entries from `source`.
     */
    void CopyEntityInlineVector(
      const gpg::fastvector_n<Entity*, 4>& source,
      gpg::fastvector_n<Entity*, 4>& destination
    )
    {
      destination.ResetStorageToInline();
      destination.reserve(source.size());
      for (Entity* const entity : source) {
        destination.push_back(entity);
      }
    }

    /**
     * Address: 0x005E8900 (FUN_005E8900, erase-and-return-cursor helper)
     *
     * What it does:
     * Erases one slot from the sorted entity vector and returns the stable
     * post-erase cursor position.
     */
    [[nodiscard]] Entity** EraseEntityVectorSlotAndReturnCursor(
      gpg::fastvector_n<Entity*, 4>& entities,
      Entity** const slot
    )
    {
      Entity** const begin = entities.begin();
      Entity** const end = entities.end();
      if (slot == nullptr || slot < begin || slot >= end) {
        return end;
      }

      const std::ptrdiff_t erasedIndex = slot - begin;
      (void)entities.erase(slot);
      Entity** const newBegin = entities.begin();
      Entity** const newEnd = entities.end();
      Entity** const newCursor = newBegin + erasedIndex;
      return (newCursor <= newEnd) ? newCursor : newEnd;
    }

  } // namespace

  /**
   * Address: 0x00582EB0 (FUN_00582EB0, func_GetUnitIdPosInVec_BinarySearch)
   *
   * What it does:
   * Returns the lower-bound insertion cursor for one unit pointer in a sorted
   * `Entity*` span keyed by `Entity::id_`.
   */
  Entity** LowerBoundUnitEntityById(Unit* const unit, Entity** vecStart, Entity** vecEnd) noexcept
  {
    std::ptrdiff_t count = vecEnd - vecStart;
    const std::uint32_t needleKey = EntitySetSortKey(unit ? static_cast<Entity*>(unit) : nullptr);
    while (count > 0) {
      const std::ptrdiff_t step = count / 2;
      Entity* const candidate = vecStart[step];
      if (EntitySetSortKey(candidate) >= needleKey) {
        count = step;
      } else {
        vecStart += step + 1;
        count -= step + 1;
      }
    }

    return vecStart;
  }

  Entity* const* LowerBoundUnitEntityById(
    const Unit* const unit,
    Entity* const* const vecStart,
    Entity* const* const vecEnd
  ) noexcept
  {
    return LowerBoundUnitEntityById(
      const_cast<Unit*>(unit),
      const_cast<Entity**>(vecStart),
      const_cast<Entity**>(vecEnd)
    );
  }

  /**
   * Address: 0x00579500 (FUN_00579500, copy-construct lane)
   *
   * What it does:
   * Resets intrusive links to singleton state and copies entity-set storage
   * from `other`.
   */
  SEntitySetTemplateUnit::SEntitySetTemplateUnit(const SEntitySetTemplateUnit& other)
    : TDatList<SEntitySetTemplateUnit, void>()
    , mVec()
  {
    CopyEntityInlineVector(other.mVec, mVec);
  }

  Unit* SEntitySetTemplateUnit::UnitFromEntry(Entity* const entity) noexcept
  {
    if (IsInvalidEntitySetEntry(entity)) {
      return nullptr;
    }
    return entity->IsUnit();
  }

  const Unit* SEntitySetTemplateUnit::UnitFromEntry(const Entity* const entity) noexcept
  {
    return UnitFromEntry(const_cast<Entity*>(entity));
  }

  /**
   * Address: 0x005796A0 (FUN_005796A0, Moho::EntitySetTemplate_Entity::~EntitySetTemplate_Entity)
   *
   * What it does:
   * Releases heap-backed set storage, restores inline lanes, and unlinks this
   * intrusive node from whatever ring currently owns it.
   */
  SEntitySetTemplateUnit::~SEntitySetTemplateUnit() noexcept
  {
    mVec.ResetStorageToInline();
    this->ListUnlink();
  }

  bool SEntitySetTemplateUnit::Empty() const noexcept
  {
    return mVec.begin() == mVec.end();
  }

  std::size_t SEntitySetTemplateUnit::Size() const noexcept
  {
    return static_cast<std::size_t>(mVec.end() - mVec.begin());
  }

  void SEntitySetTemplateUnit::Clear() noexcept
  {
    mVec.ResetStorageToInline();
  }

  bool SEntitySetTemplateUnit::ContainsEntity(const Entity* const entity) const noexcept
  {
    if (IsInvalidEntitySetEntry(entity)) {
      return false;
    }

    for (Entity* const* it = mVec.begin(); it != mVec.end(); ++it) {
      if (*it == entity) {
        return true;
      }
    }
    return false;
  }

  void SEntitySetTemplateUnit::AppendUniqueEntity(Entity* const entity)
  {
    if (IsInvalidEntitySetEntry(entity) || ContainsEntity(entity)) {
      return;
    }
    mVec.PushBack(entity);
  }

  bool SEntitySetTemplateUnit::ContainsUnit(const Unit* const unit) const noexcept
  {
    if (!unit) {
      return false;
    }

    Entity* const* const begin = mVec.begin();
    Entity* const* const end = mVec.end();
    Entity* const* const it = LowerBoundUnitEntityById(unit, begin, end);
    const Entity* const needle = static_cast<const Entity*>(unit);
    return it != end && *it == needle;
  }

  /**
   * Address: 0x0057DDD0 (FUN_0057DDD0, Moho::EntitySetTemplate_Unit::Add)
   *
   * What it does:
   * Binary-searches one insertion point by entity id, inserts one unit/entity
   * pointer lane when missing, and returns true only when insertion happened.
   */
  bool SEntitySetTemplateUnit::AddUnit(Unit* const unit)
  {
    Entity* const value = unit ? static_cast<Entity*>(unit) : nullptr;
    Entity** const begin = mVec.begin();
    Entity** const end = mVec.end();
    Entity** const it = LowerBoundUnitEntityById(unit, begin, end);
    if (it != end && *it == value) {
      return false;
    }

    mVec.InsertAt(it, &value, &value + 1);
    return true;
  }

  /**
   * Address: 0x005E8960 (FUN_005E8960, Moho::EntitySetTemplate_Unit::Remove)
   *
   * What it does:
   * Binary-searches one candidate slot by `Entity::id_`, verifies exact unit
   * pointer identity, and erases one slot from sorted unit storage.
   */
  bool SEntitySetTemplateUnit::RemoveUnit(Unit* const unit)
  {
    if (!unit) {
      return false;
    }

    Entity* const needle = static_cast<Entity*>(unit);
    Entity** const begin = mVec.begin();
    Entity** const end = mVec.end();
    Entity** const it = LowerBoundUnitEntityById(unit, begin, end);
    if (it == end || *it != needle) {
      return false;
    }

    (void)EraseEntityVectorSlotAndReturnCursor(mVec, it);
    return true;
  }

  /**
   * Address: 0x006EEC40 (FUN_006EEC40, Moho::EntitySetTemplate_Entity::Same)
   *
   * What it does:
   * Compares two sorted entity-set storages for exact membership equality by
   * lower-bound lookup and exact pointer identity match.
   */
  bool SEntitySetTemplateUnit::Same(const SEntitySetTemplateUnit& other) const noexcept
  {
    const Entity* const* const lhsBegin = mVec.begin();
    const Entity* const* const lhsEnd = mVec.end();
    const Entity* const* const rhsBegin = other.mVec.begin();
    const Entity* const* const rhsEnd = other.mVec.end();

    if ((lhsEnd - lhsBegin) != (rhsEnd - rhsBegin)) {
      return false;
    }

    for (const Entity* const* it = lhsBegin; it != lhsEnd; ++it) {
      const std::uint32_t key = EntitySetSortKey(*it);
      const Entity* const* const found =
        std::lower_bound(rhsBegin, rhsEnd, key, [](const Entity* const candidate, const std::uint32_t targetId) {
          return EntitySetSortKey(candidate) < targetId;
        });
      if (found == rhsEnd || *found != *it) {
        return false;
      }
    }

    return true;
  }

  /**
   * Address: 0x00704070 (FUN_00704070, Moho::EntitySetTemplate_Entity::AddRange)
   *
   * What it does:
   * Iterates one `Entity*` range, converts each entry to a `Unit*` owner, and
   * inserts it into this sorted set.
   */
  void SEntitySetTemplateUnit::AddRange(Entity* const* const start, Entity* const* const end)
  {
    for (Entity* const* it = start; it != end; ++it) {
      (void)AddUnit(UnitFromEntry(*it));
    }
  }

  void SEntitySetTemplateUnit::AddUnits(const EntitySetTemplate<Unit>& source)
  {
    for (Unit* const* it = source.begin(); it != source.end(); ++it) {
      (void)AddUnit(*it);
    }
  }

  void SEntitySetTemplateUnit::CopyTo(EntitySetTemplate<Unit>& out) const
  {
    for (Entity* const* it = mVec.begin(); it != mVec.end(); ++it) {
      Unit* const unit = UnitFromEntry(*it);
      if (unit) {
        (void)out.Add(unit);
      }
    }
  }

  unsigned int SEntitySetTemplateUnit::CountLiveUnits() const
  {
    unsigned int count = 0;
    for (Entity* const* it = mVec.begin(); it != mVec.end(); ++it) {
      Unit* const unit = UnitFromEntry(*it);
      if (unit && !unit->IsDead()) {
        ++count;
      }
    }
    return count;
  }

  void SEntitySetTemplateUnit::CopyLiveUnitsTo(EntitySetTemplate<Unit>& out) const
  {
    for (Entity* const* it = mVec.begin(); it != mVec.end(); ++it) {
      Unit* const unit = UnitFromEntry(*it);
      if (unit && !unit->IsDead()) {
        (void)out.Add(unit);
      }
    }
  }
} // namespace moho
