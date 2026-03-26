#include "moho/sim/ArmyUnitSet.h"

#include <algorithm>
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

  } // namespace

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

    const Entity* const needle = static_cast<const Entity*>(unit);
    const std::uint32_t needleKey = EntitySetSortKey(needle);
    Entity* const* const begin = mVec.begin();
    Entity* const* const end = mVec.end();
    Entity* const* const it = std::lower_bound(begin, end, needleKey, [](const Entity* const candidate, const std::uint32_t key) {
      return EntitySetSortKey(candidate) < key;
    });
    return it != end && *it == needle;
  }

  bool SEntitySetTemplateUnit::AddUnit(Unit* const unit)
  {
    if (!unit) {
      return false;
    }

    Entity* const value = static_cast<Entity*>(unit);
    const std::uint32_t key = EntitySetSortKey(value);
    Entity** const begin = mVec.begin();
    Entity** const end = mVec.end();
    Entity** const it = std::lower_bound(begin, end, key, [](const Entity* const candidate, const std::uint32_t targetId) {
      return EntitySetSortKey(candidate) < targetId;
    });
    if (it != end && *it == value) {
      return false;
    }

    mVec.InsertAt(it, &value, &value + 1);
    return true;
  }

  bool SEntitySetTemplateUnit::RemoveUnit(Unit* const unit)
  {
    if (!unit) {
      return false;
    }

    Entity* const needle = static_cast<Entity*>(unit);
    const std::uint32_t key = EntitySetSortKey(needle);
    Entity** const begin = mVec.begin();
    Entity** const end = mVec.end();
    Entity** const it = std::lower_bound(begin, end, key, [](const Entity* const candidate, const std::uint32_t targetId) {
      return EntitySetSortKey(candidate) < targetId;
    });
    if (it == end || *it != needle) {
      return false;
    }

    (void)mVec.erase(it);
    return true;
  }

  void SEntitySetTemplateUnit::AddUnits(const EntitySetTemplate<Unit>& source)
  {
    for (Entity* const* it = source.begin(); it != source.end(); ++it) {
      Unit* const unit = UnitFromEntry(*it);
      if (unit) {
        (void)AddUnit(unit);
      }
    }
  }

  void SEntitySetTemplateUnit::CopyTo(EntitySetTemplate<Unit>& out) const
  {
    for (Entity* const* it = mVec.begin(); it != mVec.end(); ++it) {
      Unit* const unit = UnitFromEntry(*it);
      if (unit) {
        (void)out.Add(static_cast<Entity*>(unit));
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
        (void)out.Add(static_cast<Entity*>(unit));
      }
    }
  }
} // namespace moho
