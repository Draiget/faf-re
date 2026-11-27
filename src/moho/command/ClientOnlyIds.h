#pragma once

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <vector>

#include "moho/command/SSTITarget.h"
#include "moho/containers/BVSet.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityId.h"

namespace moho
{
  /**
   * Engine addition: what exists only on this client must never enter the command stream. Every other client
   * plays the same stream, retail ones included, and none of them knows these ids. Two kinds:
   *
   * - unit ids in the client-only range (`IsClientOnlyUnitId`: the planned factories of `ui_FactoryPreOrders`);
   * - command ids registered here (the helpers that draw a planned factory's rally lines, which are never sent).
   *
   * `CMarshaller`, the one writer of the stream for every driver, drops or filters each message that carries one.
   * A sim unit's or a sent command's id never matches, so for them nothing changes. Lua arguments of a sim callback
   * are the script's own and are not looked into.
   */

  [[nodiscard]] inline bool IsClientOnlyTarget(
    const SSTITarget& target
  ) noexcept
  {
    return target.mType == EAiTargetType::AITARGET_Entity && IsClientOnlyUnitId(target.mEnt);
  }

  /// `entities` without its client-only unit ids: `entities` itself when it has none, else a filtered copy in
  /// `storage`.
  [[nodiscard]] inline const BVSet<EntId, EntIdUniverse>& WithoutClientOnlyUnits(
    const BVSet<EntId, EntIdUniverse>& entities,
    BVSet<EntId, EntIdUniverse>& storage
  )
  {
    const auto isClientOnly = [](const EntId id) {
      return IsClientOnlyUnitId(static_cast<std::uint32_t>(id));
    };
    bool any = false;
    for (const EntId id : entities) {
      if (isClientOnly(id)) {
        any = true;
        break;
      }
    }
    if (!any) {
      return entities;
    }

    storage = entities;
    for (const EntId id : entities) {
      if (isClientOnly(id)) {
        (void)storage.Bits().Remove(static_cast<unsigned int>(id));
      }
    }
    return storage;
  }

  namespace detail
  {
    struct ClientOnlyCommandIds
    {
      std::mutex mutex;
      std::vector<std::int32_t> ids;
      /// Client-only units alive now (their ids are in the client-only range).
      std::vector<std::uint32_t> units;
    };

    [[nodiscard]] inline ClientOnlyCommandIds& GetClientOnlyCommandIds()
    {
      static ClientOnlyCommandIds sIds;
      return sIds;
    }
  } // namespace detail

  inline void RegisterClientOnlyCommand(
    const std::int32_t commandId
  )
  {
    auto& registry = detail::GetClientOnlyCommandIds();
    const std::scoped_lock lock(registry.mutex);
    if (std::ranges::find(registry.ids, commandId) == registry.ids.end()) {
      registry.ids.push_back(commandId);
    }
  }

  inline void ReleaseClientOnlyCommand(
    const std::int32_t commandId
  )
  {
    auto& registry = detail::GetClientOnlyCommandIds();
    const std::scoped_lock lock(registry.mutex);
    std::erase(registry.ids, commandId);
  }

  /// A client-only unit made (its id named in Lua arguments is then dropped with the callback) or gone.
  inline void RegisterClientOnlyUnit(
    const std::uint32_t unitId
  )
  {
    auto& registry = detail::GetClientOnlyCommandIds();
    const std::scoped_lock lock(registry.mutex);
    if (std::ranges::find(registry.units, unitId) == registry.units.end()) {
      registry.units.push_back(unitId);
    }
  }

  inline void ReleaseClientOnlyUnit(
    const std::uint32_t unitId
  )
  {
    auto& registry = detail::GetClientOnlyCommandIds();
    const std::scoped_lock lock(registry.mutex);
    std::erase(registry.units, unitId);
  }

  /// Whether `unitId` is a client-only unit alive now: the test for ids read out of Lua arguments, where a
  /// number in the client-only range may be anything else.
  [[nodiscard]] inline bool IsLiveClientOnlyUnit(
    const std::uint32_t unitId
  )
  {
    if (!IsClientOnlyUnitId(unitId)) {
      return false;
    }
    auto& registry = detail::GetClientOnlyCommandIds();
    const std::scoped_lock lock(registry.mutex);
    return std::ranges::find(registry.units, unitId) != registry.units.end();
  }

  [[nodiscard]] inline bool IsClientOnlyCommand(
    const std::int32_t commandId
  )
  {
    auto& registry = detail::GetClientOnlyCommandIds();
    const std::scoped_lock lock(registry.mutex);
    return std::ranges::find(registry.ids, commandId) != registry.ids.end();
  }
} // namespace moho
