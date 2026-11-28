#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "gpg/core/containers/FastVector.h"
#include "moho/entity/EntityId.h"
#include "moho/math/Vector3f.h"

namespace moho
{
  [[nodiscard]] bool IsFactoryPreOrdersEnabled();
  void SetFactoryPreOrdersEnabled(bool enabled);

  struct REntityBlueprint;
  struct GeomCamera3;
  struct SSTICommandIssueData;
  struct SSTITarget;
  class CWldSession;
  class UserUnit;
  enum class EUnitCommandType : std::int32_t;
  enum class EAiTargetType : std::int32_t;

  /**
   * Engine addition (`ui_FactoryPreOrders`): one rally order given to a planned factory, sent to the real
   * factory once its construction starts.
   */
  struct RallyPointOrder
  {
    EUnitCommandType commandType{};
    EAiTargetType targetType{};
    Vector3f position{Vector3f::ZERO};
    std::uint32_t targetEntityId{0};
    /// The command id of the helper that draws this order's line (`IsClientOnlyCommand`), or 0.
    std::int32_t helperId{0};
  };

  /**
   * Engine addition (`ui_FactoryPreOrders`): a factory an engineer of the focus army has been ordered to
   * build and has not started. It is shown and selected through a client-only `UserUnit` (`mUserUnit`) whose
   * id lies in the client-only unit range (`IsClientOnlyUnitId`), so the construction panel, the queue
   * display and the rally lines work on it like on a factory. Its orders are kept here and sent to the
   * real factory when that appears; nothing about it reaches the sim before.
   */
  struct PlannedUnitProxy
  {
    struct PreOrder
    {
      std::string blueprintId{};
      std::int32_t count{1};

      bool operator==(const PreOrder& other) const noexcept = default;
    };

    /// One engineer's build command for this factory. `missedBeats` counts beats in a row in which that
    /// command was not in the engineer's queue; a short gap is tolerated while the queue is re-synced.
    struct Builder
    {
      std::uint32_t builderId{0};
      std::int32_t commandId{0};
      std::uint8_t missedBeats{0};
    };

    /// Slot of the client-only unit id (`MakePlannedProxyUnitId`), unique among live proxies.
    std::uint32_t mProxyId{0};
    const REntityBlueprint* mBlueprint{nullptr};
    Vector3f mPosition{Vector3f::ZERO};

    std::vector<PreOrder> mPreOrders{};
    std::vector<RallyPointOrder> mRallyOrders{};
    bool mRepeatBuild{false};
    std::vector<Builder> mBuilders{};

    /// The client-only unit. It sits in the session's entity map like the sim's units; the proxy only points
    /// at it, and removes it itself when the plan goes during a game (`Destroy`).
    UserUnit* mUserUnit{nullptr};

    void AddPreOrder(const std::string& bpId, std::int32_t count = 1);
    bool RemovePreOrderByIndex(std::size_t index, std::int32_t count);
    void ClearPreOrders() noexcept;

    void AddRallyOrder(const RallyPointOrder& order, bool clear);
    void ClearRallyOrders() noexcept;

    [[nodiscard]] bool HasBuilder(std::uint32_t builderId, std::int32_t commandId) const noexcept;
    void AddBuilder(std::uint32_t builderId, std::int32_t commandId);
    /// Removes every command of `builderId`; returns whether one was removed.
    bool RemoveBuilder(std::uint32_t builderId);
    /// The first builder still listed, or 0.
    [[nodiscard]] std::uint32_t FirstBuilderId() const noexcept;
  };

  /// Most live planned factories at once: the size of the client-only serial range.
  inline constexpr std::uint32_t kMaxPlannedProxies = kClientOnlyUnitSerialCount;

  /// The client-only unit id of proxy slot `proxyId` in army `armyIndex`.
  [[nodiscard]] constexpr std::uint32_t MakePlannedProxyUnitId(
    const std::uint8_t armyIndex,
    const std::uint32_t proxyId
  ) noexcept
  {
    return MakeEntityId(EEntityIdFamily::Unit, armyIndex, kClientOnlyUnitSerialBase + proxyId);
  }

  /**
   * Engine addition (`ui_FactoryPreOrders`): the planned factories of the focus army and their orders.
   *
   * Lifetime: proxies are created from `ISSUE_Command`, and destroyed only in `Update` (once per beat, after
   * the units' ticks) or dropped by `ForgetAll` when the session ends. `Update` sends a proxy's orders to the
   * new unit that has its blueprint and position, and drops a proxy none of whose build commands is still in
   * its engineer's queue.
   */
  class PlannedFactoryManager
  {
  public:
    PlannedFactoryManager() = default;
    PlannedFactoryManager(const PlannedFactoryManager&) = delete;
    PlannedFactoryManager& operator=(const PlannedFactoryManager&) = delete;

    [[nodiscard]] static PlannedFactoryManager& Get() noexcept;

    /// Whether `unit` is a planned factory's client-only unit. Its id says so; no sim unit has such an id.
    [[nodiscard]] static bool IsPlannedProxyUnit(const UserUnit* unit) noexcept;

    /// Whether any unit in `units` is a planned factory's client-only unit.
    [[nodiscard]] static bool AnyPlannedProxyUnit(const gpg::fastvector<UserUnit*>& units) noexcept;

    /**
     * Called by `ISSUE_Command` after an engineer's build order: registers a planned factory for each
     * builder of the focus army when `bp` is a factory, or adds the builders to the one already planned at
     * that spot. Does nothing in a replay, without a focus army, or when a unit with that blueprint already
     * stands there (it is being built, and takes orders itself).
     */
    void OnBuildOrderIssued(
      CWldSession& session,
      const gpg::fastvector<UserUnit*>& builders,
      std::int32_t commandId,
      const REntityBlueprint* bp,
      const Vector3f& pos
    );

    /**
     * The proxy half of `ISSUE_Command`: production orders and move orders given to planned factories.
     * Returns false when the order has no meaning for a planned factory.
     */
    bool OnProxyCommand(
      CWldSession& session,
      const gpg::fastvector<UserUnit*>& proxyUnits,
      const SSTICommandIssueData& data,
      bool clearQueue
    );

    /**
     * An order aimed at a planned factory's client-only unit, re-aimed: an assist (guard, repair) at an
     * engineer that will build it, a move at its spot. Returns false for any other order (attack, reclaim,
     * capture...), which then is not issued.
     */
    bool RetargetFromPlannedFactory(CWldSession& session, SSTICommandIssueData& data);

    /// A planned factory's rally line dragged to a new target (`ISSUE_SetCommandTarget` on its helper).
    void OnRallyHelperRetargeted(std::int32_t helperId, const SSTITarget& target, const Vector3f& position);

    /// A planned factory's rally line removed (`ISSUE_RemoveCommandFromUnitQueue` on its helper).
    void OnRallyHelperRemoved(CWldSession& session, std::int32_t helperId);

    /// The proxy half of `ISSUE_FactoryCommand`: records the rally order and draws its line.
    void OnProxyFactoryCommand(
      CWldSession& session,
      const gpg::fastvector<UserUnit*>& proxyUnits,
      const SSTICommandIssueData& data,
      bool clearQueue
    );

    /// Production orders for the selected planned factories (`IssueBlueprintCommand`).
    void QueueOrdersOnSelected(const CWldSession& session, const std::string& bpId, std::int32_t count, bool clear);

    /// From `UserUnit::Tick`, once per unit: remembers a unit that appeared while factories are planned.
    void NoteNewUnit(const UserUnit& unit);

    /// Once per beat, after the units' ticks. See the class comment.
    void Update(CWldSession& session);

    /// Session end: drops every proxy and its pointer without touching its unit, which stays with the ending
    /// session's entities like the sim's units do.
    void ForgetAll() noexcept;

    /// The planned factory under a screen point, by its footprint at the cursor's ground point, then by
    /// its projected centre within `pickRadius` pixels.
    [[nodiscard]] PlannedUnitProxy*
    PickAt(const GeomCamera3& camera, const Vector3f* cursorGround, float screenX, float screenY, float pickRadius);

    /// The planned factory whose footprint contains `ground` (x, z), or null.
    [[nodiscard]] PlannedUnitProxy* FindByFootprint(const Vector3f& ground);

    [[nodiscard]] PlannedUnitProxy* FindByUserUnit(const UserUnit* unit) noexcept;
    [[nodiscard]] PlannedUnitProxy* FindByProxyId(std::uint32_t proxyId) noexcept;
    [[nodiscard]] std::vector<PlannedUnitProxy*> GetSelectedProxies(const CWldSession& session);
    [[nodiscard]] const std::vector<std::unique_ptr<PlannedUnitProxy>>& GetAllProxies() const noexcept
    {
      return mProxies;
    }
    [[nodiscard]] std::size_t GetCount() const noexcept
    {
      return mProxies.size();
    }

    // The parts below need no session; the tests drive them directly.

    /**
     * Adds `builderId`'s command to the proxy planned for `bp` at `pos` (within 1 world unit), or makes a new
     * proxy in the lowest free slot. Returns null when all `kMaxPlannedProxies` slots are taken.
     */
    PlannedUnitProxy*
    AddProxy(std::uint32_t builderId, std::int32_t commandId, const REntityBlueprint* bp, const Vector3f& pos);

    /// The proxy a newly appeared unit of blueprint `bp` at `pos` builds: same blueprint, within 2 world
    /// units on the ground plane. The blueprint must match: a nearby factory of another kind is not it.
    [[nodiscard]] PlannedUnitProxy* FindForNewUnit(const REntityBlueprint* bp, const Vector3f& pos) noexcept;

    /// Removes `builderId`'s commands from every proxy (the proxies left without builders go at `Update`).
    void RemoveBuilder(std::uint32_t builderId);

    /// Drops every proxy without touching its unit (tests and `ForgetAll`).
    void Clear() noexcept;

    /// Removes the proxy in slot `proxyId` when it has no unit (tests: in a game every proxy has one, and
    /// only `Update` removes it).
    bool RemoveUnitlessProxy(std::uint32_t proxyId) noexcept;

  private:
    void Dispatch(CWldSession& session, PlannedUnitProxy& proxy, UserUnit& factory);
    /// Takes the proxy at `index` out of the list (nothing finds it after this) and returns it.
    std::unique_ptr<PlannedUnitProxy> Take(std::size_t index);
    /// Removes a taken proxy's unit and rally helpers from the session; `replacement` takes its selection.
    void Destroy(CWldSession& session, std::unique_ptr<PlannedUnitProxy> proxy, UserUnit* replacement);
    [[nodiscard]] std::uint32_t FreeSlot() const noexcept;

    std::vector<std::unique_ptr<PlannedUnitProxy>> mProxies;
    std::vector<std::uint32_t> mNewUnitIds;
  };
} // namespace moho
