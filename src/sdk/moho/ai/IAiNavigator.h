#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/containers/TDatList.h"
#include "moho/sim/SOCellPos.h"
#include "wm3/Vector3.h"

namespace gpg
{
  class RType;
  class ReadArchive;
  class WriteArchive;
}

namespace LuaPlus
{
  class LuaState;
}

namespace moho
{
  class Unit;
  class CAiPathNavigator;

  enum EAiNavigatorStatus : std::int32_t
  {
    AINAVSTATUS_Idle = 0,
    AINAVSTATUS_Thinking = 1,
    AINAVSTATUS_Steering = 2,
  };

  enum EAiNavigatorEvent : std::int32_t
  {
    AINAVEVENT_Failed = 0,
    AINAVEVENT_Aborted = 1,
    AINAVEVENT_Succeeded = 2,
    AINAVEVENT_ResumeTask = 3,
  };

  /**
   * Intrusive listener payload linked from IAiNavigator::mListenerNode.
   *
   * Evidence:
   * - FUN_005A6C50 re-links each listener node, resolves owner at `node - 0x04`,
   *   then invokes vtable slot 0 with one event code integer.
   */
  class IAiNavigatorEventListener
  {
  public:
    /**
     * Address: 0x005A6C50 (FUN_005A6C50 callback callsite)
     *
     * What it does:
     * Receives one navigator event code from IAiNavigator listener dispatch.
     */
    virtual void OnNavigatorEvent(std::int32_t eventCode) = 0;

    TDatListItem<void, void> mLink; // +0x04
  };

  static_assert(sizeof(IAiNavigatorEventListener) == 0x0C, "IAiNavigatorEventListener size must be 0x0C");
  static_assert(
    offsetof(IAiNavigatorEventListener, mLink) == 0x04, "IAiNavigatorEventListener::mLink offset must be 0x04"
  );

  /**
   * Recovered goal rectangle payload passed to land/air navigator goal evaluators.
   *
   * Evidence:
   * - CAiNavigatorLand::SetGoal (0x005A3ED0) writes/copies 9 dwords.
   * - CAiNavigatorAir::SetGoal (0x005A4C60) consumes rectangle bounds from this payload.
   */
  struct SAiNavigatorGoal
  {
    std::int32_t minX;
    std::int32_t minZ;
    std::int32_t maxX;
    std::int32_t maxZ;
    std::int32_t aux0;
    std::int32_t aux1;
    std::int32_t aux2;
    std::int32_t aux3;
    std::int32_t aux4;
  };

  static_assert(sizeof(SAiNavigatorGoal) == 0x24, "SAiNavigatorGoal size must be 0x24");
  static_assert(offsetof(SAiNavigatorGoal, minX) == 0x00, "SAiNavigatorGoal::minX offset must be 0x00");
  static_assert(offsetof(SAiNavigatorGoal, minZ) == 0x04, "SAiNavigatorGoal::minZ offset must be 0x04");
  static_assert(offsetof(SAiNavigatorGoal, maxX) == 0x08, "SAiNavigatorGoal::maxX offset must be 0x08");
  static_assert(offsetof(SAiNavigatorGoal, maxZ) == 0x0C, "SAiNavigatorGoal::maxZ offset must be 0x0C");
  static_assert(offsetof(SAiNavigatorGoal, aux0) == 0x10, "SAiNavigatorGoal::aux0 offset must be 0x10");
  static_assert(offsetof(SAiNavigatorGoal, aux1) == 0x14, "SAiNavigatorGoal::aux1 offset must be 0x14");
  static_assert(offsetof(SAiNavigatorGoal, aux2) == 0x18, "SAiNavigatorGoal::aux2 offset must be 0x18");
  static_assert(offsetof(SAiNavigatorGoal, aux3) == 0x1C, "SAiNavigatorGoal::aux3 offset must be 0x1C");
  static_assert(offsetof(SAiNavigatorGoal, aux4) == 0x20, "SAiNavigatorGoal::aux4 offset must be 0x20");

  /**
   * Packed grid-cell path payload used by land navigation callbacks.
   *
   * Evidence:
   * - CAiPathNavigator constructor initializes this 3-pointer span at +0x14.
   * - CAiNavigatorLand::GetNavPath (0x005A3EA0) returns `mPathNavigator + 0x14`.
   */
  struct SNavPath
  {
    std::uint32_t reserved0;
    SOCellPos* start;
    SOCellPos* finish;
    SOCellPos* capacity;

    [[nodiscard]] std::size_t Count() const noexcept;
    [[nodiscard]] std::int32_t CountInt() const noexcept;
    [[nodiscard]] std::size_t CapacityCount() const noexcept;

    void ClearContent() noexcept;
    void FreeStorage() noexcept;
    void EnsureCapacity(std::size_t requiredCount);
    void AssignCopy(const SNavPath& src);
    void AppendCells(const SOCellPos* begin, const SOCellPos* end);
    void PrependCells(const SOCellPos* begin, const SOCellPos* end);
    void AppendCell(const SOCellPos& cell);
    void EraseFrontCell() noexcept;
    void EraseFrontCells(std::int32_t count) noexcept;
  };

  static_assert(sizeof(SNavPath) == 0x10, "SNavPath size must be 0x10");
  static_assert(offsetof(SNavPath, reserved0) == 0x00, "SNavPath::reserved0 offset must be 0x00");
  static_assert(offsetof(SNavPath, start) == 0x04, "SNavPath::start offset must be 0x04");
  static_assert(offsetof(SNavPath, finish) == 0x08, "SNavPath::finish offset must be 0x08");
  static_assert(offsetof(SNavPath, capacity) == 0x0C, "SNavPath::capacity offset must be 0x0C");

  /**
   * VFTABLE: 0x00E1BD9C
   * COL:  0x00E71FA8
   */
  class IAiNavigator
  {
  public:
    /**
     * Address: 0x005A2D30 (FUN_005A2D30, scalar deleting thunk)
     *
     * VFTable SLOT: 0
     */
    virtual ~IAiNavigator();

    /**
     * Address: 0x005A7B60 (FUN_005A7B60, Moho::IAiNavigator::MemberDeserialize)
     *
     * What it does:
     * Loads IAiNavigator broadcaster listener payload through reflected
     * `Broadcaster<EAiNavigatorEvent>` metadata.
     */
    static void MemberDeserialize(IAiNavigator* object, gpg::ReadArchive* archive);

    /**
     * Address: 0x005A7BB0 (FUN_005A7BB0, Moho::IAiNavigator::MemberSerialize)
     *
     * What it does:
     * Saves IAiNavigator broadcaster listener payload through reflected
     * `Broadcaster<EAiNavigatorEvent>` metadata.
     */
    static void MemberSerialize(const IAiNavigator* object, gpg::WriteArchive* archive);

    /**
     * Address: 0x005A3600 (FUN_005A3600)
     *
     * VFTable SLOT: 1
     */
    virtual Unit* GetUnit() = 0;

    /**
     * Address: 0x005A3ED0 (FUN_005A3ED0, CAiNavigatorLand::SetGoal)
     * Address: 0x005A4C60 (FUN_005A4C60, CAiNavigatorAir::SetGoal)
     *
     * VFTable SLOT: 2
     */
    virtual void SetGoal(const SAiNavigatorGoal& goal) = 0;

    /**
     * Address: 0x005A4180 (FUN_005A4180, CAiNavigatorLand::SetDestUnit)
     * Address: 0x005A4A70 (FUN_005A4A70, CAiNavigatorAir::SetDestUnit)
     *
     * VFTable SLOT: 3
     */
    virtual void SetDestUnit(Unit* destinationUnit) = 0;

    /**
     * Address: 0x005A3750 (FUN_005A3750, CAiNavigatorImpl::AbortMove)
     * Address: 0x005A4F00 (FUN_005A4F00, CAiNavigatorAir::AbortMove)
     *
     * VFTable SLOT: 4
     */
    virtual void AbortMove() = 0;

    /**
     * Address: 0x005A3730 (FUN_005A3730)
     *
     * VFTable SLOT: 5
     */
    virtual void BroadcastResumeTaskEvent() = 0;

    /**
     * Address: 0x005A4240 (FUN_005A4240, CAiNavigatorLand::SetSpeedThroughGoal)
     * Address: 0x005A5080 (FUN_005A5080, CAiNavigatorAir::SetSpeedThroughGoal)
     *
     * VFTable SLOT: 6
     */
    virtual void SetSpeedThroughGoal(bool enabled) = 0;

    /**
     * Address: 0x005A4260 (FUN_005A4260, CAiNavigatorLand::GetCurrentTargetPos)
     * Address: 0x005A50B0 (FUN_005A50B0, CAiNavigatorAir::GetCurrentTargetPos)
     *
     * VFTable SLOT: 7
     */
    [[nodiscard]]
    virtual Wm3::Vector3f GetCurrentTargetPos() const = 0;

    /**
     * Address: 0x005A3D80 (FUN_005A3D80, CAiNavigatorLand::GetGoalPos)
     * Address: 0x005A49F0 (FUN_005A49F0, CAiNavigatorAir::GetGoalPos)
     *
     * VFTable SLOT: 8
     */
    [[nodiscard]]
    virtual Wm3::Vector3f GetGoalPos() const = 0;

    /**
     * Address: 0x005A37A0 (FUN_005A37A0)
     *
     * VFTable SLOT: 9
     */
    [[nodiscard]]
    virtual EAiNavigatorStatus GetStatus() const = 0;

    /**
     * Address: 0x005A3EB0 (FUN_005A3EB0, CAiNavigatorLand::HasGoodPath)
     * Address: 0x005A4E50 (FUN_005A4E50, CAiNavigatorAir::HasGoodPath)
     *
     * VFTable SLOT: 10
     */
    [[nodiscard]]
    virtual bool HasGoodPath() const = 0;

    /**
     * Address: 0x005A3EC0 (FUN_005A3EC0, CAiNavigatorLand::FollowingLeader)
     * Address: 0x005A4E60 (FUN_005A4E60, CAiNavigatorAir::FollowingLeader)
     *
     * VFTable SLOT: 11
     */
    [[nodiscard]]
    virtual bool FollowingLeader() const = 0;

    /**
     * Address: 0x005A3D60 (FUN_005A3D60, CAiNavigatorLand::IgnoreFormation)
     * Address: 0x005A4A40 (FUN_005A4A40, CAiNavigatorAir::IgnoreFormation)
     *
     * VFTable SLOT: 12
     */
    virtual void IgnoreFormation(bool ignore) = 0;

    /**
     * Address: 0x005A3D70 (FUN_005A3D70, CAiNavigatorLand::IsIgnoringFormation)
     * Address: 0x005A4A60 (FUN_005A4A60, CAiNavigatorAir::IsIgnoringFormation)
     *
     * VFTable SLOT: 13
     */
    [[nodiscard]]
    virtual bool IsIgnoringFormation() const = 0;

    /**
     * Address: 0x005A3BD0 (FUN_005A3BD0, CAiNavigatorLand::AtGoal)
     * Address: 0x005A48E0 (FUN_005A48E0, CAiNavigatorAir::AtGoal)
     *
     * VFTable SLOT: 14
     */
    [[nodiscard]]
    virtual bool AtGoal() const = 0;

    /**
     * Address: 0x005A3CD0 (FUN_005A3CD0, CAiNavigatorLand::CanPathTo)
     * Address: 0x005A49E0 (FUN_005A49E0, CAiNavigatorAir::CanPathTo)
     *
     * VFTable SLOT: 15
     */
    [[nodiscard]]
    virtual bool CanPathTo(const SAiNavigatorGoal& goal) const = 0;

    /**
     * Address: 0x005A2D10 (FUN_005A2D10)
     *
     * VFTable SLOT: 16
     */
    virtual void Func1() = 0;

    /**
     * Address: 0x005A2D20 (FUN_005A2D20)
     *
     * VFTable SLOT: 17
     */
    [[nodiscard]]
    virtual SNavPath* GetNavPath() const = 0;

    /**
     * Address: 0x005A36F0 (FUN_005A36F0)
     *
     * VFTable SLOT: 18
     */
    virtual void PushStack(LuaPlus::LuaState* luaState) = 0;

    /**
     * Address: 0x005A3710 (FUN_005A3710)
     *
     * VFTable SLOT: 19
     */
    [[nodiscard]]
    virtual bool NavigatorMakeIdle() = 0;

  public:
    static gpg::RType* sType;

    TDatListItem<void, void> mListenerNode; // +0x04
  };

  /**
   * Address: 0x00BCC9A0 (FUN_00BCC9A0)
   *
   * What it does:
   * Registers the broadcaster reflection lane for `EAiNavigatorEvent` and
   * installs process-exit cleanup.
   */
  int register_RBroadcasterRType_EAiNavigatorEvent();

  /**
   * Address: 0x00BCC9C0 (FUN_00BCC9C0)
   *
   * What it does:
   * Registers the listener reflection lane for `EAiNavigatorEvent` and installs
   * process-exit cleanup.
   */
  int register_RListenerRType_EAiNavigatorEvent();

  static_assert(sizeof(IAiNavigator) == 0x0C, "IAiNavigator size must be 0x0C");
  static_assert(offsetof(IAiNavigator, mListenerNode) == 0x04, "IAiNavigator::mListenerNode offset must be 0x04");
} // namespace moho

