#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/containers/TDatList.h"
#include "moho/path/SNavGoal.h"
#include "moho/sim/SOCellPos.h"
#include "moho/unit/Broadcaster.h"
#include "Wm3Vector3.h"

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
  class Entity;
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

    /**
     * Address: 0x005AFCC0 (FUN_005AFCC0)
     *
     * What it does:
     * Assigns one path span payload into this path storage while reusing or
     * reinitializing backing allocation as needed.
     */
    void AssignCopy(const SNavPath& src);

    void AppendCells(const SOCellPos* begin, const SOCellPos* end);

    /**
     * Address: 0x005B0B60 (FUN_005B0B60)
     * Address: 0x005B0900 (FUN_005B0900 -- forwarder into the body above)
     *
     * What it does:
     * Inserts one front range into this path span with vector-style growth and
     * stable ordering semantics.
     */
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
  class IAiNavigator : public Broadcaster<EAiNavigatorEvent>
  {
  public:
    /**
     * Address: 0x005A37D0 (FUN_005A37D0, `this` in EAX; zero callers, inlined
     *   into every navigator constructor)
     *
     * What it does:
     * Self-links the listener ring (the `Broadcaster` base) and installs the
     * interface vtable 0x00E1BD9C.
     */
    IAiNavigator() = default;

    /**
     * Address: 0x005A2CF0 (FUN_005A2CF0, the body: IDA's label
     *   `??0IAiNavigator` is wrong -- it installs the interface vtable and
     *   then *unlinks* the ring's live links, which is the `Broadcaster`
     *   base's destructor)
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
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005A7BB0 (FUN_005A7BB0, Moho::IAiNavigator::MemberSerialize)
     *
     * What it does:
     * Saves IAiNavigator broadcaster listener payload through reflected
     * `Broadcaster<EAiNavigatorEvent>` metadata.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

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
     *
     * What it does:
     * Points this navigator at a live entity instead of a fixed goal cell, so
     * the mover keeps chasing it as it moves.
     *
     * The destination is an `Entity`, not a `Unit`: both implementations store
     * it in a `WeakPtr<Entity>` (the serializers name the reflected type
     * `.?AV?$WeakPtr@VEntity@Moho@@@Moho@@` at 0x00F6B8A4, read at 0x005A8FCC
     * and 0x005A9000), and both read its position straight off `Entity` -
     * 0x005A4191 loads `[dest+0xB4]`/`[dest+0xAC]`, which is `Entity::Position`.
     * That is what lets a unit attack something it only sees on radar, because
     * the thing the attack task hands over is then a `ReconBlip`, not a `Unit`.
     */
    virtual void SetDestUnit(Entity* destinationEntity) = 0;

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
    virtual bool CanPathTo(Wm3::Vector3f* outTargetPos, const SAiNavigatorGoal& goal) const = 0;

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

    /**
     * +0x0C, never read or written by any `IAiNavigator` code: the interface
     * constructor (0x005A37D0) stores only the vtable and self-links the ring,
     * and `IAiNavigatorTypeInfo::Init` registers the size as 0x0C
     * (0x005A31F3). The shipped `CAiNavigatorImpl` still puts its `CTask`
     * base at +0x10 (`lea esi, [ebp+10h]` at 0x005A3415; `AddBase` stores
     * 0x10 at 0x005A7CBB and 0x28 for `CScriptObject` at 0x005A7D1B):
     * MSVC8 padded between the ring's trailing `boost::noncopyable` and
     * `CTask`'s leading one. VS2022 does not pad there, so the slot is
     * carried here, as `CTask` and `CScriptObject` carry their own
     * `eboPadding` words.
     */
    std::uint32_t mPad0C;
  };

  /**
   * Address: 0x005A5790 (FUN_005A5790, ?AI_CreatePathingNavigator@Moho@@YAPAVIAiNavigator@1@PAVUnit@1@@Z)
   *
   * What it does:
   * Allocates one `CAiNavigatorLand` for `unit` and returns it through the
   * `IAiNavigator` interface pointer. Returns null when allocation fails.
   */
  [[nodiscard]] IAiNavigator* AI_CreatePathingNavigator(Unit* unit);

  /**
   * Address: 0x005A5800 (FUN_005A5800, ?AI_CreateAirNavigator@Moho@@YAPAVIAiNavigator@1@PAVUnit@1@@Z)
   *
   * What it does:
   * Allocates one `CAiNavigatorAir` for `unit` and returns it through the
   * `IAiNavigator` interface pointer. Returns null when allocation fails.
   */
  [[nodiscard]] IAiNavigator* AI_CreateAirNavigator(Unit* unit);

  /**
   * Address: 0x005A5850 (FUN_005A5850, ?AI_ClearPathData@Moho@@YAXXZ)
   *
   * What it does:
   * Preserves the legacy global AI path-data clear hook as a deliberate no-op.
   */
  void AI_ClearPathData();

  /**
   * Address: 0x00BCC9A0 (FUN_00BCC9A0)
   *
   * What it does:
   * Registers the broadcaster reflection lane for `EAiNavigatorEvent` and
   * installs process-exit cleanup.
   */
  void register_RBroadcasterRType_EAiNavigatorEvent();

  /**
   * Address: 0x00BCC9C0 (FUN_00BCC9C0)
   *
   * What it does:
   * Registers the listener reflection lane for `EAiNavigatorEvent` and installs
   * process-exit cleanup.
   */
  void register_RListenerRType_EAiNavigatorEvent();

  // 0x10, not the 0x0C `IAiNavigatorTypeInfo::Init` registers: see `mPad0C`.
  static_assert(sizeof(IAiNavigator) == 0x10, "IAiNavigator size must be 0x10");
  static_assert(offsetof(IAiNavigator, mListeners) == 0x04, "IAiNavigator::mListeners offset must be 0x04");
  static_assert(offsetof(IAiNavigator, mPad0C) == 0x0C, "IAiNavigator::mPad0C offset must be 0x0C");
} // namespace moho

