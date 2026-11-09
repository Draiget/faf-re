#include "moho/unit/core/UserUnitPrivate.h"

namespace
{

  /**
   * Address: 0x008B5EB0 (FUN_008B5EB0)
   *
   * What it does:
   * Removes this command's issue-helper entry from the active session's
   * command-issue map, if present.
   *
   * Real `fa::map<CmdId, UserCommandIssueHelper*>::erase(const
   * key_type&)` call on `CommandManager::mCommands` -- "covered by typed
   * source construct... no standalone SDK address owner emitted" per this
   * token's own progress-DB note, matching the `Sim.cpp` precedent (see
   * `FindSessionCommandIssueHelperById`'s citation above for the shared
   * rb-tree cleanup this migration is part of).
   */
  void DiscardActiveSessionCommandIssueHelper(const UserCommandIssueHelper& helper) noexcept
  {
    CWldSession* const session = WLD_GetActiveSession();
    if (session == nullptr || session->mCommandManager == nullptr) {
      return;
    }

    session->mCommandManager->mCommands.erase(static_cast<CmdId>(helper.mConstantData.cmd));
  }
}

namespace moho
{
  /**
   * Address: 0x0081D030 (FUN_0081D030)
   *
   * What it does:
   * Returns the active user-command queue length (element count) by rebuilding
   * and resolving the current queue vector, then computing `(end - begin)`.
   * Exposed (namespace moho, declared in UserUnit.h) so the client-side
   * `ISSUE_Command` keystone (Sim.cpp) can enforce the 500-entry depth cap.
   */
  [[nodiscard]] std::int32_t GetUserUnitManagerQueueSize(
    UserCommandQueue* const managerPtr
  ) noexcept
  {
    const gpg::fastvector_n<WeakPtr<UserCommandIssueHelper>, 2>* const queueVector = RebuildAndGetUserUnitManagerQueue(managerPtr);
    return static_cast<std::int32_t>(queueVector->size());
  }
}

namespace
{

  /**
   * Address: 0x008B43F0 (FUN_008B43F0, func_GetEntitiesUnderCursor)
   *
   * What it does:
   * Rebuilds one cached command-issue cursor entity weak-set when dirty:
   * seeds from stored cursor entity-id lanes, then replays queued issue events
   * (`type 0` merge, `type 3` erase) into the cache and returns that set.
   */
  [[nodiscard]] WeakSet<UserUnit>* GetEntitiesUnderCursor(UserCommandIssueHelper& helper) noexcept
  {
    if (helper.mVariableDataDirty != 0u) {
      helper.mVariableDataDirty = 0u;
      helper.mCursorEntitySet.Clear();

      // 0x008B4450..0x008B4495: every stored id, found or not, goes through
      // `Add` (0x00822270); a miss adds a dead entry the next walk drops.
      for (const EntId entityId : helper.mVariableData.mEntIds) {
        UserEntity* const entity = FindSessionEntityById(WLD_GetActiveSession(), static_cast<std::int32_t>(entityId));
        (void)helper.mCursorEntitySet.Add(static_cast<UserUnit*>(entity));
      }

      fa::deque<UserCommandIssueLocalEvent>& events = helper.mLocalQueue;
      for (std::size_t index = 0; index != events.size(); ++index) {
        UserCommandIssueLocalEvent& event = events[index];
        if (event.mType == ECommandIssueEvent::DeselectUnit) {
          for (UserUnit* const unit : event.mUnits) {
            (void)helper.mCursorEntitySet.Remove(unit);
          }
        } else if (event.mType == ECommandIssueEvent::SelectUnit) {
          helper.mCursorEntitySet.Add(event.mUnits.begin(), event.mUnits.end());
        }
      }
    }

    return &helper.mCursorEntitySet;
  }
}

namespace moho
{

  /**
   * Address: 0x008B6DE0 (FUN_008B6DE0, struct_UserUnitManager::add)
   *
   * IDA signature:
   * int *__userpurge struct_UserUnitManager::add@<eax>(
   *     struct_UserUnitManager *a1@<edi>, _DWORD *eax0@<eax>, int a3, int a4);
   *
   * What it does:
   * Records one pending Add edit for `manager` ({cmdId, Add, helper, index},
   * built at 0x008B6DFB-0x008B6E07), enqueues the helper's select-unit update
   * event against the manager's owner unit, and marks the resolved links
   * dirty. `index` is the issue data's `mIndex` (`ISSUE_Command` pushes
   * `[esp+0x148]`, i.e. `data+0x08`, at 0x008B0566); -1 appends.
   */
  void UserUnitManagerAdd(
    UserCommandQueue* const manager,
    UserCommandIssueHelper* const helper,
    const CmdId cmdId,
    const CmdId index)
  {
    manager->issueQueue.push_back(UserManagerHelperEntry(cmdId, EUserQueueEdit::Add, helper, index));

    QueueCommandIssueSelectUnitEvent(helper, cmdId, manager->ownerUnit);

    manager->resolvedLinksDirty = 1u;
    manager->resolvedLinks.ResetStorageToInline();
  }

  /**
   * Address: 0x008B6E60 (FUN_008B6E60, struct_UserUnitManager::reset)
   *
   * What it does:
   * Clears one user-unit command-issue queue and pushes a Reset edit
   * {commandType, Reset, null, -1}, marks the resolved-link range dirty, and
   * restores it to inline storage.
   */
  void ResetUserUnitManagerState(UserCommandQueue* const managerPtr, const std::int32_t commandType)
  {
    if (managerPtr == nullptr) {
      return;
    }

    auto& manager = *managerPtr;
    manager.issueQueue.clear();
    manager.issueQueue.push_back(UserManagerHelperEntry(commandType, EUserQueueEdit::Reset, nullptr, -1));

    manager.resolvedLinksDirty = 1u;
    manager.resolvedLinks.ResetStorageToInline();
  }

  /**
   * Address: 0x008B6EE0 (FUN_008B6EE0, sub_8B6EE0) - see the doc comment on
   * the declaration in UserUnit.h.
   */
  void RecordUnitManagerCommandHelperRemoval(
    UserCommandIssueHelper* const helper,
    UserCommandQueue* const manager,
    const std::int32_t tag
  ) noexcept
  {
    manager->issueQueue.push_back(UserManagerHelperEntry(tag, EUserQueueEdit::Remove, helper, -1));

    QueueCommandIssueDeselectUnitEvent(helper, static_cast<CmdId>(tag), manager->ownerUnit);

    manager->resolvedLinksDirty = 1u;
    manager->resolvedLinks.ResetStorageToInline();
  }

/**
 * Address: 0x008C63B0 (FUN_008C63B0)
 *
 * What it does:
 * Rebinds the startup metatable-factory index lane for
 * `CScrLuaMetatableFactory<UserUnit>` and returns that singleton.
 */
  /**
   * Address: 0x008B3DC0 (FUN_008B3DC0, sub_8B3DC0)
   *
   * What it does:
   * See the declaration in CommandIssueHelper.h. The binary leaves the unit
   * set's allocator proxy (+0x08) unwritten; the default member state here
   * zeroes it, which is not observable.
   */
  UserCommandIssueLocalEvent::UserCommandIssueLocalEvent(const CmdId cmdId, const ECommandIssueEvent type)
    : mCmdId(cmdId)
    , mType(type)
    , mUnits()
    , mCount(0)
    , mTarget()
    , mCells()
  {}

  /**
   * Address: 0x008B3EC0 (FUN_008B3EC0, struct_CommandIssueHelper::struct_CommandIssueHelper)
   *
   * What it does:
   * Copies command constant data, initializes variable command payload
   * state and local queue lanes, and creates an empty cursor weak-set.
   */
  UserCommandIssueHelper::UserCommandIssueHelper(
    const SSTICommandConstantData& constantData,
    const std::uint8_t deleteWhenDue,
    const std::int32_t dueSeqNo
  )
    : WeakObject()
    , mConstantData(constantData)
    , mVariableData()
    , mReservedB0(0u)
    , mDeleteWhenDue(deleteWhenDue)
    , mVariableDataDirty(1u)
    , mReservedB3(0u)
    , mDueSeqNo(dueSeqNo)
    , mLocalQueue{}
    , mCursorEntitySet()
  {
  }

  /**
   * Address: 0x008B4C20 (FUN_008B4C20)
   *
   * What it does:
   * Retires this helper once its due sequence is reached, otherwise drains
   * due local command-issue events and marks variable data dirty.
   */
  void UserCommandIssueHelper::AdvanceLocalEventsToBeat(const std::int32_t beat) noexcept
  {
    const auto dueDelta = static_cast<std::int32_t>(
      static_cast<std::uint32_t>(mDueSeqNo) - static_cast<std::uint32_t>(beat)
    );
    if (mDeleteWhenDue != 0u && dueDelta <= 0) {
      this->~UserCommandIssueHelper();
      ::operator delete(this);
      return;
    }

    // Every edit the sim has now confirmed is dropped from the front.
    while (!mLocalQueue.empty()) {
      const auto eventDelta = static_cast<std::int32_t>(
        static_cast<std::uint32_t>(mLocalQueue.front().mCmdId) - static_cast<std::uint32_t>(beat)
      );
      if (eventDelta > 0) {
        break;
      }

      mLocalQueue.pop_front();
      mVariableDataDirty = 1u;
    }
  }

  /**
   * Address: 0x008B3F80 (FUN_008B3F80, struct_CommandIssueHelper::~struct_CommandIssueHelper)
   * Mangled: ??1struct_CommandIssueHelper@@QAE@@Z
   *
   * What it does:
   * Removes this helper's command-id entry from the active session command
   * map, releases cursor/entity weak-set storage and local queued issue
   * events, and then relies on typed command payload members for teardown.
   */
  UserCommandIssueHelper::~UserCommandIssueHelper() noexcept
  {
    DiscardActiveSessionCommandIssueHelper(*this);
    // `mCursorEntitySet`, then `mLocalQueue` (0x008B5210), are destroyed as
    // members, and the `WeakObject` base drops the weak references last
    // (0x008B4049).
  }

  UserCommandIssueHelper* FindCommandIssueHelperInSession(CWldSession* const session, const CmdId commandId) noexcept
  {
    return FindSessionCommandIssueHelperById(session, commandId);
  }

  EUnitCommandType ResolveCommandIssueHelperCommandType(const UserCommandIssueHelper& helper) noexcept
  {
    return ResolveHelperCommandType(helper);
  }

  WeakSet<UserUnit>* ResolveCommandIssueCursorEntities(UserCommandIssueHelper& helper) noexcept
  {
    return GetEntitiesUnderCursor(helper);
  }

  /**
   * Address: 0x008B73E0 (FUN_008B73E0)
   *
   * What it does:
   * Rebuilds/resolves one user-unit command queue and returns whether it
   * currently contains the supplied command-issue helper.
   */
  gpg::fastvector_n<WeakPtr<UserCommandIssueHelper>, 2>* GetUserUnitManagerQueueLinks(UserCommandQueue* const manager) noexcept
  {
    return RebuildAndGetUserUnitManagerQueue(manager);
  }

  bool UserUnitManagerContainsCommandIssueHelper(
    UserCommandQueue* const manager,
    const UserCommandIssueHelper* const helper
  ) noexcept
  {
    if (manager == nullptr || helper == nullptr) {
      return false;
    }

    const gpg::fastvector_n<WeakPtr<UserCommandIssueHelper>, 2>* const queueVector = RebuildAndGetUserUnitManagerQueue(manager);
    if (queueVector == nullptr) {
      return false;
    }

    const auto* const helperView = helper;
    for (const WeakPtr<UserCommandIssueHelper>& link : *queueVector) {
      if (link.GetObjectPtr() == helperView) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x008B7320 (FUN_008B7320, struct_UserUnitManager::Get) - see
   * the doc comment on the declaration in UserUnit.h.
   */
  UserCommandIssueHelper* GetUserUnitManagerLastQueuedHelper(UserCommandQueue* const manager) noexcept
  {
    if (manager == nullptr) {
      return nullptr;
    }

    return GetLastQueuedUserCommandHelper(manager);
  }

  /**
   * Address: 0x0081DD00 inlines this exact tail dereference (see the doc
   * comment on the declaration in UserUnit.h for why this differs from
   * `ResolveUserUnitFrontCommandIssueHelper`/`GetLastQueuedUserCommandHelper`).
   */
  UserCommandIssueHelper* FindColocatedQueuedBuildOrderInManager(
    UserCommandQueue* const manager,
    const Wm3::Vector3f& dragPosition,
    const REntityBlueprint* const candidateBlueprint
  ) noexcept
  {
    gpg::fastvector_n<WeakPtr<UserCommandIssueHelper>, 2>* const queueVector = RebuildAndGetUserUnitManagerQueue(manager);
    if (queueVector == nullptr || queueVector->empty() || candidateBlueprint == nullptr) {
      return nullptr;
    }

    const SOCellPos dragCell = candidateBlueprint->mFootprint.ToCellPos(dragPosition);

    for (const WeakPtr<UserCommandIssueHelper>& link : *queueVector) {
      UserCommandIssueHelper* const entryHelper = link.GetObjectPtr();
      if (entryHelper == nullptr) {
        continue;
      }

      auto* const queuedHelper = entryHelper;
      if (queuedHelper->mConstantData.blueprint != candidateBlueprint) {
        continue;
      }

      const Wm3::Vector3f anchor = ResolveCommandGraphAnchorWorldPosition(*queuedHelper);
      if (candidateBlueprint->mFootprint.ToCellPos(anchor) == dragCell) {
        return queuedHelper;
      }
    }

    return nullptr;
  }

  UserCommandIssueHelper* GetUserUnitManagerQueueTailHelperRaw(UserCommandQueue* const manager) noexcept
  {
    gpg::fastvector_n<WeakPtr<UserCommandIssueHelper>, 2>* const queueVector = RebuildAndGetUserUnitManagerQueue(manager);
    if (queueVector == nullptr || queueVector->empty()) {
      return nullptr;
    }

    return queueVector->back().GetObjectPtr();
  }

  /**
   * Address: 0x0081DD00 inlines this scan (see the doc comment on the
   * declaration in UserUnit.h).
   */
  bool UserUnitManagerQueueHasUniformCommandType(
    UserCommandQueue* const manager,
    const EUnitCommandType commandType
  ) noexcept
  {
    gpg::fastvector_n<WeakPtr<UserCommandIssueHelper>, 2>* const queueVector = RebuildAndGetUserUnitManagerQueue(manager);
    if (queueVector == nullptr) {
      return true;
    }

    for (const WeakPtr<UserCommandIssueHelper>& link : *queueVector) {
      // No null-skip: the binary dereferences each resolved entry's helper
      // pointer unconditionally here (unlike the front/tail/contains
      // accessors above), so this matches that exactly.
      if (ResolveHelperCommandType(*link.GetObjectPtr()) != commandType) {
        return false;
      }
    }

    return true;
  }

  /**
   * Address: 0x0081DEF0 inlines this scan (see the doc comment on the
   * declaration in UserUnit.h).
   */
  void RestartQueuedCommandsFromHelper(
    UserCommandQueue* const manager,
    UserCommandIssueHelper* const helper,
    const EUnitCommandType matchCommandType,
    const EUnitCommandType restartCommandType
  ) noexcept
  {
    gpg::fastvector_n<WeakPtr<UserCommandIssueHelper>, 2>* const queueVector = RebuildAndGetUserUnitManagerQueue(manager);
    if (queueVector == nullptr) {
      return;
    }

    bool foundHelper = false;
    for (const WeakPtr<UserCommandIssueHelper>& link : *queueVector) {
      UserCommandIssueHelper* const entryHelper = link.GetObjectPtr();
      if (entryHelper == nullptr) {
        continue;
      }

      if (entryHelper == helper) {
        foundHelper = true;
      }
      if (!foundHelper || ResolveHelperCommandType(*entryHelper) != matchCommandType) {
        continue;
      }

      auto& queuedHelper = *entryHelper;
      CmdId newCmdId = queuedHelper.mConstantData.cmd;
      if (ISTIDriver* const simDriver = WLD_GetDriver(); simDriver != nullptr) {
        newCmdId = simDriver->SetCommandType(newCmdId, restartCommandType);
      }
      ReissueCommandIssueEntryAsType(queuedHelper, newCmdId, restartCommandType);
    }
  }
}


/**
 * Address: 0x008BF612 (inside FUN_008BF420, once per queue)
 *
 * What it does:
 * See the declaration in UserCommandQueue.h.
 */
UserCommandQueue::UserCommandQueue(UserUnit* const owner)
  : ownerUnit(owner)
  , primaryLinks()
  , issueQueue()
  , resolvedLinks()
  , resolvedLinksDirty(0u)
{}
