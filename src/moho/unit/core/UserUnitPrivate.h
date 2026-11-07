#pragma once

// Private to moho/unit/core: helpers the pieces of the former UserUnit.cpp share.

// Auto-generated from IDA VFTABLE/RTTI scan.
#include "moho/unit/core/UserUnit.h"
#include "moho/lua/CScrLuaObjectFactory.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"
#include "lua/LuaRuntimeTypes.h"
#include "moho/command/CommandIssueHelper.h"
#include "moho/console/CVarAccess.h"
#include "moho/sim/BuildQueueCommandDecrement.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/EntityId.h"
#include "moho/entity/REntityBlueprintTypeInfo.h"
#include "moho/entity/UserEntity.h"
#include "moho/mesh/Mesh.h"
#include "moho/math/Vector3f.h"
#include "moho/animation/CAniPose.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/misc/Stats.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/blueprints/RBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/CArmyLuaFunctionRegistrations.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SOCellPos.h"
#include "moho/ui/UiRuntimeTypes.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/UserArmy.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"
#include "moho/command/UserCommandQueue.h"
#include "moho/unit/core/UnitAttributes.h"
#include "moho/vision/VisionDB.h"


using namespace moho;
namespace moho
{
  template <>
  class CScrLuaMetatableFactory<UserUnit> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(sizeof(CScrLuaMetatableFactory<UserUnit>) == 0x08, "CScrLuaMetatableFactory<UserUnit> size must be 0x08");
}

namespace
{

  [[nodiscard]] gpg::fastvector_n<WeakPtr<UserCommandIssueHelper>, 2>* RebuildAndGetUserUnitManagerQueue(UserCommandQueue* managerPtr) noexcept;

  [[maybe_unused]] [[nodiscard]] const gpg::fastvector_n<WeakPtr<UserCommandIssueHelper>, 2>* ResolveUserCommandQueueRange(
    const UserCommandQueue* const queue
  ) noexcept
  {
    UserCommandQueue* const manager = const_cast<UserCommandQueue*>(queue);
    if (manager == nullptr) {
      return nullptr;
    }

    return RebuildAndGetUserUnitManagerQueue(manager);
  }

  /**
   * Address: 0x008B7320 (FUN_008B7320, struct_UserUnitManager::Get)
   *
   * What it does:
   * Resolves one command-manager queue view and returns the most recent
   * non-null helper entry, scanning backward from the logical tail.
   */
  [[maybe_unused]] [[nodiscard]] UserCommandIssueHelper* GetLastQueuedUserCommandHelper(
    UserCommandQueue* const managerPtr
  ) noexcept
  {
    const auto& links = *RebuildAndGetUserUnitManagerQueue(managerPtr);
    for (std::ptrdiff_t index = static_cast<std::ptrdiff_t>(links.size()) - 1; index >= 0; --index) {
      if (UserCommandIssueHelper* const helper = links[static_cast<std::size_t>(index)].GetObjectPtr()) {
        return helper;
      }
    }
    return nullptr;
  }

  /**
   * No standalone address: this call site invokes real
   * `fa::map<CmdId, UserCommandIssueHelper*>::find` on
   * `CommandManager::mCommands`, whose compiled internals
   * (`find_node`/`lower_bound_node`, e.g. FUN_008B6160 and siblings) are
   * already cited on `RbTree.h`'s shared `rb_tree<Traits>` template from
   * the `Sim.cpp` instantiation of this same map -- the same template
   * member is reused across every call site for one map instantiation, so
   * no separate citation is needed per caller.
   *
   * This file now calls `mCommands` directly, same as `Sim.cpp` does.
   */
  [[nodiscard]] UserCommandIssueHelper*
  FindSessionCommandIssueHelperById(CWldSession* const session, const CmdId commandId) noexcept
  {
    if (session == nullptr || session->mCommandManager == nullptr) {
      return nullptr;
    }

    auto& mCommands = session->mCommandManager->mCommands;
    const auto it = mCommands.find(commandId);
    if (it == mCommands.end()) {
      return nullptr;
    }

    return it->second;
  }

  /**
   * Address: 0x008B6F60 (FUN_008B6F60, struct_UserUnitManager::Get)
   *
   * What it does:
   * Rebuilds one resolved command queue from the primary queue and pending
   * issue operations when the resolved view is dirty, then returns the active
   * queue vector (`primary` when no pending issues, otherwise `resolved`).
   */
  [[nodiscard]] gpg::fastvector_n<WeakPtr<UserCommandIssueHelper>, 2>* RebuildAndGetUserUnitManagerQueue(
    UserCommandQueue* const managerPtr
  ) noexcept
  {
    if (managerPtr == nullptr) {
      return nullptr;
    }

    auto& manager = *managerPtr;
    if (manager.issueQueue.empty()) {
      return &manager.primaryLinks;
    }

    if (manager.resolvedLinksDirty == 0u) {
      return &manager.resolvedLinks;
    }

    manager.resolvedLinksDirty = 0u;
    manager.resolvedLinks.ResetStorageToInline();

    // Each live acknowledged command goes through a stack `WeakPtr` into the
    // resolved run (0x008B6FDC..0x008B7051).
    for (const WeakPtr<UserCommandIssueHelper>& link : manager.primaryLinks) {
      if (UserCommandIssueHelper* const helper = link.GetObjectPtr(); helper != nullptr) {
        manager.resolvedLinks.push_back(WeakPtr<UserCommandIssueHelper>(helper));
      }
    }

    for (const UserManagerHelperEntry& pending : manager.issueQueue) {
      // The kind is +0x04 (0x008B7092). This used to switch on +0x00, which
      // is the command id, so an Add was skipped (and a Reset ignored) unless
      // the id happened to match: a new command stayed out of
      // `GetCommandQueue()`, and a cleared one stayed in it, until the sim
      // acknowledged the edit. The UI's enhancement queue dropped the upgrade
      // it had just queued because it saw no Script command to pair it with.
      switch (pending.mEdit) {
      case EUserQueueEdit::Reset:
        manager.resolvedLinks.ResetStorageToInline();
        break;

      case EUserQueueEdit::Remove: {
        // No null test on the helper (0x008B70C5..0x008B70D9): a null one
        // matches the first retired link.
        auto found = manager.resolvedLinks.begin();
        while (found != manager.resolvedLinks.end() && found->GetObjectPtr() != pending.mHelper) {
          ++found;
        }
        if (found != manager.resolvedLinks.end()) {
          (void)manager.resolvedLinks.erase(found);
        }
        break;
      }

      case EUserQueueEdit::Add: {
        if (pending.mHelper == nullptr) {
          break;
        }

        if ((static_cast<std::uint32_t>(pending.mIndex) & 0xFF000000u) == 0xFF000000u) {
          manager.resolvedLinks.push_back(WeakPtr<UserCommandIssueHelper>(pending.mHelper));
          break;
        }

        UserCommandIssueHelper* const helperToInsert =
          FindSessionCommandIssueHelperById(WLD_GetActiveSession(), pending.mIndex);
        if (helperToInsert == nullptr) {
          break;
        }

        WeakPtr<UserCommandIssueHelper>* insertionPoint = manager.resolvedLinks.begin();
        while (insertionPoint != manager.resolvedLinks.end() && insertionPoint->GetObjectPtr() != helperToInsert) {
          ++insertionPoint;
        }
        if (insertionPoint == nullptr) {
          break;
        }

        const WeakPtr<UserCommandIssueHelper> inserted(helperToInsert);
        manager.resolvedLinks.InsertAt(insertionPoint, &inserted, &inserted + 1);
        break;
      }
      }
    }

    return &manager.resolvedLinks;
  }

  /**
   * Address: 0x008B6C50 (FUN_008B6C50)
   *
   * IDA signature:
   * _DWORD *__stdcall sub_8B6C50(int queue, _DWORD *commandIdRun);
   *
   * What it does:
   * Rebinds one command queue's primary link run to the command ids the sim
   * just replicated. The run is resized to the id count with cleared lanes,
   * then each lane is pointed at the live `UserCommandIssueHelper` the session
   * command manager holds for that id - unbinding first when the lane already
   * named a different helper, and left null when the id is unknown. The
   * resolved run is then invalidated back onto its inline storage and marked
   * dirty so the next reader rebuilds it.
   */
  [[maybe_unused]] void ResyncUserCommandQueueLinks(UserCommandQueue* const queue, const CmdId* const idBegin, const CmdId* const idEnd)
  {
    if (queue == nullptr) {
      return;
    }

    CommandManager* const commandManager = WLD_GetActiveSession()->mCommandManager;
    const std::size_t idCount = static_cast<std::size_t>(idEnd - idBegin);

    // The fill value is an empty link; it is a local in the binary too
    // (0x008B6C8A), unlinked again right after the resize.
    queue->primaryLinks.resize(idCount, WeakPtr<UserCommandIssueHelper>());

    for (std::size_t index = 0; index < idCount; ++index) {
      UserCommandIssueHelper* liveHelper = nullptr;
      if (commandManager != nullptr) {
        const auto found = commandManager->mCommands.find(idBegin[index]);
        if (found != commandManager->mCommands.end()) {
          liveHelper = found->second;
        }
      }

      queue->primaryLinks[index].ResetFromObject(liveHelper);
    }

    queue->resolvedLinksDirty = 1u;
    queue->resolvedLinks.ResetStorageToInline();
  }
  [[nodiscard]] Wm3::Vector3<float> InvalidCommandQueuePosition() noexcept
  {
    return Invalid<Wm3::Vector3<float>>();
  }

  [[nodiscard]] UserEntity* FindSessionEntityById(CWldSession* session, std::int32_t entityId) noexcept;
  [[nodiscard]] Wm3::Vector3<float>
  ResolvePositionFromRawTarget(const SSTITarget& target, CWldSession* const session) noexcept
  {
    if (target.mType == EAiTargetType::AITARGET_Ground) {
      return target.mPos;
    }

    if (target.mType == EAiTargetType::AITARGET_Entity) {
      if (UserEntity* const targetEntity = FindSessionEntityById(session, static_cast<std::int32_t>(target.mEntityId));
          targetEntity != nullptr) {
        return targetEntity->mVariableData.mCurTransform.pos_;
      }
    }

    return InvalidCommandQueuePosition();
  }

  [[nodiscard]] const UserCommandIssueLocalEvent*
  FindLatestIssueEvent(const UserCommandIssueHelper& helper, const ECommandIssueEvent type) noexcept
  {
    const fa::deque<UserCommandIssueLocalEvent>& events = helper.mLocalQueue;
    for (std::size_t index = events.size(); index != 0u; --index) {
      const UserCommandIssueLocalEvent& event = events[index - 1u];
      if (event.mType == type) {
        return &event;
      }
    }

    return nullptr;
  }

  /**
   * Address: 0x008B4140 (FUN_008B4140)
   *
   * What it does:
   * Scans command-issue events from newest to oldest and returns the most
   * recent explicit command-type override; otherwise returns helper baseline
   * command type.
   */
  [[nodiscard]] EUnitCommandType ResolveHelperCommandType(const UserCommandIssueHelper& helper) noexcept
  {
    if (const UserCommandIssueLocalEvent* const event = FindLatestIssueEvent(helper, ECommandIssueEvent::SetCommandType);
        event != nullptr) {
      return event->mCommandType;
    }

    return helper.mVariableData.mCmdType;
  }

  [[maybe_unused]] [[nodiscard]] Wm3::Vector3<float>
  ResolveHelperTargetPosition(const UserCommandIssueHelper& helper, CWldSession* const session) noexcept
  {
    if (const UserCommandIssueLocalEvent* const event = FindLatestIssueEvent(helper, ECommandIssueEvent::SetTarget);
        event != nullptr) {
      return ResolvePositionFromTarget(event->mTarget);
    }

    return ResolvePositionFromRawTarget(helper.mVariableData.mTarget1, session);
  }

  /**
   * Address: 0x008B4220 (FUN_008B4220)
   *
   * What it does:
   * Resolves one effective queued-build count from helper baseline count and
   * queued increase/decrease issue events.
   */
  [[maybe_unused]] [[nodiscard]] std::int32_t ResolveHelperBuildCount(const UserCommandIssueHelper& helper) noexcept
  {
    std::int32_t count = helper.mVariableData.mCount;
    const fa::deque<UserCommandIssueLocalEvent>& events = helper.mLocalQueue;
    for (std::size_t index = 0; index != events.size(); ++index) {
      const UserCommandIssueLocalEvent& event = events[index];
      if (event.mType == ECommandIssueEvent::DecreaseCount) {
        if (event.mCount == -1) {
          count = 0;
        } else {
          count -= event.mCount;
          if (count < 0) {
            count = 0;
          }
        }
        continue;
      }

      if (event.mType == ECommandIssueEvent::IncreaseCount && event.mCount > 0) {
        const std::int32_t updatedCount = count + event.mCount;
        count = (updatedCount < 0) ? 0 : updatedCount;
      }
    }

    return count;
  }

  [[nodiscard]] UserEntity* FindSessionEntityById(CWldSession* const session, const std::int32_t entityId) noexcept
  {
    if (session == nullptr) {
      return nullptr;
    }

    return session->LookupEntityId(entityId);
  }

  /**
   * Address: 0x008BEEC0 (the caching half of `UserUnit::GetClass`)
   *
   * What it does:
   * Resolves the reflected `UserUnit` type once into the static the binary
   * caches at 0x010C77AC.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedUserUnitType()
  {
    if (UserUnit::sType == nullptr) {
      UserUnit::sType = gpg::LookupRType(typeid(UserUnit));
    }
    return UserUnit::sType;
  }
}

