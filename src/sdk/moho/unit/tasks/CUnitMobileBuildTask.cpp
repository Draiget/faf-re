#include "moho/unit/tasks/CUnitMobileBuildTask.h"

#include <memory>
#include <new>
#include <typeinfo>

#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/Entity.h"
#include "moho/misc/WeakPtr.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/Sim.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr std::uint64_t kUnitStateBuildingMask = (1ull << moho::UNITSTATE_Building);
  constexpr std::uint64_t kUnitStateNoReclaimMask = (1ull << moho::UNITSTATE_NoReclaim);

  // Reflection-type caches used by the archive load/save lanes. The binary
  // caches each reflected `gpg::RType*` in a dedicated global initialized on
  // first use via `gpg::LookupRType(typeid(...))`. Where the type owns a
  // class-static `sType` (CCommandTask, WeakPtr<T>, gpg::Rect2<T>) we mirror
  // that lane; where it does not (CBuildTaskHelper, Wm3::Vector3f,
  // Wm3::Quaternionf) we mirror the binary's file-level `Xxx__sType` global
  // with a file-static cache, exactly as the sibling CUnitPatrolTask does for
  // `Wm3::Box3f`.

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCBuildTaskHelperType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CBuildTaskHelper));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3<float>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedQuaternionfType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Quaternion<float>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrUnitType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      moho::WeakPtr<moho::Unit>::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedWeakPtrEntityType()
  {
    gpg::RType* type = moho::WeakPtr<moho::Entity>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakPtr<moho::Entity>));
      moho::WeakPtr<moho::Entity>::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedRect2iType()
  {
    gpg::RType* type = gpg::Rect2i::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(gpg::Rect2<int>));
      gpg::Rect2i::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedRect2fType()
  {
    gpg::RType* type = gpg::Rect2f::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(gpg::Rect2<float>));
      gpg::Rect2f::sType = type;
    }
    return type;
  }

  struct CUnitCommandEventBroadcasterRuntimeView
  {
    std::byte mPad00_33[0x34];
    moho::Broadcaster mEventBroadcaster;
  };

  static_assert(
    offsetof(CUnitCommandEventBroadcasterRuntimeView, mEventBroadcaster) == 0x34,
    "CUnitCommandEventBroadcasterRuntimeView::mEventBroadcaster offset must be 0x34"
  );

  [[nodiscard]] moho::Broadcaster* ResolveCommandEventBroadcaster(moho::CUnitCommand* const command)
  {
    if (command == nullptr) {
      return nullptr;
    }

    auto* const runtimeView = reinterpret_cast<CUnitCommandEventBroadcasterRuntimeView*>(command);
    return &runtimeView->mEventBroadcaster;
  }

  [[nodiscard]] moho::CUnitCommand* ResolveQueueHeadCommand(moho::Unit* const unit)
  {
    if (unit == nullptr || unit->CommandQueue == nullptr || unit->CommandQueue->mCommandVec.empty()) {
      return nullptr;
    }

    return unit->CommandQueue->mCommandVec.front().GetObjectPtr();
  }

  [[nodiscard]] moho::SOCellPos BuildPlacementCellFromTargetPosition(
    const Wm3::Vector3f& targetPosition,
    const moho::RUnitBlueprint* const blueprint
  )
  {
    moho::SOCellPos buildCell{};
    if (blueprint == nullptr) {
      return buildCell;
    }

    const float halfSizeX = static_cast<float>(blueprint->mFootprint.mSizeX) * 0.5f;
    const float halfSizeZ = static_cast<float>(blueprint->mFootprint.mSizeZ) * 0.5f;
    buildCell.x = static_cast<std::int16_t>(static_cast<int>(targetPosition.x - halfSizeX));
    buildCell.z = static_cast<std::int16_t>(static_cast<int>(targetPosition.z - halfSizeZ));
    return buildCell;
  }

  [[nodiscard]] Wm3::Vector3f ResolveBuildPlacementPosition(
    const moho::Sim* const sim,
    const moho::RUnitBlueprint* const blueprint,
    const Wm3::Vector3f& targetPosition
  )
  {
    if (sim == nullptr || sim->mMapData == nullptr || blueprint == nullptr) {
      return targetPosition;
    }

    const moho::SOCellPos buildCell = BuildPlacementCellFromTargetPosition(targetPosition, blueprint);
    return moho::COORDS_ToWorldPos(sim->mMapData, buildCell, blueprint->mFootprint);
  }

  [[nodiscard]] gpg::Rect2i BuildRectFromPlacementPosition(
    const Wm3::Vector3f& placementPosition,
    const moho::RUnitBlueprint* const blueprint
  )
  {
    gpg::Rect2i buildRect{};
    if (blueprint == nullptr) {
      return buildRect;
    }

    buildRect.x0 =
      static_cast<int>(placementPosition.x - static_cast<float>(blueprint->mFootprint.mSizeX) * 0.5f);
    buildRect.z0 =
      static_cast<int>(placementPosition.z - static_cast<float>(blueprint->mFootprint.mSizeZ) * 0.5f);
    buildRect.x1 = buildRect.x0 + static_cast<int>(blueprint->mFootprint.mSizeX);
    buildRect.z1 = buildRect.z0 + static_cast<int>(blueprint->mFootprint.mSizeZ);
    return buildRect;
  }

  [[nodiscard]] gpg::Rect2f BuildSkirtFromPlacementPosition(
    const Wm3::Vector3f& placementPosition,
    const moho::RUnitBlueprint* const blueprint
  )
  {
    if (blueprint == nullptr) {
      return {};
    }

    return blueprint->GetSkirtRect(moho::SCoordsVec2{placementPosition.x, placementPosition.z});
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005F6400 (FUN_005F6400, ??0CUnitMobileBuildTask@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes detached mobile-build-task storage for reflection lanes:
   * command/listener subobjects, build-helper defaults, and build target
   * placement/runtime weak-link state.
   */
  CUnitMobileBuildTask::CUnitMobileBuildTask()
    : CCommandTask()
    , CUnitMobileBuildTaskListenerPad{}
    , Listener<ECommandEvent>()
    , mBuildHelper()
    , mCommand(nullptr)
    , mBlueprint(nullptr)
    , mBuildPosition(Wm3::Vector3f{0.0f, 0.0f, 1.0f})
    , mBuildOrientation(Wm3::Quatf{0.0f, 0.0f, 0.0f, 0.0f})
    , mBuildDirection(Wm3::Vector3f::Zero())
    , mPlacementRetryCount(0)
    , mBuildUnit{}
    , mPendingBuildEntity{}
    , mBuildRect{}
    , mBuildSkirt{}
  {
    mListenerPad = 0;
    mListenerLink.ListResetLinks();
    mBuildUnit.ClearLinkState();
    mPendingBuildEntity.ClearLinkState();
  }

  /**
   * Address: 0x005F6520 (FUN_005F6520, ??0CUnitMobileBuildTask@Moho@@QAE@@Z_0)
   *
   * What it does:
   * Initializes one dispatch-bound mobile-build task, binds command-listener
   * lanes, resolves build placement from footprint/cell coordinates, and
   * primes runtime build-area/skirt caches.
   */
  CUnitMobileBuildTask::CUnitMobileBuildTask(
    CCommandTask* const dispatchTask,
    const RUnitBlueprint* const blueprint,
    const Wm3::Vector3f& buildPosition,
    const Wm3::Quatf& buildOrientation,
    const Wm3::Vector3f& buildDirection
  )
    : CCommandTask(dispatchTask)
    , CUnitMobileBuildTaskListenerPad{}
    , Listener<ECommandEvent>()
    , mBuildHelper("MobileBuild", dispatchTask != nullptr ? dispatchTask->mUnit : nullptr)
    , mCommand(nullptr)
    , mBlueprint(blueprint)
    , mBuildPosition(buildPosition)
    , mBuildOrientation(buildOrientation)
    , mBuildDirection(buildDirection)
    , mPlacementRetryCount(0)
    , mBuildUnit{}
    , mPendingBuildEntity{}
    , mBuildRect{}
    , mBuildSkirt{}
  {
    mListenerPad = 0;
    mListenerLink.ListResetLinks();
    mBuildUnit.ClearLinkState();
    mPendingBuildEntity.ClearLinkState();

    mCommand = ResolveQueueHeadCommand(mUnit);
    if (mCommand != nullptr) {
      if (Broadcaster* const eventBroadcaster = ResolveCommandEventBroadcaster(mCommand); eventBroadcaster != nullptr) {
        mListenerLink.ListLinkBefore(eventBroadcaster);
      }
    }

    mBuildPosition = ResolveBuildPlacementPosition(mSim, mBlueprint, mBuildPosition);
    mBuildRect = BuildRectFromPlacementPosition(mBuildPosition, mBlueprint);
    mBuildSkirt = BuildSkirtFromPlacementPosition(mBuildPosition, mBlueprint);
  }

  /**
   * Address: 0x00605CD0 (FUN_00605CD0)
   *
   * What it does:
   * Stores one blueprint pointer lane and returns this task.
   */
  CUnitMobileBuildTask* CUnitMobileBuildTask::SetBlueprint(const RUnitBlueprint* const blueprint) noexcept
  {
    mBlueprint = blueprint;
    return this;
  }

  /**
   * Address: 0x005F6AC0 (FUN_005F6AC0, ??1CUnitMobileBuildTask@Moho@@QAE@@Z)
   *
   * What it does:
   * Clears owner/build-unit state bits, commits dispatch result lane for
   * failed/interrupted completion, and tears down helper + weak-link lanes.
   */
  CUnitMobileBuildTask::~CUnitMobileBuildTask()
  {
    if (mUnit != nullptr) {
      mUnit->UnitStateMask &= ~kUnitStateBuildingMask;
      if (mUnit->AiBuilder != nullptr) {
        mUnit->AiBuilder->BuilderSetAimTarget(Wm3::Vector3f::Zero());
      }
    }

    if (Unit* const buildUnit = mBuildUnit.GetObjectPtr(); buildUnit != nullptr) {
      buildUnit->UnitStateMask &= ~kUnitStateNoReclaimMask;
    }

    mBuildHelper.OnStopBuild(true);

    if (mDispatchResult != nullptr) {
      if (mTaskState == TASKSTATE_5) {
        *mDispatchResult = static_cast<EAiResult>(1);
      } else {
        if (mUnit != nullptr) {
          mUnit->RunScript("OnFailedToBuild");
        }
        *mDispatchResult = static_cast<EAiResult>(2);
      }
    }

    if (mUnit != nullptr) {
      mUnit->FreeOgridRect();
    }

    mPendingBuildEntity.UnlinkFromOwnerChain();
    mPendingBuildEntity.ClearLinkState();
    mBuildUnit.UnlinkFromOwnerChain();
    mBuildUnit.ClearLinkState();

    if (!mListenerLink.ListIsSingleton()) {
      mListenerLink.ListUnlink();
    }
    mListenerLink.ListResetLinks();
  }

  /**
   * Address: 0x005F8370 (FUN_005F8370, ??2CUnitMobileBuildTask@Moho@@QAE@@Z_0)
   *
   * What it does:
   * Allocates one mobile-build task object and forwards arguments into
   * dispatch-bound in-place construction.
   */
  CUnitMobileBuildTask* CUnitMobileBuildTask::Create(
    CCommandTask* const dispatchTask,
    const RUnitBlueprint* const blueprint,
    const Wm3::Vector3f& buildPosition,
    const Wm3::Quatf& buildOrientation,
    const Wm3::Vector3f& buildDirection
  )
  {
    auto* const raw = static_cast<CUnitMobileBuildTask*>(::operator new(sizeof(CUnitMobileBuildTask), std::nothrow));
    if (raw == nullptr) {
      return nullptr;
    }

    auto guard = std::unique_ptr<CUnitMobileBuildTask, void (*)(CUnitMobileBuildTask*)>(raw, [](CUnitMobileBuildTask* p) {
      ::operator delete(p);
    });

    return std::construct_at(guard.release(), dispatchTask, blueprint, buildPosition, buildOrientation, buildDirection);
  }

  /**
   * Address: 0x005FE710 (FUN_005FE710, Moho::CUnitMobileBuildTask::MemberDeserialize)
   *
   * IDA signature:
   * void __usercall MemberDeserialize(CUnitCommand** this@<ecx>, gpg::ReadArchive* archive@<eax>);
   *
   * What it does:
   * Restores mobile-build-task state from an archive, lane by lane in binary
   * order (12 reads). The transform / rect / weak-link / helper lanes flow
   * through the reflected `Read`; the two tracked pointer lanes through the
   * typed `ReadPointer_*` slots; the placement-retry counter through the
   * virtual `ReadInt` slot.
   */
  void CUnitMobileBuildTask::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    // The binary reuses one zero-initialized owner-ref record across every
    // reflected `Read` (each call re-zeroes it before use); mirror that with a
    // single fresh, empty owner-ref.
    const gpg::RRef ownerRef{};

    // 1. base CCommandTask sub-object (offset 0x00).
    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(this), ownerRef);

    // 2. embedded build helper (offset 0x40).
    archive->Read(CachedCBuildTaskHelperType(), &mBuildHelper, ownerRef);

    // 3. command pointer lane (offset 0x84).
    archive->ReadPointer_CUnitCommand(&mCommand, &ownerRef);

    // 4. blueprint pointer lane (offset 0x88). ReadPointer_RUnitBlueprint wants
    //    a non-const `RUnitBlueprint**`; round-trip through a mutable local.
    RUnitBlueprint* blueprint = const_cast<RUnitBlueprint*>(mBlueprint);
    archive->ReadPointer_RUnitBlueprint(&blueprint, &ownerRef);
    mBlueprint = blueprint;

    // 5-7. build transform payloads (offsets 0x8C / 0x98 / 0xA8).
    archive->Read(CachedVector3fType(), &mBuildPosition, ownerRef);
    archive->Read(CachedQuaternionfType(), &mBuildOrientation, ownerRef);
    archive->Read(CachedVector3fType(), &mBuildDirection, ownerRef);

    // 8. placement-retry counter (offset 0xB4) via the virtual ReadInt slot.
    archive->ReadInt(&mPlacementRetryCount);

    // 9-10. runtime weak links (offsets 0xB8 / 0xC0).
    archive->Read(CachedWeakPtrUnitType(), &mBuildUnit, ownerRef);
    archive->Read(CachedWeakPtrEntityType(), &mPendingBuildEntity, ownerRef);

    // 11-12. build area / skirt rects (offsets 0xC8 / 0xD8).
    archive->Read(CachedRect2iType(), &mBuildRect, ownerRef);
    archive->Read(CachedRect2fType(), &mBuildSkirt, ownerRef);
  }

  /**
   * Address: 0x005FE950 (FUN_005FE950, Moho::CUnitMobileBuildTask::MemberSerialize)
   *
   * IDA signature:
   * void __usercall MemberSerialize(CUnitMobileBuildTask* this@<eax>, gpg::WriteArchive* archive@<esi>);
   *
   * What it does:
   * Line-for-line write mirror of `MemberDeserialize` over the identical field
   * set and order (12 writes). The reflected `Write` lanes carry an empty owner
   * ref; the two tracked pointer lanes build a typed `RRef_*` and emit it as an
   * unowned raw pointer; the placement-retry counter is written through the
   * virtual `WriteInt` slot.
   */
  void CUnitMobileBuildTask::MemberSerialize(gpg::WriteArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};

    // 1. base CCommandTask sub-object (offset 0x00).
    archive->Write(CachedCCommandTaskType(), static_cast<CCommandTask*>(this), ownerRef);

    // 2. embedded build helper (offset 0x40).
    archive->Write(CachedCBuildTaskHelperType(), &mBuildHelper, ownerRef);

    // 3. command pointer lane (offset 0x84): typed RRef then unowned raw pointer.
    gpg::RRef pointerRef{};
    (void)gpg::RRef_CUnitCommand(&pointerRef, mCommand);
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, ownerRef);

    // 4. blueprint pointer lane (offset 0x88).
    (void)gpg::RRef_RUnitBlueprint(&pointerRef, const_cast<RUnitBlueprint*>(mBlueprint));
    gpg::WriteRawPointer(archive, pointerRef, gpg::TrackedPointerState::Unowned, ownerRef);

    // 5-7. build transform payloads (offsets 0x8C / 0x98 / 0xA8).
    archive->Write(CachedVector3fType(), &mBuildPosition, ownerRef);
    archive->Write(CachedQuaternionfType(), &mBuildOrientation, ownerRef);
    archive->Write(CachedVector3fType(), &mBuildDirection, ownerRef);

    // 8. placement-retry counter (offset 0xB4) via the virtual WriteInt slot.
    archive->WriteInt(mPlacementRetryCount);

    // 9-10. runtime weak links (offsets 0xB8 / 0xC0).
    archive->Write(CachedWeakPtrUnitType(), &mBuildUnit, ownerRef);
    archive->Write(CachedWeakPtrEntityType(), &mPendingBuildEntity, ownerRef);

    // 11-12. build area / skirt rects (offsets 0xC8 / 0xD8).
    archive->Write(CachedRect2iType(), &mBuildRect, ownerRef);
    archive->Write(CachedRect2fType(), &mBuildSkirt, ownerRef);
  }
} // namespace moho
