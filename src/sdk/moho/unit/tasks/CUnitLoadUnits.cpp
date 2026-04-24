#include "moho/unit/tasks/CUnitLoadUnits.h"

#include <algorithm>
#include <cstddef>
#include <cmath>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Logging.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/ai/IAiTransport.h"
#include "moho/command/CmdDefs.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CUnitMoveTask.h"

namespace moho
{
  [[nodiscard]]
  bool PrepareMove(int moveFlags, Unit* unit, Wm3::Vector3f* inOutPos, gpg::Rect2f* outSkirtRect, bool useWholeMap);
} // namespace moho

namespace
{
  constexpr std::uint64_t kUnitStateMaskTransportLoading = (1ull << static_cast<std::uint32_t>(moho::UNITSTATE_TransportLoading));
  constexpr std::uint64_t kUnitStateMaskHoldingPattern = (1ull << static_cast<std::uint32_t>(moho::UNITSTATE_HoldingPattern));
  constexpr int kPickupTimeoutTicks = 300;
  constexpr std::uintptr_t kInvalidEntitySlot = 0x8u;

  [[nodiscard]] moho::ETaskState NextTaskState(const moho::ETaskState state) noexcept
  {
    return static_cast<moho::ETaskState>(static_cast<std::int32_t>(state) + 1);
  }

  [[nodiscard]] bool IsUsableEntitySlot(const moho::Entity* const entity) noexcept
  {
    const std::uintptr_t raw = reinterpret_cast<std::uintptr_t>(entity);
    return raw != 0u && raw != kInvalidEntitySlot;
  }

  [[nodiscard]] bool IsUsableUnitSlot(const moho::Unit* const unit) noexcept
  {
    const std::uintptr_t raw = reinterpret_cast<std::uintptr_t>(unit);
    return raw != 0u && raw != kInvalidEntitySlot;
  }

  struct SPickUpInfoSortProbe
  {
    void* ownerLinkSlot;                       // +0x00
    moho::WeakPtr<moho::Unit>* nextInOwner;   // +0x04
    float distanceSq;                          // +0x08
  };
  static_assert(sizeof(SPickUpInfoSortProbe) == 0x0C, "SPickUpInfoSortProbe size must be 0x0C");
  static_assert(
    offsetof(SPickUpInfoSortProbe, ownerLinkSlot) == 0x00,
    "SPickUpInfoSortProbe::ownerLinkSlot offset must be 0x00"
  );
  static_assert(
    offsetof(SPickUpInfoSortProbe, nextInOwner) == 0x04,
    "SPickUpInfoSortProbe::nextInOwner offset must be 0x04"
  );
  static_assert(
    offsetof(SPickUpInfoSortProbe, distanceSq) == 0x08,
    "SPickUpInfoSortProbe::distanceSq offset must be 0x08"
  );

  [[nodiscard]] float ComputePickUpInfoLoadMetric(const SPickUpInfoSortProbe& probe) noexcept
  {
    const moho::Unit* const unit = moho::WeakPtr<moho::Unit>::DecodeOwnerObject(probe.ownerLinkSlot);
    GPG_ASSERT(unit != nullptr);
    const moho::RUnitBlueprint* const blueprint = unit != nullptr ? unit->GetBlueprint() : nullptr;
    GPG_ASSERT(blueprint != nullptr);
    if (blueprint == nullptr) {
      return 0.0f;
    }

    return ((blueprint->mAverageDensity * blueprint->mSizeZ) * blueprint->mSizeY) * blueprint->mSizeX;
  }

  void RestorePickUpInfoProbeOwnerChain(SPickUpInfoSortProbe& probe) noexcept
  {
    if (probe.ownerLinkSlot == nullptr) {
      return;
    }

    auto** cursor = reinterpret_cast<moho::WeakPtr<moho::Unit>**>(probe.ownerLinkSlot);
    auto* const stackNode = reinterpret_cast<moho::WeakPtr<moho::Unit>*>(&probe.ownerLinkSlot);
    while (*cursor != stackNode) {
      GPG_ASSERT(*cursor != nullptr);
      if (*cursor == nullptr) {
        return;
      }
      cursor = &(*cursor)->nextInOwner;
    }
    *cursor = probe.nextInOwner;
  }

  /**
   * Address: 0x006248D0 (FUN_006248D0)
   *
   * What it does:
   * Compares two temporary pickup-info probe lanes by transport load metric
   * (`sizeX * sizeY * sizeZ * averageDensity`), breaks ties by lower
   * distance-squared, and restores both intrusive weak-owner chains from the
   * probe copies before returning.
   */
  [[maybe_unused]] bool ComparePickUpInfoLoadMetricThenDistance(
    SPickUpInfoSortProbe lhsProbe,
    SPickUpInfoSortProbe rhsProbe
  ) noexcept
  {
    const float lhsMetric = ComputePickUpInfoLoadMetric(lhsProbe);
    const float rhsMetric = ComputePickUpInfoLoadMetric(rhsProbe);

    bool result = false;
    if (lhsMetric == rhsMetric) {
      result = rhsProbe.distanceSq > lhsProbe.distanceSq;
    } else if (lhsMetric > rhsMetric) {
      result = true;
    }

    RestorePickUpInfoProbeOwnerChain(lhsProbe);
    RestorePickUpInfoProbeOwnerChain(rhsProbe);
    return result;
  }

  /**
   * Address: 0x00628A60 (FUN_00628A60)
   *
   * What it does:
   * Copies pickup-entry weak-unit lanes and distance payload lanes from one
   * source range into one destination range while preserving intrusive-owner
   * weak-link integrity for each copied entry.
   */
  [[maybe_unused]] moho::SPickUpInfo* CopyPickUpInfoWeakUnitRange(
    moho::SPickUpInfo* destinationBegin,
    const moho::SPickUpInfo* sourceBegin,
    const moho::SPickUpInfo* sourceEnd
  ) noexcept
  {
    moho::SPickUpInfo* write = destinationBegin;
    const moho::SPickUpInfo* read = sourceBegin;
    while (read != sourceEnd) {
      if (read->mUnit.ownerLinkSlot != write->mUnit.ownerLinkSlot) {
        write->mUnit.ResetFromOwnerLinkSlot(read->mUnit.ownerLinkSlot);
      }
      write->mDistanceSq = read->mDistanceSq;
      ++write;
      ++read;
    }
    return write;
  }

  /**
   * Address: 0x00628AB0 (FUN_00628AB0)
   *
   * What it does:
   * Unlinks each pickup-entry weak-unit lane in `[begin, end)` from the unit
   * owner-chain intrusive list without changing vector capacity.
   */
  [[maybe_unused]] void UnlinkPickUpInfoWeakUnitRange(
    moho::SPickUpInfo* begin,
    moho::SPickUpInfo* end
  ) noexcept
  {
    for (; begin != end; ++begin) {
      auto** ownerCursor = reinterpret_cast<moho::WeakPtr<moho::Unit>**>(begin->mUnit.ownerLinkSlot);
      if (ownerCursor == nullptr) {
        continue;
      }

      while (*ownerCursor != &begin->mUnit) {
        ownerCursor = &(*ownerCursor)->nextInOwner;
      }
      *ownerCursor = begin->mUnit.nextInOwner;
    }
  }

  /**
   * Address: 0x00626EA0 (FUN_00626EA0)
   *
   * What it does:
   * Erases one pickup entry from vector runtime storage by weak-link-aware
   * left-shift of trailing entries, unlinks the former tail entry, shrinks the
   * end cursor, and stores the resulting iterator lane in `outIterator`.
   */
  [[maybe_unused]] [[nodiscard]] moho::SPickUpInfo** ErasePickUpInfoAndStoreIterator(
    msvc8::vector<moho::SPickUpInfo>& storage,
    moho::SPickUpInfo** const outIterator,
    moho::SPickUpInfo* const erasePos
  ) noexcept
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    if (erasePos == nullptr || view.end == nullptr) {
      if (outIterator != nullptr) {
        *outIterator = erasePos;
      }
      return outIterator;
    }

    (void)CopyPickUpInfoWeakUnitRange(erasePos, erasePos + 1, view.end);
    UnlinkPickUpInfoWeakUnitRange(view.end - 1, view.end);
    view.end -= 1;

    if (outIterator != nullptr) {
      *outIterator = erasePos;
    }
    return outIterator;
  }

  /**
   * Address: 0x006273B0 (FUN_006273B0, Moho::CUnitLoadUnits::ErasePickUpInfoRange)
   *
   * IDA signature:
   * _DWORD *__userpurge sub_6273B0@<eax>(int a1@<edi>, _DWORD *a2, int a3, int a4);
   *
   * What it does:
   * Erases the half-open range `[rangeBegin, rangeEnd)` from the
   * `mPickupQueue` lane by copying the live tail `[rangeEnd, end)` down to
   * `rangeBegin` with weak-link-aware element copy, unlinking the now-dead
   * tail window `[newEnd, end)` from each unit's owner weak-list, and
   * shrinking the active end cursor lane to `newEnd`. The resulting iterator
   * `rangeBegin` is written to `*outIterator` and returned, matching the
   * MSVC8 `std::vector<SPickUpInfo>::erase` range-overload instantiation.
   */
  [[nodiscard]] moho::SPickUpInfo** ErasePickUpInfoRange(
    msvc8::vector<moho::SPickUpInfo>& storage,
    moho::SPickUpInfo** const outIterator,
    moho::SPickUpInfo* const rangeBegin,
    moho::SPickUpInfo* const rangeEnd
  ) noexcept
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    if (rangeBegin != rangeEnd && view.end != nullptr) {
      // Shift `[rangeEnd, view.end)` down to `rangeBegin`. The helper
      // preserves each SPickUpInfo's intrusive weak-unit owner-chain link
      // as it relocates the entry.
      moho::SPickUpInfo* const newEnd = CopyPickUpInfoWeakUnitRange(rangeBegin, rangeEnd, view.end);

      // Unlink the now-vacated tail `[newEnd, view.end)` from each unit's
      // owner weak-list so the erased slots release their weak-pointer
      // subscriptions without touching vector capacity.
      UnlinkPickUpInfoWeakUnitRange(newEnd, view.end);

      // Shrink the active end cursor; capacity lane `view.capacityEnd`
      // remains untouched, matching binary behavior for erase-in-place.
      view.end = newEnd;
    }

    if (outIterator != nullptr) {
      *outIterator = rangeBegin;
    }
    return outIterator;
  }

  [[nodiscard]] bool AllocatePickUpInfoStorage(
    msvc8::vector<moho::SPickUpInfo>& storage,
    const std::size_t elementCount
  ) noexcept
  {
    auto& view = msvc8::AsVectorRuntimeView(storage);
    if (elementCount == 0u) {
      view.begin = nullptr;
      view.end = nullptr;
      view.capacityEnd = nullptr;
      return true;
    }

    if (elementCount > (static_cast<std::size_t>(-1) / sizeof(moho::SPickUpInfo))) {
      return false;
    }

    void* rawStorage = nullptr;
    try {
      rawStorage = ::operator new(sizeof(moho::SPickUpInfo) * elementCount);
    } catch (...) {
      return false;
    }

    view.begin = static_cast<moho::SPickUpInfo*>(rawStorage);
    view.end = view.begin;
    view.capacityEnd = view.begin + elementCount;
    return true;
  }

  [[nodiscard]] moho::SPickUpInfo* CopyConstructPickUpInfoRange(
    moho::SPickUpInfo* destination,
    const moho::SPickUpInfo* sourceBegin,
    const moho::SPickUpInfo* sourceEnd
  ) noexcept
  {
    moho::SPickUpInfo* write = destination;
    for (const moho::SPickUpInfo* read = sourceBegin; read != sourceEnd; ++read, ++write) {
      ::new (write) moho::SPickUpInfo(*read);
    }
    return write;
  }

  /**
   * Address: 0x00628560 (FUN_00628560)
   *
   * What it does:
   * Assigns one `vector<SPickUpInfo>` lane using the original weak-link-aware
   * copy/unlink sequence, reusing storage when possible and preserving
   * intrusive owner-chain correctness for every element transition.
   */
  [[maybe_unused]] [[nodiscard]] msvc8::vector<moho::SPickUpInfo>& AssignPickUpInfoVectorPreservingWeakLinks(
    msvc8::vector<moho::SPickUpInfo>& destination,
    const msvc8::vector<moho::SPickUpInfo>& source
  ) noexcept
  {
    if (&destination == &source) {
      return destination;
    }

    auto& destinationView = msvc8::AsVectorRuntimeView(destination);
    const auto& sourceView = msvc8::AsVectorRuntimeView(source);

    const std::size_t sourceCount =
      sourceView.begin ? static_cast<std::size_t>(sourceView.end - sourceView.begin) : 0u;
    if (sourceCount == 0u) {
      UnlinkPickUpInfoWeakUnitRange(destinationView.begin, destinationView.end);
      destinationView.end = destinationView.begin;
      return destination;
    }

    const std::size_t currentCount =
      destinationView.begin ? static_cast<std::size_t>(destinationView.end - destinationView.begin) : 0u;
    const moho::SPickUpInfo* const sourceBegin = sourceView.begin;
    const moho::SPickUpInfo* const sourceEnd = sourceView.end;

    if (sourceCount > currentCount) {
      const std::size_t capacityCount =
        destinationView.begin ? static_cast<std::size_t>(destinationView.capacityEnd - destinationView.begin) : 0u;
      if (sourceCount <= capacityCount) {
        const moho::SPickUpInfo* const sourceTailBegin = sourceBegin + currentCount;
        (void)CopyPickUpInfoWeakUnitRange(destinationView.begin, sourceBegin, sourceTailBegin);
        destinationView.end = CopyConstructPickUpInfoRange(destinationView.end, sourceTailBegin, sourceEnd);
        return destination;
      }

      if (destinationView.begin != nullptr) {
        UnlinkPickUpInfoWeakUnitRange(destinationView.begin, destinationView.end);
        ::operator delete(destinationView.begin);
      }

      destinationView.begin = nullptr;
      destinationView.end = nullptr;
      destinationView.capacityEnd = nullptr;
      if (AllocatePickUpInfoStorage(destination, sourceCount)) {
        destinationView.end = CopyConstructPickUpInfoRange(destinationView.begin, sourceBegin, sourceEnd);
      }
      return destination;
    }

    moho::SPickUpInfo* const assignedEnd = CopyPickUpInfoWeakUnitRange(destinationView.begin, sourceBegin, sourceEnd);
    UnlinkPickUpInfoWeakUnitRange(assignedEnd, destinationView.end);
    destinationView.end = destinationView.begin + sourceCount;
    return destination;
  }

  void RunUnitScript(moho::Unit* const unit, const char* const scriptName)
  {
    if (unit == nullptr || scriptName == nullptr) {
      return;
    }

    (void)unit->RunScript(scriptName);
  }

  [[nodiscard]] bool IsEligiblePickupCandidate(const moho::Unit* const unit) noexcept
  {
    if (!IsUsableUnitSlot(unit)) {
      return false;
    }

    if (unit->IsDead() || unit->IsBeingBuilt() || unit->DestroyQueued()) {
      return false;
    }

    if (unit->IsUnitState(moho::UNITSTATE_Attached) || unit->IsUnitState(moho::UNITSTATE_WaitingForTransport)) {
      return false;
    }

    return unit->GetTransportedBy() == nullptr;
  }

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedPickupQueueType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(msvc8::vector<moho::SPickUpInfo>));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedUnitEntitySetType()
  {
    gpg::RType* type = moho::EntitySetTemplate<moho::Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::EntitySetTemplate<moho::Unit>));
      moho::EntitySetTemplate<moho::Unit>::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedVector3Type()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return type;
  }
} // namespace

namespace moho
{
  gpg::RType* CUnitLoadUnits::sType = nullptr;

  /**
   * Address: 0x00624AC0 (FUN_00624AC0, Moho::CUnitLoadUnits::CUnitLoadUnits)
   *
   * What it does:
   * Initializes one detached load-units task lane with empty pickup queue,
   * empty requested-unit set, and cleared runtime flags.
   */
  CUnitLoadUnits::CUnitLoadUnits()
    : CCommandTask()
    , mPickupQueue()
    , mRequestedUnits()
    , mPickupCenter{0.0f, 0.0f, 0.0f}
    , mReadyUnitCount(0)
    , mLoadedUnitCount(0)
    , mProcessingTicks(0)
    , mIsStagingPlatform(false)
    , mIsTeleporter(false)
    , mCompletedSuccessfully(false)
    , mPadding83_87{}
  {}

  /**
   * Address: 0x00624B70 (FUN_00624B70, Moho::CUnitLoadUnits::CUnitLoadUnits)
   *
   * What it does:
   * Initializes one parent-linked load-units task, copies requested units,
   * binds transport mode flags, links unit-set ownership in EntityDB, and
   * starts transport-loading script/state.
   */
  CUnitLoadUnits::CUnitLoadUnits(CCommandTask* const parentTask, const SEntitySetTemplateUnit& requestedUnits)
    : CCommandTask(parentTask)
    , mPickupQueue()
    , mRequestedUnits(requestedUnits)
    , mPickupCenter{0.0f, 0.0f, 0.0f}
    , mReadyUnitCount(0)
    , mLoadedUnitCount(0)
    , mProcessingTicks(0)
    , mIsStagingPlatform(false)
    , mIsTeleporter(false)
    , mCompletedSuccessfully(false)
    , mPadding83_87{}
  {
    if (mUnit == nullptr) {
      return;
    }

    if (mUnit->SimulationRef != nullptr && mUnit->SimulationRef->mEntityDB != nullptr) {
      mUnit->SimulationRef->mEntityDB->RegisterEntitySet(mRequestedUnits);
    }

    if (IAiTransport* const transport = mUnit->AiTransport; transport != nullptr) {
      mIsStagingPlatform = transport->TransportIsAirStagingPlatform();
      mIsTeleporter = transport->TransportIsTeleporter();
    }

    mUnit->UnitStateMask |= kUnitStateMaskTransportLoading;
    RunUnitScript(mUnit, "OnStartTransportLoading");
  }

  /**
   * Address: 0x00624CC0 (FUN_00624CC0, Moho::CUnitLoadUnits::~CUnitLoadUnits)
   *
   * What it does:
   * Stops transport-loading task state, clears waiting-formation lanes,
   * aborts pending pickup units on failure paths, and finalizes dispatch
   * result/status.
   */
  CUnitLoadUnits::~CUnitLoadUnits()
  {
    if (mUnit != nullptr) {
      RunUnitScript(mUnit, "OnStopTransportLoading");
      mUnit->FreeOgridRect();
      mUnit->UnitStateMask &= ~kUnitStateMaskTransportLoading;

      if (IAiTransport* const transport = mUnit->AiTransport; transport != nullptr) {
        transport->TransportClearWaitingFormation();

        if (!mCompletedSuccessfully) {
          RunUnitScript(mUnit, "OnTransportAborted");
          for (SPickUpInfo& pickupInfo : mPickupQueue) {
            Unit* const pickupUnit = pickupInfo.GetUnit();
            if (!IsUsableUnitSlot(pickupUnit)) {
              continue;
            }

            if (mProcessingTicks > kPickupTimeoutTicks) {
              transport->TransportRemovePickupUnit(pickupUnit, true);
            }

            Unit* const transportedBy = pickupUnit->GetTransportedBy();
            if (transportedBy != mUnit) {
              if (mProcessingTicks <= kPickupTimeoutTicks) {
                transport->TransportRemovePickupUnit(pickupUnit, true);
              }

              if (IAiNavigator* const navigator = pickupUnit->AiNavigator; navigator != nullptr) {
                navigator->AbortMove();
              }
            }
          }
        }
      }
    }

    *mDispatchResult = static_cast<EAiResult>(2 - static_cast<int>(mCompletedSuccessfully));
  }

  /**
   * Address: 0x006250B0 (FUN_006250B0, Moho::CUnitLoadUnits::operator new)
   *
   * What it does:
   * Allocates one load-units task and forwards constructor arguments into
   * in-place construction.
   */
  CUnitLoadUnits* CUnitLoadUnits::Create(CCommandTask* const parentTask, const SEntitySetTemplateUnit* const requestedUnits)
  {
    if (requestedUnits == nullptr) {
      return nullptr;
    }

    void* const storage = ::operator new(sizeof(CUnitLoadUnits));
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitLoadUnits(parentTask, *requestedUnits);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }

  /**
   * Address: 0x00625110 (FUN_00625110, Moho::CUnitLoadUnits::DoTask)
   *
   * What it does:
   * Rebuilds pickup candidates, selects loadable units by transport slot
   * availability, computes pickup center, and submits pickup orders into
   * transport AI.
   */
  void CUnitLoadUnits::DoTask()
  {
    if (mUnit == nullptr || mUnit->AiTransport == nullptr) {
      return;
    }

    IAiTransport* const transport = mUnit->AiTransport;

    mReadyUnitCount = 0;
    mProcessingTicks = 0;
    mPickupCenter = Wm3::Vector3f{0.0f, 0.0f, 0.0f};
    mPickupQueue.clear();

    const EntitySetTemplate<Unit> loadedUnits = transport->TransportGetLoadedUnits(true);
    mLoadedUnitCount = static_cast<std::int32_t>(loadedUnits.Size());

    for (Entity* const unitSlot : mRequestedUnits.mVec) {
      Unit* const candidate = SEntitySetTemplateUnit::UnitFromEntry(unitSlot);
      if (!IsEligiblePickupCandidate(candidate)) {
        continue;
      }

      const Wm3::Vector3f& ownerPos = mUnit->GetPosition();
      const Wm3::Vector3f& candidatePos = candidate->GetPosition();
      const float dx = ownerPos.x - candidatePos.x;
      const float dy = ownerPos.y - candidatePos.y;
      const float dz = ownerPos.z - candidatePos.z;
      const float distanceSq = (dx * dx) + (dy * dy) + (dz * dz);
      mPickupQueue.push_back(SPickUpInfo(candidate, distanceSq));
    }

    std::sort(
      mPickupQueue.begin(),
      mPickupQueue.end(),
      [](const SPickUpInfo& lhs, const SPickUpInfo& rhs) noexcept { return lhs.mDistanceSq < rhs.mDistanceSq; }
    );

    EntitySetTemplate<Unit> unitsToPickup{};
    bool rejectedByCapacity = false;

    for (std::size_t index = 0; index < mPickupQueue.size();) {
      Unit* const candidate = mPickupQueue[index].GetUnit();
      if (!IsUsableUnitSlot(candidate) || candidate->IsDead()) {
        moho::SPickUpInfo* const erasePos = mPickupQueue.data() + index;
        moho::SPickUpInfo* eraseResult = nullptr;
        (void)ErasePickUpInfoRange(mPickupQueue, &eraseResult, erasePos, erasePos + 1);
        continue;
      }

      if (transport->TransportAssignSlot(candidate, -1)) {
        const Wm3::Vector3f& pos = candidate->GetPosition();
        mPickupCenter.x += pos.x;
        mPickupCenter.y += pos.y;
        mPickupCenter.z += pos.z;

        (void)unitsToPickup.Add(candidate);
        (void)mRequestedUnits.ContainsUnit(candidate);
        ++mReadyUnitCount;

        if (transport->TransportGetWaitingFormation() != nullptr) {
          transport->TransportRemoveFromWaitingList(candidate);
        }

        ++index;
      } else {
        moho::SPickUpInfo* const erasePos = mPickupQueue.data() + index;
        moho::SPickUpInfo* eraseResult = nullptr;
        (void)ErasePickUpInfoRange(mPickupQueue, &eraseResult, erasePos, erasePos + 1);
        rejectedByCapacity = true;
      }
    }

    if (
      rejectedByCapacity
      && !mIsTeleporter
      && !mIsStagingPlatform
      && !mUnit->IsUnitState(UNITSTATE_AssistMoving)
      && !mUnit->IsUnitState(UNITSTATE_Ferrying)
      && !mUnit->IsUnitState(UNITSTATE_Guarding)
    ) {
      RunUnitScript(mUnit, "OnTransportFull");
    }

    if (mReadyUnitCount > 0) {
      if (mIsStagingPlatform) {
        mPickupCenter = mUnit->GetPosition();
      } else {
        const float invCount = 1.0f / static_cast<float>(mReadyUnitCount);
        mPickupCenter.x *= invCount;
        mPickupCenter.y *= invCount;
        mPickupCenter.z *= invCount;

        gpg::Rect2f moveSkirt{0.0f, 0.0f, 0.0f, 0.0f};
        const bool useWholeMap = (mUnit->ArmyRef != nullptr) && mUnit->ArmyRef->UseWholeMap();
        (void)PrepareMove(0, mUnit, &mPickupCenter, &moveSkirt, useWholeMap);

        gpg::Rect2i reservationRect{};
        const SCoordsVec2 pickupCenterXZ{mPickupCenter.x, mPickupCenter.z};
        (void)COORDS_ToGridRect(&reservationRect, pickupCenterXZ, mUnit->GetFootprint());
        mUnit->ReserveOgridRect(reservationRect);
      }

      transport->TransportAddPickupUnits(unitsToPickup, SCoordsVec2{mPickupCenter.x, mPickupCenter.z});

      if (mUnit->IsUnitState(UNITSTATE_Ferrying) || mUnit->IsUnitState(UNITSTATE_AssistMoving)) {
        for (Unit* const pickupUnit : unitsToPickup) {
          if (!IsUsableUnitSlot(pickupUnit)) {
            continue;
          }

          pickupUnit->AssignedTransportRef.ResetObjectPtr(mUnit);

          IAiNavigator* const navigator = pickupUnit->AiNavigator;
          if (navigator == nullptr) {
            continue;
          }

          if (
            mUnit->IsUnitState(UNITSTATE_Ferrying)
            && pickupUnit->IsUnitState(UNITSTATE_WaitForFerry)
            && !pickupUnit->IsUnitState(UNITSTATE_TransportLoading)
          ) {
            navigator->AbortMove();
          } else {
            navigator->BroadcastResumeTaskEvent();
          }
        }

        mRequestedUnits.Clear();
        mPickupQueue.clear();
      }
    }

    if (!mRequestedUnits.Empty() && transport->TransportGetWaitingFormation() == nullptr && (mIsStagingPlatform || mIsTeleporter)) {
      EntitySetTemplate<Unit> waitingUnits{};
      mRequestedUnits.CopyTo(waitingUnits);
      transport->TransportGenerateWaitingFormationForUnits(waitingUnits);
    }
  }

  /**
   * Address: 0x00625950 (FUN_00625950, Moho::CUnitLoadUnits::TaskTick)
   *
   * What it does:
   * Executes the transport-loading task state machine across prepare/wait/
   * start/process/complete phases, including teleporter checks and retry
   * transitions.
   */
  int CUnitLoadUnits::Execute()
  {
    if (mUnit == nullptr || mUnit->AiTransport == nullptr) {
      return -1;
    }

    IAiTransport* const transport = mUnit->AiTransport;

    if (mIsTeleporter) {
      const Wm3::Vector3f teleportDestination = transport->TransportGetTeleportDest();
      if (teleportDestination.x == 0.0f && teleportDestination.y == 0.0f && teleportDestination.z == 0.0f) {
        gpg::Logf("No teleport destination set for this teleporter. Cancelling teleportation task.");
        return -1;
      }
    }

    if (mUnit->mCurrentLayer == LAYER_Seabed) {
      return -1;
    }

    switch (mTaskState) {
      case TASKSTATE_Preparing: {
        if (!mUnit->IsUnitState(UNITSTATE_AssistMoving) && !mUnit->IsUnitState(UNITSTATE_Ferrying)) {
          mUnit->UnitStateMask |= kUnitStateMaskHoldingPattern;

          CUnitCommand* const ownerHeadCommand = mUnit->CommandQueue != nullptr ? mUnit->CommandQueue->GetCurrentCommand() : nullptr;
          for (Entity* const unitSlot : mRequestedUnits.mVec) {
            Unit* const candidate = SEntitySetTemplateUnit::UnitFromEntry(unitSlot);
            if (!IsUsableUnitSlot(candidate)) {
              continue;
            }

            if (candidate->IsDead() || candidate->IsBeingBuilt() || candidate->IsUnitState(UNITSTATE_Attached)
                || candidate->DestroyQueued()) {
              continue;
            }

            CUnitCommand* const candidateHeadCommand =
              candidate->CommandQueue != nullptr ? candidate->CommandQueue->GetCurrentCommand() : nullptr;
            if (candidateHeadCommand != ownerHeadCommand) {
              return 1;
            }
          }

          mUnit->UnitStateMask &= ~kUnitStateMaskHoldingPattern;
        }

        DoTask();
        mTaskState = NextTaskState(mTaskState);
        return 0;
      }

      case TASKSTATE_Waiting: {
        if (!mUnit->IsMobile()) {
          mTaskState = NextTaskState(mTaskState);
          return 1;
        }

        if (mLoadedUnitCount == 0 && !transport->TransportHasAvailableStorage()) {
          return -1;
        }

        if (mIsStagingPlatform || mIsTeleporter || !mUnit->mIsAir) {
          if (IAiNavigator* const navigator = mUnit->AiNavigator; navigator != nullptr) {
            navigator->AbortMove();
          }

          mTaskState = NextTaskState(mTaskState);
          return 1;
        }

        RunUnitScript(mUnit, "OnTransportOrdered");

        if (mUnit->mCurrentLayer != LAYER_Air && !mUnit->IsUnitState(UNITSTATE_AssistMoving)) {
          const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();
          if (blueprint != nullptr) {
            const Wm3::Vector3f& ownerPos = mUnit->GetPosition();
            const float dx = ownerPos.x - mPickupCenter.x;
            const float dz = ownerPos.z - mPickupCenter.z;
            const float distance = std::sqrt((dx * dx) + (dz * dz));
            if (distance <= blueprint->AI.GuardScanRadius) {
              mTaskState = NextTaskState(mTaskState);
              return 1;
            }
          }
        }

        const SOCellPos pickupCell = mUnit->GetFootprint().ToCellPos(mPickupCenter);
        SNavGoal pickupGoal(pickupCell);
        pickupGoal.mLayer = LAYER_Land;
        NewMoveTask(pickupGoal, this, 0, nullptr, 1);

        if (CUnitMotion* const motion = mUnit->UnitMotion; motion != nullptr) {
          motion->SetFacing(transport->TransportGetPickupFacing());
        }

        mTaskState = NextTaskState(mTaskState);
        return 1;
      }

      case TASKSTATE_Starting:
        transport->TransportAtPickupPosition();
        mTaskState = NextTaskState(mTaskState);
        return 1;

      case TASKSTATE_Processing: {
        if (mIsStagingPlatform) {
          if (transport->TransportGetPickupUnitCount() != 0u) {
            return 10;
          }

          mTaskState = NextTaskState(mTaskState);
          return 1;
        }

        ++mProcessingTicks;
        if (transport->TransportGetPickupUnitCount() != 0u && mProcessingTicks <= kPickupTimeoutTicks) {
          return 1;
        }

        const EntitySetTemplate<Unit> waitingForPickup = transport->TransportGetUnitsWaitingForPickup();
        mRequestedUnits.AddUnits(waitingForPickup);

        if (!mRequestedUnits.Empty() && mIsTeleporter) {
          mTaskState = TASKSTATE_Preparing;
          return 1;
        }

        mCompletedSuccessfully = (mProcessingTicks <= kPickupTimeoutTicks);
        return -1;
      }

      case TASKSTATE_Complete: {
        bool loadedUnitsEmpty = false;
        if (transport != nullptr) {
          const EntitySetTemplate<Unit> loaded = transport->TransportGetLoadedUnits(true);
          loadedUnitsEmpty = loaded.Empty();
        }

        if (!loadedUnitsEmpty) {
          return 10;
        }

        const EntitySetTemplate<Unit> waitingForPickup = transport->TransportGetUnitsWaitingForPickup();
        mRequestedUnits.AddUnits(waitingForPickup);

        if (!mRequestedUnits.Empty()) {
          mTaskState = TASKSTATE_Preparing;
          return 1;
        }

        mCompletedSuccessfully = true;
        return -1;
      }

      default:
        return 1;
    }
  }

  /**
   * Address: 0x00629070 (FUN_00629070)
   *
   * What it does:
   * Loads base task state, pickup queue lanes, requested-unit set, pickup
   * center, counters, and transport mode flags from archive storage.
   */
  void CUnitLoadUnits::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Read(CachedCCommandTaskType(), static_cast<CCommandTask*>(this), ownerRef);
    archive->Read(CachedPickupQueueType(), &mPickupQueue, ownerRef);
    archive->Read(CachedUnitEntitySetType(), &mRequestedUnits, ownerRef);
    archive->Read(CachedVector3Type(), &mPickupCenter, ownerRef);
    archive->ReadInt(&mReadyUnitCount);
    archive->ReadInt(&mLoadedUnitCount);
    archive->ReadInt(&mProcessingTicks);
    archive->ReadBool(&mIsStagingPlatform);
    archive->ReadBool(&mIsTeleporter);
    archive->ReadBool(&mCompletedSuccessfully);
  }

  /**
   * Address: 0x006291B0 (FUN_006291B0)
   *
   * What it does:
   * Saves base task state, pickup queue lanes, requested-unit set, pickup
   * center, counters, and transport mode flags into archive storage.
   */
  void CUnitLoadUnits::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->Write(CachedCCommandTaskType(), static_cast<const CCommandTask*>(this), ownerRef);
    archive->Write(CachedPickupQueueType(), &mPickupQueue, ownerRef);
    archive->Write(CachedUnitEntitySetType(), &mRequestedUnits, ownerRef);
    archive->Write(CachedVector3Type(), &mPickupCenter, ownerRef);
    archive->WriteInt(mReadyUnitCount);
    archive->WriteInt(mLoadedUnitCount);
    archive->WriteInt(mProcessingTicks);
    archive->WriteBool(mIsStagingPlatform);
    archive->WriteBool(mIsTeleporter);
    archive->WriteBool(mCompletedSuccessfully);
  }
} // namespace moho
