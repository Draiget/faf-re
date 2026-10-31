#include "moho/animation/PoseJobs.h"

#include <cstdint>
#include <typeinfo>
#include <vector>

#include "gpg/core/profiling/Profiler.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaCallGate.h"
#include "moho/ai/EEconResourceTypeInfo.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAnimationManipulator.h"
#include "moho/animation/CRotateManipulator.h"
#include "moho/animation/CSlaveManipulator.h"
#include "moho/animation/CSlideManipulator.h"
#include "moho/animation/CStorageManipulator.h"
#include "moho/animation/IAniManipulator.h"
#include "moho/console/CConCommand.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/SimJobStream.h"
#include "moho/sim/SimThreadRole.h"
#include "moho/sim/SimWorkerPool.h"
#include "moho/unit/core/Unit.h"

namespace moho
{
  bool sim_ParallelPose = true;
  TConVar<bool> gTConVar_sim_ParallelPose(
    "sim_ParallelPose",
    "Unit pose updates whose manipulators touch only their own unit run on sim workers (when "
    "sim_Workers > 0); same poses, same order of everything else.",
    &sim_ParallelPose
  );

  namespace
  {
    // Pose jobs held at once; at this many the stream is finished and started again. A heavy
    // 12-player beat queues ~1,800 between closes; small enough that the jobs and the ticket table
    // (128 KB) stay in cache, since every queued update looks its actor up.
    constexpr std::size_t kJobCapacity = 1u << 12;
    // Actor -> ticket table, open addressing; twice the job capacity keeps probes short.
    constexpr std::size_t kTableSize = kJobCapacity * 2u;

    struct SPoseJob
    {
      CAniActor* mActor = nullptr;
      VTransform mTransform{};
      SPoseJobInputs mInputs{};
    };

    struct STicketEntry
    {
      const CAniActor* mActor = nullptr;
      std::int32_t mTicket = 0;
    };

    struct SPoseJobs
    {
      std::vector<SPoseJob> mJobs = std::vector<SPoseJob>(kJobCapacity);
      std::size_t mJobCount = 0;
      std::vector<STicketEntry> mTable = std::vector<STicketEntry>(kTableSize);
      std::vector<std::size_t> mUsedSlots; // table entries to clear
      bool mGateSet = false;

      std::uint64_t mQueued = 0;
      std::uint64_t mInline = 0;
      std::uint64_t mStages = 0;

      // Jobs the sim thread ran or waited for, by who asked: a pose reader, an engine call from Lua
      // (the gate), or a close (end of stage A, a Lua collection, the stream full).
      std::uint64_t mReaderTaken = 0;
      std::uint64_t mGateTaken = 0;
      std::uint64_t mCloseTaken = 0;
    } sPoseJobs;

    /// Jobs the sim thread has stolen or waited for so far.
    [[nodiscard]] std::uint64_t TakenBySimThread() noexcept
    {
      const CSimJobStream::SStats& stats = CSimJobStream::Get().Stats();
      return stats.mStolen + stats.mWaited;
    }

    thread_local const SPoseJobInputs* tJobInputs = nullptr;

    [[nodiscard]] std::size_t SlotOf(const CAniActor* const actor) noexcept
    {
      const auto bits = reinterpret_cast<std::uintptr_t>(actor);
      return static_cast<std::size_t>((bits >> 4) * 0x9E3779B97F4A7C15ull) & (kTableSize - 1u);
    }

    [[nodiscard]] STicketEntry* FindEntry(const CAniActor* const actor) noexcept
    {
      for (std::size_t slot = SlotOf(actor);; slot = (slot + 1u) & (kTableSize - 1u)) {
        STicketEntry& entry = sPoseJobs.mTable[slot];
        if (entry.mActor == actor) {
          return &entry;
        }
        if (entry.mActor == nullptr) {
          return nullptr;
        }
      }
    }

    void RememberTicket(const CAniActor* const actor, const std::int32_t ticket)
    {
      for (std::size_t slot = SlotOf(actor);; slot = (slot + 1u) & (kTableSize - 1u)) {
        STicketEntry& entry = sPoseJobs.mTable[slot];
        if (entry.mActor == actor) {
          entry.mTicket = ticket;
          return;
        }
        if (entry.mActor == nullptr) {
          entry.mActor = actor;
          entry.mTicket = ticket;
          sPoseJobs.mUsedSlots.push_back(slot);
          return;
        }
      }
    }

    void RunPoseJob(void* const context)
    {
      const SPoseJob& job = *static_cast<const SPoseJob*>(context);
      tJobInputs = &job.mInputs;
      job.mActor->UpdateManipulators(job.mTransform);
      tJobInputs = nullptr;
    }

    /// Finishes every queued job, releases the workers, forgets the tickets.
    void CloseStream()
    {
      const std::uint64_t taken = TakenBySimThread();
      CSimJobStream::Get().Close();
      sPoseJobs.mCloseTaken += TakenBySimThread() - taken;
      for (const std::size_t slot : sPoseJobs.mUsedSlots) {
        sPoseJobs.mTable[slot] = STicketEntry{};
      }
      sPoseJobs.mUsedSlots.clear();
      sPoseJobs.mJobCount = 0;
      if (sPoseJobs.mGateSet) {
        LUA_SetCallGate(nullptr);
        sPoseJobs.mGateSet = false;
      }
    }

    /// Lua reaches engine state only through C functions and finalizers: queued pose updates
    /// finish first. A collection (null) also releases the workers, so its parallel mark and sweep
    /// can use them.
    void PoseJobsGate(const LuaCFunctionPtr function)
    {
      if (function == nullptr) {
        CloseStream();
        return;
      }
      if (!LUA_IsLibraryCFunction(function)) {
        const std::uint64_t taken = TakenBySimThread();
        CSimJobStream::Get().FinishAll();
        sPoseJobs.mGateTaken += TakenBySimThread() - taken;
      }
    }

    /// Rotate, Slide, Slave, Animation and Storage read their own pose plus the inputs
    /// SPoseJobInputs copies; any other manipulator reads other units or calls Lua.
    [[nodiscard]] bool IsOwnPoseManipulator(const IAniManipulator& manipulator) noexcept
    {
      // Descriptor addresses, not type_info::operator==, which falls back to strcmp on the names
      // for every type that differs (__std_type_info_compare). The exe holds one descriptor per
      // type; were there a second, the answer would be "no" and the unit would update serially.
      const std::type_info* const type = &typeid(manipulator);
      return type == &typeid(CRotateManipulator) || type == &typeid(CSlideManipulator) ||
        type == &typeid(CSlaveManipulator) || type == &typeid(CAnimationManipulator) ||
        type == &typeid(CStorageManipulator);
    }

    // Set by the last CanQueue walk (sim thread only): the actor has a storage manipulator, the one
    // reader of the army economy inputs.
    bool sSawStorage = false;

    /**
     * An own-pose type no thread waits on. With no waiters, a signal only sets the manipulator's
     * own `mTriggered` (CTaskEvent::EventSetSignaled); waiters are added only by Lua's WaitFor,
     * which the gate keeps out while jobs are pending.
     */
    [[nodiscard]] bool IsQueueable(const IAniManipulator& manipulator)
    {
      if (&typeid(manipulator) == &typeid(CStorageManipulator)) {
        sSawStorage = true;
      }
      return IsOwnPoseManipulator(manipulator) && manipulator.mWaitLinks.mNext == &manipulator.mWaitLinks;
    }

    [[nodiscard]] bool CanQueue(const CAniActor& actor)
    {
      sSawStorage = false;
      return actor.AllEnabledManipulators(&IsQueueable);
    }

    void CaptureInputs(const Unit& unit, SPoseJobInputs& inputs)
    {
      inputs.mUnit = &unit;
      inputs.mTransformOrient = unit.GetTransform().orient_;
      inputs.mVelocity = unit.GetVelocity();
      inputs.mCurOrient = unit.mVarDat.mCurTransform.orient_;
      inputs.mLastOrient = unit.mVarDat.mLastTransform.orient_;
      inputs.mBeingBuilt = unit.IsBeingBuilt();
      inputs.mHasEconomy = false;
      if (!sSawStorage) {
        return;
      }
      if (CArmyImpl* const army = unit.ArmyRef; army != nullptr) {
        if (const CSimArmyEconomyInfo* const economyInfo = army->GetEconomy(); economyInfo != nullptr) {
          inputs.mHasEconomy = true;
          inputs.mMaxStorageEnergy = economyInfo->economy.MaxStorageOf(ECON_ENERGY);
          inputs.mMaxStorageMass = economyInfo->economy.MaxStorageOf(ECON_MASS);
          inputs.mStoredEnergy = economyInfo->economy.mStored.ENERGY;
          inputs.mStoredMass = economyInfo->economy.mStored.MASS;
        }
      }
    }
  } // namespace

  const SPoseJobInputs* POSE_JobInputsFor(const Unit* const unit) noexcept
  {
    const SPoseJobInputs* const inputs = tJobInputs;
    return (inputs != nullptr && inputs->mUnit == unit) ? inputs : nullptr;
  }

  void POSE_UpdateManipulators(Unit& unit)
  {
    CAniActor* const actor = unit.AniActor;
    const bool queueable =
      sim_ParallelPose && !IsSimWorkerThread() && CSimWorkerPool::ParallelEnabled() && CanQueue(*actor);
    if (!queueable) {
      if (CSimJobStream::Get().IsOpen()) {
        ++sPoseJobs.mInline;
      }
      actor->UpdateManipulators(unit.mPendingTransform);
      return;
    }

    CSimJobStream& stream = CSimJobStream::Get();
    if (sPoseJobs.mJobCount == kJobCapacity) {
      CloseStream();
    }
    POSE_WaitFor(actor); // an earlier update of this actor still queued (not expected within a stage)

    SPoseJob& job = sPoseJobs.mJobs[sPoseJobs.mJobCount];
    job.mActor = actor;
    job.mTransform = unit.mPendingTransform;
    CaptureInputs(unit, job.mInputs);

    const std::int32_t ticket = stream.Enqueue(&RunPoseJob, &job);
    if (ticket == CSimJobStream::kRanInline) {
      ++sPoseJobs.mInline;
      return;
    }
    ++sPoseJobs.mJobCount;
    ++sPoseJobs.mQueued;
    RememberTicket(actor, ticket);
    if (!sPoseJobs.mGateSet) {
      LUA_SetCallGate(&PoseJobsGate);
      sPoseJobs.mGateSet = true;
    }
  }

  void POSE_WaitFor(const CAniActor* const actor)
  {
    // Inside a pose job (on a worker, or stolen by the sim thread) the job reads only its own pose,
    // which it is writing: waiting there would wait for itself.
    if (actor == nullptr || sPoseJobs.mJobCount == 0u || IsSimWorkerThread() || tJobInputs != nullptr) {
      return;
    }
    if (const STicketEntry* const entry = FindEntry(actor); entry != nullptr) {
      const std::uint64_t taken = TakenBySimThread();
      CSimJobStream::Get().Finish(entry->mTicket);
      sPoseJobs.mReaderTaken += TakenBySimThread() - taken;
    }
  }

  void POSE_FinishStage()
  {
    if (!CSimJobStream::Get().IsOpen() && sPoseJobs.mJobCount == 0u) {
      return;
    }
    CloseStream();
    if ((++sPoseJobs.mStages % 1000u) == 0u) {
      const CSimJobStream::SStats& stats = CSimJobStream::Get().Stats();
      gpg::Logf(
        "sim_ParallelPose: %llu pose updates queued, %llu on the sim thread while jobs were pending; "
        "of the queued, sim thread ran %llu and waited for %llu (%.1f ms); taken for readers %llu, "
        "engine calls from Lua %llu, closes %llu; %llu worker wake calls, %llu stream opens",
        static_cast<unsigned long long>(sPoseJobs.mQueued),
        static_cast<unsigned long long>(sPoseJobs.mInline),
        static_cast<unsigned long long>(stats.mStolen),
        static_cast<unsigned long long>(stats.mWaited),
        static_cast<double>(stats.mWaitMicroseconds) / 1000.0,
        static_cast<unsigned long long>(sPoseJobs.mReaderTaken),
        static_cast<unsigned long long>(sPoseJobs.mGateTaken),
        static_cast<unsigned long long>(sPoseJobs.mCloseTaken),
        static_cast<unsigned long long>(stats.mWakeCalls),
        static_cast<unsigned long long>(stats.mOpens)
      );
    }
  }
} // namespace moho
