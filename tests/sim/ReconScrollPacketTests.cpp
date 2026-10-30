// Tests scroll snapshots and payload ownership across entity update fill paths.
#include <bit>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include "moho/entity/SSTIEntityVariableData.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/SimWorkerPool.h"
#include "moho/sim/UnitUpdateFill.h"

namespace
{
  using namespace moho;

  void Check(bool value, const char* what)
  {
    if (!value)
    {
      std::fprintf(stderr, "FAIL: %s\n", what);
      std::exit(1);
    }
  }

  std::uint32_t Bits(float f)
  {
    return std::bit_cast<std::uint32_t>(f);
  }

  void Run(int workers, bool enabled, bool finish, std::size_t count)
  {
    sim_Workers = workers;
    sim_ParallelSync = true;
    sim_ParallelEntitySync = enabled;

    SSTIEntityVariableData source;
    source.mScrollBeatStart = {-1.0f, -2.0f};
    source.mScrollBeatEnd = {-3.0f, -4.0f};
    source.mRequestRefreshUI = 1;
    source.mHealth = 13.0f;
    source.mMaxHealth = 31.0f;
    source.mAuxValueVector.resize(3);
    source.mAuxValueVector[2].mAttachedEntityId = 12345;

    SPerArmyReconInfo recon{};
    recon.mHealth = 17.0f;
    recon.mMaxHealth = 41.0f;
    recon.mFractionComplete = 0.75f;
    recon.mMaybeDead = 0;

    SSyncData packet;
    std::size_t deferredCount = 0;
    {
      CUnitUpdateFills fills(&packet);
      for (std::size_t i = 0; i < count; ++i)
      {
        auto* entry = QueueEntityVariableUpdateDeferred(&packet, static_cast<EntId>(i + 1), source);
        bool deferred = entry != nullptr;
        deferredCount += deferred;
        if (!entry)
          entry = QueueEntityVariableUpdate(&packet, static_cast<EntId>(i + 1), source);
        Check(entry != nullptr, "queue entry");

        // Every second record is ordinary: catches marker reuse and neighbor corruption.
        if ((i % 2) == 0)
        {
          SSTIEntityVariableData creator;
          creator.mScrollBeatStart = {-0.0f, 18.0f};
          creator.mScrollBeatEnd = {19.0f, 20.0f};
          OverrideEntityUpdateScroll(&packet, creator);
          // Scope ends before fill; no creator pointer may survive in deferred metadata.
          creator.mScrollBeatEnd = {91.0f, 92.0f};
          bool reconDeferred = OverrideDeferredEntityUpdateFromRecon(&packet, &recon);
          Check(reconDeferred == deferred, "newest deferred ownership");
          if (!reconDeferred)
          {
            entry->mVariableData.mMeshBlueprint = recon.mStiMesh;
            entry->mVariableData.mScmResource = recon.mMesh;
            entry->mVariableData.mHealth = recon.mHealth;
            entry->mVariableData.mMaxHealth = recon.mMaxHealth;
            entry->mVariableData.mFractionComplete = recon.mFractionComplete;
            entry->mVariableData.mIsDead = recon.mMaybeDead;
          }
        }
      }
      // Move legacy-vector records before fill.
      packet.mEntityUpdates.reserve(packet.mEntityUpdates.capacity() + 1024);
      source.mRequestRefreshUI = 0; // Entity::Sync clears this after queueing.
      if (finish)
        fills.Finish(); // Otherwise the destructor completes the serial fill.
    }

    // Finish/destructor has completed all reads before the source is mutated.
    source.mAuxValueVector[2].mAttachedEntityId = 54321;
    if (workers > 0 && enabled && finish)
    {
      const auto actualWorkers = CSimWorkerPool::Get().WorkerCount();
      Check(actualWorkers > 0, "worker pool available after Finish");
      std::printf(
        "packet count=%zu configured workers=%d pool workers=%u; dispatch completed\n",
        count, workers, actualWorkers
      );
      // The caller helps with chunks: this does not assert a worker took a chunk.
    }

    const auto expectedDeferred = (workers > 0 && enabled) ? (count < 65536 ? count : 65536) : 0;
    Check(deferredCount == expectedDeferred, "serial/deferred/full-list path");
    for (std::size_t i = 0; i < count; ++i)
    {
      const auto& entry = packet.mEntityUpdates[i];
      const auto& v = entry.mVariableData;
      Check(entry.mEntityId == static_cast<EntId>(i + 1), "record identity");
      Check(v.mRequestRefreshUI == 1, "queue-time refresh snapshot");
      Check(
        v.mAuxValueVector.size() == 3 && v.mAuxValueVector[2].mAttachedEntityId == 12345,
        "owned aux payload copy"
      );
      if ((i % 2) == 0)
      {
        Check(Bits(v.mScrollBeatStart.x) == 0x80000000u && v.mScrollBeatStart.y == 18.0f, "captured start bits");
        Check(v.mScrollBeatEnd.x == 19.0f && v.mScrollBeatEnd.y == 20.0f, "captured end, not creator mutation");
        Check(v.mHealth == 17.0f && v.mMaxHealth == 41.0f && v.mFractionComplete == 0.75f, "recon overrides retained");
      }
      else
      {
        Check(v.mScrollBeatStart.x == -1.0f && v.mScrollBeatStart.y == -2.0f, "ordinary start unaffected");
        Check(v.mScrollBeatEnd.x == -3.0f && v.mScrollBeatEnd.y == -4.0f, "ordinary end unaffected");
        Check(v.mHealth == 13.0f && v.mMaxHealth == 31.0f, "ordinary health unaffected");
      }
    }

    // Mutating one owned record must not mutate its neighbor or the source.
    Check(count >= 2, "neighbor ownership fixture");
    packet.mEntityUpdates[0].mVariableData.mAuxValueVector[2].mAttachedEntityId = 98765;
    Check(
      packet.mEntityUpdates[1].mVariableData.mAuxValueVector[2].mAttachedEntityId == 12345,
      "neighbor aux payload independent"
    );
    Check(source.mAuxValueVector[2].mAttachedEntityId == 54321, "source aux payload independent");
    Check(source.mScrollBeatStart.x == -1.0f && source.mScrollBeatEnd.x == -3.0f, "sim source endpoints unmodified");
    OverrideEntityUpdateScroll(nullptr, source);
    SSyncData empty;
    OverrideEntityUpdateScroll(&empty, source);
  }
}

int main()
{
  Run(0, true, true, 257);
  Run(2, false, true, 257);
  Run(2, true, true, 257);
  Run(2, true, false, 257);
  Run(2, true, true, 65537);
  Run(2, true, true, 257);
  std::puts("PASS native recon packet: serial, disabled, workers, destructor, overflow, reuse, aux ownership and endpoint bits");
  return 0;
}
