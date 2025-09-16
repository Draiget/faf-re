#pragma once
#include <array>
#include <optional>

#include "IAiSiloBuild.h"
#include "../../gpg/core/containers/IntrusiveLink.h"

namespace moho
{
	class Unit;
    struct EconReservationHandle; // engine ticket for reserving economy

	/** Per-slot info for stockpiled munitions (e.g., Nuke / AntiNuke). */
    struct SiloSlot {
        class UnitWeapon* entry{ nullptr };   // points to a blueprint/record
        int builtCount{ 0 };    // how many already stockpiled
        int desiredCount{ 0 };  // target amount to keep
    };

    enum class SiloType : int {
        kNuke = 0,
        kAntiNuke = 1
    };

    enum class BuildState : int {
        kIdle = 0,
        kPrepare = 1,
        kActive = 2,
        kFinish = 3
    };

	class CAiSiloBuildImpl : public IAiSiloBuild
	{
        // Primary vftable (12 entries)
	public:
        /**
         * dtor
         *
         * Address: 0x5CF640
         * VFTable SLOT: 0
         */
        virtual ~CAiSiloBuildImpl() = default;

        /**
         * Re-scan owner's weapon/stockpile records and (re)bind two slots:
         * slot[0] = "nuke", slot[1] = "anti-nuke" (heuristic by flags).
         * Resets counters and marks owner as "dirty" for econ/UI refresh.
         *
         * Address: 0x5CEE40
         * VFTable SLOT: 1
         */
        virtual void RefreshSlotsFromOwner() = 0;

        /**
         * Check whether currently active queue/category equals the given type.
         * Returns true if matches.
         *
         * Address: 0x5CEF00
         * VFTable SLOT: 2
         */
        [[nodiscard]] virtual bool IsActiveType(SiloType type) const = 0; 

        /**
         * Test "built + queued >= desired" for the given type.
         * Caller uses it to decide if more should be scheduled.
         *
         * Address: 0x5CEF20
         * VFTable SLOT: 3
         */
        [[nodiscard]] virtual bool IsSufficient(SiloType type) const = 0;

        /**
         * Count how many entries of a given type are in the pending queue.
         * Implementation walks an intrusive ring list.
         *
         * Address: 0x5CEF50
         * VFTable SLOT: 4
         */
        [[nodiscard]] virtual int GetQueuedCount(SiloType type) const = 0;

        /**
         * Return how many are already stockpiled for the given type.
         *
         * Address: 0x5CEF80
         * VFTable SLOT: 5
         */
        [[nodiscard]] virtual int GetBuiltCount(SiloType type) const = 0;

        /**
         * Return desired target count for the given type.
         *
         * Address: 0x5CEF90
         * VFTable SLOT: 6
         */
        [[nodiscard]] virtual int GetDesiredCount(SiloType type) const = 0; 

        /**
         * Adjust built counter (e.g., on completion/consumption) and mark owner dirty.
         *
         * Address: 0x5CEFA0
         * VFTable SLOT: 7
         */
        virtual void AddToBuilt(SiloType type, int delta) = 0;

        /**
         * Try enqueueing a new stockpile build of the given type.
         * Validates blueprint flags; rejects if not allowed or already "busy".
         * Returns true on success.
         *
         * Address: 0x5CEFC0
         * VFTable SLOT: 8
         */
        virtual bool TryEnqueue(SiloType type) = 0;

        /**
         * Main state-machine tick:
         *  - Performs gating checks (paused, power off, etc.),
         *  - PREPARE: pulls blueprint, computes rates using
         *    GetEconomyBuildRate / GetEnergyBuildAdjMod / GetMassBuildAdjMod,
         *    creates econ reservation and fires OnSiloBuildStart,
         *  - ACTIVE: advances work (engine-side helper),
         *  - FINISH: clears owner hooks/flags, fires OnSiloBuildEnd & OnNukeArmed,
         *    pops the queue and resets.
         * Returns true if it did any meaningful work this tick.
         *
         * Address: 0x5CF1E0
         * VFTable SLOT: 9
         */
        virtual bool Tick() = 0;

        /**
         * Small SSE-heavy helper used by the state machine (details unknown).
         * Likely computes smoothed progress/time-left for UI/economy.
         *
         * Address: 0x5CF030
         * VFTable SLOT: 10
         */
        virtual int EvalVectorHelperA(int arg) = 0;

        /**
         * Another SSE helper from the same blob (details unknown).
         *
         * Address: 0x5CF130 (points into the 0x5CF038 blob)
         * VFTable SLOT: 11
         */
        virtual int EvalVectorHelperB(int arg) = 0; // slot 11

	public:
        /** Convenience: true if we still need more for this type. */
        [[nodiscard]] bool NeedsMore(SiloType t) const noexcept {
            return !IsSufficient(t);
        }

        /** Return suggested next type to build (simple heuristic). */
        [[nodiscard]] std::optional<SiloType> SuggestNextType() const noexcept {
            if (!IsSufficient(SiloType::kNuke))     return SiloType::kNuke;
            if (!IsSufficient(SiloType::kAntiNuke)) return SiloType::kAntiNuke;
            return std::nullopt;
        }
	public:
        // --------- Observed fields (semantic sketch, not ABI-accurate) ---------
        // observed at this[1]
        // Offset: 0x04
        Unit* owner_{ nullptr };

        // entry/built/desired for [0]=nuke,[1]=anti (sub_5CEE40)
        // Offset: 0x08
        std::array<SiloSlot, 2> slots_{};

        // 0x08 - slots_[0].entry (Nuke)
        // 0x0C - slots_[0].builtCount
        // 0x10 - slots_[0].desiredCount
        // 0x14 - slots_[1].entry(AntiNuke)
        // 0x18 - slots_[1].builtCount
        // 0x1C - slots_[1].desiredCount

        // node used when enqueuing (sub_5CEFC0)
        void* qPrev; // 0x20
        void* qNext; // 0x24

        int32_t activeTypeId; // 0x28  // 0=AntiNuke, 1=Nuke

        // intrusive ring head at this[9]
        // Offset: 0x2C
        void* queueHead_{ nullptr };

        // used as a gate in Idle→Prepare
        // Offset: 0x30
        BuildState state_{ BuildState::kIdle };

        // nominal 500.0
        // Offset: 0x34
        float workUnitsBase;

        // Economy/reservation bookkeeping (created during Prepare, freed on Finish)
        // Offset: 0x38
        EconReservationHandle* econ_{ nullptr };

        // computed via GetEnergyBuildAdjMod
        // Offset: 0x3C
        float        energyPerSec_{ 0.f };

        // computed via GetMassBuildAdjMod
        // Offset: 0x40
        float        massPerSec_{ 0.f };

        // based on GetEconomyBuildRate and blueprint time
        // Offset: 0x44           
        float        maxProgress{ 0.f };

        // transient progress (reset on Finish)
        // Offset: 0x48                
        float        progress_{ 0.f };
	};
}
