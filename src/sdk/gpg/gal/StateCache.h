#pragma once
#include <bitset>

#include "D3D9Utils.h"
#include <cstddef>
#include <functional>

namespace gpg::gal
{
    /**
	 * Primary template for StateCache.
	 * Provides a single virtual entry (slot 0) to flush/apply cached states.
	 */
    template <class StateT, class ValueT>
    class StateCache {
    public:
        using state_type = StateT;
        using value_type = ValueT;

        /**
         * Push all pending (dirty) states to the backend.
         */
        virtual void Apply() = 0;  // vftable slot 0

    protected:
        /**
         * Non-virtual dtor to keep vtable minimal;
         * do not delete via base*.
         */
        ~StateCache() = default;
    };

	/**
	 * Traits tweak points : number of states and units(stages / samplers).
	 * Override via explicit specialization if you want exact sizes.
	 */
    template <class StateT>
    struct StateTraits {
        static constexpr std::size_t kNumStates = 256; // safe upper bound
        static constexpr std::size_t kNumUnits = 1;   // global (no stages)
    };

    // RenderState: global, no stages.
    template <>
    struct StateTraits<d3d9::RenderState> {
        static constexpr std::size_t kNumStates = 256; // D3D9 RS range upper bound
        static constexpr std::size_t kNumUnits = 1;
    };

    // SamplerState: per-sampler, typically 16 samplers.
    template <>
    struct StateTraits<d3d9::SamplerState> {
        static constexpr std::size_t kNumStates = 32;  // enough for all SS enums
        static constexpr std::size_t kNumUnits = 16;  // D3D9 has 16 samplers
    };

    // TextureStageState: per-stage, typically 8 stages in fixed function.
    template <>
    struct StateTraits<d3d9::TextureStageState> {
        static constexpr std::size_t kNumStates = 64;  // wide margin
        static constexpr std::size_t kNumUnits = 8;   // D3D9 FF pipeline
    };

    /**
	 * Generic cache implementation with dirty-bit tracking.
	 * NumUnits  = 1 for global states, >1 for per-stage/per-sampler states.
	 * NumStates = number of distinct state keys in the enum domain.
	 */
    template <
        class StateT,
        class ValueT,
        std::size_t NumStates = StateTraits<StateT>::kNumStates,
        std::size_t NumUnits = StateTraits<StateT>::kNumUnits
    >
    class StateCacheImpl : public StateCache<StateT, ValueT> {
    public:
        static_assert(NumStates > 0 && NumUnits > 0);

        using state_type = StateT;
        using value_type = ValueT;

        /**
         * Backend setter: (unit, state, value) -> set state on device
         */
        using Setter = std::function<void(std::uint32_t unit, StateT state, ValueT value)>;

        /**
         * Construct with a backend setter callback
         */
        explicit StateCacheImpl(Setter setter)
            : setter_(std::move(setter))
        {
            // Initialize with "unknown" sentinel values; mark all dirty.
            for (std::size_t u = 0; u < NumUnits; ++u) {
                values_[u].fill(std::numeric_limits<ValueT>::max());
                dirty_[u].set(); // mark all bits dirty
            }
        }

        /**
         * Set a state; unit is ignored when NumUnits == 1.
         */
        void Set(std::uint32_t unit, StateT state, ValueT value) {
            const std::size_t u = (NumUnits == 1) ? 0u : static_cast<std::size_t>(unit % NumUnits);
            const std::size_t s = index_of(state);
            if (values_[u][s] != value) {
                values_[u][s] = value;
                dirty_[u].set(s);
            }
        }

        /**
         * Get the cached value; unit is ignored when NumUnits == 1.
         */
        ValueT Get(const std::uint32_t unit, StateT state) const {
            const std::size_t u = (NumUnits == 1) ? 0u : static_cast<std::size_t>(unit % NumUnits);
            return values_[u][index_of(state)];
        }

        /**
         * Mark all states dirty to force a full re-apply.
         */
        void InvalidateAll() noexcept {
            for (auto& d : dirty_) d.set();
        }

        /**
         * Apply all dirty states via the backend setter.
         */
        void Apply() override {
            if (!setter_) return;
            for (std::size_t u = 0; u < NumUnits; ++u) {
                auto& d = dirty_[u];
                while (d.any()) {
                    const std::size_t s = next_bit(d);
                    setter_(u, state_of(s), values_[u][s]);
                    d.reset(s);
                }
            }
        }

    private:
        /**
         * Convert enum to contiguous index in [0, NumStates).
         */
        static constexpr std::size_t index_of(StateT s) noexcept {
            if constexpr (std::is_enum_v<StateT>) {
                return static_cast<std::size_t>(static_cast<std::underlying_type_t<StateT>>(s)) % NumStates;
            } else {
                return static_cast<std::uint32_t>(s) % NumStates;
            }
        }

        /**
         * Convert index back to enum (best-effort).
         */
        static constexpr StateT state_of(std::size_t i) noexcept {
            if constexpr (std::is_enum_v<StateT>) {
                return static_cast<StateT>(static_cast<std::underlying_type_t<StateT>>(i));
            } else {
                return static_cast<StateT>(i);
            }
        }

        /**
         * Pop lowest set bit index from bitset (linear scan; small domains).
         */
        static std::size_t next_bit(const std::bitset<NumStates>& b) noexcept {
            // NumStates is small (<=256/64), linear scan is fine here.
            for (std::size_t i = 0; i < NumStates; ++i)
                if (b.test(i)) return i;
            return NumStates; // unreachable when caller checks any()
        }

    private:
        std::array<std::array<ValueT, NumStates>, NumUnits> values_{};
        std::array<std::bitset<NumStates>, NumUnits> dirty_{};
        Setter setter_;
    };


    /**
     * Convenience typedefs for common D3D9 state domains.
     * These map to the same template family the original binary likely used.
     */
    using RenderStateCacheImpl = StateCacheImpl<d3d9::RenderState, unsigned int>;
    using SamplerStateCacheImpl = StateCacheImpl<d3d9::SamplerState, unsigned int>;
    using TextureStageStateCacheImpl = StateCacheImpl<d3d9::TextureStageState, unsigned int>;
}
