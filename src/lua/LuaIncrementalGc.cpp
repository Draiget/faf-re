#include "lua/LuaIncrementalGc.h"

#include <atomic>
#include <cstdint>
#include <cstddef>

namespace moho::lua_incremental
{
	namespace
	{
		// The client creates many short-lived Lua states (startup, scratch,
		// rules, colour tables) besides the sim and UI VMs. Keep the registry
		// large enough that no live state is ever displaced, and probe by hash
		// so a barrier does not walk every slot.
		constexpr std::size_t kStateSlots = 128;
		constexpr std::size_t kIncrementalVmSlots = 2; // front-end UI + game/session UI

		SState sStates[kStateSlots]{};
		std::atomic<global_State*> sIncrementalVms[kIncrementalVmSlots]{};
		global_State* const kDeletedSlot = reinterpret_cast<global_State*>(static_cast<std::uintptr_t>(1));

		[[nodiscard]] std::size_t HashSlot(global_State* const g) noexcept
		{
			return (reinterpret_cast<std::uintptr_t>(g) >> 4) % kStateSlots;
		}

		[[nodiscard]] SState* FindSlot(global_State* const g) noexcept
		{
			if (g == nullptr) {
				return nullptr;
			}
			std::size_t index = HashSlot(g);
			for (std::size_t probe = 0; probe < kStateSlots; ++probe) {
				SState& state = sStates[index];
				if (state.g == g && state.mainThread == g->mainthread) {
					return &state;
				}
				if (state.g == nullptr) {
					return nullptr;
				}
				// kDeletedSlot keeps a probe chain alive after Release().
				index = (index + 1) % kStateSlots;
			}
			return nullptr;
		}

		[[nodiscard]] SState* FindEmptySlot(global_State* const g) noexcept
		{
			std::size_t index = HashSlot(g);
			SState* deleted = nullptr;
			for (std::size_t probe = 0; probe < kStateSlots; ++probe) {
				if (sStates[index].g == nullptr) {
					return deleted != nullptr ? deleted : &sStates[index];
				}
				if (sStates[index].g == kDeletedSlot && deleted == nullptr) {
					deleted = &sStates[index];
				}
				index = (index + 1) % kStateSlots;
			}
			return deleted;
		}
	}

	SState* Find(global_State* const g) noexcept
	{
		return FindSlot(g);
	}

	SState& Acquire(global_State* const g) noexcept
	{
		if (SState* const existing = FindSlot(g); existing != nullptr) {
			return *existing;
		}
		if (SState* const empty = FindEmptySlot(g); empty != nullptr) {
			*empty = SState{};
			empty->g = g;
			empty->mainThread = g->mainthread;
			return *empty;
		}

		// All slots are occupied. Reuse an idle one rather than allocating; a
		// live state with an active cycle is never displaced.
		for (SState& state : sStates) {
			if (state.state == EState::Pause && !state.running) {
				state = SState{};
				state.g = g;
				state.mainThread = g->mainthread;
				return state;
			}
		}
		return sStates[0];
	}

	void Release(global_State* const g) noexcept
	{
		if (SState* const state = FindSlot(g); state != nullptr) {
			*state = SState{};
			state->g = kDeletedSlot;
		}
	}

	bool Active(global_State* const g) noexcept
	{
		const SState* const state = FindSlot(g);
		return state != nullptr && state->state != EState::Pause;
	}

	bool UsesIncrementalGc(global_State* const g) noexcept
	{
		if (g == nullptr) {
			return false;
		}
		for (const std::atomic<global_State*>& slot : sIncrementalVms) {
			if (slot.load(std::memory_order_acquire) == g) {
				return true;
			}
		}
		return false;
	}

	void RegisterIncrementalVm(global_State* const g) noexcept
	{
		if (!moho::lua_IncrementalGC) {
			return;
		}
		if (g == nullptr || g->globalUserData != nullptr || UsesIncrementalGc(g)) {
			return;
		}
		for (std::atomic<global_State*>& slot : sIncrementalVms) {
			global_State* expected = nullptr;
			if (slot.compare_exchange_strong(expected, g, std::memory_order_release)) {
				return;
			}
		}
	}

	void UnregisterIncrementalVm(global_State* const g) noexcept
	{
		if (g == nullptr) {
			return;
		}
		for (std::atomic<global_State*>& slot : sIncrementalVms) {
			global_State* expected = g;
			(void)slot.compare_exchange_strong(expected, nullptr, std::memory_order_release);
		}
	}
} // namespace moho::lua_incremental

namespace moho
{
	void CaptureIncrementalGcStartupSetting() noexcept
	{
		lua_IncrementalGC = lua_IncrementalGCSetting;
	}
} // namespace moho
