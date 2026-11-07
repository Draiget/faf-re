#pragma once

#include "lua/LuaRuntimeTypes.h"

namespace moho
{
	/// The live runtime flag: the collector role of a VM is decided from this
	/// value when the VM is created. False until `CaptureIncrementalGcStartupSetting`
	/// runs, which only the game does, so headless and the server keep the
	/// shipped collector.
	extern bool lua_IncrementalGC;

	/// The configured value of the `lua_IncrementalGC` convar. The convar is
	/// bound to this variable, so a user-side change only moves the setting;
	/// the live flag is refreshed by `CaptureIncrementalGcStartupSetting`.
	extern bool lua_IncrementalGCSetting;

	/**
	 * Copies the configured convar value into the live runtime flag.
	 *
	 * Called once during startup, before the front-end UI VM is created, so
	 * that `/con lua_IncrementalGC=0` still selects the shipped 5.0 collector
	 * for the UI roots. Later changes to the convar only move the setting.
	 */
	void CaptureIncrementalGcStartupSetting() noexcept;
}

namespace moho::lua_incremental
{
	/**
	 * Engine addition: Lua 5.1-style incremental collector state.
	 *
	 * The object/global layouts are pinned by the x86 binary and by
	 * LuaRuntimeTypes.h, so the collector's own state lives here instead of in
	 * global_State. The colour bits reuse the unused high bits of GCObject::marked;
	 * the shipped 5.0 collector uses 0x01/0x02/0x04/0x10, so the incremental path
	 * adds two white bits at 0x08/0x20 and keeps the 5.0 meanings for the rest.
	 */
	enum class ELuaVmRole : int
	{
		Baseline = 0,
		FrontendUi,
		SessionUi,
	};

	enum class EState : unsigned char
	{
		Pause,
		Propagate,
		SweepString,
		SweepUserdata,
		SweepThreads,
		SweepObjects,
		Finalize,
	};

	constexpr lu_byte kBlackBit = 0x01;
	constexpr lu_byte kWhite0Bit = 0x08;
	constexpr lu_byte kWhite1Bit = 0x20;
	constexpr lu_byte kWhiteBits = static_cast<lu_byte>(kWhite0Bit | kWhite1Bit);
	constexpr lu_byte kFixedBit = 0x10;
	constexpr lu_byte kFinalizedBit = 0x02;
	constexpr lu_byte kKeyWeakBit = 0x02;
	constexpr lu_byte kValueWeakBit = 0x04;
	constexpr lu_byte kColorMask = static_cast<lu_byte>(kBlackBit | kWhiteBits);

	[[nodiscard]] inline bool IsBlack(const GCObject* const object) noexcept
	{
		return (object->gch.marked & kBlackBit) != 0;
	}

	[[nodiscard]] inline bool IsWhite(const GCObject* const object) noexcept
	{
		return (object->gch.marked & kWhiteBits) != 0;
	}

	[[nodiscard]] inline bool IsGray(const GCObject* const object) noexcept
	{
		return !IsBlack(object) && !IsWhite(object);
	}

	struct SState
	{
		global_State* g = nullptr;
		lua_State* mainThread = nullptr; // identity guard when a global_State is reused
		EState state = EState::Pause;
		lu_byte currentWhite = kWhite0Bit;
		GCObject* gray = nullptr;
		GCObject* grayagain = nullptr;
		GCObject* weak = nullptr;
		int sweepStringBucket = 0;
		GCObject** sweepLink = nullptr;
		lu_mem estimate = 0;
		lu_mem gcdebt = 0;
		int gcPause = 200;
		int gcStepMul = 200;
		bool initialized = false;
		bool running = false;
		bool frameDriven = false;
	};

	[[nodiscard]] SState* Find(global_State* g) noexcept;
	[[nodiscard]] SState& Acquire(global_State* g) noexcept;
	void Release(global_State* g) noexcept;
	[[nodiscard]] bool Active(global_State* g) noexcept;

	/// True only for the two root VMs explicitly registered as UI VMs
	/// (front-end UI and world/session UI). The sim, GameRules, UserPrefs,
	/// Colors and transient states are never registered.
	[[nodiscard]] bool UsesIncrementalGc(global_State* g) noexcept;
	void RegisterIncrementalVm(global_State* g) noexcept;
	void UnregisterIncrementalVm(global_State* g) noexcept;

	[[nodiscard]] inline lu_byte White(const SState& state) noexcept
	{
		return static_cast<lu_byte>(state.currentWhite & kWhiteBits);
	}

	/// True only for the front-end or world/session UI roots registered at VM
	/// construction. `globalUserData` only identifies the sim VM; it must not
	/// be used to infer "UI", because GameRules/UserPrefs/Colors also leave it
	/// null and must stay on the shipped 5.0 collector.
	[[nodiscard]] inline bool IsUiState(global_State* const g) noexcept
	{
		return UsesIncrementalGc(g);
	}

	[[nodiscard]] inline bool IsDead(const SState& state, const GCObject* const object) noexcept
	{
		if ((object->gch.marked & kFixedBit) != 0) {
			return false;
		}
		return (object->gch.marked & static_cast<lu_byte>(state.currentWhite ^ kWhiteBits)) != 0;
	}
}

// Implemented next to the collector in LuaObject.cpp. C linkage keeps these
// definitions out of the LuaPlus namespace they are written in.
extern "C"
{
	void faf_lua51_gc_register_vm(lua_State* L, int role);
	void faf_lua51_gc_step(lua_State* L);
	bool faf_lua51_gc_slice(lua_State* L, int workBudget, bool forceStart);
	void faf_lua51_gc_full(lua_State* L);
	void faf_lua51_gc_link(lua_State* L, GCObject* object, int typeTag);
	void faf_lua51_gc_abandon(global_State* g);
	void faf_lua51_gc_release(global_State* g);
	void faf_lua51_gc_color_userdata(lua_State* L, Udata* userdata);
	void faf_lua51_gc_color_thread(lua_State* L, lua_State* thread);
	void faf_lua51_gc_link_upval(lua_State* L, UpVal* upvalue);
	void faf_lua51_gc_barrier_f(lua_State* L, GCObject* object, GCObject* value);
	void faf_lua51_gc_barrier_back(lua_State* L, Table* table);
	void faf_lua51_gc_barrier_value(lua_State* L, GCObject* object, const LuaPlus::TObject* value);
	bool faf_lua51_gc_is_active(global_State* g);
	void faf_lua51_gc_mark_object(global_State* g, GCObject* object);
	void faf_lua51_gc_revive_string(lua_State* L, GCObject* object);
	bool faf_lua51_gc_sweep_string_active(lua_State* L);
}
