#pragma once
#include <cstdint>

#include "legacy/containers/String.h"
#include "boost/mutex.h"
#include "moho/containers/TDatTreeItem.h"

namespace moho
{
	enum class EStatType : uint32_t
	{
		kNone = 0,
		kFloat = 1,
		kInt = 2,
		kString = 3,
	};

	class StatItem : public TDatTreeItem<StatItem>
	{
	public:
		/**
		 * In binary: Destructor.
		 *
		 * PDB name: sub_408840
		 * Address: 0x408840
		 * VFTable SLOT: 0
		 */
		virtual ~StatItem() = default;

		/**
		 * In binary: Push stat items to lua.
		 *
		 * PDB name: sub_418BD0
		 * Address: 0x418BD0
		 * VFTable SLOT: 1
		 */
		virtual void PushToLua() = 0;

	public:
		std::uint32_t mTreeAux{ 0 };     // +0x20  // auxiliary field next to tree heads (zeroed in ctor)
		DWORD         mCounter;        // +0x24  // InstanceCounter<T> hits this (lock xadd)

		// Textual value buffer (used by string stats / formatting helpers)
		msvc8::string mValue;      // +0x28  // SSO string; ctor touches size@+0x3C, res@+0x40, buf[0]@+0x2C

		// Integer value / accumulator for INT kind
		DWORD         mIntValue;       // +0x44

		// Scratch string for conversions/formatting (second working buffer)
		msvc8::string mValueScratch;   // +0x48  // second SSO string; size@+0x5C, res@+0x60, buf[0]@+0x4C

		// Explicit padding hole the ctor does not touch (kept for exact layout)
		BYTE          pad64[4];        // +0x64..+0x67

		// Reserved/zeroed dwords (purpose TBD; ctor writes zeros here)
		DWORD         mSpare0;         // +0x68
		DWORD         mSpare1;         // +0x6C
		DWORD         mSpare2;         // +0x70

		// Human-readable stat name (exported to Lua as "Name")
		msvc8::string mName;           // +0x74  // SSO string; constructed from ctor parameter

		// Value kind and read-mode flag (ToLua branches on type; flag used as (==1))
		EStatType     mType{ EStatType::kNone }; // +0x90
		volatile int  mRealtimeFlag{ 0 };        // +0x94  // when 1, readers use "instant" mode

		// Engine-era thin mutex (pImpl; 8 bytes)
		boost::mutex  mLock;          // +0x98
	};
	static_assert(sizeof(StatItem) == 0xA0u, "StatItem == 0xA0");
}
