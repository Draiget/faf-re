#pragma once
#include <cstdint>

#include "TDatTreeItem.h"
#include "../../legacy/containers/String.h"
#include "../../gpg/core/utils/Sync.h"

namespace moho
{
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
		// ---- payload ----
		int32_t   value_int_or_float;   // 0x24  (raw storage read by getters)
		uint8_t   pad_28[0x78 - 0x28];  // 0x28..0x77

		msvc8::string name;             // 0x78..0x93  (size at +0x8C)

		uint32_t  valueType;            // 0x90  (0=float, 1=int, 2=string)
		uint32_t  useCurrent_flag;      // 0x94  (==1 -> pass true to getters)
		gpg::core::Mutex sync;          // 0x98
		uint8_t   pad_9D[0xA0 - 0x9D];  // 0x9D..0x9F
	};
}
