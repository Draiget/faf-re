#pragma once

#include "../../gpg/core/utils/BoostUtils.h"
#include "../misc/InstanceCounter.h"
#include "platform/Platform.h"
#include "util/Build.h"

namespace moho
{
	class_EBO CTask : public boost::noncopyable_::noncopyable, public InstanceCounter<CTask>
	{
		// Primary vftable (2 entries)
	public:
		/**
		 * In binary:
		 *
		 * Address: 0x408C90
		 * VFTable SLOT: 0
		 */
		virtual ~CTask() = default;

		/**
		 * In binary: __purecall
		 *
		 * Address: 0xA82547
		 * VFTable SLOT: 1
		 */
		virtual void sub_A82547() = 0;
	};

	ABI_SIZE_MUST_BE(CTask, 0x04);
	static_assert(sizeof(CTask) == 4, "CTask == 4");
}
