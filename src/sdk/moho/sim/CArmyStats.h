#pragma once

#include "../misc/StatItem.h"
#include "../resource/IResources.h"
#include "../misc/Stats.h"

namespace moho
{
	class CArmyStatItem : public StatItem
	{
		// Primary vftable (2 entries)
	public:
		virtual void sub_585BB0() = 0; // 0x585BB0 (slot 0)
		virtual void sub_70B430() = 0; // 0x70B430 (slot 1)
	};

	class CArmyStats : public Stats<CArmyStatItem>, public boost::noncopyable_::noncopyable
	{
		
	};
}
