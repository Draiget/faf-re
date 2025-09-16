#pragma once

#include "ISessionListener.h"
#include "../../gpg/core/utils/BoostUtils.h"

namespace moho
{
	class IdleUnitSelector : public ISessionListener, boost::noncopyable_::noncopyable
	{
		// Primary vftable (2 entries)
	public:
		virtual void sub_8656A0() = 0; // 0x8656A0 (slot 0)
		virtual void sub_8656E0() = 0; // 0x8656E0 (slot 1)
	};
}
