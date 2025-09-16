#pragma once
#include "ISessionListener.h"
#include "../../gpg/core/utils/BoostUtils.h"

namespace moho
{
	class SelectionListener : public ISessionListener, boost::noncopyable_::noncopyable
	{
		// Primary vftable (2 entries)
	public:
		virtual void sub_869540() = 0; // 0x869540 (slot 0)
		virtual void sub_869580() = 0; // 0x869580 (slot 1)
	};
}
