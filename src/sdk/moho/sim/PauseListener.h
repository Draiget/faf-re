#pragma once
#include "ISessionListener.h"
#include "../../gpg/core/utils/BoostUtils.h"

namespace moho
{
	class PauseListener : public ISessionListener, boost::noncopyable_::noncopyable
	{
	public:
		virtual void sub_869700() = 0; // 0x869700 (slot 0)
		virtual void sub_869750() = 0; // 0x869750 (slot 1)
	};
}
