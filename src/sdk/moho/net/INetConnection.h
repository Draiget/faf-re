#pragma once

#include <string>

#include "CMessageDispatcher.h"

namespace moho
{
    struct NetDataSpan
    {
        char* start;
        char* end;
    };

	class INetConnection : public CMessageDispatcher
	{
        // Primary vftable (8 entries)
	public:
        virtual int GetAddr() = 0;
        virtual int GetPort() = 0;
        virtual float GetPing() = 0;
        virtual float GetTime() = 0;
        virtual void Write(NetDataSpan* data) = 0;
        virtual void Close() = 0;
        virtual std::string ToString() = 0;
        virtual void ScheduleDestroy() = 0;
	};
}
