#pragma once

#include "gpg/core/containers/FastVector.h"
#include "legacy/containers/Vector.h"
#include "moho/render/camera/GeomCamera3.h"
#include "platform/Platform.h"

namespace moho
{
	struct SSyncFilter
	{
	    struct Subobj1
	    {
	        DWORD v0;
	        DWORD v1;
	        gpg::core::FastVector<void*> vec;
	    };

		DWORD focusArmy;
		msvc8::vector<GeomCamera3> gap4;
		BYTE gap14[12];
		Subobj1 obj1;
		DWORD v2;
		DWORD v3;
		DWORD v4;
		bool v5;
		DWORD v6;
		DWORD v7;
		DWORD v8;
		DWORD v9;
		DWORD v10;
		gpg::core::FastVector<void*> vec2;
	};
}