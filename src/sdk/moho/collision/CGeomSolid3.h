#pragma once
#include "gpg/core/containers/FastVector.h"
#include "wm3/Plane3.h"

namespace moho
{
	class CGeomSolid3
	{
	public:
		gpg::core::FastVector<Wm3::Plane3f> vec_;
	};
}
