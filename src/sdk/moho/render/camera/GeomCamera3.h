#pragma once

#include "platform/Platform.h"
#include "VTransform.h"
#include "gpg/gal/Matrix.h"
#include "moho/collision/CGeomSolid3.h"
#include "moho/math/VMatrix4.h"

namespace moho
{
	struct GeomCamera3
	{
		VTransform tranform;
		gpg::gal::Matrix projection;
		gpg::gal::Matrix view;
		gpg::gal::Matrix viewProjection;
		gpg::gal::Matrix inverseProjection;
		gpg::gal::Matrix inverseView;
		gpg::gal::Matrix inverseViewProjection;
		DWORD prolly_alignment;
		CGeomSolid3 solid1;
		CGeomSolid3 solid2;
		float lodScale;
		VMatrix4 viewport;
		DWORD v160;
	};
}
