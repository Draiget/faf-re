#pragma once
#include <cstdint>

namespace moho
{
	enum class ResourceDepositType
	{
		kNone = 0,
		kMass = 1,
		kEnergy = 2, // Hydrocarbon
	};

	struct ResourceDeposit
	{
		// Rect
		//gpg::Rect2i mLocation;
		int32_t X1;
		int32_t Z1;
		int32_t X2;
		int32_t Z2;

		ResourceDepositType type;

		// bool Intersects(CGeomSolid3* solid, CHeightField* field); // 0x00546170
	};
}
