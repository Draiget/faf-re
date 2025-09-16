#pragma once

namespace moho
{
	/**
	 * Simple triple of Euler angles in radians (XYZ: roll around X, pitch around Y, yaw around Z).
	 */
	struct Angle
	{
		float roll{};   // X
		float pitch{};  // Y
		float yaw{};    // Z
	};
}