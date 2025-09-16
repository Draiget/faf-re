#include "Vector4f.h"

#include <complex>
using namespace moho;

Angle Vector4f::quaternion_to_euler() const {
    // Assumes unit quaternion; if not, consider normalizing beforehand.
    const float qx = x, qy = y, qz = z, qw = w;

    // roll (X-axis rotation)
    const float sinr_cosp = 2.0f * (qw * qx + qy * qz);
    const float cosr_cosp = 1.0f - 2.0f * (qx * qx + qy * qy);
    const float roll = std::atan2(sinr_cosp, cosr_cosp);

    // pitch (Y-axis rotation)
    const float sinp = 2.0f * (qw * qy - qz * qx);
    float pitch;
    if (std::fabs(sinp) >= 1.0f) {
        // use 90 degrees if out of range
        pitch = std::copysign(3.14159265358979323846f / 2.0f, sinp);
    } else {
        pitch = std::asin(sinp);
    }

    // yaw (Z-axis rotation)
    const float siny_cosp = 2.0f * (qw * qz + qx * qy);
    const float cosy_cosp = 1.0f - 2.0f * (qy * qy + qz * qz);
    const float yaw = std::atan2(siny_cosp, cosy_cosp);

    return { roll, pitch, yaw };
}
