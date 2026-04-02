#include "Vector3.h"

#include <cmath>

#include "Quaternion.h"

namespace Wm3
{
/**
 * Address: 0x00452FC0 (FUN_00452FC0)
 *
 * float
 *
 * IDA signature:
 * float __cdecl sqrtf(float val);
 *
 * What it does:
 * Thin sqrtf wrapper used by vector helpers.
 */
float SqrtfBinary(const float value) noexcept
{
    using std::sqrt;
    return sqrt(value);
}

/**
 * Address: 0x00452AF0 (FUN_00452AF0, Wm3::Vector3f::Normalize)
 *
 * Wm3::Vector3<float>*
 *
 * IDA signature:
 * long double __thiscall func_NormalizeVecInPlace(Wm3::Vector3f *vec);
 *
 * What it does:
 * Normalizes `value` in place with epsilon `1e-6`; returns pre-normalize length.
 */
float NormalizeVector3fInPlace(Vector3<float>* const value) noexcept
{
    if (!value) {
        return 0.0f;
    }

    const float length = SqrtfBinary(
        value->x * value->x +
        value->y * value->y +
        value->z * value->z
    );
    if (length <= 0.000001f) {
        value->x = 0.0f;
        value->y = 0.0f;
        value->z = 0.0f;
        return 0.0f;
    }

    const float invLength = 1.0f / length;
    value->x *= invLength;
    value->y *= invLength;
    value->z *= invLength;
    return length;
}

/**
 * Address: 0x0044F7E0 (FUN_0044F7E0, Wm3::Vector3::Normalize)
 *
 * Wm3::Vector3<float> const&, Wm3::Vector3<float>*
 *
 * IDA signature:
 * Wm3::Vector3f *__usercall func_NormalizeVecInto@<eax>(Wm3::Vector3f *vec@<edi>, Wm3::Vector3f *dest@<esi>);
 *
 * What it does:
 * Normalizes source vector into destination and writes zero vector for non-positive length.
 */
Vector3<float>* NormalizeVector3fInto(
    const Vector3<float>& source,
    Vector3<float>* const dest
) noexcept
{
    if (!dest) {
        return nullptr;
    }

    const float length = SqrtfBinary(
        source.x * source.x +
        source.y * source.y +
        source.z * source.z
    );
    if (length <= 0.0f) {
        dest->x = 0.0f;
        dest->y = 0.0f;
        dest->z = 0.0f;
        return dest;
    }

    const float invLength = 1.0f / length;
    dest->x = source.x * invLength;
    dest->y = source.y * invLength;
    dest->z = source.z * invLength;
    return dest;
}

/**
 * Address: 0x005657F0 (FUN_005657F0, Wm3::Vector3f::IsntNaN)
 *
 * Wm3::Vector3<float> const*
 *
 * IDA signature:
 * BOOL __usercall Wm3::Vector3f::IsntNaN@<eax>(Wm3::Vector3f *a1@<esi>);
 *
 * What it does:
 * Returns true when all vector components are not NaN.
 */
bool Vector3fIsntNaN(const Vector3<float>* const value) noexcept
{
    if (!value) {
        return false;
    }

    using std::isnan;
    return !isnan(value->x) && !isnan(value->y) && !isnan(value->z);
}

/**
 * Address: 0x00A3CF80 (FUN_00A3CF80, Wm3::Vector3f::GenerateOrthonormalBasis)
 *
 * Wm3::Vector3<float>*, Wm3::Vector3<float>*, Wm3::Vector3<float>*, bool
 *
 * IDA signature:
 * Wm3::Vector3f *__usercall Wm3::Vector3f::GenerateOrthonormalBasis@<eax>(double a1@<st0>, Wm3::Vector3f *a2, Wm3::Vector3f *a3, Wm3::Vector3f *a4, bool a5);
 *
 * What it does:
 * Builds orthonormal basis vectors around `wInOut`, optionally normalizing it first.
 */
Vector3<float>* GenerateOrthonormalBasisVector3f(
    Vector3<float>* const uOut,
    Vector3<float>* const vOut,
    Vector3<float>* const wInOut,
    const bool unitLengthW
) noexcept
{
    if (!uOut || !vOut || !wInOut) {
        return nullptr;
    }

    if (!unitLengthW) {
        NormalizeVector3fInPlace(wInOut);
    }

    using std::fabs;
    if (fabs(wInOut->y) > fabs(wInOut->x)) {
        const float invLength = 1.0f / SqrtfBinary(wInOut->y * wInOut->y + wInOut->z * wInOut->z);
        uOut->x = 0.0f;
        uOut->y = wInOut->z * invLength;
        uOut->z = -wInOut->y * invLength;

        vOut->x = uOut->z * wInOut->y - wInOut->z * uOut->y;
        vOut->y = -wInOut->x * uOut->z;
        vOut->z = uOut->y * wInOut->x;
    } else {
        const float invLength = 1.0f / SqrtfBinary(wInOut->x * wInOut->x + wInOut->z * wInOut->z);
        uOut->x = -wInOut->z * invLength;
        uOut->y = 0.0f;
        uOut->z = wInOut->x * invLength;

        vOut->x = uOut->z * wInOut->y;
        vOut->y = wInOut->z * uOut->x - uOut->z * wInOut->x;
        vOut->z = -wInOut->y * uOut->x;
    }

    return uOut;
}

/**
 * Address: 0x00452D40 (FUN_00452D40, func_MultQuadVec)
 *
 * Wm3::Vector3<float>*, Wm3::Vector3<float> const&, Wm3::Quaternion<float> const&
 *
 * IDA signature:
 * Wm3::Vector3f *__usercall func_MultQuadVec@<eax>(Wm3::Vector3f *dest@<ebx>, Wm3::Vector3f *vec@<esi>, Wm3::Quaternionf *quat@<ecx>);
 *
 * What it does:
 * Converts quaternion to a 3x3 basis and multiplies that matrix by `vec`.
 */
Vector3<float>* MultiplyQuaternionVector(
    Vector3<float>* const dest,
    const Vector3<float>& vec,
    const Quaternion<float>& quat
) noexcept
{
    if (!dest) {
        return nullptr;
    }

    float matrix[3][3]{};
    quat.ToMat3(matrix);

    dest->x = vec.x * matrix[0][0] + vec.y * matrix[0][1] + vec.z * matrix[0][2];
    dest->y = vec.x * matrix[1][0] + vec.y * matrix[1][1] + vec.z * matrix[1][2];
    dest->z = vec.x * matrix[2][0] + vec.y * matrix[2][1] + vec.z * matrix[2][2];
    return dest;
}

/**
 * Address: 0x00428DB0 (FUN_00428DB0, Wm3::Vector3f::Add)
 *
 * Wm3::Vector3<float> const&, Wm3::Vector3<float>*, Wm3::Vector3<float> const&
 *
 * IDA signature:
 * Wm3::Vector3f *__thiscall Wm3::Vector3f::Add(Wm3::Vector3f *this, Wm3::Vector3f *out, Wm3::Vector3f *rhs);
 *
 * What it does:
 * Writes `lhs + rhs` into caller-provided `out` and returns `out`.
 */
Vector3<float>* AddVector3f(
    const Vector3<float>& lhs,
    Vector3<float>* const out,
    const Vector3<float>& rhs
) noexcept
{
    if (!out) {
        return nullptr;
    }

    out->x = lhs.x + rhs.x;
    out->y = lhs.y + rhs.y;
    out->z = lhs.z + rhs.z;
    return out;
}
} // namespace Wm3
