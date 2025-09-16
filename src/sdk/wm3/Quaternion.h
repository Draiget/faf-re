#pragma once
#include "Vector3.h"

namespace Wm3
{
    /**
     * Minimal quaternion template (w + xi + yj + zk)
     * Stored as (w, x, y, z). Right-handed, radians, unit quaternions represent rotations.
     */
    template <class T>
    struct Quaternion {
        T w{}, x{}, y{}, z{};

        /** Default constructs identity quaternion. */
        constexpr Quaternion() : w(T(1)), x(T(0)), y(T(0)), z(T(0)) {}

        /** Constructs from components. */
        constexpr Quaternion(T _w, T _x, T _y, T _z) : w(_w), x(_x), y(_y), z(_z) {}

        /** Identity quaternion. */
        static constexpr Quaternion Identity() { return Quaternion(T(1), T(0), T(0), T(0)); }

        /** Return squared length. */
        static constexpr T LengthSq(const Quaternion& q) noexcept {
            return q.w * q.w + q.x * q.x + q.y * q.y + q.z * q.z;
        }

        /** Return length. */
        static T Length(const Quaternion& q) noexcept {
            using std::sqrt;
            return sqrt(LengthSq(q));
        }

        /** Dot product. */
        static constexpr T Dot(const Quaternion& a, const Quaternion& b) noexcept {
            return a.w * b.w + a.x * b.x + a.y * b.y + a.z * b.z;
        }

        /** Conjugate (inverse for unit quaternions). */
        static constexpr Quaternion Conjugate(const Quaternion& q) noexcept {
            return Quaternion(q.w, -q.x, -q.y, -q.z);
        }

        /** True inverse (for non-zero quaternions). */
        static Quaternion Inverse(const Quaternion& q) noexcept {
            const T lsq = LengthSq(q);
            if (lsq == T(0)) return Quaternion(); // fallback to identity
            const T inv = T(1) / lsq;
            return Quaternion(q.w * inv, -q.x * inv, -q.y * inv, -q.z * inv);
        }

        /** Normalize in-place; returns previous length. */
        T Normalize(T eps = T(1e-6)) noexcept {
            const T len = Length(*this);
            if (len > eps) {
                const T inv = T(1) / len;
                w *= inv; x *= inv; y *= inv; z *= inv;
            } else {
                *this = Identity();
            }
            return len;
        }

        /** Return a normalized copy. */
        Quaternion Normalized(T eps = T(1e-6)) const noexcept {
            Quaternion tmp = *this;
            tmp.Normalize(eps);
            return tmp;
        }

        /** Quaternion multiplication (composition of rotations: result = a followed by b). */
        static constexpr Quaternion Multiply(const Quaternion& a, const Quaternion& b) noexcept {
            // Hamilton product
            return Quaternion(
                a.w * b.w - a.x * b.x - a.y * b.y - a.z * b.z,
                a.w * b.x + a.x * b.w + a.y * b.z - a.z * b.y,
                a.w * b.y - a.x * b.z + a.y * b.w + a.z * b.x,
                a.w * b.z + a.x * b.y - a.y * b.x + a.z * b.w
            );
        }

        /** Rotate vector v by this quaternion (assumes *this is (near) unit). */
        Vec3<T> Rotate(const Vec3<T>& v) const noexcept {
            // Optimized form: v' = v + 2*cross(q.xyz, cross(q.xyz, v) + q.w * v)
            const T qx = x, qy = y, qz = z, qw = w;
            const T cx1 = qy * v.z - qz * v.y;
            const T cy1 = qz * v.x - qx * v.z;
            const T cz1 = qx * v.y - qy * v.x;

            const T rx = v.x + T(2) * (qw * cx1 + (qy * cz1 - qz * cy1));
            const T ry = v.y + T(2) * (qw * cy1 + (qz * cx1 - qx * cz1));
            const T rz = v.z + T(2) * (qw * cz1 + (qx * cy1 - qy * cx1));
            return { rx, ry, rz };
        }

        /** Create from axis (must be normalized) and angle (radians). */
        static Quaternion FromAxisAngle(const Vec3<T>& axis, T angle) noexcept {
            using std::sin; using std::cos;
            const T half = angle * T(0.5);
            const T s = sin(half);
            const T c = cos(half);
            return Quaternion(c, axis.x * s, axis.y * s, axis.z * s);
        }

        /** Decompose into axis (normalized) and angle (radians). For near-identity, returns X axis. */
        void ToAxisAngle(Vec3<T>& axisOut, T& angleOut, T eps = T(1e-6)) const noexcept {
            Quaternion q = this->Normalized(eps);
            using std::acos; using std::sqrt;
            angleOut = T(2) * acos(q.w);
            const T s = sqrt(std::max(T(0), T(1) - q.w * q.w));
            if (s > eps) {
                axisOut = { q.x / s, q.y / s, q.z / s };
            } else {
                axisOut = { T(1), T(0), T(0) }; // arbitrary
            }
        }

        /** Create from Euler angles (XYZ order: roll around X, pitch around Y, yaw around Z). */
        static Quaternion FromEulerXYZ(T roll, T pitch, T yaw) noexcept {
            using std::cos; using std::sin;
            const T cx = cos(roll * T(0.5));
            const T sx = sin(roll * T(0.5));
            const T cy = cos(pitch * T(0.5));
            const T sy = sin(pitch * T(0.5));
            const T cz = cos(yaw * T(0.5));
            const T sz = sin(yaw * T(0.5));

            // q = qz * qy * qx (ZYX intrinsic == XYZ extrinsic)
            Quaternion q;
            q.w = cz * cy * cx + sz * sy * sx;
            q.x = cz * cy * sx - sz * sy * cx;
            q.y = cz * sy * cx + sz * cy * sx;
            q.z = sz * cy * cx - cz * sy * sx;
            return q;
        }

        /** Spherical linear interpolation (unit quaternions). t in [0,1]. */
        static Quaternion Slerp(const Quaternion& a, const Quaternion& b, T t, T eps = T(1e-5)) noexcept {
            Quaternion q1 = a.Normalized();
            Quaternion q2 = b.Normalized();
            T cosTheta = Dot(q1, q2);

            // Take shortest path
            if (cosTheta < T(0)) {
                q2.w = -q2.w; q2.x = -q2.x; q2.y = -q2.y; q2.z = -q2.z;
                cosTheta = -cosTheta;
            }

            if (cosTheta > T(1) - eps) {
                // Nearly identical; use normalized lerp
                return Nlerp(q1, q2, t);
            }

            using std::acos; using std::sin;
            const T theta = acos(cosTheta);
            const T s = sin(theta);
            const T w1 = sin((T(1) - t) * theta) / s;
            const T w2 = sin(t * theta) / s;

            Quaternion out(
                q1.w * w1 + q2.w * w2,
                q1.x * w1 + q2.x * w2,
                q1.y * w1 + q2.y * w2,
                q1.z * w1 + q2.z * w2
            );
            return out.Normalized();
        }

        /** Normalized linear interpolation (faster, acceptable for small angles). */
        static Quaternion Nlerp(const Quaternion& a, const Quaternion& b, T t) noexcept {
            Quaternion q1 = a;
            Quaternion q2 = b;
            if (Dot(q1, q2) < T(0)) { // shortest path
                q2.w = -q2.w; q2.x = -q2.x; q2.y = -q2.y; q2.z = -q2.z;
            }
            Quaternion out(
                q1.w + (q2.w - q1.w) * t,
                q1.x + (q2.x - q1.x) * t,
                q1.y + (q2.y - q1.y) * t,
                q1.z + (q2.z - q1.z) * t
            );
            return out.Normalized();
        }

        /** Convert to 3x3 rotation matrix (row-major). Assumes unit quaternion. */
        void ToMat3(T m[3][3]) const noexcept {
            const T xx = x + x, yy = y + y, zz = z + z;
            const T xy = x * yy, xz = x * zz, yz = y * zz;
            const T wx = w * xx, wy = w * yy, wz = w * zz;
            const T xx2 = x * xx, yy2 = y * yy, zz2 = z * zz;

            m[0][0] = T(1) - (yy2 + zz2);
            m[0][1] = xy - wz;
            m[0][2] = xz + wy;

            m[1][0] = xy + wz;
            m[1][1] = T(1) - (xx2 + zz2);
            m[1][2] = yz - wx;

            m[2][0] = xz - wy;
            m[2][1] = yz + wx;
            m[2][2] = T(1) - (xx2 + yy2);
        }

        /** Multiply operator (composition). */
        friend constexpr Quaternion operator*(const Quaternion& a, const Quaternion& b) noexcept {
            return Multiply(a, b);
        }

        /** Equality with tolerance. */
        bool NearlyEquals(const Quaternion& rhs, T eps = T(1e-6)) const noexcept {
            return std::fabs(w - rhs.w) <= eps &&
                std::fabs(x - rhs.x) <= eps &&
                std::fabs(y - rhs.y) <= eps &&
                std::fabs(z - rhs.z) <= eps;
        }

        /** Convert from different underlying scalar type. */
        template <class U>
        static Quaternion From(const Quaternion<U>& q) {
            return Quaternion(T(q.w), T(q.x), T(q.y), T(q.z));
        }
    };

    /** Rotate vector by quaternion (free function). */
    template <class T>
    inline Vec3<T> operator*(const Quaternion<T>& q, const Vec3<T>& v) noexcept {
        return q.Rotate(v);
    }

    using Quatf = Quaternion<float>;
    using Quatd = Quaternion<double>;
    using Quati = Quaternion<int>; // storage-only; rotation math expects floating-point
}
