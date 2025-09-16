#pragma once
#include "../../wm3/Box3.h"
#include "AABB.h"

namespace moho
{
	class CColPrimitiveBase
	{
        // Primary vftable (10 entries)
	public:
        virtual void sub_A82547() = 0; // 0xA82547 (slot 0)
        virtual void sub_A82547_1() = 0; // 0xA82547 (slot 1)
        virtual void sub_A82547_2() = 0; // 0xA82547 (slot 2)
        virtual void sub_A82547_3() = 0; // 0xA82547 (slot 3)
        virtual void sub_A82547_4() = 0; // 0xA82547 (slot 4)
        virtual void sub_A82547_5() = 0; // 0xA82547 (slot 5)
        virtual void sub_A82547_6() = 0; // 0xA82547 (slot 6)
        virtual void sub_A82547_7() = 0; // 0xA82547 (slot 7)
        virtual void sub_A82547_8() = 0; // 0xA82547 (slot 8)
        virtual void sub_A82547_9() = 0; // 0xA82547 (slot 9)
	};

    /**
	 * Template shell; the engine has explicit specialization for Wm3::Box3<float>.
	 * Other T are not reconstructed yet.
	 */
    template <class T>
    class CColPrimitive : public CColPrimitiveBase {
    public:
        virtual ~CColPrimitive() = default;
        // Unknown layout for generic T
    };

    using Box3f = Wm3::Box3<float>;
    using Vec3f = Wm3::Vec3<float>;
    using Mat34f = Wm3::Mat34<float>;

    template <>
    class CColPrimitive<Box3f> : public CColPrimitiveBase {
    public:

        virtual ~CColPrimitive() = default;

        /**
         * In binary: sub_4FF130 (returns 0)
         *
         * Address: 0x4FF130
         * VFTable SLOT: 1
         */
        [[nodiscard]] virtual std::uint32_t GetTypeId() const noexcept {
            // Box kind id is unknown; binary returns 0 in this impl.
            return 0u;
        }

        virtual void sub_4FF130() = 0; // 0x4FF130 (slot 1)


        /**
         * In binary: sub_4FF140 (returns this+4)
         *
         * Address: 0x4FF140
         * VFTable SLOT: 2
         */
        [[nodiscard]] virtual const Box3f* GetRawBoxPtr() const noexcept {
            // Raw layout: 15 floats immediately after vptr.
            return &box_; // placed at +0x04 in MSVC x86
        }

        /**
         * In binary: sub_4FF470 (writes center/axes from a transform-ish blob)
         *
         * Address: 0x4FF470
         * VFTable SLOT: 3
         */
        virtual void SetLocalTransform(const Mat34f& t) noexcept {
            // center <- last column
            box_.center[0] = t.m[3];
            box_.center[1] = t.m[7];
            box_.center[2] = t.m[11];
            // axis 3x3 <- first three columns
            box_.axis[0][0] = t.m[0];  box_.axis[0][1] = t.m[1];  box_.axis[0][2] = t.m[2];
            box_.axis[1][0] = t.m[4];  box_.axis[1][1] = t.m[5];  box_.axis[1][2] = t.m[6];
            box_.axis[2][0] = t.m[8];  box_.axis[2][1] = t.m[9];  box_.axis[2][2] = t.m[10];
            // extents stay unchanged here
        }

        /**
         * In binary: sub_4FFBE0 (reads float[16..18] into out vec)
         *
         * Address: 0x4FFBE0
         * VFTable SLOT: 4
         */
        [[nodiscard]] virtual Vec3f GetExtraVector() const noexcept {
            return extra_;
        }

        /**
         * In binary: sub_4FFC00 (writes float[16..18] from input vec)
         *
         * Address: 0x4FFC00
         * VFTable SLOT: 5
         */
        virtual void SetExtraVector(const Vec3f& v) noexcept {
            extra_ = v;
        }

        /**
         * In binary: sub_4FF2D0 (raycast in local space; fills hit info; returns 1/0)
         *
         * Address: 0x4FF2D0
         * VFTable SLOT: 6
         */
        virtual bool RaycastLocal(const Vec3f& rayOrigin, const Vec3f& rayDir, float& tHit) const noexcept {
            // Transform ray into box coordinates (axis are assumed orthonormal)
            const Vec3f C{ box_.center[0], box_.center[1], box_.center[2] };
            const Vec3f A0{ box_.axis[0][0], box_.axis[0][1], box_.axis[0][2] };
            const Vec3f A1{ box_.axis[1][0], box_.axis[1][1], box_.axis[1][2] };
            const Vec3f A2{ box_.axis[2][0], box_.axis[2][1], box_.axis[2][2] };

            auto dot = [](const Vec3f& a, const Vec3f& b) noexcept { return a.x * b.x + a.y * b.y + a.z * b.z; };

            Vec3f o{ rayOrigin.x - C.x, rayOrigin.y - C.y, rayOrigin.z - C.z };
            float o0 = dot(o, A0), o1 = dot(o, A1), o2 = dot(o, A2);
            float d0 = dot(rayDir, A0), d1 = dot(rayDir, A1), d2 = dot(rayDir, A2);

            float tmin = -std::numeric_limits<float>::infinity();
            float tmax = std::numeric_limits<float>::infinity();
            const float ex[3] = { box_.extent[0], box_.extent[1], box_.extent[2] };
            const float oarr[3] = { o0, o1, o2 };
            const float darr[3] = { d0, d1, d2 };

            constexpr float eps = 1e-6f;
            for (int i = 0;i < 3;i++) {
                if (std::fabs(darr[i]) < eps) {
                    if (oarr[i] < -ex[i] || oarr[i] > ex[i]) return false;
                } else {
                    float inv = 1.0f / darr[i];
                    float t1 = (-ex[i] - oarr[i]) * inv;
                    float t2 = (ex[i] - oarr[i]) * inv;
                    if (t1 > t2) std::swap(t1, t2);
                    if (t1 > tmin) tmin = t1;
                    if (t2 < tmax) tmax = t2;
                    if (tmin > tmax) return false;
                }
            }
            tHit = (tmin >= 0.0f) ? tmin : tmax;
            return tHit >= 0.0f;
        }

        /**
         * In binary: sub_4FF260 (derives local AABB; returns 1/0 and writes 4 outputs)
         *
         * Address: 0x4FF260
         * VFTable SLOT: 7
         */
        virtual bool ComputeLocalAABB(AABB& out) const noexcept {
            // Conservative OBB->AABB cover: sum |axis[i] * extent[i]|
            const Vec3f ax0{ box_.axis[0][0], box_.axis[0][1], box_.axis[0][2] };
            const Vec3f ax1{ box_.axis[1][0], box_.axis[1][1], box_.axis[1][2] };
            const Vec3f ax2{ box_.axis[2][0], box_.axis[2][1], box_.axis[2][2] };
            const Vec3f C{ box_.center[0], box_.center[1], box_.center[2] };
            const Vec3f E{ box_.extent[0], box_.extent[1], box_.extent[2] };

            Vec3f r{
                std::fabs(ax0.x) * E.x + std::fabs(ax1.x) * E.y + std::fabs(ax2.x) * E.z,
                std::fabs(ax0.y) * E.x + std::fabs(ax1.y) * E.y + std::fabs(ax2.y) * E.z,
                std::fabs(ax0.z) * E.x + std::fabs(ax1.z) * E.y + std::fabs(ax2.z) * E.z
            };
            out.min = { C.x - r.x, C.y - r.y, C.z - r.z };
            out.max = { C.x + r.x, C.y + r.y, C.z + r.z };
            return true;
        }

        /**
         * In binary: sub_4FF150 (sphere-vs-box test; writes contact data; returns 1/0)
         *
         * Address: 0x4FF150
         * VFTable SLOT: 8
         */
        virtual bool CollideSphereLocal(const Vec3f& sphereCenter, float sphereRadius, float& penetration) const noexcept {
            // Distance from point to OBB in box coordinates.
            const Vec3f C{ box_.center[0], box_.center[1], box_.center[2] };
            const Vec3f A0{ box_.axis[0][0], box_.axis[0][1], box_.axis[0][2] };
            const Vec3f A1{ box_.axis[1][0], box_.axis[1][1], box_.axis[1][2] };
            const Vec3f A2{ box_.axis[2][0], box_.axis[2][1], box_.axis[2][2] };

            auto dot = [](const Vec3f& a, const Vec3f& b) noexcept { return a.x * b.x + a.y * b.y + a.z * b.z; };

            Vec3f d{ sphereCenter.x - C.x, sphereCenter.y - C.y, sphereCenter.z - C.z };
            float qx = dot(d, A0);
            float qy = dot(d, A1);
            float qz = dot(d, A2);

            // Clamp to extents to find closest point on OBB
            float cx = std::clamp(qx, -box_.extent[0], box_.extent[0]);
            float cy = std::clamp(qy, -box_.extent[1], box_.extent[1]);
            float cz = std::clamp(qz, -box_.extent[2], box_.extent[2]);

            float dx = qx - cx;
            float dy = qy - cy;
            float dz = qz - cz;
            float dist2 = dx * dx + dy * dy + dz * dz;

            if (dist2 > sphereRadius * sphereRadius) {
                penetration = 0.0f;
                return false;
            }
            float dist = std::sqrt(dist2);
            penetration = sphereRadius - dist; // ~binary: r - sqrt(v6)
            return true;
        }

        /**
         * In binary: sub_4FF450 (point-in-box using sub_A3BC10)
         *
         * Address: 0x4FF450
         * VFTable SLOT: 9
         */
        [[nodiscard]] virtual bool ContainsPointLocal(const Vec3f& p) const noexcept {
            // Same as sub_A3BC10 semantics
            const float dx = p.x - box_.center[0];
            const float dy = p.y - box_.center[1];
            const float dz = p.z - box_.center[2];

            const float* a = &box_.axis[0][0];
            for (int i = 0;i < 3;i++) {
                float dp = a[0] * dx + a[1] * dy + a[2] * dz;
                if (std::fabs(dp) > box_.extent[i]) return false;
                a += 3;
            }
            return true;
        }

    private:
        // 0x00 : vptr (implicit)
        // 0x04 : Box3 blob (15 floats = 60 bytes)
        Box3f box_;
        // 0x40 : extra vector (3 floats) accessed by sub_4FFBE0/4FFC00
        Vec3f extra_; // unknown semantic (cache/margin/offset)
        // total size at least 0x4C (76 bytes)

    public:
        void SetExtents(const Vec3f& e) noexcept {
            box_.extent[0] = e.x; box_.extent[1] = e.y; box_.extent[2] = e.z;
        }

        [[nodiscard]] Vec3f GetExtents() const noexcept {
            return { box_.extent[0], box_.extent[1], box_.extent[2] };
        }
        void SetCenter(const Vec3f& c) noexcept {
            box_.center[0] = c.x; box_.center[1] = c.y; box_.center[2] = c.z;
        }

        [[nodiscard]] Vec3f GetCenter() const noexcept {
            return { box_.center[0], box_.center[1], box_.center[2] };
        }
    };
}