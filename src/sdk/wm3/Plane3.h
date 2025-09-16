#pragma once
#include "Vector3.h"

namespace Wm3
{
    /**
     * Plane in form: Dot(Normal, X) == Constant.
     * This matches the classic Wm3 representation: N * X = C (not Ax+By+Cz+D=0).
     */
    template <class T>
    struct Plane3 {
        Vec3<T> Normal;
        T Constant{};

        /**
         * Default ctor: zero normal and constant (degenerate plane).
         *
         */
        constexpr Plane3() = default;

        /**
         * From normal and constant (no normalization).
         */
        constexpr Plane3(const Vec3<T>& n, T c) : Normal(n), Constant(c) {}

        /**
         * From normal and a point on plane: Constant = Dot(n, p).
         */
        static constexpr Plane3 FromNormalPoint(const Vec3<T>& n, const Vec3<T>& point) noexcept {
            return Plane3(n, Vec3<T>::Dot(n, point));
        }

        /**
         * From three non-collinear points (counter-clockwise defines normal).
         */
        static Plane3 FromPoints(
            const Vec3<T>& p0, 
            const Vec3<T>& p1, 
            const Vec3<T>& p2,
            T eps = T(1e-6)) noexcept
        {
            static_assert(std::is_floating_point_v<T>, "FromPoints requires floating-point T");
            const Vec3<T> e1 = Vec3<T>::Sub(p1, p0);
            const Vec3<T> e2 = Vec3<T>::Sub(p2, p0);
            Vec3<T> n = Vec3<T>::Cross(e1, e2);
            n = Vec3<T>::Normalized(n, eps);
            const T c = Vec3<T>::Dot(n, p0);
            return Plane3(n, c);
        }

        /**
         * Normalize plane so that |Normal| == 1; returns previous |Normal|.
         */
        T Normalize(T eps = T(1e-6)) noexcept {
            static_assert(std::is_floating_point_v<T>, "Normalize requires floating-point T");
            T len = Vec3<T>::Length(Normal);
            if (len > eps) {
                const T inv = T(1) / len;
                Normal = Vec3<T>::Scale(Normal, inv);
                Constant *= inv;
            } else {
                Normal = { T(0), T(0), T(0) };
                Constant = T(0);
            }
            return len;
        }

        /**
         * Signed distance from point to plane:
         * d = Dot(N, X) - C (assumes unit Normal for true distance).
         */
        T SignedDistance(const Vec3<T>& x) const noexcept {
            static_assert(std::is_floating_point_v<T>, "SignedDistance requires floating-point T");
            return Vec3<T>::Dot(Normal, x) - Constant;
        }

        /**
         * Project point to plane along the normal direction.
         */
        Vec3<T> ProjectPoint(const Vec3<T>& x) const noexcept {
            static_assert(std::is_floating_point_v<T>, "ProjectPoint requires floating-point T");
            const T d = SignedDistance(x);
            return Vec3<T>::Sub(x, Vec3<T>::Scale(Normal, d));
        }

        /**
         * Flip plane orientation: Normal=-Normal, Constant=-Constant.
         */
        void Flip() noexcept {
	        Normal = Vec3<T>{ -Normal.x, -Normal.y, -Normal.z };
        	Constant = -Constant;
        }

        /**
         * Compare with epsilons for Normal and Constant.
         */
        static bool NearlyEquals(
            const Plane3& a, 
            const Plane3& b, 
            T epsN = T(1e-5), 
            T epsC = T(1e-5)) noexcept
    	{
            return Vec3<T>::NearlyEquals(a.Normal, b.Normal, epsN) && 
                std::fabs(a.Constant - b.Constant) <= epsC;
        }

        /**
         * Intersection with infinite line P(t)=P0 + t*D. Returns (hit, t, point).
         */
        struct LineHit {
            bool hit{};
            T    t{};
            Vec3<T> point{};
        };

        static LineHit IntersectLine(
            const Plane3& pl, 
            const Vec3<T>& P0, 
            const Vec3<T>& D, 
            T eps = T(1e-6)) noexcept
    	{
            static_assert(std::is_floating_point_v<T>, "IntersectLine requires floating-point T");
            const T denom = Vec3<T>::Dot(pl.Normal, D);
            if (std::fabs(denom) <= eps) {
                return {}; // parallel or lies in plane
            }
            const T t = (pl.Constant - Vec3<T>::Dot(pl.Normal, P0)) / denom;
            return { true, t, Vec3<T>::Add(P0, Vec3<T>::Scale(D, t)) };
        }

        /**
         * Intersection with segment [A,B]. Returns (hit, t in [0,1], point).
         */
        static LineHit IntersectSegment(
            const Plane3& pl, 
            const Vec3<T>& A, 
            const Vec3<T>& B, T eps = T(1e-6)) noexcept
    	{
            const Vec3<T> D = Vec3<T>::Sub(B, A);
            LineHit h = IntersectLine(pl, A, D, eps);
            if (!h.hit || h.t < T(0) || h.t > T(1)) {
	            return {};
            }
            return h;
        }

        /**
         * Intersection with ray P(t)=O + t*D, t>=0.
         */
        static LineHit IntersectRay(
            const Plane3& pl, 
            const Vec3<T>& O, 
            const Vec3<T>& D, 
            T eps = T(1e-6)) noexcept
    	{
            LineHit h = IntersectLine(pl, O, D, eps);
            if (!h.hit || h.t < T(0)) {
                return {};
            }
            return h;
        }

        /**
         * Classification of a point relative to plane.
         */
        enum class Side
        {
	        On,
        	Front,
        	Back
        };

        /**
         * Classify point with tolerance; assumes unit Normal for precise distance.
         */
        Side Classify(const Vec3<T>& x, T eps = T(1e-5)) const noexcept {
            static_assert(std::is_floating_point_v<T>, "Classify requires floating-point T");
            const T d = SignedDistance(x);
            if (d > eps) return Side::Front;
            if (d < -eps) return Side::Back;
            return Side::On;
        }

        /**
         * Convert from Ax+By+Cz + D = 0 form. Here Constant = -D.
         */
        static constexpr Plane3 FromAbCd(const Vec3<T>& abc, T d) noexcept {
	        return Plane3(abc, -d);
        }

        /**
         * Convert to Ax+By+Cz + D = 0 form. Returns (A,B,C,D).
         */
        constexpr Vec3<T> GetAbc() const noexcept { return Normal; }
        constexpr T       GetD()   const noexcept { return -Constant; }

        /**
         * Convert to another scalar type.
         */
        template <class U>
        static constexpr Plane3<T> From(const Plane3<U>& p) noexcept {
            return Plane3<T>(
                Vec3<T>{ T(p.Normal.x), T(p.Normal.y), T(p.Normal.z) },
                T(p.Constant)
            );
        }
    };

    using Plane3f = Plane3<float>;
    using Plane3i = Plane3<int>;   // storage-only; geometric ops expect floating-point
}
