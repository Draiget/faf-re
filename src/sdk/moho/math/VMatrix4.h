#pragma once

#include "Vector4f.h"

namespace moho
{
    /**
     * 4x4 matrix, row-major. Each row is a Vector4f.
     * Translation lives in the last row (r[3].xyz), consistent with Moho row-vector pipeline.
     */
    struct alignas(16) VMatrix4 {
        Vector4f r[4]; // rows

        /** Identity. */
        static VMatrix4 Identity() {
            VMatrix4 m{};
            m.r[0] = { 1,0,0,0 };
            m.r[1] = { 0,1,0,0 };
            m.r[2] = { 0,0,1,0 };
            m.r[3] = { 0,0,0,1 };
            return m;
        }

        /**
         * Set from unit quaternion (x,y,z,w) and translation (tx,ty,tz).
         */
        static VMatrix4 FromQuatPos(const Vector4f& qXyzw, float tx, float ty, float tz) {
            VMatrix4 out{};
            const float x = qXyzw.x, y = qXyzw.y, z = qXyzw.z, w = qXyzw.w;

            const float xx = x + x, yy = y + y, zz = z + z;
            const float xx2 = x * xx, yy2 = y * yy, zz2 = z * zz;
            const float xy = x * yy, xz = x * zz, yz = y * zz;
            const float wx = w * xx, wy = w * yy, wz = w * zz;

            out.r[0] = { 1.0f - (yy2 + zz2),  xy - wz,            xz + wy,            0.0f };
            out.r[1] = { xy + wz,             1.0f - (xx2 + zz2), yz - wx,            0.0f };
            out.r[2] = { xz - wy,             yz + wx,            1.0f - (xx2 + yy2), 0.0f };
            out.r[3] = { tx, ty, tz, 1.0f };
            return out;
        }

        /** Set translation (last row). */
        void SetTranslation(float tx, float ty, float tz) { r[3] = { tx, ty, tz, 1.0f }; }

        /** Get translation (last row). */
        [[nodiscard]]
    	Vector4f GetTranslationRow() const { return r[3]; }

#if MOHO_USE_SSE2
        /** Compile-time splat: Lane is template immediate for _mm_shuffle_ps. */
        template<int Lane>
        static MOHO_FORCEINLINE __m128 splat(__m128 v) {
            static_assert(Lane >= 0 && Lane <= 3, "Lane out of range");
            return _mm_shuffle_ps(v, v, _MM_SHUFFLE(Lane, Lane, Lane, Lane));
        }
#endif

        /**
         * Row-vector multiply: v_row * M.
         */
        friend Vector4f operator*(const Vector4f& vRow, const VMatrix4& M) {
#if MOHO_USE_SSE2
            const __m128 a = _mm_load_ps(&vRow.x);
            const __m128 m0 = _mm_load_ps(&M.r[0].x);
            const __m128 m1 = _mm_load_ps(&M.r[1].x);
            const __m128 m2 = _mm_load_ps(&M.r[2].x);
            const __m128 m3 = _mm_load_ps(&M.r[3].x);

            __m128 acc = _mm_mul_ps(splat<0>(a), m0);
            acc = _mm_add_ps(acc, _mm_mul_ps(splat<1>(a), m1));
            acc = _mm_add_ps(acc, _mm_mul_ps(splat<2>(a), m2));
            acc = _mm_add_ps(acc, _mm_mul_ps(splat<3>(a), m3));

            Vector4f out; _mm_store_ps(&out.x, acc);
            return out;
#else
            Vector4f out{};
            out.x = vRow.x * M.r[0].x + vRow.y * M.r[1].x + vRow.z * M.r[2].x + vRow.w * M.r[3].x;
            out.y = vRow.x * M.r[0].y + vRow.y * M.r[1].y + vRow.z * M.r[2].y + vRow.w * M.r[3].y;
            out.z = vRow.x * M.r[0].z + vRow.y * M.r[1].z + vRow.z * M.r[2].z + vRow.w * M.r[3].z;
            out.w = vRow.x * M.r[0].w + vRow.y * M.r[1].w + vRow.z * M.r[2].w + vRow.w * M.r[3].w;
            return out;
#endif
        }

        /**
         * Matrix multiply under row-vector convention: R = A * B (apply A then B).
         */
        static VMatrix4 Multiply(const VMatrix4& A, const VMatrix4& B) {
            VMatrix4 r{};
#if MOHO_USE_SSE2
            const __m128 b0 = _mm_load_ps(&B.r[0].x);
            const __m128 b1 = _mm_load_ps(&B.r[1].x);
            const __m128 b2 = _mm_load_ps(&B.r[2].x);
            const __m128 b3 = _mm_load_ps(&B.r[3].x);

            for (int i = 0; i < 4; ++i) {
                const __m128 ai = _mm_load_ps(&A.r[i].x);
                __m128 acc = _mm_mul_ps(splat<0>(ai), b0);
                acc = _mm_add_ps(acc, _mm_mul_ps(splat<1>(ai), b1));
                acc = _mm_add_ps(acc, _mm_mul_ps(splat<2>(ai), b2));
                acc = _mm_add_ps(acc, _mm_mul_ps(splat<3>(ai), b3));
                _mm_store_ps(&r.r[i].x, acc);
            }
#else
            for (int i = 0; i < 4; ++i) {
                const float ax = A.r[i].x, ay = A.r[i].y, az = A.r[i].z, aw = A.r[i].w;
                r.r[i].x = ax * B.r[0].x + ay * B.r[1].x + az * B.r[2].x + aw * B.r[3].x;
                r.r[i].y = ax * B.r[0].y + ay * B.r[1].y + az * B.r[2].y + aw * B.r[3].y;
                r.r[i].z = ax * B.r[0].z + ay * B.r[1].z + az * B.r[2].z + aw * B.r[3].z;
                r.r[i].w = ax * B.r[0].w + ay * B.r[1].w + az * B.r[2].w + aw * B.r[3].w;
            }
#endif
            return r;
        }

        /**
         * Transpose (useful if you prefer column-vector code paths somewhere).
         */
        static VMatrix4 Transpose(const VMatrix4& M) {
            VMatrix4 T{};
#if MOHO_USE_SSE2
            __m128 row0 = _mm_load_ps(&M.r[0].x);
            __m128 row1 = _mm_load_ps(&M.r[1].x);
            __m128 row2 = _mm_load_ps(&M.r[2].x);
            __m128 row3 = _mm_load_ps(&M.r[3].x);
            _MM_TRANSPOSE4_PS(row0, row1, row2, row3);
            _mm_store_ps(&T.r[0].x, row0);
            _mm_store_ps(&T.r[1].x, row1);
            _mm_store_ps(&T.r[2].x, row2);
            _mm_store_ps(&T.r[3].x, row3);
#else
            T.r[0] = { M.r[0].x, M.r[1].x, M.r[2].x, M.r[3].x };
            T.r[1] = { M.r[0].y, M.r[1].y, M.r[2].y, M.r[3].y };
            T.r[2] = { M.r[0].z, M.r[1].z, M.r[2].z, M.r[3].z };
            T.r[3] = { M.r[0].w, M.r[1].w, M.r[2].w, M.r[3].w };
#endif
            return T;
        }

        /**
         * Inverse for rigid transform (rotation+translation only, row-vector convention).
         */
        static VMatrix4 InverseRigid(const VMatrix4& M) {
            VMatrix4 r{};
            // Transpose 3x3 rotation block (top-left), zero the last column.
            r.r[0] = { M.r[0].x, M.r[1].x, M.r[2].x, 0.0f };
            r.r[1] = { M.r[0].y, M.r[1].y, M.r[2].y, 0.0f };
            r.r[2] = { M.r[0].z, M.r[1].z, M.r[2].z, 0.0f };
            // -t * R^T into last row
            const float tx = M.r[3].x, ty = M.r[3].y, tz = M.r[3].z;
            r.r[3].x = -(tx * r.r[0].x + ty * r.r[1].x + tz * r.r[2].x);
            r.r[3].y = -(tx * r.r[0].y + ty * r.r[1].y + tz * r.r[2].y);
            r.r[3].z = -(tx * r.r[0].z + ty * r.r[1].z + tz * r.r[2].z);
            r.r[3].w = 1.0f;
            return r;
        }
    };
}
