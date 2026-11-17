// EDITOR GPU compute: the C++ side of the kernel language (docs/projects/editor/GPU_COMPUTE.md). TEST CODE ONLY: no
// engine file includes it.
//
// A kernel (gpu/*.hlsl) is written in a small subset of HLSL that is also valid C++ once this header is included before
// it. The test (tests/EdGpuTest.cpp) includes every kernel inside its own namespace, runs it for every thread of a
// dispatch (tests/EdGpuEmu.h) and compares the result with the CPU op. The macros below are the C++ twins of the ones
// in hlsl_prelude.hlsli.
//
// Rules that keep a kernel valid in both languages (scripts/gen_gpu_shaders.py --check lints the ones that can be seen
// in the text):
//   * float literals always end in f (0.5f, 1.0f); arithmetic on mixed types and min/max/clamp of mixed types are
//   compile errors here (HLSL would promote silently): write 0u, 0.0f, int(x).
//   * no swizzles longer than one letter (v.xy): build vectors with float2(v.x, v.y). Components are x y z w only.
//   * no `return` value tricks that differ: a kernel is `void CSMain(KERNEL_IDS)`; `return;` is fine (not in kernels
//   that use PHASES_BEGIN).
//   * no round() (HLSL rounds half to even, C++ half away from zero): use floor(x + 0.5f).
//   * out / inout parameters are written OUT(T) / INOUT(T).
//   * group shared memory only through GROUPSHARED and the PHASES_BEGIN / BARRIER(0) / PHASES_END macros, BARRIER(0) at
//   the top level of the body (never in a loop or an if).
//
// The emulation runs the threads of a group one after the other (phase by phase for kernels with barriers), single
// threaded: atomics are plain operations. It reports out of range accesses of buffers and textures (emu::gOob) the way
// a GPU would silently ignore them. No fast-math, no multiply-add fusing: bit equal to the CPU where the maths is.
#pragma once

#if defined(_MSC_VER)
#pragma fp_contract(off)
#endif

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <type_traits>
#include <vector>

#include <math.h>
#include <stdlib.h>

using uint = std::uint32_t;

using std::abs;
using std::acos;
using std::asin;
using std::atan;
using std::atan2;
using std::ceil;
using std::cos;
using std::exp;
using std::exp2;
using std::floor;
using std::fmod;
using std::isinf;
using std::isnan;
using std::log;
using std::log2;
using std::pow;
using std::sin;
using std::sqrt;
using std::tan;
using std::trunc;

namespace emu
{
  // ---- vectors
  // -----------------------------------------------------------------------------------------------------------------------------

  template <class D, class T, int N>
  struct VecBase
  {
    static constexpr int kN = N;
    D& Self()
    {
      return static_cast<D&>(*this);
    }
    const D& Self() const
    {
      return static_cast<const D&>(*this);
    }
    D& operator+=(
      const D& o
    )
    {
      for (int i = 0; i < N; ++i)
        Self()[i] += o[i];
      return Self();
    }
    D& operator-=(
      const D& o
    )
    {
      for (int i = 0; i < N; ++i)
        Self()[i] -= o[i];
      return Self();
    }
    D& operator*=(
      const D& o
    )
    {
      for (int i = 0; i < N; ++i)
        Self()[i] *= o[i];
      return Self();
    }
    D& operator/=(
      const D& o
    )
    {
      for (int i = 0; i < N; ++i)
        Self()[i] /= o[i];
      return Self();
    }
    friend D operator+(
      D a,
      const D& b
    )
    {
      a += b;
      return a;
    }
    friend D operator-(
      D a,
      const D& b
    )
    {
      a -= b;
      return a;
    }
    friend D operator*(
      D a,
      const D& b
    )
    {
      a *= b;
      return a;
    }
    friend D operator/(
      D a,
      const D& b
    )
    {
      a /= b;
      return a;
    }
    friend D operator-(
      const D& a
    )
    {
      D r;
      for (int i = 0; i < N; ++i)
        r[i] = -a[i];
      return r;
    }
  };

  template <class T>
  struct Vec2 : VecBase<Vec2<T>, T, 2>
  {
    T x, y;
    Vec2() = default;
    Vec2(
      T s
    )
      : x(s)
      , y(s)
    {}
    Vec2(
      T a,
      T b
    )
      : x(a)
      , y(b)
    {}
    template <class U>
    explicit Vec2(
      const Vec2<U>& o
    )
      : x(static_cast<T>(o.x))
      , y(static_cast<T>(o.y))
    {}
    T& operator[](
      int i
    )
    {
      return (&x)[i];
    }
    const T& operator[](
      int i
    ) const
    {
      return (&x)[i];
    }
  };

  template <class T>
  struct Vec3 : VecBase<Vec3<T>, T, 3>
  {
    T x, y, z;
    Vec3() = default;
    Vec3(
      T s
    )
      : x(s)
      , y(s)
      , z(s)
    {}
    Vec3(
      T a,
      T b,
      T c
    )
      : x(a)
      , y(b)
      , z(c)
    {}
    Vec3(
      Vec2<T> v,
      T c
    )
      : x(v.x)
      , y(v.y)
      , z(c)
    {}
    Vec3(
      T a,
      Vec2<T> v
    )
      : x(a)
      , y(v.x)
      , z(v.y)
    {}
    template <class U>
    explicit Vec3(
      const Vec3<U>& o
    )
      : x(static_cast<T>(o.x))
      , y(static_cast<T>(o.y))
      , z(static_cast<T>(o.z))
    {}
    T& operator[](
      int i
    )
    {
      return (&x)[i];
    }
    const T& operator[](
      int i
    ) const
    {
      return (&x)[i];
    }
  };

  template <class T>
  struct Vec4 : VecBase<Vec4<T>, T, 4>
  {
    T x, y, z, w;
    Vec4() = default;
    Vec4(
      T s
    )
      : x(s)
      , y(s)
      , z(s)
      , w(s)
    {}
    Vec4(
      T a,
      T b,
      T c,
      T d
    )
      : x(a)
      , y(b)
      , z(c)
      , w(d)
    {}
    Vec4(
      Vec3<T> v,
      T d
    )
      : x(v.x)
      , y(v.y)
      , z(v.z)
      , w(d)
    {}
    Vec4(
      T a,
      Vec3<T> v
    )
      : x(a)
      , y(v.x)
      , z(v.y)
      , w(v.z)
    {}
    Vec4(
      Vec2<T> a,
      Vec2<T> b
    )
      : x(a.x)
      , y(a.y)
      , z(b.x)
      , w(b.y)
    {}
    template <class U>
    explicit Vec4(
      const Vec4<U>& o
    )
      : x(static_cast<T>(o.x))
      , y(static_cast<T>(o.y))
      , z(static_cast<T>(o.z))
      , w(static_cast<T>(o.w))
    {}
    T& operator[](
      int i
    )
    {
      return (&x)[i];
    }
    const T& operator[](
      int i
    ) const
    {
      return (&x)[i];
    }
  };

  // ---- run state
  // ---------------------------------------------------------------------------------------------------------------------------

  inline int gOob =
    0; // out of range buffer / texture accesses since the last reset (a GPU ignores them; a kernel must not make them)
  inline int gPhase = 0;     // the phase being run (kernels with barriers)
  inline bool gMore = false; // set when a BARRIER(0) was passed: another phase follows
} // namespace emu

using float2 = emu::Vec2<float>;
using float3 = emu::Vec3<float>;
using float4 = emu::Vec4<float>;
using int2 = emu::Vec2<int>;
using int3 = emu::Vec3<int>;
using int4 = emu::Vec4<int>;
using uint2 = emu::Vec2<uint>;
using uint3 = emu::Vec3<uint>;
using uint4 = emu::Vec4<uint>;

// ---- intrinsics
// --------------------------------------------------------------------------------------------------------------------------------
// Scalars come from <cmath> (using-declarations above) or are defined here; vectors work per component.

template <class T>
  requires std::is_arithmetic_v<T>
inline T min(
  T a,
  T b
)
{
  return b < a ? b : a;
}
template <class T>
  requires std::is_arithmetic_v<T>
inline T max(
  T a,
  T b
)
{
  return a < b ? b : a;
}
template <class T>
  requires std::is_arithmetic_v<T>
inline T clamp(
  T v,
  T lo,
  T hi
)
{
  return v < lo ? lo : (v > hi ? hi : v);
}
template <class T>
  requires std::is_floating_point_v<T>
inline T lerp(
  T a,
  T b,
  T t
)
{
  return a + (b - a) * t;
}
template <class T>
  requires std::is_floating_point_v<T>
inline T mad(
  T a,
  T b,
  T c
)
{
  return a * b + c;
}
inline float saturate(
  float v
)
{
  return v < 0.0f ? 0.0f : (v > 1.0f ? 1.0f : v);
}
inline float frac(
  float v
)
{
  return v - std::floor(v);
}
inline float rsqrt(
  float v
)
{
  return 1.0f / std::sqrt(v);
}
inline float step(
  float edge,
  float v
)
{
  return v >= edge ? 1.0f : 0.0f;
}
inline float sign(
  float v
)
{
  return v > 0.0f ? 1.0f : (v < 0.0f ? -1.0f : 0.0f);
}
inline int sign(
  int v
)
{
  return v > 0 ? 1 : (v < 0 ? -1 : 0);
}
inline float smoothstep(
  float e0,
  float e1,
  float v
)
{
  const float t = saturate((v - e0) / (e1 - e0));
  return t * t * (3.0f - 2.0f * t);
}
inline void sincos(
  float v,
  float& s,
  float& c
)
{
  s = std::sin(v);
  c = std::cos(v);
}
inline float dot(
  float a,
  float b
)
{
  return a * b;
}

inline uint asuint(
  float f
)
{
  uint u;
  std::memcpy(&u, &f, 4);
  return u;
}
inline uint asuint(
  int i
)
{
  return static_cast<uint>(i);
}
inline int asint(
  float f
)
{
  int i;
  std::memcpy(&i, &f, 4);
  return i;
}
inline int asint(
  uint u
)
{
  return static_cast<int>(u);
}
inline float asfloat(
  uint u
)
{
  float f;
  std::memcpy(&f, &u, 4);
  return f;
}
inline float asfloat(
  int i
)
{
  float f;
  std::memcpy(&f, &i, 4);
  return f;
}
inline uint countbits(
  uint v
)
{
  uint n = 0;
  while (v != 0u) {
    n += v & 1u;
    v >>= 1;
  }
  return n;
}

#define EMU_VEC_UNARY(NAME, EXPR)                                                                                      \
  template <class V, class = decltype(V::kN)>                                                                          \
  inline V NAME(V a)                                                                                                   \
  {                                                                                                                    \
    V r;                                                                                                               \
    for (int i = 0; i < V::kN; ++i) {                                                                                  \
      const auto x = a[i];                                                                                             \
      r[i] = EXPR;                                                                                                     \
    }                                                                                                                  \
    return r;                                                                                                          \
  }
EMU_VEC_UNARY(
  floor,
  std::floor(x)
)
EMU_VEC_UNARY(
  ceil,
  std::ceil(x)
)
EMU_VEC_UNARY(
  trunc,
  std::trunc(x)
)
EMU_VEC_UNARY(
  frac,
  x - std::floor(x)
)
EMU_VEC_UNARY(
  saturate,
  x < 0.0f ? 0.0f : (x > 1.0f ? 1.0f : x)
)
EMU_VEC_UNARY(
  sqrt,
  std::sqrt(x)
)
EMU_VEC_UNARY(
  rsqrt,
  1.0f / std::sqrt(x)
)
EMU_VEC_UNARY(
  abs,
  std::fabs(x)
)
EMU_VEC_UNARY(
  sin,
  std::sin(x)
)
EMU_VEC_UNARY(
  cos,
  std::cos(x)
)
EMU_VEC_UNARY(
  exp,
  std::exp(x)
)
EMU_VEC_UNARY(
  exp2,
  std::exp2(x)
)
EMU_VEC_UNARY(
  log,
  std::log(x)
)
EMU_VEC_UNARY(
  log2,
  std::log2(x)
)
EMU_VEC_UNARY(
  sign,
  x > 0.0f ? 1.0f : (x < 0.0f ? -1.0f : 0.0f)
)
#undef EMU_VEC_UNARY

#define EMU_VEC_BINARY(NAME, EXPR)                                                                                     \
  template <class V, class = decltype(V::kN)>                                                                          \
  inline V NAME(V a, V b)                                                                                              \
  {                                                                                                                    \
    V r;                                                                                                               \
    for (int i = 0; i < V::kN; ++i) {                                                                                  \
      const auto x = a[i];                                                                                             \
      const auto y = b[i];                                                                                             \
      r[i] = EXPR;                                                                                                     \
    }                                                                                                                  \
    return r;                                                                                                          \
  }
EMU_VEC_BINARY(
  min,
  y < x ? y : x
)
EMU_VEC_BINARY(
  max,
  x < y ? y : x
)
EMU_VEC_BINARY(
  pow,
  std::pow(x, y)
)
EMU_VEC_BINARY(
  fmod,
  std::fmod(x, y)
)
EMU_VEC_BINARY(
  atan2,
  std::atan2(x, y)
)
EMU_VEC_BINARY(
  step,
  y >= x ? 1.0f : 0.0f
)
#undef EMU_VEC_BINARY

// vector with a scalar (HLSL promotes the scalar)
template <class V, class = decltype(V::kN)>
inline V min(
  V a,
  decltype(a.x) s
)
{
  return min(a, V(s));
}
template <class V, class = decltype(V::kN)>
inline V max(
  V a,
  decltype(a.x) s
)
{
  return max(a, V(s));
}
template <class V, class = decltype(V::kN)>
inline V clamp(
  V v,
  V lo,
  V hi
)
{
  return min(max(v, lo), hi);
}
template <class V, class = decltype(V::kN)>
inline V clamp(
  V v,
  decltype(v.x) lo,
  decltype(v.x) hi
)
{
  return min(max(v, V(lo)), V(hi));
}
template <class V, class = decltype(V::kN)>
inline V lerp(
  V a,
  V b,
  V t
)
{
  return a + (b - a) * t;
}
template <class V, class = decltype(V::kN)>
inline V lerp(
  V a,
  V b,
  decltype(a.x) t
)
{
  return a + (b - a) * V(t);
}
template <class V, class = decltype(V::kN)>
inline V mad(
  V a,
  V b,
  V c
)
{
  return a * b + c;
}
template <class V, class = decltype(V::kN)>
inline V smoothstep(
  V e0,
  V e1,
  V v
)
{
  V r;
  for (int i = 0; i < V::kN; ++i)
    r[i] = smoothstep(e0[i], e1[i], v[i]);
  return r;
}
template <class V, class = decltype(V::kN)>
inline auto dot(
  V a,
  V b
)
{
  auto s = a[0] * b[0];
  for (int i = 1; i < V::kN; ++i)
    s += a[i] * b[i];
  return s;
}
template <class V, class = decltype(V::kN)>
inline float length(
  V a
)
{
  return std::sqrt(dot(a, a));
}
template <class V, class = decltype(V::kN)>
inline float distance(
  V a,
  V b
)
{
  return length(a - b);
}
template <class V, class = decltype(V::kN)>
inline V normalize(
  V a
)
{
  return a / V(length(a));
}
inline float3 cross(
  float3 a,
  float3 b
)
{
  return float3(a.y * b.z - a.z * b.y, a.z * b.x - a.x * b.z, a.x * b.y - a.y * b.x);
}

// ---- atomics (single threaded emulation)
// -------------------------------------------------------------------------------------------------------

#define EMU_ATOMIC(T)                                                                                                  \
  inline void InterlockedAdd(T& d, T v)                                                                                \
  {                                                                                                                    \
    d += v;                                                                                                            \
  }                                                                                                                    \
  inline void InterlockedAdd(T& d, T v, T& orig)                                                                       \
  {                                                                                                                    \
    orig = d;                                                                                                          \
    d += v;                                                                                                            \
  }                                                                                                                    \
  inline void InterlockedMin(T& d, T v)                                                                                \
  {                                                                                                                    \
    d = v < d ? v : d;                                                                                                 \
  }                                                                                                                    \
  inline void InterlockedMin(T& d, T v, T& orig)                                                                       \
  {                                                                                                                    \
    orig = d;                                                                                                          \
    d = v < d ? v : d;                                                                                                 \
  }                                                                                                                    \
  inline void InterlockedMax(T& d, T v)                                                                                \
  {                                                                                                                    \
    d = d < v ? v : d;                                                                                                 \
  }                                                                                                                    \
  inline void InterlockedMax(T& d, T v, T& orig)                                                                       \
  {                                                                                                                    \
    orig = d;                                                                                                          \
    d = d < v ? v : d;                                                                                                 \
  }                                                                                                                    \
  inline void InterlockedOr(T& d, T v)                                                                                 \
  {                                                                                                                    \
    d |= v;                                                                                                            \
  }                                                                                                                    \
  inline void InterlockedOr(T& d, T v, T& orig)                                                                        \
  {                                                                                                                    \
    orig = d;                                                                                                          \
    d |= v;                                                                                                            \
  }                                                                                                                    \
  inline void InterlockedAnd(T& d, T v)                                                                                \
  {                                                                                                                    \
    d &= v;                                                                                                            \
  }                                                                                                                    \
  inline void InterlockedAnd(T& d, T v, T& orig)                                                                       \
  {                                                                                                                    \
    orig = d;                                                                                                          \
    d &= v;                                                                                                            \
  }                                                                                                                    \
  inline void InterlockedXor(T& d, T v)                                                                                \
  {                                                                                                                    \
    d ^= v;                                                                                                            \
  }                                                                                                                    \
  inline void InterlockedXor(T& d, T v, T& orig)                                                                       \
  {                                                                                                                    \
    orig = d;                                                                                                          \
    d ^= v;                                                                                                            \
  }                                                                                                                    \
  inline void InterlockedExchange(T& d, T v, T& orig)                                                                  \
  {                                                                                                                    \
    orig = d;                                                                                                          \
    d = v;                                                                                                             \
  }                                                                                                                    \
  inline void InterlockedCompareExchange(T& d, T cmp, T v, T& orig)                                                    \
  {                                                                                                                    \
    orig = d;                                                                                                          \
    if (d == cmp)                                                                                                      \
      d = v;                                                                                                           \
  }                                                                                                                    \
  inline void InterlockedCompareStore(T& d, T cmp, T v)                                                                \
  {                                                                                                                    \
    if (d == cmp)                                                                                                      \
      d = v;                                                                                                           \
  }
EMU_ATOMIC(
  uint
)
EMU_ATOMIC(
  int
)
#undef EMU_ATOMIC

// ---- resources
// ---------------------------------------------------------------------------------------------------------------------------------

namespace emu
{
  /** What the driver hands a kernel for one slot. */
  struct ResView
  {
    void* data = nullptr;
    uint count = 0;  // buffer: elements
    uint stride = 0; // buffer: bytes per element
    uint w = 0;      // texture
    uint h = 0;
    bool texture = false;
  };

  struct Bindable
  {
    virtual ~Bindable() = default;
    virtual bool Bind(const ResView& v, std::string& err) = 0;
    virtual void Unbind() = 0;
  };

  template <class T>
  struct StructuredBuffer : Bindable
  {
    const T* p = nullptr;
    uint n = 0;
    T operator[](
      uint i
    ) const
    {
      if (i >= n) {
        ++gOob;
        return T();
      }
      return p[i];
    }
    void GetDimensions(
      uint& count,
      uint& stride
    ) const
    {
      count = n;
      stride = static_cast<uint>(sizeof(T));
    }
    bool Bind(
      const ResView& v,
      std::string& err
    ) override
    {
      if (v.texture || v.stride != sizeof(T)) {
        err = "buffer element size differs from the kernel's";
        return false;
      }
      p = static_cast<const T*>(v.data);
      n = v.count;
      return true;
    }
    void Unbind() override
    {
      p = nullptr;
      n = 0;
    }
  };

  template <class T>
  struct RWStructuredBuffer : Bindable
  {
    T* p = nullptr;
    uint n = 0;
    T& operator[](
      uint i
    )
    {
      if (i >= n) {
        ++gOob;
        static T sink;
        sink = T();
        return sink;
      }
      return p[i];
    }
    void GetDimensions(
      uint& count,
      uint& stride
    ) const
    {
      count = n;
      stride = static_cast<uint>(sizeof(T));
    }
    bool Bind(
      const ResView& v,
      std::string& err
    ) override
    {
      if (v.texture || v.stride != sizeof(T)) {
        err = "buffer element size differs from the kernel's";
        return false;
      }
      p = static_cast<T*>(v.data);
      n = v.count;
      return true;
    }
    void Unbind() override
    {
      p = nullptr;
      n = 0;
    }
  };

  /** Sampler state: slot 0 = linear filter, clamp to edge; slot 1 = point filter, clamp to edge (the two the host
   * binds). */
  struct SamplerState
  {
    int slot = 0;
  };

  struct Texture2D : Bindable
  {
    const float* p = nullptr;
    uint w = 0;
    uint h = 0;
    float Texel(
      int x,
      int y
    ) const
    {
      x = x < 0 ? 0 : (x >= static_cast<int>(w) ? static_cast<int>(w) - 1 : x);
      y = y < 0 ? 0 : (y >= static_cast<int>(h) ? static_cast<int>(h) - 1 : y);
      return p[static_cast<std::size_t>(y) * w + static_cast<std::size_t>(x)];
    }
    float Load(
      int3 c
    ) const
    {
      if (c.x < 0 || c.y < 0 || c.x >= static_cast<int>(w) || c.y >= static_cast<int>(h)) {
        ++gOob;
        return 0.0f;
      }
      return p[static_cast<std::size_t>(c.y) * w + static_cast<std::size_t>(c.x)];
    }
    float operator[](
      uint2 c
    ) const
    {
      if (c.x >= w || c.y >= h) {
        ++gOob;
        return 0.0f;
      }
      return p[static_cast<std::size_t>(c.y) * w + c.x];
    }
    float SampleLevel(
      SamplerState s,
      float2 uv,
      float /*lod*/
    ) const
    {
      if (s.slot == 1)
        return Texel(
          static_cast<int>(std::floor(uv.x * static_cast<float>(w))),
          static_cast<int>(std::floor(uv.y * static_cast<float>(h)))
        );
      const float fx = uv.x * static_cast<float>(w) - 0.5f;
      const float fy = uv.y * static_cast<float>(h) - 0.5f;
      const float ix = std::floor(fx);
      const float iy = std::floor(fy);
      const float tx = fx - ix;
      const float ty = fy - iy;
      const int x0 = static_cast<int>(ix);
      const int y0 = static_cast<int>(iy);
      const float top = Texel(x0, y0) + (Texel(x0 + 1, y0) - Texel(x0, y0)) * tx;
      const float bottom = Texel(x0, y0 + 1) + (Texel(x0 + 1, y0 + 1) - Texel(x0, y0 + 1)) * tx;
      return top + (bottom - top) * ty;
    }
    void GetDimensions(
      uint& ww,
      uint& hh
    ) const
    {
      ww = w;
      hh = h;
    }
    bool Bind(
      const ResView& v,
      std::string& err
    ) override
    {
      if (!v.texture) {
        err = "a buffer is bound where the kernel reads a texture";
        return false;
      }
      p = static_cast<const float*>(v.data);
      w = v.w;
      h = v.h;
      return true;
    }
    void Unbind() override
    {
      p = nullptr;
      w = h = 0;
    }
  };

  struct RWTexture2D : Bindable
  {
    float* p = nullptr;
    uint w = 0;
    uint h = 0;
    float& operator[](
      uint2 c
    )
    {
      if (c.x >= w || c.y >= h) {
        ++gOob;
        static float sink;
        sink = 0.0f;
        return sink;
      }
      return p[static_cast<std::size_t>(c.y) * w + c.x];
    }
    void GetDimensions(
      uint& ww,
      uint& hh
    ) const
    {
      ww = w;
      hh = h;
    }
    bool Bind(
      const ResView& v,
      std::string& err
    ) override
    {
      if (!v.texture) {
        err = "a buffer is bound where the kernel writes a texture";
        return false;
      }
      p = static_cast<float*>(v.data);
      w = v.w;
      h = v.h;
      return true;
    }
    void Unbind() override
    {
      p = nullptr;
      w = h = 0;
    }
  };

  // ---- kernel registration (filled by the macros below while the kernel file is included)
  // ---------------------------------------------------------

  using Entry = void (*)(uint3, uint3, uint3, uint);

  struct KernelEmu
  {
    std::string name;
    int tx = 1, ty = 1, tz = 1;
    Entry entry = nullptr;
    struct Res
    {
      int slot;
      Bindable* obj;
    };
    std::vector<Res> srv;
    std::vector<Res> uav;
    void* cbData = nullptr;
    std::size_t cbSize = 0;
    struct Shared
    {
      void* p;
      std::size_t bytes;
    };
    std::vector<Shared> shared;
  };

  inline std::map<std::string, KernelEmu*>& Kernels()
  {
    static std::map<std::string, KernelEmu*> k;
    return k;
  }

  struct RegRes
  {
    RegRes(
      KernelEmu& k,
      bool isUav,
      int slot,
      Bindable* b
    )
    {
      (isUav ? k.uav : k.srv).push_back({slot, b});
    }
  };
  struct RegCb
  {
    RegCb(
      KernelEmu& k,
      void* p,
      std::size_t size
    )
    {
      k.cbData = p;
      k.cbSize = size;
    }
  };
  struct RegShared
  {
    RegShared(
      KernelEmu& k,
      void* p,
      std::size_t bytes
    )
    {
      k.shared.push_back({p, bytes});
    }
  };
  struct RegThreads
  {
    RegThreads(
      KernelEmu& k,
      int x,
      int y,
      int z
    )
    {
      k.tx = x;
      k.ty = y;
      k.tz = z;
    }
  };
  struct RegEntry
  {
    RegEntry(
      KernelEmu& k,
      const char* name,
      Entry fn
    )
    {
      k.name = name;
      k.entry = fn;
      Kernels()[name] = &k;
    }
  };

  /**
   * Runs kernel `k` for gx * gy * gz groups. srv[slot] / uav[slot] are the bound resources (data == nullptr: unbound);
   * cb / cbBytes the constant buffer contents. false with `err` set when a binding does not fit the kernel (missing
   * slot, element size) or the constant buffer size differs from the kernel's struct.
   */
  inline bool Run(
    KernelEmu& k,
    uint gx,
    uint gy,
    uint gz,
    const void* cb,
    std::size_t cbBytes,
    const ResView* srv,
    const ResView* uav,
    std::string& err
  )
  {
    if (k.entry == nullptr) {
      err = "kernel has no CSMain";
      return false;
    }
    if (k.cbData != nullptr && cbBytes != k.cbSize) {
      err = "constant buffer size differs from the kernel's struct";
      return false;
    }
    for (const auto& r : k.srv) {
      if (srv[r.slot].data == nullptr || !r.obj->Bind(srv[r.slot], err)) {
        if (err.empty())
          err = "SRV slot " + std::to_string(r.slot) + " is not bound";
        return false;
      }
    }
    for (const auto& r : k.uav) {
      if (uav[r.slot].data == nullptr || !r.obj->Bind(uav[r.slot], err)) {
        if (err.empty())
          err = "UAV slot " + std::to_string(r.slot) + " is not bound";
        return false;
      }
    }
    if (k.cbData != nullptr)
      std::memcpy(k.cbData, cb, cbBytes);
    for (uint z = 0; z < gz; ++z) {
      for (uint y = 0; y < gy; ++y) {
        for (uint x = 0; x < gx; ++x) {
          for (const auto& s : k.shared)
            std::memset(s.p, 0xFF, s.bytes); // a NaN pattern: group shared memory starts undefined on a GPU
          gPhase = 0;
          do {
            gMore = false;
            for (uint tz = 0; tz < static_cast<uint>(k.tz); ++tz) {
              for (uint ty = 0; ty < static_cast<uint>(k.ty); ++ty) {
                for (uint tx = 0; tx < static_cast<uint>(k.tx); ++tx) {
                  const uint3 gid(x, y, z);
                  const uint3 gtid(tx, ty, tz);
                  const uint3 dtid(
                    x * static_cast<uint>(k.tx) + tx, y * static_cast<uint>(k.ty) + ty, z * static_cast<uint>(k.tz) + tz
                  );
                  const uint gidx =
                    tx + ty * static_cast<uint>(k.tx) + tz * static_cast<uint>(k.tx) * static_cast<uint>(k.ty);
                  k.entry(dtid, gtid, gid, gidx);
                }
              }
            }
            ++gPhase;
          } while (gMore);
        }
      }
    }
    gPhase = 0;
    for (const auto& r : k.srv)
      r.obj->Unbind();
    for (const auto& r : k.uav)
      r.obj->Unbind();
    return true;
  }
} // namespace emu

// ---- the C++ twins of hlsl_prelude.hlsli
// --------------------------------------------------------------------------------------------------------- The test
// declares the kernel's registration object first:  EMU_KERNEL_BEGIN(kern_name)  #include "<kernel>.hlsl"
// EMU_KERNEL_END(name)

#define EMU_CAT2(a, b) a##b
#define EMU_CAT(a, b) EMU_CAT2(a, b)

#define EMU_KERNEL_BEGIN(NS)                                                                                           \
  namespace NS                                                                                                         \
  {                                                                                                                    \
    static ::emu::KernelEmu emu_kernel;
#define EMU_KERNEL_END(NAME)                                                                                           \
  static ::emu::RegEntry emu_entry_reg(emu_kernel, #NAME, &CSMain);                                                    \
  }

#define CBUFFER(Type, name, slot)                                                                                      \
  static Type name;                                                                                                    \
  static ::emu::RegCb EMU_CAT(emu_cb_, name)(emu_kernel, &name, sizeof(Type));
#define SRV_BUFFER(T, name, slot)                                                                                      \
  static ::emu::StructuredBuffer<T> name;                                                                              \
  static ::emu::RegRes EMU_CAT(emu_srv_, name)(emu_kernel, false, slot, &name);
#define UAV_BUFFER(T, name, slot)                                                                                      \
  static ::emu::RWStructuredBuffer<T> name;                                                                            \
  static ::emu::RegRes EMU_CAT(emu_uav_, name)(emu_kernel, true, slot, &name);
#define SRV_TEX(name, slot)                                                                                            \
  static ::emu::Texture2D name;                                                                                        \
  static ::emu::RegRes EMU_CAT(emu_srv_, name)(emu_kernel, false, slot, &name);
#define UAV_TEX(name, slot)                                                                                            \
  static ::emu::RWTexture2D name;                                                                                      \
  static ::emu::RegRes EMU_CAT(emu_uav_, name)(emu_kernel, true, slot, &name);
#define SAMPLER(name, slot) static ::emu::SamplerState name{slot};
#define GROUPSHARED(T, name, n)                                                                                        \
  static T name[n];                                                                                                    \
  static ::emu::RegShared EMU_CAT(emu_gs_, name)(emu_kernel, name, sizeof(name));
#define NUMTHREADS(x, y, z) static ::emu::RegThreads emu_threads_reg(emu_kernel, x, y, z);
#define KERNEL_IDS                                                                                                     \
  [[maybe_unused]] ::uint3 dtid, [[maybe_unused]] ::uint3 gtid, [[maybe_unused]] ::uint3 gid,                          \
    [[maybe_unused]] ::uint gidx

#define PHASES_BEGIN                                                                                                   \
  constexpr int emu_base_ = __COUNTER__;                                                                               \
  switch (::emu::gPhase) {                                                                                             \
  case 0: {
#define BARRIER(unused)                                                                                                \
  ::emu::gMore = true;                                                                                                 \
  }                                                                                                                    \
  break;                                                                                                               \
  case (__COUNTER__ - emu_base_): {
#define PHASES_END                                                                                                     \
  }                                                                                                                    \
  break;                                                                                                               \
  default:                                                                                                             \
    break;                                                                                                             \
    }

#define UNROLL
#define LOOP
#define OUT(T) T&
#define INOUT(T) T&
#define FN inline
