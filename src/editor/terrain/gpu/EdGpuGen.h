// EDITOR GPU compute: helpers shared by the generator and filter GPU ops (EdGpuGen.cpp, EdGpuGenFilt.cpp). Internal: no
// other file includes it. See docs/projects/editor/GPU_COMPUTE.md
// ("Generator and filter kernels").
#pragma once
#pragma fp_contract(off)

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <vector>

#include "editor/terrain/EdFieldCore.h"
#include "editor/terrain/gpu/EdGpu.h"
#include "editor/terrain/gpu/EdGpuOps.h"

namespace faf::editor::gpu::gen
{
  using field::Grid;
  using field::OpArgs;

  /** Shape of an op's output, read like MakeOut of the CPU ops (`like`, else `a`, else width / height / cell / ox /
   * oz). */
  struct Shape
  {
    int w = 0;
    int h = 0;
    float cell = 1.0f;
    float ox = 0.0f;
    float oz = 0.0f;
    [[nodiscard]] std::uint64_t Count() const
    {
      return static_cast<std::uint64_t>(w) * static_cast<std::uint64_t>(h);
    }
  };

  inline const Grid* In(
    const OpArgs& a,
    const char* const key
  )
  {
    const auto it = a.in.find(key);
    return it != a.in.end() ? it->second.get() : nullptr;
  }

  /** false when the CPU op would refuse (it then reports the error itself): the GPU op answers Unsupported. */
  inline bool ShapeOf(
    const OpArgs& a,
    Shape& s
  )
  {
    const Grid* ref = In(a, "like");
    if (ref == nullptr)
      ref = In(a, "a");
    if (const Grid* const inA = In(a, "a"); inA != nullptr && ref != nullptr && (inA->w != ref->w || inA->h != ref->h))
      return false;
    if (ref != nullptr) {
      s.w = ref->w;
      s.h = ref->h;
      s.cell = ref->cell;
      s.ox = ref->ox;
      s.oz = ref->oz;
      return s.w >= 1 && s.h >= 1;
    }
    const int w = static_cast<int>(a.p.N("width", 0));
    const int h = static_cast<int>(a.p.N("height", 0));
    if (w < 1 || h < 1 || static_cast<long long>(w) * h > (1LL << 24))
      return false;
    s.w = w;
    s.h = h;
    s.cell = static_cast<float>(a.p.N("cell", 1.0));
    s.ox = static_cast<float>(a.p.N("ox", 0.0));
    s.oz = static_cast<float>(a.p.N("oz", 0.0));
    return true;
  }

  template <class T>
  [[nodiscard]] std::expected<void, std::string> UploadVec(
    Executor& ex,
    const std::vector<T>& v,
    std::unique_ptr<Resource>& out
  )
  {
    static_assert(sizeof(T) == 4, "tables hold 4 byte elements");
    const std::vector<T>* src = &v;
    std::vector<T> one;
    if (v.empty()) {
      one.assign(1, T());
      src = &one;
    }
    FAF_GPU_TRY(MakeBuffer(ex, static_cast<u32>(src->size()), out));
    return UploadBuffer(ex, *out, src->data(), src->size() * sizeof(T));
  }

  /** The optional `mask` input as a field (or a one element dummy: every slot a kernel declares must be bound). */
  struct MaskBind
  {
    Field field;
    std::unique_ptr<Resource> dummy;
    bool has = false;
    [[nodiscard]] const Resource& R() const
    {
      return has ? field.R() : *dummy;
    }
  };

  [[nodiscard]] inline std::expected<void, std::string> BindMask(
    Executor& ex,
    const OpArgs& a,
    MaskBind& m
  )
  {
    if (const Grid* g = In(a, "mask"); g != nullptr) {
      m.has = true;
      return UploadGrid(ex, *g, m.field);
    }
    const float zero = 0.0f;
    FAF_GPU_TRY(MakeBuffer(ex, 1, m.dummy));
    return UploadBuffer(ex, *m.dummy, &zero, 4);
  }

  /** One dispatch of `unitsPerCell` * cells "octave evaluations" at most this big (a few ms on a discrete card, well
   * below the 2 second driver reset on a weak one). */
  inline constexpr double kBandUnits = 2.5e7;

  /**
   * Dispatches kernel `k` over w x h samples in row bands. `params` must have the members w, z0 and rows (the kernel
   * reads row = dtid.y + z0 and returns when dtid.y >= rows). `unitsPerCell` = cost of one sample in octave
   * evaluations. A big field becomes several bands in time limited submissions (RunIterations).
   */
  template <class P>
  [[nodiscard]] std::expected<void, std::string> DispatchBands(
    Executor& ex,
    const KernelInfo& k,
    const u32 w,
    const u32 h,
    const double unitsPerCell,
    P params,
    const Bindings& b
  )
  {
    const double perRow = std::max(1.0, static_cast<double>(w) * std::max(1.0, unitsPerCell));
    const u32 rowsPer =
      static_cast<u32>(std::max(1.0, std::min(static_cast<double>(h), std::floor(kBandUnits / perRow))));
    const u32 bands = (h + rowsPer - 1) / rowsPer;
    if (bands <= 1) {
      params.z0 = 0;
      params.rows = h;
      return DispatchGrid(ex, k, w, h, params, b);
    }
    return RunIterations(ex, bands, 60.0, [&](const u32 i) {
      P p = params;
      p.z0 = i * rowsPer;
      p.rows = std::min(rowsPer, h - p.z0);
      return DispatchGrid(ex, k, w, p.rows, p, b);
    });
  }

  /** Writes the affine map (see gen_noise.hlsli) of one octave into float table `tab` at record `o` (16 floats). false
   * when the integer part does not fit exactly in a float. */
  inline bool PutMap(
    std::vector<float>& tab,
    const int o,
    const double u0,
    const double v0,
    const double a,
    const double b,
    const double c,
    const double d
  )
  {
    if (!(std::fabs(u0) < 4.0e6 && std::fabs(v0) < 4.0e6))
      return false;
    const double iu = std::floor(u0);
    const double iv = std::floor(v0);
    float* r = tab.data() + static_cast<std::size_t>(o) * 16u;
    r[0] = static_cast<float>(iu);
    r[1] = static_cast<float>(iv);
    r[2] = static_cast<float>(u0 - iu);
    r[3] = static_cast<float>(v0 - iv);
    r[4] = static_cast<float>(a);
    r[5] = static_cast<float>(b);
    r[6] = static_cast<float>(c);
    r[7] = static_cast<float>(d);
    return true;
  }

  /** The map of an octave at `freq` lattice units per world unit for a field starting at world (wox, woz) with `cell`
   * spacing; (c, s) = turn of the octave's frame, (fox, foz) = its shift. */
  inline bool PutOctaveMap(
    std::vector<float>& tab,
    const int o,
    const double wox,
    const double woz,
    const double cell,
    const double freq,
    const double c,
    const double s,
    const double fox,
    const double foz
  )
  {
    const double px = wox * freq, pz = woz * freq, st = cell * freq;
    return PutMap(tab, o, c * px - s * pz + fox, s * px + c * pz + foz, c * st, -s * st, s * st, c * st);
  }

  /** The same map skewed for simplex noise: lattice (u, v) -> (u + (u + v) F2, v + (u + v) F2). */
  inline bool PutSimplexMap(
    std::vector<float>& tab,
    const int o,
    const double wox,
    const double woz,
    const double cell,
    const double freq,
    const double c,
    const double s,
    const double fox,
    const double foz
  )
  {
    constexpr double F2 = 0.36602540378443865;
    const double px = wox * freq, pz = woz * freq, st = cell * freq;
    const double u0 = c * px - s * pz + fox, v0 = s * px + c * pz + foz;
    const double a = c * st, b = -s * st, cc = s * st, d = c * st;
    return PutMap(
      tab,
      o,
      u0 + (u0 + v0) * F2,
      v0 + (u0 + v0) * F2,
      a + (a + cc) * F2,
      b + (b + d) * F2,
      cc + (a + cc) * F2,
      d + (b + d) * F2
    );
  }

  /** A fresh output grid of the op's shape. */
  inline Grid NewGrid(
    const Shape& s
  )
  {
    return Grid(s.w, s.h, s.cell, s.ox, s.oz);
  }

  /** True when the buffers the op needs fit the executor (an op holds at most MaxBytes). */
  inline bool Fits(
    Executor& ex,
    const std::uint64_t fieldCount,
    const int fields
  )
  {
    return fieldCount * 4ull * static_cast<std::uint64_t>(fields) <= ex.MaxBytes();
  }

  /** The common tail of a generator op: output field as UAV 0, banded dispatch of kernel `kernel`, download into a
   * local grid (`out` is only written on success). */
  template <class P>
  [[nodiscard]] std::expected<OpResult, std::string> RunGenerator(
    Executor& ex,
    const char* const kernel,
    const Shape& s,
    const double unitsPerCell,
    const P& params,
    Bindings b,
    Grid& out
  )
  {
    const KernelInfo* k = FindKernel(kernel);
    if (k == nullptr) {
      return std::unexpected(std::string("kernel ") + kernel + " is missing");
    }
    Field res;
    FAF_GPU_TRY(MakeField(ex, s.w, s.h, res));
    b.Uav(0, res.R());
    FAF_GPU_TRY(DispatchBands(ex, *k, static_cast<u32>(s.w), static_cast<u32>(s.h), unitsPerCell, params, b));
    Grid result = NewGrid(s);
    FAF_GPU_TRY(DownloadGrid(ex, res, result));
    out = std::move(result);
    return OpResult::Done;
  }

} // namespace faf::editor::gpu::gen
