// EDITOR GPU compute: GPU versions of more filter ops of the field engine (EdFieldFilt.cpp, EdFieldSc.cpp): morph,
// convolve, unsharp, edge, blur_slope, slope_limit ... Each op reads its options exactly like the CPU op and answers
// Unsupported for what it does not handle (the CPU op then runs and reports bad input itself). Ops whose cost per
// sample is small go to the GPU only when the window is big enough to pay for the transfer (fops::WorthIt).
// docs/projects/editor/GPU_COMPUTE.md, "More field ops (GP4)".
#pragma fp_contract(off)

#include "editor/terrain/EdFieldUtil.h"
#include "editor/terrain/gpu/EdGpuFieldCommon.h"

namespace faf::editor::gpu::hk
{
  using uint = std::uint32_t;
#include "editor/terrain/gpu/field_blurslope_params.hlsli"
#include "editor/terrain/gpu/field_convolve_params.hlsli"
#include "editor/terrain/gpu/field_edge_params.hlsli"
#include "editor/terrain/gpu/field_morph_params.hlsli"
#include "editor/terrain/gpu/field_slopelimit_params.hlsli"
#include "editor/terrain/gpu/field_slopescan_params.hlsli"
#include "editor/terrain/gpu/field_rockiness_params.hlsli"
#include "editor/terrain/gpu/field_stratify_params.hlsli"
#include "editor/terrain/gpu/field_sub_params.hlsli"
#include "editor/terrain/gpu/field_unsharp_params.hlsli"
} // namespace faf::editor::gpu::hk

namespace faf::editor::gpu
{
  using namespace fops;

  namespace
  {
    /** Window size in samples from world units (EdFieldFilt.cpp SamplesOf). */
    inline int SamplesOf(
      const double units,
      const Grid& g,
      const int lo,
      const int hi
    )
    {
      return std::max(lo, std::min(hi, static_cast<int>(std::lround(units / static_cast<double>(g.cell)))));
    }

    // ---- morph
    // --------------------------------------------------------------------------------------------------------------------------------------

    struct MorphJob
    {
      Executor* ex = nullptr;
      const KernelInfo* km = nullptr;
      int w = 0, h = 0, r = 0, shape = 0; // shape as the CPU op: 0 square, 1 disc, 2 cross, 3 diamond
      double unitsPerCell = 1.0;

      /** One dilation (isMax) or erosion of `in` into `out`; the square element takes `tmp` as the in-between field
       * (two separable passes). */
      std::expected<void, std::string> Pass(
        const Resource& in,
        Resource& out,
        Resource& tmp,
        const bool isMax
      )
      {
        hk::MorphParams p{};
        p.w = static_cast<std::uint32_t>(w);
        p.h = static_cast<std::uint32_t>(h);
        p.rad = static_cast<std::uint32_t>(r);
        p.isMax = isMax ? 1u : 0u;
        if (shape == 0) {
          p.shape = 0;
          Bindings b0;
          b0.Srv(0, in).Uav(0, tmp);
          FAF_GPU_TRY(DispatchBands(*ex, *km, p.w, p.h, unitsPerCell, p, b0));
          p.shape = 1;
          Bindings b1;
          b1.Srv(0, tmp).Uav(0, out);
          return DispatchBands(*ex, *km, p.w, p.h, unitsPerCell, p, b1);
        }
        p.shape = shape == 1 ? 2u : (shape == 2 ? 4u : 3u);
        Bindings b;
        b.Srv(0, in).Uav(0, out);
        return DispatchBands(*ex, *km, p.w, p.h, unitsPerCell, p, b);
      }
    };

    std::expected<OpResult, std::string> OpMorphGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      const Grid* src = SourceStrict(a);
      if (src == nullptr)
        return OpResult::Unsupported;
      const std::string op = a.p.S("op", "dilate");
      static const char* const ops[] = {"dilate", "erode", "open", "close", "gradient", "tophat", "bothat"};
      int k = -1;
      for (int i = 0; i < 7; ++i) {
        if (op == ops[i])
          k = i;
      }
      const std::string sh = a.p.S("shape", "square");
      const int shape = sh == "square" ? 0 : (sh == "disc" ? 1 : (sh == "cross" ? 2 : (sh == "diamond" ? 3 : -1)));
      if (k < 0 || shape < 0)
        return OpResult::Unsupported; // the CPU op reports the bad name
      const int r = SamplesOf(a.p.N("radius", 4.0), *src, 1, shape == 0 ? 32 : 16);
      // taps of one dilation / erosion: two windows for the square, the candidate positions of the window otherwise
      const double tapsPerPass = shape == 0
        ? 2.0 * (2.0 * r + 1.0)
        : (shape == 2 ? 2.0 * (2.0 * r + 1.0)
                      : (shape == 3 ? (r + 1.0) * (r + 1.0) * 2.0 : (2.0 * r + 1.0) * (2.0 * r + 1.0)));
      const int passes = k < 2 ? 1 : 2;
      if (!WorthIt(a, tapsPerPass * passes))
        return OpResult::Unsupported;
      if (!Fits(ex, src->Count(), 5))
        return OpResult::Unsupported;
      MorphJob job;
      job.ex = &ex;
      job.km = FindKernel("field_morph");
      const KernelInfo* ks = FindKernel("field_sub");
      if (job.km == nullptr || ks == nullptr) {
        return std::unexpected("kernel field_morph / field_sub is missing");
      }
      job.w = src->w;
      job.h = src->h;
      job.r = r;
      job.shape = shape;
      job.unitsPerCell = tapsPerPass * 0.06;
      Field in, t1, t2, tmp, res;
      FAF_GPU_TRY(UploadGrid(ex, *src, in));
      FAF_GPU_TRY(MakeField(ex, job.w, job.h, t1));
      FAF_GPU_TRY(MakeField(ex, job.w, job.h, t2));
      FAF_GPU_TRY(MakeField(ex, job.w, job.h, tmp));
      FAF_GPU_TRY(MakeField(ex, job.w, job.h, res));
      Field* result = &t1;
      switch (k) {
      case 0:
        FAF_GPU_TRY(job.Pass(in.R(), t1.R(), tmp.R(), true));
        break;
      case 1:
        FAF_GPU_TRY(job.Pass(in.R(), t1.R(), tmp.R(), false));
        break;
      case 2:
        FAF_GPU_TRY(job.Pass(in.R(), t2.R(), tmp.R(), false));
        FAF_GPU_TRY(job.Pass(t2.R(), t1.R(), tmp.R(), true));
        break;
      case 3:
        FAF_GPU_TRY(job.Pass(in.R(), t2.R(), tmp.R(), true));
        FAF_GPU_TRY(job.Pass(t2.R(), t1.R(), tmp.R(), false));
        break;
      default: {
        // gradient = dilate(a) - erode(a); tophat = a - open(a); bothat = close(a) - a
        const Resource* x = nullptr;
        const Resource* y = nullptr;
        if (k == 4) {
          FAF_GPU_TRY(job.Pass(in.R(), t1.R(), tmp.R(), true));
          FAF_GPU_TRY(job.Pass(in.R(), t2.R(), tmp.R(), false));
          x = &t1.R();
          y = &t2.R();
        } else if (k == 5) {
          FAF_GPU_TRY(job.Pass(in.R(), t1.R(), tmp.R(), false));
          FAF_GPU_TRY(job.Pass(t1.R(), t2.R(), tmp.R(), true));
          x = &in.R();
          y = &t2.R();
        } else {
          FAF_GPU_TRY(job.Pass(in.R(), t1.R(), tmp.R(), true));
          FAF_GPU_TRY(job.Pass(t1.R(), t2.R(), tmp.R(), false));
          x = &t2.R();
          y = &in.R();
        }
        hk::SubParams sp{};
        sp.w = static_cast<std::uint32_t>(job.w);
        sp.h = static_cast<std::uint32_t>(job.h);
        Bindings b;
        b.Srv(0, *x).Srv(1, *y).Uav(0, res.R());
        FAF_GPU_TRY(DispatchGrid(ex, *ks, sp.w, sp.h, sp, b));
        result = &res;
        break;
      }
      }
      Grid g = LikeOf(*src);
      FAF_GPU_TRY(DownloadGrid(ex, *result, g));
      out = std::move(g);
      return OpResult::Done;
    }

    // ---- convolve
    // -----------------------------------------------------------------------------------------------------------------------------------

    std::expected<OpResult, std::string> OpConvolveGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      const Grid* src = Source(a);
      const std::vector<double>* kv = a.p.A("kernel");
      Shape shape;
      if (src == nullptr || kv == nullptr || kv->empty() || !ShapeOf(a, shape))
        return OpResult::Unsupported;
      const int n = static_cast<int>(std::lround(std::sqrt(static_cast<double>(kv->size()))));
      if (n * n != static_cast<int>(kv->size()) || n % 2 == 0 || n > 15)
        return OpResult::Unsupported; // the CPU op reports the bad kernel
      if (!WorthIt(a, static_cast<double>(n) * n) || !Fits(ex, src->Count(), 2))
        return OpResult::Unsupported;
      std::vector<float> k(kv->size());
      double sum = 0.0;
      for (std::size_t i = 0; i < k.size(); ++i) {
        k[i] = static_cast<float>((*kv)[i]);
        sum += static_cast<double>(k[i]);
      }
      float mul = static_cast<float>(a.p.N("scale", 1.0));
      if (a.p.N("normalize", 1) != 0 && std::fabs(sum) > 1e-6)
        mul /= static_cast<float>(sum);
      hk::ConvolveParams p{};
      p.w = static_cast<std::uint32_t>(src->w);
      p.h = static_cast<std::uint32_t>(src->h);
      p.n = static_cast<std::uint32_t>(n);
      p.edge = static_cast<std::uint32_t>(field::t7::ParseEdge(a, field::t7::kClamp));
      p.mul = mul;
      p.bias = static_cast<float>(a.p.N("bias", 0.0));
      const KernelInfo* kc = FindKernel("field_convolve");
      if (kc == nullptr) {
        return std::unexpected("kernel field_convolve is missing");
      }
      Field in, res;
      std::unique_ptr<Resource> kbuf;
      FAF_GPU_TRY(UploadGrid(ex, *src, in));
      FAF_GPU_TRY(MakeField(ex, src->w, src->h, res));
      FAF_GPU_TRY(UploadVec(ex, k, kbuf));
      Bindings b;
      b.Srv(0, in.R()).Srv(1, *kbuf).Uav(0, res.R());
      FAF_GPU_TRY(DispatchBands(ex, *kc, p.w, p.h, static_cast<double>(n) * n * 0.05, p, b));
      Grid g = NewGrid(shape); // placed like the CPU op places it (`like`, else `a`)
      FAF_GPU_TRY(DownloadGrid(ex, res, g));
      out = std::move(g);
      return OpResult::Done;
    }

    // ---- unsharp, edge, blur_slope (a gaussian blur on the device and a point pass)
    // ---------------------------------------------------------------------------

    /** Source, mask and output shape of the blur based ops: false = Unsupported (a mask of another size, a bad `like`:
     * the CPU op reports it). */
    bool BlurOpInputs(
      const OpArgs& a,
      const Grid*& src,
      Shape& shape
    )
    {
      src = Source(a);
      const Grid* mask = In(a, "mask");
      return src != nullptr && (mask == nullptr || mask->SameShape(*src)) && ShapeOf(a, shape);
    }

    std::expected<OpResult, std::string> OpUnsharpGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      const Grid* src = nullptr;
      Shape shape;
      if (!BlurOpInputs(a, src, shape))
        return OpResult::Unsupported;
      const double sigma = std::max(0.3, a.p.N("radius", 4.0) / static_cast<double>(src->cell));
      if (!WorthIt(a, BlurTaps(sigma) + 4.0) || !BlurAffordable(src->w, src->h, sigma) || !Fits(ex, src->Count(), 5))
        return OpResult::Unsupported;
      const KernelInfo* ku = FindKernel("field_unsharp");
      if (ku == nullptr) {
        return std::unexpected("kernel field_unsharp is missing");
      }
      hk::UnsharpParams p{};
      p.w = static_cast<std::uint32_t>(src->w);
      p.h = static_cast<std::uint32_t>(src->h);
      p.amount = static_cast<float>(a.p.N("amount", 1.0));
      p.thr = std::max(0.0f, static_cast<float>(a.p.N("threshold", 0.0)));
      Field in, tmp, blur, res;
      MaskBind mb;
      FAF_GPU_TRY(UploadGrid(ex, *src, in));
      FAF_GPU_TRY(MakeField(ex, src->w, src->h, tmp));
      FAF_GPU_TRY(MakeField(ex, src->w, src->h, blur));
      FAF_GPU_TRY(MakeField(ex, src->w, src->h, res));
      FAF_GPU_TRY(BindMask(ex, a, mb));
      FAF_GPU_TRY(BlurDevice(ex, in.R(), tmp.R(), blur.R(), src->w, src->h, sigma));
      p.hasMask = mb.has ? 1u : 0u;
      Bindings b;
      b.Srv(0, in.R()).Srv(1, blur.R()).Srv(2, mb.R()).Uav(0, res.R());
      FAF_GPU_TRY(DispatchGrid(ex, *ku, p.w, p.h, p, b));
      Grid g = NewGrid(shape);
      FAF_GPU_TRY(DownloadGrid(ex, res, g));
      out = std::move(g);
      return OpResult::Done;
    }

    std::expected<OpResult, std::string> OpEdgeGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      const Grid* src0 = Source(a);
      Shape shape;
      if (src0 == nullptr || !ShapeOf(a, shape))
        return OpResult::Unsupported;
      const std::string mode = a.p.S("mode", "sobel");
      const int m = mode == "sobel" ? 0 : (mode == "prewitt" ? 1 : (mode == "laplace" ? 2 : (mode == "dog" ? 3 : -1)));
      if (m < 0)
        return OpResult::Unsupported; // the CPU op reports the bad mode
      const double pre = a.p.N("smooth", 0.0) / static_cast<double>(src0->cell);
      const bool smoothFirst = pre > 0.05;
      double s1 = 0.0, s2 = 0.0;
      double work = 8.0;
      if (m == 3) {
        s1 = std::max(0.3, a.p.N("radius", 2.0) / static_cast<double>(src0->cell));
        s2 = s1 * std::max(1.1, a.p.N("ratio", 1.6));
        work = BlurTaps(s1) + BlurTaps(s2);
      }
      if (smoothFirst)
        work += BlurTaps(pre);
      const bool blurs = m == 3 || smoothFirst;
      if (blurs ? !WorthIt(a, work) : !BigField(a))
        return OpResult::Unsupported; // a bare 3 x 3 stencil only pays on big fields
      if (
        (smoothFirst && !BlurAffordable(src0->w, src0->h, pre)) ||
        (m == 3 && (!BlurAffordable(src0->w, src0->h, s1) || !BlurAffordable(src0->w, src0->h, s2)))
      )
        return OpResult::Unsupported;
      if (!Fits(ex, src0->Count(), 5))
        return OpResult::Unsupported;
      const KernelInfo* ke = FindKernel("field_edge");
      if (ke == nullptr) {
        return std::unexpected("kernel field_edge is missing");
      }
      hk::EdgeParams p{};
      p.w = static_cast<std::uint32_t>(src0->w);
      p.h = static_cast<std::uint32_t>(src0->h);
      p.mode = static_cast<std::uint32_t>(m);
      p.gain = static_cast<float>(a.p.N("gain", 1.0));
      p.sgn = a.p.N("signed", 0) != 0 ? 1u : 0u;
      const float cell = src0->cell;
      p.wc = m == 0 ? 2.0f : 1.0f;
      p.denom = (2.0f + p.wc) * 2.0f * cell;
      p.cell2 = cell * cell;
      Field in, tmp, sm, b1, b2, res;
      FAF_GPU_TRY(UploadGrid(ex, *src0, in));
      FAF_GPU_TRY(MakeField(ex, p.w, p.h, res));
      const Field* base = &in; // the (smoothed) field the edge is taken from
      if (smoothFirst || m == 3) {
        FAF_GPU_TRY(MakeField(ex, p.w, p.h, tmp));
      }
      if (smoothFirst) {
        FAF_GPU_TRY(MakeField(ex, p.w, p.h, sm));
        FAF_GPU_TRY(BlurDevice(ex, in.R(), tmp.R(), sm.R(), src0->w, src0->h, pre));
        base = &sm;
      }
      Bindings b;
      if (m == 3) {
        FAF_GPU_TRY(MakeField(ex, p.w, p.h, b1));
        FAF_GPU_TRY(MakeField(ex, p.w, p.h, b2));
        FAF_GPU_TRY(BlurDevice(ex, base->R(), tmp.R(), b1.R(), src0->w, src0->h, s1));
        FAF_GPU_TRY(BlurDevice(ex, base->R(), tmp.R(), b2.R(), src0->w, src0->h, s2));
        b.Srv(0, b1.R()).Srv(1, b2.R()).Uav(0, res.R());
      } else {
        b.Srv(0, base->R()).Srv(1, base->R()).Uav(0, res.R());
      }
      FAF_GPU_TRY(DispatchBands(ex, *ke, p.w, p.h, 0.03, p, b));
      Grid g = NewGrid(shape);
      FAF_GPU_TRY(DownloadGrid(ex, res, g));
      out = std::move(g);
      return OpResult::Done;
    }

    std::expected<OpResult, std::string> OpBlurSlopeGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      const Grid* src = nullptr;
      Shape shape;
      if (!BlurOpInputs(a, src, shape))
        return OpResult::Unsupported;
      const std::string mode = a.p.S("mode", "flat");
      if (mode != "flat" && mode != "steep")
        return OpResult::Unsupported;
      const double sigma = std::max(0.3, a.p.N("radius", 6.0) / static_cast<double>(src->cell));
      if (!WorthIt(a, BlurTaps(sigma) + 6.0) || !BlurAffordable(src->w, src->h, sigma) || !Fits(ex, src->Count(), 5))
        return OpResult::Unsupported;
      const KernelInfo* kb = FindKernel("field_blurslope");
      if (kb == nullptr) {
        return std::unexpected("kernel field_blurslope is missing");
      }
      hk::BlurSlopeParams p{};
      p.w = static_cast<std::uint32_t>(src->w);
      p.h = static_cast<std::uint32_t>(src->h);
      p.flat = mode == "flat" ? 1u : 0u;
      p.cell = src->cell;
      p.lo = static_cast<float>(a.p.N("lo", 0.3));
      p.hi = static_cast<float>(a.p.N("hi", 0.7));
      p.amount = Clamp01(static_cast<float>(a.p.N("amount", 1.0)));
      Field in, tmp, blur, res;
      MaskBind mb;
      FAF_GPU_TRY(UploadGrid(ex, *src, in));
      FAF_GPU_TRY(MakeField(ex, src->w, src->h, tmp));
      FAF_GPU_TRY(MakeField(ex, src->w, src->h, blur));
      FAF_GPU_TRY(MakeField(ex, src->w, src->h, res));
      FAF_GPU_TRY(BindMask(ex, a, mb));
      FAF_GPU_TRY(BlurDevice(ex, in.R(), tmp.R(), blur.R(), src->w, src->h, sigma));
      p.hasMask = mb.has ? 1u : 0u;
      Bindings b;
      b.Srv(0, in.R()).Srv(1, blur.R()).Srv(2, mb.R()).Uav(0, res.R());
      FAF_GPU_TRY(DispatchGrid(ex, *kb, p.w, p.h, p, b));
      Grid g = NewGrid(shape);
      FAF_GPU_TRY(DownloadGrid(ex, res, g));
      out = std::move(g);
      return OpResult::Done;
    }

    // ---- rockiness
    // ----------------------------------------------------------------------------------------------------------------------------------

    std::expected<OpResult, std::string> OpRockinessGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      const Grid* src = Source(a);
      const Grid* soil = In(a, "b");
      Shape shape;
      if (src == nullptr || (soil != nullptr && !soil->SameShape(*src)) || !ShapeOf(a, shape))
        return OpResult::Unsupported;
      const float breakup = static_cast<float>(a.p.N("breakup", 0.15));
      // with the breakup noise (3 octaves) the maths pays for the transfer; without it this is a 3 x 3 gradient and
      // four taps: only big fields
      if (breakup != 0.0f ? !WorthIt(a, 100.0) : !BigField(a))
        return OpResult::Unsupported;
      if (!Fits(ex, src->Count(), 4))
        return OpResult::Unsupported;
      const KernelInfo* kr = FindKernel("field_rockiness");
      if (kr == nullptr) {
        return std::unexpected("kernel field_rockiness is missing");
      }
      hk::RockinessParams p{};
      p.w = static_cast<std::uint32_t>(src->w);
      p.h = static_cast<std::uint32_t>(src->h);
      const int n = std::max(1, std::min(16, static_cast<int>(std::lround(a.p.N("radius", 6.0) / src->cell))));
      p.n = static_cast<std::uint32_t>(n);
      p.hasSoil = soil != nullptr ? 1u : 0u;
      p.seed = static_cast<std::uint32_t>(static_cast<std::int64_t>(a.p.N("seed", 1)));
      p.noiseOn = breakup != 0.0f ? 1u : 0u;
      p.cell = src->cell;
      p.d2 = static_cast<float>(n) * static_cast<float>(n) * src->cell * src->cell;
      p.slopeLo = static_cast<float>(a.p.N("slope_lo", 25.0));
      p.slopeHi = static_cast<float>(a.p.N("slope_hi", 50.0));
      p.gain = static_cast<float>(a.p.N("gain", 14.0));
      p.soilFull = std::max(1e-3f, static_cast<float>(a.p.N("soil_full", 1.5)));
      p.wSlope = std::max(0.0f, static_cast<float>(a.p.N("w_slope", 1.0)));
      p.wConvex = std::max(0.0f, static_cast<float>(a.p.N("w_convex", 0.5)));
      p.wSoil = soil != nullptr ? std::max(0.0f, static_cast<float>(a.p.N("w_soil", 1.0))) : 0.0f;
      p.norm = std::max(1e-6f, p.wSlope + p.wConvex + p.wSoil);
      p.breakup = breakup;
      p.degK = 180.0f / 3.14159265358979f;
      // the Fbm01 of the breakup: world position / 14 units as an affine map of the sample index (computed in double)
      std::vector<float> oct(16u, 0.0f);
      const double inv = 1.0 / 14.0, step = static_cast<double>(src->cell) * inv;
      if (!PutMap(oct, 0, static_cast<double>(src->ox) * inv, static_cast<double>(src->oz) * inv, step, 0.0, 0.0, step))
        return OpResult::Unsupported;
      Field in, sf, res;
      std::unique_ptr<Resource> octBuf, dummy;
      const float zero = 0.0f;
      FAF_GPU_TRY(UploadGrid(ex, *src, in));
      FAF_GPU_TRY(MakeField(ex, p.w, p.h, res));
      FAF_GPU_TRY(UploadVec(ex, oct, octBuf));
      FAF_GPU_TRY(MakeBuffer(ex, 1, dummy));
      FAF_GPU_TRY(UploadBuffer(ex, *dummy, &zero, 4));
      if (soil != nullptr) {
        FAF_GPU_TRY(UploadGrid(ex, *soil, sf));
      }
      Bindings b;
      b.Srv(0, in.R()).Srv(1, soil != nullptr ? sf.R() : *dummy).Srv(2, *octBuf).Uav(0, res.R());
      FAF_GPU_TRY(DispatchBands(ex, *kr, p.w, p.h, breakup != 0.0f ? 3.0 : 0.15, p, b));
      Grid g = NewGrid(shape);
      FAF_GPU_TRY(DownloadGrid(ex, res, g));
      out = std::move(g);
      return OpResult::Done;
    }

    // ---- stratify
    // -----------------------------------------------------------------------------------------------------------------------------------

    std::expected<OpResult, std::string> OpStratifyGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      const Grid* src = Source(a);
      const Grid* mask = In(a, "mask");
      Shape shape;
      if (src == nullptr || (mask != nullptr && !mask->SameShape(*src)) || !ShapeOf(a, shape))
        return OpResult::Unsupported;
      const double warp = a.p.N("warp", 0.0);
      // the layer lookup is a 13 step search; with the warp noise on top the maths pays for the transfer, without it
      // only big fields do
      if (warp != 0.0 ? !WorthIt(a, 100.0) : !BigField(a))
        return OpResult::Unsupported;
      if (!Fits(ex, src->Count(), 4))
        return OpResult::Unsupported;
      const KernelInfo* ks = FindKernel("field_stratify");
      if (ks == nullptr) {
        return std::unexpected("kernel field_stratify is missing");
      }
      const std::uint32_t seed = static_cast<std::uint32_t>(static_cast<std::int64_t>(a.p.N("seed", 1)));
      const float thick = std::max(0.2f, static_cast<float>(a.p.N("thickness", 3.0)));
      const float variation = Clamp01(static_cast<float>(a.p.N("variation", 0.5)));
      const double warpSize = std::max(2.0, a.p.N("warp_size", 120.0));
      const float sharp = Clamp01(static_cast<float>(a.p.N("sharpness", 0.7)));
      // the table of layer boundaries and hardness values, formed exactly like the CPU op forms it
      constexpr int K = 2048;
      std::vector<float> tab(static_cast<std::size_t>(2 * K + 1 + 2 * K), 0.0f);
      for (int k = 0; k < K; ++k) {
        const float t = thick * (1.0f + variation * (2.0f * field::t7::Unit(field::t7::Hash2(k, 0, seed)) - 1.0f));
        tab[static_cast<std::size_t>(K + k + 1)] = tab[static_cast<std::size_t>(K + k)] + t;
      }
      for (int k = -1; k >= -K; --k) {
        const float t = thick * (1.0f + variation * (2.0f * field::t7::Unit(field::t7::Hash2(k, 0, seed)) - 1.0f));
        tab[static_cast<std::size_t>(K + k)] = tab[static_cast<std::size_t>(K + k + 1)] - t;
      }
      for (int i = 0; i < 2 * K; ++i)
        tab[static_cast<std::size_t>(2 * K + 1 + i)] = 0.25f + 0.5f * field::t7::Unit(field::t7::Hash2(i - K, 1, seed));
      hk::StratifyParams p{};
      p.w = static_cast<std::uint32_t>(src->w);
      p.h = static_cast<std::uint32_t>(src->h);
      p.seed = seed + 911U;
      p.warpOn = warp != 0.0 ? 1u : 0u;
      const float sLo = static_cast<float>(a.p.N("slope_lo", 0.0)), sHi = static_cast<float>(a.p.N("slope_hi", 0.0));
      p.slopeOn = sHi > sLo ? 1u : 0u;
      p.cell = src->cell;
      p.ox = src->ox;
      p.oz = src->oz;
      p.tiltX = static_cast<float>(a.p.N("tilt_x", 0.0));
      p.tiltZ = static_cast<float>(a.p.N("tilt_z", 0.0));
      p.warp = static_cast<float>(warp);
      p.wdt = 0.5f * (1.0f - sharp) + 0.02f;
      p.strength = Clamp01(static_cast<float>(a.p.N("strength", 1.0)));
      p.slopeLo = sLo;
      p.slopeHi = sHi;
      std::vector<float> oct(16u, 0.0f);
      const double inv = 1.0 / warpSize, step = static_cast<double>(src->cell) * inv;
      if (!PutMap(oct, 0, static_cast<double>(src->ox) * inv, static_cast<double>(src->oz) * inv, step, 0.0, 0.0, step))
        return OpResult::Unsupported;
      Field in, res;
      std::unique_ptr<Resource> tabBuf, octBuf;
      MaskBind mb;
      FAF_GPU_TRY(UploadGrid(ex, *src, in));
      FAF_GPU_TRY(MakeField(ex, p.w, p.h, res));
      FAF_GPU_TRY(UploadVec(ex, tab, tabBuf));
      FAF_GPU_TRY(UploadVec(ex, oct, octBuf));
      FAF_GPU_TRY(BindMask(ex, a, mb));
      p.hasMask = mb.has ? 1u : 0u;
      Bindings b;
      b.Srv(0, in.R()).Srv(1, mb.R()).Srv(2, *tabBuf).Srv(3, *octBuf).Uav(0, res.R());
      FAF_GPU_TRY(DispatchBands(ex, *ks, p.w, p.h, warp != 0.0 ? 3.5 : 0.8, p, b));
      Grid g = NewGrid(shape);
      FAF_GPU_TRY(DownloadGrid(ex, res, g));
      out = std::move(g);
      return OpResult::Done;
    }

    // ---- slope_limit
    // --------------------------------------------------------------------------------------------------------------------------------

    std::expected<OpResult, std::string> OpSlopeLimitGpu(
      Executor& ex,
      const OpArgs& a,
      Grid& out
    )
    {
      const Grid* src = In(a, "a"); // (the CPU op ignores `like`: the result is the input with its placement)
      if (src == nullptr || src->w < 1 || src->h < 1)
        return OpResult::Unsupported;
      const std::string mode = a.p.S("mode", "both");
      if (mode != "lower" && mode != "raise" && mode != "both")
        return OpResult::Unsupported;
      const Grid* mask = In(a, "mask");
      if (mask != nullptr && !mask->SameShape(*src))
        return OpResult::Unsupported;
      if (!WorthIt(a, mode == "both" ? 125.0 : 70.0) || !Fits(ex, src->Count(), 6))
        return OpResult::Unsupported;
      const KernelInfo* kscan = FindKernel("field_slopescan");
      const KernelInfo* kapply = FindKernel("field_slopelimit");
      if (kscan == nullptr || kapply == nullptr) {
        return std::unexpected("kernel field_slopescan / field_slopelimit is missing");
      }
      const double limit = a.p.N("limit", 0.75);
      const double margin = std::max(0.0, a.p.N("margin", 0.03));
      const double L = std::max(0.0, (limit - margin)) * static_cast<double>(src->cell);
      const int w = src->w, h = src->h;
      Field in, tmp, lo, up, res;
      MaskBind mb;
      FAF_GPU_TRY(UploadGrid(ex, *src, in));
      FAF_GPU_TRY(MakeField(ex, w, h, tmp));
      FAF_GPU_TRY(MakeField(ex, w, h, res));
      FAF_GPU_TRY(BindMask(ex, a, mb));
      // the lower envelope of sign * source: along every row, then along every column (a Lipschitz surface under the
      // input)
      const auto envelope = [&](const float sign, Field& dst) -> std::expected<void, std::string> {
        FAF_GPU_TRY(MakeField(ex, w, h, dst));
        hk::SlopeScanParams p{};
        p.lim = static_cast<float>(L);
        p.inSign = sign;
        p.lines = static_cast<std::uint32_t>(h);
        p.len = static_cast<std::uint32_t>(w);
        p.stride = 1;
        p.lineStride = static_cast<std::uint32_t>(w);
        Bindings b0;
        b0.Srv(0, in.R()).Uav(0, tmp.R());
        FAF_GPU_TRY(DispatchGrid(ex, *kscan, p.lines, 1, p, b0));
        p.inSign = 1.0f;
        p.lines = static_cast<std::uint32_t>(w);
        p.len = static_cast<std::uint32_t>(h);
        p.stride = static_cast<std::uint32_t>(w);
        p.lineStride = 1;
        Bindings b1;
        b1.Srv(0, tmp.R()).Uav(0, dst.R());
        return DispatchGrid(ex, *kscan, p.lines, 1, p, b1);
      };
      if (mode != "raise")
        FAF_GPU_TRY(envelope(1.0f, lo));
      if (mode != "lower")
        FAF_GPU_TRY(envelope(-1.0f, up));
      hk::SlopeLimitParams p{};
      p.w = static_cast<std::uint32_t>(w);
      p.h = static_cast<std::uint32_t>(h);
      p.mode = mode == "lower" ? 0u : (mode == "raise" ? 1u : 2u);
      p.hasMask = mb.has ? 1u : 0u;
      p.balance = static_cast<float>(Clamp01(static_cast<float>(a.p.N("balance", 0.5))));
      p.strength = Clamp01(static_cast<float>(a.p.N("strength", 1.0)));
      Bindings b;
      b.Srv(0, in.R()).Srv(1, lo ? lo.R() : up.R()).Srv(2, up ? up.R() : lo.R()).Srv(3, mb.R()).Uav(0, res.R());
      FAF_GPU_TRY(DispatchGrid(ex, *kapply, p.w, p.h, p, b));
      Grid g = LikeOf(*src);
      FAF_GPU_TRY(DownloadGrid(ex, res, g));
      out = std::move(g);
      return OpResult::Done;
    }

    struct Registrar
    {
      Registrar()
      {
        RegisterGpuOp("rockiness", &OpRockinessGpu);
        RegisterGpuOp("stratify", &OpStratifyGpu);
        RegisterGpuOp("slope_limit", &OpSlopeLimitGpu);
        RegisterGpuOp("morph", &OpMorphGpu);
        RegisterGpuOp("convolve", &OpConvolveGpu);
        RegisterGpuOp("unsharp", &OpUnsharpGpu);
        RegisterGpuOp("edge", &OpEdgeGpu);
        RegisterGpuOp("blur_slope", &OpBlurSlopeGpu);
      }
    };
    const Registrar gRegistrar;
  } // namespace
} // namespace faf::editor::gpu
