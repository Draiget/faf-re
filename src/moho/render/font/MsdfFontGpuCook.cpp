#include "moho/render/font/MsdfFontGpuCook.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <vector>

#include "boost/shared_ptr.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/GpuDriven.h"
#include "moho/console/CConCommand.h"
#include "moho/render/GpuPathSettings.h"

namespace moho
{
  int ren_GpuFontCook = -1;
  bool ren_GpuFontCookCompare = false;

  TConVar<int> gTConVar_ren_GpuFontCook(
    "ren_GpuFontCook",
    "Work out fonts' MSDF atlases with a compute shader. -1 (auto, the default) where the backend has "
    "verified this path, 1 wherever it has compute shaders, 0 never.",
    &ren_GpuFontCook
  );
  TConVar<bool> gTConVar_ren_GpuFontCookCompare(
    "ren_GpuFontCookCompare",
    "With ren_GpuFontCook, also cook each font on the CPU, ignoring the cache, and log how far apart the atlases are.",
    &ren_GpuFontCookCompare
  );

  namespace
  {
    constexpr std::uint32_t kMaxBatchEdges = 65536u;
    constexpr std::uint32_t kMaxBatchTexels = 131072u;
    constexpr std::uint32_t kMaxBatchGlyphs = 32u;
    // Texels times edges in one frame. Windows resets a GPU after a long unbroken dispatch, and frames
    // have to stay steady, so a batch stays far below what a weak GPU does in a frame.
    constexpr std::uint64_t kMaxBatchCost = 4000000u;
    constexpr int kWaitSeconds = 120;

    constexpr char kCookShaderSource[] = R"hlsl(
struct Edge
{
  float2 p0;
  float2 p1;
  float2 p2;
  uint color;
  uint kind;
  float2 startDir;      // unit length, or zero
  float2 endDir;
  float2 startBisector; // of the corner with the edge before; unit length, or zero
  float2 endBisector;   // of the corner with the edge after
};
StructuredBuffer<Edge> gEdges : register(t0);
RWStructuredBuffer<float4> gOutput : register(u0);

cbuffer Params : register(b0)
{
  uint gFirstEdge;
  uint gEdgeCount;
  uint gWidth;
  uint gHeight;
  uint gOutOffset;
  float gRange;
  float gPad0;
  float gPad1;
};

static const float kPi = 3.14159265358979;

float Cross2(float2 a, float2 b) { return a.x * b.y - a.y * b.x; }
float NonZeroSign(float value) { return value > 0.0 ? 1.0 : -1.0; }

struct Distance
{
  float d;
  float dotValue;
  float param;
};

bool IsCloser(Distance a, Distance b)
{
  float absA = abs(a.d);
  float absB = abs(b.d);
  return absA < absB || (absA == absB && a.dotValue < b.dotValue);
}

float2 StartDirection(Edge e)
{
  if (e.kind == 1u) {
    return e.p1 - e.p0;
  }
  float2 tangent = e.p1 - e.p0;
  return (tangent.x != 0.0 || tangent.y != 0.0) ? tangent : e.p2 - e.p0;
}

float2 EndDirection(Edge e)
{
  if (e.kind == 1u) {
    return e.p1 - e.p0;
  }
  float2 tangent = e.p2 - e.p1;
  return (tangent.x != 0.0 || tangent.y != 0.0) ? tangent : e.p2 - e.p0;
}

float2 EndPoint(Edge e)
{
  return e.kind == 1u ? e.p1 : e.p2;
}

// msdfgen's LinearSegment::signedDistance.
Distance LineDistance(Edge e, float2 q)
{
  Distance result;
  float2 aq = q - e.p0;
  float2 ab = e.p1 - e.p0;
  result.param = dot(aq, ab) / dot(ab, ab);
  float2 eq = (result.param > 0.5 ? e.p1 : e.p0) - q;
  float endpointDistance = length(eq);
  if (result.param > 0.0 && result.param < 1.0) {
    float abLength = length(ab);
    float orthoDistance = dot(float2(-ab.y, ab.x) / abLength, aq);
    if (abs(orthoDistance) < endpointDistance) {
      result.d = orthoDistance;
      result.dotValue = 0.0;
      return result;
    }
  }
  result.d = NonZeroSign(Cross2(aq, ab)) * endpointDistance;
  result.dotValue = abs(dot(normalize(ab), endpointDistance > 0.0 ? eq / endpointDistance : float2(0.0, 1.0)));
  return result;
}

// msdfgen's solveCubic, in 32 bits: the coordinates are texels of one glyph, so they stay small.
int SolveCubic(float a, float b, float c, float d, out float3 roots)
{
  roots = float3(0.0, 0.0, 0.0);
  if (a != 0.0 && abs(b / a) < 1.0e6) {
    float bn = b / a;
    float cn = c / a;
    float dn = d / a;
    float a2 = bn * bn;
    float qq = (a2 - 3.0 * cn) / 9.0;
    float rr = (bn * (2.0 * a2 - 9.0 * cn) + 27.0 * dn) / 54.0;
    float r2 = rr * rr;
    float q3 = qq * qq * qq;
    float third = bn / 3.0;
    if (r2 < q3) {
      float t = acos(clamp(rr / sqrt(q3), -1.0, 1.0));
      float m = -2.0 * sqrt(qq);
      roots = float3(m * cos(t / 3.0) - third, m * cos((t + 2.0 * kPi) / 3.0) - third, m * cos((t - 2.0 * kPi) / 3.0) - third);
      return 3;
    }
    float u = (rr < 0.0 ? 1.0 : -1.0) * pow(abs(rr) + sqrt(r2 - q3), 1.0 / 3.0);
    float v = u == 0.0 ? 0.0 : qq / u;
    roots.x = (u + v) - third;
    if (u == v || abs(u - v) < 1.0e-6 * abs(u + v)) {
      roots.y = -0.5 * (u + v) - third;
      return 2;
    }
    return 1;
  }
  if (b == 0.0) {
    if (c == 0.0) {
      return 0;
    }
    roots.x = -d / c;
    return 1;
  }
  float disc = c * c - 4.0 * b * d;
  if (disc < 0.0) {
    return 0;
  }
  float s = sqrt(disc);
  roots.x = (-c + s) / (2.0 * b);
  roots.y = (-c - s) / (2.0 * b);
  return 2;
}

// msdfgen's QuadraticSegment::signedDistance.
Distance QuadraticDistance(Edge e, float2 q)
{
  Distance result;
  float2 qa = e.p0 - q;
  float2 ab = e.p1 - e.p0;
  float2 br = e.p2 - e.p1 - ab;
  float3 roots;
  int solutions = SolveCubic(dot(br, br), 3.0 * dot(ab, br), 2.0 * dot(ab, ab) + dot(qa, br), dot(qa, ab), roots);

  float2 startDir = StartDirection(e);
  float minDistance = NonZeroSign(Cross2(startDir, qa)) * length(qa);
  result.param = -dot(qa, startDir) / dot(startDir, startDir);
  float2 toEnd = e.p2 - q;
  float endDistance = length(toEnd);
  if (endDistance < abs(minDistance)) {
    float2 endDir = EndDirection(e);
    minDistance = NonZeroSign(Cross2(endDir, toEnd)) * endDistance;
    result.param = dot(q - e.p1, endDir) / dot(endDir, endDir);
  }
  for (int i = 0; i < solutions; ++i) {
    float t = roots[i];
    if (t > 0.0 && t < 1.0) {
      float2 qe = qa + 2.0 * t * ab + t * t * br;
      float distanceToCurve = length(qe);
      if (distanceToCurve <= abs(minDistance)) {
        minDistance = NonZeroSign(Cross2(ab + t * br, qe)) * distanceToCurve;
        result.param = t;
      }
    }
  }

  result.d = minDistance;
  if (result.param >= 0.0 && result.param <= 1.0) {
    result.dotValue = 0.0;
  } else if (result.param < 0.5) {
    result.dotValue = abs(dot(normalize(startDir), normalize(qa)));
  } else {
    result.dotValue = abs(dot(normalize(EndDirection(e)), normalize(toEnd)));
  }
  return result;
}

// msdfgen's EdgeSegment::distanceToPerpendicularDistance.
float PerpendicularDistance(Edge e, float2 q, Distance found)
{
  if (found.param < 0.0) {
    float2 dir = normalize(StartDirection(e));
    float2 aq = q - e.p0;
    if (dot(aq, dir) < 0.0) {
      float perpendicular = Cross2(aq, dir);
      if (abs(perpendicular) <= abs(found.d)) {
        return perpendicular;
      }
    }
  } else if (found.param > 1.0) {
    float2 dir = normalize(EndDirection(e));
    float2 bq = q - EndPoint(e);
    if (dot(bq, dir) > 0.0) {
      float perpendicular = Cross2(bq, dir);
      if (abs(perpendicular) <= abs(found.d)) {
        return perpendicular;
      }
    }
  }
  return found.d;
}

// How much this edge winds around q, counted along a ray towards +x; together, the exact non-zero fill. The CPU
// splits quadratics where they turn up or down (PushGpuQuadratic), so each edge here only rises or only falls, and
// its endpoints decide whether the ray crosses it, half-open as for a line: a ray touching a curve's top or bottom
// counts once or not at all, never twice.
int Winding(Edge e, float2 q)
{
  float2 end = EndPoint(e);
  if ((e.p0.y <= q.y) == (end.y <= q.y)) {
    return 0;
  }
  int direction = end.y > e.p0.y ? 1 : -1;
  if (e.kind == 1u) {
    float t = (q.y - e.p0.y) / (end.y - e.p0.y);
    return lerp(e.p0.x, end.x, t) > q.x ? direction : 0;
  }
  // The one t where this monotonic curve reaches q.y.
  float a = e.p0.y - 2.0 * e.p1.y + e.p2.y;
  float b = 2.0 * (e.p1.y - e.p0.y);
  float c = e.p0.y - q.y;
  float t;
  if (abs(a) < 1.0e-6) {
    t = -c / b;
  } else {
    float s = sqrt(max(b * b - 4.0 * a * c, 0.0));
    float t0 = (-b - s) / (2.0 * a);
    float t1 = (-b + s) / (2.0 * a);
    t = (t0 >= 0.0 && t0 <= 1.0) ? t0 : t1;
  }
  t = clamp(t, 0.0, 1.0);
  float mt = 1.0 - t;
  float x = mt * mt * e.p0.x + 2.0 * mt * t * e.p1.x + t * t * e.p2.x;
  return x > q.x ? direction : 0;
}

[numthreads(8, 8, 1)]
void CookFontCS(uint3 id : SV_DispatchThreadID)
{
  if (id.x >= gWidth || id.y >= gHeight) {
    return;
  }
  float2 q = float2(float(id.x) + 0.5, float(id.y) + 0.5);

  Distance trueBest;
  trueBest.d = 1.0e30;
  trueBest.dotValue = 1.0e30;
  trueBest.param = 0.0;
  // Per channel, as msdfgen's PerpendicularDistanceSelectorBase: the closest edge, and the perpendicular distances
  // nearest zero on either side, from every edge whose corner the texel lies outside of.
  Distance best[3];
  uint bestEdge[3];
  float minNegative[3];
  float minPositive[3];
  for (int j = 0; j < 3; ++j) {
    best[j] = trueBest;
    bestEdge[j] = 0xFFFFFFFFu;
    minNegative[j] = -1.0e30;
    minPositive[j] = 1.0e30;
  }

  int wind = 0;
  for (uint i = 0u; i < gEdgeCount; ++i) {
    Edge e = gEdges[gFirstEdge + i];
    Distance found;
    if (e.kind == 1u) {
      found = LineDistance(e, q);
    } else {
      found = QuadraticDistance(e, q);
    }
    if (IsCloser(found, trueBest)) {
      trueBest = found;
    }

    // msdfgen's MultiDistanceSelector::addEdge: past an end, the extended edge counts only on the outer side of
    // that corner, as the bisector with the neighbouring edge decides, and only when nearer than the edge itself.
    bool hasStart = false;
    bool hasEnd = false;
    float startPerpendicular = 0.0;
    float endPerpendicular = 0.0;
    float2 ap = q - e.p0;
    float2 bp = q - EndPoint(e);
    if (dot(ap, e.startBisector) > 0.0 && dot(ap, -e.startDir) > 0.0) {
      float perpendicular = Cross2(ap, -e.startDir);
      if (abs(perpendicular) < abs(found.d)) {
        hasStart = true;
        startPerpendicular = -perpendicular;
      }
    }
    if (-dot(bp, e.endBisector) > 0.0 && dot(bp, e.endDir) > 0.0) {
      float perpendicular = Cross2(bp, e.endDir);
      if (abs(perpendicular) < abs(found.d)) {
        hasEnd = true;
        endPerpendicular = perpendicular;
      }
    }

    for (int c = 0; c < 3; ++c) {
      if ((e.color & (1u << uint(c))) == 0u) {
        continue;
      }
      if (IsCloser(found, best[c])) {
        best[c] = found;
        bestEdge[c] = gFirstEdge + i;
      }
      if (hasStart) {
        if (startPerpendicular <= 0.0 && startPerpendicular > minNegative[c]) {
          minNegative[c] = startPerpendicular;
        }
        if (startPerpendicular >= 0.0 && startPerpendicular < minPositive[c]) {
          minPositive[c] = startPerpendicular;
        }
      }
      if (hasEnd) {
        if (endPerpendicular <= 0.0 && endPerpendicular > minNegative[c]) {
          minNegative[c] = endPerpendicular;
        }
        if (endPerpendicular >= 0.0 && endPerpendicular < minPositive[c]) {
          minPositive[c] = endPerpendicular;
        }
      }
    }
    wind += Winding(e, q);
  }

  // FXC keeps a for loop's variable in the enclosing scope, so each loop here has its own name.
  float4 value;
  // msdfgen's PerpendicularDistanceSelectorBase::computeDistance.
  for (int k = 0; k < 3; ++k) {
    float channel = best[k].d < 0.0 ? minNegative[k] : minPositive[k];
    if (bestEdge[k] != 0xFFFFFFFFu) {
      float converted = PerpendicularDistance(gEdges[bestEdge[k]], q, best[k]);
      if (abs(converted) < abs(channel)) {
        channel = converted;
      }
    }
    value[k] = channel / gRange + 0.5;
  }
  value.a = trueBest.d / gRange + 0.5;

  // msdfgen's sign correction: the exact fill decides inside and outside, and a texel on the wrong side turns over.
  float median = max(min(value.r, value.g), min(max(value.r, value.g), value.b));
  if ((median > 0.5) != (wind != 0)) {
    value = 1.0 - value;
  }
  gOutput[gOutOffset + id.y * gWidth + id.x] = value;
}
)hlsl";

    struct DispatchParams
    {
      std::uint32_t mFirstEdge;
      std::uint32_t mEdgeCount;
      std::uint32_t mWidth;
      std::uint32_t mHeight;
      std::uint32_t mOutOffset;
      float mRange;
      float mPad[2];
    };
    static_assert(sizeof(DispatchParams) == 32u, "DispatchParams must match Params in the shader");
    static_assert(sizeof(SMsdfGpuEdge) == 64u, "SMsdfGpuEdge must match Edge in the shader");

    struct Job
    {
      MsdfCookPlan* mPlan = nullptr;
      std::size_t mNextGlyph = 0u;
      std::vector<std::vector<float>> mFields;
      bool mDone = false;
      bool mFailed = false;
      std::string mError;
    };

    struct Cooker
    {
      std::mutex mMutex;
      std::condition_variable mWake;
      Job* mJob = nullptr;
      std::atomic<bool> mHasJob{false};
      bool mCancelled = false;

      // On the frame thread only.
      const gpg::gal::Device* mDevice = nullptr;
      boost::shared_ptr<gpg::gal::GpuProgram> mProgram;
      boost::shared_ptr<gpg::gal::GpuBuffer> mEdges;
      boost::shared_ptr<gpg::gal::GpuBuffer> mOutput;
      std::vector<SMsdfGpuEdge> mBatchEdges;
      std::vector<float> mReadBack;
    };

    [[nodiscard]] Cooker& GetCooker()
    {
      static Cooker cooker;
      return cooker;
    }

    [[nodiscard]] bool EnsureResources(Cooker& cooker, gpg::gal::Device& device)
    {
      if (cooker.mDevice == &device && cooker.mProgram && cooker.mEdges && cooker.mOutput) {
        return true;
      }
      cooker.mDevice = &device;

      gpg::gal::GpuProgramDesc program{};
      program.name = "MsdfFontCook";
      program.source = kCookShaderSource;
      program.sourceBytes = sizeof(kCookShaderSource) - 1u;
      program.computeEntry = "CookFontCS";
      cooker.mProgram = device.CreateGpuProgram(program);

      gpg::gal::GpuBufferDesc edges{};
      edges.name = "MsdfFontCookEdges";
      edges.stride = sizeof(SMsdfGpuEdge);
      edges.capacity = kMaxBatchEdges;
      cooker.mEdges = device.CreateGpuBuffer(edges);

      gpg::gal::GpuBufferDesc output{};
      output.name = "MsdfFontCookOutput";
      output.stride = 16u;
      output.capacity = kMaxBatchTexels;
      output.shaderWrite = true;
      cooker.mOutput = device.CreateGpuBuffer(output);
      return cooker.mProgram && cooker.mEdges && cooker.mOutput;
    }

    /** One batch: as many glyphs as stay inside the budgets, at least one. */
    void RunBatch(Cooker& cooker, gpg::gal::Device& device, Job& job)
    {
      const std::vector<SMsdfGpuGlyph>& glyphs = job.mPlan->GpuGlyphs();
      const std::vector<SMsdfGpuEdge>& edges = job.mPlan->GpuEdges();

      struct BatchGlyph
      {
        std::size_t mGlyph;
        std::uint32_t mFirstEdge;
        std::uint32_t mOffset;
      };
      std::vector<BatchGlyph> batch;
      cooker.mBatchEdges.clear();
      std::uint32_t texels = 0u;
      std::uint64_t cost = 0u;
      std::size_t next = job.mNextGlyph;
      for (; next < glyphs.size() && batch.size() < kMaxBatchGlyphs; ++next) {
        const SMsdfGpuGlyph& glyph = glyphs[next];
        if (glyph.mWidth <= 0) {
          continue;
        }
        const std::uint32_t glyphTexels = static_cast<std::uint32_t>(glyph.mWidth) * static_cast<std::uint32_t>(glyph.mHeight);
        if (glyphTexels > kMaxBatchTexels || glyph.mEdgeCount > kMaxBatchEdges) {
          job.mFailed = true;
          job.mError = "a glyph is too large for a batch";
          return;
        }
        const std::uint64_t glyphCost = static_cast<std::uint64_t>(glyphTexels) * glyph.mEdgeCount;
        if (!batch.empty()
            && (texels + glyphTexels > kMaxBatchTexels || cooker.mBatchEdges.size() + glyph.mEdgeCount > kMaxBatchEdges
                || cost + glyphCost > kMaxBatchCost)) {
          break;
        }
        batch.push_back({next, static_cast<std::uint32_t>(cooker.mBatchEdges.size()), texels});
        cooker.mBatchEdges.insert(
          cooker.mBatchEdges.end(), edges.begin() + glyph.mFirstEdge, edges.begin() + glyph.mFirstEdge + glyph.mEdgeCount
        );
        texels += glyphTexels;
        cost += glyphCost;
      }
      job.mNextGlyph = next;
      if (batch.empty()) {
        return;
      }

      device.UpdateGpuBuffer(*cooker.mEdges, 0u, static_cast<std::uint32_t>(cooker.mBatchEdges.size()), cooker.mBatchEdges.data());
      for (const BatchGlyph& item : batch) {
        const SMsdfGpuGlyph& glyph = glyphs[item.mGlyph];
        const DispatchParams params{
          item.mFirstEdge, glyph.mEdgeCount, static_cast<std::uint32_t>(glyph.mWidth), static_cast<std::uint32_t>(glyph.mHeight),
          item.mOffset, job.mPlan->RangeTexels(), {0.0f, 0.0f}
        };
        gpg::gal::GpuDispatch dispatch{};
        dispatch.program = cooker.mProgram.get();
        dispatch.bindings.constants = &params;
        dispatch.bindings.constantBytes = sizeof(params);
        dispatch.bindings.readBuffers[0] = cooker.mEdges.get();
        dispatch.bindings.writeBuffers[0] = cooker.mOutput.get();
        dispatch.groupsX = (static_cast<std::uint32_t>(glyph.mWidth) + 7u) / 8u;
        dispatch.groupsY = (static_cast<std::uint32_t>(glyph.mHeight) + 7u) / 8u;
        device.DispatchGpuProgram(dispatch);
      }

      cooker.mReadBack.resize(static_cast<std::size_t>(texels) * 4u);
      if (!device.ReadGpuBuffer(*cooker.mOutput, 0u, texels, cooker.mReadBack.data())) {
        job.mFailed = true;
        job.mError = "the GPU's results couldn't be read back";
        return;
      }
      for (const BatchGlyph& item : batch) {
        const SMsdfGpuGlyph& glyph = glyphs[item.mGlyph];
        const std::size_t count = static_cast<std::size_t>(glyph.mWidth) * static_cast<std::size_t>(glyph.mHeight) * 4u;
        const auto first = cooker.mReadBack.begin() + static_cast<std::ptrdiff_t>(static_cast<std::size_t>(item.mOffset) * 4u);
        job.mFields[item.mGlyph].assign(first, first + static_cast<std::ptrdiff_t>(count));
      }
    }
  } // namespace

  bool MSDF_IsGpuCookAvailable()
  {
    return GpuPathEnabled(
      ren_GpuFontCook, gpg::gal::kGpuPathMsdfCook, gpg::gal::kGpuFeatureVertexPulling | gpg::gal::kGpuFeatureCompute
    );
  }

  bool MSDF_CookOnGpu(MsdfCookPlan& plan, std::string& error)
  {
    Job job;
    job.mPlan = &plan;
    plan.BuildGpuData();
    job.mFields.resize(plan.GpuGlyphs().size());

    Cooker& cooker = GetCooker();
    {
      std::unique_lock<std::mutex> lock(cooker.mMutex);
      if (cooker.mCancelled) {
        error = "shutting down";
        return false;
      }
      cooker.mJob = &job;
      cooker.mHasJob.store(true, std::memory_order_release);
      const bool finished = cooker.mWake.wait_for(lock, std::chrono::seconds(kWaitSeconds), [&job, &cooker]() {
        return job.mDone || cooker.mCancelled;
      });
      cooker.mJob = nullptr;
      cooker.mHasJob.store(false, std::memory_order_release);
      if (!finished || !job.mDone) {
        error = "no frames came to run it on";
        return false;
      }
    }
    if (job.mFailed) {
      error = job.mError;
      return false;
    }

    // The error correction stays on this thread: it compares neighbouring texels, and it's the slow part left.
    for (std::size_t i = 0; i < job.mFields.size(); ++i) {
      if (!job.mFields[i].empty()) {
        plan.StoreGlyphField(i, job.mFields[i]);
      }
    }
    return true;
  }

  void MSDF_TickGpuCook()
  {
    Cooker& cooker = GetCooker();
    if (!cooker.mHasJob.load(std::memory_order_acquire)) {
      return;
    }
    const std::lock_guard<std::mutex> lock(cooker.mMutex);
    Job* const job = cooker.mJob;
    if (job == nullptr || job->mDone) {
      return;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr || !EnsureResources(cooker, *device)) {
      job->mFailed = true;
      job->mError = "the compute program or its buffers couldn't be made";
    } else {
      RunBatch(cooker, *device, *job);
    }
    if (job->mFailed || job->mNextGlyph >= job->mFields.size()) {
      job->mDone = true;
      cooker.mWake.notify_all();
    }
  }

  void MSDF_CancelGpuCook()
  {
    Cooker& cooker = GetCooker();
    const std::lock_guard<std::mutex> lock(cooker.mMutex);
    cooker.mCancelled = true;
    cooker.mWake.notify_all();
  }

  void MSDF_LogAtlasComparison(const char* const name, const SMsdfFontAtlas& gpu, const SMsdfFontAtlas& cpu, const double gpuMs, const double cpuMs)
  {
    if (gpu.mPixels.size() != cpu.mPixels.size()) {
      gpg::Warnf("MSDF compare %s: the atlases have different sizes", name);
      return;
    }
    const auto median = [](const std::uint8_t* const texel) {
      const int r = texel[0];
      const int g = texel[1];
      const int b = texel[2];
      return (std::max)((std::min)(r, g), (std::min)((std::max)(r, g), b));
    };
    int largest = 0;
    int largestAlpha = 0;
    std::uint64_t texels = 0u;
    std::uint64_t over8 = 0u;
    std::uint64_t ink = 0u;
    std::uint64_t shapeDiffers = 0u;
    std::uint64_t edgeMedianOver8 = 0u;
    for (std::size_t i = 0; i + 4u <= gpu.mPixels.size(); i += 4u) {
      const std::uint8_t* const a = gpu.mPixels.data() + i;
      const std::uint8_t* const b = cpu.mPixels.data() + i;
      int texelLargest = 0;
      for (int c = 0; c < 3; ++c) {
        texelLargest = (std::max)(texelLargest, std::abs(static_cast<int>(a[c]) - static_cast<int>(b[c])));
      }
      largest = (std::max)(largest, texelLargest);
      largestAlpha = (std::max)(largestAlpha, std::abs(static_cast<int>(a[3]) - static_cast<int>(b[3])));
      ++texels;
      over8 += texelLargest > 8 ? 1u : 0u;
      const int medianA = median(a);
      const int medianB = median(b);
      ink += medianB >= 128 ? 1u : 0u;
      shapeDiffers += (medianA >= 128) != (medianB >= 128) ? 1u : 0u;
      edgeMedianOver8 += (std::abs(medianB - 128) < 32 && std::abs(medianA - medianB) > 8) ? 1u : 0u;
    }
    gpg::Logf(
      "MSDF compare %s: GPU %.1f ms, CPU %.1f ms; largest channel difference %d, alpha %d; %llu of %llu texels differ by over 8; "
      "%llu of %llu inked texels change sides; %llu near the outline move by over 8",
      name, gpuMs, cpuMs, largest, largestAlpha, static_cast<unsigned long long>(over8), static_cast<unsigned long long>(texels),
      static_cast<unsigned long long>(shapeDiffers), static_cast<unsigned long long>(ink), static_cast<unsigned long long>(edgeMedianOver8)
    );
  }
} // namespace moho
