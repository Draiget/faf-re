// EDITOR GPU compute backend: the device independent helpers (fields, dispatch geometry, RunIterations, the Lease) and
// the Direct3D 11 implementation of Backend / Executor. See EdGpu.h and docs/projects/editor/GPU_COMPUTE.md. NOTHING IN
// THE DIRECT3D 11 PART WAS RUN ON A GPU when this was written (Linux, g++ syntax check against hand written stub
// headers only): the first thing to do on a Windows machine is `dev.gpu` / ed_gpu_selftest().
//
// Failure rules: no exception leaves this file, no wait is unbounded, any failure of the device marks the backend
// failed for the session (the objects are then NOT released: a stuck driver may block Release) and every caller falls
// back to the CPU.
#include "editor/terrain/gpu/EdGpu.h"

#include "platform/PlatformDefines.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <expected>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <tuple>
#include <vector>

#include "editor/terrain/gpu/EdGpuShaders.generated.h"

namespace faf::editor::gpu::hk
{
  using uint = std::uint32_t;
#include "editor/terrain/gpu/field_params.hlsli"
} // namespace faf::editor::gpu::hk

namespace faf::editor::gpu
{
  // ---- kernel table
  // --------------------------------------------------------------------------------------------------------------------------

  const KernelInfo* FindKernel(
    const char* const name
  )
  {
    if (name == nullptr) {
      return nullptr;
    }
    for (int i = 0; i < shaders::kKernelCount; ++i) {
      if (std::strcmp(shaders::kKernels[i].name, name) == 0) {
        return &shaders::kKernels[i];
      }
    }
    return nullptr;
  }

  int KernelCount()
  {
    return shaders::kKernelCount;
  }
  const KernelInfo& KernelAt(
    const int index
  )
  {
    return shaders::kKernels[index];
  }

  namespace
  {
    std::atomic<LogFn> gLog{nullptr};

    [[maybe_unused]] void Log(
      const std::string& line
    )
    {
      if (const LogFn fn = gLog.load(); fn != nullptr) {
        fn(line.c_str());
      }
    }

    double MsSince(
      const std::chrono::steady_clock::time_point t0
    )
    {
      return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    }
  } // namespace

  void SetLogSink(
    const LogFn fn
  )
  {
    gLog.store(fn);
  }

  // ---- helpers on top of an Executor
  // ---------------------------------------------------------------------------------------------------------

  std::expected<void, std::string> MakeBuffer(
    Executor& ex,
    const u32 count,
    std::unique_ptr<Resource>& out
  )
  {
    if (count == 0) {
      return std::unexpected("empty buffer");
    }
    auto made = ex.CreateBuffer(count, 4);
    out = made ? std::move(*made) : nullptr;
    if (!out) {
      return std::unexpected(made || made.error().empty() ? std::string("could not create a buffer") : made.error());
    }
    return {};
  }

  std::expected<void, std::string> UploadBuffer(
    Executor& ex,
    Resource& r,
    const void* const data,
    const std::size_t bytes
  )
  {
    return ex.Upload(r, data, bytes);
  }

  std::expected<void, std::string> FillBuffer(
    Executor& ex,
    Resource& r,
    const u32 pattern
  )
  {
    if (r.kind != Resource::Kind::Buffer || r.stride != 4 || r.count == 0) {
      return std::unexpected(std::string("FillBuffer needs a buffer of 4 byte elements"));
    }
    const std::vector<u32> words(r.count, pattern);
    return ex.Upload(r, words.data(), words.size() * 4);
  }

  std::expected<void, std::string> MakeField(
    Executor& ex,
    const int w,
    const int h,
    Field& out
  )
  {
    if (w < 1 || h < 1 || static_cast<std::uint64_t>(w) * static_cast<std::uint64_t>(h) > (1ull << 27)) {
      return std::unexpected("field size out of range");
    }
    if (static_cast<std::uint64_t>(w) * static_cast<std::uint64_t>(h) * 4ull > ex.MaxBytes()) {
      return std::unexpected("field larger than the memory the GPU backend may use");
    }
    auto made = ex.CreateBuffer(static_cast<u32>(w) * static_cast<u32>(h), 4);
    out.buf = made ? std::move(*made) : nullptr;
    out.w = w;
    out.h = h;
    if (!out.buf) {
      return std::unexpected(made || made.error().empty() ? std::string("could not create a field") : made.error());
    }
    return {};
  }

  std::expected<void, std::string> UploadField(
    Executor& ex,
    Field& f,
    const float* const data
  )
  {
    if (!f.buf) {
      return std::unexpected("field not created");
    }
    return ex.Upload(*f.buf, data, f.buf->Bytes());
  }

  std::expected<void, std::string> DownloadField(
    Executor& ex,
    Field& f,
    float* const data
  )
  {
    if (!f.buf) {
      return std::unexpected("field not created");
    }
    return ex.Download(*f.buf, data, f.buf->Bytes());
  }

  std::expected<void, std::string> UploadGrid(
    Executor& ex,
    const field::Grid& g,
    Field& out
  )
  {
    if (g.v.size() != g.Count()) {
      return std::unexpected("grid size does not match its data");
    }
    FAF_GPU_TRY(MakeField(ex, g.w, g.h, out));
    return UploadField(ex, out, g.v.data());
  }

  std::expected<void, std::string> DownloadGrid(
    Executor& ex,
    Field& f,
    field::Grid& g
  )
  {
    if (g.w != f.w || g.h != f.h || g.v.size() != g.Count()) {
      return std::unexpected("grid and field differ in size");
    }
    return DownloadField(ex, f, g.v.data());
  }

  std::expected<Groups, std::string> GroupsFor(
    const KernelInfo& k,
    const u32 w,
    const u32 h
  )
  {
    if (w == 0 || h == 0 || k.tx == 0 || k.ty == 0) {
      return std::unexpected("empty dispatch");
    }
    Groups g;
    g.x = (w + k.tx - 1) / k.tx;
    g.y = (h + k.ty - 1) / k.ty;
    g.z = 1;
    if (g.x > kMaxGroups || g.y > kMaxGroups) {
      return std::unexpected("dispatch has more thread groups than the hardware allows");
    }
    return g;
  }

  std::expected<void, std::string> DispatchGridNoCb(
    Executor& ex,
    const KernelInfo& k,
    const u32 w,
    const u32 h,
    const Bindings& b
  )
  {
    const auto g = GroupsFor(k, w, h);
    if (!g)
      return std::unexpected(g.error());
    return ex.Dispatch(k, *g, nullptr, 0, b);
  }

  std::expected<void, std::string> MakeTextureFromField(
    Executor& ex,
    const Field& f,
    std::unique_ptr<Resource>& tex
  )
  {
    if (!f.buf || !ex.SupportsTextures()) {
      return std::unexpected("no texture support");
    }
    const KernelInfo* k = FindKernel("buf_to_tex");
    if (k == nullptr) {
      return std::unexpected("kernel buf_to_tex is missing");
    }
    auto made = ex.CreateTexture(static_cast<u32>(f.w), static_cast<u32>(f.h));
    tex = made ? std::move(*made) : nullptr;
    if (!tex) {
      return std::unexpected(made || made.error().empty() ? std::string("could not create a texture") : made.error());
    }
    hk::FieldParams p{};
    p.w = static_cast<std::uint32_t>(f.w);
    p.h = static_cast<std::uint32_t>(f.h);
    p.srcW = p.w;
    p.srcH = p.h;
    Bindings b;
    b.Srv(0, *f.buf).Uav(0, *tex);
    return DispatchGrid(ex, *k, p.w, p.h, p, b);
  }

  u32 NextBatch(
    const u32 batch,
    const double ms,
    const double targetMs,
    const u32 remaining
  )
  {
    if (remaining == 0) {
      return 0;
    }
    const double perIteration = std::max(ms, 0.001) / static_cast<double>(std::max<u32>(batch, 1));
    double n = targetMs / perIteration;
    n = std::min(
      n, static_cast<double>(std::max<u32>(batch, 1)) * 4.0
    ); // grow at most 4 times per step: one slow iteration is not an average
    const u32 whole = n < 1.0 ? 1u : static_cast<u32>(n);
    return std::min(whole, remaining);
  }

  std::expected<void, std::string> RunIterations(
    Executor& ex,
    const u32 count,
    const double targetMs,
    const std::function<std::expected<void, std::string>(u32)>& step,
    IterStats* const stats
  )
  {
    IterStats local;
    IterStats& s = stats != nullptr ? *stats : local;
    s = IterStats{};
    const double target = targetMs > 0.0 ? targetMs : 60.0;
    u32 done = 0;
    u32 batch = 1;
    while (done < count) {
      const u32 n = std::min(batch, count - done);
      const auto t0 = std::chrono::steady_clock::now();
      for (u32 i = 0; i < n; ++i) {
        if (auto stepped = step(done + i); !stepped) {
          s.iterations = done + i;
          return stepped;
        }
      }
      double gpuMs = 0.0;
      if (auto synced = ex.Sync(&gpuMs); !synced) {
        s.iterations = done;
        return synced;
      }
      const double ms = MsSince(t0); // wall time of the whole submission: the conservative number for the TDR limit
      done += n;
      ++s.submits;
      s.totalMs += ms;
      s.maxSubmitMs = std::max(s.maxSubmitMs, ms);
      s.largestBatch = std::max(s.largestBatch, n);
      s.iterations = done;
      batch = NextBatch(n, ms, target, count - done);
    }
    return {};
  }

  // ---- Lease and the process backend
  // -----------------------------------------------------------------------------------------------------------

  namespace
  {
    thread_local bool tHolding = false;
    Backend* gOverride = nullptr;
    std::atomic<u32> gPreferredVendor{0};
    std::atomic<u32> gPreferredDevice{0};
  } // namespace

  void SetBackendForTest(
    Backend* const b
  )
  {
    gOverride = b;
  }
  void SetPreferredAdapter(
    const u32 vendorId,
    const u32 deviceId
  )
  {
    gPreferredVendor.store(vendorId);
    gPreferredDevice.store(deviceId);
  }

  Lease::Lease(
    const bool wait
  )
  {
    if (tHolding) {
      busy_ = true;
      err_ = "the GPU is already in use by this thread";
      return;
    }
    try {
      backend_ = &CurrentBackend();
      ex_ = backend_->Acquire(wait, busy_, err_);
    } catch (...) {
      ex_ = nullptr;
      err_ = "exception while taking the GPU";
    }
    if (ex_ != nullptr) {
      tHolding = true;
    }
  }

  Lease::~Lease()
  {
    if (ex_ == nullptr) {
      return;
    }
    try {
      if (ex_->DeviceLost()) {
        backend_->MarkFailed("device lost");
      }
    } catch (...) {}
    tHolding = false;
    backend_->Release();
  }

  void Lease::Fail(
    const std::string& why
  )
  {
    if (backend_ != nullptr && ex_ != nullptr) {
      backend_->MarkFailed(why);
    }
  }
} // namespace faf::editor::gpu

// =================================================================================================================================================
// Direct3D 11
// =================================================================================================================================================

#if FAFRE_PLATFORM_WINDOWS

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <d3d11.h>
#include <dxgi.h>

namespace faf::editor::gpu
{
  namespace
  {
    // d3dcompiler is loaded at run time (d3dcompiler_47.dll, else _43): no link dependency. The flags are written out
    // so the old d3dcompiler.h of the June 2010 SDK is not needed.
    constexpr UINT kCompileOptimizationLevel3 = 1u << 15;
    constexpr UINT kCompileEnableStrictness = 1u << 11;
    using PFN_D3DCompile_ = HRESULT(WINAPI*)(
      LPCVOID pSrcData,
      SIZE_T SrcDataSize,
      LPCSTR pSourceName,
      const D3D_SHADER_MACRO* pDefines,
      ID3DInclude* pInclude,
      LPCSTR pEntrypoint,
      LPCSTR pTarget,
      UINT Flags1,
      UINT Flags2,
      ID3DBlob** ppCode,
      ID3DBlob** ppErrorMsgs
    );
    using PFN_CreateDXGIFactory1_ = HRESULT(WINAPI*)(REFIID riid, void** ppFactory);

    constexpr int kSyncTimeoutMs =
      6000; // far above the 2 s of the Windows driver reset: a wait this long means the device is gone
    constexpr UINT kConstantBufferBytes = 4096;
    constexpr UINT kAdapterFlagSoftware = 2; // DXGI_ADAPTER_FLAG_SOFTWARE (not in the June 2010 SDK's dxgi.h)
    constexpr std::uint64_t kPoolCapBytes = 512ull << 20;
    constexpr double kPoolMaxIdleSeconds = 30.0;

    /** Minimal COM smart pointer. */
    template <class T>
    class Com
    {
    public:
      Com() = default;
      explicit Com(
        T* p
      )
        : p_(p)
      {}
      Com(const Com&) = delete;
      Com& operator=(const Com&) = delete;
      Com(
        Com&& o
      ) noexcept
        : p_(o.p_)
      {
        o.p_ = nullptr;
      }
      Com& operator=(
        Com&& o
      ) noexcept
      {
        if (this != &o) {
          Reset();
          p_ = o.p_;
          o.p_ = nullptr;
        }
        return *this;
      }
      ~Com()
      {
        Reset();
      }
      void Reset()
      {
        if (p_ != nullptr) {
          p_->Release();
          p_ = nullptr;
        }
      }
      T* Detach()
      {
        T* t = p_;
        p_ = nullptr;
        return t;
      }
      [[nodiscard]] T* Get() const
      {
        return p_;
      }
      [[nodiscard]] T** Put()
      {
        Reset();
        return &p_;
      }
      T* operator->() const
      {
        return p_;
      }
      explicit operator bool() const
      {
        return p_ != nullptr;
      }

    private:
      T* p_ = nullptr;
    };

    std::string Hex(
      const HRESULT hr
    )
    {
      char buf[24];
      std::snprintf(buf, sizeof(buf), "0x%08lX", static_cast<unsigned long>(hr));
      return buf;
    }

    std::string Narrow(
      const wchar_t* w
    )
    {
      char buf[260] = {};
      WideCharToMultiByte(CP_UTF8, 0, w, -1, buf, static_cast<int>(sizeof(buf)) - 1, nullptr, nullptr);
      return buf;
    }

    // ---- pooled device objects
    // ---------------------------------------------------------------------------------------------------------------

    struct PoolEntry
    {
      Com<ID3D11Resource> res;
      Com<ID3D11ShaderResourceView> srv;
      Com<ID3D11UnorderedAccessView> uav;
      std::uint64_t bytes = 0;
      std::chrono::steady_clock::time_point last;
    };
    using PoolKey = std::tuple<int, u32, u32>; // (0 buffer / 1 texture / 2 staging buffer / 3 staging texture, a, b)

    class Pool
    {
    public:
      bool Take(
        const PoolKey& key,
        PoolEntry& out
      )
      {
        const std::lock_guard<std::mutex> lock(m_);
        auto it = free_.find(key);
        if (it == free_.end() || it->second.empty()) {
          return false;
        }
        out = std::move(it->second.back());
        it->second.pop_back();
        pooled_ -= out.bytes;
        return true;
      }
      void Give(
        const PoolKey& key,
        PoolEntry&& e
      )
      {
        const std::lock_guard<std::mutex> lock(m_);
        if (pooled_ + e.bytes > kPoolCapBytes) {
          return; // dropped (released) when `e` goes out of scope
        }
        e.last = std::chrono::steady_clock::now();
        pooled_ += e.bytes;
        free_[key].push_back(std::move(e));
      }
      void Purge(
        const double idleSeconds
      )
      {
        const std::lock_guard<std::mutex> lock(m_);
        const auto now = std::chrono::steady_clock::now();
        for (auto& kv : free_) {
          auto& list = kv.second;
          for (std::size_t i = 0; i < list.size();) {
            if (std::chrono::duration<double>(now - list[i].last).count() > idleSeconds) {
              pooled_ -= list[i].bytes;
              list.erase(list.begin() + static_cast<std::ptrdiff_t>(i));
            } else {
              ++i;
            }
          }
        }
      }
      void Clear()
      {
        const std::lock_guard<std::mutex> lock(m_);
        free_.clear();
        pooled_ = 0;
      }

    private:
      std::mutex m_;
      std::map<PoolKey, std::vector<PoolEntry>> free_;
      std::uint64_t pooled_ = 0;
    };

    class D3DResource final : public Resource
    {
    public:
      ~D3DResource() override
      {
        if (const std::shared_ptr<Pool> p = pool.lock(); p != nullptr && entry.res) {
          p->Give(key, std::move(entry));
        }
      }
      PoolEntry entry;
      PoolKey key;
      std::weak_ptr<Pool> pool;
      const void* owner = nullptr;
    };

    // ---- the executor
    // ------------------------------------------------------------------------------------------------------------------------

    class D3D11Executor final : public Executor
    {
    public:
      Com<ID3D11Device> dev;
      Com<ID3D11DeviceContext> ctx;
      std::shared_ptr<Pool> pool = std::make_shared<Pool>();
      std::map<std::uint64_t, Com<ID3D11ComputeShader>> shaders;
      Com<ID3D11Buffer> cbuf;
      Com<ID3D11SamplerState> samplers[2];
      Com<ID3D11Query> qEvent, qDisjoint, qStart, qEnd;
      PFN_D3DCompile_ compile = nullptr;
      std::uint64_t maxBytes = 256ull << 20;
      bool textures = false;
      bool lost = false;
      std::string lostWhy;
      bool timingOpen = false;

      ~D3D11Executor() override
      {
        if (ctx) {
          ctx->ClearState();
          ctx->Flush();
        }
        if (pool) {
          pool->Clear();
        }
      }

      [[nodiscard]] const char* Name() const override
      {
        return "Direct3D 11";
      }
      [[nodiscard]] std::uint64_t MaxBytes() const override
      {
        return maxBytes;
      }
      [[nodiscard]] bool SupportsTextures() const override
      {
        return textures;
      }
      [[nodiscard]] bool DeviceLost() const override
      {
        return lost;
      }

      std::unexpected<std::string> Fail(
        const std::string& what,
        const HRESULT hr
      )
      {
        std::string err = what + " (" + Hex(hr) + ")";
        CheckRemoved(err);
        return std::unexpected(std::move(err));
      }

      /** After any failure: a removed device marks the executor lost (the backend then stays off). */
      void CheckRemoved(
        std::string& err
      )
      {
        if (!dev) {
          return;
        }
        const HRESULT reason = dev->GetDeviceRemovedReason();
        if (reason != S_OK) {
          lost = true;
          lostWhy = "device removed (" + Hex(reason) + ")";
          err += "; " + lostWhy;
        }
      }

      void MarkLost(
        const std::string& why
      )
      {
        lost = true;
        lostWhy = why;
      }

      std::expected<std::unique_ptr<Resource>, std::string> CreateBuffer(
        const u32 count,
        const u32 stride
      ) override
      {
        if (lost) {
          return std::unexpected(lostWhy);
        }
        if (count == 0 || stride == 0 || stride % 4 != 0 || static_cast<std::uint64_t>(count) * stride > maxBytes) {
          return std::unexpected("buffer size out of range");
        }
        auto r = std::make_unique<D3DResource>();
        r->kind = Resource::Kind::Buffer;
        r->count = count;
        r->stride = stride;
        r->key = PoolKey(0, count, stride);
        r->pool = pool;
        r->owner = this;
        if (pool->Take(r->key, r->entry)) {
          return r;
        }
        D3D11_BUFFER_DESC bd = {};
        bd.ByteWidth = count * stride;
        bd.Usage = D3D11_USAGE_DEFAULT;
        bd.BindFlags = D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_UNORDERED_ACCESS;
        bd.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_STRUCTURED;
        bd.StructureByteStride = stride;
        Com<ID3D11Buffer> buf;
        HRESULT hr = dev->CreateBuffer(&bd, nullptr, buf.Put());
        if (FAILED(hr)) {
          return Fail("CreateBuffer of " + std::to_string(bd.ByteWidth) + " bytes failed", hr);
        }
        D3D11_SHADER_RESOURCE_VIEW_DESC sd = {};
        sd.Format = DXGI_FORMAT_UNKNOWN;
        sd.ViewDimension = D3D11_SRV_DIMENSION_BUFFER;
        sd.Buffer.FirstElement = 0;
        sd.Buffer.NumElements = count;
        hr = dev->CreateShaderResourceView(buf.Get(), &sd, r->entry.srv.Put());
        if (FAILED(hr)) {
          return Fail("CreateShaderResourceView (buffer) failed", hr);
        }
        D3D11_UNORDERED_ACCESS_VIEW_DESC ud = {};
        ud.Format = DXGI_FORMAT_UNKNOWN;
        ud.ViewDimension = D3D11_UAV_DIMENSION_BUFFER;
        ud.Buffer.FirstElement = 0;
        ud.Buffer.NumElements = count;
        ud.Buffer.Flags = 0;
        hr = dev->CreateUnorderedAccessView(buf.Get(), &ud, r->entry.uav.Put());
        if (FAILED(hr)) {
          return Fail("CreateUnorderedAccessView (buffer) failed", hr);
        }
        r->entry.bytes = static_cast<std::uint64_t>(bd.ByteWidth);
        r->entry.res = Com<ID3D11Resource>(
          buf.Detach()
        ); // Detach keeps the reference the new Com owns (ID3D11Buffer derives from ID3D11Resource)
        return r;
      }

      std::expected<std::unique_ptr<Resource>, std::string> CreateTexture(
        const u32 w,
        const u32 h
      ) override
      {
        if (lost) {
          return std::unexpected(lostWhy);
        }
        if (!textures) {
          return std::unexpected("textures are not supported by this device");
        }
        if (w == 0 || h == 0 || w > 16384 || h > 16384 || static_cast<std::uint64_t>(w) * h * 4ull > maxBytes) {
          return std::unexpected("texture size out of range");
        }
        auto r = std::make_unique<D3DResource>();
        r->kind = Resource::Kind::Texture2D;
        r->w = w;
        r->h = h;
        r->key = PoolKey(1, w, h);
        r->pool = pool;
        r->owner = this;
        if (pool->Take(r->key, r->entry)) {
          return r;
        }
        D3D11_TEXTURE2D_DESC td = {};
        td.Width = w;
        td.Height = h;
        td.MipLevels = 1;
        td.ArraySize = 1;
        td.Format = DXGI_FORMAT_R32_FLOAT;
        td.SampleDesc.Count = 1;
        td.SampleDesc.Quality = 0;
        td.Usage = D3D11_USAGE_DEFAULT;
        td.BindFlags = D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_UNORDERED_ACCESS;
        Com<ID3D11Texture2D> tex;
        HRESULT hr = dev->CreateTexture2D(&td, nullptr, tex.Put());
        if (FAILED(hr)) {
          return Fail("CreateTexture2D failed", hr);
        }
        D3D11_SHADER_RESOURCE_VIEW_DESC sd = {};
        sd.Format = DXGI_FORMAT_R32_FLOAT;
        sd.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
        sd.Texture2D.MostDetailedMip = 0;
        sd.Texture2D.MipLevels = 1;
        hr = dev->CreateShaderResourceView(tex.Get(), &sd, r->entry.srv.Put());
        if (FAILED(hr)) {
          return Fail("CreateShaderResourceView (texture) failed", hr);
        }
        D3D11_UNORDERED_ACCESS_VIEW_DESC ud = {};
        ud.Format = DXGI_FORMAT_R32_FLOAT;
        ud.ViewDimension = D3D11_UAV_DIMENSION_TEXTURE2D;
        ud.Texture2D.MipSlice = 0;
        hr = dev->CreateUnorderedAccessView(tex.Get(), &ud, r->entry.uav.Put());
        if (FAILED(hr)) {
          return Fail("CreateUnorderedAccessView (texture) failed", hr);
        }
        r->entry.bytes = static_cast<std::uint64_t>(w) * h * 4ull;
        r->entry.res = Com<ID3D11Resource>(tex.Detach());
        return r;
      }

      std::expected<D3DResource*, std::string> Mine(
        Resource& r
      )
      {
        auto* d = static_cast<D3DResource*>(&r);
        if (d->owner != this || !d->entry.res) {
          return std::unexpected("resource belongs to another executor");
        }
        return d;
      }

      std::expected<void, std::string> Upload(
        Resource& r,
        const void* const data,
        const std::size_t bytes
      ) override
      {
        if (lost) {
          return std::unexpected(lostWhy);
        }
        const auto mine = Mine(r);
        if (!mine) {
          return std::unexpected(mine.error());
        }
        D3DResource* d = *mine;
        if (data == nullptr || bytes == 0 || bytes > r.Bytes()) {
          return std::unexpected("upload size out of range");
        }
        if (r.kind == Resource::Kind::Texture2D) {
          if (bytes != r.Bytes()) {
            return std::unexpected("a texture is uploaded whole");
          }
          ctx->UpdateSubresource(d->entry.res.Get(), 0, nullptr, data, r.w * 4u, 0);
        } else if (bytes == r.Bytes()) {
          ctx->UpdateSubresource(d->entry.res.Get(), 0, nullptr, data, 0, 0);
        } else {
          D3D11_BOX box = {};
          box.left = 0;
          box.right = static_cast<UINT>(bytes);
          box.top = 0;
          box.bottom = 1;
          box.front = 0;
          box.back = 1;
          ctx->UpdateSubresource(d->entry.res.Get(), 0, &box, data, 0, 0);
        }
        return {};
      }

      std::expected<void, std::string> WaitQuery(
        ID3D11Query* const q,
        void* const data,
        const UINT size
      )
      {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kSyncTimeoutMs);
        int spins = 0;
        for (;;) {
          const HRESULT hr = ctx->GetData(q, data, size, 0);
          if (hr == S_OK) {
            return {};
          }
          if (hr != S_FALSE) {
            return Fail("waiting for the GPU failed", hr);
          }
          if (std::chrono::steady_clock::now() > deadline) {
            MarkLost("the GPU did not finish within " + std::to_string(kSyncTimeoutMs) + " ms");
            return std::unexpected(lostWhy);
          }
          if (++spins < 200) {
            Sleep(0);
          } else {
            Sleep(1);
          }
        }
      }

      std::expected<void, std::string> Download(
        Resource& r,
        void* const data,
        const std::size_t bytes
      ) override
      {
        if (lost) {
          return std::unexpected(lostWhy);
        }
        const auto mine = Mine(r);
        if (!mine) {
          return std::unexpected(mine.error());
        }
        D3DResource* d = *mine;
        if (data == nullptr || bytes == 0 || bytes > r.Bytes()) {
          return std::unexpected("download size out of range");
        }
        const bool tex = r.kind == Resource::Kind::Texture2D;
        PoolEntry stage;
        const PoolKey key = tex ? PoolKey(3, r.w, r.h) : PoolKey(2, static_cast<u32>(r.Bytes() / 4), 4);
        if (!pool->Take(key, stage)) {
          if (tex) {
            D3D11_TEXTURE2D_DESC td = {};
            td.Width = r.w;
            td.Height = r.h;
            td.MipLevels = 1;
            td.ArraySize = 1;
            td.Format = DXGI_FORMAT_R32_FLOAT;
            td.SampleDesc.Count = 1;
            td.Usage = D3D11_USAGE_STAGING;
            td.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
            Com<ID3D11Texture2D> t;
            const HRESULT hr = dev->CreateTexture2D(&td, nullptr, t.Put());
            if (FAILED(hr)) {
              return Fail("CreateTexture2D (staging) failed", hr);
            }
            stage.res = Com<ID3D11Resource>(t.Detach());
          } else {
            D3D11_BUFFER_DESC bd = {};
            bd.ByteWidth = static_cast<UINT>(r.Bytes());
            bd.Usage = D3D11_USAGE_STAGING;
            bd.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
            Com<ID3D11Buffer> b;
            const HRESULT hr = dev->CreateBuffer(&bd, nullptr, b.Put());
            if (FAILED(hr)) {
              return Fail("CreateBuffer (staging) failed", hr);
            }
            stage.res = Com<ID3D11Resource>(b.Detach());
          }
          stage.bytes = r.Bytes();
        }
        ctx->CopyResource(stage.res.Get(), d->entry.res.Get());
        if (auto synced = Sync(nullptr); !synced) {
          return synced;
        }
        D3D11_MAPPED_SUBRESOURCE m = {};
        const HRESULT hr = ctx->Map(stage.res.Get(), 0, D3D11_MAP_READ, 0, &m);
        if (FAILED(hr)) {
          return Fail("Map (staging) failed", hr);
        }
        if (tex) {
          const std::size_t rowBytes = static_cast<std::size_t>(r.w) * 4u;
          for (u32 y = 0; y < r.h && (static_cast<std::size_t>(y) + 1) * rowBytes <= bytes; ++y) {
            std::memcpy(
              static_cast<char*>(data) + static_cast<std::size_t>(y) * rowBytes,
              static_cast<const char*>(m.pData) + static_cast<std::size_t>(y) * m.RowPitch,
              rowBytes
            );
          }
        } else {
          std::memcpy(data, m.pData, bytes);
        }
        ctx->Unmap(stage.res.Get(), 0);
        pool->Give(key, std::move(stage));
        return {};
      }

      // ---- shaders
      // ---------------------------------------------------------------------------------------------------------------------------

      std::expected<ID3D11ComputeShader*, std::string> GetShader(
        const KernelInfo& k
      )
      {
        const auto it = shaders.find(k.hash);
        if (it != shaders.end()) {
          return it->second.Get();
        }
        if (compile == nullptr) {
          return std::unexpected("no shader compiler (d3dcompiler_47.dll / d3dcompiler_43.dll) found");
        }
        Com<ID3DBlob> code, errors;
        const auto t0 = std::chrono::steady_clock::now();
        const HRESULT hr = compile(
          k.source,
          std::strlen(k.source),
          k.name,
          nullptr,
          nullptr,
          k.entry,
          "cs_5_0",
          kCompileOptimizationLevel3 | kCompileEnableStrictness,
          0,
          code.Put(),
          errors.Put()
        );
        if (FAILED(hr) || !code) {
          std::string text = errors
            ? std::string(static_cast<const char*>(errors->GetBufferPointer()), errors->GetBufferSize())
            : std::string();
          if (text.size() > 2000) {
            text.resize(2000);
          }
          std::string err = std::string("compiling kernel ") + k.name + " failed (" + Hex(hr) + "): " + text;
          Log("GPU compute: " + err);
          return std::unexpected(std::move(err));
        }
        Com<ID3D11ComputeShader> cs;
        const HRESULT hr2 =
          dev->CreateComputeShader(code->GetBufferPointer(), code->GetBufferSize(), nullptr, cs.Put());
        if (FAILED(hr2)) {
          return Fail(std::string("CreateComputeShader ") + k.name + " failed", hr2);
        }
        Log(
          std::string("GPU compute: compiled kernel ") + k.name + " in " +
          std::to_string(static_cast<int>(MsSince(t0))) + " ms"
        );
        ID3D11ComputeShader* const out = cs.Get();
        shaders[k.hash] = std::move(cs);
        return out;
      }

      std::expected<void, std::string> Dispatch(
        const KernelInfo& k,
        const Groups groups,
        const void* const cb,
        const u32 cbBytes,
        const Bindings& b
      ) override
      {
        if (lost) {
          return std::unexpected(lostWhy);
        }
        if (
          groups.x == 0 || groups.y == 0 || groups.z == 0 || groups.x > kMaxGroups || groups.y > kMaxGroups ||
          groups.z > kMaxGroups
        ) {
          return std::unexpected("dispatch group count out of range");
        }
        if (
          (k.hasCb != 0) != (cb != nullptr) ||
          (k.hasCb != 0 && (cbBytes == 0 || cbBytes % 16 != 0 || cbBytes > kConstantBufferBytes))
        ) {
          return std::unexpected(
            std::string("kernel ") + k.name + ": constant buffer missing, unexpected or not a multiple of 16 bytes"
          );
        }
        ID3D11ShaderResourceView* srvs[kMaxSrv] = {};
        ID3D11UnorderedAccessView* uavs[kMaxUav] = {};
        u32 nSrv = 0;
        u32 nUav = 0;
        for (u32 s = 0; s < kMaxSrv; ++s) {
          if (b.srv[s] == nullptr) {
            if ((k.srvMask >> s) & 1u) {
              return std::unexpected(
                std::string("kernel ") + k.name + ": SRV slot " + std::to_string(s) + " is not bound"
              );
            }
            continue;
          }
          auto* d = static_cast<D3DResource*>(const_cast<Resource*>(b.srv[s]));
          const bool wantTex = ((k.srvTexMask >> s) & 1u) != 0;
          if (d->owner != this || !d->entry.srv || (d->kind == Resource::Kind::Texture2D) != wantTex) {
            return std::unexpected(
              std::string("kernel ") + k.name + ": SRV slot " + std::to_string(s) + " has the wrong resource"
            );
          }
          srvs[s] = d->entry.srv.Get();
          nSrv = s + 1;
        }
        for (u32 s = 0; s < kMaxUav; ++s) {
          if (b.uav[s] == nullptr) {
            if ((k.uavMask >> s) & 1u) {
              return std::unexpected(
                std::string("kernel ") + k.name + ": UAV slot " + std::to_string(s) + " is not bound"
              );
            }
            continue;
          }
          auto* d = static_cast<D3DResource*>(const_cast<Resource*>(b.uav[s]));
          const bool wantTex = ((k.uavTexMask >> s) & 1u) != 0;
          if (d->owner != this || !d->entry.uav || (d->kind == Resource::Kind::Texture2D) != wantTex) {
            return std::unexpected(
              std::string("kernel ") + k.name + ": UAV slot " + std::to_string(s) + " has the wrong resource"
            );
          }
          for (u32 t = 0; t < kMaxSrv; ++t) {
            if (b.srv[t] == b.uav[s]) {
              return std::unexpected(
                std::string("kernel ") + k.name + ": a resource is bound for reading and writing in one dispatch"
              );
            }
          }
          uavs[s] = d->entry.uav.Get();
          nUav = s + 1;
        }
        const auto shader = GetShader(k);
        if (!shader) {
          return std::unexpected(shader.error());
        }
        ID3D11ComputeShader* const cs = *shader;
        if (!timingOpen) {
          ctx->Begin(qDisjoint.Get());
          ctx->End(qStart.Get());
          timingOpen = true;
        }
        if (k.hasCb != 0) {
          D3D11_MAPPED_SUBRESOURCE m = {};
          const HRESULT hr = ctx->Map(cbuf.Get(), 0, D3D11_MAP_WRITE_DISCARD, 0, &m);
          if (FAILED(hr)) {
            return Fail("Map (constant buffer) failed", hr);
          }
          std::memcpy(m.pData, cb, cbBytes);
          ctx->Unmap(cbuf.Get(), 0);
        }
        ctx->CSSetShader(cs, nullptr, 0);
        if (k.hasCb != 0) {
          ID3D11Buffer* cbs[1] = {cbuf.Get()};
          ctx->CSSetConstantBuffers(0, 1, cbs);
        }
        ID3D11SamplerState* smp[2] = {samplers[0].Get(), samplers[1].Get()};
        ctx->CSSetSamplers(0, 2, smp);
        if (nSrv != 0) {
          ctx->CSSetShaderResources(0, nSrv, srvs);
        }
        if (nUav != 0) {
          ctx->CSSetUnorderedAccessViews(0, nUav, uavs, nullptr);
        }
        ctx->Dispatch(groups.x, groups.y, groups.z);
        // unbind again: a buffer left bound as UAV could not be bound as SRV by the next dispatch
        ID3D11ShaderResourceView* noSrv[kMaxSrv] = {};
        ID3D11UnorderedAccessView* noUav[kMaxUav] = {};
        if (nSrv != 0) {
          ctx->CSSetShaderResources(0, nSrv, noSrv);
        }
        if (nUav != 0) {
          ctx->CSSetUnorderedAccessViews(0, nUav, noUav, nullptr);
        }
        return {};
      }

      std::expected<void, std::string> Sync(
        double* const gpuMs
      ) override
      {
        if (gpuMs != nullptr) {
          *gpuMs = 0.0;
        }
        if (lost) {
          return std::unexpected(lostWhy);
        }
        const auto t0 = std::chrono::steady_clock::now();
        if (timingOpen) {
          ctx->End(qEnd.Get());
          ctx->End(qDisjoint.Get());
          timingOpen = false;
          ctx->Flush();
          D3D11_QUERY_DATA_TIMESTAMP_DISJOINT dj = {};
          if (auto waited = WaitQuery(qDisjoint.Get(), &dj, sizeof(dj)); !waited) {
            return waited;
          }
          UINT64 t1 = 0;
          UINT64 t2 = 0;
          auto stamps = WaitQuery(qStart.Get(), &t1, sizeof(t1));
          if (stamps) {
            stamps = WaitQuery(qEnd.Get(), &t2, sizeof(t2));
          }
          if (stamps && !dj.Disjoint && dj.Frequency != 0 && t2 >= t1) {
            if (gpuMs != nullptr) {
              *gpuMs = static_cast<double>(t2 - t1) * 1000.0 / static_cast<double>(dj.Frequency);
            }
          } else if (lost) {
            return std::unexpected(stamps ? lostWhy : stamps.error());
          }
        } else {
          ctx->End(qEvent.Get());
          ctx->Flush();
          BOOL done = FALSE;
          if (auto waited = WaitQuery(qEvent.Get(), &done, sizeof(done)); !waited) {
            return waited;
          }
        }
        if (gpuMs != nullptr && *gpuMs <= 0.0) {
          *gpuMs = MsSince(t0);
        }
        const HRESULT reason = dev->GetDeviceRemovedReason();
        if (reason != S_OK) {
          MarkLost("device removed (" + Hex(reason) + ")");
          return std::unexpected(lostWhy);
        }
        return {};
      }

      /** Called by the backend at the start of a lease: gives back device objects idle for a long time. */
      void Housekeeping()
      {
        pool->Purge(kPoolMaxIdleSeconds);
      }

      /** Creates what every dispatch needs (constant buffer, samplers, queries) and finds out whether R32_FLOAT
       * textures can be sampled and written. */
      std::expected<void, std::string> Prepare(
        const PFN_D3DCompile_ compileFn
      )
      {
        compile = compileFn;
        D3D11_BUFFER_DESC bd = {};
        bd.ByteWidth = kConstantBufferBytes;
        bd.Usage = D3D11_USAGE_DYNAMIC;
        bd.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
        bd.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
        HRESULT hr = dev->CreateBuffer(&bd, nullptr, cbuf.Put());
        if (FAILED(hr)) {
          return Fail("creating the constant buffer failed", hr);
        }
        D3D11_SAMPLER_DESC sd = {};
        sd.Filter = D3D11_FILTER_MIN_MAG_MIP_LINEAR;
        sd.AddressU = D3D11_TEXTURE_ADDRESS_CLAMP;
        sd.AddressV = D3D11_TEXTURE_ADDRESS_CLAMP;
        sd.AddressW = D3D11_TEXTURE_ADDRESS_CLAMP;
        sd.MaxAnisotropy = 1;
        sd.ComparisonFunc = D3D11_COMPARISON_NEVER;
        sd.MinLOD = 0.0f;
        sd.MaxLOD = D3D11_FLOAT32_MAX;
        hr = dev->CreateSamplerState(&sd, samplers[0].Put());
        if (FAILED(hr)) {
          return Fail("creating the linear sampler failed", hr);
        }
        sd.Filter = D3D11_FILTER_MIN_MAG_MIP_POINT;
        hr = dev->CreateSamplerState(&sd, samplers[1].Put());
        if (FAILED(hr)) {
          return Fail("creating the point sampler failed", hr);
        }
        D3D11_QUERY_DESC qd = {};
        qd.Query = D3D11_QUERY_EVENT;
        hr = dev->CreateQuery(&qd, qEvent.Put());
        if (FAILED(hr)) {
          return Fail("creating the event query failed", hr);
        }
        qd.Query = D3D11_QUERY_TIMESTAMP_DISJOINT;
        hr = dev->CreateQuery(&qd, qDisjoint.Put());
        if (FAILED(hr)) {
          return Fail("creating the timestamp query failed", hr);
        }
        qd.Query = D3D11_QUERY_TIMESTAMP;
        hr = dev->CreateQuery(&qd, qStart.Put());
        if (SUCCEEDED(hr)) {
          hr = dev->CreateQuery(&qd, qEnd.Put());
        }
        if (FAILED(hr)) {
          return Fail("creating the timestamp query failed", hr);
        }
        UINT fs = 0;
        UINT tex2d = 0;
        if (SUCCEEDED(dev->CheckFormatSupport(DXGI_FORMAT_R32_FLOAT, &fs))) {
          tex2d = fs & D3D11_FORMAT_SUPPORT_TEXTURE2D;
        }
        const bool sample = (fs & D3D11_FORMAT_SUPPORT_SHADER_SAMPLE) != 0;
        D3D11_FEATURE_DATA_FORMAT_SUPPORT2 f2 = {};
        f2.InFormat = DXGI_FORMAT_R32_FLOAT;
        const bool store = SUCCEEDED(dev->CheckFeatureSupport(D3D11_FEATURE_FORMAT_SUPPORT2, &f2, sizeof(f2))) &&
          (f2.OutFormatSupport2 & D3D11_FORMAT_SUPPORT2_UAV_TYPED_STORE) != 0;
        textures = tex2d != 0 && sample && store;
        return {};
      }
    };

    // ---- the backend
    // -------------------------------------------------------------------------------------------------------------------------

    struct Candidate
    {
      Com<IDXGIAdapter1> adapter;
      DXGI_ADAPTER_DESC1 desc = {};
      bool preferred = false;
    };

    class D3D11Backend final : public Backend
    {
    public:
      ~D3D11Backend() override
      {
        // process exit: a healthy device is released properly, a failed or stuck one is left to the operating system
        if (failed_) {
          (void)exec_.release();
        }
      }

      BackendInfo Info(
        const bool probe
      ) override
      {
        if (probe && !tHolding && !tried_) {
          bool busy = false;
          std::string err;
          if (Executor* ex = Acquire(true, busy, err); ex != nullptr) {
            Release();
          }
        }
        const std::lock_guard<std::mutex> lock(infoMutex_);
        BackendInfo i = info_;
        i.compiledIn = true;
        i.failed = failed_;
        i.tried = tried_;
        i.available = available_ && !failed_;
        i.lastError = lastError_;
        return i;
      }

      bool MayWork() override
      {
        const std::lock_guard<std::mutex> lock(infoMutex_);
        return !failed_ && !(tried_ && !available_);
      }

      Executor* Acquire(
        const bool wait,
        bool& busy,
        std::string& err
      ) override
      {
        busy = false;
        std::unique_lock<std::mutex> lk(use_, std::defer_lock);
        if (wait) {
          lk.lock();
        } else if (!lk.try_lock()) {
          busy = true;
          err = "the GPU is busy with another operation";
          return nullptr;
        }
        {
          const std::lock_guard<std::mutex> lock(infoMutex_);
          if (failed_) {
            err = lastError_.empty() ? std::string("the GPU backend is off for this session") : lastError_;
            return nullptr;
          }
        }
        if (!tried_) {
          Init();
        }
        if (!exec_ || !available_) {
          const std::lock_guard<std::mutex> lock(infoMutex_);
          err = lastError_.empty() ? std::string("the GPU backend is not available") : lastError_;
          return nullptr;
        }
        exec_->Housekeeping();
        (void)lk.release(); // stays locked until Release()
        return exec_.get();
      }

      void Release() override
      {
        use_.unlock();
      }

      void MarkFailed(
        const std::string& why
      ) override
      {
        const std::lock_guard<std::mutex> lock(infoMutex_);
        if (!failed_) {
          failed_ = true;
          lastError_ = why;
          Log("GPU compute: backend switched off for this session: " + why);
        }
      }

      void Reset() override
      {
        if (tHolding) {
          return; // the thread that holds a lease cannot reset the device under itself
        }
        const std::lock_guard<std::mutex> useLock(use_);
        // a failed device is abandoned (leaked), a healthy one released
        if (failed_) {
          (void)exec_.release();
        } else {
          exec_.reset();
        }
        const std::lock_guard<std::mutex> lock(infoMutex_);
        failed_ = false;
        tried_ = false;
        available_ = false;
        lastError_.clear();
        info_ = BackendInfo();
      }

    private:
      void SetError(
        const std::string& e
      )
      {
        const std::lock_guard<std::mutex> lock(infoMutex_);
        lastError_ = e;
        Log("GPU compute: " + e);
      }

      void Init()
      {
        tried_ = true;
        try {
          InitDevice();
        } catch (...) {
          exec_.reset();
          available_ = false;
          SetError("exception while creating the Direct3D 11 device");
        }
      }

      void InitDevice()
      {
        const HMODULE d3d11 = LoadLibraryA("d3d11.dll");
        if (d3d11 == nullptr) {
          SetError("d3d11.dll not found (Direct3D 11 is not installed)");
          return;
        }
        const auto create = reinterpret_cast<PFN_D3D11_CREATE_DEVICE>(
          reinterpret_cast<void*>(GetProcAddress(d3d11, "D3D11CreateDevice"))
        );
        const HMODULE dxgi = LoadLibraryA("dxgi.dll");
        const auto createFactory = dxgi != nullptr
          ? reinterpret_cast<PFN_CreateDXGIFactory1_>(
              reinterpret_cast<void*>(GetProcAddress(dxgi, "CreateDXGIFactory1"))
            )
          : nullptr;
        if (create == nullptr || createFactory == nullptr) {
          SetError("D3D11CreateDevice / CreateDXGIFactory1 not found");
          return;
        }
        // the shader compiler: 47 (Windows 10), else 43 (the June 2010 SDK redistributable)
        const char* compilerName = "d3dcompiler_47.dll";
        HMODULE compiler = LoadLibraryA(compilerName);
        if (compiler == nullptr) {
          compilerName = "d3dcompiler_43.dll";
          compiler = LoadLibraryA(compilerName);
        }
        PFN_D3DCompile_ compileFn = compiler != nullptr
          ? reinterpret_cast<PFN_D3DCompile_>(reinterpret_cast<void*>(GetProcAddress(compiler, "D3DCompile")))
          : nullptr;
        if (compileFn == nullptr) {
          SetError("no shader compiler: d3dcompiler_47.dll / d3dcompiler_43.dll not found");
          return;
        }

        // adapters: hardware only; the one the game's Direct3D 11 device runs on first, then by dedicated video memory
        Com<IDXGIFactory1> factory;
        HRESULT hr = createFactory(__uuidof(IDXGIFactory1), reinterpret_cast<void**>(factory.Put()));
        if (FAILED(hr)) {
          SetError("CreateDXGIFactory1 failed (" + Hex(hr) + ")");
          return;
        }
        std::vector<Candidate> list;
        for (UINT i = 0;; ++i) {
          Candidate c;
          if (factory->EnumAdapters1(i, c.adapter.Put()) != S_OK) {
            break;
          }
          if (FAILED(c.adapter->GetDesc1(&c.desc))) {
            continue;
          }
          if ((c.desc.Flags & kAdapterFlagSoftware) != 0 || c.desc.VendorId == 0x1414) {
            continue; // WARP / the basic render driver: far slower than the CPU ops
          }
          c.preferred = gPreferredVendor.load() != 0 && c.desc.VendorId == gPreferredVendor.load() &&
            (gPreferredDevice.load() == 0 || c.desc.DeviceId == gPreferredDevice.load());
          list.push_back(std::move(c));
        }
        if (list.empty()) {
          SetError("no hardware adapter");
          return;
        }
        std::stable_sort(list.begin(), list.end(), [](const Candidate& a, const Candidate& b) {
          if (a.preferred != b.preferred) {
            return a.preferred;
          }
          return a.desc.DedicatedVideoMemory > b.desc.DedicatedVideoMemory;
        });

        std::string lastFail;
        for (Candidate& c : list) {
          auto ex = std::make_unique<D3D11Executor>();
          const D3D_FEATURE_LEVEL wanted[1] = {D3D_FEATURE_LEVEL_11_0};
          D3D_FEATURE_LEVEL got = D3D_FEATURE_LEVEL_9_1;
          hr = create(
            c.adapter.Get(),
            D3D_DRIVER_TYPE_UNKNOWN,
            nullptr,
            0,
            wanted,
            1,
            D3D11_SDK_VERSION,
            ex->dev.Put(),
            &got,
            ex->ctx.Put()
          );
          if (FAILED(hr) || !ex->dev || !ex->ctx) {
            lastFail =
              Narrow(c.desc.Description) + ": D3D11CreateDevice at feature level 11_0 failed (" + Hex(hr) + ")";
            continue;
          }
          if (got < D3D_FEATURE_LEVEL_11_0) {
            lastFail = Narrow(c.desc.Description) + ": feature level below 11_0";
            continue;
          }
          if (auto prepared = ex->Prepare(compileFn); !prepared) {
            lastFail = Narrow(c.desc.Description) + ": " + prepared.error();
            continue;
          }
          const std::uint64_t dedicated = static_cast<std::uint64_t>(c.desc.DedicatedVideoMemory);
          const std::uint64_t shared = static_cast<std::uint64_t>(c.desc.SharedSystemMemory);
          const std::uint64_t base = dedicated != 0 ? dedicated : shared / 4;
          ex->maxBytes = std::max<std::uint64_t>(256ull << 20, std::min<std::uint64_t>(base / 2, 3ull << 30));
          {
            const std::lock_guard<std::mutex> lock(infoMutex_);
            info_.adapter = Narrow(c.desc.Description);
            info_.vramMB = dedicated >> 20;
            info_.featureLevel = static_cast<int>(got) == 0xb100
              ? "11_1"
              : "11_0"; // D3D_FEATURE_LEVEL_11_1 is not in the June 2010 SDK's headers
            info_.compiler = compilerName;
            info_.textures = ex->textures;
            info_.maxBytes = ex->maxBytes;
            lastError_.clear();
          }
          exec_ = std::move(ex);
          available_ = true;
          Log(
            "GPU compute: using " + info_.adapter + " (" + std::to_string(info_.vramMB) + " MB, feature level " +
            info_.featureLevel + ", " + compilerName + ")"
          );
          return;
        }
        SetError(lastFail.empty() ? std::string("no adapter supports feature level 11_0") : lastFail);
      }

      std::mutex use_;       // held by the Lease
      std::mutex infoMutex_; // the state below; never held while waiting for the device
      std::unique_ptr<D3D11Executor> exec_;
      std::atomic<bool> tried_{false};
      std::atomic<bool> available_{false};
      bool failed_ = false; // under infoMutex_
      std::string lastError_;
      BackendInfo info_;
    };
  } // namespace
} // namespace faf::editor::gpu

#endif // FAFRE_PLATFORM_WINDOWS

namespace faf::editor::gpu
{
#if !FAFRE_PLATFORM_WINDOWS
  namespace
  {
    /** Built without Direct3D 11 (the tests on other systems): never available. */
    class NullBackend final : public Backend
    {
    public:
      BackendInfo Info(
        bool
      ) override
      {
        BackendInfo i;
        i.lastError = "built without Direct3D 11";
        return i;
      }
      bool MayWork() override
      {
        return false;
      }
      Executor* Acquire(
        bool,
        bool& busy,
        std::string& err
      ) override
      {
        busy = false;
        err = "built without Direct3D 11";
        return nullptr;
      }
      void Release() override {}
      void MarkFailed(
        const std::string&
      ) override
      {}
      void Reset() override {}
    };
  } // namespace
#endif

  Backend& CurrentBackend()
  {
    if (gOverride != nullptr) {
      return *gOverride;
    }
#if FAFRE_PLATFORM_WINDOWS
    static D3D11Backend backend;
#else
    static NullBackend backend;
#endif
    return backend;
  }
} // namespace faf::editor::gpu
