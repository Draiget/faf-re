// EDITOR GPU compute backend (docs/projects/editor/GPU_COMPUTE.md). A SEPARATE Direct3D 11 device with compute shaders
// (cs_5_0) next to the game's Direct3D 11 renderer: the field engine's heavy ops (erosion, generators, filters) can run
// there and fall back to the CPU ops on any problem.
//
// This header is plain C++ (no Windows, no Direct3D): the kernels, the op glue and the tests use it, only EdGpu.cpp
// knows Direct3D 11. The pieces:
//
//   KernelInfo      one compute shader: name, HLSL source (embedded by scripts/gen_gpu_shaders.py from
//   gpu/<name>.hlsl), thread group size, which slots it uses. Resource        a structured buffer (element count x
//   stride) or an R32_FLOAT 2D texture on the device. Made by an Executor, owned by the caller (unique_ptr). Executor
//   what runs kernels: the Direct3D 11 one (EdGpu.cpp) or the CPU emulator of the tests (tests/EdGpuEmu.h). Create /
//   Upload / Download / Dispatch / Sync. Backend, Lease  the process-wide access: `Lease lease; if (!lease) { /* CPU */
//   } Executor& ex = *lease;` takes the one lock, creates the device on first use, never throws. Field, PingPong
//   helpers for fields (w * h floats) and double buffering; DispatchGrid for a kernel over a 2D grid; RunIterations for
//   long loops in time-limited submissions.
//
// Rules for everything that runs on an Executor (the full text is in the document): bool results with `err` set, never
// an exception through the API, never a wait without a limit, resources must not outlive the Lease they were made
// under, and an op that fails leaves its output untouched so the CPU op can run instead.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

#include "editor/terrain/EdFieldCore.h"

namespace faf::editor::gpu
{
  using u32 = std::uint32_t;
  using u64 = std::uint64_t;

  inline constexpr u32 kMaxSrv = 16;
  inline constexpr u32 kMaxUav = 8;
  inline constexpr u32 kMaxSamplers = 2;   // s0 linear + clamp, s1 point + clamp
  inline constexpr u32 kMaxGroups = 65535; // per dimension (cs_5_0)

  // ---- kernels
  // -------------------------------------------------------------------------------------------------------------------------------

  /** One compute shader. The table kKernels (EdGpuShaders.generated.h) is generated; a kernel is found by name with
   * FindKernel. */
  struct KernelInfo
  {
    const char* name;   // the file name without .hlsl
    const char* source; // the complete HLSL text (prelude + kernel + inlined includes)
    const char* entry;  // "CSMain"
    u32 tx, ty, tz;     // threads per group (NUMTHREADS)
    u32 srvMask;        // bit s = the kernel reads slot t<s>
    u32 uavMask;        // bit s = the kernel writes slot u<s>
    u32 srvTexMask;     // the slots of srvMask that are textures (the others are structured buffers)
    u32 uavTexMask;
    u32 samplerMask;
    u32 hasCb; // 1 = constant buffer b0
    u64 hash;  // FNV-1a of source: the key of the compiled-shader caches
  };

  /** The generated kernel `name`, or null. */
  [[nodiscard]] const KernelInfo* FindKernel(const char* name);
  /** Number of generated kernels. */
  [[nodiscard]] int KernelCount();
  [[nodiscard]] const KernelInfo& KernelAt(int index);

  // ---- resources
  // -----------------------------------------------------------------------------------------------------------------------------

  /** A buffer or texture on the device. The fields are read-only for everyone but the Executor that made it. */
  class Resource
  {
  public:
    enum class Kind
    {
      Buffer,
      Texture2D
    };
    virtual ~Resource() = default;
    Kind kind = Kind::Buffer;
    u32 count = 0;  // buffer: elements
    u32 stride = 4; // buffer: bytes per element
    u32 w = 0;      // texture: size
    u32 h = 0;
    [[nodiscard]] std::size_t Bytes() const
    {
      return kind == Kind::Buffer ? static_cast<std::size_t>(count) * stride : static_cast<std::size_t>(w) * h * 4u;
    }
  };

  /** The resources of one dispatch by slot (null = unbound). A resource must not appear as SRV and UAV of the same
   * dispatch. */
  struct Bindings
  {
    const Resource* srv[kMaxSrv] = {};
    const Resource* uav[kMaxUav] = {};
    Bindings& Srv(
      const u32 slot,
      const Resource& r
    )
    {
      if (slot < kMaxSrv)
        srv[slot] = &r;
      return *this;
    }
    Bindings& Uav(
      const u32 slot,
      const Resource& r
    )
    {
      if (slot < kMaxUav)
        uav[slot] = &r;
      return *this;
    }
  };

  struct Groups
  {
    u32 x = 1, y = 1, z = 1;
  };

  /**
   * Runs kernels. All calls come from the thread that holds the Lease. Every method returns false with `err` set
   * instead of throwing. Resource contents are undefined after CreateBuffer / CreateTexture (a recycled buffer is not
   * cleared): Upload or write them before reading.
   */
  class Executor
  {
  public:
    virtual ~Executor() = default;
    [[nodiscard]] virtual const char* Name() const = 0;
    /** A structured buffer of `count` elements of `stride` bytes (a multiple of 4). */
    virtual std::unique_ptr<Resource> CreateBuffer(u32 count, u32 stride, std::string& err) = 0;
    /** An R32_FLOAT texture, shader resource and unordered access. */
    virtual std::unique_ptr<Resource> CreateTexture(u32 w, u32 h, std::string& err) = 0;
    virtual bool Upload(Resource& r, const void* data, std::size_t bytes, std::string& err) = 0;
    /** Waits for the device (with a time limit) and copies the resource into `data` (bytes <= r.Bytes()). */
    virtual bool Download(Resource& r, void* data, std::size_t bytes, std::string& err) = 0;
    /** `cb`/`cbBytes`: the constant buffer b0 (bytes a multiple of 16, at most 4096; null when the kernel has none). */
    virtual bool
    Dispatch(const KernelInfo& k, Groups groups, const void* cb, u32 cbBytes, const Bindings& b, std::string& err) = 0;
    /** Submits everything queued and waits for it (with a time limit). `gpuMs` (may be null) = device time of the work
     * since the last Sync, or the wall time when unknown. */
    virtual bool Sync(double* gpuMs, std::string& err) = 0;
    /** Largest total size of resources one op may hold (a fraction of the video memory). */
    [[nodiscard]] virtual u64 MaxBytes() const = 0;
    [[nodiscard]] virtual bool SupportsTextures() const
    {
      return true;
    }
    /** True once the device was removed / reset / timed out: the caller reports it with Lease::Fail and stops using the
     * GPU. */
    [[nodiscard]] virtual bool DeviceLost() const
    {
      return false;
    }
  };

  // ---- backend
  // -------------------------------------------------------------------------------------------------------------------------------

  struct BackendInfo
  {
    bool compiledIn = false; // false: built without Direct3D 11 (tests on other systems)
    bool tried = false;      // device creation was attempted
    bool available = false;  // a device exists and works
    bool failed = false;     // marked unavailable for the rest of the session (error, device removed, timeout)
    bool textures = false;
    std::string adapter;
    std::string featureLevel;
    std::string compiler; // d3dcompiler_47.dll ...
    std::string lastError;
    u64 vramMB = 0;
    u64 maxBytes = 0;
  };

  class Backend
  {
  public:
    virtual ~Backend() = default;
    /** What is known now; `probe` = try to create the device first when that has not been tried (blocks while another
     * thread uses the device). */
    virtual BackendInfo Info(bool probe) = 0;
    /** false when the backend is known not to work (not compiled in, creation failed, marked failed): ops skip the GPU
     * without taking the lock. */
    virtual bool MayWork() = 0;
    /** Takes the lock and returns the executor (creating the device on first use), or null (busy / unavailable; `err`
     * says why). Pair with Release(). */
    virtual Executor* Acquire(bool wait, bool& busy, std::string& err) = 0;
    virtual void Release() = 0;
    /** The device is unusable: every later Acquire returns null until Reset. Does not release the device objects (they
     * may be stuck). */
    virtual void MarkFailed(const std::string& why) = 0;
    /** Forgets a failure and the device so the next use creates a new one. */
    virtual void Reset() = 0;
  };

  /** Where the backend writes its log lines (shader compile errors, device creation, failures). EdGpuLua.cpp points it
   * at the engine's log; null = no log. */
  using LogFn = void (*)(const char* line);
  void SetLogSink(LogFn fn);

  /** The process-wide backend (Direct3D 11 on Windows). */
  [[nodiscard]] Backend& CurrentBackend();
  /** Tests: use `b` instead (null restores the real one). */
  void SetBackendForTest(Backend* b);
  /** The adapter the game's Direct3D 11 device runs on (0 = unknown): the backend prefers the same vendor / device.
   * Call from the thread that owns the game's device. */
  void SetPreferredAdapter(u32 vendorId, u32 deviceId);

  /** RAII access to the backend: holds its lock while alive. Not copyable. A thread that already holds a Lease gets
   * none (no nested use). */
  class Lease
  {
  public:
    explicit Lease(bool wait = false);
    ~Lease();
    Lease(const Lease&) = delete;
    Lease& operator=(const Lease&) = delete;
    explicit operator bool() const noexcept
    {
      return ex_ != nullptr;
    }
    [[nodiscard]] Executor& operator*() const noexcept
    {
      return *ex_;
    }
    [[nodiscard]] Executor* operator->() const noexcept
    {
      return ex_;
    }
    [[nodiscard]] bool Busy() const noexcept
    {
      return busy_;
    }
    [[nodiscard]] const std::string& Error() const noexcept
    {
      return err_;
    }
    /** Reports a failure the device is to blame for (device removed, timeout): the backend stays off for the session.
     */
    void Fail(const std::string& why);

  private:
    Executor* ex_ = nullptr;
    Backend* backend_ = nullptr;
    bool busy_ = false;
    std::string err_;
  };

  // ---- helpers on top of an Executor
  // ---------------------------------------------------------------------------------------------------------

  /** w * h floats on the device. */
  struct Field
  {
    std::unique_ptr<Resource> buf;
    int w = 0;
    int h = 0;
    [[nodiscard]] explicit operator bool() const
    {
      return buf != nullptr;
    }
    [[nodiscard]] const Resource& R() const
    {
      return *buf;
    }
    [[nodiscard]] Resource& R()
    {
      return *buf;
    }
  };

  [[nodiscard]] bool MakeField(Executor& ex, int w, int h, Field& out, std::string& err);
  /** Uploads w * h floats. */
  [[nodiscard]] bool UploadField(Executor& ex, Field& f, const float* data, std::string& err);
  [[nodiscard]] bool DownloadField(Executor& ex, Field& f, float* data, std::string& err);
  /** MakeField + UploadField of a grid. */
  [[nodiscard]] bool UploadGrid(Executor& ex, const field::Grid& g, Field& out, std::string& err);
  /** Downloads into `g`, which must have the field's size. */
  [[nodiscard]] bool DownloadGrid(Executor& ex, Field& f, field::Grid& g, std::string& err);
  /** A buffer of floats / uints (weights, counters): count elements of 4 bytes. */
  [[nodiscard]] bool MakeBuffer(Executor& ex, u32 count, std::unique_ptr<Resource>& out, std::string& err);
  [[nodiscard]] bool UploadBuffer(Executor& ex, Resource& r, const void* data, std::size_t bytes, std::string& err);
  /** Sets every 4 byte word of a buffer to `pattern` (0 = zero floats / zero counters; uploads a host array: for set-up
   * between iterations, not for use inside a loop). */
  [[nodiscard]] bool FillBuffer(Executor& ex, Resource& r, u32 pattern, std::string& err);
  /** An R32_FLOAT texture holding a field (copied on the device with the buf_to_tex kernel). */
  [[nodiscard]] bool
  MakeTextureFromField(Executor& ex, const Field& f, std::unique_ptr<Resource>& tex, std::string& err);

  /** Two fields of one size; kernels read Src() and write Dst(), Flip() swaps them. */
  struct PingPong
  {
    Field f[2];
    int cur = 0; // f[cur] is the source
    [[nodiscard]] bool Make(
      Executor& ex,
      int w,
      int h,
      std::string& err
    )
    {
      return MakeField(ex, w, h, f[0], err) && MakeField(ex, w, h, f[1], err);
    }
    [[nodiscard]] Field& Src()
    {
      return f[cur];
    }
    [[nodiscard]] Field& Dst()
    {
      return f[1 - cur];
    }
    void Flip()
    {
      cur = 1 - cur;
    }
  };

  /** Groups needed to cover w x h (x, y) threads with kernel k; false when that is more than the hardware's group
   * count. */
  [[nodiscard]] bool GroupsFor(const KernelInfo& k, u32 w, u32 h, Groups& g, std::string& err);

  /** Dispatches kernel k over a w x h grid with the constant buffer `params` (a struct of 4 byte members, size a
   * multiple of 16). */
  template <class T>
  [[nodiscard]] bool DispatchGrid(
    Executor& ex,
    const KernelInfo& k,
    u32 w,
    u32 h,
    const T& params,
    const Bindings& b,
    std::string& err
  )
  {
    static_assert(sizeof(T) % 16 == 0, "constant buffer structs are padded to 16 bytes");
    static_assert(std::is_trivially_copyable_v<T>, "constant buffer structs are plain data");
    Groups g;
    return GroupsFor(k, w, h, g, err) && ex.Dispatch(k, g, &params, static_cast<u32>(sizeof(T)), b, err);
  }

  /** A dispatch of a kernel without a constant buffer. */
  [[nodiscard]] bool
  DispatchGridNoCb(Executor& ex, const KernelInfo& k, u32 w, u32 h, const Bindings& b, std::string& err);

  struct IterStats
  {
    u32 iterations = 0;
    u32 submits = 0;
    double totalMs = 0.0;
    double maxSubmitMs = 0.0;
    u32 largestBatch = 0;
  };

  /**
   * Runs step(0) ... step(count - 1) (each one a short sequence of dispatches) in submissions that take about
   * `targetMs` each (0 = 60): after every batch the work is submitted and waited for (Sync), the time it took sets the
   * size of the next batch. This keeps one submission far below the 2 second limit after which Windows resets the
   * driver (TDR). The first batch is one iteration. If one iteration alone is slower than the target it still runs as
   * one batch (it cannot be split); `stats->maxSubmitMs` shows it. false when a step or a Sync fails (`err` set); the
   * iterations done are in stats.
   */
  [[nodiscard]] bool RunIterations(
    Executor& ex,
    u32 count,
    double targetMs,
    const std::function<bool(u32 iteration, std::string& err)>& step,
    std::string& err,
    IterStats* stats = nullptr
  );

  /** Next batch size from the batch just measured (exposed for the test): `ms` for `batch` iterations, target
   * `targetMs`, `remaining` iterations left. */
  [[nodiscard]] u32 NextBatch(u32 batch, double ms, double targetMs, u32 remaining);

} // namespace faf::editor::gpu
