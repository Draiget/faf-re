#pragma once

// FAF addition, not in the shipped binary.
//
// The GPU-driven part of gal: buffers shaders read (and compute shaders write),
// engine-owned shader programs that pull their vertices from those buffers,
// compute dispatches, and draws whose counts come from a buffer. A backend
// that implements them says so through `Device::GetGpuDrivenFeatures()`; the
// base `Device` answers 0 and turns every call into a no-op, so a caller always
// asks first and keeps its original path when the answer is 0.
//
// The binding model is deliberately small and fixed, so every backend can map
// it the same way:
//   b0         one constant block, copied at the call (`GpuBindings::constants`)
//   t0..t3     read buffers (StructuredBuffer<T> / ByteAddressBuffer)
//   t4..t5     textures, sampled through s0 (the program's `GpuSampler`)
//   u0..u1     writable buffers (compute only)
// D3D11 binds those registers directly. D3D12: one root signature (root CBV
// or root constants at b0, an SRV table t0..t5, a UAV table u0..u1, s0 as a
// static sampler) and one PSO per program. Vulkan: one descriptor set with the
// same nine bindings (DXC -fvk-b-shift/-fvk-t-shift/-fvk-u-shift/-fvk-s-shift
// separate the register classes) and one pipeline per program.
//
// Shader programs are HLSL source compiled by the backend: vs_5_0/ps_5_0/cs_5_0
// with d3dcompiler for D3D11, DXIL or SPIR-V with DXC for D3D12/Vulkan. Sources
// must stay inside the subset all three accept (no effect-framework syntax,
// explicit registers, 32-bit types only).

#include <cstddef>
#include <cstdint>

namespace gpg::gal
{
  class IndexBuffer;
  class Texture;

  /** Capability bits of `Device::GetGpuDrivenFeatures()`. */
  enum GpuDrivenFeature : std::uint32_t
  {
    /// `CreateGpuBuffer`, `UpdateGpuBuffer`, `CreateGpuProgram` with a vertex and pixel entry, `DrawGpuProgram`.
    kGpuFeatureVertexPulling = 1U << 0U,
    /// `CreateGpuProgram` with a compute entry, writable buffers, `DispatchGpuProgram`.
    kGpuFeatureCompute = 1U << 1U,
    /// `GpuDrawCall::indirectArgs`.
    kGpuFeatureIndirectDraw = 1U << 2U,
    /// `BeginProfileRegion` / `EndProfileRegion` measure GPU time.
    kGpuFeatureTimestamps = 1U << 3U,
    /// `Device::CopyVertexBufferRegion` copies on the GPU.
    kGpuFeatureBufferCopy = 1U << 4U,
  };

  /**
   * The engine's GPU-driven render paths, as `Device::GetGpuDrivenVerified()`
   * reports them: each bit says the backend has passed that path's parity
   * checks (self-check readback, same-process screenshot A/B). A path's
   * console variable at -1 (auto, the default) turns it on only where the
   * backend has both the features it needs and its verified bit; 1 forces it
   * on wherever the features exist, 0 turns it off.
   */
  enum GpuDrivenPath : std::uint32_t
  {
    kGpuPathStrategicIcons = 1U << 0U,  ///< `ren_GpuIcons`
    kGpuPathIconClassify = 1U << 1U,    ///< `ren_GpuIconClassify`
    kGpuPathFogOfWar = 1U << 2U,        ///< `ren_GpuFog`
    kGpuPathSelectBrackets = 1U << 3U,  ///< `ren_GpuSelectBrackets`
    kGpuPathParticleBatch = 1U << 4U,   ///< `ren_ParticleBatch`
    kGpuPathProjectileIcons = 1U << 5U, ///< `ren_GpuProjectileIcons`
  };

  enum class GpuBufferKind : std::uint8_t
  {
    /// `StructuredBuffer<T>` (`RWStructuredBuffer<T>` when shader-writable), `stride` bytes per element.
    Structured,
    /// Draw arguments: `{vertexCountPerInstance, instanceCount, startVertex, startInstance}` uint
    /// quadruples a compute shader may write (`RWByteAddressBuffer`); `stride` must be 16.
    IndirectArgs,
  };

  struct GpuBufferDesc
  {
    const char* name = "";
    std::uint32_t stride = 0U;   ///< bytes per element, a multiple of 4
    std::uint32_t capacity = 0U; ///< elements
    GpuBufferKind kind = GpuBufferKind::Structured;
    bool shaderWrite = false;    ///< a compute shader writes it (u0..u1)
  };

  /** One GPU buffer. Contents persist until overwritten by `UpdateGpuBuffer` or a compute shader. */
  class GpuBuffer
  {
  public:
    explicit GpuBuffer(const GpuBufferDesc& desc) noexcept
      : mDesc(desc)
    {}
    virtual ~GpuBuffer() = default;
    GpuBuffer(const GpuBuffer&) = delete;
    GpuBuffer& operator=(const GpuBuffer&) = delete;

    [[nodiscard]] const GpuBufferDesc& Desc() const noexcept { return mDesc; }

  protected:
    GpuBufferDesc mDesc;
  };

  enum class GpuBlend : std::uint8_t
  {
    Opaque,
    AlphaBlend, ///< src * srcAlpha + dst * (1 - srcAlpha)
    Additive,   ///< src * srcAlpha + dst
  };

  enum class GpuCompare : std::uint8_t
  {
    Never,
    Less,
    Equal,
    LessEqual,
    Greater,
    NotEqual,
    GreaterEqual,
    Always,
  };

  enum class GpuStencilOp : std::uint8_t
  {
    Keep,
    Zero,
    Replace,
    IncrementSaturate,
    DecrementSaturate,
    Invert,
    Increment, ///< wraps, as D3D9's D3DSTENCILOP_INCR
    Decrement, ///< wraps, as D3D9's D3DSTENCILOP_DECR
  };

  struct GpuStencilFace
  {
    GpuStencilOp fail = GpuStencilOp::Keep;
    GpuStencilOp depthFail = GpuStencilOp::Keep;
    GpuStencilOp pass = GpuStencilOp::Keep;
    GpuCompare func = GpuCompare::Always;
  };

  /** Stencil test of a program; front faces are the clockwise ones. */
  struct GpuStencil
  {
    bool enable = false;
    std::uint8_t readMask = 0xFFU;
    std::uint8_t writeMask = 0xFFU;
    std::uint8_t reference = 0U;
    GpuStencilFace front{};
    GpuStencilFace back{};
  };

  enum class GpuSampler : std::uint8_t
  {
    PointClamp,
    LinearClamp,
    LinearWrap,
  };

  struct GpuProgramDesc
  {
    const char* name = "";
    const char* source = nullptr;
    std::size_t sourceBytes = 0U;
    const char* vertexEntry = nullptr;  ///< with `pixelEntry`: a draw program
    const char* pixelEntry = nullptr;
    const char* computeEntry = nullptr; ///< alone: a compute program
    GpuBlend blend = GpuBlend::Opaque;
    std::uint8_t colorWriteMask = 0x0FU; ///< bit 0 red .. bit 3 alpha
    bool depthTest = false;              ///< `depthFunc` against the bound depth target
    bool depthWrite = false;
    GpuCompare depthFunc = GpuCompare::LessEqual;
    bool depthClip = true;               ///< clip to the near/far planes, as D3D9 always does
    GpuStencil stencil{};
    /// Keep the depth-stencil state already bound instead of the four fields above: the program
    /// stands in for an effect pass that sets none of its own. D3D12/Vulkan, which bake depth into
    /// the pipeline, take it from the engine's current depth state at the draw.
    bool inheritDepthStencil = false;
    bool cullBackFaces = false;
    GpuSampler sampler = GpuSampler::PointClamp;
  };

  /** One compiled program with its fixed render state. */
  class GpuProgram
  {
  public:
    GpuProgram() = default;
    virtual ~GpuProgram() = default;
    GpuProgram(const GpuProgram&) = delete;
    GpuProgram& operator=(const GpuProgram&) = delete;
  };

  inline constexpr std::uint32_t kGpuMaxReadBuffers = 4U;
  inline constexpr std::uint32_t kGpuMaxTextures = 2U;
  inline constexpr std::uint32_t kGpuMaxWriteBuffers = 2U;
  inline constexpr std::uint32_t kGpuMaxConstantBytes = 4096U;

  struct GpuBindings
  {
    const void* constants = nullptr; ///< b0, copied at the call
    std::uint32_t constantBytes = 0U; ///< a multiple of 16, at most `kGpuMaxConstantBytes`
    GpuBuffer* readBuffers[kGpuMaxReadBuffers]{};   ///< t0..t3
    Texture* textures[kGpuMaxTextures]{};           ///< t4..t5
    GpuBuffer* writeBuffers[kGpuMaxWriteBuffers]{}; ///< u0..u1, compute only
  };

  /**
   * A triangle-list draw of `program` into the bound colour/depth targets and
   * viewport. Vertices come from the shader (SV_VertexID / SV_InstanceID), not
   * from vertex buffers. With `indexBuffer`, `vertexCountPerInstance` indices
   * are read from it and SV_VertexID is the index value (base vertex 0). With
   * `indirectArgs` the counts are read from that buffer at
   * `indirectArgsOffset` instead (non-indexed only).
   */
  struct GpuDrawCall
  {
    GpuProgram* program = nullptr;
    GpuBindings bindings{};
    std::uint32_t vertexCountPerInstance = 0U;
    std::uint32_t instanceCount = 0U;
    std::uint32_t firstInstance = 0U;
    GpuBuffer* indirectArgs = nullptr;
    std::uint32_t indirectArgsOffset = 0U;
    IndexBuffer* indexBuffer = nullptr;
  };

  struct GpuDispatch
  {
    GpuProgram* program = nullptr;
    GpuBindings bindings{};
    std::uint32_t groupsX = 1U;
    std::uint32_t groupsY = 1U;
    std::uint32_t groupsZ = 1U;
  };
} // namespace gpg::gal
