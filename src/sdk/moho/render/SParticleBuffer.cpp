#include "moho/render/SParticleBuffer.h"

#include <array>
#include <cstdint>
#include <cstring>

#include "gpg/gal/Device.hpp"
#include "gpg/gal/IndexBufferContext.hpp"
#include "gpg/gal/VertexBufferContext.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectTechniqueD3D9.hpp"
#include "gpg/gal/backends/d3d9/IndexBufferD3D9.hpp"
#include "gpg/gal/backends/d3d9/VertexBufferD3D9.hpp"
#include "gpg/gal/backends/d3d9/VertexFormatD3D9.hpp"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"

namespace moho
{
  namespace
  {
    constexpr std::array<float, 8> kParticleQuadVertexLane{
      -1.0f, -1.0f, 1.0f, -1.0f, 1.0f, 1.0f, -1.0f, 1.0f
    };

    constexpr std::array<std::uint32_t, 3> kParticleQuadIndexLane{
      0x00010000u,
      0x00000002u,
      0x00030002u,
    };

    constexpr std::uint32_t kParticleTopologyTriangleList = 4U;
    constexpr std::uint32_t kParticleQuadVertexCount = 4U;
    constexpr std::uint32_t kParticleQuadPrimitiveCountInput = 6U;

    struct DrawIndexedPrimitiveContextRuntime final
    {
      std::uint32_t pad00 = 0U;               // +0x00
      std::uint32_t topologyToken = 0U;       // +0x04
      std::uint32_t minVertexIndex = 0U;      // +0x08
      std::uint32_t vertexCount = 0U;         // +0x0C
      std::uint32_t primitiveCountInput = 0U; // +0x10
      std::uint32_t startIndex = 0U;          // +0x14
      std::int32_t baseVertexIndex = 0;       // +0x18
    };
    static_assert(
      sizeof(DrawIndexedPrimitiveContextRuntime) == 0x1C,
      "DrawIndexedPrimitiveContextRuntime size must be 0x1C"
    );
  } // namespace

  /**
   * Address: 0x0048E250 (FUN_0048E250)
   *
   * What it does:
   * Initializes particle-buffer state lanes and null GPU resource handles.
   */
  ParticleBuffer::ParticleBuffer()
    : mMaxParticles(0)
    , mInitialized(false)
    , mPadding09{0, 0, 0}
    , mVertexFormat()
    , mQuadVertexBuffer()
    , mInstanceVertexBuffer()
    , mQuadIndexBuffer()
  {}

  /**
   * Address: 0x0048E2A0 (FUN_0048E2A0)
   * Mangled: ??1ParticleBuffer@Moho@@UAE@XZ
   *
   * What it does:
   * Tears down particle-buffer runtime state and releases retained GPU resources.
   */
  ParticleBuffer::~ParticleBuffer()
  {
    Shutdown();
  }

  /**
   * Address: 0x0048E3E0 (FUN_0048E3E0)
   * Mangled: ?Shutdown@ParticleBuffer@Moho@@QAEXXZ
   *
   * What it does:
   * Releases all retained GPU handles and clears count/initialized lanes.
   */
  void ParticleBuffer::Shutdown()
  {
    mVertexFormat.reset();
    mQuadVertexBuffer.reset();
    mInstanceVertexBuffer.reset();
    mQuadIndexBuffer.reset();
    mMaxParticles = 0;
    mInitialized = false;
  }

  /**
   * Address: 0x0048E4E0 (FUN_0048E4E0)
   * Mangled: ?Reset@ParticleBuffer@Moho@@QAEXXZ
   *
   * What it does:
   * Releases all retained GPU handles and clears initialized lane only.
   */
  void ParticleBuffer::Reset()
  {
    mVertexFormat.reset();
    mQuadVertexBuffer.reset();
    mInstanceVertexBuffer.reset();
    mQuadIndexBuffer.reset();
    mInitialized = false;
  }

  /**
   * Address: 0x0048E5D0 (FUN_0048E5D0)
   * Mangled: ?Size@ParticleBuffer@Moho@@QBEHXZ
   *
   * What it does:
   * Returns configured maximum particle count.
   */
  int ParticleBuffer::Size() const
  {
    return mMaxParticles;
  }

  /**
   * Address: 0x0048E5E0 (FUN_0048E5E0)
   * Mangled: ?Lock@ParticleBuffer@Moho@@QAEPAUInstanced@12@H@Z
   *
   * What it does:
   * Ensures particle GPU resources exist, then locks instance data from start.
   */
  ParticleBuffer::Instanced* ParticleBuffer::Lock(const int count)
  {
    if (!Initialize()) {
      return nullptr;
    }

    const int byteCount = count * static_cast<int>(sizeof(Instanced));
    return static_cast<Instanced*>(mInstanceVertexBuffer->Lock(0U, static_cast<unsigned int>(byteCount), gpg::gal::MohoD3DLockFlags::Discard));
  }

  /**
   * Address: 0x0048E610 (FUN_0048E610)
   * Mangled: ?Lock@ParticleBuffer@Moho@@QAEPAUInstanced@12@HH@Z
   *
   * What it does:
   * Ensures particle GPU resources exist, then locks one instance-data subrange.
   */
  ParticleBuffer::Instanced* ParticleBuffer::Lock(const int start, const int count)
  {
    if (!Initialize()) {
      return nullptr;
    }

    const int offsetBytes = start * static_cast<int>(sizeof(Instanced));
    const int sizeBytes = count * static_cast<int>(sizeof(Instanced));
    return static_cast<Instanced*>(mInstanceVertexBuffer->Lock(
      static_cast<unsigned int>(offsetBytes),
      static_cast<unsigned int>(sizeBytes),
      gpg::gal::MohoD3DLockFlags::ReadOnly
    ));
  }

  /**
   * Address: 0x0048E640 (FUN_0048E640)
   *
   * What it does:
   * Ensures particle GPU resources exist, then unlocks instance data stream.
   */
  int ParticleBuffer::UnlockInstanceBuffer()
  {
    if (!Initialize()) {
      return 0;
    }

    return mInstanceVertexBuffer->Unlock();
  }

  /**
   * Address: 0x0048E660 (FUN_0048E660)
   * Mangled: ?Render@ParticleBuffer@Moho@@QAEXHH@Z
   *
   * What it does:
   * Binds particle instance/quad buffers and renders one instanced-pass chain.
   */
  void ParticleBuffer::Render(const int count, const int startIndex)
  {
    if (count <= 0 || !Initialize()) {
      return;
    }

    CD3DDevice* const d3dDevice = D3D_GetDevice();
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    CD3DEffect* const effect = d3dDevice->GetCurEffect();

    int renderCount = mMaxParticles - startIndex;
    if (count < renderCount) {
      renderCount = count;
    }
    if (renderCount < 0) {
      renderCount = 0;
    }

    device->SetVertexDeclaration(mVertexFormat);
    device->SetVertexBuffer(0U, mQuadVertexBuffer, renderCount, 0);
    device->SetVertexBuffer(1U, mInstanceVertexBuffer, 1, startIndex);
    device->SetBufferIndices(mQuadIndexBuffer);

    DrawIndexedPrimitiveContextRuntime drawContext{};
    drawContext.topologyToken = kParticleTopologyTriangleList;
    drawContext.vertexCount = kParticleQuadVertexCount;
    drawContext.primitiveCountInput = kParticleQuadPrimitiveCountInput;

    gpg::gal::EffectTechniqueD3D9* const technique = effect->mCurrentTechnique.px;
    const unsigned int passCount = static_cast<unsigned int>(technique->BeginTechnique());
    for (unsigned int passIndex = 0; passIndex < passCount; ++passIndex) {
      technique->BeginPass(static_cast<int>(passIndex));
      device->DrawIndexedPrimitive(&drawContext);
      technique->EndPass();
    }
    technique->EndTechnique();
  }

  /**
   * Address: 0x0048E830 (FUN_0048E830)
   * Mangled: ?Initialize@ParticleBuffer@Moho@@AAE_NXZ
   *
   * What it does:
   * Lazily creates particle vertex/index GPU resources and seeds static quad data.
   */
  bool ParticleBuffer::Initialize()
  {
    if (mInitialized) {
      return true;
    }

    gpg::gal::Device* const deviceBase = gpg::gal::Device::GetInstance();
    if (deviceBase == nullptr) {
      return false;
    }

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(deviceBase);

    boost::shared_ptr<gpg::gal::VertexFormatD3D9> vertexFormat;
    device->CreateVertexFormat(&vertexFormat, 19U);
    mVertexFormat = vertexFormat;

    gpg::gal::VertexBufferContext quadVertexContext{};
    quadVertexContext.type_ = 2U;
    quadVertexContext.usage_ = 1U;
    quadVertexContext.width_ = 4U;
    quadVertexContext.height_ = 8U;

    boost::shared_ptr<gpg::gal::VertexBufferD3D9> quadVertexBuffer;
    device->CreateVertexBuffer(&quadVertexBuffer, &quadVertexContext);
    mQuadVertexBuffer = quadVertexBuffer;

    void* const quadVertexData =
      mQuadVertexBuffer->Lock(0U, 0U, gpg::gal::MohoD3DLockFlags::None);
    std::memcpy(quadVertexData, kParticleQuadVertexLane.data(), sizeof(kParticleQuadVertexLane));
    (void)mQuadVertexBuffer->Unlock();

    gpg::gal::VertexBufferContext instanceVertexContext{};
    instanceVertexContext.type_ = 3U;
    instanceVertexContext.usage_ = 2U;
    instanceVertexContext.width_ = static_cast<unsigned int>(mMaxParticles);
    instanceVertexContext.height_ = sizeof(Instanced);

    boost::shared_ptr<gpg::gal::VertexBufferD3D9> instanceVertexBuffer;
    device->CreateVertexBuffer(&instanceVertexBuffer, &instanceVertexContext);
    mInstanceVertexBuffer = instanceVertexBuffer;

    gpg::gal::IndexBufferContext indexContext{};
    indexContext.type_ = 1U;
    indexContext.format_ = 1U;
    indexContext.size_ = 6U;

    boost::shared_ptr<gpg::gal::IndexBufferD3D9> indexBuffer;
    device->CreateIndexBuffer(&indexBuffer, &indexContext);
    mQuadIndexBuffer = indexBuffer;

    auto* const indexWords = reinterpret_cast<std::uint32_t*>(
      mQuadIndexBuffer->Lock(0U, 0U, gpg::gal::MohoD3DLockFlags::None)
    );
    indexWords[0] = kParticleQuadIndexLane[0];
    indexWords[1] = kParticleQuadIndexLane[1];
    indexWords[2] = kParticleQuadIndexLane[2];
    (void)mQuadIndexBuffer->Unlock();

    mInitialized = true;
    return mInitialized;
  }
} // namespace moho
