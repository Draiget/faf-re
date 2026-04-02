#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"

namespace gpg::gal
{
  class IndexBufferD3D9;
  class VertexBufferD3D9;
  class VertexFormatD3D9;
} // namespace gpg::gal

namespace moho
{
  class ParticleBuffer
  {
  public:
    struct Instanced
    {
      std::uint8_t data[0x5C];
    };
    static_assert(sizeof(Instanced) == 0x5C, "ParticleBuffer::Instanced size must be 0x5C");

    /**
     * Address: 0x0048E250 (FUN_0048E250)
     *
     * What it does:
     * Initializes particle-buffer state lanes and null GPU resource handles.
     */
    ParticleBuffer();

    /**
     * Address: 0x0048E2A0 (FUN_0048E2A0)
     * Mangled: ??1ParticleBuffer@Moho@@UAE@XZ
     *
     * What it does:
     * Tears down particle-buffer runtime state and releases retained GPU resources.
     */
    virtual ~ParticleBuffer();

    /**
     * Address: 0x0048E3E0 (FUN_0048E3E0)
     * Mangled: ?Shutdown@ParticleBuffer@Moho@@QAEXXZ
     *
     * What it does:
     * Releases all retained GPU handles and clears count/initialized lanes.
     */
    void Shutdown();

    /**
     * Address: 0x0048E4E0 (FUN_0048E4E0)
     * Mangled: ?Reset@ParticleBuffer@Moho@@QAEXXZ
     *
     * What it does:
     * Releases all retained GPU handles and clears initialized lane only.
     */
    void Reset();

    /**
     * Address: 0x0048E5D0 (FUN_0048E5D0)
     * Mangled: ?Size@ParticleBuffer@Moho@@QBEHXZ
     *
     * What it does:
     * Returns configured maximum particle count.
     */
    [[nodiscard]] int Size() const;

    /**
     * Address: 0x0048E5E0 (FUN_0048E5E0)
     * Mangled: ?Lock@ParticleBuffer@Moho@@QAEPAUInstanced@12@H@Z
     *
     * What it does:
     * Ensures particle GPU resources exist, then locks instance data from start.
     */
    [[nodiscard]] Instanced* Lock(int count);

    /**
     * Address: 0x0048E610 (FUN_0048E610)
     * Mangled: ?Lock@ParticleBuffer@Moho@@QAEPAUInstanced@12@HH@Z
     *
     * What it does:
     * Ensures particle GPU resources exist, then locks one instance-data subrange.
     */
    [[nodiscard]] Instanced* Lock(int start, int count);

    /**
     * Address: 0x0048E640 (FUN_0048E640)
     *
     * What it does:
     * Ensures particle GPU resources exist, then unlocks instance data stream.
     */
    int UnlockInstanceBuffer();

    /**
     * Address: 0x0048E660 (FUN_0048E660)
     * Mangled: ?Render@ParticleBuffer@Moho@@QAEXHH@Z
     *
     * What it does:
     * Binds particle instance/quad buffers and renders one instanced-pass chain.
     */
    void Render(int count, int startIndex);

  public:
    int mMaxParticles; // +0x04
    bool mInitialized; // +0x08
    std::uint8_t mPadding09[3]; // +0x09
    boost::shared_ptr<gpg::gal::VertexFormatD3D9> mVertexFormat; // +0x0C
    boost::shared_ptr<gpg::gal::VertexBufferD3D9> mQuadVertexBuffer; // +0x14
    boost::shared_ptr<gpg::gal::VertexBufferD3D9> mInstanceVertexBuffer; // +0x1C
    boost::shared_ptr<gpg::gal::IndexBufferD3D9> mQuadIndexBuffer; // +0x24

  private:
    /**
     * Address: 0x0048E830 (FUN_0048E830)
     * Mangled: ?Initialize@ParticleBuffer@Moho@@AAE_NXZ
     *
     * What it does:
     * Lazily creates particle vertex/index GPU resources and seeds static quad data.
     */
    [[nodiscard]] bool Initialize();
  };

  using SParticleBuffer = ParticleBuffer;

  static_assert(offsetof(ParticleBuffer, mMaxParticles) == 0x04, "ParticleBuffer::mMaxParticles offset must be 0x04");
  static_assert(offsetof(ParticleBuffer, mInitialized) == 0x08, "ParticleBuffer::mInitialized offset must be 0x08");
  static_assert(offsetof(ParticleBuffer, mVertexFormat) == 0x0C, "ParticleBuffer::mVertexFormat offset must be 0x0C");
  static_assert(
    offsetof(ParticleBuffer, mQuadVertexBuffer) == 0x14, "ParticleBuffer::mQuadVertexBuffer offset must be 0x14"
  );
  static_assert(
    offsetof(ParticleBuffer, mInstanceVertexBuffer) == 0x1C,
    "ParticleBuffer::mInstanceVertexBuffer offset must be 0x1C"
  );
  static_assert(
    offsetof(ParticleBuffer, mQuadIndexBuffer) == 0x24, "ParticleBuffer::mQuadIndexBuffer offset must be 0x24"
  );
  static_assert(sizeof(ParticleBuffer) == 0x2C, "ParticleBuffer size must be 0x2C");
} // namespace moho
