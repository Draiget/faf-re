#include "moho/render/SkyDome.h"

#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <stdexcept>

#include "gpg/core/containers/CheckedArrayAllocationLanes.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/gal/DrawContext.hpp"
#include "gpg/gal/DrawIndexedContext.hpp"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/IndexBufferContext.hpp"
#include "gpg/gal/VertexBufferContext.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectTechniqueD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
#include "gpg/gal/backends/d3d9/IndexBufferD3D9.hpp"
#include "gpg/gal/backends/d3d9/VertexBufferD3D9.hpp"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"
#include "moho/render/d3d/CD3DVertexFormat.h"
#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/resource/CResourceWatcher.h"
#include "moho/resource/ResourceManager.h"

namespace
{
  struct SkyDomeVertex
  {
    float x;
    float y;
    float z;
    float u;
    float v;
  };

  static_assert(sizeof(SkyDomeVertex) == 0x14, "SkyDomeVertex size must be 0x14");

  constexpr float kHalfPi = 1.5707964f;
  constexpr float kTwoPi = 6.2831855f;

  constexpr std::array<float, 8> kDecalBillboardQuadVertices = {
    -1.0f, 1.0f,
    -1.0f, -1.0f,
    1.0f, 1.0f,
    1.0f, -1.0f,
  };

  constexpr std::array<std::int16_t, 6> kDecalQuadIndices = {
    0, 1, 2,
    2, 1, 3,
  };

  /**
   * Address: 0x008153C0 (FUN_008153C0)
   *
   * What it does:
   * Clears the retained dome vertex-buffer handle, writes the incoming dome
   * origin/shape lanes, and restores default tessellation lanes (`16x6`) plus
   * the default start-angle lane (`1.2566371f`).
   */
  void InitializeSkyDomeShapeRuntime(
    moho::SkyDome* const skyDome,
    const Wm3::Vector3f& domeOrigin,
    const float domeHeight,
    const float domeRadius
  ) noexcept
  {
    if (skyDome == nullptr) {
      return;
    }

    skyDome->mDomeVertBuf.reset();
    skyDome->mDomeOrigin = domeOrigin;
    skyDome->mDomeShapeParams.x = domeHeight;
    skyDome->mDomeShapeParams.y = domeRadius;
    skyDome->mDomeShapeParams.z = 1.2566371f;
    skyDome->mWidth = 16;
    skyDome->mHeight = 6;
  }

  /**
   * Address: 0x008154A0 (FUN_008154A0)
   *
   * IDA signature:
   * int __userpurge sub_8154A0(float *skyColor@<ebx>, SkyDome *this@<esi>,
   *     float horizonSize, float *horizonColor);
   *
   * What it does:
   * Clears the retained horizon-lookup texture handle, writes the incoming
   * horizon size lane, and stores the horizon and sky colour vectors. The
   * horizon-lookup path string is built/destroyed around this call by
   * SetupHorizonAndCirrus but is not consumed here (threaded through as an
   * ignored parameter so the caller keeps the original temporary lifetime).
   */
  void InitializeSkyDomeHorizonRuntime(
    moho::SkyDome* const skyDome,
    const Wm3::Vector3f& skyColor,
    const float horizonSize,
    const Wm3::Vector3f& horizonColor,
    const msvc8::string& horizonLookupPath
  ) noexcept
  {
    (void)horizonLookupPath;

    skyDome->mHorizonLookupTex.reset();
    skyDome->mHorizonSize = horizonSize;
    skyDome->mHorizonColor = horizonColor;
    skyDome->mSkyColor = skyColor;
  }

  // ---------------------------------------------------------------------------
  // Static cirrus runtime table (byte_F5AE00, 0x50 bytes / 20 float lanes)
  // copied verbatim into SkyDome::mCirrusData by SetupHorizonAndCirrus.
  // Extracted byte-for-byte from ForgedAlliance.exe .data @0xF5AE00.
  // ---------------------------------------------------------------------------
  constexpr std::array<float, 20> kSkyDomeCirrusRuntimeTable = {
    0.00428f, 0.0030100001f, 0.55000001f, 0.53288001f,
    -0.84618998f, 0.00191f, 0.00164f, 0.090000004f,
    0.96638f, 0.25713f, 0.00119f, 0.0060000001f,
    0.15000001f, 0.15816f, 0.98741001f, 0.0026400001f,
    0.0011f, 0.30000001f, -0.59482002f, -0.80386001f,
  };

  static_assert(sizeof(kSkyDomeCirrusRuntimeTable) == 0x50,
    "SkyDome cirrus runtime table must be 0x50 bytes");

  /**
   * Address: 0x0081A590 (FUN_0081A590)
   *
   * What it does:
   * Allocates one decal-upload node and initializes link lanes plus the
   * 0x28-byte packed decal-vertex payload.
   */
  [[nodiscard]] moho::SkyDomeDecalUploadNode* AllocateSkyDomeDecalUploadNode(
    moho::SkyDomeDecalUploadNode* const next,
    moho::SkyDomeDecalUploadNode* const prev,
    const void* const vertexData
  )
  {
    auto* const node = static_cast<moho::SkyDomeDecalUploadNode*>(
      gpg::core::legacy::AllocateChecked48ByteLane(1u)
    );

    node->mNext = next;
    node->mPrev = prev;
    if (vertexData != nullptr) {
      std::memcpy(node->mVertexData, vertexData, sizeof(node->mVertexData));
    } else {
      std::memset(node->mVertexData, 0, sizeof(node->mVertexData));
    }
    return node;
  }

  /**
   * Address: 0x0081A5D0 (FUN_0081A5D0)
   *
   * What it does:
   * The size increment MSVC emits for the decal-upload list. The ceiling is
   * the list's own max_size - how many 40-byte payloads a 32-bit size can
   * address - and overflowing it is reported the way the standard library
   * reports it.
   */
  [[nodiscard]] std::int32_t BumpSkyDomeDecalUploadCount(const std::int32_t currentCount)
  {
    constexpr std::int32_t kMaxDecalUploadRecords = 107374182;
    if (currentCount == kMaxDecalUploadRecords) {
      throw std::length_error("list<T> too long");
    }
    return currentCount + 1;
  }

  /**
   * Address: 0x0081A440 (FUN_0081A440)
   *
   * What it does:
   * Allocates one 48-byte sky-decal upload sentinel and self-links
   * `next/prev`.
   */
  [[nodiscard]] moho::SkyDomeDecalUploadNode* AllocateSkyDomeDecalUploadListSentinel()
  {
    auto* const node = static_cast<moho::SkyDomeDecalUploadNode*>(
      gpg::core::legacy::AllocateChecked48ByteLane(1u)
    );
    node->mNext = node;
    node->mPrev = node;
    return node;
  }

  /**
   * Address: 0x0081A550 (FUN_0081A550)
   *
   * What it does:
   * Clears one intrusive sky-decal upload list by unlinking all payload nodes,
   * preserving the head sentinel, and releasing removed nodes.
   */
  /**
   * Address: 0x0081A550 (FUN_0081A550)
   *
   * What it does:
   * Empties one decal upload list: re-self-links the head sentinel, resets the
   * count, then frees every detached payload node. The sentinel itself is kept
   * -- callers that are tearing the owner down free it separately.
   *
   * Takes the head *and* the count because the emission does: it reads the
   * head from `[arg+4]` and stores zero to `[arg+8]`, which on `SkyDome` are
   * `mDecalUploadHead` (+0xB8) and `mDecalUploadCount` (+0xBC). An earlier
   * version took only the node and left the count stale.
   */
  void ClearSkyDomeDecalUploadList(
    moho::SkyDomeDecalUploadNode* const listHead,
    std::int32_t& uploadCount
  ) noexcept
  {
    if (listHead == nullptr) {
      uploadCount = 0;
      return;
    }

    moho::SkyDomeDecalUploadNode* node = listHead->mNext;
    listHead->mNext = listHead;
    listHead->mPrev = listHead;
    uploadCount = 0;

    while (node != listHead) {
      moho::SkyDomeDecalUploadNode* const next = node->mNext;
      ::operator delete(node);
      node = next;
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x008149E0 (FUN_008149E0, ??0SkyDome@Moho@@QAE@XZ)
   *
   * What it does:
   * Initializes all sky dome rendering state to defaults — horizon/sky colors,
   * texture paths, zero-initialized shared_ptr resource handles, and copies
   * static cirrus data. Also inlines `CResourceWatcher::CResourceWatcher`
   * (0x007DD660) to set up the watched-resource small-vector in inline mode
   * (`mWatchedBegin`/`mWatchedEnd` pointing at `mWatchedInline`, empty range) -
   * previously left uninitialized here, which made `CreateTextures`'s
   * `mWatchedBegin != mWatchedEnd` guard read garbage stack/heap bytes and
   * crash inside `ManageWatchedResources` the first time a sky dome rendered.
   */
  SkyDome::SkyDome()
    : mWatcherFlags(0)
    , mWatchedBegin(mWatchedInline)
    , mWatchedEnd(mWatchedInline)
    , mWatchedStorageEnd(mWatchedInline + sizeof(mWatchedInline))
    , mWatchedStorageOrigin(mWatchedInline)
    , mWatchedInline{}
    , mHorizonLookupPath("/textures/environment/horizonLookup.dds")
    , mCirrusTexPath("/textures/environment/cirrus000.dds")
  {
    // Legacy small-vector reset path reads `*(origin)` as fallback storage
    // end - see CResourceWatcher::CResourceWatcher for the same idiom.
    auto** const inlineSlots = reinterpret_cast<void**>(mWatchedInline);
    inlineSlots[0] = mWatchedStorageEnd;

    mDecalUploadHead = AllocateSkyDomeDecalUploadListSentinel();
  }

  /**
   * Address: 0x008158D0 (FUN_008158D0, ?SetCirrusContext@SkyDome@Moho@@QAEXMABV?$Vector3@M@Wm3@@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
   *
   * What it does:
   * Restores the cirrus multiplier lane to `1.8f`, copies direction
   * components, drops any previous cirrus texture reference, and records the
   * new cirrus texture path.
   */
  void SkyDome::SetCirrusContext(
    const float speed,
    const Wm3::Vector3f& direction,
    const msvc8::string& texturePath
  )
  {
    (void)speed;
    mCirrusMultiplier = 1.8f;
    mCirrusColor_R = direction.x;
    mCirrusColor_G = direction.y;
    mCirrusColor_B = direction.z;
    mCirrusTex.reset();
    mCirrusTexPath.reset_and_assign(texturePath);
  }

  /**
   * Address: 0x00815230 (FUN_00815230)
   *
   * IDA signature:
   * void __thiscall SkyDome::SetupHorizonAndCirrus(SkyDome *this@<ecx>,
   *     const Wm3::Vector3f *domeOrigin@<edx>, float waterElevation, float domeRadius);
   *
   * What it does:
   * Reconfigures the dome shape (origin/elevation/radius) and default
   * tessellation, restores the horizon colour/size and sky colour with a
   * transient horizon-lookup path string, restores the fixed cirrus
   * colour/texture context, and copies the static cirrus runtime table into the
   * dome's cirrus-data lane. Invoked by CWldTerrainRes::Load/Reset after the
   * terrain map bounds are known.
   */
  void SkyDome::SetupHorizonAndCirrus(
    const Wm3::Vector3f& domeOrigin,
    const float waterElevation,
    const float domeRadius
  )
  {
    // sub_8153C0: dome origin / elevation / radius + default 16x6 tessellation,
    // drops the retained dome vertex buffer.
    InitializeSkyDomeShapeRuntime(this, domeOrigin, waterElevation, domeRadius);

    // Horizon + sky colour context. The horizon-lookup path is built here (heap
    // side effect preserved) and released after the horizon lane is written; it
    // is not consumed by the horizon setup itself.
    {
      const msvc8::string horizonLookupPath("/textures/environment/horizonLookup.dds");
      InitializeSkyDomeHorizonRuntime(
        this,
        Wm3::Vector3f{0.25999999f, 0.46000001f, 0.58999997f},   // sky colour
        domeRadius * 0.15360001f,                               // horizon size
        Wm3::Vector3f{0.81000000f, 0.74000001f, 0.63999999f},   // horizon colour
        horizonLookupPath);
    }

    // Cirrus context: fixed colour vector + cirrus texture path.
    {
      const msvc8::string cirrusTexturePath("/textures/environment/cirrus001_512.dds");
      SetCirrusContext(
        0.0f,                                                   // speed lane (ignored)
        Wm3::Vector3f{1.39000000f, 0.75999999f, 0.49000001f},   // cirrus colour
        cirrusTexturePath);
    }

    // qmemcpy(this+0x140, byte_F5AE00, 0x50): install the static cirrus table.
    std::memcpy(mCirrusData, kSkyDomeCirrusRuntimeTable.data(), sizeof(mCirrusData));
  }

  /**
   * Address: 0x008177B0 (FUN_008177B0, ?CreateRenderAbility@SkyDome@Moho@@AAEXXZ)
   *
   * What it does:
   * Loads all textures, creates the dome vertex format, builds dome and decal
   * vertex/index buffers from the current sky parameters.
   */
  void SkyDome::CreateRenderAbility()
  {
    CreateTextures();
    CreateDomeFormat();
    CreateDomeVertexBuffer(mDomeShapeParams.x, mDomeShapeParams.y, mDomeShapeParams.z, mWidth, mHeight);
    CreateDomeIndexBuffer(mWidth, mHeight);
    CreateDecalFormat();
    CreateDecalVertexBuffers();
    CreateDecalIndexBuffer();
  }

  /**
   * Address: 0x00814CD0 (FUN_00814CD0, ??1SkyDome@Moho@@UAE@XZ)
   * Address: 0x00814CA0 (FUN_00814CA0, vtable-slot-2 scalar deleting
   * destructor: tail-calls the body below then conditionally frees the
   * object -- ordinary C++ `delete` semantics, not modeled as a separate
   * function here)
   * Mangled: ??1SkyDome@Moho@@UAE@XZ
   *
   * What it does:
   * Tears the dome down: releases the sky resources through `Reset`, empties
   * the decal upload list and frees its sentinel, then inlines
   * `CResourceWatcher::~CResourceWatcher` (0x007DA8D0) - flush any pending
   * watched-resource nodes through the resource manager, then free
   * non-inline watched storage - since `SkyDome` doesn't C++-inherit
   * `CResourceWatcher` (see the field comment above) so there is no real
   * base dtor to do this automatically. Every other member (the shared_ptr
   * lanes) unwinds on its own in reverse declaration order.
   *
   * The emission runs to 601 instructions, but roughly 190 of those are the
   * compiler's own `boost::shared_ptr` member releases, which C++ performs
   * implicitly. What is left is the steps above.
   */
  SkyDome::~SkyDome()
  {
    Reset();

    ClearSkyDomeDecalUploadList(mDecalUploadHead, mDecalUploadCount);

    // The list head is a sentinel the constructor allocated; clearing the list
    // deliberately keeps it, so the owner frees it here.
    ::operator delete(mDecalUploadHead);
    mDecalUploadHead = nullptr;

    if (mWatchedBegin != mWatchedEnd) {
      if (ResourceManager* const manager = RES_GetResourceManager(); manager != nullptr) {
        manager->ManageWatchedResources(reinterpret_cast<CResourceWatcher*>(this));
      }
    }

    if (mWatchedBegin != mWatchedStorageOrigin) {
      ::operator delete[](mWatchedBegin);
      mWatchedBegin = mWatchedStorageOrigin;
      mWatchedStorageEnd = *reinterpret_cast<void**>(mWatchedStorageOrigin);
    }
  }

  /**
   * Address: 0x00817160 (FUN_00817160, ?Reset@SkyDome@Moho@@QAEXXZ)
   *
   * What it does:
   * Clears all retained sky-dome GPU resources, zeros dome index/vertex
   * counters, and marks the runtime for a full rebuild.
   */
  void SkyDome::Reset()
  {
    mCloudsTexture = {};
    mHorizonLookupTex = {};
    mCirrusTex = {};
    mDecalVertBuf3 = {};
    mDecalFormat2 = {};
    mDecalTex3 = {};
    mDecalTex2 = {};
    mDecalTex1 = {};
    mDecalVertBuf2 = {};
    mDecalFormat1 = {};
    mAtmosphereTex = {};
    mAtmosphereTex2 = {};
    mDecalIndexBuf = {};
    mDecalVertBuf1 = {};
    mDomeFormat = {};
    mDomeVertBuf = {};
    mDomeIndexBuf = {};
    mDomeVertexCount = 0;
    mDomeIndexCount = 0;
    mNeedsRebuild = true;
  }

  /**
   * Address: 0x00815FA0 (FUN_00815FA0, ?Load@SkyDome@Moho@@QAEXIAAVBinaryReader@gpg@@@Z)
   *
   * IDA signature:
   * void __thiscall Moho::SkyDome::Load(SkyDome *this, unsigned int version, gpg::BinaryReader *reader);
   *
   * What it does:
   * Reads the sky block of a `.scmap`: dome placement and shape, the horizon
   * and sky gradient, the three cloud-texture paths, a run of packed cloud
   * records that become the decal-upload list, and the cirrus parameters and
   * its four 20-byte layer records. Drops every GPU resource first, so the
   * next frame rebuilds the dome from what was just read.
   *
   * The version is passed but never consulted - the sky block gained no
   * version-gated fields before the format froze, and the caller only reaches
   * this at map version 0x3A and above.
   */
  void SkyDome::Load(unsigned int, gpg::BinaryReader& reader)
  {
    Reset();

    reader.ReadExact(mDomeOrigin);
    reader.ReadExact(mDomeShapeParams.x);
    reader.ReadExact(mDomeShapeParams.y);
    reader.ReadExact(mDomeShapeParams.z);
    reader.ReadExact(mWidth);
    reader.ReadExact(mHeight);
    reader.ReadExact(mHorizonSize);
    reader.ReadExact(mHorizonColor);
    reader.ReadExact(mSkyColor);
    reader.ReadExact(mHorizonBlend);

    msvc8::string scratch;
    reader.ReadString(&scratch);
    mAtmosphereTexPath.assign(scratch, 0u, 0xFFFFFFFFu);
    reader.ReadString(&scratch);
    mAtmosphereTexPath2.assign(scratch, 0u, 0xFFFFFFFFu);

    // Cumulus records, appended to the upload list in file order. The list is
    // the sentinel-headed one the constructor built, so each record links in
    // ahead of the sentinel and the count is the list size the decal draw
    // reads back.
    std::int32_t cloudRecordCount = 0;
    reader.ReadExact(cloudRecordCount);
    for (std::int32_t record = 0; record < cloudRecordCount; ++record) {
      std::uint8_t vertexData[sizeof(SkyDomeDecalUploadNode::mVertexData)]{};
      reader.Read(reinterpret_cast<char*>(vertexData), sizeof(vertexData));

      SkyDomeDecalUploadNode* const tail = mDecalUploadHead->mPrev;
      SkyDomeDecalUploadNode* const node =
        AllocateSkyDomeDecalUploadNode(mDecalUploadHead, tail, vertexData);
      mDecalUploadCount = BumpSkyDomeDecalUploadCount(mDecalUploadCount);
      tail->mNext = node;
      mDecalUploadHead->mPrev = node;
    }

    reader.ReadString(&scratch);
    mDecalTexPath1.assign(scratch, 0u, 0xFFFFFFFFu);
    reader.ReadString(&scratch);
    mDecalTexPath2.assign(scratch, 0u, 0xFFFFFFFFu);
    reader.ReadString(&scratch);
    mDecalTexPath3.assign(scratch, 0u, 0xFFFFFFFFu);

    reader.ReadExact(mCirrusMultiplier);
    reader.ReadExact(mCirrusColor_R);
    reader.ReadExact(mCirrusColor_G);
    reader.ReadExact(mCirrusColor_B);
    reader.ReadString(&scratch);
    mCirrusTexPath.assign(scratch, 0u, 0xFFFFFFFFu);

    // A layer count the reader consumes and ignores: the four cirrus layer
    // records that follow are a fixed-size block either way.
    std::int32_t discardedCirrusLayerCount = 0;
    reader.ReadExact(discardedCirrusLayerCount);

    constexpr std::size_t kCirrusLayerRecordSize = 20u;
    constexpr std::size_t kCirrusLayerCount = sizeof(mCirrusData) / kCirrusLayerRecordSize;
    for (std::size_t layer = 0; layer < kCirrusLayerCount; ++layer) {
      reader.Read(reinterpret_cast<char*>(mCirrusData) + layer * kCirrusLayerRecordSize, kCirrusLayerRecordSize);
    }
  }

  /**
   * Address: 0x008175D0 (FUN_008175D0, Moho::SkyDome::Destroy)
   *
   * What it does:
   * Releases sky texture resource handles used by runtime sky layers.
   */
void SkyDome::Destroy()
{
    ClearSkyDomeDecalUploadList(mDecalUploadHead, mDecalUploadCount);
    mHorizonLookupTex = {};
    mCirrusTex = {};
    mDecalTex3 = {};
    mDecalTex1 = {};
    mDecalTex2 = {};
    mAtmosphereTex = {};
    mAtmosphereTex2 = {};
}

  /**
   * Address: 0x00817810 (FUN_00817810, ?GetEffect@SkyDome@Moho@@AAE?AV?$shared_ptr@VEffect@gal@gpg@@@boost@@XZ)
   *
   * What it does:
   * Looks up the "sky" shader effect from the active D3D device resources.
   */
  boost::shared_ptr<gpg::gal::Effect> SkyDome::GetEffect()
  {
    // The binary returns the same shared_ptr backing-store that
    // CD3DEffect::GetBaseEffect() does, but the recovered SDK currently models
    // EffectD3D9 and Effect as unrelated `gpg::gal::*` classes (no shared
    // base) so the implicit upcast of `shared_ptr<EffectD3D9>` to
    // `shared_ptr<Effect>` doesn't compile. Re-enable the lookup once the
    // Effect / EffectD3D9 inheritance is recovered.
    (void)D3D_GetDevice()->GetResources()->FindEffect("sky");
    return {};
  }

  /**
   * Address: 0x00817850 (FUN_00817850, ?CreateTextures@SkyDome@Moho@@AAEXXZ)
   * Mangled: ?CreateTextures@SkyDome@Moho@@AAEXXZ
   *
   * IDA signature:
   * private: void __thiscall Moho::SkyDome::CreateTextures(void);
   *
   * What it does:
   * Loads all seven sky-dome textures (atmosphere albedo/glow, horizon lookup,
   * cirrus, and the three cumulus/decal ramp textures) from the active D3D
   * device resources and stores each resolved base GAL texture into the
   * matching texture lane. Runs only when at least one of the four "anchor"
   * lanes (atmosphere albedo/glow, cirrus, horizon lookup) is still null, so
   * repeated calls after a successful load are no-ops. When this watcher already
   * tracks resources, it first flushes/re-registers them with the resource
   * manager so the loaded textures participate in hot-reload.
   *
   * SkyDome derives its runtime layout from CResourceWatcher (its constructor
   * inlines the watcher init at 0x008149E0 and the +0x04/+0x08 fields are the
   * watcher flag / watched-resource small-vector). The binary passes `this`
   * (viewed as CResourceWatcher*) as the resource-lookup owner argument; the
   * recovered CD3DDeviceResources::GetTexture ignores that slot, but it is
   * preserved here for 1:1 fidelity with the original call.
   */
  void SkyDome::CreateTextures()
  {
    // Skip if all anchor texture lanes are already resolved.
    if (mAtmosphereTex && mAtmosphereTex2 && mCirrusTex && mHorizonLookupTex) {
      return;
    }

    // SkyDome shares CResourceWatcher's layout (watcher init is inlined into
    // the SkyDome constructor); use the typed watcher view for the tracked-
    // resource flush and for the resource-lookup owner argument.
    auto* const watcher = reinterpret_cast<CResourceWatcher*>(this);

    // When this watcher already tracks resources, flush/re-register them with
    // the resource manager (mirrors ~CResourceWatcher's watched-vector guard).
    if (watcher->mWatchedBegin != watcher->mWatchedEnd) {
      if (ResourceManager* const manager = RES_GetResourceManager(); manager != nullptr) {
        manager->ManageWatchedResources(watcher);
      }
    }

    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();

    // Each texture: resolve the resource by path (with fallback), then extract
    // its base GAL texture into the destination lane. Path -> lane mapping is
    // taken verbatim from the store offsets in FUN_00817850.
    const auto loadTexture =
      [&](const msvc8::string& path, boost::shared_ptr<gpg::gal::TextureD3D9>& lane) {
        ID3DDeviceResources::TextureResourceHandle textureResource;
        resources->GetTexture(textureResource, path.c_str(), watcher, true);
        textureResource->GetTexture(lane);
      };

    loadTexture(mAtmosphereTexPath, mAtmosphereTex);    // 0x7C  -> 0x1CC
    loadTexture(mHorizonLookupPath, mHorizonLookupTex); // 0x5C  -> 0x1B0
    loadTexture(mAtmosphereTexPath2, mAtmosphereTex2);  // 0x98  -> 0x1D4
    loadTexture(mDecalTexPath3, mDecalTex3);            // 0xF8  -> 0x1FC
    loadTexture(mDecalTexPath1, mDecalTex1);            // 0xC0  -> 0x1EC
    loadTexture(mDecalTexPath2, mDecalTex2);            // 0xDC  -> 0x1F4
    loadTexture(mCirrusTexPath, mCirrusTex);            // 0x124 -> 0x214
  }

  /**
   * Address: 0x008180A0 (FUN_008180A0, ?CreateDomeFormat@SkyDome@Moho@@AAEXXZ)
   *
   * What it does:
   * Creates one dome vertex-format descriptor (format token `3`) when it is
   * not already present.
   */
  void SkyDome::CreateDomeFormat()
  {
    if (!mDomeFormat) {
      mDomeFormat = boost::shared_ptr<CD3DVertexFormat>(new CD3DVertexFormat(3U));
    }
  }

  /**
   * Address: 0x00818630 (FUN_00818630, ?CreateDecalFormat@SkyDome@Moho@@AAEXXZ)
   *
   * What it does:
   * Creates the two sky-decal vertex-format descriptors (format tokens `20`
   * and `21`) when they are not already present.
   */
  void SkyDome::CreateDecalFormat()
  {
    if (!mDecalFormat1) {
      mDecalFormat1 = boost::shared_ptr<CD3DVertexFormat>(new CD3DVertexFormat(20U));
      mDecalFormat2 = boost::shared_ptr<CD3DVertexFormat>(new CD3DVertexFormat(21U));
    }
  }

  /**
   * Address: 0x00818170 (FUN_00818170, ?CreateDomeVertexBuffer@SkyDome@Moho@@AAEXMMMHH@Z)
   *
   * What it does:
   * Creates and fills the sky dome vertex buffer from polar rings and one apex
   * vertex, using the serialized dome origin/shape parameters.
   */
  void SkyDome::CreateDomeVertexBuffer(
    const float verticalOffset,
    const float domeRadius,
    const float startAngleRadians,
    const int widthSegments,
    const int heightSegments
  )
  {
    if (mDomeVertBuf) {
      return;
    }

    const float invWidth = 1.0f / static_cast<float>(widthSegments);
    const float verticalStep = (kHalfPi - startAngleRadians) / static_cast<float>(heightSegments);
    const float radiusDivCos = domeRadius / std::cos(startAngleRadians);
    const float baseHeight = radiusDivCos * std::sin(startAngleRadians);

    auto* const device = reinterpret_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    const int widthPlusOne = widthSegments + 1;
    mDomeVertexCount = (heightSegments * widthPlusOne) + 1;

    gpg::gal::VertexBufferContext context{};
    context.width_ = static_cast<std::uint32_t>(mDomeVertexCount);
    context.height_ = sizeof(SkyDomeVertex);
    context.type_ = 1u;
    context.usage_ = 1u;
    device->CreateVertexBuffer(&mDomeVertBuf, &context);

    auto* const vertices = static_cast<SkyDomeVertex*>(
      mDomeVertBuf->Lock(0u, 0u, static_cast<gpg::gal::MohoD3DLockFlags>(0))
    );

    int vertexWriteIndex = 0;
    for (int row = 0; row < heightSegments; ++row) {
      const float rowAngle = startAngleRadians + (static_cast<float>(row) * verticalStep);
      const float ringRadius = std::cos(rowAngle) * radiusDivCos;
      const float ringHeight = (std::sin(rowAngle) * radiusDivCos) - baseHeight;

      for (int column = 0; column < widthPlusOne; ++column) {
        const float azimuth = (static_cast<float>(column) * invWidth) * kTwoPi;
        SkyDomeVertex& vertex = vertices[vertexWriteIndex++];
        vertex.x = (std::cos(azimuth) * ringRadius) + mDomeOrigin.x;
        vertex.y = ringHeight + mDomeOrigin.y + verticalOffset;
        vertex.z = (std::sin(azimuth) * ringRadius) + mDomeOrigin.z;
        vertex.u = azimuth;
        vertex.v = 0.0f;
      }
    }

    SkyDomeVertex& apex = vertices[vertexWriteIndex];
    apex.x = mDomeOrigin.x;
    apex.y = (radiusDivCos - baseHeight) + mDomeOrigin.y + verticalOffset;
    apex.z = mDomeOrigin.z;
    apex.u = 0.0f;
    apex.v = 0.0f;

    mDomeVertBuf->Unlock();
  }

  /**
   * Address: 0x00818410 (FUN_00818410, ?CreateDomeIndexBuffer@SkyDome@Moho@@AAEXHH@Z)
   *
   * What it does:
   * Creates one 16-bit index buffer for dome strips and one apex fan.
   */
  void SkyDome::CreateDomeIndexBuffer(const int widthSegments, const int heightSegments)
  {
    if (mDomeIndexBuf) {
      return;
    }

    auto* const device = reinterpret_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    mDomeIndexCount = widthSegments * ((6 * (heightSegments - 1)) + 3);

    gpg::gal::IndexBufferContext context{};
    context.size_ = static_cast<std::uint32_t>(mDomeIndexCount);
    context.format_ = 1u;
    context.type_ = 1u;
    device->CreateIndexBuffer(&mDomeIndexBuf, &context);

    std::int16_t* const indices = mDomeIndexBuf->Lock(0u, 0u, static_cast<gpg::gal::MohoD3DLockFlags>(0));
    int writeIndex = 0;

    for (int ring = 0; ring < heightSegments - 1; ++ring) {
      const int base = ring * (widthSegments + 1);
      std::int16_t topLeft = static_cast<std::int16_t>(base + 1);
      std::int16_t topRight = static_cast<std::int16_t>(base + widthSegments + 1);
      std::int16_t bottomRight = static_cast<std::int16_t>(base + widthSegments + 2);

      for (int column = 0; column < widthSegments; ++column) {
        const std::int16_t bottomLeft = static_cast<std::int16_t>(base + column);
        indices[writeIndex++] = topLeft;
        indices[writeIndex++] = topRight;
        indices[writeIndex++] = bottomLeft;
        indices[writeIndex++] = topRight;
        indices[writeIndex++] = topLeft;
        indices[writeIndex++] = bottomRight;
        ++topLeft;
        ++topRight;
        ++bottomRight;
      }
    }

    const int capBase = (heightSegments - 1) * (widthSegments + 1);
    for (int column = 0; column < widthSegments; ++column) {
      indices[writeIndex++] = static_cast<std::int16_t>(capBase + column + 1);
      indices[writeIndex++] = static_cast<std::int16_t>(mDomeVertexCount - 1);
      indices[writeIndex++] = static_cast<std::int16_t>(capBase + column);
    }

    mDomeIndexBuf->Unlock();
  }

  /**
   * Address: 0x00818780 (FUN_00818780, ?CreateDecalVertexBuffers@SkyDome@Moho@@AAEXXZ)
   *
   * What it does:
   * Creates three decal vertex buffers and seeds the first one with the static
   * billboard quad coordinates used by sky decal rendering.
   */
  void SkyDome::CreateDecalVertexBuffers()
  {
    if (mDecalVertBuf1 && mDecalVertBuf2) {
      return;
    }

    auto* const device = reinterpret_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

    gpg::gal::VertexBufferContext quadContext{};
    quadContext.width_ = 4u;
    quadContext.height_ = 8u;
    quadContext.type_ = 2u;
    quadContext.usage_ = 1u;
    device->CreateVertexBuffer(&mDecalVertBuf1, &quadContext);

    void* const quadVertices = mDecalVertBuf1->Lock(0u, 0u, static_cast<gpg::gal::MohoD3DLockFlags>(0));
    std::memcpy(quadVertices, kDecalBillboardQuadVertices.data(), sizeof(kDecalBillboardQuadVertices));
    mDecalVertBuf1->Unlock();

    gpg::gal::VertexBufferContext cumulusContext{};
    cumulusContext.width_ = 1024u;
    cumulusContext.height_ = 40u;
    cumulusContext.type_ = 3u;
    cumulusContext.usage_ = 2u;
    device->CreateVertexBuffer(&mDecalVertBuf2, &cumulusContext);

    gpg::gal::VertexBufferContext cirrusContext{};
    cirrusContext.width_ = 10000u;
    cirrusContext.height_ = 60u;
    cirrusContext.type_ = 3u;
    cirrusContext.usage_ = 2u;
    device->CreateVertexBuffer(&mDecalVertBuf3, &cirrusContext);
  }

  /**
   * Address: 0x00818A10 (FUN_00818A10, ?CreateDecalIndexBuffer@SkyDome@Moho@@AAEXXZ)
   *
   * What it does:
   * Creates and fills the static six-index quad list used by decal rendering.
   */
  void SkyDome::CreateDecalIndexBuffer()
  {
    if (mDecalIndexBuf) {
      return;
    }

    auto* const device = reinterpret_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());

    gpg::gal::IndexBufferContext context{};
    context.size_ = 6u;
    context.format_ = 1u;
    context.type_ = 1u;
    device->CreateIndexBuffer(&mDecalIndexBuf, &context);

    std::int16_t* const indices = mDecalIndexBuf->Lock(0u, 0u, static_cast<gpg::gal::MohoD3DLockFlags>(0));
    std::memcpy(indices, kDecalQuadIndices.data(), sizeof(kDecalQuadIndices));
    mDecalIndexBuf->Unlock();
  }

  /**
   * Address: 0x0081A190 (FUN_0081A190, Moho::SkyDome::UpdateDecalBuffer)
   *
   * What it does:
   * Uploads queued sky-decal vertex records to the dynamic decal vertex
   * buffer and clears the pending rebuild latch.
   */
  void SkyDome::UpdateDecalBuffer()
  {
    if (!mNeedsRebuild) {
      return;
    }

    std::uint8_t* writeCursor =
      static_cast<std::uint8_t*>(mDecalVertBuf2->Lock(0u, 0u, static_cast<gpg::gal::MohoD3DLockFlags>(0)));

    SkyDomeDecalUploadNode* const listHead = mDecalUploadHead;
    for (SkyDomeDecalUploadNode* node = listHead->mNext; node != listHead; node = node->mNext) {
      std::memcpy(writeCursor, node->mVertexData, sizeof(node->mVertexData));
      writeCursor += sizeof(node->mVertexData);
    }

    mDecalVertBuf2->Unlock();
    mNeedsRebuild = false;
  }

  namespace
  {
    constexpr int kSkyTopologyTriangleList = 4; // gpg::gal::DrawContext::TOPOLOGY D3DPT_TRIANGLELIST

    /**
     * Resolves the concrete D3D9 "sky" effect the render passes drive.
     *
     * This is the body of `SkyDome::GetEffect` (FUN_00817810):
     * `D3D_GetDevice()->GetResources()->FindEffect("sky")->GetBaseEffect()`.
     * It is inlined here rather than calling `GetEffect()` because that
     * accessor's recovered return type is the base `gpg::gal::Effect` (whose
     * slots are all pure-virtual in the current SDK), so it cannot drive the
     * concrete `EffectD3D9` parameter/technique virtuals the render passes
     * need. The base/derived `Effect`/`EffectD3D9` relationship is not yet
     * recovered; once it is, these passes can call `GetEffect()` by name.
     */
    [[nodiscard]] boost::shared_ptr<gpg::gal::EffectD3D9> ResolveSkyEffect()
    {
      moho::CD3DEffect* const skyEffect = moho::D3D_GetDevice()->GetResources()->FindEffect("sky");
      return skyEffect->GetBaseEffect();
    }
  } // namespace

  /**
   * Address: 0x00819AF0 (FUN_00819AF0, ?RenderDomeUsing@SkyDome@Moho@@AAEXV?$shared_ptr@VEffectTechnique@gal@gpg@@@boost@@@Z)
   *
   * IDA signature:
   * void __stdcall Moho::SkyDome::RenderDomeUsing(boost::shared_ptr<gpg::gal::EffectTechnique> technique);
   *
   * What it does:
   * Binds the dome vertex format/vertex buffer/index buffer on the active GAL
   * device, then iterates each pass of the supplied technique issuing one
   * indexed dome draw per pass.
   *
   * The parameter is typed as the concrete D3D9 backend technique (the runtime
   * object), because the base `gpg::gal::EffectTechnique` is the pure-virtual
   * skeleton whose inheritance from `EffectTechniqueD3D9` is not yet recovered.
   */
  void SkyDome::RenderDomeUsing(boost::shared_ptr<gpg::gal::EffectTechniqueD3D9> technique)
  {
    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    gpg::gal::EffectTechniqueD3D9* const techniqueImpl = technique.get();

    device->SetVertexDeclaration(mDomeFormat->mFormat);
    device->SetVertexBuffer(0u, mDomeVertBuf, 1, 0);
    device->SetBufferIndices(mDomeIndexBuf);

    const unsigned int passCount = static_cast<unsigned int>(techniqueImpl->BeginTechnique());
    for (unsigned int pass = 0; pass < passCount; ++pass) {
      techniqueImpl->BeginPass(static_cast<int>(pass));
      gpg::gal::DrawIndexedContext drawContext(
        kSkyTopologyTriangleList, mDomeVertexCount, mDomeIndexCount, 0, 0
      );
      device->DrawIndexedPrimitive(&drawContext);
      techniqueImpl->EndPass();
    }
    techniqueImpl->EndTechnique();
  }

  /**
   * Address: 0x00818B40 (FUN_00818B40, ?RenderAtmosphere@SkyDome@Moho@@AAEXABVGeomCamera3@2@@Z)
   *
   * IDA signature:
   * void __thiscall Moho::SkyDome::RenderAtmosphere(const GeomCamera3 &cam);
   *
   * What it does:
   * Selects the "Atmosphere" technique on the sky effect, feeds the camera
   * view position/projection plus the horizon begin/end, horizon/sky colors,
   * and horizon lookup texture, then renders the dome with that technique.
   */
  void SkyDome::RenderAtmosphere(const GeomCamera3& cam)
  {
    boost::shared_ptr<gpg::gal::EffectD3D9> effect = ResolveSkyEffect();
    boost::shared_ptr<gpg::gal::EffectTechniqueD3D9> technique = effect->SetTechnique("Atmosphere");

    const Vector4f& cameraPosition = cam.inverseView.r[3];
    const float viewPosition[3] = {cameraPosition.x, cameraPosition.y, cameraPosition.z};
    effect->SetMatrix("viewPosition")->SetPtr(viewPosition, sizeof(viewPosition));
    effect->SetMatrix("viewProjMatrix")->SetMatrix4x4(&cam.viewProjection);
    effect->SetMatrix("horizonBegin")->SetFloat(mDomeShapeParams.x);
    effect->SetMatrix("horizonEnd")->SetFloat(mHorizonSize + mDomeShapeParams.x);
    effect->SetMatrix("horizonColor")->SetPtr(&mHorizonColor, sizeof(mHorizonColor));
    effect->SetMatrix("skyColor")->SetPtr(&mSkyColor, sizeof(mSkyColor));
    effect->SetMatrix("horizonLookup")->SetTexture(mHorizonLookupTex);

    RenderDomeUsing(technique);
  }

  /**
   * Address: 0x00819650 (FUN_00819650, ?RenderCirrus@SkyDome@Moho@@AAEXHMABVGeomCamera3@2@@Z)
   *
   * IDA signature:
   * void __thiscall Moho::SkyDome::RenderCirrus(int tick, float interpolant, const GeomCamera3 &cam);
   *
   * What it does:
   * Selects the "Cirrus" technique, feeds the animation tick/interpolant lanes,
   * the camera position/projection, cirrus multiplier/color, cirrus texture,
   * and the packed cirrus parameter block, then renders the dome with that
   * technique.
   */
  void SkyDome::RenderCirrus(const int tick, const float interpolant, const GeomCamera3& cam)
  {
    boost::shared_ptr<gpg::gal::EffectD3D9> effect = ResolveSkyEffect();
    boost::shared_ptr<gpg::gal::EffectTechniqueD3D9> technique = effect->SetTechnique("Cirrus");

    effect->SetMatrix("tick")->Func6(tick);
    effect->SetMatrix("interpolant")->SetFloat(interpolant);

    const Vector4f& cameraPosition = cam.inverseView.r[3];
    const float viewPosition[3] = {cameraPosition.x, cameraPosition.y, cameraPosition.z};
    effect->SetMatrix("viewPosition")->SetPtr(viewPosition, sizeof(viewPosition));
    effect->SetMatrix("viewProjMatrix")->SetMatrix4x4(&cam.viewProjection);
    effect->SetMatrix("cirrusMultiplier")->SetFloat(mCirrusMultiplier);
    effect->SetMatrix("cirrusColor")->SetPtr(&mCirrusColor_R, 3 * sizeof(float));
    // 0x00819971: `mov eax, [ebp+214h]` / `mov eax, [ebp+218h]` — the
    // "cirrusTexture" sampler is fed from the +0x214 lane (mCirrusTex, loaded
    // by CreateTextures from mCirrusTexPath), not the +0x21C lane.
    effect->SetMatrix("cirrusTexture")->SetTexture(mCirrusTex);
    effect->SetMatrix("aCirrus")->SetPtr(mCirrusData, sizeof(mCirrusData));

    RenderDomeUsing(technique);
  }

  /**
   * Address: 0x00818FB0 (FUN_00818FB0, ?RenderCumulus@SkyDome@Moho@@AAEXHMABVGeomCamera3@2@ABV?$vector@UCumulusVertex@SkyDome@Moho@@V?$allocator@UCumulusVertex@SkyDome@Moho@@@std@@@std@@@Z)
   *
   * IDA signature:
   * void __thiscall Moho::SkyDome::RenderCumulus(int head, float deltaFrame,
   *     const GeomCamera3 &cam, const std::vector<CumulusVertex> &cumulusVertices);
   *
   * What it does:
   * When cumulus instance records exist, uploads them to the instanced cumulus
   * vertex stream, selects the "Cumulus" technique, binds the quad/instance/
   * index streams plus the cumulus dispersion/light ramp and cumulus textures,
   * then issues one indexed quad draw per technique pass.
   *
   * Note: `head`/`deltaFrame` carry the public Render dispatch lanes named by
   * the binary symbol; this pass consumes the camera and cumulus instance
   * stream.
   */
  void SkyDome::RenderCumulus(
    const int head,
    const float deltaFrame,
    const GeomCamera3& cam,
    const msvc8::vector<CumulusVertex>& cumulusVertices
  )
  {
    (void)head;
    (void)deltaFrame;

    const std::size_t cloudCount = cumulusVertices.size();
    if (cloudCount == 0) {
      return;
    }

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    boost::shared_ptr<gpg::gal::EffectD3D9> effect = ResolveSkyEffect();
    boost::shared_ptr<gpg::gal::EffectTechniqueD3D9> technique = effect->SetTechnique("Cumulus");

    // Upload the per-cloud instance records into the instanced cumulus stream.
    void* const instanceData = mDecalVertBuf3->Lock(0u, 0u, static_cast<gpg::gal::MohoD3DLockFlags>(0));
    std::memcpy(instanceData, cumulusVertices.data(), cloudCount * sizeof(CumulusVertex));
    mDecalVertBuf3->Unlock();

    device->SetVertexDeclaration(mDecalFormat2->mFormat);
    device->SetVertexBuffer(0u, mDecalVertBuf1, static_cast<int>(cloudCount), 0);
    device->SetVertexBuffer(1u, mDecalVertBuf3, 1, 0);
    device->SetBufferIndices(mDecalIndexBuf);

    const float viewRightVec[3] = {cam.view.r[0].x, cam.view.r[1].x, cam.view.r[2].x};
    effect->SetMatrix("viewRight")->SetPtr(viewRightVec, sizeof(viewRightVec));

    const float viewUpVec[3] = {cam.view.r[0].y, cam.view.r[1].y, cam.view.r[2].y};
    effect->SetMatrix("viewUp")->SetPtr(viewUpVec, sizeof(viewUpVec));

    const Vector4f& cameraPosition = cam.inverseView.r[3];
    const float viewPosition[3] = {cameraPosition.x, cameraPosition.y, cameraPosition.z};
    effect->SetMatrix("viewPosition")->SetPtr(viewPosition, sizeof(viewPosition));
    effect->SetMatrix("viewProjMatrix")->SetMatrix4x4(&cam.viewProjection);

    effect->SetMatrix("cumulusDispersionRamp")->SetTexture(mDecalTex2);
    effect->SetMatrix("cumulusLightRamp")->SetTexture(mDecalTex1);
    effect->SetMatrix("cumulusTexture")->SetTexture(mDecalTex3);

    const unsigned int passCount = static_cast<unsigned int>(technique->BeginTechnique());
    for (unsigned int pass = 0; pass < passCount; ++pass) {
      technique->BeginPass(static_cast<int>(pass));
      gpg::gal::DrawIndexedContext drawContext(kSkyTopologyTriangleList, 4, 6, 0, 0);
      device->DrawIndexedPrimitive(&drawContext);
      technique->EndPass();
    }
    technique->EndTechnique();
  }

  /**
   * Address: 0x00819C90 (FUN_00819C90, ?RenderDecals@SkyDome@Moho@@AAEXABVGeomCamera3@2@@Z)
   *
   * IDA signature:
   * void __thiscall Moho::SkyDome::RenderDecals(const GeomCamera3 &cam);
   *
   * What it does:
   * When decal records and both decal textures exist, flushes the decal upload
   * buffer, selects the "Decal" technique, binds the decal billboard/instance/
   * index streams plus albedo/glow textures and the glow multiplier, then
   * issues one indexed quad draw per technique pass.
   */
  void SkyDome::RenderDecals(const GeomCamera3& cam)
  {
    if (mDecalUploadCount == 0 || !mAtmosphereTex || !mAtmosphereTex2) {
      return;
    }

    UpdateDecalBuffer();

    auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
    boost::shared_ptr<gpg::gal::EffectD3D9> effect = ResolveSkyEffect();
    boost::shared_ptr<gpg::gal::EffectTechniqueD3D9> technique = effect->SetTechnique("Decal");

    device->SetVertexDeclaration(mDecalFormat1->mFormat);
    device->SetVertexBuffer(0u, mDecalVertBuf1, static_cast<int>(mDecalUploadCount), 0);
    device->SetVertexBuffer(1u, mDecalVertBuf2, 1, 0);
    device->SetBufferIndices(mDecalIndexBuf);

    const float viewRightVec[3] = {cam.view.r[0].x, cam.view.r[1].x, cam.view.r[2].x};
    effect->SetMatrix("viewRight")->SetPtr(viewRightVec, sizeof(viewRightVec));

    const float viewUpVec[3] = {cam.view.r[0].y, cam.view.r[1].y, cam.view.r[2].y};
    effect->SetMatrix("viewUp")->SetPtr(viewUpVec, sizeof(viewUpVec));

    const Vector4f& cameraPosition = cam.inverseView.r[3];
    const float viewPosition[3] = {cameraPosition.x, cameraPosition.y, cameraPosition.z};
    effect->SetMatrix("viewPosition")->SetPtr(viewPosition, sizeof(viewPosition));
    effect->SetMatrix("viewProjMatrix")->SetMatrix4x4(&cam.viewProjection);
    effect->SetMatrix("decalGlowMultiplier")->SetFloat(mHorizonBlend);
    effect->SetMatrix("decalAlbedoTexture")->SetTexture(mAtmosphereTex);
    effect->SetMatrix("decalGlowTexture")->SetTexture(mAtmosphereTex2);

    const unsigned int passCount = static_cast<unsigned int>(technique->BeginTechnique());
    for (unsigned int pass = 0; pass < passCount; ++pass) {
      technique->BeginPass(static_cast<int>(pass));
      gpg::gal::DrawIndexedContext drawContext(kSkyTopologyTriangleList, 4, 6, 0, 0);
      device->DrawIndexedPrimitive(&drawContext);
      technique->EndPass();
    }
    technique->EndTechnique();
  }
} // namespace moho
