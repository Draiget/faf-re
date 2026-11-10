#include "moho/render/Shadow.h"

#include <Windows.h>

#include <cstring>
#include <new>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/effects/ShadowCascades.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DVertexSheet.h"
#include "moho/render/RayScene.h"
#include "moho/render/ScreenQuadVertexSheet.h"
#include "moho/render/ShadowCascadeFit.h"
#include "moho/render/ShadowStableFit.h"
#include "moho/render/d3d/CD3DDepthStencil.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DRenderTarget.h"
#include "moho/collision/CGeomSolid3.h"
#include "moho/console/CConCommand.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"
#include "moho/terrain/water/WaterSurface.h"
#include "moho/terrain/TerrainCommon.h"
#include "moho/terrain/TerrainShaderVars.h"
#include "moho/mesh/Mesh.h"
#include "gpg/gal/RenderTargetContext.hpp"

namespace gpg::gal
{
  long DebugSaveSurfaceToFileA(const char* filePath, unsigned int fileFormat, void* sourceSurface);
}
// The Direct3D 9 backend is Windows-only (the Linux client, issue #255).
#if defined(_WIN32)
#include "gpg/gal/backends/d3d9/RenderTargetD3D9.hpp"
#endif

#include <algorithm>
#include <cmath>
#include <vector>
#include "moho/render/d3d/CD3DVertexSheet.h"

namespace
{
  // Depth-stencil format the shadow map's companion buffer is created with.
  constexpr int kShadowDepthStencilFormat = 3;

  struct BlinkyBoxListNode
  {
    BlinkyBoxListNode* next;
    BlinkyBoxListNode* prev;
  };

  BlinkyBoxListNode gBlinkyBoxesListHead{&gBlinkyBoxesListHead, &gBlinkyBoxesListHead};

  /**
   * Address: 0x007FE040 (FUN_007FE040)
   *
   * What it does:
   * Unlinks one blinky-box node from its current intrusive list and reinserts
   * it at the head of the global blinky-box list.
   */
  [[maybe_unused]] [[nodiscard]] BlinkyBoxListNode* RelinkBlinkyBoxNodeToGlobalHead(BlinkyBoxListNode* const node)
  {
    if (node == nullptr || node->next == nullptr || node->prev == nullptr) {
      return node;
    }

    node->next->prev = node->prev;
    node->prev->next = node->next;
    node->next = node;
    node->prev = node;

    node->next = gBlinkyBoxesListHead.next;
    node->prev = &gBlinkyBoxesListHead;
    gBlinkyBoxesListHead.next = node;
    node->next->prev = node;
    return node;
  }
} // namespace

namespace moho
{
  extern int ren_ShadowSize;
  extern bool ren_ShadowBlur;
  extern float ren_ShadowCoeff;
  extern float ren_ShadowLOD;
  extern bool ren_Shadows;
  extern int shadow_Fidelity;
  extern int shadow_FidelitySupported;

  class IWldTerrainRes;

  // Defined in moho/app/WxRuntimeTypes.cpp (0x007FA170); folds in both the
  // map and terrain null checks.
  [[nodiscard]] IWldTerrainRes* REN_GetTerrainRes();

  namespace
  {
    /**
     * Engine addition: `ren_ShadowStable`. 1 fits the shadow map so its texels stay on the same
     * world positions while the camera pans, which stops shadow edges crawling (ShadowStableFit.h).
     * 0 is the binary's fit. -1 (the default) is 1 on every renderer but Direct3D 9, which keeps the
     * original look.
     */
    int ren_ShadowStable = -1;

    TConVar<int> gTConVar_ren_ShadowStable(
      "ren_ShadowStable",
      "Keep shadow texels on the same world positions while the camera pans: 1 on, 0 the original "
      "fit, -1 on except on Direct3D 9.",
      &ren_ShadowStable
    );

    /** Direct3D 9 keeps the sizes FAF's options slider had before it reached 4096. */
    constexpr int kShadowSizeLimitD3D9 = 2048;

    // The box lengths the stable fit used last frame, per axis. Shadow's layout is the binary's,
    // and the render thread alone reads these; two world views only cost each other the hold.
    float sShadowStableWidth = 0.0f;
    float sShadowStableHeight = 0.0f;

    [[nodiscard]] bool RenderingOnD3D9()
    {
      gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
      const gpg::gal::DeviceContext* const context = device != nullptr ? device->GetDeviceContext() : nullptr;
      return context == nullptr || context->mDeviceType == gpg::gal::DeviceApi::Direct3D9;
    }

    [[nodiscard]] bool ShadowStableFitEnabled()
    {
      return ren_ShadowStable > 0 || (ren_ShadowStable < 0 && !RenderingOnD3D9());
    }

    /**
     * Engine addition: `ren_ShadowCascades`. On Direct3D 12 and Vulkan the shadow textures become a
     * 2x2 atlas of `ren_ShadowSize` tiles: one holds the map the original fits over the whole shadowed
     * view, and up to this many hold the same light space over the near part of the view at more texels
     * per world unit (gpg/gal/effects/ShadowCascades.h). 0 keeps the single map. A tile that would cover
     * nearly as much as the whole-view map both ways is skipped, so a top-down view draws only that one.
     */
    int ren_ShadowCascades = 3;

    TConVar<int> gTConVar_ren_ShadowCascades(
      "ren_ShadowCascades",
      "Finer shadow map tiles near the camera on Direct3D 12 and Vulkan (0-3, 0 the single original map).",
      &ren_ShadowCascades
    );

    /**
     * Engine addition: `ren_ShadowCascadeSplit`. Tile k of n (0 the finest) reaches this fraction to the
     * power n - k of the shadowed depth range, so with 3 tiles and 0.5 they reach 1/8, 1/4 and 1/2 of it.
     */
    float ren_ShadowCascadeSplit = 0.5f;

    TConVar<float> gTConVar_ren_ShadowCascadeSplit(
      "ren_ShadowCascadeSplit",
      "How far each finer shadow tile reaches: tile k of n covers this to the power n - k of the shadowed depth.",
      &ren_ShadowCascadeSplit
    );

    /**
     * Engine addition: `ren_ShadowCasterCull`. The light camera's box is fitted around the shadowed part
     * of the view, so it also holds meshes whose shadows fall only outside it; at near zoom it held twice
     * the meshes the view draws. With this on, a mesh is drawn into the shadow map only when its bounding
     * sphere, moved along the light down to the lowest terrain in view, can reach the shadowed part of
     * the view (ShadowCasterRegion in Mesh.h). Shadows outside the view, which only a water reflection
     * might show, can lose casters.
     */
    bool ren_ShadowCasterCull = true;

    TConVar<bool> gTConVar_ren_ShadowCasterCull(
      "ren_ShadowCasterCull",
      "Draw into the shadow map only the meshes whose shadow can fall in the view (1, the default), or every mesh in "
      "the light's box (0, the original).",
      &ren_ShadowCasterCull
    );

    /** Shadow-map texels around the shadowed region whose casters are kept: the blur's reach and the filter's. */
    constexpr float kCasterMarginTexels = 6.0f;

    /** This frame's shadowed region, from PrepareLightCamera, for RenderShadowMap's mesh batches. */
    ShadowCasterRegion sCasterRegion{};

    /**
     * Engine addition: `ren_ShadowTileReuse`. The finer cascade tiles take their meshes from the
     * whole-view tile's batch, filtered by their own box (MeshRenderer::BatchFromSaved), instead of a
     * full Batch each: a second spatial query, LOD walk and bucket build per tile.
     */
    bool ren_ShadowTileReuse = true;

    TConVar<bool> gTConVar_ren_ShadowTileReuse(
      "ren_ShadowTileReuse",
      "Finer shadow tiles reuse the whole-view tile's mesh batch, filtered by their box (1, the default), or batch the "
      "meshes again (0).",
      &ren_ShadowTileReuse
    );

    /** The whole-view tile's buckets this frame, while finer tiles follow. */
    std::vector<MeshRenderer::SavedBucket> sWholeTileBatch;

    constexpr int kCascadeTiles = static_cast<int>(gpg::gal::effects::kShadowCascadeCount);
    constexpr int kCascadeFiner = kCascadeTiles - 1;
    /** Texels around each tile's viewport the blur may smear into; nothing is drawn there. */
    constexpr int kCascadeGutter = 4;
    /** Texels inside a tile's edge a lookup keeps clear of: the blur's reach and the filter's footprint. */
    constexpr float kCascadeMargin = 5.0f;
    /** A finer tile covering more than this share of the whole-view map on both axes isn't worth drawing. */
    constexpr float kCascadeWorthIt = 0.75f;

    [[nodiscard]] bool RenderingOnModern()
    {
      gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
      const gpg::gal::DeviceContext* const context = device != nullptr ? device->GetDeviceContext() : nullptr;
      return context != nullptr &&
        (context->mDeviceType == gpg::gal::DeviceApi::Direct3D12 || context->mDeviceType == gpg::gal::DeviceApi::Vulkan);
    }

    [[nodiscard]] bool CascadeAtlasWanted()
    {
      return ren_ShadowCascades > 0 && RenderingOnModern() && !gpg::gal::effects::gShadowCascadesBlocked.load();
    }

    // The shadow renderers whose targets are the atlas. Shadow's layout is the binary's.
    // Each also holds two more blur quads: the blur covers only the tiles a frame draws, tile 0 alone or
    // the top row, and these read just that part of the atlas (the shadow renderer's own quad reads all).
    struct CascadeAtlas
    {
      const Shadow* shadow = nullptr;
      boost::shared_ptr<ID3DVertexSheet> firstTileQuad;
      boost::shared_ptr<ID3DVertexSheet> topRowQuad;
    };
    std::vector<CascadeAtlas> sAtlasShadows;

    [[nodiscard]] CascadeAtlas* FindCascadeAtlas(const Shadow& shadow)
    {
      for (CascadeAtlas& atlas : sAtlasShadows) {
        if (atlas.shadow == &shadow) {
          return &atlas;
        }
      }
      return nullptr;
    }

    [[nodiscard]] bool IsCascadeAtlas(const Shadow& shadow)
    {
      return FindCascadeAtlas(shadow) != nullptr;
    }

    /** Texels across one atlas tile's viewport. */
    [[nodiscard]] int CascadeContent(const int tileSize)
    {
      return tileSize - (2 * kCascadeGutter);
    }

    // This frame's finer tiles, built by PrepareLightCamera and drawn by RenderShadowMap right after it,
    // and the box lengths each one's stable fit held last frame (as sShadowStableWidth for the whole map).
    struct CascadeFrame
    {
      int finer = 0;
      GeomCamera3 cameras[kCascadeFiner];
    };
    CascadeFrame sCascadeFrame;
    float sCascadeHeldWidth[kCascadeFiner]{};
    float sCascadeHeldHeight[kCascadeFiner]{};

    /** Atlas tile `index`'s top-left texel: tiles go left to right, then down. */
    void CascadeTileOrigin(const int index, const int tileSize, int& x, int& y)
    {
      x = (index % 2) * tileSize;
      y = (index / 2) * tileSize;
    }

    /** Publishes what the effects' shadow lookups read (ShadowCascades.h); `count` 0 is the plain map. */
    void PublishCascades(const float (&vectors)[gpg::gal::effects::kShadowCascadeVectors][4])
    {
      gpg::gal::effects::ShadowCascadeConstants& constants = gpg::gal::effects::gShadowCascades;
      if (std::memcmp(constants.vectors, vectors, sizeof(constants.vectors)) != 0) {
        std::memcpy(constants.vectors, vectors, sizeof(constants.vectors));
        ++constants.version;
      }
    }

    void PublishNoCascades()
    {
      const float none[gpg::gal::effects::kShadowCascadeVectors][4]{};
      PublishCascades(none);
    }

    /**
     * The corners of the convex region inside every plane (normal . x <= constant, CGeomSolid3's
     * convention): each point three planes meet at that no plane excludes. Empty when the region is.
     */
    void ConvexRegionCorners(const Wm3::Plane3f* const planes, const std::size_t count, std::vector<Wm3::Vector3f>& corners)
    {
      corners.clear();
      const auto cross = [](const Wm3::Vector3f& a, const Wm3::Vector3f& b) {
        return Wm3::Vector3f(a.y * b.z - a.z * b.y, a.z * b.x - a.x * b.z, a.x * b.y - a.y * b.x);
      };
      const auto dot = [](const Wm3::Vector3f& a, const Wm3::Vector3f& b) { return a.x * b.x + a.y * b.y + a.z * b.z; };
      for (std::size_t a = 0U; a < count; ++a) {
        for (std::size_t b = a + 1U; b < count; ++b) {
          const Wm3::Vector3f bc = cross(planes[a].Normal, planes[b].Normal);
          for (std::size_t c = b + 1U; c < count; ++c) {
            const Wm3::Vector3f cb = cross(planes[b].Normal, planes[c].Normal);
            const float determinant = dot(planes[a].Normal, cb);
            if (std::fabs(determinant) < 1.0e-6f) {
              continue;
            }
            const Wm3::Vector3f ca = cross(planes[c].Normal, planes[a].Normal);
            const float scale = 1.0f / determinant;
            const Wm3::Vector3f point(
              (planes[a].Constant * cb.x + planes[b].Constant * ca.x + planes[c].Constant * bc.x) * scale,
              (planes[a].Constant * cb.y + planes[b].Constant * ca.y + planes[c].Constant * bc.y) * scale,
              (planes[a].Constant * cb.z + planes[b].Constant * ca.z + planes[c].Constant * bc.z) * scale
            );
            bool inside = true;
            for (std::size_t other = 0U; inside && other < count; ++other) {
              const float tolerance = 0.01f + 1.0e-5f * std::fabs(planes[other].Constant);
              inside = dot(planes[other].Normal, point) - planes[other].Constant <= tolerance;
            }
            if (inside) {
              corners.push_back(point);
            }
          }
        }
      }
    }
  } // namespace

  int ShadowTextureSize(const Shadow& shadow)
  {
    return IsCascadeAtlas(shadow) ? 2 * shadow.mShadowSize : shadow.mShadowSize;
  }

  int ShadowMapTexels(const Shadow& shadow)
  {
    return IsCascadeAtlas(shadow) ? CascadeContent(shadow.mShadowSize) : shadow.mShadowSize;
  }

  /**
   * Address: 0x009407D0 (FUN_009407D0, sub_9407D0)
   *
   * What it does:
   * Builds a right-handed look-at matrix. The binary forwards to D3DXMatrixLookAtRH.
   * Engine change (issue #317): computed here with D3DX's formula, so the client needs
   * D3DX9 only for the Direct3D 9 renderer. Against d3dx9_43 over 10^6 random inputs it
   * differs by at most 8.7e-6 of each term's scale (tmp/claude/half/lookat.cpp, 2026-11-06).
   */
  gpg::gal::Matrix* MatrixLookAtRH(
    gpg::gal::Matrix* const outMatrix,
    const Wm3::Vector3f* const eye,
    const Wm3::Vector3f* const target,
    const Wm3::Vector3f* const up
  )
  {
    Wm3::Vector3f zAxis{eye->x - target->x, eye->y - target->y, eye->z - target->z};
    const float zScale = 1.0f / std::sqrt(zAxis.x * zAxis.x + zAxis.y * zAxis.y + zAxis.z * zAxis.z);
    zAxis = {zAxis.x * zScale, zAxis.y * zScale, zAxis.z * zScale};

    Wm3::Vector3f xAxis{up->y * zAxis.z - up->z * zAxis.y, up->z * zAxis.x - up->x * zAxis.z,
                        up->x * zAxis.y - up->y * zAxis.x};
    const float xScale = 1.0f / std::sqrt(xAxis.x * xAxis.x + xAxis.y * xAxis.y + xAxis.z * xAxis.z);
    xAxis = {xAxis.x * xScale, xAxis.y * xScale, xAxis.z * xScale};

    const Wm3::Vector3f yAxis{zAxis.y * xAxis.z - zAxis.z * xAxis.y, zAxis.z * xAxis.x - zAxis.x * xAxis.z,
                              zAxis.x * xAxis.y - zAxis.y * xAxis.x};

    outMatrix->r[0] = {xAxis.x, yAxis.x, zAxis.x, 0.0f};
    outMatrix->r[1] = {xAxis.y, yAxis.y, zAxis.y, 0.0f};
    outMatrix->r[2] = {xAxis.z, yAxis.z, zAxis.z, 0.0f};
    outMatrix->r[3] = {-(xAxis.x * eye->x + xAxis.y * eye->y + xAxis.z * eye->z),
                       -(yAxis.x * eye->x + yAxis.y * eye->y + yAxis.z * eye->z),
                       -(zAxis.x * eye->x + zAxis.y * eye->y + zAxis.z * eye->z), 1.0f};
    return outMatrix;
  }

  /**
   * Address: 0x007FE120 (FUN_007FE120, ??0Shadow@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes shadow-renderer fidelity/size flags, constructs the light-space
   * camera at `+0x18`, and null-clears every resource handle.
   */
  Shadow::Shadow()
    : mShadowFidelity(0)
    , mShadowBlurEnabled(false)
    , mPadding0D_0F{}
    , mShadowSize(0)
    , mShadowCameraValid(false)
    , mPadding15_17{}
    , mCamera()
    , mShadowMap()
    , mBlurTargetA()
    , mBlurTargetB()
    , mDepthStencil()
    , mQuadVertexSheet()
    , mUnreferencedResources{}
  {}

  /**
   * Address: 0x007FE760 (FUN_007FE760)
   *
   * IDA signature:
   * int __usercall sub_7FE760@<eax>(Moho::Shadow *this@<esi>);
   *
   * What it does:
   * Clears the cached fidelity/blur/size settings and releases every render
   * resource the shadow renderer holds. Called from the destructor, from
   * `Init` (on entry and again on either failure path), and from
   * `WRenViewport::D3DWindowOnDeviceExit` when the device drops its
   * default-pool resources.
   */
  int Shadow::ReleaseRenderResources() noexcept
  {
    mShadowFidelity = 0;
    mShadowBlurEnabled = false;

    mShadowMap.reset();
    mBlurTargetA.reset();
    mBlurTargetB.reset();
    mDepthStencil.reset();
    mQuadVertexSheet.reset();
    for (boost::shared_ptr<void>& resource : mUnreferencedResources) {
      resource.reset();
    }

    mShadowSize = 0;
    // Engine addition (ren_ShadowCascades): the targets that were the atlas are gone.
    sAtlasShadows.erase(
      std::remove_if(sAtlasShadows.begin(), sAtlasShadows.end(), [this](const CascadeAtlas& atlas) { return atlas.shadow == this; }),
      sAtlasShadows.end()
    );
    return 0;
  }

  /**
   * Address: 0x007FE200 (FUN_007FE200, ??1Shadow@Moho@@UAE@XZ)
   *
   * What it does:
   * Runs non-deleting teardown for one shadow runtime object.
   */
  Shadow::~Shadow()
  {
    (void)ReleaseRenderResources();
  }

  /**
   * Address: 0x007FEE70 (FUN_007FEE70)
   *
   * What it does:
   * Selects `mBlurTargetB` (+0x2F0) when `mShadowBlurEnabled` (+0x0C) is set,
   * otherwise `mShadowMap` (+0x2E0), and returns a retained copy.
   */
  boost::shared_ptr<CD3DRenderTarget> Shadow::GetShadowTexture() const
  {
    return mShadowBlurEnabled ? mBlurTargetB : mShadowMap;
  }

  /**
   * Address: 0x007DB350 (FUN_007DB350)
   *
   * What it does:
   * Returns a retained copy of the shadow-map render target for shader binding.
   */
  boost::shared_ptr<CD3DRenderTarget>& Shadow::GetShadowMap(
    boost::shared_ptr<CD3DRenderTarget>& outShadowMap
  ) const
  {
    outShadowMap = mShadowMap;
    return outShadowMap;
  }

  /**
   * Address: 0x007FE3E0 (FUN_007FE3E0, Moho::Shadow::Init)
   *
   * IDA signature:
   * int __usercall Moho::Shadow::Init@<eax>(int fidelity, Moho::Shadow *this);
   *
   * What it does:
   * Rebuilds every shadow render resource for the requested fidelity. Latches
   * the current shadow-size/blur tuning, drops what was held before, and for a
   * non-zero fidelity allocates the shadow-map target (plus the two blur
   * ping-pong targets when blur is enabled), the depth stencil, and the
   * fullscreen quad the blur passes draw - scaled to the shadow resolution.
   */
  int Shadow::Init(const int fidelity)
  {
    // Both tuning values are sampled before the reset below, which zeroes the
    // cached copies.
    const int shadowSize = RenderingOnD3D9() ? std::min(ren_ShadowSize, kShadowSizeLimitD3D9) : ren_ShadowSize;
    const bool shadowBlur = ren_ShadowBlur;

    (void)ReleaseRenderResources();

    mShadowFidelity = fidelity;
    mShadowBlurEnabled = shadowBlur;
    mShadowSize = shadowSize;

    if (fidelity == 0) {
      return 1;
    }

    // Fidelity 1 uses the cheaper target format; every higher level uses the
    // wider one.
    const int targetFormat = (fidelity != 1) ? 7 : 2;

    // The binary pulls the GAL device singleton here and discards it; the call
    // is kept because it is what forces the backend to be resolved before the
    // resource factory below is used.
    (void)gpg::gal::Device::GetInstance();

    ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();

    // Engine addition (ren_ShadowCascades): every target is the 2x2 atlas of shadowSize tiles.
    const bool atlas = CascadeAtlasWanted() && CascadeContent(shadowSize) > 64;
    const int textureSize = atlas ? 2 * shadowSize : shadowSize;

    resources->CreateRenderTarget(mShadowMap, textureSize, textureSize, targetFormat);
    if (mShadowBlurEnabled) {
      resources->CreateRenderTarget(mBlurTargetA, textureSize, textureSize, targetFormat);
      resources->CreateRenderTarget(mBlurTargetB, textureSize, textureSize, targetFormat);
    }

    resources->CreateDepthStencil(mDepthStencil, textureSize, textureSize, kShadowDepthStencilFormat);
    if (!mDepthStencil) {
      gpg::Warnf("unable to create depth sheet used by the shadow map");
      (void)ReleaseRenderResources();
      return 0;
    }

    CD3DVertexFormat* const vertexFormat = resources->GetVertexFormat(kScreenQuadVertexFormatToken);
    mQuadVertexSheet.reset(
      resources->NewVertexSheet(kScreenQuadStreamUsage, kScreenQuadVertexCount, vertexFormat)
    );
    if (!mQuadVertexSheet) {
      gpg::Warnf("unable to create the main vertex sheet used by the shadow map");
      (void)ReleaseRenderResources();
      return 0;
    }

    // The template is a unit quad; scale it out to the shadow-map resolution.
    // The binary leaves the texture coordinates alone, which is what passing
    // 1.0f for both texture scales does here.
    const float shadowSizeF = static_cast<float>(textureSize);
    FillScreenQuadVertexSheet(*mQuadVertexSheet, shadowSizeF, shadowSizeF, 1.0f, 1.0f);
    if (atlas) {
      CascadeAtlas entry{};
      entry.shadow = this;
      entry.firstTileQuad.reset(resources->NewVertexSheet(kScreenQuadStreamUsage, kScreenQuadVertexCount, vertexFormat));
      entry.topRowQuad.reset(resources->NewVertexSheet(kScreenQuadStreamUsage, kScreenQuadVertexCount, vertexFormat));
      if (entry.firstTileQuad && entry.topRowQuad) {
        FillScreenQuadVertexSheet(*entry.firstTileQuad, shadowSizeF, shadowSizeF, 0.5f, 0.5f);
        FillScreenQuadVertexSheet(*entry.topRowQuad, shadowSizeF, shadowSizeF, 1.0f, 0.5f);
      }
      sAtlasShadows.push_back(entry);
    }
    return 1;
  }

  /**
   * Address: 0x007FE1A0 (FUN_007FE1A0)
   *
   * What it does:
   * Runs one deleting-destructor thunk for `Shadow`, forwarding through
   * `Shadow::~Shadow` and optional storage release.
   */
  [[nodiscard]] Shadow* DestroyShadowDeleting(Shadow* const shadow, const unsigned char deleteFlag)
  {
    shadow->~Shadow();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(shadow));
    }
    return shadow;
  }
  /**
   * Address: 0x007FE940 (FUN_007FE940, sub_7FE940)
   *
   * What it does:
   * Builds the light-space camera the shadow map is rendered with.
   *
   * The light basis is built around the sun direction, using the camera's
   * forward axis as the reference up - unless the two are nearly parallel
   * (dot >= 0.99), where the cross products would collapse and a fixed
   * (0, 0, -1) is used instead.
   *
   * The view frustum's far plane is pulled in to `ren_ShadowCoeff * zoom`
   * before the terrain clip, which is what keeps the shadow volume tight
   * as the camera zooms rather than covering the whole visible distance.
   *
   * The eye sits 10000 units back along the light direction - far enough
   * that the projection is effectively directional - and the near plane is
   * pushed a further 25 units out so casters just behind the clipped volume
   * still reach it. The 8-unit lift on the box top is the same idea for
   * casters standing above the terrain.
   */
  bool ren_ShadowVolumeCache = true;
  namespace
  {
    struct ShadowVolumeMemo
    {
      static constexpr std::uint32_t kPlanes = 8U;
      bool valid = false;
      const CHeightField* field = nullptr;
      std::uint64_t terrainRevision = 0U;
      std::uint32_t planeCount = 0U;
      Wm3::Plane3f planes[kPlanes]{};
      Wm3::AxisAlignedBox3f volume{};
    };
    ShadowVolumeMemo sShadowVolume;

    TConVar<bool> gTConVar_ren_ShadowVolumeCache(
      "ren_ShadowVolumeCache",
      "The shadow volume's terrain intersection is kept while the frustum and terrain stay the same (1, the default), "
      "or computed each frame (0). Read each frame.",
      &ren_ShadowVolumeCache
    );
  } // namespace

  namespace
  {
    /** The light camera for a light-space box: PrepareLightCamera's projection, also each cascade tile's. */
    void BuildShadowLightCamera(
      const gpg::gal::Matrix& lightView,
      const float nearDepth,
      const float farDepth,
      const ShadowStableBox& box,
      GeomCamera3& camera
    )
    {
      gpg::gal::Matrix lightProjection{};
      lightProjection.r[0].x = 2.0f / (box.maxX - box.minX);
      lightProjection.r[1].y = 2.0f / (box.maxY - box.minY);
      lightProjection.r[2].z = 1.0f / (nearDepth - farDepth);
      lightProjection.r[3].x = (box.maxX + box.minX) / (box.minX - box.maxX);
      lightProjection.r[3].y = (box.minY + box.maxY) / (box.minY - box.maxY);
      lightProjection.r[3].z = lightProjection.r[2].z * nearDepth;
      lightProjection.r[3].w = 1.0f;

      gpg::gal::Matrix lightViewProjection{};
      (void)gpg::gal::Math::mul(&lightViewProjection, &lightView, &lightProjection);

      const VTransform identityTransform{VMatrix4::Identity()};
      camera.Init(identityTransform, lightViewProjection);
    }

    void PrepareCascades(
      int shadowSize,
      const Wm3::Vector3f& cameraForward,
      const CGeomSolid3& shadowFrustum,
      const Wm3::AxisAlignedBox3f& volume,
      const gpg::gal::Matrix& lightView,
      float nearDepth,
      float farDepth,
      const ShadowStableBox& base,
      int content,
      bool stableFit
    );
  } // namespace

  bool Shadow::PrepareLightCamera(
    const GeomCamera3& viewCamera,
    const Wm3::Vector3f& sunDirection,
    const float zoom
  )
  {
    mShadowCameraValid = false;
    if (mShadowFidelity == 0 || zoom > ren_ShadowLOD) {
      return false;
    }

    IWldTerrainRes* const terrainRes = REN_GetTerrainRes();
    if (terrainRes == nullptr) {
      return false;
    }
    // Same route the terrain passes use: the resource view carries the map,
    // and the map's height-field lane is the collision surface.
    CHeightField* const heightField = terrainRes->mMap->mHeightField.get();
    if (heightField == nullptr) {
      return false;
    }

    // The light travels along -sunDirection; the camera forward axis is
    // inverseView.r[2], also negated.
    const Wm3::Vector3f lightDirection(-sunDirection.X(), -sunDirection.Y(), -sunDirection.Z());
    const Vector4f& cameraBasisZ = viewCamera.inverseView.r[2];
    const Wm3::Vector3f cameraForward(-cameraBasisZ.x, -cameraBasisZ.y, -cameraBasisZ.z);

    Wm3::Vector3f lightUp(0.0f, 0.0f, -1.0f);
    const float alignment = (cameraForward.X() * lightDirection.X())
      + (cameraForward.Y() * lightDirection.Y())
      + (cameraForward.Z() * lightDirection.Z());
    if (alignment < 0.99f) {
      Wm3::Vector3f lightRight(
        (cameraForward.Z() * lightDirection.Y()) - (cameraForward.Y() * lightDirection.Z()),
        (cameraForward.X() * lightDirection.Z()) - (cameraForward.Z() * lightDirection.X()),
        (cameraForward.Y() * lightDirection.X()) - (cameraForward.X() * lightDirection.Y())
      );
      lightRight.Normalize();

      lightUp = Wm3::Vector3f(
        (lightRight.Y() * lightDirection.Z()) - (lightRight.Z() * lightDirection.Y()),
        (lightRight.Z() * lightDirection.X()) - (lightRight.X() * lightDirection.Z()),
        (lightRight.X() * lightDirection.Y()) - (lightRight.Y() * lightDirection.X())
      );
      lightUp.Normalize();
    }

    // Clip the view frustum to the shadow distance, then to the terrain.
    CGeomSolid3 shadowFrustum{viewCamera.solid2};
    shadowFrustum.planes_[5].Constant =
      (ren_ShadowCoeff * zoom) - shadowFrustum.planes_[4].Constant;

    // Engine change (ren_ShadowVolumeCache): the same frustum and terrain give the same box, and this
    // walk of the height field's tiers was 2 % of a frame at near zoom.
    Wm3::AxisAlignedBox3f volume{};
    const std::uint64_t terrainRevision = HeightFieldRevision();
    const std::uint32_t planeCount = static_cast<std::uint32_t>(shadowFrustum.planes_.Size());
    bool cached = ren_ShadowVolumeCache && sShadowVolume.valid && sShadowVolume.field == heightField &&
      sShadowVolume.terrainRevision == terrainRevision && sShadowVolume.planeCount == planeCount &&
      planeCount <= ShadowVolumeMemo::kPlanes;
    for (std::uint32_t index = 0U; cached && index < planeCount; ++index) {
      cached = std::memcmp(&sShadowVolume.planes[index], &shadowFrustum.planes_[index], sizeof(Wm3::Plane3f)) == 0;
    }
    if (cached) {
      volume = sShadowVolume.volume;
    } else {
      volume = heightField->ConvexIntersection(shadowFrustum);
      sShadowVolume.valid = planeCount <= ShadowVolumeMemo::kPlanes;
      sShadowVolume.field = heightField;
      sShadowVolume.terrainRevision = terrainRevision;
      sShadowVolume.planeCount = planeCount;
      for (std::uint32_t index = 0U; sShadowVolume.valid && index < planeCount; ++index) {
        sShadowVolume.planes[index] = shadowFrustum.planes_[index];
      }
      sShadowVolume.volume = volume;
    }
    if (volume.Max.X() <= volume.Min.X()) {
      return false;
    }

    // Lift the top so casters standing above the terrain still fit.
    volume.Max.Y() = volume.Max.Y() + 8.0f;

    // Engine addition: the stable fit looks at the world origin rather than the view centre, from
    // far enough back that the largest map stays in front of the eye. The camera's forward axis
    // sets the light's up axis above, and panning doesn't change it, so a pan leaves this light
    // space where it is. Zooming or turning the camera re-fits it, as the original always does.
    const bool stableFit = ShadowStableFitEnabled();
    const Wm3::Vector3f center = stableFit
      ? Wm3::Vector3f(0.0f, 0.0f, 0.0f)
      : Wm3::Vector3f(
          (volume.Min.X() + volume.Max.X()) * 0.5f,
          (volume.Min.Y() + volume.Max.Y()) * 0.5f,
          (volume.Min.Z() + volume.Max.Z()) * 0.5f
        );
    const float eyeDistance = stableFit ? 20000.0f : 10000.0f;
    const Wm3::Vector3f eye(
      center.X() - (lightDirection.X() * eyeDistance),
      center.Y() - (lightDirection.Y() * eyeDistance),
      center.Z() - (lightDirection.Z() * eyeDistance)
    );

    gpg::gal::Matrix lightView{};
    (void)MatrixLookAtRH(&lightView, &eye, &center, &lightUp);

    Wm3::AxisAlignedBox3f lightSpaceVolume{};
    (void)ProjectBoxByMatrix(
      &lightView, &volume, &lightSpaceVolume);

    const float nearMagnitude = std::fabs(lightSpaceVolume.Max.Z());
    const float farMagnitude = std::fabs(lightSpaceVolume.Min.Z());
    const float nearDepth = std::min(nearMagnitude, farMagnitude) - 25.0f;
    const float farDepth = std::max(nearMagnitude, farMagnitude);

    ShadowStableBox box{
      lightSpaceVolume.Min.X(),
      lightSpaceVolume.Max.X(),
      lightSpaceVolume.Min.Y(),
      lightSpaceVolume.Max.Y(),
    };
    // Engine addition (ren_ShadowCascades): in the atlas the whole-view map is one tile, drawn into a
    // viewport the gutters inset (the stable fit's size argument is that viewport plus its usual border).
    const bool atlas = IsCascadeAtlas(*this);
    const int content = atlas ? CascadeContent(mShadowSize) : mShadowSize - 2;
    if (stableFit) {
      box = FitShadowStableBox(box.minX, box.maxX, box.minY, box.maxY, content + 2, sShadowStableWidth, sShadowStableHeight);
    }

    // Orthographic projection fitted to the light-space volume, built by
    // hand rather than through a helper - the binary writes these seven
    // elements and zeroes the rest (BuildShadowLightCamera).
    BuildShadowLightCamera(lightView, nearDepth, farDepth, box, mCamera);

    // Engine addition (ren_ShadowCasterCull): the region the mesh batches keep casters for.
    sCasterRegion = ShadowCasterRegion{};
    {
      const float lightLength = std::sqrt(
        lightDirection.X() * lightDirection.X() + lightDirection.Y() * lightDirection.Y() +
        lightDirection.Z() * lightDirection.Z()
      );
      if (planeCount <= ShadowCasterRegion::kMaxPlanes && lightLength > 0.0f) {
        for (std::uint32_t index = 0U; index < planeCount; ++index) {
          const Wm3::Plane3f& plane = shadowFrustum.planes_[index];
          sCasterRegion.planes[index][0] = plane.Normal.x;
          sCasterRegion.planes[index][1] = plane.Normal.y;
          sCasterRegion.planes[index][2] = plane.Normal.z;
          sCasterRegion.planes[index][3] = plane.Constant;
        }
        sCasterRegion.planeCount = planeCount;
        sCasterRegion.light[0] = lightDirection.X() / lightLength;
        sCasterRegion.light[1] = lightDirection.Y() / lightLength;
        sCasterRegion.light[2] = lightDirection.Z() / lightLength;
        sCasterRegion.floorY = volume.Min.Y();
        const float texel = std::max(box.maxX - box.minX, box.maxY - box.minY) / static_cast<float>(content);
        sCasterRegion.margin = kCasterMarginTexels * texel;
        sCasterRegion.active = true;
      }
    }

    mShadowCameraValid = true;
    if (atlas) {
      PrepareCascades(mShadowSize, cameraForward, shadowFrustum, volume, lightView, nearDepth, farDepth, box, content, stableFit);
    } else {
      PublishNoCascades();
    }
    return mShadowCameraValid;
  }

  namespace
  {
  /**
   * Engine addition (ren_ShadowCascades): fits this frame's finer atlas tiles and publishes where every
   * tile sits. Tile k covers the part of the shadowed view frustum, above the lowest terrain it shows and
   * below the volume's top, nearer than the split of the depth range (ren_ShadowCascadeSplit), in the
   * whole-view map's light space and cut to its box. RenderShadowMap batches the meshes for each tile.
   */
  void PrepareCascades(
    const int shadowSize,
    const Wm3::Vector3f& cameraForward,
    const CGeomSolid3& shadowFrustum,
    const Wm3::AxisAlignedBox3f& volume,
    const gpg::gal::Matrix& lightView,
    const float nearDepth,
    const float farDepth,
    const ShadowStableBox& base,
    const int content,
    const bool stableFit
  )
  {
    sCascadeFrame.finer = 0;

    // The frustum the map shadows, between the terrain's lowest and highest point in it.
    constexpr std::size_t kMaxPlanes = 16U;
    Wm3::Plane3f planes[kMaxPlanes]{};
    std::size_t planeCount = 0U;
    for (std::size_t index = 0U; index < shadowFrustum.planes_.Size() && planeCount + 3U < kMaxPlanes; ++index) {
      planes[planeCount++] = shadowFrustum.planes_[index];
    }
    planes[planeCount].Normal = Wm3::Vector3f(0.0f, 1.0f, 0.0f);
    planes[planeCount++].Constant = volume.Max.Y();
    planes[planeCount].Normal = Wm3::Vector3f(0.0f, -1.0f, 0.0f);
    planes[planeCount++].Constant = -volume.Min.Y();

    std::vector<Wm3::Vector3f> corners;
    ConvexRegionCorners(planes, planeCount, corners);
    const auto depthOf = [&](const Wm3::Vector3f& point) {
      return point.x * cameraForward.x + point.y * cameraForward.y + point.z * cameraForward.z;
    };
    float nearest = 0.0f;
    float farthest = 0.0f;
    for (std::size_t index = 0U; index < corners.size(); ++index) {
      const float depth = depthOf(corners[index]);
      nearest = (index == 0U) ? depth : std::min(nearest, depth);
      farthest = (index == 0U) ? depth : std::max(farthest, depth);
    }

    const int wanted = std::clamp(ren_ShadowCascades, 0, kCascadeFiner);
    const float split = std::clamp(ren_ShadowCascadeSplit, 0.05f, 0.95f);
    const float baseWidth = base.maxX - base.minX;
    const float baseHeight = base.maxY - base.minY;
    ShadowStableBox boxes[kCascadeFiner]{};
    if (!corners.empty() && farthest > nearest) {
      for (int finest = 0; finest < wanted; ++finest) {
        const float reach = nearest + (farthest - nearest) * std::pow(split, static_cast<float>(wanted - finest));
        planes[planeCount].Normal = cameraForward;
        planes[planeCount].Constant = reach;
        ConvexRegionCorners(planes, planeCount + 1U, corners);
        if (corners.empty()) {
          continue;
        }
        ShadowStableBox raw{};
        for (std::size_t index = 0U; index < corners.size(); ++index) {
          const Wm3::Vector3f& p = corners[index];
          const float x = p.x * lightView.r[0].x + p.y * lightView.r[1].x + p.z * lightView.r[2].x + lightView.r[3].x;
          const float y = p.x * lightView.r[0].y + p.y * lightView.r[1].y + p.z * lightView.r[2].y + lightView.r[3].y;
          raw.minX = (index == 0U) ? x : std::min(raw.minX, x);
          raw.maxX = (index == 0U) ? x : std::max(raw.maxX, x);
          raw.minY = (index == 0U) ? y : std::min(raw.minY, y);
          raw.maxY = (index == 0U) ? y : std::max(raw.maxY, y);
        }
        raw.minX = std::max(raw.minX, base.minX);
        raw.maxX = std::min(raw.maxX, base.maxX);
        raw.minY = std::max(raw.minY, base.minY);
        raw.maxY = std::min(raw.maxY, base.maxY);
        if (raw.maxX - raw.minX < 1.0f || raw.maxY - raw.minY < 1.0f ||
            (raw.maxX - raw.minX > kCascadeWorthIt * baseWidth && raw.maxY - raw.minY > kCascadeWorthIt * baseHeight)) {
          continue;
        }
        ShadowStableBox fitted = raw;
        if (stableFit) {
          fitted = FitShadowStableBox(
            raw.minX, raw.maxX, raw.minY, raw.maxY, content + 2, sCascadeHeldWidth[finest], sCascadeHeldHeight[finest]
          );
        } else {
          // One texel of room for the rasteriser at the edge, as the stable fit's margin gives.
          const float padX = (raw.maxX - raw.minX) / static_cast<float>(content);
          const float padY = (raw.maxY - raw.minY) / static_cast<float>(content);
          fitted = ShadowStableBox{raw.minX - padX, raw.maxX + padX, raw.minY - padY, raw.maxY + padY};
        }
        const int tile = sCascadeFrame.finer;
        boxes[tile] = fitted;
        BuildShadowLightCamera(lightView, nearDepth, farDepth, fitted, sCascadeFrame.cameras[tile]);
        ++sCascadeFrame.finer;
      }
    }

    // Diagnostics: FAF_SHADOW_CASCADE_LOG=1 logs the finer tiles drawn whenever their number changes.
    static const bool sLogTiles = [] {
      char value[8] = {};
      std::size_t length = 0;
      return ::getenv_s(&length, value, sizeof(value), "FAF_SHADOW_CASCADE_LOG") == 0 && value[0] == '1';
    }();
    static int sLoggedTiles = -1;
    if (sLogTiles && sCascadeFrame.finer != sLoggedTiles) {
      sLoggedTiles = sCascadeFrame.finer;
      gpg::Logf("shadow cascades: %d finer tiles (depth %.0f to %.0f)", sCascadeFrame.finer, nearest, farthest);
    }

    // What the effects read: the finer tiles finest first, then the whole-view map. Tile 0 of the atlas
    // is the whole-view map and tile 1 + k the k-th finer one.
    const float atlasSize = static_cast<float>(2 * shadowSize);
    float vectors[gpg::gal::effects::kShadowCascadeVectors][4]{};
    const int tiles = sCascadeFrame.finer + 1;
    vectors[0][0] = static_cast<float>(tiles);
    vectors[0][2] = 0.5f / atlasSize; // texel (0, 0): outside every viewport and the blur's, so cleared
    vectors[0][3] = 0.5f / atlasSize;
    for (int entry = 0; entry < tiles; ++entry) {
      const bool whole = entry == sCascadeFrame.finer;
      const int atlasTile = whole ? 0 : entry + 1;
      int originX = 0;
      int originY = 0;
      CascadeTileOrigin(atlasTile, shadowSize, originX, originY);
      const ShadowCascadeLookup lookup = FitShadowCascadeLookup(
        base, whole ? base : boxes[entry], static_cast<float>(originX + kCascadeGutter), static_cast<float>(originY + kCascadeGutter),
        static_cast<float>(content), atlasSize, kCascadeMargin
      );
      std::memcpy(vectors[1 + 2 * entry], lookup.box, sizeof(lookup.box));
      std::memcpy(vectors[2 + 2 * entry], lookup.map, sizeof(lookup.map));
    }
    PublishCascades(vectors);
  }
  } // namespace

  /**
   * Address: 0x007FEEA0 (FUN_007FEEA0, sub_7FEEA0)
   *
   * What it does:
   * Draws the shadow map for this frame: terrain depth first, then every
   * mesh, both from the light camera PrepareLightCamera built.
   *
   * With no valid light camera it only rebinds the targets and returns, so
   * the map is left cleared rather than holding the previous frame.
   *
   * Every pass insets its viewport by one pixel on each side. That border
   * is what stops the blur taps and the shadow lookup from sampling past
   * the edge of the map.
   *
   * When blur is on the depth map is turned into a variance map by two
   * separable passes, shadow map -> A -> B, each drawing the unit quad.
   */
  void Shadow::RenderShadowMap(TerrainCommon* const terrain, const GeomCamera3& viewCamera)
  {
    if (mShadowFidelity == 0) {
      RayScene::PublishOff();
      return;
    }

    CD3DDevice* const device = D3D_GetDevice();
    (void)device->GetResources();

    if (!mShadowCameraValid) {
      RayScene::PublishOff();
      // Nothing to draw - just leave the targets bound and cleared.
      device->SetRenderTarget1(mShadowMap.get(), mDepthStencil.get(), true, -1, 1.0f, 0);
      if (mShadowBlurEnabled) {
        device->SetRenderTarget1(mBlurTargetA.get(), mDepthStencil.get(), true, -1, 1.0f, 0);
        device->SetRenderTarget1(mBlurTargetB.get(), mDepthStencil.get(), true, -1, 1.0f, 0);
      }
      return;
    }

    gpg::gal::RenderTargetContext targetContext{};

    Wm3::Vector2i savedPos{};
    Wm3::Vector2i savedSize{};
    float savedMinDepth = 0.0f;
    float savedMaxDepth = 1.0f;

    // Binds one target and gives it a viewport inset by a one-pixel border.
    const auto bindTargetWithBorder =
      [&](const boost::shared_ptr<CD3DRenderTarget>& target) {
        device->GetView(&savedPos, &savedSize, &savedMinDepth, &savedMaxDepth);

        // The target's real extent, via its surface's context.
        ID3DRenderTarget::SurfaceHandle surface{};
        (void)target->GetSurface(surface);
        const gpg::gal::RenderTargetContext* const context =
          (surface != nullptr) ? surface->GetContext() : nullptr;
        if (context == nullptr) {
          return;
        }

        Wm3::Vector2i borderPos{1, 1};
        Wm3::Vector2i borderSize{
          static_cast<std::int32_t>(context->width_) - 2,
          static_cast<std::int32_t>(context->height_) - 2
        };
        device->SetViewport(&borderPos, &borderSize, savedMinDepth, savedMaxDepth);
      };

    const auto restoreViewport = [&]() {
      device->SetViewport(&savedPos, &savedSize, savedMinDepth, savedMaxDepth);
    };

    // Depth pass into the shadow map.
    device->SetRenderTarget1(mShadowMap.get(), mDepthStencil.get(), true, -1, 1.0f, 0);
    MeshRenderer* const meshRenderer = MeshRenderer::GetInstance();
    gShadowCasterRegion = ren_ShadowCasterCull ? sCasterRegion : ShadowCasterRegion{};

    // Engine addition (ren_RayTracedShadows): with rays, the ground and opaque meshes shadow by ray from the
    // scene built off the whole-view batch (RayScene.h); the map draws only alpha-tested meshes.
    bool rays = RayScene::Instance().Active();
    IWldTerrainRes* const rayTerrainRes = rays ? REN_GetTerrainRes() : nullptr;
    const CHeightField* const rayHeightField =
      (rayTerrainRes != nullptr && rayTerrainRes->mMap != nullptr) ? rayTerrainRes->mMap->mHeightField.get() : nullptr;
    if (!rays) {
      RayScene::PublishOff();
    }
    // Rays can drop out here (the device couldn't build the scene), or leave the ground uncovered (a tile still
    // being built, or one whose geometry failed): then this tile draws its terrain depth after all, and so do the
    // rest.
    bool terrainInMap = !rays;
    const auto submitRays = [&](const GeomCamera3& tileCamera) {
      if (rays) {
        // The map's sun direction points towards the sun (PrepareLightCamera's light travels along its negative).
        const Wm3::Vector3f sun = rayTerrainRes->GetSunDirection();
        const float sunDirection[3] = {sun.X(), sun.Y(), sun.Z()};
        rays = RayScene::Instance().Submit(*meshRenderer, meshRenderer->meshes, rayHeightField, mCamera, viewCamera, sunDirection);
        if (!terrainInMap && (!rays || !RayScene::Instance().TerrainTraced())) {
          terrain->DrawTerrainDepth(tileCamera);
          terrainInMap = true;
        }
      }
    };
    if (IsCascadeAtlas(*this)) {
      // Engine addition (ren_ShadowCascades): each tile draws into its own viewport of the atlas, with the
      // meshes batched for its own light camera. Drawing the whole-view batch into every tile and leaving
      // the rest to clipping cost four times the mesh depth work (Vulkan top view: +0.48 ms with it,
      // +0.10 ms without meshes in the finer tiles, tmp/claude/csm/split).
      device->GetView(&savedPos, &savedSize, &savedMinDepth, &savedMaxDepth);
      const int content = CascadeContent(mShadowSize);
      for (int tile = 0; tile <= sCascadeFrame.finer; ++tile) {
        int originX = 0;
        int originY = 0;
        CascadeTileOrigin(tile, mShadowSize, originX, originY);
        Wm3::Vector2i tilePos{originX + kCascadeGutter, originY + kCascadeGutter};
        Wm3::Vector2i tileSize{content, content};
        device->SetViewport(&tilePos, &tileSize, savedMinDepth, savedMaxDepth);
        const GeomCamera3& camera = (tile == 0) ? mCamera : sCascadeFrame.cameras[tile - 1];
        if (terrainInMap) {
          terrain->DrawTerrainDepth(camera);
        }
        // Engine change (ren_ShadowTileReuse): a finer tile's box lies inside the whole-view tile's, in the same
        // light space and depth range, so its meshes are the whole-view tile's that fall in its box.
        if (tile > 0 && ren_ShadowTileReuse) {
          meshRenderer->BatchFromSaved(REN_GetGameTick(), REN_GetSimDeltaSeconds(), camera, sWholeTileBatch);
        } else {
          meshRenderer->Batch(REN_GetGameTick(), REN_GetSimDeltaSeconds(), camera, viewCamera.viewport.r[1]);
          if (tile == 0 && ren_ShadowTileReuse && sCascadeFrame.finer > 0) {
            meshRenderer->SaveBatch(sWholeTileBatch);
          }
        }
        if (tile == 0) {
          submitRays(camera);
        }
        meshRenderer->RenderDepth(camera, meshRenderer->meshes);
      }
    } else {
      bindTargetWithBorder(mShadowMap);

      if (terrainInMap) {
        terrain->DrawTerrainDepth(mCamera);
      }

      meshRenderer->Batch(REN_GetGameTick(), REN_GetSimDeltaSeconds(), mCamera, viewCamera.viewport.r[1]);
      submitRays(mCamera);
      meshRenderer->RenderDepth(mCamera, meshRenderer->meshes);
    }
    gShadowCasterRegion.active = false;

    restoreViewport();
    // Engine addition (ren_RayTracedShadows): only the shadow pass leaves the traced meshes out.
    gMeshDepthSkipsTraced = false;
    gMeshDepthSkipsAlpha = false;

    const auto dumpShadowTargets = [&](const bool includeBlur) {
#if defined(_WIN32)
      static bool sDumped = false;
      static unsigned sDumpCalls = 0;
      if (sDumped || (sDumpCalls++ % 120u) != 60u) {
        return;
      }
      char dir[512] = {};
      std::size_t length = 0;
      if (::getenv_s(&length, dir, sizeof(dir), "FAF_TOGGLE_DIR") != 0 || length == 0u) {
        return;
      }
      char path[600];
      (void)std::snprintf(path, sizeof(path), "%s\\dumpshadow.on", dir);
      if (::GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        return;
      }
      sDumped = true;
      const auto dump = [&](const boost::shared_ptr<CD3DRenderTarget>& target, const char* const name) {
        if (!target) {
          return;
        }
        ID3DRenderTarget::SurfaceHandle surface{};
        (void)target->GetSurface(surface);
        if (!surface) {
          return;
        }
        (void)std::snprintf(path, sizeof(path), "%s\\%s.bmp", dir, name);
        const long hr = gpg::gal::DebugSaveSurfaceToFileA(
          path, 0U, static_cast<gpg::gal::RenderTargetD3D9*>(surface.get())->GetSurface()
        );
        gpg::Warnf("[SHADOWDUMP] %s -> %s hr=0x%08lX size=%d blur=%d valid=%d", name, path, hr, mShadowSize,
                   mShadowBlurEnabled ? 1 : 0, mShadowCameraValid ? 1 : 0);
      };
      dump(mShadowMap, "shadow_raw");
      if (includeBlur) {
        dump(mBlurTargetB, "shadow_blurB");
      }
#else
      // The dump saves D3D9 surfaces; the Linux client has no D3D9 backend (issue #255).
      (void)includeBlur;
#endif
    };

    if (!mShadowBlurEnabled) {
      dumpShadowTargets(false);
      return;
    }

    auto& shaderVars = GetTerrainShaderVars();

    // Engine addition (ren_ShadowCascades): the atlas blurs only the tiles this frame drew - tile 0, the
    // top row, or all four - with a quad that reads just that part. The viewport is that part exactly, so
    // each blurred texel lines up with the texel it came from; the gutters keep the edge taps off the
    // tiles' content. The original's whole-map quad over a viewport inset one texel shifts its result by
    // up to two texels at the far edge.
    const CascadeAtlas* const atlas = FindCascadeAtlas(*this);
    ID3DVertexSheet* blurQuad = mQuadVertexSheet.get();
    Wm3::Vector2i blurSize{ShadowTextureSize(*this), ShadowTextureSize(*this)};
    if (atlas != nullptr && atlas->firstTileQuad && atlas->topRowQuad && sCascadeFrame.finer < 2) {
      blurQuad = (sCascadeFrame.finer == 0) ? atlas->firstTileQuad.get() : atlas->topRowQuad.get();
      blurSize.x = (sCascadeFrame.finer == 0) ? mShadowSize : 2 * mShadowSize;
      blurSize.y = mShadowSize;
    }

    // Separable variance blur: shadow map -> A (horizontal) -> B (vertical).
    const auto blurPass = [&](
      const boost::shared_ptr<CD3DRenderTarget>& target,
      const boost::shared_ptr<CD3DRenderTarget>& source,
      const char* const technique
    ) {
      device->SetRenderTarget1(target.get(), mDepthStencil.get(), true, -1, 1.0f, 0);
      if (atlas != nullptr) {
        device->GetView(&savedPos, &savedSize, &savedMinDepth, &savedMaxDepth);
        Wm3::Vector2i blurPos{0, 0};
        device->SetViewport(&blurPos, &blurSize, savedMinDepth, savedMaxDepth);
      } else {
        bindTargetWithBorder(target);
      }

      device->SelectFxFile("terrain");
      device->SelectTechnique(technique);
      (void)shaderVars.shadowSize.SetFloat(static_cast<float>(ShadowTextureSize(*this)));
      (void)shaderVars.shadowTexture.SetRenderTargetTexture(source);

      SD3DVertexRange quadView{};
      quadView.sheet = blurQuad;
      quadView.startVertex = 0;
      quadView.baseVertex = 0;
      quadView.endVertex = 3;
      std::int32_t primitiveType = 5;
      (void)device->DrawPrimitiveList(&quadView, &primitiveType);

      restoreViewport();
    };

    blurPass(mBlurTargetA, mShadowMap, "THorizontalBlurDepthToVariance");
    blurPass(mBlurTargetB, mBlurTargetA, "TVerticalBlurDepthToVariance");
    dumpShadowTargets(true);
  }

  /**
   * Address: 0x007F7D10 (FUN_007F7D10,
   *          ?RenderShadows@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@M@Z)
   *
   * What it does:
   * The frame's shadow pass. Re-initialises the shadow renderer when any of
   * the three tuning lanes has moved since it was last built, derives the
   * light camera from the sun direction, and draws the map.
   *
   * The fidelity is clamped to what the device reports it can do, and the
   * clamped value is written back to the global - so a request for more than
   * the hardware supports is remembered as the value actually used, not the
   * value asked for.
   */
  void Shadow::RenderFrameShadows(TerrainCommon* const terrain, const GeomCamera3& viewCamera, const float zoom)
  {
    if (!ren_Shadows) {
      RayScene::PublishOff();
      return;
    }

    std::int32_t fidelity = std::min(shadow_Fidelity, shadow_FidelitySupported);
    if (fidelity < 0) {
      fidelity = 0;
    }
    shadow_Fidelity = fidelity;

    // Engine addition (ren_ShadowCascades): turning the atlas on or off rebuilds the targets too.
    const bool atlasChanged = mShadowFidelity != 0 &&
      (CascadeAtlasWanted() && CascadeContent(mShadowSize) > 64) != IsCascadeAtlas(*this);
    if (fidelity != mShadowFidelity
      || ren_ShadowSize != mShadowSize
      || ren_ShadowBlur != mShadowBlurEnabled
      || atlasChanged) {
      (void)Init(fidelity);

      // Init settles what could actually be allocated; publish that back.
      shadow_Fidelity = mShadowFidelity;
      ren_ShadowSize = mShadowSize;
      ren_ShadowBlur = mShadowBlurEnabled;
    }

    IWldTerrainRes* const terrainRes = REN_GetTerrainRes();
    if (terrainRes == nullptr) {
      return;
    }

    const Wm3::Vector3f sunDirection = terrainRes->GetSunDirection();
    if (!PrepareLightCamera(viewCamera, sunDirection, zoom)) {
      // Engine addition (ren_ShadowCascades): no tiles this frame, so no lookup follows last frame's.
      PublishNoCascades();
    }
    RenderShadowMap(terrain, viewCamera);
  }

} // namespace moho
