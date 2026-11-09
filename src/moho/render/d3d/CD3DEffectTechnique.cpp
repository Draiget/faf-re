#include "moho/render/d3d/CD3DEffectTechnique.h"
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <exception>
#include <mutex>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/Effect.hpp"
#include "gpg/gal/EffectContext.hpp"
#include "gpg/gal/EffectMacro.hpp"
#include "gpg/gal/EffectTechnique.hpp"
#include "gpg/gal/EffectVariable.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/TextureContext.h"
#include "gpg/gal/effects/EffectRuntime.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/ID3DTextureSheet.h"

namespace moho
{
  fa::string GetEngineVersion();

  bool ren_TerrainTessellation = false;

  TConVar<bool> gTConVar_ren_TerrainTessellation(
    "ren_TerrainTessellation",
    "Direct3D 12 and Vulkan: split the terrain into fine triangles near the camera and sink them where the ground "
    "texture is darker than its surroundings, so cracks and gaps between rocks get real depth "
    "(fafengine/effects/terrain_tess.fx). Read when the terrain effect loads: set it at startup "
    "(/con) or restart for a change to apply. Off by default.",
    &ren_TerrainTessellation
  );

  namespace
  {
    using Implementation = CD3DEffect::Technique::Implementation;


    using IntAnnotationTree = Implementation::IntAnnotationTree;
    using StringAnnotationTree = Implementation::StringAnnotationTree;
    using TechniqueSet = CD3DEffect::TechniqueSet;

    /**
     * MSVC8's `std::set` handed out a mutable iterator, so the shipped code
     * edits a technique's implementation lanes in place through one. This
     * container follows the modern rule and makes the element const, so the
     * edit needs saying out loud - the key the tree orders on is `mName`, and
     * nothing below touches it.
     */
    [[nodiscard]] CD3DEffect::Technique& MutableTechnique(const TechniqueSet::iterator it) noexcept
    {
      return const_cast<CD3DEffect::Technique&>(*it);
    }

    /**
     * FAF addition, not in the shipped binary (issue #307).
     *
     * The technique MSDF text draws with, appended to `primbatcher.fx`, which is FAF's game data. It
     * uses that file's vertex shader, sampler and variables. The distance range in screen pixels comes
     * as a constant rather than from `fwidth`, so it stays within `ps_2_0` for Direct3D 9.
     */
    constexpr const char kMsdfTechniqueSource[] = R"fx(

float MsdfPixelRange = 1.0;

float4 MsdfTextPS(
    float4 Pos : POSITION,
    float4 Diff : COLOR0,
    float2 Tex1 : TEXCOORD0) : COLOR
{
    float3 field = tex2D(LinearSampler, Tex1).rgb;
    float median = max(min(field.r, field.g), min(max(field.r, field.g), field.b));
    float4 color = Diff;
    color.a *= saturate(MsdfPixelRange * (median - 0.5) + 0.5) * AlphaMultiplier;
    return color;
}

technique TMsdfText
{
    pass P0
    {
        AlphaState( AlphaBlend_SrcAlpha_InvSrcAlpha_Write_RGB )
        DepthState( Depth_Disable )
        RasterizerState( Rasterizer_Cull_None )

#ifndef DIRECT3D10
        AlphaTestEnable = true;
        AlphaRef = 0;
        AlphaFunc = Greater;
#endif

        VertexShader = compile vs_1_1 PrimBatcherVS();
        PixelShader = compile ps_2_0 MsdfTextPS();
    }
}
)fx";

    [[nodiscard]] gpg::MemBuffer<char> AppendSource(const gpg::MemBuffer<char>& source, const char* const tail, const std::size_t tailBytes)
    {
      const std::size_t sourceBytes = source.Size();
      gpg::MemBuffer<char> merged = gpg::AllocMemBuffer(sourceBytes + 1u + tailBytes);
      std::memcpy(merged.data(), source.data(), sourceBytes);
      merged.data()[sourceBytes] = '\n'; // the source may end without one
      std::memcpy(merged.data() + sourceBytes + 1u, tail, tailBytes);
      return merged;
    }

    /**
     * Engine addition (ren_TerrainTessellation).
     *
     * The tessellated terrain techniques, `fafengine/effects/terrain_tess.fx` next to the
     * executable (data/fafengine in the repository), appended to FAF's `terrain.fx` on Direct3D 12
     * and Vulkan, the renderers with hull and domain shaders. Empty on any other renderer or when
     * the file is missing.
     */
    [[nodiscard]] gpg::MemBuffer<const char> TerrainTessellationSource(
      const gpg::gal::DeviceContext* const deviceContext, FWaitHandleSet* const waitHandleSet
    )
    {
      if (deviceContext == nullptr || (deviceContext->mDeviceType != gpg::gal::DeviceApi::Direct3D12 &&
                                       deviceContext->mDeviceType != gpg::gal::DeviceApi::Vulkan)) {
        return {};
      }
      fa::string mountedPath{};
      (void)waitHandleSet->mHandle->FindFile(&mountedPath, "/fafengine/effects/terrain_tess.fx", nullptr);
      if (mountedPath.empty()) {
        gpg::Logf("terrain: /fafengine/effects/terrain_tess.fx not found; no terrain tessellation");
        return {};
      }
      return DISK_MemoryMapFile(mountedPath.c_str());
    }

    /**
     * FAF addition, not in the shipped binary.
     *
     * What it does:
     * Decides whether an effect is compiled with FAF_BONE_TEXTURE, which makes
     * FAF's mesh.fx read the skinning palette from a vertex texture (see
     * `HardwareMeshBatch::UsesBoneTexture`). The source has to mention the
     * macro - any other effect would only gain a second cache file - the
     * device has to be Direct3D 9 and able to read a float4 texture in a
     * vertex shader, and /nobonetexture on the command line turns it off.
     */
    [[nodiscard]] bool WantsBoneTextureVariant(
      const gpg::gal::DeviceContext* const deviceContext, const gpg::MemBuffer<const char>& source
    )
    {
      constexpr std::string_view kMacroName = "FAF_BONE_TEXTURE";

      if (deviceContext == nullptr || gpg::gal::UsesD3D10EffectDialect(deviceContext->mDeviceType)) {
        return false;
      }

      const char* const text = source.GetPtr(0U, 0U);
      if (text == nullptr || std::string_view(text, source.Size()).find(kMacroName) == std::string_view::npos) {
        return false;
      }

      if (CFG_GetArgOption("/nobonetexture", 0U, nullptr)) {
        return false;
      }

      return gpg::gal::SupportsVertexTextureFormat(gpg::gal::kTextureFormatFloat4);
    }

    /**
     * A lane counts as defined once it has been given a non-empty name.
     *
     * Every lane is constructed up front - Technique's constructor runs an eh
     * vector constructor iterator over 3 x 0x38 (FUN_0042BE40) and each
     * Implementation starts out as an empty SSO string with capacity 15
     * (FUN_0042BB80) - so capacity cannot distinguish a defined lane from an
     * untouched one. Length can, and length is what the binary reads.
     *
     * The word is lane+0x18. mName sits at lane+0x04 and fa::string keeps
     * its allocator cookie at +0x00, so the layout is bx at lane+0x08,
     * mySize at lane+0x18, myRes at lane+0x1C - which is exactly what the
     * Implementation constructor stores (`mov [esi+1Ch], 0Fh` for the
     * capacity, `mov [esi+18h], ebx` for the length, `mov [esi+8], bl` for
     * the first buffer byte).
     *
     * Three independent sites agree on lane+0x18:
     *   - FUN_0042BF40 tests this+0x38 / +0x70 / +0xA8 against lanes based at
     *     this+0x20 / +0x58 / +0x90,
     *   - FUN_0042C650 tests `v50[17 + 14k]` against lanes at `v50 + 11 + 14k`
     *     (v50 is the TechniqueNode, whose mTechnique starts at +0x0C),
     *   - FUN_0042D290 tests `v3[14 * fidelity + 17]` and then reads
     *     `v3[14 * fidelity + 18] < 0x10` to pick between the SSO buffer and
     *     the heap pointer. That capacity-versus-16 test one word higher is
     *     what pins lane+0x1C as myRes and therefore lane+0x18 as mySize.
     */
    [[nodiscard]] bool HasConstructedLaneName(const Implementation& lane) noexcept
    {
      return lane.mName.mySize != 0U;
    }



    /**
     * Address family:
     * - 0x004345A0 (FUN_004345A0)
     * - 0x00434CA0 (FUN_00434CA0)
     *
     * What it does:
     * Performs one left rotation around the provided tree node.
     */
    /**
     * Address family:
     * - 0x00434550 (FUN_00434550)
     * - 0x00434C50 (FUN_00434C50)
     *
     * What it does:
     * Performs one right rotation around the provided tree node.
     */
    /**
     * Address family:
     * - 0x00432B60 (FUN_00432B60)
     * - 0x00433900 (FUN_00433900)
     *
     * What it does:
     * Restores red-black invariants after linking one freshly allocated node.
     */
    [[nodiscard]] bool IsDiskFileInfoNotOlder(const SDiskFileInfo& lhs, const SDiskFileInfo& rhs) noexcept
    {
      const LONG comparison = ::CompareFileTime(&lhs.mLastWriteTime, &rhs.mLastWriteTime);
      return comparison >= 0;
    }

    [[nodiscard]] std::int32_t ResolveGraphicsFidelityIndex()
    {
      return graphics_Fidelity;
    }

    /**
     * Engine addition (ren_TechniqueMemo): the techniques each effect's `SetTechnique` resolved. A lookup
     * built a whole `Technique` (three lanes, each with a string and two maps) as its search key, then had
     * the gal effect search its techniques by name and allocate a new technique object, for every batch of
     * every pass. An effect's entry holds its gal effect and the fidelity it was resolved at, and is dropped
     * when either changes, when the effect loads a file and when it is destroyed - before its gal effect is
     * released, so no technique outlives the effect it came from. Only successful resolutions are kept, so
     * an invalid fidelity definition still logs at each call.
     */
    bool ren_TechniqueMemo = true;
    TConVar<bool> gTConVar_ren_TechniqueMemo(
      "ren_TechniqueMemo",
      "An effect finds a technique it selected before in a small table (1, the default), or looks it up by name each "
      "time (0). Read at each selection.",
      &ren_TechniqueMemo
    );

    struct EffectTechniqueMemo
    {
      static constexpr std::size_t kTechniques = 24U;
      const gpg::gal::Effect* galEffect = nullptr;
      std::int32_t fidelity = 0;
      std::vector<std::pair<std::string, boost::shared_ptr<gpg::gal::EffectTechnique>>> techniques;
    };

    struct TechniqueMemoTable
    {
      std::mutex mutex;
      std::unordered_map<const CD3DEffect*, EffectTechniqueMemo> effects;
    };

    [[nodiscard]] TechniqueMemoTable& GetTechniqueMemoTable()
    {
      // Never destroyed: an effect still alive at exit would otherwise have its techniques released after
      // the device is gone.
      static TechniqueMemoTable* const table = new TechniqueMemoTable();
      return *table;
    }

    void ForgetEffectTechniques(const CD3DEffect* const effect)
    {
      TechniqueMemoTable& table = GetTechniqueMemoTable();
      EffectTechniqueMemo dropped;
      {
        const std::lock_guard<std::mutex> lock(table.mutex);
        const auto found = table.effects.find(effect);
        if (found == table.effects.end()) {
          return;
        }
        dropped = std::move(found->second);
        table.effects.erase(found);
      }
    }
  } // namespace

  /**
   * Address: 0x0042BB80 (FUN_0042BB80)
   * Mangled: ??0Implementation@Technique@CD3DEffect@Moho@@QAE@@Z
   *
   * What it does:
   * Initializes one technique implementation lane with empty annotation trees.
   */
  CD3DEffect::Technique::Implementation::Implementation() = default;

  /**
   * Address: 0x0042BC10 (FUN_0042BC10)
   * Mangled: ??0Implementation@Technique@CD3DEffect@Moho@@QAE@@Z_0
   *
   * What it does:
   * Initializes one implementation lane and copies one lane-name string.
   */
  CD3DEffect::Technique::Implementation::Implementation(const fa::string& implementationName)
  {
    mName.assign(implementationName, 0U, fa::string::npos);
  }

  /**
   * Address: 0x0042BCB0 (FUN_0042BCB0)
   * Mangled: ??1Implementation@Technique@CD3DEffect@Moho@@QAE@@Z
   *
   * What it does:
   * Destroys both annotation trees and releases the implementation name.
   */
  CD3DEffect::Technique::Implementation::~Implementation()
  {
    mName.tidy(true, 0U);
  }

  /**
   * Address: 0x0042C1D0 (FUN_0042C1D0)
   *
   * Implementation const &
   *
   * What it does:
   * Copies the lane name and both annotation trees from the source lane.
   */
  CD3DEffect::Technique::Implementation& CD3DEffect::Technique::Implementation::operator=(
    const Implementation& other
  )
  {
    mName.assign(other.mName, 0U, fa::string::npos);
    mIntegerAnnotations = other.mIntegerAnnotations;
    mStringAnnotations = other.mStringAnnotations;
    return *this;
  }

  /**
   * Address: 0x0042BDC0 (FUN_0042BDC0)
   *
   * What it does:
   * Looks up one integer annotation by key and writes the found value.
   */
  bool CD3DEffect::Technique::Implementation::TryGetIntegerAnnotation(
    const fa::string& annotationName,
    std::int32_t* const outValue
  ) const
  {
    const auto node = mIntegerAnnotations.find(annotationName);
    if (node == mIntegerAnnotations.end()) {
      return false;
    }

    *outValue = node->second;
    return true;
  }

  /**
   * Address: 0x0042BE00 (FUN_0042BE00)
   *
   * What it does:
   * Looks up one string annotation by key and copies the stored value.
   */
  bool CD3DEffect::Technique::Implementation::TryGetStringAnnotation(
    const fa::string& annotationName,
    fa::string* const outValue
  ) const
  {
    const auto node = mStringAnnotations.find(annotationName);
    if (node == mStringAnnotations.end()) {
      return false;
    }

    outValue->assign(node->second, 0U, fa::string::npos);
    return true;
  }

  void CD3DEffect::Technique::Implementation::UnknownVirtualSlot()
  {
  }

  /**
   * Address: 0x0042BE40 (FUN_0042BE40)
   * Mangled: ??0Technique@CD3DEffect@Moho@@QAE@@Z
   *
   * What it does:
   * Initializes one technique with name text and three implementation lanes.
   */
  CD3DEffect::Technique::Technique(const fa::string& techniqueName)
  {
    mName.assign(techniqueName, 0U, fa::string::npos);

    Implementation* const lanes = GetImplementationLanes();
    std::uint32_t constructedCount = 0;
    try {
      for (; constructedCount < 3U; ++constructedCount) {
        ::new (static_cast<void*>(lanes + constructedCount)) Implementation();
      }
    } catch (...) {
      while (constructedCount > 0U) {
        --constructedCount;
        lanes[constructedCount].Implementation::~Implementation();
      }
      throw;
    }
  }

  /**
   * Address: 0x0042BEC0 (FUN_0042BEC0)
   * Mangled: ??1Technique@CD3DEffect@Moho@@UAE@XZ
   *
   * What it does:
   * Destroys all implementation lanes and releases the technique name.
   */
  CD3DEffect::Technique::~Technique()
  {
    Implementation* const lanes = GetImplementationLanes();
    for (std::int32_t index = 2; index >= 0; --index) {
      lanes[index].Implementation::~Implementation();
    }

    mName.tidy(true, 0U);
  }

  /**
   * Address: 0x0042BF40 (FUN_0042BF40)
   *
   * What it does:
   * Fills missing fidelity lanes by cloning the first available implementation.
   */
  void CD3DEffect::Technique::FinalizeMissingImplementations()
  {
    Implementation* const lanes = GetImplementationLanes();
    if (HasConstructedLaneName(lanes[0]) && HasConstructedLaneName(lanes[1]) && HasConstructedLaneName(lanes[2])) {
      return;
    }

    std::optional<Implementation> sharedFallback{};
    auto resolveSourceLane = [&](const std::uint32_t primary, const std::uint32_t secondary, const std::uint32_t tertiary) -> const Implementation* {
      if (HasConstructedLaneName(lanes[primary])) {
        return &lanes[primary];
      }
      if (HasConstructedLaneName(lanes[secondary])) {
        return &lanes[secondary];
      }
      if (HasConstructedLaneName(lanes[tertiary])) {
        return &lanes[tertiary];
      }

      if (!sharedFallback.has_value()) {
        sharedFallback.emplace(mName);
      }
      return &sharedFallback.value();
    };

    const Implementation* const lane0Source = resolveSourceLane(0U, 1U, 2U);
    lanes[0] = *lane0Source;

    const Implementation* const lane1Source = resolveSourceLane(1U, 0U, 2U);
    lanes[1] = *lane1Source;

    const Implementation* const lane2Source = resolveSourceLane(2U, 1U, 0U);
    lanes[2] = *lane2Source;
  }

  CD3DEffect::Technique::Implementation* CD3DEffect::Technique::GetImplementationLanes() noexcept
  {
    return reinterpret_cast<Implementation*>(mImplementationStorage);
  }

  const CD3DEffect::Technique::Implementation* CD3DEffect::Technique::GetImplementationLanes() const noexcept
  {
    return reinterpret_cast<const Implementation*>(mImplementationStorage);
  }

  /**
   * Address: 0x0042C430 (FUN_0042C430)
   * Mangled: ??0CD3DEffect@Moho@@QAE@@Z
   *
   * What it does:
   * Initializes one effect object with empty technique tree and cleared shared handles.
   */
  CD3DEffect::CD3DEffect()
    : mAttachedLinks(nullptr)
    , mTechniques{}
    , mName{}
    , mFile{}
    , mEffect{}
    , mCurrentTechnique{}
  {

  }

  /**
   * Address: 0x0042C520 (FUN_0042C520)
   * Address: 0x00440BA0 (FUN_00440BA0, deleting thunk)
   * Mangled: ??1CD3DEffect@Moho@@QAE@XZ
   *
   * What it does:
   * Releases effect/technique shared handles, clears metadata strings, destroys
   * technique tree storage, and unlinks attached callback links.
   */
  CD3DEffect::~CD3DEffect()
  {
    // The binary releases these first, then the strings, the technique set
    // and finally the attached links -- plain member destruction with the
    // link walk last, which says the owner-link head is a base or first
    // member with a destructor of its own (`WeakObject`). Until that head is
    // modelled, the walk stays in this body and the handles are dropped here
    // to keep them ahead of it.
    ForgetEffectTechniques(this); // engine addition (ren_TechniqueMemo): before the gal effect goes
    mCurrentTechnique.reset();
    mEffect.reset();

    mFile.tidy(true, 0U);
    mName.tidy(true, 0U);



    while (mAttachedLinks != nullptr) {
      AttachedLink* const detached = mAttachedLinks;
      mAttachedLinks = detached->mNext;
      detached->mLinkLane = nullptr;
      detached->mNext = nullptr;
    }
  }

  /**
   * Address: 0x0042C3D0 (FUN_0042C3D0, Moho::CON_d3d_AntiAliasingSamples)
   *
   * What it does:
   * Parses one sample-count argument and forwards it to the active D3D device.
   */
  void CD3DEffect::CON_d3d_AntiAliasingSamples(const fa::vector<fa::string>& args)
  {
    if (args.size() != 2U) {
      return;
    }

    const fa::string* const sampleCountText = ConCommandArg(args, 1U);
    if (sampleCountText == nullptr) {
      return;
    }

    CD3DDevice* const device = D3D_GetDevice();
    if (device == nullptr) {
      return;
    }

    device->SetAntiAliasingSamples(std::atoi(sampleCountText->c_str()));
  }

  /**
   * Address: 0x0042C650 (FUN_0042C650)
   * Mangled: ?InitEffectFromFile@CD3DEffect@Moho@@QAE_NPBD@Z
   *
   * What it does:
   * Loads one effect source file, merges compatibility preamble state,
   * creates one gal effect object, and rebuilds fidelity definitions.
   */
  bool CD3DEffect::InitEffectFromFile(const char* const effectFilePath)
  {
    const fa::string engineVersion = GetEngineVersion();
    ForgetEffectTechniques(this); // engine addition (ren_TechniqueMemo): the techniques belong to the old effect
    mEffect.reset();

    try {
      gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
      const gpg::gal::DeviceContext* const deviceContext = (device != nullptr) ? device->GetDeviceContext() : nullptr;
      const char* const compatResourcePath =
        (deviceContext != nullptr && gpg::gal::UsesD3D10EffectDialect(deviceContext->mDeviceType))
          ? "/effects/d3d10states.compat"
          : "/effects/d3d9states.compat";

      FILE_EnsureWaitHandleSet();
      FWaitHandleSet* const waitHandleSet = FILE_GetWaitHandleSet();
      if (waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr) {
        return false;
      }

      fa::string compatPath{};
      (void)waitHandleSet->mHandle->FindFile(&compatPath, compatResourcePath, nullptr);
      const gpg::MemBuffer<const char> compatStateBuffer = DISK_MemoryMapFile(compatPath.c_str());
      const fa::string cacheDirectory = USER_GetAppCacheDir();
      const fa::string effectBaseName = FILE_Base(effectFilePath, true);

      mName.assign(effectBaseName, 0U, fa::string::npos);
      mFile.assign(effectFilePath, std::char_traits<char>::length(effectFilePath));

      SDiskFileInfo sourceInfo{};
      (void)waitHandleSet->GetFileInfo(mFile.c_str(), &sourceInfo, false);

      const gpg::MemBuffer<const char> effectSourceBuffer = DISK_MemoryMapFile(mFile.c_str());
      const std::size_t compatByteCount = compatStateBuffer.Size();
      const std::size_t effectByteCount = effectSourceBuffer.Size();
      gpg::MemBuffer<char> mergedBuffer = gpg::AllocMemBuffer(compatByteCount + effectByteCount);
      if (compatByteCount > 0U) {
        // Raw effect-code blob copy into the merged buffer.
        std::copy_n(compatStateBuffer.GetPtr(0U, 0U), compatByteCount, mergedBuffer.GetPtr(0U, 0U));
      }
      if (effectByteCount > 0U) {
        // Raw effect-code blob copy into the merged buffer.
        std::copy_n(effectSourceBuffer.GetPtr(0U, 0U), effectByteCount, mergedBuffer.GetPtr(compatByteCount, 0U));
      }

      // Builds the effect, from its compiled copy in the cache when that is at
      // least as new as the source. FAF: `boneTexture` compiles the variant
      // with FAF_BONE_TEXTURE defined (see WantsBoneTextureVariant); it turns
      // into different shaders, so it is cached under a name of its own. So
      // does `msdfText`, the source with the MSDF technique appended, and
      // `terrainTess`, terrain.fx with the tessellated techniques appended.
      gpg::MemBuffer<const char> terrainTess{};
      const auto createEffect = [&](const bool boneTexture, const bool msdfText = false, const bool withTerrainTess = false) {
        const char* const variant = boneTexture ? ".bonetex." : (msdfText ? ".msdf." : (withTerrainTess ? ".tess." : "."));
        const fa::string cachePath = cacheDirectory + "/" + mName + variant + engineVersion;
        SDiskFileInfo cacheInfo{};
        bool useCachePayload = false;
        if (waitHandleSet->GetFileInfo(cachePath.c_str(), &cacheInfo, false)) {
          useCachePayload = IsDiskFileInfoNotOlder(cacheInfo, sourceInfo);
        }

        fa::vector<gpg::gal::EffectMacro> effectMacros{};
        if (boneTexture) {
          effectMacros.push_back(gpg::gal::EffectMacro("FAF_BONE_TEXTURE", "1"));
        }
        const gpg::gal::EffectContext context(
          useCachePayload, mFile.c_str(), cachePath.c_str(),
          msdfText          ? AppendSource(mergedBuffer, kMsdfTechniqueSource, sizeof(kMsdfTechniqueSource) - 1u)
            : withTerrainTess ? AppendSource(mergedBuffer, terrainTess.GetPtr(0U, 0U), terrainTess.Size())
                              : mergedBuffer,
          effectMacros
        );
        mEffect = gpg::gal::Effect::Create(context);
      };

      // A bone texture variant that fails to build falls back to the plain
      // effect, which keeps the skinning palette in shader constants.
      if (WantsBoneTextureVariant(deviceContext, effectSourceBuffer)) {
        try {
          createEffect(true);
        } catch (const std::exception& exception) {
          gpg::Warnf("%s: %s; building it without FAF_BONE_TEXTURE", effectFilePath, exception.what());
          mEffect.reset();
        }
      }
      // The MSDF technique goes on the end of primbatcher.fx, which is FAF's
      // game data and which every renderer compiles from this same buffer. If
      // it doesn't compile against that file, text stays on the old path.
      if (!mEffect && std::strcmp(mName.c_str(), "primbatcher") == 0) {
        try {
          createEffect(false, true);
        } catch (const std::exception& exception) {
          gpg::Warnf("%s: %s; building it without MSDF text", effectFilePath, exception.what());
          mEffect.reset();
        }
      }
      // Engine addition (ren_TerrainTessellation): terrain.fx with terrain_tess.fx on its end, on
      // Direct3D 12 and Vulkan, when the switch is on as the effect loads and the device draws hull
      // and domain shaders. Otherwise the terrain effect is the original one: the appended source
      // shares one HLSL file with every terrain shader, and checking it costs a moment of loading.
      // If it doesn't compile, the terrain is drawn as before.
      gpg::gal::Device* const galDevice = gpg::gal::Device::GetInstance();
      const bool tessellationDrawn =
        galDevice != nullptr && (galDevice->GetGpuDrivenFeatures() & gpg::gal::kGpuFeatureTessellation) != 0U;
      if (!mEffect && ren_TerrainTessellation && tessellationDrawn && std::strcmp(mName.c_str(), "terrain") == 0) {
        terrainTess = TerrainTessellationSource(deviceContext, waitHandleSet);
        if (terrainTess.Size() > 0U) {
          try {
            createEffect(false, false, true);
            // Shaders compile on first use, and all of the effect's come from one source: a
            // mistake in terrain_tess.fx would take the whole terrain with it. Every technique
            // SetTechnique can redirect to compiles here, once (the shader cache keeps them): a
            // twin that failed later would draw nothing in place of its pass.
            auto* const program = dynamic_cast<gpg::gal::ProgramEffect*>(mEffect.get());
            for (const char* const name :
                 {"TTerrainTess", "TTerrainXPTess", "TTerrainGlowTess", "TTerrainNormalsTess", "TTerrainNormalsXPTess",
                  "TTerrainBasisTess", "TTerrainBasisBiCubicTess"}) {
              if (program == nullptr || !program->TechniqueCompiles(name)) {
                throw std::runtime_error(std::string("technique ") + name + " of terrain_tess.fx did not compile (see the shader messages above)");
              }
            }
            gpg::Logf("terrain: tessellated techniques loaded (ren_TerrainTessellation %d)", ren_TerrainTessellation ? 1 : 0);
          } catch (const std::exception& exception) {
            gpg::Warnf("%s: %s; building it without terrain tessellation", effectFilePath, exception.what());
            mEffect.reset();
          }
        }
      }
      if (!mEffect) {
        createEffect(false);
      }

      mTechniques.clear();

      fa::vector<fa::string> techniqueImplementationNames{};
      EnumerateValidTechniques(techniqueImplementationNames);
      for (const fa::string& implementationName : techniqueImplementationNames) {
        fa::string abstractTechniqueName{};
        const fa::string abstractTechniqueToken("abstractTechnique", 17U);
        if (!GetImplAnnotation(&abstractTechniqueName, implementationName, abstractTechniqueToken)) {
          abstractTechniqueName.assign(implementationName, 0U, fa::string::npos);
        }

        const TechniqueSet::iterator definition = mTechniques.emplace(abstractTechniqueName).first;
        Technique::Implementation* const lanes = MutableTechnique(definition).GetImplementationLanes();
        if (HasConstructedLaneName(lanes[0]) && HasConstructedLaneName(lanes[1]) && HasConstructedLaneName(lanes[2])) {
          gpg::Warnf(
            "technique %s in effect %s has been finalized (attempt to define a redundant fidelity)",
            abstractTechniqueName.c_str(),
            mName.c_str()
          );
          continue;
        }

        if (abstractTechniqueName == implementationName) {
          Technique::Implementation implementation(abstractTechniqueName);
          lanes[0] = implementation;
          lanes[1] = implementation;
          lanes[2] = implementation;
          continue;
        }

        std::int32_t fidelityIndex = -1;
        const fa::string fidelityToken("fidelity", 8U);
        (void)GetImplAnnotation(&fidelityIndex, implementationName, fidelityToken);
        if (fidelityIndex < 0 || fidelityIndex > 2) {
          gpg::Warnf(
            "technique %s in effect %s has incomplete definition",
            abstractTechniqueName.c_str(),
            mName.c_str()
          );
          continue;
        }

        if (HasConstructedLaneName(lanes[fidelityIndex])) {
          gpg::Warnf(
            "redundant implementation for technique %s in effect %s",
            abstractTechniqueName.c_str(),
            mName.c_str()
          );
          continue;
        }

        Technique::Implementation implementation(implementationName);
        lanes[fidelityIndex] = implementation;
      }

      for (TechniqueSet::iterator it = mTechniques.begin(); it != mTechniques.end(); ++it) {
        MutableTechnique(it).FinalizeMissingImplementations();
      }
      return true;
    } catch (const std::exception& exception) {
      gpg::Warnf("%s: %s", effectFilePath, exception.what());
      return false;
    }
  }

  /**
   * Address: 0x00431C60 (FUN_00431C60)
   *
   * Technique const &
   *
   * What it does:
   * Resolves one exact fidelity-definition node for the supplied technique.
   */
  CD3DEffect::TechniqueSet::iterator CD3DEffect::GetFidelityDefinitions(const Technique& technique)
  {
    return mTechniques.find(technique);
  }

  /**
   * Address: 0x0042DB30 (FUN_0042DB30)
   *
   * What it does:
   * Queries the current effect for valid techniques and appends their names.
   */
  void CD3DEffect::EnumerateValidTechniques(fa::vector<fa::string>& outTechniqueNames)
  {
    fa::vector<boost::shared_ptr<gpg::gal::EffectTechnique>> techniques{};
    mEffect->GetTechniques(techniques);

    for (const boost::shared_ptr<gpg::gal::EffectTechnique>& technique : techniques) {
      outTechniqueNames.push_back(*technique->GetName());
    }
  }

  /**
   * Address: 0x0042D290 (FUN_0042D290, ?SetTechnique@CD3DEffect@Moho@@QAEXPBD@Z)
   *
   * What it does:
   * Selects one technique on the backing gal effect, preferring the current
   * fidelity implementation lane when present.
   */
  void CD3DEffect::SetTechnique(const char* techniqueName)
  {
    // Engine addition (ren_TerrainTessellation): a terrain technique with a tessellated twin
    // "<name>Tess" (terrain_tess.fx, Direct3D 12 and Vulkan) draws through the twin.
    fa::string tessellatedName{};
    if (ren_TerrainTessellation && std::strcmp(mName.c_str(), "terrain") == 0) {
      tessellatedName.assign(techniqueName, std::char_traits<char>::length(techniqueName));
      tessellatedName.append("Tess", 4U);
      if (GetFidelityDefinitions(Technique(tessellatedName)) != mTechniques.end()) {
        techniqueName = tessellatedName.c_str();
      }
    }

    // Engine change (ren_TechniqueMemo): a technique this effect selected before is found without building the
    // search key or a new gal technique.
    const std::int32_t memoFidelity = ResolveGraphicsFidelityIndex();
    if (ren_TechniqueMemo && mEffect != nullptr) {
      TechniqueMemoTable& table = GetTechniqueMemoTable();
      const std::lock_guard<std::mutex> lock(table.mutex);
      const auto found = table.effects.find(this);
      if (found != table.effects.end() && found->second.galEffect == mEffect.get() && found->second.fidelity == memoFidelity) {
        for (const auto& [name, technique] : found->second.techniques) {
          if (name == techniqueName) {
            mCurrentTechnique = technique;
            return;
          }
        }
      }
    }

    const fa::string lookupName(techniqueName, std::char_traits<char>::length(techniqueName));
    const Technique lookupTechnique(lookupName);
    const TechniqueSet::iterator definition = GetFidelityDefinitions(lookupTechnique);

    auto selectAndWarnInvalid = [&]() {
      mCurrentTechnique = mEffect->GetTechnique(techniqueName);
      gpg::Debugf(
        "technique %s in effect %s has an invalid fidelity definition",
        techniqueName,
        mName.c_str()
      );
    };

    if (definition == mTechniques.end()) {
      selectAndWarnInvalid();
      return;
    }

    const std::int32_t fidelityIndex = ResolveGraphicsFidelityIndex();
    Technique::Implementation* const lanes = MutableTechnique(definition).GetImplementationLanes();
    Technique::Implementation& selectedLane = lanes[fidelityIndex];
    if (!HasConstructedLaneName(selectedLane)) {
      selectAndWarnInvalid();
      return;
    }

    mCurrentTechnique = mEffect->GetTechnique(selectedLane.mName.c_str());

    if (ren_TechniqueMemo && mEffect != nullptr && mCurrentTechnique != nullptr) {
      TechniqueMemoTable& table = GetTechniqueMemoTable();
      EffectTechniqueMemo stale;
      const std::lock_guard<std::mutex> lock(table.mutex);
      EffectTechniqueMemo& memo = table.effects[this];
      if (memo.galEffect != mEffect.get() || memo.fidelity != memoFidelity) {
        stale = std::move(memo);
        memo = EffectTechniqueMemo{};
        memo.galEffect = mEffect.get();
        memo.fidelity = memoFidelity;
      }
      if (memo.techniques.size() < EffectTechniqueMemo::kTechniques) {
        memo.techniques.emplace_back(techniqueName, mCurrentTechnique);
      }
    }
  }

  /**
   * Address: 0x0042D580 (FUN_0042D580)
   * Mangled: ?GetImplAnnotation@CD3DEffect@Moho@@AAE_NAAHABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@1@Z
   *
   * What it does:
   * Reads one integer annotation from one implementation technique lane.
   */
  bool CD3DEffect::GetImplAnnotation(
    std::int32_t* const outValue,
    const fa::string& implementationName,
    const fa::string& annotationName
  )
  {
    const boost::shared_ptr<gpg::gal::EffectTechnique> technique = mEffect->GetTechnique(implementationName.c_str());
    if (!technique) {
      return false;
    }
    return technique->GetAnnotationInt(outValue, annotationName);
  }

  /**
   * Address: 0x0042D640 (FUN_0042D640)
   * Mangled: ?GetIntegerAnnotation@CD3DEffect@Moho@@QAEHABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@0H@Z
   *
   * What it does:
   * Returns one integer annotation for the selected technique/fidelity lane,
   * resolving from implementation annotation when cache is missing.
   */
  std::int32_t CD3DEffect::GetIntegerAnnotation(
    const fa::string& techniqueName,
    const fa::string& annotationName,
    const std::int32_t defaultValue
  )
  {
    (void)defaultValue;
    std::int32_t resolvedValue = 0;

    if (!mEffect) {
      gpg::Warnf("attempt to retrieve annotation from invalid effect");
      return resolvedValue;
    }

    const Technique lookupTechnique(techniqueName);
    const TechniqueSet::iterator definition = GetFidelityDefinitions(lookupTechnique);
    if (definition == mTechniques.end()) {
      gpg::Warnf("attempt to retrieve annotation from unknown technique %s", techniqueName.c_str());
      return resolvedValue;
    }

    const std::int32_t fidelityIndex = ResolveGraphicsFidelityIndex();
    Technique::Implementation& lane = MutableTechnique(definition).GetImplementationLanes()[fidelityIndex];
    if (!lane.TryGetIntegerAnnotation(annotationName, &resolvedValue)) {
      (void)GetImplAnnotation(&resolvedValue, lane.mName, annotationName);
      lane.mIntegerAnnotations[annotationName] = resolvedValue;
    }

    return resolvedValue;
  }

  /**
   * Address: 0x0042D780 (FUN_0042D780)
   * Mangled: ?GetImplAnnotation@CD3DEffect@Moho@@AAE_NAAV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABV34@1@Z
   *
   * What it does:
   * Reads one string annotation from one implementation technique lane.
   */
  bool CD3DEffect::GetImplAnnotation(
    fa::string* const outValue,
    const fa::string& implementationName,
    const fa::string& annotationName
  )
  {
    const boost::shared_ptr<gpg::gal::EffectTechnique> technique = mEffect->GetTechnique(implementationName.c_str());
    if (!technique) {
      return false;
    }
    return technique->GetAnnotationString(outValue, annotationName);
  }

  /**
   * Address: 0x0042D840 (FUN_0042D840)
   * Mangled: ?GetStringAnnotation@CD3DEffect@Moho@@QAE?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABV34@00@Z
   *
   * What it does:
   * Returns one string annotation for the selected technique/fidelity lane,
   * resolving from implementation annotation when cache is missing.
   */
  fa::string CD3DEffect::GetStringAnnotation(
    const fa::string& techniqueName,
    const fa::string& annotationName,
    const fa::string& defaultValue
  )
  {
    fa::string resolvedValue{};
    resolvedValue.assign(defaultValue, 0U, fa::string::npos);

    if (!mEffect) {
      gpg::Warnf("attempt to retrieve annotation from invalid effect");
      return resolvedValue;
    }

    const Technique lookupTechnique(techniqueName);
    const TechniqueSet::iterator definition = GetFidelityDefinitions(lookupTechnique);
    if (definition == mTechniques.end()) {
      gpg::Warnf("attempt to retrieve annotation from unknown technique %s", techniqueName.c_str());
      return resolvedValue;
    }

    const std::int32_t fidelityIndex = ResolveGraphicsFidelityIndex();
    Technique::Implementation& lane = MutableTechnique(definition).GetImplementationLanes()[fidelityIndex];
    if (!lane.TryGetStringAnnotation(annotationName, &resolvedValue)) {
      (void)GetImplAnnotation(&resolvedValue, lane.mName, annotationName);
      lane.mStringAnnotations[annotationName] = resolvedValue;
    }

    return resolvedValue;
  }

  /**
   * Address: 0x00437E90 (FUN_00437E90, ?GetBaseEffect@CD3DEffect@Moho@@QAE?AV?$shared_ptr@VEffect@gal@gpg@@@boost@@XZ)
   *
   * What it does:
   * Returns a new reference to the gal effect.
   */
  boost::shared_ptr<gpg::gal::Effect> CD3DEffect::GetBaseEffect()
  {
    return mEffect;
  }

  /**
   * Address: 0x0042DA30 (FUN_0042DA30, ?SetTexture@CD3DEffect@Moho@@QAEXPBDV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@@Z)
   *
   * What it does:
   * Resolves one effect variable by name and binds one texture handle (or
   * clears the slot when texture is null).
   */
  void CD3DEffect::SetTexture(const char* const variableName, boost::shared_ptr<ID3DTextureSheet> texture)
  {
    const boost::shared_ptr<gpg::gal::EffectVariable> variable = mEffect->GetVariable(variableName);

    if (texture) {
      ID3DTextureSheet::TextureHandle textureHandle{};
      texture->GetTexture(textureHandle);
      variable->SetTexture(textureHandle);
      return;
    }

    variable->SetTexture(ID3DTextureSheet::TextureHandle{});
  }
} // namespace moho
