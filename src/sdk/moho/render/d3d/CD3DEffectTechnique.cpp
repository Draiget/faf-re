#include "moho/render/d3d/CD3DEffectTechnique.h"

#include <cstring>
#include <cstdlib>
#include <exception>
#include <new>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <type_traits>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/Effect.hpp"
#include "gpg/gal/EffectContext.hpp"
#include "gpg/gal/EffectMacro.hpp"
#include "gpg/gal/EffectTechnique.hpp"
#include "gpg/gal/EffectVariable.hpp"
#include "gpg/gal/TextureContext.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "moho/console/CConCommand.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/ID3DTextureSheet.h"

namespace moho
{
  msvc8::string GetEngineVersion();

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

      if (deviceContext == nullptr || deviceContext->mDeviceType == gpg::gal::DeviceApi::Direct3D10) {
        return false;
      }

      const char* const text = source.GetPtr(0U, 0U);
      if (text == nullptr || std::string_view(text, source.Size()).find(kMacroName) == std::string_view::npos) {
        return false;
      }

      if (CFG_GetArgOption("/nobonetexture", 0U, nullptr)) {
        return false;
      }

      auto* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
      return device != nullptr && device->SupportsVertexTextureFormat(gpg::gal::kTextureFormatFloat4);
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
     * The word is lane+0x18. mName sits at lane+0x04 and msvc8::string keeps
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
  CD3DEffect::Technique::Implementation::Implementation(const msvc8::string& implementationName)
  {
    mName.assign(implementationName, 0U, msvc8::string::npos);
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
    mName.assign(other.mName, 0U, msvc8::string::npos);
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
    const msvc8::string& annotationName,
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
    const msvc8::string& annotationName,
    msvc8::string* const outValue
  ) const
  {
    const auto node = mStringAnnotations.find(annotationName);
    if (node == mStringAnnotations.end()) {
      return false;
    }

    outValue->assign(node->second, 0U, msvc8::string::npos);
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
  CD3DEffect::Technique::Technique(const msvc8::string& techniqueName)
  {
    mName.assign(techniqueName, 0U, msvc8::string::npos);

    Implementation* const lanes = GetImplementationLanes();
    std::uint32_t constructedCount = 0;
    try {
      for (; constructedCount < 3U; ++constructedCount) {
        ::new (static_cast<void*>(lanes + constructedCount)) Implementation();
      }
    } catch (...) {
      while (constructedCount > 0U) {
        --constructedCount;
        lanes[constructedCount].~Implementation();
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
      lanes[index].~Implementation();
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
  void CD3DEffect::CON_d3d_AntiAliasingSamples(const msvc8::vector<msvc8::string>& args)
  {
    if (args.size() != 2U) {
      return;
    }

    const msvc8::string* const sampleCountText = ConCommandArg(args, 1U);
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
    const msvc8::string engineVersion = GetEngineVersion();
    mEffect.reset();

    try {
      gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
      const gpg::gal::DeviceContext* const deviceContext = (device != nullptr) ? device->GetDeviceContext() : nullptr;
      const char* const compatResourcePath =
        (deviceContext != nullptr && deviceContext->mDeviceType == gpg::gal::DeviceApi::Direct3D10)
          ? "/effects/d3d10states.compat"
          : "/effects/d3d9states.compat";

      FILE_EnsureWaitHandleSet();
      FWaitHandleSet* const waitHandleSet = FILE_GetWaitHandleSet();
      if (waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr) {
        return false;
      }

      msvc8::string compatPath{};
      (void)waitHandleSet->mHandle->FindFile(&compatPath, compatResourcePath, nullptr);
      const gpg::MemBuffer<const char> compatStateBuffer = DISK_MemoryMapFile(compatPath.c_str());
      const msvc8::string cacheDirectory = USER_GetAppCacheDir();
      const msvc8::string effectBaseName = FILE_Base(effectFilePath, true);

      mName.assign(effectBaseName, 0U, msvc8::string::npos);
      mFile.assign(effectFilePath, std::char_traits<char>::length(effectFilePath));

      SDiskFileInfo sourceInfo{};
      (void)waitHandleSet->GetFileInfo(mFile.c_str(), &sourceInfo, false);

      const gpg::MemBuffer<const char> effectSourceBuffer = DISK_MemoryMapFile(mFile.c_str());
      const std::size_t compatByteCount = compatStateBuffer.Size();
      const std::size_t effectByteCount = effectSourceBuffer.Size();
      gpg::MemBuffer<char> mergedBuffer = gpg::AllocMemBuffer(compatByteCount + effectByteCount);
      if (compatByteCount > 0U) {
        std::memcpy(
          mergedBuffer.GetPtr(0U, 0U),
          compatStateBuffer.GetPtr(0U, 0U),
          compatByteCount
        );
      }
      if (effectByteCount > 0U) {
        std::memcpy(
          mergedBuffer.GetPtr(compatByteCount, 0U),
          effectSourceBuffer.GetPtr(0U, 0U),
          effectByteCount
        );
      }

      // Builds the effect, from its compiled copy in the cache when that is at
      // least as new as the source. FAF: `boneTexture` compiles the variant
      // with FAF_BONE_TEXTURE defined (see WantsBoneTextureVariant); it turns
      // into different shaders, so it is cached under a name of its own.
      const auto createEffect = [&](const bool boneTexture) {
        const msvc8::string cachePath =
          cacheDirectory + "/" + mName + (boneTexture ? ".bonetex." : ".") + engineVersion;
        SDiskFileInfo cacheInfo{};
        bool useCachePayload = false;
        if (waitHandleSet->GetFileInfo(cachePath.c_str(), &cacheInfo, false)) {
          useCachePayload = IsDiskFileInfoNotOlder(cacheInfo, sourceInfo);
        }

        msvc8::vector<gpg::gal::EffectMacro> effectMacros{};
        if (boneTexture) {
          effectMacros.push_back(gpg::gal::EffectMacro("FAF_BONE_TEXTURE", "1"));
        }
        const gpg::gal::EffectContext context(
          useCachePayload, mFile.c_str(), cachePath.c_str(), mergedBuffer, effectMacros
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
      if (!mEffect) {
        createEffect(false);
      }

      mTechniques.clear();

      msvc8::vector<msvc8::string> techniqueImplementationNames{};
      EnumerateValidTechniques(techniqueImplementationNames);
      for (const msvc8::string& implementationName : techniqueImplementationNames) {
        msvc8::string abstractTechniqueName{};
        const msvc8::string abstractTechniqueToken("abstractTechnique", 17U);
        if (!GetImplAnnotation(&abstractTechniqueName, implementationName, abstractTechniqueToken)) {
          abstractTechniqueName.assign(implementationName, 0U, msvc8::string::npos);
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
        const msvc8::string fidelityToken("fidelity", 8U);
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
  void CD3DEffect::EnumerateValidTechniques(msvc8::vector<msvc8::string>& outTechniqueNames)
  {
    msvc8::vector<boost::shared_ptr<gpg::gal::EffectTechnique>> techniques{};
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
  void CD3DEffect::SetTechnique(const char* const techniqueName)
  {
    const msvc8::string lookupName(techniqueName, std::char_traits<char>::length(techniqueName));
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
    const msvc8::string& implementationName,
    const msvc8::string& annotationName
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
    const msvc8::string& techniqueName,
    const msvc8::string& annotationName,
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
    msvc8::string* const outValue,
    const msvc8::string& implementationName,
    const msvc8::string& annotationName
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
  msvc8::string CD3DEffect::GetStringAnnotation(
    const msvc8::string& techniqueName,
    const msvc8::string& annotationName,
    const msvc8::string& defaultValue
  )
  {
    msvc8::string resolvedValue{};
    resolvedValue.assign(defaultValue, 0U, msvc8::string::npos);

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
