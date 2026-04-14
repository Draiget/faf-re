#include "RMeshBlueprint.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <limits>
#include <new>
#include <string>
#include <string_view>
#include <system_error>
#include <typeinfo>

#include "moho/resource/RResId.h"

namespace moho
{
  namespace
  {
    [[nodiscard]] std::string ExtractMeshFamilyPrefix(const std::string_view sourcePath)
    {
      const std::size_t markerPos = sourcePath.rfind('_');
      if (markerPos == std::string_view::npos) {
        return std::string{sourcePath};
      }
      return std::string{sourcePath.substr(0, markerPos)};
    }

    [[nodiscard]] bool ResourceFileExists(const std::string_view resourceName)
    {
      if (resourceName.empty()) {
        return false;
      }

      std::error_code ec;
      return std::filesystem::exists(std::filesystem::path{resourceName}, ec) && !ec;
    }

    void ResolveExplicitOrFallbackPath(
      msvc8::string& destination, const std::string_view sourcePath, const std::string_view fallbackName
    )
    {
      if (!destination.empty()) {
        msvc8::string sourcePathText;
        sourcePathText.assign_owned(sourcePath);
        const msvc8::string completedPath = RES_CompletePath(destination.c_str(), sourcePathText.c_str());
        destination.assign_owned(completedPath.view());
        return;
      }

      if (ResourceFileExists(fallbackName)) {
        destination.assign_owned(fallbackName);
      }
    }

    /**
     * Address: 0x0051A3D0 (FUN_0051A3D0)
     *
     * What it does:
     * Builds one `gpg::RRef` lane for an `RMeshBlueprint*` and writes it into
     * caller-provided storage.
     */
    [[nodiscard]] gpg::RRef* BuildMeshBlueprintRef(gpg::RRef* const out, RMeshBlueprint* const object)
    {
      GPG_ASSERT(out != nullptr);
      if (!out) {
        return nullptr;
      }

      gpg::RRef temp{};
      (void)gpg::RRef_RMeshBlueprint(&temp, object);
      out->mObj = temp.mObj;
      out->mType = temp.mType;
      return out;
    }
  } // namespace

  gpg::RType* RMeshBlueprint::sType = nullptr;

  /**
   * Address: 0x005183D0 (FUN_005183D0)
   * Mangled: ??0RMeshBlueprintLOD@Moho@@QAE@XZ
   *
   * What it does:
   * Default-initializes one mesh LOD descriptor with empty string lanes,
   * default cutoff, and disabled bool flags.
   */
  RMeshBlueprintLOD::RMeshBlueprintLOD()
    : mMeshName()
    , mAlbedoName()
    , mNormalsName()
    , mSpecularName()
    , mLookupName()
    , mSecondaryName()
    , mShaderName()
    , mLodCutoff(1000.0f)
    , mScrolling(0)
    , mOcclude(0)
    , mSilhouette(0)
    , mPadCB(0)
  {
  }

  /**
   * Address: 0x0051A0F0 (FUN_0051A0F0, Moho::RMeshBlueprintLOD::RMeshBlueprintLOD)
   * Mangled: ??0RMeshBlueprintLOD@Moho@@QAE@ABV01@@Z
   *
   * What it does:
   * Copy-constructs one mesh LOD descriptor including all path string lanes
   * and scalar flags.
   */
  RMeshBlueprintLOD::RMeshBlueprintLOD(const RMeshBlueprintLOD& other)
    : mMeshName(other.mMeshName)
    , mAlbedoName(other.mAlbedoName)
    , mNormalsName(other.mNormalsName)
    , mSpecularName(other.mSpecularName)
    , mLookupName(other.mLookupName)
    , mSecondaryName(other.mSecondaryName)
    , mShaderName(other.mShaderName)
    , mLodCutoff(other.mLodCutoff)
    , mScrolling(other.mScrolling)
    , mOcclude(other.mOcclude)
    , mSilhouette(other.mSilhouette)
    , mPadCB(other.mPadCB)
  {
  }

  /**
   * Address: 0x00518870 (FUN_00518870)
   * Mangled: ?Init@RMeshBlueprintLOD@Moho@@QAEXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@I@Z
   *
   * What it does:
   * Resolves mesh/material texture names for this LOD from source path and
   * fallback naming rules (`_lod%d.scm`, `_albedo.dds`, `_normalsTS.dds`,
   * `_SpecTeam.dds`, `_lookup.dds`).
   */
  void RMeshBlueprintLOD::Init(const msvc8::string& sourcePath, const std::uint32_t lodIndex)
  {
    const std::string sourcePrefix = ExtractMeshFamilyPrefix(sourcePath.view());

    if (!mMeshName.empty()) {
      const msvc8::string completedPath = RES_CompletePath(mMeshName.c_str(), sourcePath.c_str());
      mMeshName.assign_owned(completedPath.view());
    } else {
      const std::string lodMeshName = sourcePrefix + "_lod" + std::to_string(lodIndex) + ".scm";
      if (ResourceFileExists(lodMeshName)) {
        mMeshName.assign_owned(lodMeshName);
      }
    }

    ResolveExplicitOrFallbackPath(mAlbedoName, sourcePath.view(), sourcePrefix + "_albedo.dds");

    ResolveExplicitOrFallbackPath(mNormalsName, sourcePath.view(), sourcePrefix + "_normalsTS.dds");

    ResolveExplicitOrFallbackPath(mSpecularName, sourcePath.view(), sourcePrefix + "_SpecTeam.dds");

    ResolveExplicitOrFallbackPath(mLookupName, sourcePath.view(), sourcePrefix + "_lookup.dds");
  }

  /**
   * Address: 0x00528360 (FUN_00528360)
   * Mangled: ?GetClass@RMeshBlueprint@Moho@@UBEPAVRType@gpg@@XZ
   *
   * What it does:
   * Returns cached reflection descriptor for `RMeshBlueprint`.
   */
  gpg::RType* RMeshBlueprint::GetClass() const
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(RMeshBlueprint));
    }
    return sType;
  }

  /**
   * Address: 0x00528380 (FUN_00528380)
   * Mangled: ?GetDerivedObjectRef@RMeshBlueprint@Moho@@UAE?AVRRef@gpg@@XZ
   *
   * What it does:
   * Packs `{this, GetClass()}` as a reflection reference handle.
   */
  gpg::RRef RMeshBlueprint::GetDerivedObjectRef()
  {
    gpg::RRef out{};
    (void)BuildMeshBlueprintRef(&out, this);
    return out;
  }

  /**
   * Address: 0x00518EB0 (FUN_00518EB0)
   * Mangled: ?OnInitBlueprint@RMeshBlueprint@Moho@@MAEXXZ
   *
   * What it does:
   * Initializes each LOD entry using blueprint source-path derived rules.
   */
  void RMeshBlueprint::OnInitBlueprint()
  {
    RMeshBlueprintLOD* const begin = mLods.begin();
    if (!begin) {
      return;
    }

    std::uint32_t lodIndex = 0;
    for (RMeshBlueprintLOD* lod = begin; lod != mLods.end(); ++lod, ++lodIndex) {
      lod->Init(mSource, lodIndex);
    }
  }
} // namespace moho
