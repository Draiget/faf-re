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
  } // namespace

  gpg::RType* RMeshBlueprint::sType = nullptr;

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
    out.mObj = this;
    out.mType = GetClass();
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
