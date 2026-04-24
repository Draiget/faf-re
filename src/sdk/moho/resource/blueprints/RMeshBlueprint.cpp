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
    /**
     * Address: 0x0051AF70 (FUN_0051AF70, copy_RMeshBlueprintLOD_counted_range_with_rollback)
     *
     * What it does:
     * Copy-constructs `count` contiguous `RMeshBlueprintLOD` elements from
     * `source` into `destination`, then destroys already-built elements before
     * rethrowing if one copy step throws.
     */
    [[maybe_unused]] RMeshBlueprintLOD* CopyRMeshBlueprintLODCountedRangeWithRollback(
      RMeshBlueprintLOD* destination,
      int count,
      const RMeshBlueprintLOD* source
    )
    {
      RMeshBlueprintLOD* destinationCursor = destination;
      try {
        while (count > 0) {
          if (destinationCursor != nullptr) {
            ::new (destinationCursor) RMeshBlueprintLOD(*source);
          }
          --count;
          ++source;
          ++destinationCursor;
        }
        return destinationCursor;
      } catch (...) {
        for (RMeshBlueprintLOD* destroyCursor = destination; destroyCursor != destinationCursor; ++destroyCursor) {
          destroyCursor->~RMeshBlueprintLOD();
        }
        throw;
      }
    }

    /**
     * Address: 0x0051A0A0 (FUN_0051A0A0)
     *
     * What it does:
     * Adapts one register-lane caller shape into the canonical counted
     * `RMeshBlueprintLOD` copy-with-rollback helper.
     */
    [[maybe_unused]] RMeshBlueprintLOD* CopyRMeshBlueprintLODCountedRangeRegisterAdapter(
      RMeshBlueprintLOD* const destination,
      const int count,
      const RMeshBlueprintLOD* const source
    )
    {
      return CopyRMeshBlueprintLODCountedRangeWithRollback(destination, count, source);
    }

    /**
     * Address: 0x0051A640 (FUN_0051A640)
     *
     * What it does:
     * Alternate register-shape adapter lane that forwards one counted
     * `RMeshBlueprintLOD` copy-with-rollback request into the canonical helper.
     */
    [[maybe_unused]] RMeshBlueprintLOD* CopyRMeshBlueprintLODCountedRangeRegisterAdapterAlt(
      RMeshBlueprintLOD* const destination,
      const int count,
      const RMeshBlueprintLOD* const source
    )
    {
      return CopyRMeshBlueprintLODCountedRangeWithRollback(destination, count, source);
    }

    /**
     * Address: 0x0051B330 (FUN_0051B330, copy_RMeshBlueprintLOD_range_with_rollback)
     * Address: 0x0051B4A0 (FUN_0051B4A0, sub_51B4A0)
     *
     * What it does:
     * Copy-constructs one contiguous source range into destination storage and
     * destroys already-built destination elements before rethrowing on failure.
     */
    [[maybe_unused]] RMeshBlueprintLOD* CopyRMeshBlueprintLODRangeWithRollback(
      RMeshBlueprintLOD* destinationBegin,
      RMeshBlueprintLOD* destinationEnd,
      const RMeshBlueprintLOD* sourceBegin
    )
    {
      RMeshBlueprintLOD* destinationCursor = destinationBegin;
      const RMeshBlueprintLOD* sourceCursor = sourceBegin;
      try {
        while (destinationCursor != destinationEnd) {
          if (sourceCursor != nullptr) {
            ::new (destinationCursor) RMeshBlueprintLOD(*sourceCursor);
          }
          ++destinationCursor;
          ++sourceCursor;
        }
        return destinationCursor;
      } catch (...) {
        for (RMeshBlueprintLOD* destroyCursor = destinationBegin; destroyCursor != destinationCursor; ++destroyCursor) {
          destroyCursor->~RMeshBlueprintLOD();
        }
        throw;
      }
    }

    /**
     * Address: 0x0051AE30 (FUN_0051AE30)
     *
     * What it does:
     * Adapter lane that forwards one destination/source range copy request
     * into the canonical mesh-LOD range copy-with-rollback helper.
     */
    [[maybe_unused]] [[nodiscard]] RMeshBlueprintLOD* CopyRMeshBlueprintLODRangeAdapterLaneA(
      RMeshBlueprintLOD* const destinationBegin,
      RMeshBlueprintLOD* const destinationEnd,
      const RMeshBlueprintLOD* const sourceBegin
    )
    {
      return CopyRMeshBlueprintLODRangeWithRollback(destinationBegin, destinationEnd, sourceBegin);
    }

    /**
     * Address: 0x0051B020 (FUN_0051B020)
     *
     * What it does:
     * Adapter lane that forwards one destination/source range copy request
     * into the canonical mesh-LOD range copy-with-rollback helper.
     */
    [[maybe_unused]] [[nodiscard]] RMeshBlueprintLOD* CopyRMeshBlueprintLODRangeAdapterLaneB(
      RMeshBlueprintLOD* const destinationBegin,
      RMeshBlueprintLOD* const destinationEnd,
      const RMeshBlueprintLOD* const sourceBegin
    )
    {
      return CopyRMeshBlueprintLODRangeWithRollback(destinationBegin, destinationEnd, sourceBegin);
    }

    /**
     * Address: 0x0051B190 (FUN_0051B190)
     *
     * What it does:
     * Adapter lane that forwards one destination/source range copy request
     * into the canonical mesh-LOD range copy-with-rollback helper.
     */
    [[maybe_unused]] [[nodiscard]] RMeshBlueprintLOD* CopyRMeshBlueprintLODRangeAdapterLaneC(
      RMeshBlueprintLOD* const destinationBegin,
      RMeshBlueprintLOD* const destinationEnd,
      const RMeshBlueprintLOD* const sourceBegin
    )
    {
      return CopyRMeshBlueprintLODRangeWithRollback(destinationBegin, destinationEnd, sourceBegin);
    }

    /**
     * Address: 0x0051B220 (FUN_0051B220)
     *
     * What it does:
     * Adapter lane that forwards one destination/source range copy request
     * into the canonical mesh-LOD range copy-with-rollback helper.
     */
    [[maybe_unused]] [[nodiscard]] RMeshBlueprintLOD* CopyRMeshBlueprintLODRangeAdapterLaneD(
      RMeshBlueprintLOD* const destinationBegin,
      RMeshBlueprintLOD* const destinationEnd,
      const RMeshBlueprintLOD* const sourceBegin
    )
    {
      return CopyRMeshBlueprintLODRangeWithRollback(destinationBegin, destinationEnd, sourceBegin);
    }

    /**
     * Address: 0x0051B2F0 (FUN_0051B2F0)
     *
     * What it does:
     * Adapter lane that forwards one destination/source range copy request
     * into the canonical mesh-LOD range copy-with-rollback helper.
     */
    [[maybe_unused]] [[nodiscard]] RMeshBlueprintLOD* CopyRMeshBlueprintLODRangeAdapterLaneE(
      RMeshBlueprintLOD* const destinationBegin,
      RMeshBlueprintLOD* const destinationEnd,
      const RMeshBlueprintLOD* const sourceBegin
    )
    {
      return CopyRMeshBlueprintLODRangeWithRollback(destinationBegin, destinationEnd, sourceBegin);
    }

    [[nodiscard]] const RMeshBlueprintLOD* CopyConstructRMeshBlueprintLodIfPresent(
      RMeshBlueprintLOD* const destination,
      const RMeshBlueprintLOD* const source
    )
    {
      if (source == nullptr) {
        return source;
      }

      return ::new (destination) RMeshBlueprintLOD(*source);
    }

    /**
     * Address: 0x0051B130 (FUN_0051B130)
     *
     * What it does:
     * Primary adapter lane that copy-constructs one `RMeshBlueprintLOD` into
     * destination storage only when source is non-null.
     */
    [[maybe_unused]] [[nodiscard]] const RMeshBlueprintLOD* CopyConstructRMeshBlueprintLodIfPresentPrimary(
      RMeshBlueprintLOD* const destination,
      const RMeshBlueprintLOD* const source
    )
    {
      return CopyConstructRMeshBlueprintLodIfPresent(destination, source);
    }

    /**
     * Address: 0x0051B270 (FUN_0051B270)
     *
     * What it does:
     * Secondary adapter lane for nullable `RMeshBlueprintLOD` copy-construction.
     */
    [[maybe_unused]] [[nodiscard]] const RMeshBlueprintLOD* CopyConstructRMeshBlueprintLodIfPresentSecondary(
      RMeshBlueprintLOD* const destination,
      const RMeshBlueprintLOD* const source
    )
    {
      return CopyConstructRMeshBlueprintLodIfPresent(destination, source);
    }

    /**
     * Address: 0x0051A580 (FUN_0051A580)
     *
     * What it does:
     * Copy-assigns one contiguous destination LOD range from source lanes and
     * returns the advanced source cursor.
     */
    [[maybe_unused]] const RMeshBlueprintLOD* CopyAssignRMeshBlueprintLODRange(
      RMeshBlueprintLOD* destinationBegin,
      RMeshBlueprintLOD* destinationEnd,
      const RMeshBlueprintLOD* sourceBegin
    )
    {
      RMeshBlueprintLOD* destinationCursor = destinationBegin;
      const RMeshBlueprintLOD* sourceCursor = sourceBegin;

      while (destinationCursor != destinationEnd) {
        *destinationCursor = *sourceCursor;
        ++destinationCursor;
        ++sourceCursor;
      }

      return sourceCursor;
    }

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

    /**
     * Address: 0x00528340 (FUN_00528340)
     *
     * What it does:
     * Lazily resolves and caches RTTI metadata for `RMeshBlueprint`.
     */
    [[nodiscard]] gpg::RType* ResolveRMeshBlueprintType()
    {
      gpg::RType* type = RMeshBlueprint::sType;
      if (!type) {
        type = gpg::LookupRType(typeid(RMeshBlueprint));
        RMeshBlueprint::sType = type;
      }
      return type;
    }
  } // namespace

  gpg::RType* RMeshBlueprint::sType = nullptr;

  /**
   * Address: 0x005283A0 (FUN_005283A0, Moho::RMeshBlueprint::RMeshBlueprint)
   * Mangled: ??0RMeshBlueprint@Moho@@QAE@@Z
   *
   * What it does:
   * Forwards to `RBlueprint` base ctor; member defaults are supplied by the
   * in-class initializers so the body is otherwise empty.
   */
  RMeshBlueprint::RMeshBlueprint(RRuleGameRules* const owner, const RResId& resId)
    : RBlueprint(owner, resId)
  {
  }

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
   * Address: 0x0051B080 (FUN_0051B080)
   * Mangled: ??4RMeshBlueprintLOD@Moho@@QAEAAV01@ABV01@@Z
   *
   * IDA signature:
   * int __usercall sub_51B080@<eax>(int a1@<edi>, int a2@<esi>);
   *
   * What it does:
   * Copy-assigns every field in-place via `std::string::assign(src, 0, npos)`
   * for each of the 7 path lanes followed by direct scalar copies for the
   * cutoff float and the three boolean flags. Preserves the pad byte without
   * touching it so the 0xCC-byte record layout is stable.
   */
  RMeshBlueprintLOD& RMeshBlueprintLOD::operator=(const RMeshBlueprintLOD& other)
  {
    if (this == &other) {
      return *this;
    }

    constexpr std::size_t kNoCount = static_cast<std::size_t>(-1);
    mMeshName.assign(other.mMeshName, 0u, kNoCount);
    mAlbedoName.assign(other.mAlbedoName, 0u, kNoCount);
    mNormalsName.assign(other.mNormalsName, 0u, kNoCount);
    mSpecularName.assign(other.mSpecularName, 0u, kNoCount);
    mLookupName.assign(other.mLookupName, 0u, kNoCount);
    mSecondaryName.assign(other.mSecondaryName, 0u, kNoCount);
    mShaderName.assign(other.mShaderName, 0u, kNoCount);

    mLodCutoff = other.mLodCutoff;
    mScrolling = other.mScrolling;
    mOcclude = other.mOcclude;
    mSilhouette = other.mSilhouette;
    return *this;
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
    return ResolveRMeshBlueprintType();
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
