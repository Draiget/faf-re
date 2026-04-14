#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"
#include "moho/resource/blueprints/RBlueprint.h"

namespace moho
{
  /**
   * Address: 0x005184C0 (FUN_005184C0)
   *
   * What it does:
   * Reflection type init for a single mesh LOD descriptor (`sizeof = 0xCC`).
   */
  struct RMeshBlueprintLOD
  {
    msvc8::string mMeshName;      // +0x00
    msvc8::string mAlbedoName;    // +0x1C
    msvc8::string mNormalsName;   // +0x38
    msvc8::string mSpecularName;  // +0x54
    msvc8::string mLookupName;    // +0x70
    msvc8::string mSecondaryName; // +0x8C
    msvc8::string mShaderName;    // +0xA8
    float mLodCutoff{1000.0f};    // +0xC4
    std::uint8_t mScrolling{0};   // +0xC8
    std::uint8_t mOcclude{0};     // +0xC9
    std::uint8_t mSilhouette{0};  // +0xCA
    std::uint8_t mPadCB{0};       // +0xCB

    /**
     * Address: 0x005183D0 (FUN_005183D0)
     * Mangled: ??0RMeshBlueprintLOD@Moho@@QAE@XZ
     *
     * What it does:
     * Default-initializes one mesh LOD descriptor with empty string lanes,
     * default cutoff, and disabled bool flags.
     */
    RMeshBlueprintLOD();

    /**
     * Address: 0x0051A0F0 (FUN_0051A0F0, Moho::RMeshBlueprintLOD::RMeshBlueprintLOD)
     * Mangled: ??0RMeshBlueprintLOD@Moho@@QAE@ABV01@@Z
     *
     * What it does:
     * Copy-constructs one mesh LOD descriptor including all path string lanes
     * and scalar flags.
     */
    RMeshBlueprintLOD(const RMeshBlueprintLOD& other);

    /**
     * Address: 0x00518870 (FUN_00518870)
     * Mangled: ?Init@RMeshBlueprintLOD@Moho@@QAEXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@I@Z
     *
     * What it does:
     * Resolves mesh/material texture names for this LOD from source path and
     * fallback naming rules (`_lod%d.scm`, `_albedo.dds`, `_normalsTS.dds`,
     * `_SpecTeam.dds`, `_lookup.dds`).
     */
    void Init(const msvc8::string& sourcePath, std::uint32_t lodIndex);
  };

  /**
   * Address: 0x00518710 (FUN_00518710)
   *
   * What it does:
   * Reflection type init for `RMeshBlueprint` (`sizeof = 0x80`) and fields:
   * `LODs` (+0x60), `IconFadeInZoom` (+0x70), `SortOrder` (+0x74),
   * `UniformScale` (+0x78), `StraddleWater` (+0x7C).
   */
  struct RMeshBlueprint : public RBlueprint
  {
    msvc8::vector<RMeshBlueprintLOD> mLods; // +0x60
    float mIconFadeInZoom{0.0f};            // +0x70
    float mSortOrder{0.0f};                 // +0x74
    float mUniformScale{1.0f};              // +0x78
    std::uint8_t mStraddleWater{0};         // +0x7C
    std::uint8_t mPad7D[3]{0, 0, 0};        // +0x7D
    static gpg::RType* sType;

    /**
     * Address: 0x005283A0 (FUN_005283A0)
     * Mangled: ??0RMeshBlueprint@Moho@@QAE@@Z
     *
     * What it does:
     * Forwards to `RBlueprint` base ctor; all member defaults are handled by
     * in-class initializers (`mLods` empty, `mIconFadeInZoom/mSortOrder = 0`,
     * `mUniformScale = 1.0`, `mStraddleWater = 0`).
     */
    RMeshBlueprint(RRuleGameRules* owner, const RResId& resId);

    /**
     * Address: 0x00528360 (FUN_00528360)
     * Mangled: ?GetClass@RMeshBlueprint@Moho@@UBEPAVRType@gpg@@XZ
     *
     * What it does:
     * Returns cached reflection descriptor for `RMeshBlueprint`.
     */
    [[nodiscard]] gpg::RType* GetClass() const;

    /**
     * Address: 0x00528380 (FUN_00528380)
     * Mangled: ?GetDerivedObjectRef@RMeshBlueprint@Moho@@UAE?AVRRef@gpg@@XZ
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef();

    /**
     * Address: 0x00518EB0 (FUN_00518EB0)
     * Mangled: ?OnInitBlueprint@RMeshBlueprint@Moho@@MAEXXZ
     *
     * What it does:
     * Initializes each LOD entry using blueprint source-path derived rules.
     */
    void OnInitBlueprint();
  };

  static_assert(sizeof(RMeshBlueprintLOD) == 0xCC, "RMeshBlueprintLOD size must be 0xCC");
  static_assert(offsetof(RMeshBlueprintLOD, mMeshName) == 0x00, "RMeshBlueprintLOD::mMeshName offset must be 0x00");
  static_assert(offsetof(RMeshBlueprintLOD, mAlbedoName) == 0x1C, "RMeshBlueprintLOD::mAlbedoName offset must be 0x1C");
  static_assert(
    offsetof(RMeshBlueprintLOD, mNormalsName) == 0x38, "RMeshBlueprintLOD::mNormalsName offset must be 0x38"
  );
  static_assert(
    offsetof(RMeshBlueprintLOD, mSpecularName) == 0x54, "RMeshBlueprintLOD::mSpecularName offset must be 0x54"
  );
  static_assert(offsetof(RMeshBlueprintLOD, mLookupName) == 0x70, "RMeshBlueprintLOD::mLookupName offset must be 0x70");
  static_assert(
    offsetof(RMeshBlueprintLOD, mSecondaryName) == 0x8C, "RMeshBlueprintLOD::mSecondaryName offset must be 0x8C"
  );
  static_assert(offsetof(RMeshBlueprintLOD, mShaderName) == 0xA8, "RMeshBlueprintLOD::mShaderName offset must be 0xA8");
  static_assert(offsetof(RMeshBlueprintLOD, mLodCutoff) == 0xC4, "RMeshBlueprintLOD::mLodCutoff offset must be 0xC4");
  static_assert(offsetof(RMeshBlueprintLOD, mScrolling) == 0xC8, "RMeshBlueprintLOD::mScrolling offset must be 0xC8");
  static_assert(offsetof(RMeshBlueprintLOD, mOcclude) == 0xC9, "RMeshBlueprintLOD::mOcclude offset must be 0xC9");
  static_assert(offsetof(RMeshBlueprintLOD, mSilhouette) == 0xCA, "RMeshBlueprintLOD::mSilhouette offset must be 0xCA");

  static_assert(offsetof(RMeshBlueprint, mLods) == 0x60, "RMeshBlueprint::mLods offset must be 0x60");
  static_assert(
    offsetof(RMeshBlueprint, mIconFadeInZoom) == 0x70, "RMeshBlueprint::mIconFadeInZoom offset must be 0x70"
  );
  static_assert(offsetof(RMeshBlueprint, mSortOrder) == 0x74, "RMeshBlueprint::mSortOrder offset must be 0x74");
  static_assert(offsetof(RMeshBlueprint, mUniformScale) == 0x78, "RMeshBlueprint::mUniformScale offset must be 0x78");
  static_assert(offsetof(RMeshBlueprint, mStraddleWater) == 0x7C, "RMeshBlueprint::mStraddleWater offset must be 0x7C");
  static_assert(sizeof(RMeshBlueprint) == 0x80, "RMeshBlueprint size must be 0x80");
} // namespace moho
