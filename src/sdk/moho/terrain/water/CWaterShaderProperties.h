#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/utils/BoostWrappers.h"
#include "legacy/containers/String.h"

namespace gpg
{
  class BinaryReader;
  class BinaryWriter;
}

namespace moho
{
  class CD3DDynamicTextureSheet;
  class ID3DTextureSheet;

  /**
   * The `water2` effect's parameter block, held on `CWaterShaderProperties` at
   * +0x04 and bound lane-for-lane by `HighFidelityWater`/`LowFidelityWater`.
   *
   * Every name here is pinned by three independent sources that agree:
   *
   * - the effect-variable strings the renderers look each lane up by
   *   (`"WaterColor"`, `"NormalRepeatRate"`, `"SunDirection"`, ... -- see
   *   `WaterShaderVars.cpp`), and the float count each `SetShaderVarMem` call
   *   passes, which is what makes the array members arrays;
   * - the defaults the constructor at 0x0089F600 seeds, which are the stock
   *   map water settings verbatim -- `SunDirection` normalises to
   *   (0.0999, -0.9626, 0.2519) and `SunColor` to (0.8127, 0.4741, 0.3387);
   * - the archive order of `Save`/`Load` (0x0089FEA0 / 0x008A03C0), which is
   *   the `.scmap` water-settings block field for field.
   *
   * `mSunStrength` is the one lane no render path binds: it round-trips
   * through the archive and is otherwise unread, which is why the earlier
   * placeholder layout had nothing to hang a name on.
   */
  struct WaterShaderNumericState
  {
    float mWaterColor[3]{};        // +0x00  "WaterColor",           3 floats
    float mWaterLerp[2]{};         // +0x0C  "WaterLerp",            2 floats
    float mRefractionScale{};      // +0x14  "RefractionScale"
    float mFresnelBias{};          // +0x18  "FresnelBias"
    float mFresnelPower{};         // +0x1C  "FresnelPower"
    float mUnitReflectionAmount{}; // +0x20  "UnitReflectionAmount"
    float mSkyReflectionAmount{};  // +0x24  "SkyReflectionAmount"
    float mNormalRepeatRate[4]{};  // +0x28  "NormalRepeatRate",     4 floats
    float mNormal1Movement[2]{};   // +0x38  "Normal1Movement",      2 floats
    float mNormal2Movement[2]{};   // +0x40  "Normal2Movement",      2 floats
    float mNormal3Movement[2]{};   // +0x48  "Normal3Movement",      2 floats
    float mNormal4Movement[2]{};   // +0x50  "Normal4Movement",      2 floats
    float mSunShininess{};         // +0x58  "SunShininess"
    float mSunStrength{};          // +0x5C  archive-only, bound by nothing
    float mSunDirection[3]{};      // +0x60  "SunDirection",         3 floats
    float mSunColor[3]{};          // +0x6C  "SunColor",             3 floats
    float mSunReflectionAmount{};  // +0x78  "SunReflectionAmount"
    float mSunGlow{};              // +0x7C  "SunGlow"
  };
  static_assert(offsetof(WaterShaderNumericState, mWaterLerp) == 0x0C,
                "WaterShaderNumericState::mWaterLerp offset must be 0x0C");
  static_assert(offsetof(WaterShaderNumericState, mNormalRepeatRate) == 0x28,
                "WaterShaderNumericState::mNormalRepeatRate offset must be 0x28");
  static_assert(offsetof(WaterShaderNumericState, mNormal1Movement) == 0x38,
                "WaterShaderNumericState::mNormal1Movement offset must be 0x38");
  static_assert(offsetof(WaterShaderNumericState, mSunShininess) == 0x58,
                "WaterShaderNumericState::mSunShininess offset must be 0x58");
  static_assert(offsetof(WaterShaderNumericState, mSunDirection) == 0x60,
                "WaterShaderNumericState::mSunDirection offset must be 0x60");
  static_assert(offsetof(WaterShaderNumericState, mSunColor) == 0x6C,
                "WaterShaderNumericState::mSunColor offset must be 0x6C");
  static_assert(offsetof(WaterShaderNumericState, mSunGlow) == 0x7C,
                "WaterShaderNumericState::mSunGlow offset must be 0x7C");
  static_assert(sizeof(WaterShaderNumericState) == 0x80,
                "WaterShaderNumericState size must be 0x80");

  /**
   * Water shader parameters and texture handles for the high-fidelity water
   * rendering path in Moho/ForgedAlliance.
   *
   * VFTABLE: 0x00E4BD4C  (??_7CWaterShaderProperties@Moho@@6B@)
   * COL: 0x00EDF584
   */
  class CWaterShaderProperties
  {
  public:
    /**
     * Address: 0x0089F600 (FUN_0089F600, ??0CWaterShaderProperties@Moho@@QAE@XZ)
     *
     * What it does:
     * Seeds default water-shader numeric lanes, initializes wave/cubemap/ramp
     * texture path strings, clears cached texture handles, and normalizes
     * the two direction vectors used by wave projection.
     */
    CWaterShaderProperties();

    /**
     * Address: 0x0089F8D0 (FUN_0089F8D0, ??0CWaterShaderProperties@Moho@@QAE@ABV01@@Z)
     *
     * What it does:
     * Constructs one water-shader payload from another instance, initializing
     * local string/shared-pointer lanes and then copying scalar + string state.
     */
    CWaterShaderProperties(const CWaterShaderProperties& rhs);

    /**
     * Address: 0x0089F9A0 (FUN_0089F9A0)
     * Mangled: ??1CWaterShaderProperties@Moho@@UAE@XZ
     *
     * What it does:
     * Resets the vtable pointer, releases all texture handles via releaseTextures(),
     * frees texture shared-ptr lanes, and destroys all string members.
     */
    virtual ~CWaterShaderProperties();

    /**
     * Address: 0x0089FEA0 (FUN_0089FEA0, ?Save@CWaterShaderProperties@Moho@@QBEXAAVBinaryWriter@gpg@@@Z)
     * Mangled: ?Save@CWaterShaderProperties@Moho@@QBEXAAVBinaryWriter@gpg@@@Z
     *
     * What it does:
     * Persists one deterministic water-shader payload in the legacy terrain
     * archive order (float lanes + shader-name strings + ramp/cubemap paths).
     */
    void Save(gpg::BinaryWriter& writer) const;

    /**
     * Address: 0x008A03C0 (FUN_008A03C0, ?Load@CWaterShaderProperties@Moho@@QAEXIAAVBinaryReader@gpg@@@Z)
     * Mangled: ?Load@CWaterShaderProperties@Moho@@QAEXIAAVBinaryReader@gpg@@@Z
     *
     * What it does:
     * Restores one water-shader payload from the legacy terrain archive lane,
     * including the interleaved `(float,float,string)` wave entries.
     */
    void Load(unsigned int version, gpg::BinaryReader& reader);

    /**
     * Address: 0x008A0740 (FUN_008A0740)
     * Mangled: ?releaseTextures@CWaterShaderProperties@Moho@@QAEXXZ
     *
     * What it does:
     * Clears all mTextures entries (sheet ptr + reference count) using the
     * atomic boost shared_ptr release pattern.
     */
    void releaseTextures();

    /**
     * Address: 0x0089FD70 (FUN_0089FD70)
     * Mangled: ?GetWaterRamp@CWaterShaderProperties@Moho@@QBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ
     *
     * What it does:
     * Lazily resolves one water-ramp texture resource from the stored ramp-path
     * string, caches it in mTextures[5], and returns one retained shared
     * texture-sheet handle.
     */
    [[nodiscard]] boost::shared_ptr<ID3DTextureSheet> GetWaterRamp() const;

    /**
     * Address: 0x0089FC40 (FUN_0089FC40, ?GetCubeMap@CWaterShaderProperties@Moho@@QBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ)
     * Mangled: ?GetCubeMap@CWaterShaderProperties@Moho@@QBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ
     *
     * What it does:
     * Lazily resolves one water-cubemap texture from mWaterCubemap, caches
     * it in mTextures[4], and returns one retained shared texture-sheet
     * handle.
     */
    [[nodiscard]] boost::shared_ptr<ID3DTextureSheet> GetCubeMap() const;

    /**
     * Address: 0x0089FB00 (FUN_0089FB00, ?GetNormalMap@CWaterShaderProperties@Moho@@QBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@H@Z)
     * Mangled: ?GetNormalMap@CWaterShaderProperties@Moho@@QBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@H@Z
     *
     * What it does:
     * Lazily resolves one indexed normal-map texture from mShaderNames[index],
     * caches it in mTextures[index], and returns one retained shared texture
     * sheet handle.
     */
    [[nodiscard]] boost::shared_ptr<ID3DTextureSheet> GetNormalMap(int index) const;

    // -------------------------------------------------------------------------
    // Layout - offsets confirmed from binary evidence (ctor/copy/dtor).
    // The compiler-implicit vtable pointer occupies +0x00.
    // -------------------------------------------------------------------------

    WaterShaderNumericState mNumericState{}; // +0x04

    // Shader parameter strings - array of 4 at +0x84.
    // Confirmed by: eh_vector_destructor(this+0x84, size=0x1C, n=4, std::string::~string)
    msvc8::string mShaderNames[4]{}; // +0x84  (4 x 0x1C = 0x70 bytes)

    msvc8::string mWaterCubemap{}; // +0xF4
    msvc8::string mWaterRamp{};    // +0x110

    // Six texture-sheet handles (boost::SharedPtrRaw<ID3DTextureSheet>).
    // Confirmed by: releaseTextures() iterating mTextures[0..5].
    mutable boost::SharedPtrRaw<ID3DTextureSheet> mTextures[6]{}; // +0x12C

  private:
    /**
     * Address: 0x008A08D0 (FUN_008A08D0, ?copy@CWaterShaderProperties@Moho@@AAEXABV12@@Z)
     *
     * What it does:
     * Releases resident texture handles, copies scalar shader lanes, and
     * assigns all shader/cubemap/ramp strings from rhs.
     */
    void copy(const CWaterShaderProperties& rhs);
  };

  static_assert(offsetof(CWaterShaderProperties, mNumericState) == 0x04,
                "CWaterShaderProperties::mNumericState offset must be 0x04");
  static_assert(offsetof(CWaterShaderProperties, mShaderNames) == 0x84,
                "CWaterShaderProperties::mShaderNames offset must be 0x84");
  static_assert(offsetof(CWaterShaderProperties, mWaterCubemap) == 0xF4,
                "CWaterShaderProperties::mWaterCubemap offset must be 0xF4");
  static_assert(offsetof(CWaterShaderProperties, mWaterRamp) == 0x110,
                "CWaterShaderProperties::mWaterRamp offset must be 0x110");
  static_assert(offsetof(CWaterShaderProperties, mTextures) == 0x12C,
                "CWaterShaderProperties::mTextures offset must be 0x12C");
  static_assert(sizeof(CWaterShaderProperties) == 0x15C,
                "CWaterShaderProperties size must be 0x15C");

} // namespace moho
