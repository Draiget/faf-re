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

  struct WaterDirectionVector
  {
    float x{};
    float y{};
    float z{};
  };
  static_assert(sizeof(WaterDirectionVector) == 0x0C,
                "WaterDirectionVector size must be 0x0C");

  /**
   * Typed placeholder for unrecovered numeric shader lanes in
   * CWaterShaderProperties (+0x04..+0x83).
   */
  struct WaterShaderNumericState
  {
    std::uint32_t laneFlags{}; // +0x00

    float scalar00{}; // +0x04
    float scalar01{}; // +0x08
    float scalar02{}; // +0x0C
    float scalar03{}; // +0x10
    float scalar04{}; // +0x14
    float scalar05{}; // +0x18
    float scalar06{}; // +0x1C
    float scalar07{}; // +0x20
    float scalar08{}; // +0x24
    float scalar09{}; // +0x28
    float scalar10{}; // +0x2C
    float scalar11{}; // +0x30
    float scalar12{}; // +0x34
    float scalar13{}; // +0x38
    float scalar14{}; // +0x3C
    float scalar15{}; // +0x40
    float scalar16{}; // +0x44
    float scalar17{}; // +0x48
    float scalar18{}; // +0x4C
    float scalar19{}; // +0x50
    float scalar20{}; // +0x54
    float scalar21{}; // +0x58
    float scalar22{}; // +0x5C

    WaterDirectionVector directionPrimary{};   // +0x60
    WaterDirectionVector directionSecondary{}; // +0x6C

    float scalar29{}; // +0x78
    float scalar30{}; // +0x7C
  };
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
