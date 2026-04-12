#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/utils/BoostWrappers.h"
#include "legacy/containers/String.h"

namespace moho
{
  class CD3DDynamicTextureSheet;

  /**
   * Water shader parameters and texture handles for the high-fidelity water
   * rendering path in Moho/ForgedAlliance.
   *
   * VFTABLE: 0x00E4BD4C  (??_7CWaterShaderProperties@Moho@@6B@)
   * COL: 0x00EDF584
   *
   * The destructor calls releaseTextures() then destroys the string fields and
   * texture handle array in reverse construction order.
   */
  class CWaterShaderProperties
  {
  public:
    /**
     * Address: 0x0089F9A0 (FUN_0089F9A0)
     * Mangled: ??1CWaterShaderProperties@Moho@@UAE@XZ
     *
     * IDA signature:
     * void __thiscall Moho::CWaterShaderProperties::~CWaterShaderProperties(int this);
     *
     * What it does:
     * Resets the vtable pointer, releases all texture handles via releaseTextures(),
     * frees the weak-ptr texture array element-wise, and destroys all string members.
     */
    virtual ~CWaterShaderProperties();

    /**
     * Address: 0x008A0740 (FUN_008A0740)
     * Mangled: ?releaseTextures@CWaterShaderProperties@Moho@@QAEXXZ
     *
     * What it does:
     * Clears all mTextures entries (sheet ptr + reference count) using the
     * atomic InterlockedExchangeAdd-based boost shared_ptr release pattern.
     */
    void releaseTextures();

    // -------------------------------------------------------------------------
    // Layout — offsets confirmed from binary evidence (dtor + releaseTextures).
    // Fields at +0x04 through +0x83 are not yet recovered; placeholder used.
    // The compiler-implicit vtable pointer occupies +0x00.
    // -------------------------------------------------------------------------

    std::uint8_t mPad_0x04[0x80]{};                 // +0x04  (placeholder for unrecovered fields)

    // Shader parameter strings — array of 4 at +0x84.
    // Confirmed by: eh_vector_destructor(this+0x84, size=0x1C, n=4, std::string::~string)
    msvc8::string mShaderNames[4]{};                 // +0x84  (4 × 0x1C = 0x70 bytes)

    // Two additional string fields following the array.
    msvc8::string mShaderName4{};                    // +0xF4
    msvc8::string mShaderName5{};                    // +0x110

    // Six texture-sheet handles (boost::SharedPtrRaw<CD3DDynamicTextureSheet>).
    // Confirmed by: releaseTextures() iterating mTextures[0..5] and
    //   eh_vector_destructor(this+0x12C, size=8, n=4, WeakPtr_CD3DDynamicTextureSheet::Release).
    boost::SharedPtrRaw<CD3DDynamicTextureSheet> mTextures[6]{};  // +0x12C
  };

  // Spot-check key field offsets derived from binary evidence.
  static_assert(offsetof(CWaterShaderProperties, mShaderNames) == 0x84,
                "CWaterShaderProperties::mShaderNames offset must be 0x84");
  static_assert(offsetof(CWaterShaderProperties, mShaderName4) == 0xF4,
                "CWaterShaderProperties::mShaderName4 offset must be 0xF4");
  static_assert(offsetof(CWaterShaderProperties, mShaderName5) == 0x110,
                "CWaterShaderProperties::mShaderName5 offset must be 0x110");
  static_assert(offsetof(CWaterShaderProperties, mTextures) == 0x12C,
                "CWaterShaderProperties::mTextures offset must be 0x12C");

} // namespace moho
