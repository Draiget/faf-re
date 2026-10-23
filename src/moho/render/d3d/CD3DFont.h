#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>

#include "platform/Platform.h"

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "legacy/containers/Vector.h"
#include "moho/math/Vector3f.h"
#include "moho/misc/CountedObject.h"
#include "moho/render/d3d/CD3DFontTypes.h"
#include "Wm3Vector2.h"

namespace moho
{
  class CD3DPrimBatcher;

  class CD3DFont : public CountedObject
  {
  public:
    struct SKerningPair
    {
      wchar_t mLeft;   // +0x00
      wchar_t mRight;  // +0x02
      float mAmount;   // +0x04
    };

    using SCharInfo = CD3DFontCharInfo;

    using SCharInfoPage = msvc8::vector<SCharInfo>;
    using SCharInfoPages = msvc8::vector<SCharInfoPage>;
    using KerningPairVector = msvc8::vector<SKerningPair>;

    /**
     * Address: 0x00425290 (FUN_00425290,
     * ?Create@CD3DFont@Moho@@SA?AV?$CountedPtr@VCD3DFont@Moho@@@2@HVStrArg@gpg@@@Z)
     *
     * int, gpg::StrArg
     *
     * What it does:
     * Looks up or creates one cached D3D font object for point-size + face-name.
     */
    [[nodiscard]] static boost::SharedPtrRaw<CD3DFont> Create(std::int32_t pointSize, gpg::StrArg faceName);

    /**
     * Address: 0x00425500 (FUN_00425500, ??0CD3DFont@Moho@@AAE@PAX@Z)
     *
     * HFONT
     *
     * What it does:
     * Initializes D3D font metrics, glyph-page cache lanes, and kerning pairs
     * from one Win32 font handle.
     */
    explicit CD3DFont(HFONT font);

    /**
     * Address: 0x00425860 (FUN_00425860, ??1CD3DFont@Moho@@UAE@XZ)
     *
     * What it does:
     * Releases Win32 font/DC/bitmap resources and tears down glyph + kerning
     * container ownership lanes.
     */
    ~CD3DFont() override;

    /**
     * Address: 0x00425840 (FUN_00425840, Moho::CD3DFont::dtr)
     *
     * int
     *
     * What it does:
     * Executes the scalar-deleting-dtor thunk path used by intrusive release
     * callsites.
     */
    CD3DFont* Release(std::int32_t destroyNow);

    /**
     * Address: 0x00425940 (FUN_00425940, ?GetCharInfo@CD3DFont@Moho@@QAEABUSCharInfo@12@_W@Z)
     *
     * wchar_t
     *
     * What it does:
     * Returns cached glyph metrics/texture info for one UTF-16 codepoint,
     * building the glyph page/atlas data on first use.
     */
    const SCharInfo& GetCharInfo(wchar_t chText);

    /**
     * Address: 0x00426470 (FUN_00426470, ?Render@CD3DFont@Moho@@QAE?AV?$Vector3@M@Wm3@@VStrArg@gpg@@PAVCD3DPrimBatcher@2@ABV34@22IMM@Z)
     *
     * gpg::StrArg, Moho::CD3DPrimBatcher*, Wm3::Vector3<float> const&,
     * Wm3::Vector3<float> const&, Wm3::Vector3<float> const&, unsigned int,
     * float, float
     *
     * What it does:
     * Draws one UTF-8 string along caller-provided axis vectors and returns the
     * final pen position.
     */
    [[nodiscard]] Vector3f Render(
      gpg::StrArg text,
      CD3DPrimBatcher* primBatcher,
      const Vector3f& origin,
      const Vector3f& xAxis,
      const Vector3f& yAxis,
      std::uint32_t color,
      float glyphScale,
      float maxAdvance
    );

    /**
     * Address: 0x00426580 (FUN_00426580, ?Render2D@CD3DFont@Moho@@QAEXVStrArg@gpg@@PAVCD3DPrimBatcher@2@ABV?$Vector2@M@Wm3@@IMM@Z)
     *
     * gpg::StrArg, Moho::CD3DPrimBatcher*, Wm3::Vector2<float> const&,
     * unsigned int, float, float
     *
     * What it does:
     * Projects one 2D text draw into 3D render space and dispatches to
     * `Render(...)` with screen-space axes.
     */
    void Render2D(
      gpg::StrArg text,
      CD3DPrimBatcher* primBatcher,
      const Wm3::Vector2f& origin,
      std::uint32_t color,
      float glyphScale,
      float maxAdvance
    );

    /**
     * Address: 0x00426610 (FUN_00426610, ?GetAdvance@CD3DFont@Moho@@QAEMVStrArg@gpg@@H@Z)
     *
     * gpg::StrArg, int
     *
     * What it does:
     * Returns cumulative glyph advance for one UTF-8 string.
     */
    [[nodiscard]] float GetAdvance(gpg::StrArg text, std::int32_t flags);

    /**
     * Address: 0x00426680 (FUN_00426680, ?GetNearestCharacterIndex@CD3DFont@Moho@@QAEHVStrArg@gpg@@M@Z)
     *
     * gpg::StrArg, float
     *
     * What it does:
     * Returns the UTF-8 character index closest to the caller-provided advance.
     */
    [[nodiscard]] std::int32_t GetNearestCharacterIndex(gpg::StrArg text, float targetAdvance);

  public:
    HFONT mFont;              // +0x08
    bool mIsTruetype;         // +0x0C
    std::uint8_t mPad0D[0x03];
    float mHeight;            // +0x10
    float mAscent;            // +0x14
    float mDescent;           // +0x18
    float mInternalLeading;   // +0x1C
    float mExternalLeading;   // +0x20
    float mAveCharWidth;      // +0x24
    float mOverhang;          // +0x28
    SCharInfoPages mCharInfo; // +0x2C
    KerningPairVector mKerningPairs; // +0x3C
    HDC mDeviceContext;              // +0x4C
    HBITMAP mBitmap;                 // +0x50
  };

  static_assert(sizeof(CD3DFont::SKerningPair) == 0x08, "moho::CD3DFont::SKerningPair size must be 0x08");
  static_assert(offsetof(CD3DFont::SKerningPair, mLeft) == 0x00, "moho::CD3DFont::SKerningPair::mLeft offset must be 0x00");
  static_assert(
    offsetof(CD3DFont::SKerningPair, mRight) == 0x02,
    "moho::CD3DFont::SKerningPair::mRight offset must be 0x02"
  );
  static_assert(
    offsetof(CD3DFont::SKerningPair, mAmount) == 0x04,
    "moho::CD3DFont::SKerningPair::mAmount offset must be 0x04"
  );

  static_assert(
    offsetof(CD3DFont, mFont) == 0x08,
    "moho::CD3DFont::mFont offset must be 0x08"
  );
  static_assert(
    offsetof(CD3DFont, mIsTruetype) == 0x0C,
    "moho::CD3DFont::mIsTruetype offset must be 0x0C"
  );
  static_assert(offsetof(CD3DFont, mHeight) == 0x10, "moho::CD3DFont::mHeight offset must be 0x10");
  static_assert(offsetof(CD3DFont, mAscent) == 0x14, "moho::CD3DFont::mAscent offset must be 0x14");
  static_assert(
    offsetof(CD3DFont, mExternalLeading) == 0x20,
    "moho::CD3DFont::mExternalLeading offset must be 0x20"
  );
  static_assert(offsetof(CD3DFont, mCharInfo) == 0x2C, "moho::CD3DFont::mCharInfo offset must be 0x2C");
  static_assert(
    offsetof(CD3DFont, mKerningPairs) == 0x3C,
    "moho::CD3DFont::mKerningPairs offset must be 0x3C"
  );
  static_assert(
    offsetof(CD3DFont, mDeviceContext) == 0x4C,
    "moho::CD3DFont::mDeviceContext offset must be 0x4C"
  );
  static_assert(offsetof(CD3DFont, mBitmap) == 0x50, "moho::CD3DFont::mBitmap offset must be 0x50");
  static_assert(sizeof(CD3DFont) == 0x54, "moho::CD3DFont size must be 0x54");
} // namespace moho
