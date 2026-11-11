// Engine addition (issue #255): the GDI text calls CD3DFont makes (declared in
// platform/posix/win32/Windows.h), answered with FreeType for the Linux client.
//
// CD3DFont asks GDI for a font by family name and size, selects it and a 32-bit scratch bitmap
// into a memory DC, reads the text metrics, the 'head' table and the kerning pairs, and draws one
// character at a time white on black to read its coverage back. Here a font is a FreeType face
// made from the files the game registered with AddFontMemResourceEx (D3D_InitFonts), sized as GDI
// sizes a negative CreateFont height (the em in pixels); the metrics follow GDI's TrueType rules
// (OS/2 Windows ascent and descent, hhea line gap); a glyph is FreeType's anti-aliased rendering
// with the light autohinter (the build has no bytecode interpreter), so pixels differ a little from
// Windows, as nothing on Linux can compare them to. Kerning pairs come from the 'kern' table, as
// GDI's do. One lock covers everything: FreeType faces are not shared between threads.

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <Windows.h>

#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_SFNT_NAMES_H
#include FT_TRUETYPE_IDS_H
#include FT_TRUETYPE_TABLES_H
#include FT_TRUETYPE_TAGS_H

namespace
{
  enum class GdiKind
  {
    Font,
    Bitmap,
    Dc,
    Brush,
  };

  struct GdiObject
  {
    explicit GdiObject(
      const GdiKind kind
    )
      : mKind(kind)
    {}
    virtual ~GdiObject() = default;
    const GdiKind mKind;
  };

  /// One face of a registered font file.
  struct RegisteredFace
  {
    const void* mRegistration = nullptr; // the AddFontMemResourceEx handle it came from
    std::shared_ptr<const std::vector<unsigned char>> mBytes;
    FT_Long mIndex = 0;
    std::vector<std::string> mNames; // family names, lower case (name IDs 1, 16 and FreeType's)
    std::wstring mFamily;            // as GetTextFaceW reports it
    bool mStyled = false;            // bold or italic
  };

  struct FontObject final : GdiObject
  {
    FontObject()
      : GdiObject(GdiKind::Font)
    {}
    ~FontObject() override
    {
      if (mFace != nullptr) {
        FT_Done_Face(mFace);
      }
    }

    std::shared_ptr<const std::vector<unsigned char>> mBytes; // FreeType reads the face from these
    FT_Face mFace = nullptr;
    std::wstring mFamily;
    TEXTMETRICW mMetrics{};
    bool mKerningRead = false;
    std::vector<KERNINGPAIR> mKerning;
  };

  struct BitmapObject final : GdiObject
  {
    BitmapObject()
      : GdiObject(GdiKind::Bitmap)
    {}
    int mWidth = 0;
    int mHeight = 0;
    std::vector<std::uint32_t> mPixels; // B, G, R, X bytes, as a 32-bit DIB
  };

  struct DcObject final : GdiObject
  {
    DcObject()
      : GdiObject(GdiKind::Dc)
    {}
    FontObject* mFont = nullptr;
    BitmapObject* mBitmap = nullptr;
    UINT mAlign = 0;
    COLORREF mTextColor = RGB(0, 0, 0);
    COLORREF mBkColor = RGB(255, 255, 255);
  };

  struct BrushObject final : GdiObject
  {
    explicit BrushObject(
      const COLORREF color
    )
      : GdiObject(GdiKind::Brush)
      , mColor(color)
    {}
    const COLORREF mColor;
  };

  std::mutex gLock;
  std::vector<RegisteredFace> gFaces;

  FT_Library Library()
  {
    static FT_Library library = [] {
      FT_Library created = nullptr;
      return FT_Init_FreeType(&created) == 0 ? created : nullptr;
    }();
    return library;
  }

  template <class T>
  [[nodiscard]] T* As(
    void* const handle,
    const GdiKind kind
  )
  {
    auto* const object = static_cast<GdiObject*>(handle);
    return object != nullptr && object->mKind == kind ? static_cast<T*>(object) : nullptr;
  }

  [[nodiscard]] std::string Lower(
    std::string text
  )
  {
    for (char& character : text) {
      if (character >= 'A' && character <= 'Z') {
        character = static_cast<char>(character - 'A' + 'a');
      }
    }
    return text;
  }

  /// A 'name' table string: UTF-16BE for the Windows and Unicode platforms, single bytes otherwise.
  [[nodiscard]] std::wstring DecodeName(
    const FT_SfntName& name
  )
  {
    std::wstring text;
    if (name.platform_id == TT_PLATFORM_MICROSOFT || name.platform_id == TT_PLATFORM_APPLE_UNICODE) {
      for (FT_UInt index = 0; index + 1u < name.string_len; index += 2u) {
        text += static_cast<wchar_t>((name.string[index] << 8) | name.string[index + 1u]);
      }
    } else {
      for (FT_UInt index = 0; index < name.string_len; ++index) {
        text += static_cast<wchar_t>(name.string[index]);
      }
    }
    return text;
  }

  [[nodiscard]] std::string Narrow(
    const std::wstring& text
  )
  {
    std::string narrow;
    for (const wchar_t character : text) {
      narrow += character < 0x80 ? static_cast<char>(character) : '?';
    }
    return narrow;
  }

  void AddName(
    std::vector<std::string>& names,
    const std::string& name
  )
  {
    const std::string lower = Lower(name);
    if (!lower.empty() && std::find(names.begin(), names.end(), lower) == names.end()) {
      names.push_back(lower);
    }
  }

  [[nodiscard]] FT_Face OpenFace(
    const std::vector<unsigned char>& bytes,
    const FT_Long index
  )
  {
    FT_Face face = nullptr;
    if (
      Library() == nullptr ||
      FT_New_Memory_Face(Library(), bytes.data(), static_cast<FT_Long>(bytes.size()), index, &face) != 0
    ) {
      return nullptr;
    }
    return face;
  }

  /// Registers every face in `bytes`; returns how many.
  DWORD RegisterFaces(
    const void* const registration,
    std::shared_ptr<const std::vector<unsigned char>> bytes
  )
  {
    const FT_Face first = OpenFace(*bytes, 0);
    if (first == nullptr) {
      return 0;
    }
    const FT_Long faceCount = first->num_faces;
    FT_Done_Face(first);

    DWORD registered = 0;
    for (FT_Long index = 0; index < faceCount; ++index) {
      const FT_Face face = OpenFace(*bytes, index);
      if (face == nullptr) {
        continue;
      }
      RegisteredFace entry;
      entry.mRegistration = registration;
      entry.mBytes = bytes;
      entry.mIndex = index;
      entry.mStyled = (face->style_flags & (FT_STYLE_FLAG_BOLD | FT_STYLE_FLAG_ITALIC)) != 0;
      const FT_UInt nameCount = FT_Get_Sfnt_Name_Count(face);
      for (FT_UInt nameIndex = 0; nameIndex < nameCount; ++nameIndex) {
        FT_SfntName name{};
        if (FT_Get_Sfnt_Name(face, nameIndex, &name) != 0) {
          continue;
        }
        if (name.name_id == TT_NAME_ID_FONT_FAMILY || name.name_id == TT_NAME_ID_TYPOGRAPHIC_FAMILY) {
          const std::wstring decoded = DecodeName(name);
          AddName(entry.mNames, Narrow(decoded));
          // GDI reports the Windows-platform family name (ID 1).
          if (
            name.name_id == TT_NAME_ID_FONT_FAMILY &&
            (entry.mFamily.empty() || name.platform_id == TT_PLATFORM_MICROSOFT)
          ) {
            entry.mFamily = decoded;
          }
        }
      }
      if (face->family_name != nullptr) {
        AddName(entry.mNames, face->family_name);
        if (entry.mFamily.empty()) {
          for (const char* character = face->family_name; *character != '\0'; ++character) {
            entry.mFamily += static_cast<wchar_t>(static_cast<unsigned char>(*character));
          }
        }
      }
      FT_Done_Face(face);
      gFaces.push_back(std::move(entry));
      ++registered;
    }
    return registered;
  }

  /// A registered face of `family`, upright and regular when there is one.
  [[nodiscard]] const RegisteredFace* FindFace(
    const std::string& family
  )
  {
    const std::string wanted = Lower(family);
    const RegisteredFace* styled = nullptr;
    for (const RegisteredFace& face : gFaces) {
      if (std::find(face.mNames.begin(), face.mNames.end(), wanted) == face.mNames.end()) {
        continue;
      }
      if (!face.mStyled) {
        return &face;
      }
      if (styled == nullptr) {
        styled = &face;
      }
    }
    return styled;
  }

  /// Windows' core fonts are not on Linux: their metric-compatible stand-ins, then any sans face.
  [[nodiscard]] const RegisteredFace* FindSystemFace(
    const std::string& family
  )
  {
    static const char* const kCandidates[] = {
      "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
      "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
      "/usr/share/fonts/liberation-sans/LiberationSans-Regular.ttf",
      "/usr/share/fonts/TTF/LiberationSans-Regular.ttf",
      "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
      "/usr/share/fonts/TTF/DejaVuSans.ttf",
      "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    };
    static const void* const kSystemRegistration = &kCandidates;
    static bool sLoaded = false;
    if (!sLoaded) {
      sLoaded = true;
      for (const char* const path : kCandidates) {
        std::FILE* const file = std::fopen(path, "rb");
        if (file == nullptr) {
          continue;
        }
        auto bytes = std::make_shared<std::vector<unsigned char>>();
        unsigned char chunk[65536];
        std::size_t read = 0;
        while ((read = std::fread(chunk, 1, sizeof(chunk), file)) > 0) {
          bytes->insert(bytes->end(), chunk, chunk + read);
        }
        std::fclose(file);
        if (RegisterFaces(kSystemRegistration, std::move(bytes)) != 0) {
          break; // the first one found is enough
        }
      }
    }
    (void)family;
    for (const RegisteredFace& face : gFaces) {
      if (face.mRegistration == kSystemRegistration) {
        return &face;
      }
    }
    return gFaces.empty() ? nullptr : &gFaces.front();
  }

  [[nodiscard]] LONG Scaled(
    const double units,
    const double scale
  )
  {
    return static_cast<LONG>(std::lround(units * scale));
  }

  /// GDI's TEXTMETRIC for a TrueType face at `emPixels`.
  void ComputeMetrics(
    FontObject& font,
    const int emPixels
  )
  {
    const FT_Face face = font.mFace;
    TEXTMETRICW& metrics = font.mMetrics;
    const double scale =
      static_cast<double>(emPixels) / static_cast<double>(face->units_per_EM != 0 ? face->units_per_EM : 2048);
    const auto* const os2 = static_cast<const TT_OS2*>(FT_Get_Sfnt_Table(face, FT_SFNT_OS2));
    const auto* const hhea = static_cast<const TT_HoriHeader*>(FT_Get_Sfnt_Table(face, FT_SFNT_HHEA));

    const double winAscent = os2 != nullptr && os2->version != 0xFFFFu ? os2->usWinAscent : face->ascender;
    const double winDescent = os2 != nullptr && os2->version != 0xFFFFu ? os2->usWinDescent : -face->descender;
    metrics.tmAscent = Scaled(winAscent, scale);
    metrics.tmDescent = Scaled(winDescent, scale);
    metrics.tmHeight = metrics.tmAscent + metrics.tmDescent;
    metrics.tmInternalLeading = (std::max)(0, metrics.tmHeight - emPixels);
    if (hhea != nullptr) {
      // GDI: the line gap that the Windows ascent and descent don't already cover.
      const double gap = hhea->Line_Gap - ((winAscent + winDescent) - (hhea->Ascender - hhea->Descender));
      metrics.tmExternalLeading = (std::max)(0, Scaled(gap, scale));
    }
    metrics.tmAveCharWidth = os2 != nullptr && os2->version != 0xFFFFu && os2->xAvgCharWidth > 0
      ? Scaled(os2->xAvgCharWidth, scale)
      : Scaled(face->max_advance_width, scale) / 2;
    metrics.tmMaxCharWidth = Scaled(face->bbox.xMax - face->bbox.xMin, scale);
    metrics.tmWeight = os2 != nullptr && os2->version != 0xFFFFu ? os2->usWeightClass : FW_NORMAL;
    metrics.tmOverhang = 0;
    metrics.tmDigitizedAspectX = 96;
    metrics.tmDigitizedAspectY = 96;
    FT_UInt glyphIndex = 0;
    const FT_ULong firstChar = FT_Get_First_Char(face, &glyphIndex);
    metrics.tmFirstChar = static_cast<WCHAR>((std::min<FT_ULong>)(firstChar, 0xFFFFu));
    FT_ULong lastChar = firstChar;
    for (FT_ULong code = firstChar; glyphIndex != 0 && code <= 0xFFFFu;
         code = FT_Get_Next_Char(face, code, &glyphIndex)) {
      lastChar = code;
    }
    metrics.tmLastChar = static_cast<WCHAR>(lastChar);
    metrics.tmDefaultChar = static_cast<WCHAR>(0x1Fu);
    metrics.tmBreakChar = static_cast<WCHAR>(0x20u);
    metrics.tmItalic = (face->style_flags & FT_STYLE_FLAG_ITALIC) != 0 ? 1u : 0u;
    // Bit 0 set means a variable-pitch font (the name is GDI's, the meaning inverted).
    metrics.tmPitchAndFamily =
      static_cast<BYTE>(TMPF_TRUETYPE | TMPF_VECTOR | (FT_IS_FIXED_WIDTH(face) ? 0u : TMPF_FIXED_PITCH));
    metrics.tmCharSet = 1u; // DEFAULT_CHARSET, as CreateFontA asked
  }

  [[nodiscard]] std::uint16_t ReadU16(
    const unsigned char* const bytes
  )
  {
    return static_cast<std::uint16_t>((bytes[0] << 8) | bytes[1]);
  }

  /// The 'kern' table's horizontal format-0 pairs, per character, scaled to pixels.
  void ReadKerning(
    FontObject& font
  )
  {
    font.mKerningRead = true;
    const FT_Face face = font.mFace;
    FT_ULong length = 0;
    if (FT_Load_Sfnt_Table(face, TTAG_kern, 0, nullptr, &length) != 0 || length < 4u) {
      return;
    }
    std::vector<unsigned char> table(length);
    if (FT_Load_Sfnt_Table(face, TTAG_kern, 0, table.data(), &length) != 0) {
      return;
    }

    std::unordered_map<FT_UInt, std::vector<WORD>> charsOfGlyph;
    FT_UInt glyphIndex = 0;
    for (FT_ULong code = FT_Get_First_Char(face, &glyphIndex); glyphIndex != 0 && code <= 0xFFFFu;
         code = FT_Get_Next_Char(face, code, &glyphIndex)) {
      charsOfGlyph[glyphIndex].push_back(static_cast<WORD>(code));
    }

    const double scale = static_cast<double>(face->size->metrics.y_ppem) / static_cast<double>(face->units_per_EM);
    const std::uint16_t subtableCount = ReadU16(table.data() + 2);
    std::size_t offset = 4;
    for (std::uint16_t subtable = 0; subtable < subtableCount && offset + 6u <= table.size(); ++subtable) {
      const std::uint16_t subtableLength = ReadU16(table.data() + offset + 2);
      const std::uint16_t coverage = ReadU16(table.data() + offset + 4);
      const bool horizontalFormat0 = (coverage & 0x0001u) != 0 && (coverage >> 8) == 0u && (coverage & 0x0004u) == 0;
      if (horizontalFormat0 && offset + 14u <= table.size()) {
        const std::uint16_t pairCount = ReadU16(table.data() + offset + 6);
        std::size_t pairOffset = offset + 14u;
        for (std::uint16_t pair = 0; pair < pairCount && pairOffset + 6u <= table.size(); ++pair, pairOffset += 6u) {
          const auto left = charsOfGlyph.find(ReadU16(table.data() + pairOffset));
          const auto right = charsOfGlyph.find(ReadU16(table.data() + pairOffset + 2));
          if (left == charsOfGlyph.end() || right == charsOfGlyph.end()) {
            continue;
          }
          const auto value = static_cast<std::int16_t>(ReadU16(table.data() + pairOffset + 4));
          const int amount = static_cast<int>(Scaled(value, scale));
          for (const WORD first : left->second) {
            for (const WORD second : right->second) {
              font.mKerning.push_back(KERNINGPAIR{first, second, amount});
            }
          }
        }
      }
      if (subtableLength == 0u) {
        break;
      }
      offset += subtableLength;
    }
  }

  constexpr FT_Int32 kLoadFlags = FT_LOAD_TARGET_LIGHT;

  /// A character's advance in whole pixels, as GDI reports it.
  [[nodiscard]] int Advance(
    const FT_Face face,
    const wchar_t character
  )
  {
    if (FT_Load_Char(face, static_cast<FT_ULong>(character), kLoadFlags) != 0) {
      return 0;
    }
    return static_cast<int>((face->glyph->advance.x + 32) >> 6);
  }

  [[nodiscard]] std::uint32_t ToPixel(
    const COLORREF color
  )
  {
    const std::uint32_t red = color & 0xFFu;
    const std::uint32_t green = (color >> 8) & 0xFFu;
    const std::uint32_t blue = (color >> 16) & 0xFFu;
    return blue | (green << 8) | (red << 16);
  }

  void Fill(
    BitmapObject& bitmap,
    const int left,
    const int top,
    const int right,
    const int bottom,
    const std::uint32_t pixel
  )
  {
    for (int y = (std::max)(top, 0); y < (std::min)(bottom, bitmap.mHeight); ++y) {
      for (int x = (std::max)(left, 0); x < (std::min)(right, bitmap.mWidth); ++x) {
        bitmap.mPixels
          [static_cast<std::size_t>(y) * static_cast<std::size_t>(bitmap.mWidth) + static_cast<std::size_t>(x)] = pixel;
      }
    }
  }

  /// Draws `character` with its origin at (penX, baseline): coverage blends the text colour over the background.
  void DrawGlyph(
    DcObject& dc,
    const int penX,
    const int baseline,
    const wchar_t character
  )
  {
    BitmapObject& bitmap = *dc.mBitmap;
    const FT_Face face = dc.mFont->mFace;
    if (FT_Load_Char(face, static_cast<FT_ULong>(character), kLoadFlags | FT_LOAD_RENDER) != 0) {
      return;
    }
    const FT_GlyphSlot slot = face->glyph;
    const FT_Bitmap& glyph = slot->bitmap;
    const int text[3] = {
      static_cast<int>(dc.mTextColor & 0xFFu),
      static_cast<int>((dc.mTextColor >> 8) & 0xFFu),
      static_cast<int>((dc.mTextColor >> 16) & 0xFFu)
    };
    const int background[3] = {
      static_cast<int>(dc.mBkColor & 0xFFu),
      static_cast<int>((dc.mBkColor >> 8) & 0xFFu),
      static_cast<int>((dc.mBkColor >> 16) & 0xFFu)
    };
    for (unsigned int row = 0; row < glyph.rows; ++row) {
      const int y = baseline - slot->bitmap_top + static_cast<int>(row);
      if (y < 0 || y >= bitmap.mHeight) {
        continue;
      }
      const unsigned char* const source = glyph.buffer + static_cast<std::ptrdiff_t>(row) * glyph.pitch;
      for (unsigned int column = 0; column < glyph.width; ++column) {
        const int x = penX + slot->bitmap_left + static_cast<int>(column);
        if (x < 0 || x >= bitmap.mWidth) {
          continue;
        }
        int coverage = 0;
        if (glyph.pixel_mode == FT_PIXEL_MODE_MONO) {
          coverage = (source[column >> 3] & (0x80u >> (column & 7u))) != 0 ? 255 : 0;
        } else if (glyph.pixel_mode == FT_PIXEL_MODE_GRAY) {
          coverage = source[column];
        }
        if (coverage == 0) {
          continue;
        }
        int channel[3];
        for (int index = 0; index < 3; ++index) {
          channel[index] = (text[index] * coverage + background[index] * (255 - coverage) + 127) / 255;
        }
        bitmap.mPixels
          [static_cast<std::size_t>(y) * static_cast<std::size_t>(bitmap.mWidth) + static_cast<std::size_t>(x)] =
          ToPixel(RGB(channel[0], channel[1], channel[2]));
      }
    }
  }
} // namespace

HANDLE AddFontMemResourceEx(
  void* const fontData,
  const DWORD size,
  void* const reserved,
  DWORD* const fontCount
)
{
  (void)reserved;
  if (fontData == nullptr || size == 0u || fontCount == nullptr) {
    return nullptr;
  }
  const std::lock_guard<std::mutex> lock(gLock);
  auto bytes = std::make_shared<const std::vector<unsigned char>>(
    static_cast<const unsigned char*>(fontData), static_cast<const unsigned char*>(fontData) + size
  );
  // The handle only has to be unique and non-null: the address of the registered bytes.
  const void* const registration = bytes.get();
  *fontCount = RegisterFaces(registration, std::move(bytes));
  return *fontCount != 0u ? const_cast<void*>(registration) : nullptr;
}

BOOL RemoveFontMemResourceEx(
  const HANDLE fontHandle
)
{
  const std::lock_guard<std::mutex> lock(gLock);
  const auto removed = std::remove_if(gFaces.begin(), gFaces.end(), [fontHandle](const RegisteredFace& face) {
    return face.mRegistration == fontHandle;
  });
  const bool found = removed != gFaces.end();
  gFaces.erase(removed, gFaces.end());
  return found ? TRUE : FALSE;
}

HFONT CreateFontA(
  const int height,
  const int width,
  const int escapement,
  const int orientation,
  const int weight,
  const DWORD italic,
  const DWORD underline,
  const DWORD strikeOut,
  const DWORD charSet,
  const DWORD outPrecision,
  const DWORD clipPrecision,
  const DWORD quality,
  const DWORD pitchAndFamily,
  const char* const faceName
)
{
  // The width, angles, weight, styles and precisions CD3DFont passes are all GDI's defaults.
  (void)width, (void)escapement, (void)orientation, (void)weight, (void)italic, (void)underline, (void)strikeOut;
  (void)charSet, (void)outPrecision, (void)clipPrecision, (void)quality, (void)pitchAndFamily;
  const std::lock_guard<std::mutex> lock(gLock);
  const std::string family = faceName != nullptr ? faceName : "";
  const RegisteredFace* registered = FindFace(family);
  if (registered == nullptr) {
    registered = FindSystemFace(family);
  }
  if (registered == nullptr) {
    return nullptr;
  }

  auto font = std::make_unique<FontObject>();
  font->mBytes = registered->mBytes;
  font->mFamily = registered->mFamily;
  font->mFace = OpenFace(*font->mBytes, registered->mIndex);
  if (font->mFace == nullptr) {
    return nullptr;
  }
  // A negative height is the em in pixels; a positive one the cell (ascent + descent).
  int emPixels = height < 0 ? -height : 12;
  if (height > 0) {
    const auto* const os2 = static_cast<const TT_OS2*>(FT_Get_Sfnt_Table(font->mFace, FT_SFNT_OS2));
    const double cellUnits = os2 != nullptr && os2->version != 0xFFFFu ? os2->usWinAscent + os2->usWinDescent
                                                                       : font->mFace->ascender - font->mFace->descender;
    emPixels =
      (std::max)(1, static_cast<int>(std::lround(height * static_cast<double>(font->mFace->units_per_EM) / cellUnits)));
  }
  if (FT_Set_Pixel_Sizes(font->mFace, 0, static_cast<FT_UInt>(emPixels)) != 0) {
    return nullptr;
  }
  ComputeMetrics(*font, emPixels);
  return font.release();
}

HDC CreateCompatibleDC(
  const HDC dc
)
{
  (void)dc;
  return new DcObject();
}

HBITMAP CreateBitmap(
  const int width,
  const int height,
  const UINT planes,
  const UINT bitsPerPixel,
  const void* const bits
)
{
  if (width <= 0 || height <= 0 || planes != 1u || bitsPerPixel != 32u) {
    return nullptr; // the only kind CD3DFont makes
  }
  auto* const bitmap = new BitmapObject();
  bitmap->mWidth = width;
  bitmap->mHeight = height;
  bitmap->mPixels.assign(static_cast<std::size_t>(width) * static_cast<std::size_t>(height), 0u);
  if (bits != nullptr) {
    std::memcpy(bitmap->mPixels.data(), bits, bitmap->mPixels.size() * sizeof(std::uint32_t));
  }
  return bitmap;
}

HGDIOBJ SelectObject(
  const HDC dcHandle,
  const HGDIOBJ object
)
{
  const std::lock_guard<std::mutex> lock(gLock);
  DcObject* const dc = As<DcObject>(dcHandle, GdiKind::Dc);
  if (dc == nullptr || object == nullptr) {
    return nullptr;
  }
  if (FontObject* const font = As<FontObject>(object, GdiKind::Font)) {
    FontObject* const previous = dc->mFont;
    dc->mFont = font;
    return previous;
  }
  if (BitmapObject* const bitmap = As<BitmapObject>(object, GdiKind::Bitmap)) {
    BitmapObject* const previous = dc->mBitmap;
    dc->mBitmap = bitmap;
    return previous;
  }
  return nullptr;
}

namespace
{
  BrushObject gBlackBrush(RGB(0, 0, 0));
  BrushObject gWhiteBrush(RGB(255, 255, 255));
} // namespace

HGDIOBJ GetStockObject(
  const int object
)
{
  switch (object) {
  case BLACK_BRUSH:
    return &gBlackBrush;
  case 0: // WHITE_BRUSH
    return &gWhiteBrush;
  default:
    return nullptr;
  }
}

BOOL DeleteObject(
  const HGDIOBJ object
)
{
  if (object == nullptr || object == &gBlackBrush || object == &gWhiteBrush) {
    return object != nullptr ? TRUE : FALSE;
  }
  const std::lock_guard<std::mutex> lock(gLock);
  delete static_cast<GdiObject*>(object); // CD3DFont also deletes its DC this way
  return TRUE;
}

BOOL DeleteDC(
  const HDC dc
)
{
  return DeleteObject(dc);
}

int GetObjectW(
  const HGDIOBJ object,
  const int size,
  void* const out
)
{
  const std::lock_guard<std::mutex> lock(gLock);
  const BitmapObject* const bitmap = As<BitmapObject>(object, GdiKind::Bitmap);
  if (bitmap == nullptr || out == nullptr || size < static_cast<int>(sizeof(BITMAP))) {
    return 0;
  }
  BITMAP info{};
  info.bmWidth = bitmap->mWidth;
  info.bmHeight = bitmap->mHeight;
  info.bmWidthBytes = bitmap->mWidth * 4;
  info.bmPlanes = 1;
  info.bmBitsPixel = 32;
  std::memcpy(out, &info, sizeof(info));
  return static_cast<int>(sizeof(info));
}

BOOL GetTextMetricsW(
  const HDC dcHandle,
  TEXTMETRICW* const metrics
)
{
  const std::lock_guard<std::mutex> lock(gLock);
  const DcObject* const dc = As<DcObject>(dcHandle, GdiKind::Dc);
  if (dc == nullptr || dc->mFont == nullptr || metrics == nullptr) {
    return FALSE;
  }
  *metrics = dc->mFont->mMetrics;
  return TRUE;
}

int GetTextFaceW(
  const HDC dcHandle,
  const int count,
  wchar_t* const face
)
{
  const std::lock_guard<std::mutex> lock(gLock);
  const DcObject* const dc = As<DcObject>(dcHandle, GdiKind::Dc);
  if (dc == nullptr || dc->mFont == nullptr) {
    return 0;
  }
  const std::wstring& family = dc->mFont->mFamily;
  if (face == nullptr) {
    return static_cast<int>(family.size()) + 1;
  }
  if (count <= 0) {
    return 0;
  }
  const std::size_t copied = (std::min)(family.size(), static_cast<std::size_t>(count - 1));
  std::wmemcpy(face, family.data(), copied);
  face[copied] = L'\0';
  return static_cast<int>(copied) + 1; // with the terminator, as GDI counts
}

DWORD GetFontData(
  const HDC dcHandle,
  const DWORD table,
  const DWORD offset,
  void* const buffer,
  const DWORD size
)
{
  const std::lock_guard<std::mutex> lock(gLock);
  const DcObject* const dc = As<DcObject>(dcHandle, GdiKind::Dc);
  if (dc == nullptr || dc->mFont == nullptr) {
    return GDI_ERROR;
  }
  // GDI takes the tag as its bytes in file order read little-endian; FreeType as a big-endian number.
  const FT_ULong tag =
    table == 0u ? 0u : ((table & 0xFFu) << 24) | ((table & 0xFF00u) << 8) | ((table >> 8) & 0xFF00u) | (table >> 24);
  FT_ULong length = 0;
  if (FT_Load_Sfnt_Table(dc->mFont->mFace, tag, 0, nullptr, &length) != 0 || offset > length) {
    return GDI_ERROR;
  }
  const FT_ULong available = length - offset;
  if (buffer == nullptr || size == 0u) {
    return static_cast<DWORD>(available);
  }
  FT_ULong wanted = (std::min<FT_ULong>)(available, size);
  if (
    FT_Load_Sfnt_Table(dc->mFont->mFace, tag, static_cast<FT_Long>(offset), static_cast<FT_Byte*>(buffer), &wanted) != 0
  ) {
    return GDI_ERROR;
  }
  return static_cast<DWORD>(wanted);
}

DWORD GetKerningPairsW(
  const HDC dcHandle,
  const DWORD count,
  KERNINGPAIR* const pairs
)
{
  const std::lock_guard<std::mutex> lock(gLock);
  const DcObject* const dc = As<DcObject>(dcHandle, GdiKind::Dc);
  if (dc == nullptr || dc->mFont == nullptr) {
    return 0;
  }
  FontObject& font = *dc->mFont;
  if (!font.mKerningRead) {
    ReadKerning(font);
  }
  if (pairs == nullptr) {
    return static_cast<DWORD>(font.mKerning.size());
  }
  const std::size_t copied = (std::min)(font.mKerning.size(), static_cast<std::size_t>(count));
  std::copy_n(font.mKerning.begin(), copied, pairs);
  return static_cast<DWORD>(copied);
}

UINT SetTextAlign(
  const HDC dcHandle,
  const UINT align
)
{
  const std::lock_guard<std::mutex> lock(gLock);
  DcObject* const dc = As<DcObject>(dcHandle, GdiKind::Dc);
  if (dc == nullptr) {
    return GDI_ERROR;
  }
  const UINT previous = dc->mAlign;
  dc->mAlign = align;
  return previous;
}

COLORREF SetTextColor(
  const HDC dcHandle,
  const COLORREF color
)
{
  const std::lock_guard<std::mutex> lock(gLock);
  DcObject* const dc = As<DcObject>(dcHandle, GdiKind::Dc);
  if (dc == nullptr) {
    return 0xFFFFFFFFu; // CLR_INVALID
  }
  const COLORREF previous = dc->mTextColor;
  dc->mTextColor = color;
  return previous;
}

COLORREF SetBkColor(
  const HDC dcHandle,
  const COLORREF color
)
{
  const std::lock_guard<std::mutex> lock(gLock);
  DcObject* const dc = As<DcObject>(dcHandle, GdiKind::Dc);
  if (dc == nullptr) {
    return 0xFFFFFFFFu; // CLR_INVALID
  }
  const COLORREF previous = dc->mBkColor;
  dc->mBkColor = color;
  return previous;
}

int FillRect(
  const HDC dcHandle,
  const RECT* const rect,
  const HBRUSH brushHandle
)
{
  const std::lock_guard<std::mutex> lock(gLock);
  DcObject* const dc = As<DcObject>(dcHandle, GdiKind::Dc);
  const BrushObject* const brush = As<BrushObject>(brushHandle, GdiKind::Brush);
  if (dc == nullptr || dc->mBitmap == nullptr || rect == nullptr || brush == nullptr) {
    return 0;
  }
  Fill(*dc->mBitmap, rect->left, rect->top, rect->right, rect->bottom, ToPixel(brush->mColor));
  return 1;
}

int DrawTextW(
  const HDC dcHandle,
  const wchar_t* const text,
  const int count,
  RECT* const rect,
  const UINT format
)
{
  const std::lock_guard<std::mutex> lock(gLock);
  DcObject* const dc = As<DcObject>(dcHandle, GdiKind::Dc);
  if (dc == nullptr || dc->mFont == nullptr || text == nullptr || rect == nullptr) {
    return 0;
  }
  const std::size_t length = count < 0 ? std::wcslen(text) : static_cast<std::size_t>(count);
  const FT_Face face = dc->mFont->mFace;
  const TEXTMETRICW& metrics = dc->mFont->mMetrics;

  int width = 0;
  for (std::size_t index = 0; index < length; ++index) {
    width += Advance(face, text[index]);
  }
  if ((format & DT_CALCRECT) != 0u) {
    rect->right = rect->left + width;
    rect->bottom = rect->top + metrics.tmHeight;
    return metrics.tmHeight;
  }
  if (dc->mBitmap == nullptr) {
    return metrics.tmHeight;
  }

  // Single-line text at the rectangle's left; with TA_BASELINE the rectangle's top is the baseline.
  const bool baselineAligned = (dc->mAlign & TA_BASELINE) == TA_BASELINE;
  const int baseline = baselineAligned ? rect->top : rect->top + metrics.tmAscent;
  // GDI's default opaque background: the text cell takes the background colour first.
  Fill(
    *dc->mBitmap,
    rect->left,
    baseline - metrics.tmAscent,
    rect->left + width,
    baseline + metrics.tmDescent,
    ToPixel(dc->mBkColor)
  );
  int penX = rect->left;
  for (std::size_t index = 0; index < length; ++index) {
    DrawGlyph(*dc, penX, baseline, text[index]);
    penX += Advance(face, text[index]);
  }
  return metrics.tmHeight;
}

COLORREF GetPixel(
  const HDC dcHandle,
  const int x,
  const int y
)
{
  const std::lock_guard<std::mutex> lock(gLock);
  const DcObject* const dc = As<DcObject>(dcHandle, GdiKind::Dc);
  if (
    dc == nullptr || dc->mBitmap == nullptr || x < 0 || y < 0 || x >= dc->mBitmap->mWidth || y >= dc->mBitmap->mHeight
  ) {
    return 0xFFFFFFFFu; // CLR_INVALID
  }
  const std::uint32_t pixel =
    dc->mBitmap->mPixels
      [static_cast<std::size_t>(y) * static_cast<std::size_t>(dc->mBitmap->mWidth) + static_cast<std::size_t>(x)];
  return RGB((pixel >> 16) & 0xFFu, (pixel >> 8) & 0xFFu, pixel & 0xFFu);
}

LONG GetBitmapBits(
  const HBITMAP bitmapHandle,
  const LONG size,
  void* const bits
)
{
  const std::lock_guard<std::mutex> lock(gLock);
  const BitmapObject* const bitmap = As<BitmapObject>(bitmapHandle, GdiKind::Bitmap);
  if (bitmap == nullptr || bits == nullptr || size <= 0) {
    return 0;
  }
  const std::size_t copied = (std::min)(static_cast<std::size_t>(size), bitmap->mPixels.size() * sizeof(std::uint32_t));
  std::memcpy(bits, bitmap->mPixels.data(), copied);
  return static_cast<LONG>(copied);
}

BOOL GdiFlush()
{
  return TRUE;
}
