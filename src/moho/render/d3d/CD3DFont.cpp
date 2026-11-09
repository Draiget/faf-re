#include "CD3DFont.h"

#include <array>
#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <limits>
#include <atomic>
#include <map>
#include <mutex>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "gpg/core/utils/Logging.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/LocalCache.h"
#include "gpg/gal/effects/EffectRuntime.h"
#include "gpg/gal/Effect.hpp"
#include "gpg/gal/EffectTechnique.hpp"
#include "gpg/gal/EffectVariable.hpp"
#include "moho/console/CConCommand.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/d3d/ShaderVar.h"
#include "moho/render/font/MsdfFontRegistry.h"
#include "moho/render/font/MsdfTextGpuRenderer.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/render/textures/DXTCodec.h"

namespace moho
{
  namespace
  {
    /**
     * Engine addition: `ren_GlyphBitmapRead`. A new character's glyph is read from the
     * scratch bitmap with one GetBitmapBits call instead of one GetPixel per pixel; the pixels
     * are the same (checked on the session's first glyph, see GetCharInfo).
     */
    bool ren_GlyphBitmapRead = true;

    TConVar<bool> gTConVar_ren_GlyphBitmapRead(
      "ren_GlyphBitmapRead",
      "Read a new character's glyph from the font's scratch bitmap in one call (1, the default) instead of one "
      "GetPixel per pixel (0), which cost tens of ms when a frame met many new characters.",
      &ren_GlyphBitmapRead
    );

    /**
     * Engine addition: `ren_GlyphCache`. A character's glyph (its DXT5 blocks and metrics), once
     * rasterized through GDI, is kept in glyph-cache.bin in the local cache directory, so later
     * launches take it from there instead of rasterizing it again. An entry is keyed by the font
     * (the face GDI selected, its text metrics and its 'head' table: revision, checksum, dates), the
     * character, and what else decides GDI's output (the Windows build and its font smoothing
     * settings) and this executable. The session's first glyph from the cache is rasterized too and
     * compared; any difference drops the cache for good. (Not one per font: a font's first glyph
     * makes GDI realize the font, most of a lobby's glyph time when each of ~30 fonts did it.)
     */
    bool ren_GlyphCache = true;

    TConVar<bool> gTConVar_ren_GlyphCache(
      "ren_GlyphCache",
      "Take a character's glyph from the glyph cache kept with the shaders when an earlier launch rasterized it "
      "(1, the default), or rasterize every glyph through GDI (0). The same glyphs either way.",
      &ren_GlyphCache
    );

    using gpg::gal::effects::Fnv1a64;

    template <class T>
    void AddValue(Fnv1a64& hash, const T& value) noexcept
    {
      hash.Add(&value, sizeof(value));
    }

    /// What besides the font decides GDI's output, and this executable: hashed once.
    [[nodiscard]] std::uint64_t GlyphEnvironment()
    {
      static const std::uint64_t sEnvironment = [] {
        Fnv1a64 hash;
        AddValue(hash, gpg::ExecutableIdentity());
        using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOW*);
        OSVERSIONINFOW version{};
        version.dwOSVersionInfoSize = sizeof(version);
        if (const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll"); ntdll != nullptr) {
          if (const auto rtlGetVersion = reinterpret_cast<RtlGetVersionFn>(GetProcAddress(ntdll, "RtlGetVersion"))) {
            (void)rtlGetVersion(&version);
          }
        }
        AddValue(hash, version.dwMajorVersion);
        AddValue(hash, version.dwMinorVersion);
        AddValue(hash, version.dwBuildNumber);
        for (const UINT action : {SPI_GETFONTSMOOTHING, SPI_GETFONTSMOOTHINGTYPE, SPI_GETFONTSMOOTHINGCONTRAST,
                                  SPI_GETFONTSMOOTHINGORIENTATION}) {
          UINT value = 0;
          (void)SystemParametersInfoW(action, 0, &value, 0);
          AddValue(hash, value);
        }
        return hash.Value();
      }();
      return sEnvironment;
    }

    /// One cached glyph: what GetCharInfo builds its SCharInfo from.
    struct SCachedGlyph
    {
      std::uint16_t mBlockWidth = 0;
      std::uint16_t mBlockHeight = 0;
      float mV2 = 0.0f;
      float mV3 = 0.0f;
      float mV4 = 0.0f;
      float mV5 = 0.0f;
      float mAdvance = 0.0f;
      std::vector<std::uint64_t> mBlocks;

      [[nodiscard]] bool operator==(const SCachedGlyph& other) const
      {
        return mBlockWidth == other.mBlockWidth && mBlockHeight == other.mBlockHeight && mV2 == other.mV2 &&
          mV3 == other.mV3 && mV4 == other.mV4 && mV5 == other.mV5 && mAdvance == other.mAdvance &&
          mBlocks == other.mBlocks;
      }
    };

    /**
     * glyph-cache.bin: "FAFGLYP1", the environment hash, then entries {u64 key, u16 width, u16
     * height, 5 floats, u32 block count, the blocks}. Read on first use, written whole (to a temporary
     * file, then moved over the old one) a few seconds after the last glyph was added, and at exit.
     */
    class GlyphCacheStore
    {
    public:
      [[nodiscard]] const SCachedGlyph* Find(const std::uint64_t key)
      {
        const std::lock_guard<std::mutex> lock(mLock);
        LoadLocked();
        const auto found = mGlyphs.find(key);
        return found != mGlyphs.end() ? &found->second : nullptr;
      }

      void Add(const std::uint64_t key, SCachedGlyph glyph)
      {
        const std::lock_guard<std::mutex> lock(mLock);
        LoadLocked();
        mGlyphs.insert_or_assign(key, std::move(glyph));
        mDirty = true;
        mLastAdd = GetTickCount64();
      }

      void Drop()
      {
        const std::lock_guard<std::mutex> lock(mLock);
        mGlyphs.clear();
        mDirty = false;
        if (const std::string path = PathLocked(); !path.empty()) {
          (void)DeleteFileA(path.c_str());
        }
      }

      void SaveIfIdle(const bool now)
      {
        const std::lock_guard<std::mutex> lock(mLock);
        if (!mDirty || (!now && GetTickCount64() - mLastAdd < 3000u)) {
          return;
        }
        mDirty = false;
        const std::string path = PathLocked();
        if (path.empty()) {
          return;
        }
        // Another process (the other game of a local test, say) may have written glyphs this one
        // never met since this one read the file: they are kept.
        ReadFileLocked(path, mGlyphs);
        const std::string temporary = path + "." + std::to_string(GetCurrentProcessId()) + ".tmp"; // each process its own
        std::FILE* const out = std::fopen(temporary.c_str(), "wb");
        if (out == nullptr) {
          return;
        }
        bool written = std::fwrite("FAFGLYP1", 1, 8, out) == 8;
        const std::uint64_t environment = GlyphEnvironment();
        written = written && std::fwrite(&environment, sizeof(environment), 1, out) == 1;
        for (const auto& [key, glyph] : mGlyphs) {
          const std::uint32_t count = static_cast<std::uint32_t>(glyph.mBlocks.size());
          const float metrics[] = {glyph.mV2, glyph.mV3, glyph.mV4, glyph.mV5, glyph.mAdvance};
          written = written && std::fwrite(&key, sizeof(key), 1, out) == 1 &&
            std::fwrite(&glyph.mBlockWidth, sizeof(glyph.mBlockWidth), 1, out) == 1 &&
            std::fwrite(&glyph.mBlockHeight, sizeof(glyph.mBlockHeight), 1, out) == 1 &&
            std::fwrite(metrics, sizeof(metrics), 1, out) == 1 && std::fwrite(&count, sizeof(count), 1, out) == 1 &&
            (count == 0 || std::fwrite(glyph.mBlocks.data(), sizeof(std::uint64_t), count, out) == count);
        }
        written = std::fclose(out) == 0 && written;
        if (!written || !MoveFileExA(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
          (void)DeleteFileA(temporary.c_str());
        }
      }

    private:
      [[nodiscard]] std::string PathLocked() const
      {
        const std::string& directory = gpg::LocalCacheDirectory();
        return directory.empty() ? std::string{} : directory + "glyph-cache.bin";
      }

      void LoadLocked()
      {
        if (mLoaded) {
          return;
        }
        mLoaded = true;
        if (const std::string path = PathLocked(); !path.empty()) {
          ReadFileLocked(path, mGlyphs);
        }
      }

      /// A glyph as GetCharInfo makes them: 4 to 128 pixels each way in steps of 4, two blocks per 4x4.
      [[nodiscard]] static bool IsGlyphShape(const std::uint16_t width, const std::uint16_t height, const std::uint32_t count)
      {
        const auto fits = [](const std::uint16_t size) { return size >= 4u && size <= 128u && size % 4u == 0u; };
        return fits(width) && fits(height) && count == (width / 4u) * (height / 4u) * 2u;
      }

      /// Adds the file's glyphs that `glyphs` does not hold yet; stops at the first damaged entry.
      static void ReadFileLocked(const std::string& path, std::unordered_map<std::uint64_t, SCachedGlyph>& glyphs)
      {
        std::FILE* const in = std::fopen(path.c_str(), "rb");
        if (in == nullptr) {
          return;
        }
        char magic[8] = {};
        std::uint64_t environment = 0;
        if (std::fread(magic, 1, 8, in) == 8 && std::memcmp(magic, "FAFGLYP1", 8) == 0 &&
            std::fread(&environment, sizeof(environment), 1, in) == 1 && environment == GlyphEnvironment()) {
          for (;;) {
            std::uint64_t key = 0;
            SCachedGlyph glyph;
            float metrics[5] = {};
            std::uint32_t count = 0;
            if (std::fread(&key, sizeof(key), 1, in) != 1 ||
                std::fread(&glyph.mBlockWidth, sizeof(glyph.mBlockWidth), 1, in) != 1 ||
                std::fread(&glyph.mBlockHeight, sizeof(glyph.mBlockHeight), 1, in) != 1 ||
                std::fread(metrics, sizeof(metrics), 1, in) != 1 || std::fread(&count, sizeof(count), 1, in) != 1 ||
                !IsGlyphShape(glyph.mBlockWidth, glyph.mBlockHeight, count)) {
              break;
            }
            glyph.mBlocks.resize(count);
            if (count != 0 && std::fread(glyph.mBlocks.data(), sizeof(std::uint64_t), count, in) != count) {
              break;
            }
            glyph.mV2 = metrics[0];
            glyph.mV3 = metrics[1];
            glyph.mV4 = metrics[2];
            glyph.mV5 = metrics[3];
            glyph.mAdvance = metrics[4];
            glyphs.emplace(key, std::move(glyph));
          }
        }
        std::fclose(in);
      }

      std::mutex mLock;
      bool mLoaded = false;
      bool mDirty = false;
      std::uint64_t mLastAdd = 0;
      std::unordered_map<std::uint64_t, SCachedGlyph> mGlyphs;
    };

    // Never destroyed: fonts outlive static destruction order.
    GlyphCacheStore& GlyphCache()
    {
      static auto* const store = new GlyphCacheStore();
      return *store;
    }

    std::atomic<bool> gGlyphCacheVerified{false}; // the session's first cached glyph matched its rasterization

    /// Each live font's identity for the glyph cache (0: not cached).
    std::mutex gFontIdentityLock;
    std::unordered_map<const void*, std::uint64_t>& FontIdentities()
    {
      static auto* const identities = new std::unordered_map<const void*, std::uint64_t>();
      return *identities;
    }

    /// The identity of the font selected into `dc`: its face, text metrics and 'head' table.
    [[nodiscard]] std::uint64_t ComputeFontIdentity(HDC const dc)
    {
      constexpr DWORD kHeadTable = 0x64616568u; // 'head'
      const DWORD headSize = GetFontData(dc, kHeadTable, 0, nullptr, 0);
      if (headSize == GDI_ERROR || headSize == 0 || headSize > 4096u) {
        return 0;
      }
      std::vector<unsigned char> head(headSize);
      if (GetFontData(dc, kHeadTable, 0, head.data(), headSize) != headSize) {
        return 0;
      }
      wchar_t face[LF_FACESIZE] = {};
      const int faceLength = GetTextFaceW(dc, LF_FACESIZE, face);
      TEXTMETRICW metrics{};
      if (faceLength <= 0 || !GetTextMetricsW(dc, &metrics)) {
        return 0;
      }
      Fnv1a64 hash;
      hash.Add(face, static_cast<std::size_t>(faceLength) * sizeof(wchar_t));
      AddValue(hash, metrics);
      hash.Add(head.data(), head.size());
      return hash.Value() | 1u; // never 0
    }

    [[nodiscard]] std::uint64_t GlyphKey(const std::uint64_t font, const wchar_t character)
    {
      Fnv1a64 hash;
      AddValue(hash, font);
      AddValue(hash, static_cast<std::uint32_t>(character));
      return hash.Value();
    }

    /**
     * Engine addition: `ren_MsdfText` (issue #307). Screen-space text at `ren_MsdfTextMinSize` pixels or
     * more draws from an MSDF atlas (a texture of distances to each glyph's outline) when one is ready.
     * Advances still come from the GDI font, so Lua's layout and word wrapping don't move.
     */
    bool ren_MsdfText = true;
    int ren_MsdfTextMinSize = 1;

    TConVar<bool> gTConVar_ren_MsdfText(
      "ren_MsdfText",
      "Draw screen-space text from MSDF atlases where one is ready (1, the default), or always through GDI glyphs (0). "
      "A mod's font has no GDI version and keeps its atlas either way.",
      &ren_MsdfText
    );
    TConVar<int> gTConVar_ren_MsdfTextMinSize(
      "ren_MsdfTextMinSize",
      "The smallest text in pixels ren_MsdfText draws from an atlas; smaller text stays on GDI glyphs. Not for a mod's font.",
      &ren_MsdfTextMinSize
    );

    constexpr const char* kMsdfTechnique = "TMsdfText";
    constexpr const char* kModFontFallbackFace = "Arial";
    constexpr const char* kScreenTextTechnique = "TAlphaBlendLinearSampleNoDepth";
    constexpr std::uint32_t kAtlasTextureFormat = 2u; // 32-bit; byte order doesn't matter to the median

    /** What a `CD3DFont` needs for MSDF text. Kept beside it: the class's layout is the binary's. */
    struct MsdfBinding
    {
      std::string mFace;
      std::int32_t mPointSize = 0;
      std::shared_ptr<const SMsdfFontAtlas> mAtlas;
      // A family from `LoadFont` (`mod:<hash>`): GDI never hears of it and draws the default font until the
      // atlas arrives, and from then on the atlas's metrics and advances replace GDI's.
      bool mIsMod = false;
      const SMsdfStrike* mStrike = nullptr; // into mAtlas: this size as a bitmap, when it has one
      std::shared_ptr<const SMsdfFontAtlas> mFallbackAtlas;
      // The atlas page had no room for this mod font's atlas: it draws in the default font, with that font's
      // advances too, rather than GDI's glyphs at the mod font's spacing. Its bitmaps of small sizes still apply.
      bool mNoPage = false;
    };

    /**
     * Many fonts' atlases on one GPU texture, so a change of font doesn't split a draw. A device reset
     * replaces the sheet's texture and loses its pixels, so they're written again.
     */
    struct MsdfAtlasPage
    {
      struct PlacedFont
      {
        const SMsdfFontAtlas* mAtlas = nullptr;
        std::int32_t mX = 0;
        std::int32_t mY = 0;
      };

      boost::shared_ptr<CD3DDynamicTextureSheet> mSheet;
      const void* mUploadedTexture = nullptr;
      std::vector<PlacedFont> mFonts;
      std::int32_t mShelfX = 0;
      std::int32_t mShelfY = 0;
      std::int32_t mShelfHeight = 0;
    };

    constexpr std::int32_t kMsdfPageWidth = 2048;
    constexpr std::int32_t kMsdfPageHeight = 4096;
    constexpr std::int32_t kMsdfPageSpacing = 3; // empty texels between fonts, as between glyph boxes

    std::map<const CD3DFont*, MsdfBinding> sMsdfBindings;
    bool sHasModFonts = false; // so a game with none pays one load
    // The game's fonts on one page, mods' fonts on another (with their own copy of the default font for the
    // characters they lack), so fonts from mods can't take the room the game's text needs.
    MsdfAtlasPage sMsdfGamePage;
    MsdfAtlasPage sMsdfModPage;

    [[nodiscard]] const SMsdfGlyph* FindMsdfGlyph(const SMsdfFontAtlas& atlas, const std::uint32_t codepoint)
    {
      const auto found = std::lower_bound(
        atlas.mGlyphs.begin(), atlas.mGlyphs.end(), codepoint,
        [](const SMsdfGlyph& glyph, const std::uint32_t value) { return glyph.mCodepoint < value; }
      );
      return found != atlas.mGlyphs.end() && found->mCodepoint == codepoint ? &*found : nullptr;
    }

    /** Writes one font's pixels and the empty texels to its right and below it, which keep the next font apart. */
    [[nodiscard]] bool WriteFontToPage(MsdfAtlasPage& page, const MsdfAtlasPage::PlacedFont& placed)
    {
      const SMsdfFontAtlas& atlas = *placed.mAtlas;
      const std::int32_t right = (std::min)(placed.mX + atlas.mWidth + kMsdfPageSpacing, kMsdfPageWidth);
      const std::int32_t bottom = (std::min)(placed.mY + atlas.mHeight + kMsdfPageSpacing, kMsdfPageHeight);
      const RECT rect{placed.mX, placed.mY, right, bottom};
      std::uint32_t pitch = 0u;
      void* bits = nullptr;
      if (!page.mSheet->LockRect(&rect, &pitch, &bits) || bits == nullptr) {
        return false;
      }
      const std::size_t lockedRowBytes = static_cast<std::size_t>(right - placed.mX) * 4u;
      const std::size_t atlasRowBytes = static_cast<std::size_t>(atlas.mWidth) * 4u;
      for (std::int32_t row = 0; row < bottom - placed.mY; ++row) {
        auto* const out = static_cast<std::uint8_t*>(bits) + static_cast<std::size_t>(pitch) * static_cast<std::size_t>(row);
        std::memset(out, 0, lockedRowBytes);
        if (row < atlas.mHeight) {
          std::memcpy(out, atlas.mPixels.data() + atlasRowBytes * static_cast<std::size_t>(row), atlasRowBytes);
        }
      }
      (void)page.mSheet->Unlock();
      return true;
    }

    /**
     * Where an atlas sits on the page, placing it on first use and rewriting the page after a device reset.
     * False when the page is full or can't be made; that font stays on GDI glyphs. `outFull` says it was full.
     */
    [[nodiscard]] bool AcquireMsdfPlacement(
      MsdfAtlasPage& page, const SMsdfFontAtlas& atlas, std::int32_t& outX, std::int32_t& outY, bool& outFull
    )
    {
      outFull = false;
      if (!page.mSheet) {
        CD3DDevice* const device = D3D_GetDevice();
        ID3DDeviceResources* const resources = device != nullptr ? device->GetResources() : nullptr;
        if (resources == nullptr) {
          return false;
        }
        (void)resources->NewDynamicTextureSheet(page.mSheet, kMsdfPageWidth, kMsdfPageHeight, kAtlasTextureFormat);
        if (!page.mSheet) {
          return false;
        }
      }

      CD3DDynamicTextureSheet::TextureHandle texture;
      page.mSheet->GetTexture(texture);
      if (texture.get() != page.mUploadedTexture) {
        for (const MsdfAtlasPage::PlacedFont& placed : page.mFonts) {
          if (!WriteFontToPage(page, placed)) {
            return false;
          }
        }
        page.mUploadedTexture = texture.get();
      }

      for (const MsdfAtlasPage::PlacedFont& placed : page.mFonts) {
        if (placed.mAtlas == &atlas) {
          outX = placed.mX;
          outY = placed.mY;
          return true;
        }
      }

      if (page.mShelfX + atlas.mWidth > kMsdfPageWidth) {
        page.mShelfY += page.mShelfHeight + kMsdfPageSpacing;
        page.mShelfX = 0;
        page.mShelfHeight = 0;
      }
      if (atlas.mWidth > kMsdfPageWidth || page.mShelfY + atlas.mHeight > kMsdfPageHeight) {
        outFull = true;
        return false;
      }
      const MsdfAtlasPage::PlacedFont placed{&atlas, page.mShelfX, page.mShelfY};
      if (!WriteFontToPage(page, placed)) {
        return false;
      }
      page.mFonts.push_back(placed);
      page.mShelfX += atlas.mWidth + kMsdfPageSpacing;
      page.mShelfHeight = (std::max)(page.mShelfHeight, atlas.mHeight);
      outX = placed.mX;
      outY = placed.mY;
      return true;
    }

    [[nodiscard]] const SMsdfStrike* FindMsdfStrike(const SMsdfFontAtlas& atlas, const std::int32_t pixelSize)
    {
      for (const SMsdfStrike& strike : atlas.mStrikes) {
        if (strike.mPixelSize == pixelSize) {
          return &strike;
        }
      }
      return nullptr;
    }

    [[nodiscard]] const SMsdfStrikeGlyph* FindMsdfStrikeGlyph(const SMsdfStrike& strike, const std::uint32_t codepoint)
    {
      const auto found = std::lower_bound(
        strike.mGlyphs.begin(), strike.mGlyphs.end(), codepoint,
        [](const SMsdfStrikeGlyph& glyph, const std::uint32_t value) { return glyph.mCodepoint < value; }
      );
      return found != strike.mGlyphs.end() && found->mCodepoint == codepoint ? &*found : nullptr;
    }

    void PollModFontBinding(CD3DFont& font, MsdfBinding& binding);
    void InitializeGlyphPageCache(CD3DFont::SCharInfoPages& pages);
    void DestroyGlyphPageCache(CD3DFont::SCharInfoPages& pages);

    /**
     * Draws a string from its font's MSDF atlas, at any uniform scale of the screen plane (the axes' length), so
     * text that grows or shrinks stays sharp and costs no new font. Returns false, having drawn nothing, when the
     * old path has to: no atlas yet, small text, text not on the screen plane, a character no atlas has, or a
     * caller drawing with a technique other than the UI's.
     */
    [[nodiscard]] bool RenderMsdfText(
      CD3DFont& font, const char* const text, CD3DPrimBatcher& primBatcher, const Vector3f& origin, const Vector3f& xAxis,
      const Vector3f& yAxis, const std::uint32_t color, const float maxAdvance, Vector3f& outCursor
    )
    {
      const auto bound = sMsdfBindings.find(&font);
      // A mod's font has no GDI version, so the switches for the game's fonts don't send it there.
      if (bound == sMsdfBindings.end() || (bound->second.mPointSize < ren_MsdfTextMinSize && !bound->second.mIsMod)) {
        return false;
      }
      const float textScale = xAxis.x;
      if (!(textScale > 0.0f) || xAxis.y != 0.0f || xAxis.z != 0.0f || yAxis.x != 0.0f || yAxis.y != -textScale || yAxis.z != 0.0f) {
        return false;
      }
      MsdfBinding& binding = bound->second;
      if (binding.mIsMod) {
        PollModFontBinding(font, binding);
        // Its small sizes have bitmaps, which GetCharInfo draws; scaled, they'd blur, and the atlas doesn't.
        if (binding.mStrike != nullptr && textScale == 1.0f) {
          return false;
        }
      } else if (!binding.mAtlas) {
        binding.mAtlas = MSDF_FindAtlas(binding.mFace.c_str());
      }
      if (!binding.mAtlas) {
        return false;
      }
      const SMsdfFontAtlas& atlas = *binding.mAtlas;
      if (binding.mIsMod && !binding.mFallbackAtlas) {
        binding.mFallbackAtlas = MSDF_FindAtlas(kModFontFallbackFace);
      }
      const SMsdfFontAtlas* const fallback = binding.mIsMod ? binding.mFallbackAtlas.get() : nullptr;

      // A character a mod's font lacks comes from the default font's atlas, on the same page and in the same draw.
      bool usesFallback = false;
      wchar_t codepoint = 0;
      for (const char* encoded = gpg::STR_DecodeUtf8Char(text, codepoint); codepoint != 0;
           encoded = gpg::STR_DecodeUtf8Char(encoded, codepoint)) {
        if (FindMsdfGlyph(atlas, static_cast<std::uint32_t>(codepoint)) == nullptr) {
          if (fallback == nullptr || FindMsdfGlyph(*fallback, static_cast<std::uint32_t>(codepoint)) == nullptr) {
            return false;
          }
          usesFallback = true;
        }
      }

      CD3DDevice* const device = D3D_GetDevice();
      CD3DEffect* const effect = device != nullptr ? device->GetCurEffect() : nullptr;
      if (effect == nullptr || std::strcmp(effect->mName.c_str(), "primbatcher") != 0
          || !effect->mCurrentTechnique || std::strcmp(effect->mCurrentTechnique->GetName()->c_str(), kScreenTextTechnique) != 0) {
        return false;
      }
      std::int32_t pageX = 0;
      std::int32_t pageY = 0;
      bool pageFull = false;
      MsdfAtlasPage& page = binding.mIsMod ? sMsdfModPage : sMsdfGamePage;
      if (!AcquireMsdfPlacement(page, atlas, pageX, pageY, pageFull)) {
        if (pageFull && binding.mIsMod && !binding.mNoPage) {
          gpg::Warnf("MSDF: the atlas page is full; %s at %d px draws in the default font", binding.mFace.c_str(), binding.mPointSize);
          binding.mNoPage = true;
          DestroyGlyphPageCache(font.mCharInfo); // they hold the mod font's advances
          InitializeGlyphPageCache(font.mCharInfo);
        }
        return false;
      }
      std::int32_t fallbackPageX = 0;
      std::int32_t fallbackPageY = 0;
      if (usesFallback && !AcquireMsdfPlacement(page, *fallback, fallbackPageX, fallbackPageY, pageFull)) {
        return false;
      }
      const boost::shared_ptr<CD3DDynamicTextureSheet>& sheet = page.mSheet;

      const float size = static_cast<float>(binding.mPointSize) * textScale;
      const float pixelRange = atlas.mDistanceRange * size / atlas.mEmPixels;

      // One instanced draw from a GPU buffer where the backend has it; through the batcher otherwise.
      MsdfTextGpuRenderer& instancedText = MsdfTextGpuRenderer::Get();
      const bool instanced = instancedText.IsActive() && instancedText.BeginString(primBatcher, sheet);
      CD3DPrimBatcher::TextureBinding previousTexture{};
      boost::shared_ptr<gpg::gal::EffectTechnique> previousTechnique;
      if (!instanced) {
        if (!shaderVarPrimBatcherMsdfPixelRange.Exists()) {
          return false;
        }
        primBatcher.Flush();
        previousTexture = primBatcher.GetTextureBinding();
        previousTechnique = effect->mCurrentTechnique;
        effect->SetTechnique(kMsdfTechnique);
        shaderVarPrimBatcherMsdfPixelRange.mEffectVariable->SetFloat(pixelRange);
        primBatcher.SetTexture(boost::static_pointer_cast<ID3DTextureSheet>(sheet));
      }

      const float inverseWidth = 1.0f / static_cast<float>(kMsdfPageWidth);
      const float inverseHeight = 1.0f / static_cast<float>(kMsdfPageHeight);
      const auto corner = [&](const Vector3f& pen, const float x, const float y) {
        return Vector3f{pen.x + x * size, pen.y - y * size, pen.z};
      };
      Vector3f cursor = origin;
      float totalAdvance = 0.0f;
      for (const char* encoded = gpg::STR_DecodeUtf8Char(text, codepoint); codepoint != 0;
           encoded = gpg::STR_DecodeUtf8Char(encoded, codepoint)) {
        // The clip width is the control's, so it counts unscaled advances: a pop doesn't change what fits.
        const float advance = font.GetCharInfo(codepoint).mAdvance;
        totalAdvance += advance;
        if (std::isfinite(maxAdvance) && totalAdvance > maxAdvance) {
          break;
        }
        const SMsdfGlyph* found = FindMsdfGlyph(atlas, static_cast<std::uint32_t>(codepoint));
        float glyphPageX = static_cast<float>(pageX);
        float glyphPageY = static_cast<float>(pageY);
        if (found == nullptr) {
          found = FindMsdfGlyph(*fallback, static_cast<std::uint32_t>(codepoint));
          glyphPageX = static_cast<float>(fallbackPageX);
          glyphPageY = static_cast<float>(fallbackPageY);
        }
        const SMsdfGlyph& glyph = *found;
        if (glyph.mAtlasRight > glyph.mAtlasLeft) {
          const Vector3f topLeft = corner(cursor, glyph.mPlaneLeft, glyph.mPlaneTop);
          const Vector3f bottomRight = corner(cursor, glyph.mPlaneRight, glyph.mPlaneBottom);
          const float u0 = (glyph.mAtlasLeft + glyphPageX) * inverseWidth;
          const float u1 = (glyph.mAtlasRight + glyphPageX) * inverseWidth;
          const float v0 = (glyph.mAtlasTop + glyphPageY) * inverseHeight;
          const float v1 = (glyph.mAtlasBottom + glyphPageY) * inverseHeight;
          if (instanced) {
            MsdfUiQuad quad;
            const float xs[4] = {topLeft.x, bottomRight.x, bottomRight.x, topLeft.x};
            const float ys[4] = {topLeft.y, topLeft.y, bottomRight.y, bottomRight.y};
            const float us[4] = {u0, u1, u1, u0};
            const float vs[4] = {v0, v0, v1, v1};
            for (int c = 0; c < 4; ++c) {
              quad.mX[c] = xs[c];
              quad.mY[c] = ys[c];
              quad.mU[c] = us[c];
              quad.mV[c] = vs[c];
              quad.mColor[c] = color;
            }
            quad.mPixelRange = pixelRange;
            quad.mZ = topLeft.z;
            instancedText.AddGlyph(quad);
          } else {
            primBatcher.DrawQuad(
              CD3DPrimBatcher::Vertex{topLeft.x, topLeft.y, topLeft.z, color, u0, v0},
              CD3DPrimBatcher::Vertex{bottomRight.x, topLeft.y, topLeft.z, color, u1, v0},
              CD3DPrimBatcher::Vertex{bottomRight.x, bottomRight.y, topLeft.z, color, u1, v1},
              CD3DPrimBatcher::Vertex{topLeft.x, bottomRight.y, topLeft.z, color, u0, v1}
            );
          }
        }
        cursor.x += advance * textScale;
      }

      if (!instanced) {
        primBatcher.Flush();
        effect->mCurrentTechnique = previousTechnique;
        primBatcher.SetTextureBinding(previousTexture);
      }
      outCursor = cursor;
      return true;
    }

    /**
     * The `sampleWidth` x `sampleHeight` corner of the 32-bit scratch bitmap as GetPixel
     * COLORREFs (0x00BBGGRR); the rest of `out` stays zero, as the GetPixel loop leaves it.
     */
    template <std::size_t N>
    [[nodiscard]] bool ReadGlyphBitmap(
      HBITMAP const bitmap, const int width, const int height, const int sampleWidth, const int sampleHeight,
      std::array<COLORREF, N>& out
    )
    {
      if (bitmap == nullptr || static_cast<std::size_t>(width * height) != N) {
        return false;
      }
      BITMAP info{};
      if (GetObjectW(bitmap, sizeof(info), &info) == 0 || info.bmBitsPixel != 32 || info.bmWidth != width ||
          info.bmHeight != height || info.bmWidthBytes != width * 4) {
        return false;
      }
      (void)GdiFlush(); // DrawTextW may still sit in the GDI batch; GetPixel flushes it implicitly
      std::array<std::uint32_t, N> bits{};
      if (GetBitmapBits(bitmap, static_cast<LONG>(N * sizeof(std::uint32_t)), bits.data()) != static_cast<LONG>(N * sizeof(std::uint32_t))) {
        return false;
      }
      out.fill(0u);
      for (int y = 0; y < sampleHeight; ++y) {
        for (int x = 0; x < sampleWidth; ++x) {
          const std::uint32_t bgrx = bits[static_cast<std::size_t>(y * width + x)]; // bytes B, G, R, X
          out[static_cast<std::size_t>(y * width + x)] = RGB((bgrx >> 16) & 0xFFu, (bgrx >> 8) & 0xFFu, bgrx & 0xFFu);
        }
      }
      return true;
    }

    struct FontLookup
    {
      std::int32_t mPointSize = 0;
      std::string mFace{};
    };

    struct FontLookupLess
    {
      /**
       * Address: 0x004271D0 (FUN_004271D0, Moho::FontInfo::cmp)
       *
       * What it does:
       * Orders font-cache lookup keys by point-size first, then face-name bytes.
       */
      [[nodiscard]] bool operator()(const FontLookup& lhs, const FontLookup& rhs) const noexcept
      {
        if (lhs.mPointSize != rhs.mPointSize) {
          return lhs.mPointSize < rhs.mPointSize;
        }
        return lhs.mFace < rhs.mFace;
      }
    };

    using FontCacheMap = std::map<FontLookup, CD3DFont*, FontLookupLess>;
    struct DxtWordPair
    {
      std::uint32_t mLo = 0;
      std::uint32_t mHi = 0;
    };

    using DxtWordPairVector = std::vector<DxtWordPair>;
    [[nodiscard]] std::pair<FontCacheMap::iterator, bool>
    InsertFontCacheEntryChecked(FontCacheMap& cache, const FontLookup& lookup, CD3DFont* font);
    [[nodiscard]] constexpr std::size_t GetDxtWordPairMaxCount() noexcept;
    [[noreturn]] void ThrowVectorTooLong();

    /**
     * Address: 0x004251C0 (FUN_004251C0)
     *
     * What it does:
     * Builds one font-cache lookup key from point-size and face-name text.
     */
    [[nodiscard]] FontLookup MakeFontLookup(const std::int32_t pointSize, const char* const faceName)
    {
      FontLookup lookup{};
      lookup.mPointSize = pointSize;
      lookup.mFace = (faceName != nullptr) ? faceName : "";
      return lookup;
    }

    /**
     * Address: 0x00426A50 (FUN_00426A50)
     *
     * What it does:
     * Releases one intrusive `CD3DFont` owner lane and clears on last-owner.
     */
    void ReleaseIntrusiveFont(CD3DFont* const font) noexcept
    {
      if (font == nullptr) {
        return;
      }

      --font->mRefCount;
      if (font->mRefCount == 0) {
        font->Release(1);
      }
    }

    /**
     * Address: 0x00425490 (FUN_00425490)
     *
     * What it does:
     * Releases one font-cache entry payload (intrusive CD3DFont reference) and
     * resets the stored pointer lane.
     */
    void ReleaseFontCacheEntry(CD3DFont*& font) noexcept
    {
      ReleaseIntrusiveFont(font);
      font = nullptr;
    }

    /**
     * Address: 0x00427C20 (FUN_00427C20)
     * Address: 0x00428780 (FUN_00428780)
     * Address: 0x00428C00 (FUN_00428C00)
     * Address: 0x00428CC0 (FUN_00428CC0)
     *
     * What it does:
     * Returns the process-static D3D font-cache map singleton.
     */
    [[nodiscard]] FontCacheMap& GetFontCache() noexcept
    {
      static FontCacheMap sD3DFontMap{};
      return sD3DFontMap;
    }

    /**
     * Address: 0x004268F0 (FUN_004268F0)
     *
     * What it does:
     * Returns the end/sentinel iterator for the static font-cache map.
     */
    [[nodiscard]] FontCacheMap::iterator GetFontCacheEnd() noexcept
    {
      return GetFontCache().end();
    }

    /**
     * Address: 0x00427AD0 (FUN_00427AD0)
     *
     * What it does:
     * Returns the map head/sentinel lane represented as `end()`.
     */
    [[nodiscard]] FontCacheMap::iterator GetFontCacheHead() noexcept
    {
      return GetFontCacheEnd();
    }

    /**
     * Address: 0x00426F60 (FUN_00426F60)
     *
     * What it does:
     * Returns the begin/leftmost iterator for the static font-cache map.
     */
    [[nodiscard]] FontCacheMap::iterator GetFontCacheBegin() noexcept
    {
      return GetFontCache().begin();
    }

    /**
     * Address: 0x00427A70 (FUN_00427A70, std::map_FontLookup_CD3DFont::_Lbound)
     *
     * What it does:
     * Returns lower-bound iterator for one font-cache lookup key.
     */
    [[nodiscard]] FontCacheMap::iterator LowerBoundCachedFont(const FontLookup& lookup)
    {
      return GetFontCache().lower_bound(lookup);
    }

    /**
     * Address: 0x004269E0 (FUN_004269E0, std::map_FontLookup_CD3DFont::find)
     *
     * What it does:
     * Performs key lookup in the static font-cache map.
     */
    [[nodiscard]] FontCacheMap::iterator FindCachedFont(const FontLookup& lookup)
    {
      FontCacheMap& cache = GetFontCache();
      const auto lowerBound = LowerBoundCachedFont(lookup);
      if (lowerBound == cache.end()) {
        return lowerBound;
      }

      const FontLookupLess less{};
      if (less(lookup, lowerBound->first) || less(lowerBound->first, lookup)) {
        return cache.end();
      }

      return lowerBound;
    }

    /**
     * Address: 0x00426900 (FUN_00426900)
     *
     * What it does:
     * Inserts one key/value record in the static font-cache map when missing and
     * reports iterator + insertion status.
     */
    [[nodiscard]] std::pair<FontCacheMap::iterator, bool>
    InsertFontCacheEntry(const FontLookup& lookup, CD3DFont* const font)
    {
      FontCacheMap& cache = GetFontCache();
      return InsertFontCacheEntryChecked(cache, lookup, font);
    }

    /**
     * Address: 0x00426F80 (FUN_00426F80)
     *
     * What it does:
     * Inserts one cache record with map-size guard semantics.
     */
    [[nodiscard]] std::pair<FontCacheMap::iterator, bool>
    InsertFontCacheEntryChecked(FontCacheMap& cache, const FontLookup& lookup, CD3DFont* const font)
    {
      constexpr std::size_t kMaxMapSize = 0x071C71C6u;
      if (cache.size() >= kMaxMapSize) {
        throw std::length_error("map/set<T> too long");
      }

      return cache.emplace(lookup, font);
    }

    /**
     * Address: 0x00426CE0 (FUN_00426CE0)
     * Address: 0x00429140 (FUN_00429140)
     * Address: 0x00429500 (FUN_00429500)
     *
     * What it does:
     * Initializes glyph-page storage with 256 page slots.
     */
    void InitializeGlyphPageCache(CD3DFont::SCharInfoPages& pages)
    {
      pages = CD3DFont::SCharInfoPages(256);
    }

    /**
     * Address: 0x004283E0 (FUN_004283E0)
     *
     * What it does:
     * Tail-thunk adapter that forwards one glyph-page cache init lane into
     * `FUN_00429140`.
     */
    [[maybe_unused]] void InitializeGlyphPageCacheThunk(CD3DFont::SCharInfoPages& pages)
    {
      InitializeGlyphPageCache(pages);
    }

    /**
     * Address: 0x00426D70 (FUN_00426D70)
     * Address: 0x004294B0 (FUN_004294B0)
     * Address: 0x004298C0 (FUN_004298C0)
     * Address: 0x00429A20 (FUN_00429A20)
     *
     * What it does:
     * Clears glyph-page storage and releases owned page vectors.
     */
    void DestroyGlyphPageCache(CD3DFont::SCharInfoPages& pages)
    {
      pages = CD3DFont::SCharInfoPages{};
    }

    /**
     * Address: 0x00426C60 (FUN_00426C60)
     *
     * What it does:
     * Returns begin pointer for one kerning-pair vector storage lane.
     */
    [[nodiscard]] CD3DFont::SKerningPair* GetKerningPairsBegin(CD3DFont::KerningPairVector& pairs)
    {
      return pairs.begin();
    }

    /**
     * Address: 0x00426810 (FUN_00426810)
     *
     * What it does:
     * Returns end pointer for one kerning-pair vector storage lane.
     */
    [[nodiscard]] CD3DFont::SKerningPair* GetKerningPairsEnd(CD3DFont::KerningPairVector& pairs)
    {
      return pairs.end();
    }

    /**
     * Address: 0x00426860 (FUN_00426860)
     * Address: 0x00426B50 (FUN_00426B50)
     *
     * What it does:
     * Computes element pointer for one indexed kerning-pair slot.
     */
    [[nodiscard]] CD3DFont::SKerningPair* GetKerningPairAt(CD3DFont::SKerningPair* const begin, const std::size_t index)
    {
      return begin + index;
    }

    /**
     * Address: 0x00426BF0 (FUN_00426BF0)
     *
     * What it does:
     * Computes element pointer for one indexed glyph-info slot.
     */
    [[maybe_unused]] [[nodiscard]] CD3DFont::SCharInfo* GetGlyphInfoAt(CD3DFont::SCharInfo* const begin, const std::size_t index)
    {
      return begin + index;
    }

    /**
     * Address: 0x00427270 (FUN_00427270)
     * Address: 0x00427C90 (FUN_00427C90)
     * Address: 0x00429210 (FUN_00429210)
     * Address: 0x00429670 (FUN_00429670)
     * Address: 0x004298A0 (FUN_004298A0)
     * Address: 0x0042A6F0 (FUN_0042A6F0)
     *
     * What it does:
     * Initializes one kerning-pair buffer to requested count + fill value.
     * The two `resize` addresses (FUN_00426DD0 fill form, FUN_00426820
     * default-fill form) are the `KerningPairVector::resize(n, v)` emission
     * at its two call shapes, cited on `resize` in legacy/containers/Vector.h.
     */
    [[nodiscard]] bool InitKerningPairBuffer(
      const std::size_t count, CD3DFont::KerningPairVector& out, const CD3DFont::SKerningPair& fillValue
    )
    {
      out = CD3DFont::KerningPairVector{};
      if (count == 0u) {
        return false;
      }

      if (count > GetDxtWordPairMaxCount()) {
        ThrowVectorTooLong();
      }

      out.resize(count, fillValue);
      return true;
    }

    /**
     * Address: 0x00426B00 (FUN_00426B00)
     *
     * What it does:
     * Initializes one kerning-pair buffer to requested count with zero fill.
     */
    void InitKerningPairBufferZeroFill(const std::size_t count, CD3DFont::KerningPairVector& out)
    {
      const CD3DFont::SKerningPair fill{};
      (void)InitKerningPairBuffer(count, out, fill);
    }

    /**
     * Address: 0x00427490 (FUN_00427490)
     *
     * What it does:
     * Returns current glyph-entry count for one glyph page.
     */
    [[nodiscard]] std::size_t GetGlyphPageEntryCount(const CD3DFont::SCharInfoPage& page) noexcept
    {
      return page.size();
    }

    /**
     * Address: 0x00427980 (FUN_00427980)
     * Address: 0x00428790 (FUN_00428790)
     * Address: 0x00428900 (FUN_00428900)
     * Address: 0x00428C70 (FUN_00428C70)
     *
     * What it does:
     * Returns the allocator max-count constant for 0x24-byte glyph entries.
     */
    [[nodiscard]] constexpr std::size_t GetGlyphPageMaxCount() noexcept
    {
      return 0x071C71C7u;
    }

    /**
     * Address: 0x004273A0 (FUN_004273A0)
     * Address: 0x00427D80 (FUN_00427D80)
     * Address: 0x00427E70 (FUN_00427E70)
     * Address: 0x00428930 (FUN_00428930)
     * Address: 0x004292A0 (FUN_004292A0)
     * Address: 0x004296B0 (FUN_004296B0)
     * Address: 0x00429780 (FUN_00429780)
     * Address: 0x00429910 (FUN_00429910)
     * Address: 0x00429E90 (FUN_00429E90)
     * Address: 0x0042A710 (FUN_0042A710)
     * Address: 0x0042A960 (FUN_0042A960)
     *
     * What it does:
     * Normalizes one glyph page to exactly 256 entries, appending fill records
     * or trimming trailing records as needed.
     */
    void NormalizeGlyphPageTo256(
      CD3DFont::SCharInfoPage& page, const CD3DFont::SCharInfo& fillValue
    )
    {
      constexpr std::size_t kGlyphEntriesPerPage = 256u;
      if (kGlyphEntriesPerPage > GetGlyphPageMaxCount()) {
        throw std::length_error("vector<T> too long");
      }

      const std::size_t count = GetGlyphPageEntryCount(page);
      if (count < kGlyphEntriesPerPage) {
        page.resize(kGlyphEntriesPerPage, fillValue);
      }
      else if (count > kGlyphEntriesPerPage) {
        page.erase(page.begin() + static_cast<std::ptrdiff_t>(kGlyphEntriesPerPage), page.end());
      }
    }

    /**
     * Address: 0x00426B60 (FUN_00426B60)
     *
     * What it does:
     * Normalizes one glyph page to 256 entries using zero/default glyph fill.
     */
    void NormalizeGlyphPageTo256ZeroFill(CD3DFont::SCharInfoPage& page)
    {
      const CD3DFont::SCharInfo fill{};
      NormalizeGlyphPageTo256(page, fill);
    }

    /**
     * Address: 0x004275F0 (FUN_004275F0)
     * Address: 0x00428C80 (FUN_00428C80)
     * Address: 0x00428430 (FUN_00428430)
     * Address: 0x00428820 (FUN_00428820)
     * Address: 0x00428A10 (FUN_00428A10)
     * Address: 0x00428C40 (FUN_00428C40)
     *
     * What it does:
     * Returns the allocator max-count constant for 8-byte word-pair lanes.
     */
    [[nodiscard]] constexpr std::size_t GetDxtWordPairMaxCount() noexcept
    {
      return 0x1FFFFFFFu;
    }

    /**
     * Address: 0x004278A0 (FUN_004278A0)
     * Address: 0x00428370 (FUN_00428370)
     * Address: 0x00428830 (FUN_00428830)
     * Address: 0x00428960 (FUN_00428960)
     * Address: 0x00428A20 (FUN_00428A20)
     *
     * What it does:
     * Throws the legacy vector length_error used by DXT scratch growth paths.
     */
    [[noreturn]] void ThrowVectorTooLong()
    {
      throw std::length_error("vector<T> too long");
    }

    /**
     * Address: 0x004274B0 (FUN_004274B0)
     * Address: 0x00428220 (FUN_00428220)
     * Address: 0x004292F0 (FUN_004292F0)
     *
     * What it does:
     * Resizes one DXT scratch lane as 8-byte word-pairs with fill pattern.
     */
    void ResizeDxtWordPairScratch(
      const std::size_t count, DxtWordPairVector& scratch, const DxtWordPair& fillValue
    )
    {
      if (count > GetDxtWordPairMaxCount()) {
        ThrowVectorTooLong();
      }
      scratch.assign(count, fillValue);
    }

    /**
     * Address: 0x00426C00 (FUN_00426C00)
     *
     * What it does:
     * Resizes one DXT scratch lane as zero-filled 8-byte word-pairs.
     */
    [[maybe_unused]] void ResizeDxtWordPairScratchZeroFill(const std::size_t count, DxtWordPairVector& scratch)
    {
      const DxtWordPair fill{};
      ResizeDxtWordPairScratch(count, scratch, fill);
    }

    /**
     * Address: 0x00427990 (FUN_00427990)
     * Address: 0x00428440 (FUN_00428440)
     * Address: 0x00428700 (FUN_00428700)
     * Address: 0x00428B80 (FUN_00428B80)
     * Address: 0x00428BC0 (FUN_00428BC0)
     * Address: 0x00428BE0 (FUN_00428BE0)
     *
     * What it does:
     * Releases intrusive font ownership payload for one map iterator range and
     * erases matching cache nodes.
     */
    void ReleaseFontCacheRange(FontCacheMap& cache, FontCacheMap::iterator begin, const FontCacheMap::iterator end)
    {
      if (begin == cache.begin() && end == GetFontCacheHead()) {
        for (auto& [lookup, cachedFont] : cache) {
          (void)lookup;
          ReleaseFontCacheEntry(cachedFont);
        }
        cache.clear();
        return;
      }

      while (begin != end) {
        ReleaseFontCacheEntry(begin->second);
        begin = cache.erase(begin);
      }
    }

    /**
     * Address: 0x00425240 (FUN_00425240)
     *
     * What it does:
     * Clears and tears down the static D3D font-cache map at process shutdown.
     */
    void ShutdownFontCache()
    {
      FontCacheMap& cache = GetFontCache();
      ReleaseFontCacheRange(cache, GetFontCacheBegin(), GetFontCacheHead());
    }

    void RegisterFontCacheTeardown()
    {
      static const bool registered = []() {
        std::atexit(ShutdownFontCache);
        return true;
      }();
      (void)registered;
    }

    [[nodiscard]] boost::SharedPtrRaw<CD3DFont> MakeFontHandle(CD3DFont* const font)
    {
      return boost::SharedPtrRaw<CD3DFont>::with_deleter(font, [](CD3DFont* const ptr) { ReleaseIntrusiveFont(ptr); });
    }

    [[nodiscard]] std::uint32_t PackKerningKey(const CD3DFont::SKerningPair& pair) noexcept
    {
      const auto left = static_cast<std::uint16_t>(pair.mLeft);
      const auto right = static_cast<std::uint16_t>(pair.mRight);
      return static_cast<std::uint32_t>(left) | (static_cast<std::uint32_t>(right) << 16u);
    }

    /**
     * Address: 0x004293B0 (FUN_004293B0)
     * Address: 0x00429AF0 (FUN_00429AF0)
     * Address: 0x00429DA0 (FUN_00429DA0)
     * Address: 0x0042A2A0 (FUN_0042A2A0)
     * Address: 0x0042A3A0 (FUN_0042A3A0)
     * Address: 0x0042A3F0 (FUN_0042A3F0)
     * Address: 0x0042A520 (FUN_0042A520)
     * Address: 0x0042A5E0 (FUN_0042A5E0)
     * Address: 0x0042A7C0 (FUN_0042A7C0)
     * Address: 0x0042A860 (FUN_0042A860)
     *
     * What it does:
     * Orders one kerning-pair lane by packed (left,right) key.
     */
    void SortKerningPairsByPackedKey(CD3DFont::KerningPairVector& pairs)
    {
      std::sort(
        GetKerningPairsBegin(pairs),
        GetKerningPairsEnd(pairs),
        [](const CD3DFont::SKerningPair& lhs, const CD3DFont::SKerningPair& rhs) {
          return PackKerningKey(lhs) < PackKerningKey(rhs);
        }
      );
    }

    /**
     * Address: 0x00429D90 (FUN_00429D90)
     *
     * What it does:
     * Tail-thunk adapter that forwards one kerning-pair sort lane into
     * `FUN_0042A3F0`.
     */
    [[maybe_unused]] void SortKerningPairsByPackedKeyThunk(CD3DFont::KerningPairVector& pairs)
    {
      SortKerningPairsByPackedKey(pairs);
    }

    /**
     * Takes a mod's atlas once it has been cooked: from then on the font has that file's metrics and advances, so
     * what GDI's default font measured is dropped along with its glyphs.
     */
    void PollModFontBinding(CD3DFont& font, MsdfBinding& binding)
    {
      if (!binding.mIsMod || binding.mAtlas) {
        return;
      }
      binding.mAtlas = MSDF_FindAtlas(binding.mFace.c_str());
      if (!binding.mAtlas) {
        return;
      }
      const SMsdfFontAtlas& atlas = *binding.mAtlas;
      const float size = static_cast<float>(binding.mPointSize);
      binding.mStrike = FindMsdfStrike(atlas, binding.mPointSize);
      gpg::Logf(
        "MSDF: %s at %d px drawn from %s", binding.mFace.c_str(), binding.mPointSize,
        binding.mStrike != nullptr ? "its bitmaps" : "its distance field"
      );
      font.mAscent = std::ceil(atlas.mAscent * size);
      font.mDescent = std::ceil(atlas.mDescent * size);
      font.mHeight = font.mAscent + font.mDescent;
      font.mInternalLeading = (std::max)(0.0f, font.mHeight - size);
      font.mExternalLeading = (std::max)(0.0f, std::round(atlas.mLineGap * size));
      MSDF_FlushPendingText();
      DestroyGlyphPageCache(font.mCharInfo);
      InitializeGlyphPageCache(font.mCharInfo);
    }
  } // namespace

  bool CD3DFont::IsModFont() const
  {
    if (!sHasModFonts) {
      return false;
    }
    const auto bound = sMsdfBindings.find(this);
    return bound != sMsdfBindings.end() && bound->second.mIsMod;
  }

  void CD3DFont::PollModFont()
  {
    if (!sHasModFonts) {
      return;
    }
    const auto bound = sMsdfBindings.find(this);
    if (bound != sMsdfBindings.end()) {
      PollModFontBinding(*this, bound->second);
    }
  }

  /**
   * Address: 0x00425290 (FUN_00425290, ?Create@CD3DFont@Moho@@SA?AV?$CountedPtr@VCD3DFont@Moho@@@2@HVStrArg@gpg@@@Z)
   *
   * What it does:
   * Looks up or creates one cached D3D font object for point-size + face-name.
   */
  boost::SharedPtrRaw<CD3DFont> CD3DFont::Create(const std::int32_t pointSize, const gpg::StrArg faceName)
  {
    RegisterFontCacheTeardown();

    const FontLookup lookup = MakeFontLookup(pointSize, faceName);
    const auto existingIt = FindCachedFont(lookup);
    if (existingIt != GetFontCacheEnd()) {
      CD3DFont* const existingFont = existingIt->second;
      if (existingFont != nullptr) {
        ++existingFont->mRefCount;
      }
      return MakeFontHandle(existingFont);
    }

    // A mod's family never reaches GDI; its name means nothing there anyway, and its file was never loaded there.
    const bool isModFace = lookup.mFace.compare(0u, 4u, "mod:") == 0;
    const HFONT createdWin32Font =
      CreateFontA(-pointSize, 0, 0, 0, 0, 0, 0, 0, 1u, 0, 0, 4u, 0, isModFace ? kModFontFallbackFace : lookup.mFace.c_str());
    if (createdWin32Font == nullptr) {
      return {};
    }

    CD3DFont* const createdFont = new (std::nothrow) CD3DFont(createdWin32Font);
    if (createdFont == nullptr) {
      DeleteObject(createdWin32Font);
      return {};
    }

    MsdfBinding binding{};
    binding.mFace = lookup.mFace;
    binding.mPointSize = pointSize;
    binding.mIsMod = isModFace;
    sHasModFonts = sHasModFonts || isModFace;
    sMsdfBindings[createdFont] = std::move(binding);

    ++createdFont->mRefCount; // cache-owned reference
    const auto [insertedIt, inserted] = InsertFontCacheEntry(lookup, createdFont);
    if (!inserted) {
      ReleaseIntrusiveFont(createdFont);
      CD3DFont* const racedFont = insertedIt->second;
      if (racedFont != nullptr) {
        ++racedFont->mRefCount;
      }
      return MakeFontHandle(racedFont);
    }

    ++createdFont->mRefCount; // returned-handle reference
    return MakeFontHandle(createdFont);
  }

  /**
   * Address: 0x00425500 (FUN_00425500, ??0CD3DFont@Moho@@AAE@PAX@Z)
   *
   * What it does:
   * Initializes D3D font metrics, glyph-page cache lanes, and kerning pairs
   * from one Win32 font handle.
   */
  CD3DFont::CD3DFont(const HFONT font)
    : CountedObject()
    , mFont(font)
    , mIsTruetype(false)
    , mPad0D{}
    , mHeight(0.0f)
    , mAscent(0.0f)
    , mDescent(0.0f)
    , mInternalLeading(0.0f)
    , mExternalLeading(0.0f)
    , mAveCharWidth(0.0f)
    , mOverhang(0.0f)
    , mCharInfo()
    , mKerningPairs()
    , mDeviceContext(nullptr)
    , mBitmap(nullptr)
  {
    InitializeGlyphPageCache(mCharInfo);

    mDeviceContext = CreateCompatibleDC(nullptr);
    if (mDeviceContext == nullptr) {
      return;
    }

    mBitmap = CreateBitmap(128, 128, 1u, 0x20u, nullptr);
    SelectObject(mDeviceContext, mBitmap);
    SelectObject(mDeviceContext, mFont);

    TEXTMETRICW metrics{};
    GetTextMetricsW(mDeviceContext, &metrics);

    mHeight = static_cast<float>(metrics.tmHeight);
    mAscent = static_cast<float>(metrics.tmAscent);
    mDescent = static_cast<float>(metrics.tmDescent);
    mInternalLeading = static_cast<float>(metrics.tmInternalLeading);
    mExternalLeading = static_cast<float>(metrics.tmExternalLeading);
    mAveCharWidth = static_cast<float>(metrics.tmAveCharWidth);
    mOverhang = static_cast<float>(metrics.tmOverhang);
    mIsTruetype = (metrics.tmPitchAndFamily & TMPF_TRUETYPE) != 0;

    // Engine addition (ren_GlyphCache): which font this is, for the cached glyphs.
    if (ren_GlyphCache) {
      const std::uint64_t identity = ComputeFontIdentity(mDeviceContext);
      const std::lock_guard<std::mutex> lock(gFontIdentityLock);
      FontIdentities()[this] = identity;
    }

    const int kerningPairCount = GetKerningPairsW(mDeviceContext, 0, nullptr);
    if (kerningPairCount <= 0) {
      return;
    }

    std::vector<KERNINGPAIR> kerningPairs(static_cast<std::size_t>(kerningPairCount));
    GetKerningPairsW(mDeviceContext, static_cast<DWORD>(kerningPairCount), kerningPairs.data());

    InitKerningPairBufferZeroFill(static_cast<std::size_t>(kerningPairCount), mKerningPairs);
    SKerningPair* const kerningPairBegin = GetKerningPairsBegin(mKerningPairs);
    for (std::size_t index = 0; index < kerningPairs.size(); ++index) {
      const KERNINGPAIR& source = kerningPairs[index];
      SKerningPair& dest = *GetKerningPairAt(kerningPairBegin, index);
      dest.mLeft = source.wFirst;
      dest.mRight = source.wSecond;
      dest.mAmount = static_cast<float>(source.iKernAmount);
    }

    SortKerningPairsByPackedKey(mKerningPairs);
  }

  /**
   * Address: 0x00425840 (FUN_00425840, Moho::CD3DFont::dtr)
   *
   * What it does:
   * Executes the scalar-deleting-dtor thunk path used by intrusive release
   * callsites.
   */
  CD3DFont* CD3DFont::Release(const std::int32_t destroyNow)
  {
    this->~CD3DFont();
    if ((destroyNow & 1) != 0) {
      ::operator delete(this);
    }
    return this;
  }

  /**
   * Address: 0x00425860 (FUN_00425860, ??1CD3DFont@Moho@@UAE@XZ)
   *
   * What it does:
   * Releases Win32 font/DC/bitmap resources and tears down glyph + kerning
   * container ownership lanes.
   */
  CD3DFont::~CD3DFont()
  {
    {
      const std::lock_guard<std::mutex> lock(gFontIdentityLock);
      FontIdentities().erase(this);
    }
    sMsdfBindings.erase(this);

    // FUN_004272F0: the member-empty `operator=` release of the kerning vector.
    mKerningPairs = CD3DFont::KerningPairVector{};
    DestroyGlyphPageCache(mCharInfo);

    if (mFont != nullptr) {
      DeleteObject(mFont);
      mFont = nullptr;
    }

    if (mBitmap != nullptr) {
      DeleteObject(mBitmap);
      mBitmap = nullptr;
    }

    if (mDeviceContext != nullptr) {
      DeleteObject(mDeviceContext);
      mDeviceContext = nullptr;
    }
  }

  /**
   * Address: 0x00425940 (FUN_00425940, ?GetCharInfo@CD3DFont@Moho@@QAEABUSCharInfo@12@_W@Z)
   *
   * What it does:
   * Returns cached glyph metrics/texture info for one UTF-16 codepoint,
   * building the glyph page/atlas data on first use.
   */
  const CD3DFont::SCharInfo& CD3DFont::GetCharInfo(const wchar_t chText)
  {
    constexpr int kGlyphScratchWidth = 128;
    constexpr int kGlyphScratchHeight = 128;
    constexpr std::uint32_t kDxtOpaqueColorBlock = 0x000000000000FFFFull;

    const std::uint8_t pageIndex = static_cast<std::uint8_t>((static_cast<std::uint16_t>(chText) >> 8u) & 0xFFu);
    SCharInfoPage& page = mCharInfo[pageIndex];
    if (page.size() != 256u) {
      NormalizeGlyphPageTo256ZeroFill(page);
    }

    SCharInfo& charInfo = page[static_cast<std::uint8_t>(chText & 0xFFu)];
    if (charInfo.mTex || mDeviceContext == nullptr) {
      return charInfo;
    }

    // Engine addition (ren_GlyphCache): the glyph an earlier launch rasterized; the session's first
    // one is rasterized below as well and compared.
    std::uint64_t glyphKey = 0;
    bool verifyCached = false;
    SCachedGlyph cachedGlyph;
    if (ren_GlyphCache) {
      std::uint64_t fontIdentity = 0;
      {
        const std::lock_guard<std::mutex> lock(gFontIdentityLock);
        const auto found = FontIdentities().find(this);
        if (found != FontIdentities().end()) {
          fontIdentity = found->second;
        }
      }
      if (fontIdentity != 0) {
        glyphKey = GlyphKey(fontIdentity, chText);
        if (const SCachedGlyph* const cached = GlyphCache().Find(glyphKey); cached != nullptr) {
          if (gGlyphCacheVerified.load(std::memory_order_relaxed)) {
            charInfo.mTex = CD3DBatchTexture::FromDXT5(
              cached->mBlockWidth, cached->mBlockHeight, cached->mBlocks.data(), 16u * (cached->mBlockWidth / 4u)
            );
            charInfo.mV2 = cached->mV2;
            charInfo.mV3 = cached->mV3;
            charInfo.mV4 = cached->mV4;
            charInfo.mV5 = cached->mV5;
            charInfo.mAdvance = cached->mAdvance;
            return charInfo;
          }
          verifyCached = true;
          cachedGlyph = *cached;
        }
      }
    }

    (void)SetTextAlign(mDeviceContext, 0x18u);
    const int baselineAscent = static_cast<int>(std::ceil(mAscent + 1.0f));
    const int baselineDescent = static_cast<int>(std::ceil(mDescent));

    RECT textRect{};
    (void)DrawTextW(mDeviceContext, &chText, 1, &textRect, 0xC20u);
    float advance = static_cast<float>(textRect.right - textRect.left);

    // Engine addition (issue #304): a mod's font, once its atlas is here, has its own advances and small bitmaps.
    const SMsdfStrike* modStrike = nullptr;
    const SMsdfStrikeGlyph* modStrikeGlyph = nullptr;
    if (sHasModFonts) {
      const auto bound = sMsdfBindings.find(this);
      if (bound != sMsdfBindings.end() && bound->second.mIsMod && bound->second.mAtlas) {
        const MsdfBinding& binding = bound->second;
        const SMsdfGlyph* const glyph = binding.mNoPage ? nullptr : FindMsdfGlyph(*binding.mAtlas, static_cast<std::uint32_t>(chText));
        if (glyph != nullptr) {
          advance = glyph->mAdvance * static_cast<float>(binding.mPointSize);
        }
        modStrike = binding.mStrike;
        modStrikeGlyph = modStrike != nullptr ? FindMsdfStrikeGlyph(*modStrike, static_cast<std::uint32_t>(chText)) : nullptr;
        if (modStrikeGlyph != nullptr) {
          advance = modStrikeGlyph->mAdvance;
        }
      }
    }

    int glyphWidth = (static_cast<int>((mAveCharWidth * 2.0f) + advance) + 3) & ~3;
    int glyphHeight = (baselineAscent + baselineDescent + 4) & ~3;
    const int baselineX = static_cast<int>(mAveCharWidth);

    if (glyphWidth > kGlyphScratchWidth) {
      gpg::Warnf("Clamping character u+%04x to MAX_CHAR_WIDTH", static_cast<unsigned int>(chText));
      glyphWidth = kGlyphScratchWidth;
    }
    if (glyphHeight > kGlyphScratchHeight) {
      gpg::Warnf("Clamping character u+%04x to MAX_CHAR_HEIGHT", static_cast<unsigned int>(chText));
      glyphHeight = kGlyphScratchHeight;
    }

    RECT clearRect{};
    clearRect.right = glyphWidth + 4;
    clearRect.bottom = glyphHeight + 4;
    (void)FillRect(mDeviceContext, &clearRect, static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
    (void)SetBkColor(mDeviceContext, RGB(0, 0, 0));
    (void)SetTextColor(mDeviceContext, RGB(255, 255, 255));

    RECT drawRect{};
    drawRect.left = baselineX;
    drawRect.right = baselineX;
    drawRect.top = baselineAscent;
    drawRect.bottom = baselineAscent;
    (void)DrawTextW(mDeviceContext, &chText, 1, &drawRect, 0x920u);

    std::array<COLORREF, static_cast<std::size_t>(kGlyphScratchWidth * kGlyphScratchHeight)> pixels{};
    const int sampleWidth = (std::min)(glyphWidth + 4, kGlyphScratchWidth);
    const int sampleHeight = (std::min)(glyphHeight + 4, kGlyphScratchHeight);
    const auto readWithGetPixel = [&](std::array<COLORREF, static_cast<std::size_t>(kGlyphScratchWidth * kGlyphScratchHeight)>& out) {
      for (int y = 0; y < sampleHeight; ++y) {
        for (int x = 0; x < sampleWidth; ++x) {
          out[static_cast<std::size_t>(y * kGlyphScratchWidth + x)] = GetPixel(mDeviceContext, x, y);
        }
      }
    };
    if (ren_GlyphBitmapRead && ReadGlyphBitmap(mBitmap, kGlyphScratchWidth, kGlyphScratchHeight, sampleWidth, sampleHeight, pixels)) {
      // Engine addition (ren_GlyphBitmapRead): the whole 128x128 scratch bitmap in one call, instead
      // of the binary's GetPixel per pixel (0x00425BC7), one kernel call each: 70 ms in a zoom frame
      // that met new characters. The first glyph of the session is read both ways; any difference
      // turns the fast read off for good.
      static bool sChecked = false;
      if (!sChecked) {
        sChecked = true;
        std::array<COLORREF, static_cast<std::size_t>(kGlyphScratchWidth * kGlyphScratchHeight)> reference{};
        readWithGetPixel(reference);
        if (reference != pixels) {
          gpg::Warnf("CD3DFont: the glyph bitmap read differs from GetPixel; reading glyphs with GetPixel from now on");
          ren_GlyphBitmapRead = false;
          pixels = reference;
        }
      }
    } else {
      readWithGetPixel(pixels);
    }

    if (modStrikeGlyph != nullptr) {
      // The rest of this function only sees pixels, so a mod's bitmap takes GDI's place here and every
      // renderer draws it the way it draws any glyph.
      pixels.fill(0u);
      const std::uint8_t* const coverage = modStrike->mCoverage.data() + modStrikeGlyph->mOffset;
      for (int row = 0; row < modStrikeGlyph->mHeight; ++row) {
        const int y = baselineAscent - modStrikeGlyph->mTop + row;
        for (int column = 0; column < modStrikeGlyph->mWidth; ++column) {
          const int x = baselineX + modStrikeGlyph->mLeft + column;
          if (x >= 0 && x < sampleWidth && y >= 0 && y < sampleHeight) {
            const std::uint8_t value = coverage[static_cast<std::size_t>(row) * static_cast<std::size_t>(modStrikeGlyph->mWidth) + static_cast<std::size_t>(column)];
            pixels[static_cast<std::size_t>(y * kGlyphScratchWidth + x)] = RGB(value, value, value);
          }
        }
      }
    }

    auto isColumnBlack = [&pixels](const int x, const int yMin, const int yMaxExclusive) noexcept {
      for (int y = yMin; y < yMaxExclusive; ++y) {
        if (pixels[static_cast<std::size_t>(y * kGlyphScratchWidth + x)] != 0u) {
          return false;
        }
      }
      return true;
    };
    auto isRowBlack = [&pixels](const int y, const int xMin, const int xMaxExclusive) noexcept {
      for (int x = xMin; x < xMaxExclusive; ++x) {
        if (pixels[static_cast<std::size_t>(y * kGlyphScratchWidth + x)] != 0u) {
          return false;
        }
      }
      return true;
    };

    if (!isRowBlack(0, 0, glyphWidth)) {
      gpg::Warnf("Top edge of character u+%04x is not black!", static_cast<unsigned int>(chText));
    }
    if (!isColumnBlack(0, 0, glyphHeight)) {
      gpg::Warnf("Left edge of character u+%04x is not black!", static_cast<unsigned int>(chText));
    }
    {
      const int rightEdgeX = (std::min)(glyphWidth + 1, kGlyphScratchWidth - 1);
      if (!isColumnBlack(rightEdgeX, 0, glyphHeight)) {
        gpg::Warnf("Right edge of character u+%04x is not black!", static_cast<unsigned int>(chText));
      }
    }
    {
      const int bottomEdgeY = (std::min)(glyphHeight, kGlyphScratchHeight - 1);
      if (!isRowBlack(bottomEdgeY, 0, glyphWidth)) {
        gpg::Warnf("Bottom edge of character u+%04x is not black!", static_cast<unsigned int>(chText));
      }
    }

    int xMin = 0;
    for (int x = 1; x < glyphWidth; ++x) {
      if (isColumnBlack(x, 0, glyphHeight)) {
        ++xMin;
      } else {
        break;
      }
    }

    // The scanned column trails the running bound by two. Ground truth seats
    // the column pointer at `base + 4*(glyphWidth - 2)` (0x00425D32, against
    // the pixel base `var_10014` established at 0x00425BA1) while the bound
    // itself starts at `glyphWidth` (0x00425B8F, `var_10050 = ebx`), and
    // 0x00425D63..0x00425D69 decrements the two in lockstep. So the bound
    // settles at `lastInkColumn + 2`, not at `lastInkColumn`.
    //
    // Scanning at the bound instead - what this did before - burns two extra
    // iterations on the black padding and lands two columns short. After the
    // round-up to a 4-pixel DXT block that is frequently a whole block, which
    // is what cropped the right edge off glyphs ('P' as 'F', 'U' as 'L', '1'
    // as its bare top flag).
    int xMaxExclusive = glyphWidth;
    while (xMaxExclusive > 1) {
      const int sampleX = (std::min)(xMaxExclusive - 2, kGlyphScratchWidth - 1);
      if (sampleX < 0 || !isColumnBlack(sampleX, 0, glyphHeight)) {
        break;
      }
      --xMaxExclusive;
    }
    if (xMaxExclusive <= xMin) {
      xMaxExclusive = xMin + 1;
    }

    int blockWidth = (xMaxExclusive - xMin + 3) & ~3;
    if (blockWidth <= 0) {
      blockWidth = 4;
      xMin = 0;
    }
    if (xMin + blockWidth > kGlyphScratchWidth) {
      blockWidth = ((kGlyphScratchWidth - xMin) & ~3);
      if (blockWidth <= 0) {
        xMin = 0;
        blockWidth = kGlyphScratchWidth & ~3;
      }
    }

    // Same trailing-by-two shape as the column trim above: 0x00425DD5 seats the
    // row at `glyphHeight - 2` (`lea esi, [ecx-2]`) while the bound starts at
    // `glyphHeight` (0x00425B97, `var_10048 = edi`), and they decrement
    // together at 0x00425E14..0x00425E1A.
    int yMin = 0;
    int yMaxExclusive = glyphHeight;
    while (yMaxExclusive > 1) {
      const int sampleY = yMaxExclusive - 2;
      if (sampleY < 0 || !isRowBlack(sampleY, xMin, xMin + blockWidth)) {
        break;
      }
      --yMaxExclusive;
    }
    while ((yMin + 1) < yMaxExclusive) {
      if (!isRowBlack(yMin + 1, xMin, xMin + blockWidth)) {
        break;
      }
      ++yMin;
    }

    int blockHeight = (yMaxExclusive - yMin + 3) & ~3;
    if (blockHeight <= 0) {
      blockHeight = 4;
      yMin = 0;
    }
    if (yMin + blockHeight > kGlyphScratchHeight) {
      blockHeight = ((kGlyphScratchHeight - yMin) & ~3);
      if (blockHeight <= 0) {
        yMin = 0;
        blockHeight = kGlyphScratchHeight & ~3;
      }
    }

    const std::uint32_t blockCount = static_cast<std::uint32_t>((blockWidth / 4) * (blockHeight / 4));
    std::vector<std::uint64_t> dxt5Blocks;
    dxt5Blocks.reserve(static_cast<std::size_t>(blockCount) * 2u);

    for (int y = yMin; y < (yMin + blockHeight); y += 4) {
      for (int x = xMin; x < (xMin + blockWidth); x += 4) {
        const auto* const source = reinterpret_cast<const std::uint8_t*>(
          &pixels[static_cast<std::size_t>(y * kGlyphScratchWidth + x)]
        );
        dxt5Blocks.push_back(DXT_EncodeAlphaBlock(source, static_cast<int>(sizeof(COLORREF)), kGlyphScratchWidth * 4));
        dxt5Blocks.push_back(kDxtOpaqueColorBlock);
      }
    }

    const std::uint32_t sourcePitchBytes = static_cast<std::uint32_t>(16u * (static_cast<std::uint32_t>(blockWidth) / 4u));
    charInfo.mTex = CD3DBatchTexture::FromDXT5(
      static_cast<std::uint32_t>(blockWidth),
      static_cast<std::uint32_t>(blockHeight),
      dxt5Blocks.data(),
      sourcePitchBytes
    );

    charInfo.mV2 = static_cast<float>(xMin - baselineX);
    charInfo.mV3 = static_cast<float>(baselineAscent - (yMin + blockHeight));
    charInfo.mV4 = static_cast<float>((xMin + blockWidth) - baselineX);
    charInfo.mV5 = static_cast<float>(baselineAscent - yMin);
    charInfo.mAdvance = advance;

    if (glyphKey != 0 && ren_GlyphCache) {
      SCachedGlyph rasterized;
      rasterized.mBlockWidth = static_cast<std::uint16_t>(blockWidth);
      rasterized.mBlockHeight = static_cast<std::uint16_t>(blockHeight);
      rasterized.mV2 = charInfo.mV2;
      rasterized.mV3 = charInfo.mV3;
      rasterized.mV4 = charInfo.mV4;
      rasterized.mV5 = charInfo.mV5;
      rasterized.mAdvance = charInfo.mAdvance;
      rasterized.mBlocks = std::move(dxt5Blocks);
      if (verifyCached) {
        if (rasterized == cachedGlyph) {
          gGlyphCacheVerified = true;
        } else {
          gpg::Warnf("CD3DFont: a cached glyph (u+%04x) differs from its rasterization; glyphs are rasterized from now on",
                     static_cast<unsigned int>(chText));
          ren_GlyphCache = false;
          GlyphCache().Drop();
        }
      } else {
        GlyphCache().Add(glyphKey, std::move(rasterized));
      }
    }
    return charInfo;
  }

  /**
   * Address: 0x00426470 (FUN_00426470, ?Render@CD3DFont@Moho@@QAE?AV?$Vector3@M@Wm3@@VStrArg@gpg@@PAVCD3DPrimBatcher@2@ABV34@22IMM@Z)
   *
   * What it does:
   * Draws one UTF-8 string along caller-provided axis vectors and returns the
   * final pen position.
   */
  Vector3f CD3DFont::Render(
    const gpg::StrArg text,
    CD3DPrimBatcher* const primBatcher,
    const Vector3f& origin,
    const Vector3f& xAxis,
    const Vector3f& yAxis,
    const std::uint32_t color,
    const float glyphScale,
    const float maxAdvance
  )
  {
    PollModFont();
    Vector3f cursor = origin;
    if ((ren_MsdfText || IsModFont()) && RenderMsdfText(*this, text, *primBatcher, origin, xAxis, yAxis, color, maxAdvance, cursor)) {
      return cursor;
    }

    float totalAdvance = 0.0f;

    wchar_t codepoint = 0;
    const char* encoded = gpg::STR_DecodeUtf8Char(text, codepoint);
    while (codepoint != 0) {
      const SCharInfo& charInfo = GetCharInfo(codepoint);
      totalAdvance += charInfo.mAdvance;
      if (std::isfinite(maxAdvance) && totalAdvance > maxAdvance) {
        break;
      }

      primBatcher->DrawChar(xAxis, yAxis, charInfo, cursor, color);

      cursor.x += xAxis.x * charInfo.mAdvance;
      cursor.y += xAxis.y * charInfo.mAdvance;
      cursor.z += xAxis.z * charInfo.mAdvance;

      encoded = gpg::STR_DecodeUtf8Char(encoded, codepoint);
    }

    (void)glyphScale;
    return cursor;
  }

  /**
   * Address: 0x00426580 (FUN_00426580, ?Render2D@CD3DFont@Moho@@QAEXVStrArg@gpg@@PAVCD3DPrimBatcher@2@ABV?$Vector2@M@Wm3@@IMM@Z)
   *
   * What it does:
   * Projects one 2D text draw into 3D render space and dispatches to
   * `Render(...)` with screen-space axes.
   */
  void CD3DFont::Render2D(
    const gpg::StrArg text,
    CD3DPrimBatcher* const primBatcher,
    const Wm3::Vector2f& origin,
    const std::uint32_t color,
    const float glyphScale,
    const float /*maxAdvance*/
  )
  {
    const Vector3f origin3D{origin.x, origin.y, 0.0f};
    const Vector3f xAxis{1.0f, 0.0f, 0.0f};
    const Vector3f yAxis{0.0f, -1.0f, 0.0f};
    (void)Render(
      text,
      primBatcher,
      origin3D,
      xAxis,
      yAxis,
      color,
      glyphScale,
      gpg::NaN
    );
  }

  /**
   * Address: 0x00426610 (FUN_00426610, ?GetAdvance@CD3DFont@Moho@@QAEMVStrArg@gpg@@H@Z)
   *
   * What it does:
   * Returns cumulative glyph advance for one UTF-8 string.
   */
  float CD3DFont::GetAdvance(const gpg::StrArg text, const std::int32_t /*flags*/)
  {
    PollModFont();
    float advance = 0.0f;
    wchar_t codepoint = 0;
    const char* encoded = gpg::STR_DecodeUtf8Char(text, codepoint);
    while (codepoint != 0) {
      advance += GetCharInfo(codepoint).mAdvance;
      encoded = gpg::STR_DecodeUtf8Char(encoded, codepoint);
    }
    return advance;
  }

  /**
   * Address: 0x00426680 (FUN_00426680, ?GetNearestCharacterIndex@CD3DFont@Moho@@QAEHVStrArg@gpg@@M@Z)
   *
   * What it does:
   * Returns the UTF-8 character index closest to the caller-provided advance.
   */
  std::int32_t CD3DFont::GetNearestCharacterIndex(const gpg::StrArg text, const float targetAdvance)
  {
    std::int32_t index = 0;
    float cumulativeAdvance = 0.0f;

    wchar_t codepoint = 0;
    const char* encoded = gpg::STR_DecodeUtf8Char(text, codepoint);
    while (codepoint != 0) {
      cumulativeAdvance += GetCharInfo(codepoint).mAdvance;
      if (cumulativeAdvance > targetAdvance) {
        break;
      }

      ++index;
      encoded = gpg::STR_DecodeUtf8Char(encoded, codepoint);
    }
    return index;
  }

  void REN_SaveGlyphCache(const bool now)
  {
    if (ren_GlyphCache) {
      GlyphCache().SaveIfIdle(now);
    }
  }

  /**
   * Address: 0x00BC3C50 (FUN_00BC3C50, register_sD3DFontMap)
   *
   * What it does:
   * Materializes the process D3D font-cache map during startup.
   */
  void RegisterD3DFontCacheMapStartup()
  {
    (void)GetFontCache();
  }
} // namespace moho

namespace
{
  struct CD3DFontStartupRegistrations
  {
    CD3DFontStartupRegistrations()
    {
      moho::RegisterD3DFontCacheMapStartup();
    }
  };

  [[maybe_unused]] CD3DFontStartupRegistrations gCD3DFontStartupRegistrations;
} // namespace
