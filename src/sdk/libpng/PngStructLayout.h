#pragma once

// ============================================================================
// libpng 1.2.x png_struct partial typed layout
// ============================================================================
//
// This header centralises the named, offset-checked typed views of the libpng
// png_struct fields used by the recovered libpng runtime in src/sdk/libpng/**.
//
// The full png_struct layout in libpng 1.2.5 is 608 bytes (0x260) — verified
// by the FUN_009E1C4A.asm trailer (`memset(arr, 0, 608)` in png_read_destroy).
// Rather than reconstruct every byte of the struct, we expose only the fields
// that recovered behaviour code reads or writes, all behind named accessors.
// This avoids `*(BYTE*)(p + 0xNN)` arithmetic at the call sites while keeping
// the binary layout faithful.
//
// Field offsets are quoted alongside each accessor; primary evidence comes
// from the .asm files in decomp/recovery/disasm/fa_full_2026_03_26 for the
// libpng functions in the 0x009E* range.

#include <cstddef>
#include <cstdint>

#include "libpng/PngWriteRuntime.h"  // png_structp opaque forward declaration

namespace libpng_layout {

// libpng 1.2.x png_struct total size (bytes).
constexpr std::size_t kPngStructSize = 608;

// ----------------------------------------------------------------------------
// Field offset table
// ----------------------------------------------------------------------------
// All offsets verified from FUN_009E1383.asm (png_read_row),
// FUN_009E1C4A.asm (png_read_destroy), FUN_009E0E93.asm (png_read_info),
// FUN_009E1856.asm (png_read_end), FUN_009E0B6E.asm (png_create_read_struct_2)
// and the listed set_* leaves.

constexpr std::size_t kOffJmpBuf            = 0x00;   // jmp_buf (first 64 bytes used by setjmp)

constexpr std::size_t kOffMode              = 0x68;   // png_uint_32 mode
constexpr std::size_t kOffFlags             = 0x6C;   // png_uint_32 flags
constexpr std::size_t kOffTransformations   = 0x70;   // png_uint_32 transformations
constexpr std::size_t kOffZbuf              = 0xAC;   // png_bytep   zbuf
constexpr std::size_t kOffZbufSize          = 0xB0;   // png_size_t  zbuf_size
constexpr std::size_t kOffZstream           = 0x74;   // z_stream    zstream
constexpr std::size_t kOffZstreamNextOut    = 0x80;   // z_stream.next_out
constexpr std::size_t kOffZstreamAvailOut   = 0x84;   // z_stream.avail_out
constexpr std::size_t kOffZstreamZalloc     = 0x94;   // z_stream.zalloc
constexpr std::size_t kOffZstreamZfree      = 0x98;   // z_stream.zfree
constexpr std::size_t kOffZstreamOpaque     = 0x9C;   // z_stream.opaque

constexpr std::size_t kOffSigBytes          = 0x110;  // png_byte    sig_bytes (also crc field per common runtime)
constexpr std::size_t kOffChunkName         = 0x11C;  // png_byte    chunk_name[4]
constexpr std::size_t kOffNumChunkList      = 0x220;  // png_uint_32 num_chunk_list
constexpr std::size_t kOffChunkList         = 0x224;  // png_bytep   chunk_list

constexpr std::size_t kOffWidth             = 0xDC;   // png_uint_32 width
constexpr std::size_t kOffHeight            = 0xE0;   // png_uint_32 height
constexpr std::size_t kOffNumRows           = 0xCC;   // png_uint_32 num_rows
constexpr std::size_t kOffRowbytes          = 0xE4;   // png_uint_32 rowbytes / usr field

constexpr std::size_t kOffBitDepth          = 0x127;  // png_byte bit_depth (offset 295)
constexpr std::size_t kOffColorType         = 0x126;  // png_byte color_type (offset 294)
constexpr std::size_t kOffChannels          = 0x129;  // png_byte channels   (offset 297)
constexpr std::size_t kOffPixelDepth        = 0x12A;  // png_byte pixel_depth(offset 298)
constexpr std::size_t kOffUsrChannels       = 0x12B;  // png_byte usr_channels (offset 299)
constexpr std::size_t kOffUsrBitDepth       = 0x128;  // png_byte usr_bit_depth(offset 296)
constexpr std::size_t kOffInterlaced        = 0x123;  // png_byte interlaced (offset 291)
constexpr std::size_t kOffPass              = 0x124;  // png_byte pass       (offset 292)
constexpr std::size_t kOffFiller            = 0x12E;  // png_uint_16 filler  (offset 302)
constexpr std::size_t kOffShift             = 0x181;  // png_color_8 shift   (offset 385, 5 bytes)

// ----------------------------------------------------------------------------
// Typed accessors
// ----------------------------------------------------------------------------

[[nodiscard]] inline std::uint8_t* RawBase(png_structp png_ptr) noexcept
{
  return reinterpret_cast<std::uint8_t*>(png_ptr);
}

template <typename T>
[[nodiscard]] inline T& Field(png_structp png_ptr, std::size_t off) noexcept
{
  return *reinterpret_cast<T*>(RawBase(png_ptr) + off);
}

[[nodiscard]] inline std::uint32_t& Mode(png_structp p) noexcept            { return Field<std::uint32_t>(p, kOffMode); }
[[nodiscard]] inline std::uint32_t& Flags(png_structp p) noexcept           { return Field<std::uint32_t>(p, kOffFlags); }
[[nodiscard]] inline std::uint32_t& Transformations(png_structp p) noexcept { return Field<std::uint32_t>(p, kOffTransformations); }

[[nodiscard]] inline std::uint8_t&  BitDepth(png_structp p) noexcept    { return *(RawBase(p) + kOffBitDepth); }
[[nodiscard]] inline std::uint8_t&  ColorType(png_structp p) noexcept   { return *(RawBase(p) + kOffColorType); }
[[nodiscard]] inline std::uint8_t&  Interlaced(png_structp p) noexcept  { return *(RawBase(p) + kOffInterlaced); }
[[nodiscard]] inline std::uint8_t&  Pass(png_structp p) noexcept        { return *(RawBase(p) + kOffPass); }
[[nodiscard]] inline std::uint8_t&  UsrBitDepth(png_structp p) noexcept { return *(RawBase(p) + kOffUsrBitDepth); }
[[nodiscard]] inline std::uint8_t&  UsrChannels(png_structp p) noexcept { return *(RawBase(p) + kOffUsrChannels); }
[[nodiscard]] inline std::uint16_t& Filler(png_structp p) noexcept      { return Field<std::uint16_t>(p, kOffFiller); }

[[nodiscard]] inline std::uint32_t& NumRows(png_structp p) noexcept     { return Field<std::uint32_t>(p, kOffNumRows); }

// ----------------------------------------------------------------------------
// libpng transformation flag constants used by recovered helpers
// ----------------------------------------------------------------------------
constexpr std::uint32_t kPngBgr            = 0x0001;
constexpr std::uint32_t kPngInterlace      = 0x0002;
constexpr std::uint32_t kPngPack           = 0x0004;
constexpr std::uint32_t kPngShift          = 0x0008;
constexpr std::uint32_t kPngFiller         = 0x8000;
constexpr std::uint32_t kPngPackSwap       = 0x10000;
constexpr std::uint32_t kPngSwapAlpha      = 0x20000;
constexpr std::uint32_t kPngInvertAlpha    = 0x80000;
constexpr std::uint32_t kPngInvertMono     = 0x0020;
constexpr std::uint32_t kPngSwapBytes      = 0x0010;

// png_set_filler "flags" extra bit (PNG_FILLER_BEFORE flag stored at offset 0x6C+0x80 in
// the binary's flag word; recovered binary uses bit 0x80 in field at offset 108 (0x6C)).
constexpr std::uint32_t kPngFlagFillerBefore = 0x80;

// png_set_filler third argument: 1 == PNG_FILLER_BEFORE, 0 == PNG_FILLER_AFTER.
constexpr int kPngFillerBefore = 1;

// libpng color types we test against:
constexpr std::uint8_t kColorTypeGray      = 0;
constexpr std::uint8_t kColorTypeRgb       = 2;
constexpr std::uint8_t kColorTypePalette   = 3;
constexpr std::uint8_t kColorTypeGrayAlpha = 4;
constexpr std::uint8_t kColorTypeRgbAlpha  = 6;

} // namespace libpng_layout
