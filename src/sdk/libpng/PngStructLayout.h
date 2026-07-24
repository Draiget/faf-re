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
constexpr std::size_t kOffZlibMethod        = 0xB8;   // int         zlib_method
constexpr std::size_t kOffZlibWindowBits    = 0xBC;   // int         zlib_window_bits
constexpr std::size_t kOffZstream           = 0x74;   // z_stream    zstream
constexpr std::size_t kOffZstreamNextIn     = 0x74;   // z_stream.next_in
constexpr std::size_t kOffZstreamAvailIn    = 0x78;   // z_stream.avail_in
constexpr std::size_t kOffZstreamNextOut    = 0x80;   // z_stream.next_out
constexpr std::size_t kOffZstreamAvailOut   = 0x84;   // z_stream.avail_out
constexpr std::size_t kOffZstreamMsg        = 0x8C;   // z_stream.msg (const char*)
constexpr std::size_t kOffZstreamZalloc     = 0x94;   // z_stream.zalloc
constexpr std::size_t kOffZstreamZfree      = 0x98;   // z_stream.zfree
constexpr std::size_t kOffZstreamOpaque     = 0x9C;   // z_stream.opaque

constexpr std::size_t kOffSigBytes          = 0x110;  // png_byte    sig_bytes (also crc field per common runtime)
constexpr std::size_t kOffCrc               = 0x110;  // png_uint_32 crc (running CRC; overlaps sig_bytes slot)
constexpr std::size_t kOffChunkName         = 0x11C;  // png_byte    chunk_name[4]
constexpr std::size_t kOffReadUserChunkFn   = 0x21C;  // png_user_chunk_ptr read_user_chunk_fn
constexpr std::size_t kOffNumChunkList      = 0x220;  // png_uint_32 num_chunk_list
constexpr std::size_t kOffChunkList         = 0x224;  // png_bytep   chunk_list

// png_struct image-dimension lane, offsets confirmed from png_handle_IHDR
// (width/height stores) and png_read_finish_row (num_rows/rowbytes/iwidth/
// irowbytes/row_number pass-advance) .asm. The prior kOffWidth/kOffHeight/
// kOffNumRows/kOffRowbytes values were transposed across this run of fields.
constexpr std::size_t kOffWidth             = 0xC8;   // png_uint_32 width       (set by png_handle_IHDR)
constexpr std::size_t kOffHeight            = 0xCC;   // png_uint_32 height      (set by png_handle_IHDR)
constexpr std::size_t kOffNumRows           = 0xD0;   // png_uint_32 num_rows    (rows in current pass)
constexpr std::size_t kOffRowbytes          = 0xD8;   // png_uint_32 rowbytes    (bytes in a full row)
constexpr std::size_t kOffIrowbytes         = 0xDC;   // png_uint_32 irowbytes   (bytes in current interlaced row)
constexpr std::size_t kOffIwidth            = 0xE0;   // png_uint_32 iwidth      (pixels in current interlaced row)
constexpr std::size_t kOffRowNumber         = 0xE4;   // png_uint_32 row_number  (current row within the pass)
constexpr std::size_t kOffPrevRow           = 0xE8;   // png_bytep   prev_row
constexpr std::size_t kOffRowBuf            = 0xEC;   // png_bytep   row_buf (points 32 bytes into big_row_buf)
constexpr std::size_t kOffIdatSize          = 0x10C;  // png_uint_32 idat_size   (bytes left in current IDAT chunk)
constexpr std::size_t kOffUserTransformDepth    = 0x64;   // png_byte user_transform_depth
constexpr std::size_t kOffUserTransformChannels = 0x65;   // png_byte user_transform_channels
constexpr std::size_t kOffNumPalette        = 0x118;  // png_uint_16 num_palette (PLTE entry count)
constexpr std::size_t kOffNumTrans          = 0x11A;  // png_uint_16 num_trans (tRNS entry count)
constexpr std::size_t kOffBigRowBuf         = 0x250;  // png_bytep   big_row_buf (allocated row buffer base)

constexpr std::size_t kOffBitDepth          = 0x127;  // png_byte bit_depth (offset 295)
constexpr std::size_t kOffColorType         = 0x126;  // png_byte color_type (offset 294)
constexpr std::size_t kOffPixelDepth        = 0x129;  // png_byte pixel_depth (offset 297) = channels*bit_depth, set by png_handle_IHDR
constexpr std::size_t kOffChannels          = 0x12A;  // png_byte channels    (offset 298) = 1/2/3/4, set by png_handle_IHDR
constexpr std::size_t kOffUsrChannels       = 0x12B;  // png_byte usr_channels (offset 299)
constexpr std::size_t kOffUsrBitDepth       = 0x128;  // png_byte usr_bit_depth(offset 296)
constexpr std::size_t kOffInterlaced        = 0x123;  // png_byte interlaced (offset 291)
constexpr std::size_t kOffPass              = 0x124;  // png_byte pass       (offset 292)
constexpr std::size_t kOffFiller            = 0x12E;  // png_uint_16 filler  (offset 302)
constexpr std::size_t kOffShift             = 0x181;  // png_color_8 shift   (offset 385, 5 bytes)

// read-transform dispatcher fields (png_do_read_transformations, FUN_009E711B);
// offsets confirmed from the leaf-call push order in FUN_009E711B.asm.
constexpr std::size_t kOffReadUserTransformFn = 0x58;  // png_user_transform_ptr read_user_transform_fn
constexpr std::size_t kOffWriteDataFn       = 0x4C;   // png_rw_ptr write_data_fn (output callback)
constexpr std::size_t kOffRowInfoRowbytes   = 0x104;  // row_info.rowbytes mirror (dither ==0 check)
constexpr std::size_t kOffRowInfoColorType  = 0x108;  // row_info.color_type mirror (expand check)
constexpr std::size_t kOffTrans             = 0x188;  // png_bytep    trans (tRNS alpha array; 4th arg @0x9E717C)
constexpr std::size_t kOffBackgroundGammaType = 0x130; // int         background_gamma_type (read as byte @0x9E68DE)
constexpr std::size_t kOffBackgroundGamma   = 0x134;  // float        background_gamma (lea @0x9E6942)
constexpr std::size_t kOffBackground        = 0x138;  // png_color_16 background (10 bytes)
constexpr std::size_t kOffBackground1       = 0x142;  // png_color_16 background_1 (10 bytes)
constexpr std::size_t kOffGammaShift        = 0x158;  // png_byte     gamma_shift (written by png_build_gamma_table)
constexpr std::size_t kOffGamma             = 0x15C;  // float        gamma (image-file gamma; fcomp dword @0x9E6050)
constexpr std::size_t kOffScreenGamma       = 0x160;  // float        screen_gamma (fld dword @0x9E6072)
constexpr std::size_t kOffGammaTable        = 0x164;  // png_bytep    gamma_table
constexpr std::size_t kOffGammaFrom1        = 0x168;  // png_bytep    gamma_from_1 (store @0x9E617A)
constexpr std::size_t kOffGammaTo1          = 0x16C;  // png_bytep    gamma_to_1   (store @0x9E611B)
constexpr std::size_t kOffGamma16Table      = 0x170;  // png_uint_16pp gamma_16_table
constexpr std::size_t kOffGamma16From1      = 0x174;  // png_uint_16pp gamma_16_from_1 (store @0x9E6596)
constexpr std::size_t kOffGamma16To1        = 0x178;  // png_uint_16pp gamma_16_to_1   (store @0x9E64AF)
constexpr std::size_t kOffSigBitRed         = 0x17C;  // png_byte     sig_bit.red   (png_color_8)
constexpr std::size_t kOffSigBitGreen       = 0x17D;  // png_byte     sig_bit.green
constexpr std::size_t kOffSigBitBlue        = 0x17E;  // png_byte     sig_bit.blue
constexpr std::size_t kOffSigBitGray        = 0x17F;  // png_byte     sig_bit.gray
constexpr std::size_t kOffPalette           = 0x114;  // png_colorp   palette (before num_palette@0x118; 3rd arg @0x9E7188)
constexpr std::size_t kOffTransValues       = 0x18C;  // png_color_16 trans_values
constexpr std::size_t kOffPaletteLookup     = 0x1EC;  // png_bytep    palette_lookup (dither)
constexpr std::size_t kOffDitherIndex       = 0x1F0;  // png_bytep    dither_index (dither lookup)
constexpr std::size_t kOffRgbToGrayStatus   = 0x228;  // png_byte     rgb_to_gray_status

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
[[nodiscard]] inline int& ZlibMethod(png_structp p) noexcept                { return Field<int>(p, kOffZlibMethod); }
[[nodiscard]] inline int& ZlibWindowBits(png_structp p) noexcept            { return Field<int>(p, kOffZlibWindowBits); }

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
constexpr std::uint32_t kPngFlagZlibCustomWindowBits = 0x0008;
constexpr std::uint32_t kPngFlagZlibCustomMethod = 0x0010;

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
