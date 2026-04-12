#pragma once

#include <cstddef>
#include <cstdint>

#include "libpng/PngWriteRuntime.h"

// ============================================================================
// Minimal partial views of libpng 1.2.x png_struct used by recovered runtime
// helpers that read/write individual fields.
// ============================================================================
//
// The full png_struct layout lives in the bundled wxWindows 2.4.2 copy of
// libpng (dependencies/wxWindows-2.4.2/src/png/png.h). To avoid pulling the
// full layout into recovered code, we isolate each field group behind a
// small named view and access it via a typed accessor. No raw pointer
// arithmetic escapes into behavior code.
//
// Field offsets are taken directly from the binary evidence cited next to
// each view.

namespace libpng_detail {

// --------------------------------------------------------------------------
// png_struct::io_ptr (user IO state pointer)
//
// Evidence: png_get_io_ptr (0x009E09AA)
//   mov eax, [eax+54h]
// --------------------------------------------------------------------------
constexpr std::size_t kPngStructIoPtrOffset = 0x54;

[[nodiscard]] inline void* GetIoPtr(png_structp png_ptr) noexcept
{
  auto* base = reinterpret_cast<std::uint8_t*>(png_ptr);
  return *reinterpret_cast<void* const*>(base + kPngStructIoPtrOffset);
}

// --------------------------------------------------------------------------
// png_struct::{num_chunk_list, chunk_list} — unknown-chunk keep table.
//
// libpng 1.2.x stores a user-supplied "keep" directive list as an array of
// 5-byte records: 4 bytes of chunk name followed by a 1-byte keep value
// (PNG_HANDLE_CHUNK_AS_DEFAULT / ALWAYS / IF_SAFE / NEVER).
//
// Evidence:
//   png_info_destroy        (0x009E0959)  lea edi, [ebx+220h]; lea esi, [ebx+224h]
//   png_handle_as_unknown   (0x009E0A5E)  lea eax, [ecx+220h]; mov ecx, [ecx+224h]
// --------------------------------------------------------------------------
constexpr std::size_t kPngStructNumChunkListOffset = 0x220;
constexpr std::size_t kPngStructChunkListOffset    = 0x224;
constexpr std::size_t kPngChunkListRecordSize      = 5;
constexpr std::size_t kPngChunkListNameSize        = 4;

struct PngChunkListView
{
  std::uint32_t&  num;
  std::uint8_t*&  entries;
};

[[nodiscard]] inline PngChunkListView GetChunkList(png_structp png_ptr) noexcept
{
  auto* base = reinterpret_cast<std::uint8_t*>(png_ptr);
  return PngChunkListView{
    *reinterpret_cast<std::uint32_t*>(base + kPngStructNumChunkListOffset),
    *reinterpret_cast<std::uint8_t**>(base + kPngStructChunkListOffset),
  };
}

// --------------------------------------------------------------------------
// png_struct::{asm_flags, mmx_bitdepth_threshold, mmx_rowbytes_threshold}.
//
// These MMX assembly dispatch flags exist in libpng 1.2.x builds with
// PNG_ASSEMBLER_CODE_SUPPORTED. The zero-initializer helper
// png_init_mmx_flags writes only the low byte of asm_flags, the single-byte
// mmx_bitdepth_threshold, and the 32-bit mmx_rowbytes_threshold.
//
// Evidence: png_init_mmx_flags (0x009E0ACC)
//   mov  [eax+23Ch], ecx   ; mmx_rowbytes_threshold (dword)
//   mov  [eax+239h], cl    ; mmx_bitdepth_threshold (byte)
//   mov  [eax+240h], cl    ; asm_flags              (byte)
// --------------------------------------------------------------------------
constexpr std::size_t kPngStructMmxBitdepthThresholdOffset = 0x239;
constexpr std::size_t kPngStructMmxRowbytesThresholdOffset = 0x23C;
constexpr std::size_t kPngStructAsmFlagsOffset             = 0x240;

inline void ClearMmxAndAsmFlags(png_structp png_ptr) noexcept
{
  auto* base = reinterpret_cast<std::uint8_t*>(png_ptr);
  *reinterpret_cast<std::uint32_t*>(base + kPngStructMmxRowbytesThresholdOffset) = 0;
  *(base + kPngStructMmxBitdepthThresholdOffset) = 0;
  *(base + kPngStructAsmFlagsOffset)             = 0;
}

// --------------------------------------------------------------------------
// png_struct gamma + rgb_to_gray fields used by transform helpers.
//
// Evidence:
//   png_do_rgb_to_gray (0x009E424D)
//     mov  eax, [a1+158h]            ; gamma_shift  (uint16)
//     mov  eax, [a1+168h]            ; gamma_to_1   (png_bytep)
//     mov  eax, [a1+16Ch]            ; gamma_from_1 (png_bytep)
//     mov  eax, [a1+174h]            ; gamma_16_to_1   (png_uint_16pp)
//     mov  eax, [a1+178h]            ; gamma_16_from_1 (png_uint_16pp)
//     mov  ax,  [a1+22Ah]            ; rgb_to_gray_red_coeff   (uint16)
//     mov  ax,  [a1+22Ch]            ; rgb_to_gray_green_coeff (uint16)
//     mov  ax,  [a1+22Eh]            ; rgb_to_gray_blue_coeff  (uint16)
// --------------------------------------------------------------------------
constexpr std::size_t kPngStructGammaShiftOffset       = 0x158;
constexpr std::size_t kPngStructGammaTo1Offset         = 0x168;
constexpr std::size_t kPngStructGammaFrom1Offset       = 0x16C;
constexpr std::size_t kPngStructGamma16To1Offset       = 0x174;
constexpr std::size_t kPngStructGamma16From1Offset     = 0x178;
constexpr std::size_t kPngStructRgbToGrayRedCoeffOff   = 0x22A;
constexpr std::size_t kPngStructRgbToGrayGreenCoeffOff = 0x22C;
constexpr std::size_t kPngStructRgbToGrayBlueCoeffOff  = 0x22E;

struct PngRgbToGrayContext
{
  std::uint16_t                  red_coeff;
  std::uint16_t                  green_coeff;
  std::uint16_t                  blue_coeff;
  const std::uint8_t*            gamma_to_1;
  const std::uint8_t*            gamma_from_1;
  const std::uint16_t* const*    gamma_16_to_1;
  const std::uint16_t* const*    gamma_16_from_1;
  std::uint16_t                  gamma_shift;
};

[[nodiscard]] inline PngRgbToGrayContext GetRgbToGrayContext(png_structp png_ptr) noexcept
{
  auto* base = reinterpret_cast<std::uint8_t*>(png_ptr);
  return PngRgbToGrayContext{
    *reinterpret_cast<std::uint16_t*>(base + kPngStructRgbToGrayRedCoeffOff),
    *reinterpret_cast<std::uint16_t*>(base + kPngStructRgbToGrayGreenCoeffOff),
    *reinterpret_cast<std::uint16_t*>(base + kPngStructRgbToGrayBlueCoeffOff),
    *reinterpret_cast<const std::uint8_t* const*>(base + kPngStructGammaTo1Offset),
    *reinterpret_cast<const std::uint8_t* const*>(base + kPngStructGammaFrom1Offset),
    *reinterpret_cast<const std::uint16_t* const* const*>(base + kPngStructGamma16To1Offset),
    *reinterpret_cast<const std::uint16_t* const* const*>(base + kPngStructGamma16From1Offset),
    *reinterpret_cast<std::uint16_t*>(base + kPngStructGammaShiftOffset),
  };
}

} // namespace libpng_detail
