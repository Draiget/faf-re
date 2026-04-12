// libpng 1.2.x common runtime recovery.
// Source: embedded wxWindows 2.4.2 libpng (dependencies/wxWindows-2.4.2/src/png/png.c).
// The ForgedAlliance.exe binary links libpng statically; these functions match
// the binary at their given addresses.

#include "libpng/PngCommonRuntime.h"

#include <array>

namespace {

// The canonical 8-byte PNG file signature: 89 50 4E 47 0D 0A 1A 0A.
// In libpng 1.2.x this lives as a file-static array in png.c (png_sig).
constexpr std::array<std::uint8_t, 8> kPngFileSignature = {
  0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
};

// View into the CRC / flags / chunk_name triad inside png_struct, accessed via
// typed offsets to avoid exposing the full (large) libpng layout here.
// Field offsets verified from FUN_009E0526.asm.
struct PngStructCrcChunkView
{
  std::uint32_t flags;       // +0x6C in full png_struct
  std::uint32_t crc;         // +0x110
  std::uint8_t  chunk_name[4]; // +0x11C, byte 0 carries ancillary bit
};

// Offsets within the full png_struct that this view maps to.
constexpr std::size_t kPngStructFlagsOffset     = 0x6C;
constexpr std::size_t kPngStructCrcOffset       = 0x110;
constexpr std::size_t kPngStructChunkNameOffset = 0x11C;

// Access helpers that read/write the triad without leaving raw offset math in
// behavior code. These are localized to this translation unit so the typed
// access surface is the only thing callers see.
[[nodiscard]] std::uint32_t& PngStructFlags(png_structp png_ptr) noexcept
{
  return *reinterpret_cast<std::uint32_t*>(
    reinterpret_cast<std::uint8_t*>(png_ptr) + kPngStructFlagsOffset);
}

[[nodiscard]] std::uint32_t& PngStructCrc(png_structp png_ptr) noexcept
{
  return *reinterpret_cast<std::uint32_t*>(
    reinterpret_cast<std::uint8_t*>(png_ptr) + kPngStructCrcOffset);
}

[[nodiscard]] const std::uint8_t* PngStructChunkName(png_structp png_ptr) noexcept
{
  return reinterpret_cast<const std::uint8_t*>(png_ptr) + kPngStructChunkNameOffset;
}

} // namespace

/**
 * Address: 0x009E0401 (FUN_009E0401)
 * Mangled: png_sig_cmp
 */
extern "C" int png_sig_cmp(
  const std::uint8_t* sig,
  std::uint32_t       start,
  std::uint32_t       num_to_check)
{
  // Clamp num_to_check into the 8-byte window; if start is past the signature,
  // treat as a match (libpng 1.2.x behavior).
  std::uint32_t effective = num_to_check;
  if (num_to_check <= 8)
  {
    if (num_to_check == 0)
      return 0;
  }
  else
  {
    effective = 8;
  }

  if (start > 7)
    return 0;

  if (start + effective > 8)
    effective = 8 - start;

  return png_memcmp(sig + start, &kPngFileSignature[start], effective);
}

/**
 * Address: 0x009E050E (FUN_009E050E)
 * Mangled: png_reset_crc
 */
extern "C" png_uint_32 png_reset_crc(png_structp png_ptr)
{
  const auto fresh = static_cast<png_uint_32>(crc32(0, nullptr, 0));
  PngStructCrc(png_ptr) = fresh;
  return fresh;
}

/**
 * Address: 0x009E0526 (FUN_009E0526)
 * Mangled: png_calculate_crc
 */
extern "C" void png_calculate_crc(
  png_structp png_ptr,
  png_bytep   ptr,
  png_size_t  length)
{
  const std::uint8_t  chunk_first = PngStructChunkName(png_ptr)[0];
  const std::uint32_t flags       = PngStructFlags(png_ptr);

  // Chunk is ancillary when bit 5 of the first name byte is set.
  const bool is_ancillary = (chunk_first & kPngChunkAncillaryBit) != 0;

  if (is_ancillary)
  {
    // Skip CRC when both ancillary-use and ancillary-nowarn are set
    // (PNG_FLAG_CRC_ANCILLARY_USE | PNG_FLAG_CRC_ANCILLARY_NOWARN).
    if ((flags & kPngFlagCrcAncillaryMask) == kPngFlagCrcAncillaryMask)
      return;
  }
  else
  {
    // Critical chunk: skip CRC when PNG_FLAG_CRC_CRITICAL_IGNORE is set.
    if ((flags & kPngFlagCrcCriticalIgnore) != 0)
      return;
  }

  auto& crc_field = PngStructCrc(png_ptr);
  crc_field = static_cast<png_uint_32>(
    crc32(crc_field, ptr, static_cast<unsigned int>(length)));
}
