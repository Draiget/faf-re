// libpng info-struct lifecycle runtime recovery.
// Source: embedded wxWindows 2.4.2 libpng (dependencies/wxWindows-2.4.2/src/png/png.c).
// The ForgedAlliance.exe binary links libpng statically as png.lib; these
// recovered functions match the binary at their given addresses.

#include <cstring>

#include "libpng/PngInfoRuntime.h"
#include "libpng/PngSetRuntime.h"   // png_info_struct field layout
#include "libpng/PngStructRuntime.h"

namespace {

struct PngInfoRowLayoutRuntimeView
{
  std::uint8_t pad00_5F[0x60]{};
  std::uint32_t rowbytes = 0;  // +0x60
  std::uint8_t channels = 0;   // +0x64
  std::uint8_t pixelDepth = 0; // +0x65
};

static_assert(offsetof(PngInfoRowLayoutRuntimeView, rowbytes) == 0x60,
              "PngInfoRowLayoutRuntimeView::rowbytes offset must be 0x60");
static_assert(offsetof(PngInfoRowLayoutRuntimeView, channels) == 0x64,
              "PngInfoRowLayoutRuntimeView::channels offset must be 0x64");
static_assert(offsetof(PngInfoRowLayoutRuntimeView, pixelDepth) == 0x65,
              "PngInfoRowLayoutRuntimeView::pixelDepth offset must be 0x65");

} // namespace

/**
 * Address: 0x009E0567 (FUN_009E0567)
 *
 * IDA signature:
 * void __cdecl png_info_init_3(png_infopp ptr_ptr, png_size_t png_info_struct_size);
 *
 * What it does:
 * Reinitialises a png_info pointer in place. If the caller-supplied struct
 * size is smaller than the real 0x120-byte png_info layout (version skew
 * guard), frees the existing struct and allocates a fresh one via the libpng
 * allocator before zeroing. Otherwise zeroes the existing struct in place.
 */
extern "C" void png_info_init_3(png_infopp ptr_ptr, png_size_t png_info_struct_size)
{
  auto* info_ptr = reinterpret_cast<void*>(*ptr_ptr);

  if (png_info_struct_size < kPngInfoStructSize) {
    // Version-skew path: caller's png_info_struct is smaller than this
    // libpng build expects. Replace it with a fresh one.
    png_destroy_struct(info_ptr);
    info_ptr = png_create_struct(kPngStructInfo);
    *ptr_ptr = reinterpret_cast<png_info_struct*>(info_ptr);
  }

  std::memset(info_ptr, 0, kPngInfoStructSize);
}

/**
 * Address: 0x009E0959 (FUN_009E0959)
 *
 * IDA signature:
 * void __cdecl png_info_destroy(png_structp png_ptr, png_infop info_ptr);
 *
 * What it does:
 * Releases all dynamically-allocated sub-resources owned by a png_info struct
 * via png_free_data(..., PNG_FREE_ALL, -1), releases the png_ptr-owned
 * unknown-chunk-keep list when present, and finally reinitialises the info
 * struct in place through png_info_init_3.
 */
extern "C" void png_info_destroy(png_structp png_ptr, png_infop info_ptr)
{
  constexpr std::uint32_t kPngFreeAll = 0x7FFF;

  png_free_data(png_ptr, info_ptr, kPngFreeAll, -1);

  auto chunk_list = libpng_detail::GetChunkList(png_ptr);
  if (chunk_list.num != 0) {
    png_free(png_ptr, chunk_list.entries);
    chunk_list.entries = nullptr;
    chunk_list.num     = 0;
  }

  png_info_init_3(&info_ptr, kPngInfoStructSize);
}

/**
 * Address: 0x009E25E3 (FUN_009E25E3)
 *
 * IDA signature:
 * png_uint_32 __cdecl png_get_valid(png_structp png_ptr, png_infop info_ptr, png_uint_32 flag);
 *
 * What it does:
 * Returns the bits of `flag` that are set in info_ptr->valid (bitmask of which
 * optional PNG chunks have been read or supplied). Returns 0 if either pointer
 * is null. The png_struct argument is required by the libpng API but not
 * dereferenced — only its presence acts as a guard.
 */
extern "C" std::uint32_t png_get_valid(png_structp png_ptr, png_infop info_ptr, std::uint32_t flag)
{
  if (png_ptr == nullptr || info_ptr == nullptr) {
    return 0;
  }
  // info_ptr->valid is a uint32_t at +0x08 (see PngSetRuntime.h layout view).
  return flag & info_ptr->valid;
}

/**
 * Address: 0x009E25C1 (FUN_009E25C1)
 *
 * IDA signature:
 * int __cdecl sub_9E25C1(int a1, int a2, char a3, char a4);
 *
 * What it does:
 * Stores rowbytes/channels/pixel-depth lanes in one png_info payload.
 */
extern "C" void png_info_set_row_layout_runtime(
  png_infop const info_ptr,
  const std::uint32_t rowbytes,
  const std::uint8_t channels,
  const std::uint8_t pixel_depth)
{
  auto* const info = reinterpret_cast<PngInfoRowLayoutRuntimeView*>(info_ptr);
  info->rowbytes = rowbytes;
  info->channels = channels;
  info->pixelDepth = pixel_depth;
}

/**
 * Address: 0x009E25DB (FUN_009E25DB)
 *
 * IDA signature:
 * int __cdecl sub_9E25DB(int a1);
 *
 * What it does:
 * Returns one png_info rowbytes lane (`+0x60`).
 */
extern "C" std::uint32_t png_info_get_rowbytes_runtime(png_infop info_ptr)
{
  const auto* const info = reinterpret_cast<const PngInfoRowLayoutRuntimeView*>(info_ptr);
  return info->rowbytes;
}
