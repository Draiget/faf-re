// libpng 1.2.x memory / zlib allocator runtime recovery.
// Source: embedded wxWindows 2.4.2 libpng (dependencies/wxWindows-2.4.2/src/png/pngmem.c).

#include "libpng/PngMemRuntime.h"
#include "libpng/PngCommonRuntime.h"  // kPngFlagMallocNullMemOk + flag offset

#include <cstring>

namespace {

// Access the flags field inside png_struct without leaking raw offset math into
// the behavior body. Offset verified from FUN_009E0494.asm (mov ebx, [edi+6Ch]).
constexpr std::size_t kPngStructFlagsOffset = 0x6C;

[[nodiscard]] std::uint32_t& PngStructFlags(png_structp png_ptr) noexcept
{
  return *reinterpret_cast<std::uint32_t*>(
    reinterpret_cast<std::uint8_t*>(png_ptr) + kPngStructFlagsOffset);
}

// libpng's legacy memset chunking threshold (16-bit near-memset ceiling).
// Binary evidence: FUN_009E0494 splits the zero-fill at 0x8000 bytes.
constexpr std::uint32_t kPngMemsetChunkSize = 0x8000;

} // namespace

/**
 * Address: 0x009E0494 (FUN_009E0494)
 * Mangled: png_zalloc
 */
extern "C" void* png_zalloc(
  png_structp   png_ptr,
  std::uint32_t items,
  std::uint32_t size)
{
  const std::uint32_t total = items * size;

  auto& flags_field = PngStructFlags(png_ptr);
  const std::uint32_t saved_flags = flags_field;

  // Temporarily allow png_malloc to return NULL without longjmp'ing out.
  flags_field = saved_flags | kPngFlagMallocNullMemOk;
  void* const block = png_malloc(png_ptr, total);
  flags_field = saved_flags;

  if (block == nullptr)
    return nullptr;

  // Zero-fill in up to two chunks to mirror the binary's 0x8000-byte split.
  auto* const bytes = static_cast<std::uint8_t*>(block);
  if (total <= kPngMemsetChunkSize)
  {
    std::memset(bytes, 0, total);
  }
  else
  {
    std::memset(bytes, 0, kPngMemsetChunkSize);
    std::memset(bytes + kPngMemsetChunkSize, 0, total - kPngMemsetChunkSize);
  }

  return block;
}

/**
 * Address: 0x009E0509 (FUN_009E0509)
 * Mangled: png_zfree
 *
 * libpng 1.2.x implements png_zfree as a thin wrapper that discards the first
 * argument (a voidpf opaque, here the png_structp) and forwards to png_free.
 * The binary emits this as a tail-call thunk to png_free.
 */
extern "C" void png_zfree(png_structp png_ptr, void* ptr)
{
  png_free(png_ptr, ptr);
}
