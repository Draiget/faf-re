// libpng 1.2.x memory / zlib allocator runtime recovery.
// Source: embedded wxWindows 2.4.2 libpng (dependencies/wxWindows-2.4.2/src/png/pngmem.c).

#include "libpng/PngMemRuntime.h"
#include "libpng/PngCommonRuntime.h"  // kPngFlagMallocNullMemOk + flag offset

#include <cstdlib>
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

// png_struct::free_fn — user-supplied free callback (PNG_USER_MEM_SUPPORTED).
// Offset verified from FUN_00A2113B.asm (mov eax, [ecx+24Ch]).
constexpr std::size_t kPngStructFreeFnOffset = 0x24C;
using PngFreeFn = void (*)(png_structp, void*);

[[nodiscard]] PngFreeFn PngStructFreeFn(png_structp png_ptr) noexcept
{
  return *reinterpret_cast<PngFreeFn*>(
    reinterpret_cast<std::uint8_t*>(png_ptr) + kPngStructFreeFnOffset);
}

// png_struct::mem_ptr — user-supplied opaque handed to the mem callbacks.
// Offset verified from FUN_00A20F69.asm / FUN_00A20FDC.asm: the mem_ptr field
// sits at [ebp-0x20] within the 0x264-byte stack dummy => struct offset 0x244.
constexpr std::size_t kPngStructMemPtrOffset = 0x244;

[[nodiscard]] void*& PngStructMemPtr(png_structp png_ptr) noexcept
{
  return *reinterpret_cast<void**>(
    reinterpret_cast<std::uint8_t*>(png_ptr) + kPngStructMemPtrOffset);
}

// png_struct::malloc_fn — user-supplied malloc callback.
// Offset verified from FUN_00A21094.asm (mov [eax+248h], ecx).
constexpr std::size_t kPngStructMallocFnOffset = 0x248;

// png_create_struct/destroy allocation sizes + type selectors.
// Verified from FUN_00A20F69.asm: type 2 (PNG_STRUCT_INFO) => 0x120 bytes,
// type 1 (PNG_STRUCT_PNG) => 0x260 bytes.
using PngMallocFn = void* (*)(png_structp, std::uint32_t);
constexpr int          kPngStructPngType    = 1;
constexpr int          kPngStructInfoType   = 2;
constexpr std::uint32_t kPngSizeofPngStruct  = 0x260;
constexpr std::uint32_t kPngSizeofInfoStruct = 0x120;

[[nodiscard]] PngMallocFn PngStructMallocFn(png_structp png_ptr) noexcept
{
  return *reinterpret_cast<PngMallocFn*>(
    reinterpret_cast<std::uint8_t*>(png_ptr) + kPngStructMallocFnOffset);
}

/**
 * Address: 0x00A21022 (FUN_00A21022)
 * Mangled: png_malloc_default
 *
 * IDA signature:
 * png_voidp __cdecl png_malloc_default(png_structp png_ptr, png_uint_32 size);
 *
 * libpng's default allocator body, reached from png_malloc when no user
 * malloc_fn is installed. This build carries no DOS/OS2 16-bit far-heap
 * segment workaround (PNG_MAX_MALLOC_64K is unset for the Win32 target), so
 * it reduces to the CRT allocator plus the standard out-of-memory diagnostic,
 * suppressed when PNG_FLAG_MALLOC_NULL_MEM_OK is set (e.g. png_zalloc
 * temporarily tolerating a NULL return while zlib probes an allocation size).
 */
void* png_malloc_default(png_structp png_ptr, std::uint32_t size)
{
  void* const block = std::malloc(size);
  if (block == nullptr && (PngStructFlags(png_ptr) & kPngFlagMallocNullMemOk) == 0) {
    png_error(png_ptr, "Out of Memory");
  }
  return block;
}

/**
 * Address: 0x00A21051 (FUN_00A21051)
 * Mangled: png_free_default
 *
 * IDA signature:
 * void __cdecl png_free_default(png_structp png_ptr, void* ptr);
 *
 * libpng's default free path. In this build the 16-bit far-heap offset_table
 * bookkeeping is compiled out, so it reduces to handing ptr back to the CRT.
 */
void png_free_default(png_structp png_ptr, void* ptr)
{
  if (png_ptr == nullptr || ptr == nullptr) {
    return;
  }
  std::free(ptr);
}

} // namespace

/**
 * Address: 0x00A2113B (FUN_00A2113B)
 * Mangled: png_free
 *
 * IDA signature:
 * void __cdecl png_free(png_structp png_ptr, void* ptr);
 *
 * libpng free entry point. No-op on a null png_ptr or ptr. Dispatches to the
 * user free callback (png_ptr->free_fn, +0x24C) when one is installed, otherwise
 * falls back to png_free_default (the CRT free path).
 */
extern "C" void png_free(png_structp png_ptr, void* ptr)
{
  if (png_ptr == nullptr || ptr == nullptr) {
    return;
  }
  if (const PngFreeFn free_fn = PngStructFreeFn(png_ptr)) {
    free_fn(png_ptr, ptr);
  } else {
    png_free_default(png_ptr, ptr);
  }
}

/**
 * Address: 0x00A210E4 (FUN_00A210E4)
 * Mangled: png_malloc
 *
 * IDA signature:
 * png_voidp __cdecl png_malloc(png_structp png_ptr, png_uint_32 size);
 *
 * libpng malloc entry point. No-op (returns null) on a null png_ptr or a
 * zero size. Dispatches to the user malloc callback (png_ptr->malloc_fn,
 * +0x248) when one is installed -- raising the standard out-of-memory error
 * unless PNG_FLAG_MALLOC_NULL_MEM_OK is set -- otherwise falls back to
 * png_malloc_default (the CRT malloc path).
 */
extern "C" void* png_malloc(png_structp png_ptr, std::uint32_t size)
{
  if (png_ptr == nullptr || size == 0) {
    return nullptr;
  }
  if (const PngMallocFn malloc_fn = PngStructMallocFn(png_ptr)) {
    void* const block = malloc_fn(png_ptr, size);
    if (block == nullptr && (PngStructFlags(png_ptr) & kPngFlagMallocNullMemOk) == 0) {
      png_error(png_ptr, "Out of Memory!");
    }
    return block;
  }
  return png_malloc_default(png_ptr, size);
}

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

/**
 * Address: 0x00A20F69 (FUN_00A20F69)
 * Mangled: png_create_struct_2
 *
 * IDA signature:
 * png_voidp __cdecl png_create_struct_2(int type, png_malloc_ptr malloc_fn, png_voidp mem_ptr);
 *
 * Allocates and zero-fills a raw png_struct (type 1, 0x260 bytes) or
 * png_info_struct (type 2, 0x120 bytes). When a user malloc callback is
 * supplied it is invoked with a stack dummy png_struct carrying mem_ptr;
 * otherwise the CRT malloc is used. An unknown type returns null. Matching the
 * binary, only the dummy's mem_ptr field is set before the callback (the rest
 * is left as-is) and the returned buffer is the one that gets zero-filled.
 */
extern "C" void* png_create_struct_2(int type, PngMallocFn malloc_fn, void* mem_ptr)
{
  std::uint32_t size;
  if (type == kPngStructInfoType) {
    size = kPngSizeofInfoStruct;
  } else if (type == kPngStructPngType) {
    size = kPngSizeofPngStruct;
  } else {
    return nullptr;
  }

  void* struct_ptr;
  if (malloc_fn != nullptr) {
    std::uint8_t dummy_struct[kPngSizeofPngStruct];
    PngStructMemPtr(reinterpret_cast<png_structp>(dummy_struct)) = mem_ptr;
    struct_ptr = malloc_fn(reinterpret_cast<png_structp>(dummy_struct), size);
  } else {
    struct_ptr = std::malloc(size);
  }

  if (struct_ptr != nullptr) {
    std::memset(struct_ptr, 0, size);
  }
  return struct_ptr;
}

/**
 * Address: 0x00A210C2 (FUN_00A210C2)
 * Mangled: png_create_struct
 *
 * IDA signature:
 * png_voidp __cdecl png_create_struct(int type);
 *
 * Thin wrapper: allocates a zero-filled png_struct/png_info of the given type
 * via the CRT allocator (no user malloc callback).
 */
extern "C" void* png_create_struct(int type)
{
  return png_create_struct_2(type, nullptr, nullptr);
}

/**
 * Address: 0x00A20FDC (FUN_00A20FDC)
 * Mangled: png_destroy_struct_2
 *
 * IDA signature:
 * void __cdecl png_destroy_struct_2(png_voidp struct_ptr, png_free_ptr free_fn, png_voidp mem_ptr);
 *
 * Frees a png_struct/png_info. When a user free callback is supplied it is
 * invoked with a stack dummy png_struct carrying mem_ptr; otherwise the CRT
 * free is used. A null struct_ptr is a no-op.
 */
extern "C" void png_destroy_struct_2(void* struct_ptr, PngFreeFn free_fn, void* mem_ptr)
{
  if (struct_ptr == nullptr) {
    return;
  }
  if (free_fn != nullptr) {
    std::uint8_t dummy_struct[kPngSizeofPngStruct];
    PngStructMemPtr(reinterpret_cast<png_structp>(dummy_struct)) = mem_ptr;
    free_fn(reinterpret_cast<png_structp>(dummy_struct), struct_ptr);
  } else {
    std::free(struct_ptr);
  }
}

/**
 * Address: 0x00A210D3 (FUN_00A210D3)
 * Mangled: png_destroy_struct
 *
 * IDA signature:
 * void __cdecl png_destroy_struct(png_voidp struct_ptr);
 *
 * Thin wrapper: frees a png_struct/png_info via the CRT allocator (no user free
 * callback).
 */
extern "C" void png_destroy_struct(void* struct_ptr)
{
  png_destroy_struct_2(struct_ptr, nullptr, nullptr);
}

/**
 * Address: 0x00A21094 (FUN_00A21094)
 * Mangled: png_set_mem_fn
 *
 * IDA signature:
 * void __cdecl png_set_mem_fn(png_structp png_ptr, png_voidp mem_ptr,
 *                             png_malloc_ptr malloc_fn, png_free_ptr free_fn);
 *
 * Installs the user memory callbacks (mem_ptr@0x244, malloc_fn@0x248,
 * free_fn@0x24C) on the png_struct.
 */
extern "C" void png_set_mem_fn(png_structp png_ptr, void* mem_ptr,
                               PngMallocFn malloc_fn, PngFreeFn free_fn)
{
  auto* const base = reinterpret_cast<std::uint8_t*>(png_ptr);
  PngStructMemPtr(png_ptr) = mem_ptr;
  *reinterpret_cast<PngMallocFn*>(base + kPngStructMallocFnOffset) = malloc_fn;
  *reinterpret_cast<PngFreeFn*>(base + kPngStructFreeFnOffset)     = free_fn;
}
