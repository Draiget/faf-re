// libpng read-side runtime recovery.
// Source: embedded wxWindows 2.4.2 libpng (dependencies/wxWindows-2.4.2/src/png/png.c,
// pngget.c, pngread.c). The ForgedAlliance.exe binary links libpng statically as
// png.lib; these recovered functions match the binary at their given addresses.

#include "libpng/PngReadRuntime.h"
#include "libpng/PngInfoRuntime.h"
#include "libpng/PngMemRuntime.h"
#include "libpng/PngSetRuntime.h"
#include "libpng/PngStructLayout.h"
#include "libpng/PngStructRuntime.h"

#include <cstdio>
#include <csetjmp>
#include <cstdlib>
#include <cstring>

// ----------------------------------------------------------------------------
// Externally-linked libpng implementation symbols
// ----------------------------------------------------------------------------
//
// These functions live in the embedded wxWindows libpng object code that
// ForgedAlliance.exe statically links against. The recovered helpers below
// dispatch to them by name; the linker resolves the symbol against the
// existing png.lib build, and the recovered code never carries an address
// trampoline.

extern "C" {

void* png_create_struct_2(int type, void* (*malloc_fn)(png_structp, std::uint32_t), void* mem_ptr);
void  png_destroy_struct_2(void* struct_ptr, void (*free_fn)(png_structp, void*), void* mem_ptr);
void* png_create_struct(int type);
void  png_destroy_struct(void* struct_ptr);
void  png_set_mem_fn(png_structp png_ptr, void* mem_ptr,
                     void* (*malloc_fn)(png_structp, std::uint32_t),
                     void  (*free_fn)(png_structp, void*));
void  png_set_error_fn(png_structp png_ptr, void* error_ptr,
                       png_error_ptr error_fn, png_error_ptr warn_fn);
void  png_error(png_structp png_ptr, const char* message);
void  png_set_read_fn(png_structp png_ptr, void* io_ptr, void* read_data_fn);
void  png_push_fill_buffer(png_structp png_ptr, std::uint8_t* buf, std::uint32_t length);
unsigned long png_get_uint_32(const std::uint8_t* buf);
void  png_crc_read(png_structp png_ptr, std::uint8_t* buf, std::uint32_t length);
int   png_crc_finish(png_structp png_ptr, std::uint32_t skip);
void  png_combine_row(png_structp png_ptr, std::uint8_t* row, int mask);
void  png_read_filter_row(png_structp png_ptr, void* row_info,
                          std::uint8_t* row, std::uint8_t* prev_row, int filter);
void  png_read_finish_row(png_structp png_ptr);
void  png_read_start_row(png_structp png_ptr);
void  png_do_read_transformations(png_structp png_ptr);
void  png_do_read_intrapixel(int* row_info, std::uint32_t row_addr_plus1);
void  png_do_read_interlace(png_structp png_ptr);
void  png_memcpy_check(png_structp png_ptr, void* dst, void* src, std::uint32_t length);

// libpng chunk handlers (live in png.lib at addresses >= 0x00A2xxxx).
void  png_handle_IHDR(png_structp, png_infop, std::uint32_t);
void  png_handle_PLTE(png_structp, png_infop, std::uint32_t);
void  png_handle_IEND(png_structp, png_infop, std::uint32_t);
void  png_handle_bKGD(png_structp, png_infop, std::uint32_t);
void  png_handle_cHRM(png_structp, png_infop, std::uint32_t);
void  png_handle_gAMA(png_structp, png_infop, std::uint32_t);
void  png_handle_hIST(png_structp, png_infop, std::uint32_t);
void  png_handle_oFFs(png_structp, png_infop, std::uint32_t);
void  png_handle_pCAL(png_structp, png_infop, std::uint32_t);
void  png_handle_sCAL(png_structp, png_infop, std::uint32_t);
void  png_handle_pHYs(png_structp, png_infop, std::uint32_t);
void  png_handle_sBIT(png_structp, png_infop, std::uint32_t);
void  png_handle_sRGB(png_structp, png_infop, std::uint32_t);
void  png_handle_iCCP(png_structp, png_infop, std::uint32_t);
void  png_handle_sPLT(png_structp, png_infop, std::uint32_t);
void  png_handle_tEXt(png_structp, png_infop, std::uint32_t);
void  png_handle_tIME(png_structp, png_infop, std::uint32_t);
void  png_handle_tRNS(png_structp, png_infop, std::uint32_t);
void  png_handle_zTXt(png_structp, png_infop, std::uint32_t);
void  png_handle_unknown(png_structp, png_infop, std::uint32_t);

// zlib symbols.
struct z_stream_s;
int   inflate(z_stream_s* strm, int flush);
int   inflateEnd(z_stream_s* strm);
int   inflateInit_(z_stream_s* strm, const char* version, int stream_size);

// libpng's externally-defined pass mask tables (used by png_read_row).
extern const std::uint8_t png_pass_mask[7];
extern const std::uint8_t png_pass_dsp_mask[7];

} // extern "C"

/**
 * Address: 0x009E753F (FUN_009E753F)
 * Mangled: png_push_fill_buffer
 *
 * What it does:
 * Invokes the registered png_struct read callback, or raises png_error when
 * the callback slot is null.
 */
extern "C" void png_push_fill_buffer(png_structp png_ptr, std::uint8_t* buf, std::uint32_t length)
{
  const auto read_data_fn = libpng_detail::GetReadDataFn(png_ptr);
  if (read_data_fn == nullptr) {
    png_error(png_ptr, "Call to NULL read function");
  }

  read_data_fn(png_ptr, buf, length);
}

/**
 * Address: 0x009E0A46 (FUN_009E0A46)
 * Mangled: png_get_copyright
 *
 * What it does:
 * Returns the embedded libpng copyright/version banner text.
 */
extern "C" const char* png_get_copyright(png_structp png_ptr)
{
  (void)png_ptr;
  return "\n"
         " libpng version 1.2.5rc3 - September 18, 2002\n"
         "   Copyright (c) 1998-2002 Glenn Randers-Pehrson\n"
         "   Copyright (c) 1996-1997 Andreas Dilger\n"
         "   Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc.\n";
}

/**
 * Address: 0x009E0A4C (FUN_009E0A4C)
 * Mangled: png_get_libpng_ver
 *
 * What it does:
 * Returns the embedded libpng version token expected by callers.
 */
extern "C" const char* png_get_libpng_ver(png_structp png_ptr)
{
  (void)png_ptr;
  return "1.2.5rc3";
}

/**
 * Address: 0x009E0A52 (FUN_009E0A52)
 * Mangled: png_get_header_ver
 *
 * What it does:
 * Returns the embedded libpng header-version token.
 */
extern "C" const char* png_get_header_ver()
{
  return "1.2.5rc3";
}

/**
 * Address: 0x009E0A58 (FUN_009E0A58)
 * Mangled: png_get_header_version
 *
 * What it does:
 * Returns the embedded libpng header-version banner string.
 */
extern "C" const char* png_get_header_version()
{
  return " libpng version 1.2.5rc3 - September 18, 2002 (header)\n";
}

namespace {

using libpng_layout::Field;
using libpng_layout::RawBase;
using libpng_layout::kPngStructSize;

// libpng version string the runtime expects from the application header.
constexpr const char* kPngLibraryVersion = "1.2.5rc3";

// Memory function slots inside png_struct.
//   +0x244 = mem_ptr,  +0x248 = malloc_fn,  +0x24C = free_fn
constexpr std::size_t kOffMemPtr   = 0x244;
constexpr std::size_t kOffMallocFn = 0x248;
constexpr std::size_t kOffFreeFn   = 0x24C;

// Read-state mode bits used here.
constexpr std::uint32_t kPngHaveIhdr      = 0x0001;
constexpr std::uint32_t kPngHavePlte      = 0x0002;
constexpr std::uint32_t kPngHaveIdat      = 0x0004;
constexpr std::uint32_t kPngAfterIdat     = 0x0008;
constexpr std::uint32_t kPngHaveIend      = 0x0010;
constexpr std::uint32_t kPngHaveFileSig   = 0x1000;

// Flag bits used by version handshake / read state.
constexpr std::uint32_t kPngFlagLibraryMismatch = 0x20000;
constexpr std::size_t kOffWarningFn = 0x44;

[[nodiscard]] inline void*& MemPtrSlot(png_structp png_ptr)   { return Field<void*>(png_ptr, kOffMemPtr); }
[[nodiscard]] inline png_malloc_ptr& MallocFnSlot(png_structp png_ptr) { return Field<png_malloc_ptr>(png_ptr, kOffMallocFn); }
[[nodiscard]] inline png_free_ptr&   FreeFnSlot(png_structp png_ptr)   { return Field<png_free_ptr>(png_ptr, kOffFreeFn); }

[[nodiscard]] inline int Memcmp4(const std::uint8_t* a, const char (&lit)[5]) noexcept
{
  return png_memcmp(a, lit, 4);
}

constexpr int kPngStructPng  = 1;

constexpr std::uint32_t kPngFreeAllRead = 0x4000;

} // namespace

/**
 * Address: 0x009E0D7F (FUN_009E0D7F)
 * Mangled: png_read_init_2
 *
 * What it does:
 * Reinitializes one png read-state lane from legacy caller arguments while
 * preserving the callback/jmp prefix and rebuilding zlib state.
 */
extern "C" void png_read_init_2(
  png_structp* const png_ptr_ptr,
  const char* const  user_png_ver,
  const std::uint32_t png_struct_size)
{
  if (png_ptr_ptr == nullptr || *png_ptr_ptr == nullptr) {
    return;
  }

  png_structp png_ptr = *png_ptr_ptr;
  if (user_png_ver == nullptr || std::strcmp(user_png_ver, kPngLibraryVersion) != 0) {
    Field<std::uint32_t>(png_ptr, kOffWarningFn) = 0u;
    png_warning(png_ptr, "Application uses deprecated png_read_init() and should be recompiled.");
  }

  std::uint8_t preservedPrefix[0x40]{};
  std::memcpy(preservedPrefix, png_ptr, sizeof(preservedPrefix));

  if (png_struct_size < kPngStructSize) {
    png_destroy_struct(png_ptr);
    png_ptr = static_cast<png_structp>(png_create_struct(kPngStructPng));
    *png_ptr_ptr = png_ptr;
  }

  std::memset(png_ptr, 0, kPngStructSize);
  std::memcpy(png_ptr, preservedPrefix, sizeof(preservedPrefix));

  Field<std::uint32_t>(png_ptr, kOffZbufSize) = 0x2000;
  Field<void*>(png_ptr, kOffZbuf) = png_malloc(png_ptr, 0x2000);
  Field<void*>(png_ptr, kOffZstreamZalloc) = reinterpret_cast<void*>(&png_zalloc);
  Field<void*>(png_ptr, kOffZstreamZfree) = reinterpret_cast<void*>(&png_zfree);
  Field<void*>(png_ptr, kOffZstreamOpaque) = png_ptr;

  auto* const zstream = reinterpret_cast<z_stream_s*>(RawBase(png_ptr) + kOffZstream);
  const int zret = inflateInit_(zstream, "1.1.4", 56);
  if (zret == -6) {
    png_error(png_ptr, "zlib version");
  } else if (zret == -4 || zret == -2) {
    png_error(png_ptr, "zlib memory");
  } else if (zret != 0) {
    png_error(png_ptr, "Unknown zlib error");
  }

  Field<void*>(png_ptr, kOffZstreamNextOut) = Field<void*>(png_ptr, kOffZbuf);
  Field<std::uint32_t>(png_ptr, kOffZstreamAvailOut) = Field<std::uint32_t>(png_ptr, kOffZbufSize);
  png_set_read_fn(png_ptr, nullptr, nullptr);
}

/**
 * Address: 0x009E0AE9 (FUN_009E0AE9)
 * Mangled: png_create_info_struct
 */
extern "C" png_infop png_create_info_struct(png_structp png_ptr)
{
  if (png_ptr == nullptr) {
    return nullptr;
  }

  // Pull the user-supplied (or default) memory functions out of the png_struct
  // by name and forward them to the libpng allocator.
  void* const                  mem_ptr   = MemPtrSlot(png_ptr);
  png_malloc_ptr const         malloc_fn = MallocFnSlot(png_ptr);

  auto* info_ptr = static_cast<png_info_struct*>(
    png_create_struct_2(kPngStructInfo, malloc_fn, mem_ptr));
  if (info_ptr != nullptr) {
    png_info_init_3(&info_ptr, kPngInfoStructSize);
  }
  return info_ptr;
}

/**
 * Address: 0x009E0B6E (FUN_009E0B6E)
 * Mangled: png_create_read_struct_2
 */
extern "C" png_structp png_create_read_struct_2(
  const char*    user_png_ver,
  void*          error_ptr,
  png_error_ptr  error_fn,
  png_error_ptr  warn_fn,
  void*          mem_ptr,
  png_malloc_ptr malloc_fn,
  png_free_ptr   free_fn)
{
  using namespace libpng_layout;

  auto* png_ptr = static_cast<png_structp>(
    png_create_struct_2(kPngStructPng, malloc_fn, mem_ptr));
  if (png_ptr == nullptr) {
    return nullptr;
  }

  png_init_mmx_flags(png_ptr);

  // The libpng longjmp recovery path: if any allocation below longjmps back to
  // here, release the partially-initialised zbuf and tear down the struct.
  if (setjmp(*reinterpret_cast<jmp_buf*>(RawBase(png_ptr))) != 0) {
    png_free(png_ptr, Field<void*>(png_ptr, kOffZbuf));
    Field<void*>(png_ptr, kOffZbuf) = nullptr;
    png_destroy_struct_2(png_ptr, free_fn, mem_ptr);
    return nullptr;
  }

  png_set_mem_fn(png_ptr, mem_ptr, malloc_fn, free_fn);
  png_set_error_fn(png_ptr, error_ptr, error_fn, warn_fn);

  // Validate the application-side libpng version against the embedded version
  // string. The binary walks both strings byte-for-byte rather than using
  // strcmp, OR-ing PNG_FLAG_LIBRARY_MISMATCH on any divergence.
  bool mismatch = false;
  for (const char* p = kPngLibraryVersion; *p != '\0'; ++p) {
    const char other = (user_png_ver != nullptr) ? user_png_ver[p - kPngLibraryVersion] : '\0';
    if (other != *p) {
      mismatch = true;
    }
  }
  if (mismatch) {
    Flags(png_ptr) |= kPngFlagLibraryMismatch;
  }

  if ((Flags(png_ptr) & kPngFlagLibraryMismatch) != 0) {
    bool fatal = (user_png_ver == nullptr);

    if (!fatal) {
      const char first      = user_png_ver[0];
      const char first_lib  = kPngLibraryVersion[0];
      const char third      = user_png_ver[2];
      const char third_lib  = kPngLibraryVersion[2];

      if (first != first_lib ||
          (first == '1' && third != third_lib) ||
          (first == '0' && third < '9'))
      {
        char message[80];
        std::sprintf(message,
                     "Application was compiled with png.h from libpng-%.20s",
                     user_png_ver);
        png_warning(png_ptr, message);
        fatal = true;
      }
    }

    if (fatal) {
      char message[80];
      std::sprintf(message,
                   "Application  is  running with png.c from libpng-%.20s",
                   kPngLibraryVersion);
      png_warning(png_ptr, message);
      Flags(png_ptr) = 0;
      png_error(png_ptr, "Incompatible libpng version in application and library");
    }
  }

  // Allocate and wire the zlib input buffer + zstream callbacks.
  Field<std::uint32_t>(png_ptr, kOffZbufSize) = 0x2000;
  Field<void*>(png_ptr, kOffZbuf) = png_malloc(png_ptr, 0x2000);
  Field<void*>(png_ptr, kOffZstreamZalloc) = reinterpret_cast<void*>(&png_zalloc);
  Field<void*>(png_ptr, kOffZstreamZfree)  = reinterpret_cast<void*>(&png_zfree);
  Field<void*>(png_ptr, kOffZstreamOpaque) = png_ptr;

  auto* const zstream =
    reinterpret_cast<z_stream_s*>(RawBase(png_ptr) + kOffZstream);
  const int zret = inflateInit_(zstream, "1.1.4", 56);
  if (zret == -6) {
    png_error(png_ptr, "zlib version error");
  }
  if (zret == -4 || zret == -2) {
    png_error(png_ptr, "zlib memory error");
  }
  if (zret != 0) {
    png_error(png_ptr, "Unknown zlib error");
  }

  // Point next_out at the freshly allocated zbuf and prime avail_out.
  Field<void*>(png_ptr, kOffZstreamNextOut)         = Field<void*>(png_ptr, kOffZbuf);
  Field<std::uint32_t>(png_ptr, kOffZstreamAvailOut) = Field<std::uint32_t>(png_ptr, kOffZbufSize);

  png_set_read_fn(png_ptr, nullptr, nullptr);

  // Second setjmp call: matches the binary's "if (setjmp) abort()" tail. The
  // libpng public API expects the application to install its own jmpbuf via
  // png_setjmp; this internal setjmp guards against unrecoverable bring-up
  // failures during the very last init step.
  if (setjmp(*reinterpret_cast<jmp_buf*>(RawBase(png_ptr))) != 0) {
    std::abort();
  }
  return png_ptr;
}

/**
 * Address: 0x009E1FED (FUN_009E1FED)
 * Mangled: png_create_read_struct
 */
extern "C" png_structp png_create_read_struct(
  const char*   user_png_ver,
  void*         error_ptr,
  png_error_ptr error_fn,
  png_error_ptr warn_fn)
{
  return png_create_read_struct_2(
    user_png_ver, error_ptr, error_fn, warn_fn,
    nullptr, nullptr, nullptr);
}

/**
 * Address: 0x009E1809 (FUN_009E1809)
 * Mangled: png_read_image
 */
extern "C" void png_read_image(png_structp png_ptr, std::uint8_t** image)
{
  using namespace libpng_layout;

  const int passes  = png_set_interlace_handling(png_ptr);
  const std::uint32_t height = Field<std::uint32_t>(png_ptr, kOffNumRows);
  Field<std::uint32_t>(png_ptr, 0xD0) = height;  // num_rows duplicated to row counter

  if (passes <= 0) {
    return;
  }

  for (int pass = passes; pass > 0; --pass) {
    std::uint8_t** row_pp = image;
    for (std::uint32_t row = height; row != 0; --row) {
      png_read_row(png_ptr, *row_pp++, nullptr);
    }
  }
}

/**
 * Address: 0x009E1383 (FUN_009E1383)
 * Mangled: png_read_row
 *
 * The recovered body preserves the binary's pass-mask short-circuit table 1:1
 * to maintain Adam7 fidelity, even though the high-level shape would prefer a
 * single switch with named cases. The fallthrough into LABEL_38 mirrors the
 * binary's break out of the pass switch when the row needs full decoding.
 */
extern "C" void png_read_row(png_structp png_ptr, std::uint8_t* row, std::uint8_t* dsp_row)
{
  using namespace libpng_layout;

  if ((Flags(png_ptr) & 0x40) == 0) {
    png_read_start_row(png_ptr);
  }

  const std::uint8_t  interlaced = Interlaced(png_ptr);
  const std::uint32_t trans      = Transformations(png_ptr);

  bool full_decode = true;

  if (interlaced != 0 && (trans & kPngInterlace) != 0) {
    const std::uint8_t pass = Pass(png_ptr);
    const std::uint32_t rowbytes = Field<std::uint32_t>(png_ptr, 0xC8);

    auto pass_finish = [&] {
      png_read_finish_row(png_ptr);
    };
    auto combine_then_finish = [&](int mask) {
      if (dsp_row != nullptr) {
        png_combine_row(png_ptr, dsp_row, mask);
      }
      pass_finish();
    };

    switch (pass) {
      case 0:
        if ((rowbytes & 7) == 0) {
          break;  // full decode
        }
        if (dsp_row == nullptr) {
          pass_finish();
          return;
        }
        png_combine_row(png_ptr, dsp_row, 255);
        pass_finish();
        return;

      case 1: {
        const std::uint32_t width = Field<std::uint32_t>(png_ptr, 0xC8);
        if ((rowbytes & 7) != 0 || width < 5u) {
          combine_then_finish(15);
          return;
        }
        break;
      }

      case 2: {
        const std::uint32_t r = rowbytes;
        if ((r & 7) == 4) {
          break;
        }
        if (dsp_row == nullptr || (r & 4) == 0) {
          pass_finish();
          return;
        }
        png_combine_row(png_ptr, dsp_row, 255);
        pass_finish();
        return;
      }

      case 3: {
        const std::uint32_t width = Field<std::uint32_t>(png_ptr, 0xC8);
        if ((rowbytes & 3) != 0 || width < 3u) {
          combine_then_finish(51);
          return;
        }
        break;
      }

      case 4: {
        const std::uint32_t r = rowbytes;
        if ((r & 3) == 2) {
          break;
        }
        if (dsp_row == nullptr || (r & 2) == 0) {
          pass_finish();
          return;
        }
        png_combine_row(png_ptr, dsp_row, 255);
        pass_finish();
        return;
      }

      case 5: {
        const std::uint32_t width = Field<std::uint32_t>(png_ptr, 0xC8);
        if ((rowbytes & 1) != 0 || width < 2u) {
          combine_then_finish(85);
          return;
        }
        break;
      }

      default:
        if (pass == 6 && (rowbytes & 1) == 0) {
          pass_finish();
          return;
        }
        break;
    }

    (void) full_decode;  // fall through to full decode below
  }

  // LABEL_38: full row decode path.
  if ((Mode(png_ptr) & kPngHaveIdat) == 0) {
    png_error(png_ptr, "Invalid attempt to read row data");
  }

  // zstream.next_out = row_buf; zstream.avail_out = irowbytes
  Field<void*>(png_ptr, kOffZstreamNextOut) = Field<void*>(png_ptr, 0xEC);
  Field<std::uint32_t>(png_ptr, 0x84)       = Field<std::uint32_t>(png_ptr, 0xDC);  // avail_out from rowbytes-equivalent

  while (true) {
    if (Field<std::uint32_t>(png_ptr, 0x78) == 0) {
      // Refill the inflate input buffer from one or more IDAT chunks.
      while (Field<std::uint32_t>(png_ptr, 0x10C) == 0) {
        png_crc_finish(png_ptr, 0);
        std::uint32_t length_buf;
        png_push_fill_buffer(png_ptr, reinterpret_cast<std::uint8_t*>(&length_buf), 4);
        const std::uint32_t length = static_cast<std::uint32_t>(
          png_get_uint_32(reinterpret_cast<const std::uint8_t*>(&length_buf)));
        Field<std::uint32_t>(png_ptr, 0x10C) = length;
        if (length > 0x7FFFFFFFu) {
          png_error(png_ptr, "Invalid chunk length.");
        }
        png_reset_crc(png_ptr);
        png_crc_read(png_ptr, RawBase(png_ptr) + 0x11C, 4);
        if (Memcmp4(RawBase(png_ptr) + 0x11C, "IDAT")) {
          png_error(png_ptr, "Not enough image data");
        }
      }

      const std::uint32_t buffer_size = Field<std::uint32_t>(png_ptr, 0xB0);
      const std::uint32_t idat_left   = Field<std::uint32_t>(png_ptr, 0x10C);
      auto* const buffer              = Field<std::uint8_t*>(png_ptr, 0xAC);

      Field<std::uint32_t>(png_ptr, 0x78) = buffer_size;
      Field<std::uint8_t*>(png_ptr, 0x74) = buffer;
      if (buffer_size > idat_left) {
        Field<std::uint32_t>(png_ptr, 0x78) = idat_left;
      }
      png_crc_read(png_ptr, buffer, Field<std::uint32_t>(png_ptr, 0x78));
      Field<std::uint32_t>(png_ptr, 0x10C) -= Field<std::uint32_t>(png_ptr, 0x78);
    }

    auto* const zstream = reinterpret_cast<z_stream_s*>(RawBase(png_ptr) + kOffZstream);
    const int zret = inflate(zstream, 1);
    if (zret == 1) {
      break;
    }
    if (zret != 0) {
      const char* msg = Field<const char*>(png_ptr, 0x8C);
      if (msg == nullptr) {
        msg = "Decompression error";
      }
      png_error(png_ptr, msg);
    }
    if (Field<std::uint32_t>(png_ptr, 0x84) == 0) {
      goto label_post_inflate;
    }
  }

  if (Field<std::uint32_t>(png_ptr, 0x84) != 0 ||
      Field<std::uint32_t>(png_ptr, 0x78) != 0 ||
      Field<std::uint32_t>(png_ptr, 0x10C) != 0)
  {
    png_error(png_ptr, "Extra compressed data");
  }
  Mode(png_ptr)  |= kPngAfterIdat;
  Flags(png_ptr) |= 0x20;

label_post_inflate:
  // Build the row_info struct that the unfilter / transform path consumes.
  const std::uint8_t color_type = ColorType(png_ptr);
  const std::uint8_t bit_depth  = BitDepth(png_ptr);
  const std::uint8_t channels   = *(RawBase(png_ptr) + 0x129);
  const std::uint8_t pixel_depth= *(RawBase(png_ptr) + 0x12A);
  *(RawBase(png_ptr) + 0x108) = color_type;     // row_info.color_type mirror
  *(RawBase(png_ptr) + 0x109) = bit_depth;
  *(RawBase(png_ptr) + 0x10A) = channels;
  *(RawBase(png_ptr) + 0x10B) = pixel_depth;

  const std::uint32_t width      = Field<std::uint32_t>(png_ptr, 0xE0);
  const std::uint32_t row_bytes  = (width * pixel_depth + 7) >> 3;
  Field<std::uint32_t>(png_ptr, 0x100) = width;
  Field<std::uint32_t>(png_ptr, 0x104) = row_bytes;

  auto* const row_buf = Field<std::uint8_t*>(png_ptr, 0xEC);
  if (*row_buf != 0) {
    png_read_filter_row(png_ptr,
                        reinterpret_cast<void*>(RawBase(png_ptr) + 0x100),
                        row_buf + 1,
                        Field<std::uint8_t*>(png_ptr, 0xE8) + 1,
                        *row_buf);
  }
  png_memcpy_check(png_ptr,
                   Field<void*>(png_ptr, 0xE8),
                   Field<void*>(png_ptr, 0xEC),
                   Field<std::uint32_t>(png_ptr, 0xD8) + 1);

  if ((*(RawBase(png_ptr) + 0x230) & 4) != 0 && *(RawBase(png_ptr) + 0x238) == 64) {
    png_do_read_intrapixel(reinterpret_cast<int*>(RawBase(png_ptr) + 0x100),
                           reinterpret_cast<std::uintptr_t>(Field<std::uint8_t*>(png_ptr, 0xEC)) + 1);
  }
  if (Transformations(png_ptr) != 0) {
    png_do_read_transformations(png_ptr);
  }

  if (Interlaced(png_ptr) != 0 && (Transformations(png_ptr) & kPngInterlace) != 0) {
    if (Pass(png_ptr) < 6) {
      png_do_read_interlace(png_ptr);
    }
    if (dsp_row != nullptr) {
      png_combine_row(png_ptr, dsp_row, png_pass_dsp_mask[Pass(png_ptr)]);
    }
    if (row != nullptr) {
      png_combine_row(png_ptr, row, png_pass_mask[Pass(png_ptr)]);
    }
  } else {
    if (row != nullptr) {
      png_combine_row(png_ptr, row, 255);
    }
    if (dsp_row != nullptr) {
      png_combine_row(png_ptr, dsp_row, 255);
    }
  }

  png_read_finish_row(png_ptr);

  using row_callback_t = void (*)(png_structp, std::uint32_t, std::uint8_t);
  auto cb = Field<row_callback_t>(png_ptr, 0x198);
  if (cb != nullptr) {
    cb(png_ptr, Field<std::uint32_t>(png_ptr, 0xE4), Pass(png_ptr));
  }
}

/**
 * Address: 0x009E0E93 (FUN_009E0E93)
 * Mangled: png_read_info
 */
extern "C" void png_read_info(png_structp png_ptr, png_infop info_ptr)
{
  using namespace libpng_layout;

  // Validate the 8-byte file signature, consuming whatever the caller has
  // not yet pushed in via png_set_sig_bytes.
  std::uint8_t* signature_field =
      reinterpret_cast<std::uint8_t*>(info_ptr) + 0x18;  // png_info.signature
  std::uint8_t  sig_bytes_seen  = *(RawBase(png_ptr) + 0x110);
  if (sig_bytes_seen < 8) {
    const std::uint32_t already = sig_bytes_seen;
    const int           need    = 8 - sig_bytes_seen;
    png_push_fill_buffer(png_ptr, signature_field + sig_bytes_seen,
                         static_cast<std::uint32_t>(need));
    *(RawBase(png_ptr) + 0x110) = 8;

    if (png_sig_cmp(signature_field, already, static_cast<std::uint32_t>(need)) != 0) {
      if (already < 4) {
        if (png_sig_cmp(signature_field, already,
                        static_cast<std::uint32_t>(need - 4)) != 0)
        {
          png_error(png_ptr, "Not a PNG file");
        }
      }
      png_error(png_ptr, "PNG file corrupted by ASCII conversion");
    }
    if (already < 3) {
      Mode(png_ptr) |= kPngHaveFileSig;
    }
  }

  while (true) {
    std::uint32_t length_buf;
    png_push_fill_buffer(png_ptr, reinterpret_cast<std::uint8_t*>(&length_buf), 4);
    const std::uint32_t length = static_cast<std::uint32_t>(
      png_get_uint_32(reinterpret_cast<const std::uint8_t*>(&length_buf)));
    png_reset_crc(png_ptr);
    auto* const chunk = RawBase(png_ptr) + 0x11C;
    png_crc_read(png_ptr, chunk, 4);
    if (length > 0x7FFFFFFFu) {
      png_error(png_ptr, "Invalid chunk length.");
    }

    if (Memcmp4(chunk, "IHDR") == 0) {
      png_handle_IHDR(png_ptr, info_ptr, length);
      continue;
    }
    if (Memcmp4(chunk, "IEND") == 0) {
      png_handle_IEND(png_ptr, info_ptr, length);
      continue;
    }
    if (png_handle_as_unknown(png_ptr, chunk) != 0) {
      if (Memcmp4(chunk, "IDAT") == 0) {
        Mode(png_ptr) |= kPngHaveIdat;
      }
      png_handle_unknown(png_ptr, info_ptr, length);
      if (Memcmp4(chunk, "PLTE") == 0) {
        Mode(png_ptr) |= kPngHavePlte;
      } else if (Memcmp4(chunk, "IDAT") == 0) {
        const std::uint32_t mode = Mode(png_ptr);
        if ((mode & kPngHaveIhdr) == 0) {
          png_error(png_ptr, "Missing IHDR before IDAT");
        }
        if (ColorType(png_ptr) == kColorTypePalette && (mode & kPngHavePlte) == 0) {
          png_error(png_ptr, "Missing PLTE before IDAT");
        }
        return;
      }
      continue;
    }
    if (Memcmp4(chunk, "PLTE") == 0) {
      png_handle_PLTE(png_ptr, info_ptr, length);
      continue;
    }
    if (Memcmp4(chunk, "IDAT") == 0) {
      const std::uint32_t mode = Mode(png_ptr);
      if ((mode & kPngHaveIhdr) == 0) {
        png_error(png_ptr, "Missing IHDR before IDAT");
      }
      if (ColorType(png_ptr) == kColorTypePalette && (mode & kPngHavePlte) == 0) {
        png_error(png_ptr, "Missing PLTE before IDAT");
      }
      Mode(png_ptr) |= kPngHaveIdat;
      Field<std::uint32_t>(png_ptr, 0x10C) = length;  // idat_size
      return;
    }
    if (Memcmp4(chunk, "bKGD") == 0) { png_handle_bKGD(png_ptr, info_ptr, length); continue; }
    if (Memcmp4(chunk, "cHRM") == 0) { png_handle_cHRM(png_ptr, info_ptr, length); continue; }
    if (Memcmp4(chunk, "gAMA") == 0) { png_handle_gAMA(png_ptr, info_ptr, length); continue; }
    if (Memcmp4(chunk, "hIST") == 0) { png_handle_hIST(png_ptr, info_ptr, length); continue; }
    if (Memcmp4(chunk, "oFFs") == 0) { png_handle_oFFs(png_ptr, info_ptr, length); continue; }
    if (Memcmp4(chunk, "pCAL") == 0) { png_handle_pCAL(png_ptr, info_ptr, length); continue; }
    if (Memcmp4(chunk, "sCAL") == 0) { png_handle_sCAL(png_ptr, info_ptr, length); continue; }
    if (Memcmp4(chunk, "pHYs") == 0) { png_handle_pHYs(png_ptr, info_ptr, length); continue; }
    if (Memcmp4(chunk, "sBIT") == 0) { png_handle_sBIT(png_ptr, info_ptr, length); continue; }
    if (Memcmp4(chunk, "sRGB") == 0) { png_handle_sRGB(png_ptr, info_ptr, length); continue; }
    if (Memcmp4(chunk, "iCCP") == 0) { png_handle_iCCP(png_ptr, info_ptr, length); continue; }
    if (Memcmp4(chunk, "sPLT") == 0) { png_handle_sPLT(png_ptr, info_ptr, length); continue; }
    if (Memcmp4(chunk, "tEXt") == 0) { png_handle_tEXt(png_ptr, info_ptr, length); continue; }
    if (Memcmp4(chunk, "tIME") == 0) { png_handle_tIME(png_ptr, info_ptr, length); continue; }
    if (Memcmp4(chunk, "tRNS") == 0) { png_handle_tRNS(png_ptr, info_ptr, length); continue; }
    if (Memcmp4(chunk, "zTXt") == 0) { png_handle_zTXt(png_ptr, info_ptr, length); continue; }
    png_handle_unknown(png_ptr, info_ptr, length);
  }
}

/**
 * Address: 0x009E1856 (FUN_009E1856)
 * Mangled: png_read_end
 */
extern "C" void png_read_end(png_structp png_ptr, png_infop info_ptr)
{
  using namespace libpng_layout;

  png_crc_finish(png_ptr, 0);

  do {
    std::uint32_t length_buf;
    png_push_fill_buffer(png_ptr, reinterpret_cast<std::uint8_t*>(&length_buf), 4);
    const std::uint32_t length = static_cast<std::uint32_t>(
      png_get_uint_32(reinterpret_cast<const std::uint8_t*>(&length_buf)));
    png_reset_crc(png_ptr);
    auto* const chunk = RawBase(png_ptr) + 0x11C;
    png_crc_read(png_ptr, chunk, 4);
    if (length > 0x7FFFFFFFu) {
      png_error(png_ptr, "Invalid chunk length.");
    }

    if (png_memcmp(chunk, "IHDR", 4u) == 0) {
      png_handle_IHDR(png_ptr, info_ptr, length);
      continue;
    }
    if (png_memcmp(chunk, "IEND", 4u) == 0) {
      png_handle_IEND(png_ptr, info_ptr, length);
      continue;
    }

    if (png_handle_as_unknown(png_ptr, chunk) != 0) {
      if (png_memcmp(chunk, "IDAT", 4u) != 0) {
        Mode(png_ptr) |= kPngAfterIdat;
      } else if (length != 0 || (Mode(png_ptr) & kPngAfterIdat) != 0) {
        png_error(png_ptr, "Too many IDAT's found");
      }
      png_handle_unknown(png_ptr, info_ptr, length);
      if (png_memcmp(chunk, "PLTE", 4u) == 0) {
        Mode(png_ptr) |= kPngHavePlte;
      }
      continue;
    }

    if (png_memcmp(chunk, "IDAT", 4u) == 0) {
      if (length != 0 || (Mode(png_ptr) & kPngAfterIdat) != 0) {
        png_error(png_ptr, "Too many IDAT's found");
      }
      png_crc_finish(png_ptr, 0);
      continue;
    }

    if (png_memcmp(chunk, "PLTE", 4u) == 0) { png_handle_PLTE(png_ptr, info_ptr, length); continue; }
    if (png_memcmp(chunk, "bKGD", 4u) == 0) { png_handle_bKGD(png_ptr, info_ptr, length); continue; }
    if (png_memcmp(chunk, "cHRM", 4u) == 0) { png_handle_cHRM(png_ptr, info_ptr, length); continue; }
    if (png_memcmp(chunk, "gAMA", 4u) == 0) { png_handle_gAMA(png_ptr, info_ptr, length); continue; }
    if (png_memcmp(chunk, "hIST", 4u) == 0) { png_handle_hIST(png_ptr, info_ptr, length); continue; }
    if (png_memcmp(chunk, "oFFs", 4u) == 0) { png_handle_oFFs(png_ptr, info_ptr, length); continue; }
    if (png_memcmp(chunk, "pCAL", 4u) == 0) { png_handle_pCAL(png_ptr, info_ptr, length); continue; }
    if (png_memcmp(chunk, "sCAL", 4u) == 0) { png_handle_sCAL(png_ptr, info_ptr, length); continue; }
    if (png_memcmp(chunk, "pHYs", 4u) == 0) { png_handle_pHYs(png_ptr, info_ptr, length); continue; }
    if (png_memcmp(chunk, "sBIT", 4u) == 0) { png_handle_sBIT(png_ptr, info_ptr, length); continue; }
    if (png_memcmp(chunk, "sRGB", 4u) == 0) { png_handle_sRGB(png_ptr, info_ptr, length); continue; }
    if (png_memcmp(chunk, "iCCP", 4u) == 0) { png_handle_iCCP(png_ptr, info_ptr, length); continue; }
    if (png_memcmp(chunk, "sPLT", 4u) == 0) { png_handle_sPLT(png_ptr, info_ptr, length); continue; }
    if (png_memcmp(chunk, "tEXt", 4u) == 0) { png_handle_tEXt(png_ptr, info_ptr, length); continue; }
    if (png_memcmp(chunk, "tIME", 4u) == 0) { png_handle_tIME(png_ptr, info_ptr, length); continue; }
    if (png_memcmp(chunk, "tRNS", 4u) == 0) { png_handle_tRNS(png_ptr, info_ptr, length); continue; }
    if (png_memcmp(chunk, "zTXt", 4u) == 0) { png_handle_zTXt(png_ptr, info_ptr, length); continue; }
    png_handle_unknown(png_ptr, info_ptr, length);
  } while ((Mode(png_ptr) & kPngHaveIend) == 0);
}

/**
 * Address: 0x009E1C4A (FUN_009E1C4A)
 * Mangled: png_read_destroy
 *
 * Reset preserves: jmp_buf [0..63], free_fn slot, error_fn/warning_fn block
 * (offsets +0x40, +0x44, +0x48 in dwords = +0x40..+0x4C bytes), and the
 * memory-allocator function pointer slot at offset 0x24C.
 */
extern "C" void png_read_destroy(png_structp png_ptr, png_infop info_ptr, png_infop end_info_ptr)
{
  using namespace libpng_layout;

  if (info_ptr != nullptr) {
    png_info_destroy(png_ptr, info_ptr);
  }
  if (end_info_ptr != nullptr) {
    png_info_destroy(png_ptr, end_info_ptr);
  }

  // Indexed by dword offset (sizeof(uint32) * idx) — see FUN_009E1C4A.c.
  auto field32 = [&](std::size_t idx) -> std::uint32_t& {
    return Field<std::uint32_t>(png_ptr, idx * sizeof(std::uint32_t));
  };
  auto fieldp = [&](std::size_t idx) -> void*& {
    return Field<void*>(png_ptr, idx * sizeof(std::uint32_t));
  };

  png_free(png_ptr, fieldp(43));
  png_free(png_ptr, fieldp(148));
  png_free(png_ptr, fieldp(58));
  png_free(png_ptr, fieldp(123));
  png_free(png_ptr, fieldp(124));
  png_free(png_ptr, fieldp(89));
  png_free(png_ptr, fieldp(90));
  png_free(png_ptr, fieldp(91));

  if ((field32(133) & 0x1000) != 0) {
    png_zfree(png_ptr, fieldp(69));
  }
  field32(133) &= ~0x1000u;
  if ((field32(133) & 0x2000) != 0) {
    png_free(png_ptr, fieldp(98));
  }
  field32(133) &= ~0x2000u;
  if ((field32(133) & 0x8) != 0) {
    png_free(png_ptr, fieldp(125));
  }
  field32(133) &= ~0x8u;

  // Three optional gamma-shift table groups (gamma_table, gamma_from_1,
  // gamma_to_1). Each is a 2D array of 1<<(8-bit_depth) entries.
  const auto release_gamma_table = [&](std::size_t slot_idx) {
    auto*& table_pp = fieldp(slot_idx);
    if (table_pp == nullptr) {
      return;
    }
    const int bit_depth = static_cast<int>(*(RawBase(png_ptr) + 344));
    const int rows = 1 << (8 - bit_depth);
    if (rows > 0) {
      auto** rowsp = static_cast<void**>(table_pp);
      for (int i = 0; i < rows; ++i) {
        png_free(png_ptr, rowsp[i]);
      }
    }
    png_free(png_ptr, table_pp);
    table_pp = nullptr;
  };
  release_gamma_table(92);
  release_gamma_table(93);
  release_gamma_table(94);

  png_free(png_ptr, fieldp(132));

  auto* const zstream = reinterpret_cast<z_stream_s*>(RawBase(png_ptr) + kOffZstream);
  inflateEnd(zstream);

  png_free(png_ptr, fieldp(108));
  png_free(png_ptr, fieldp(121));

  // Save the four field groups that survive the reset.
  std::uint8_t  jmp_block[64];
  std::memcpy(jmp_block, png_ptr, sizeof(jmp_block));
  const std::uint32_t saved_err16 = field32(16);  // error_ptr
  const std::uint32_t saved_err17 = field32(17);  // error_fn
  const std::uint32_t saved_err18 = field32(18);  // warning_fn
  void* const         saved_freefn = fieldp(147);  // free_fn slot

  std::memset(png_ptr, 0, kPngStructSize);

  field32(17) = saved_err17;
  field32(18) = saved_err18;
  fieldp(147) = saved_freefn;
  field32(16) = saved_err16;

  std::memcpy(png_ptr, jmp_block, sizeof(jmp_block));
}

/**
 * Address: 0x009E20D5 (FUN_009E20D5)
 * Mangled: png_destroy_read_struct
 */
extern "C" void png_destroy_read_struct(
  png_structp* png_ptr_ptr,
  png_infop*   info_ptr_ptr,
  png_infop*   end_info_ptr_ptr)
{
  using namespace libpng_layout;

  png_structp png_ptr      = nullptr;
  png_infop   info_ptr     = nullptr;
  png_infop   end_info_ptr = nullptr;

  if (png_ptr_ptr != nullptr) {
    png_ptr = *png_ptr_ptr;
  }
  if (info_ptr_ptr != nullptr) {
    info_ptr = *info_ptr_ptr;
  }
  if (end_info_ptr_ptr != nullptr) {
    end_info_ptr = *end_info_ptr_ptr;
  }

  // Snapshot the memory functions before png_read_destroy clobbers most of
  // the struct (it preserves the free_fn slot but takes the rest down).
  png_free_ptr const free_fn = FreeFnSlot(png_ptr);
  void* const        mem_ptr = MemPtrSlot(png_ptr);

  png_read_destroy(png_ptr, info_ptr, end_info_ptr);

  if (info_ptr != nullptr) {
    png_free_data(png_ptr, info_ptr, kPngFreeAllRead, -1);
    png_destroy_struct_2(info_ptr, free_fn, mem_ptr);
    *info_ptr_ptr = nullptr;
  }
  if (end_info_ptr != nullptr) {
    png_free_data(png_ptr, end_info_ptr, kPngFreeAllRead, -1);
    png_destroy_struct_2(end_info_ptr, free_fn, mem_ptr);
    *end_info_ptr_ptr = nullptr;
  }

  png_destroy_struct_2(png_ptr, free_fn, mem_ptr);
  *png_ptr_ptr = nullptr;
}

/**
 * Address: 0x009E09AA (FUN_009E09AA)
 *
 * IDA signature:
 * void *__cdecl png_get_io_ptr(png_structp png_ptr);
 *
 * What it does:
 * Returns the user-supplied IO state pointer stored inside png_struct. The
 * wxWidgets PNG handler uses this to recover its wxPNGInfoStruct from inside
 * read/write/error/warning callbacks.
 */
extern "C" void* png_get_io_ptr(png_structp png_ptr)
{
  return libpng_detail::GetIoPtr(png_ptr);
}

/**
 * Address: 0x009E09B2 (FUN_009E09B2)
 *
 * IDA signature:
 * int __cdecl sub_9E09B2(int a1, int a2);
 *
 * What it does:
 * Writes one caller-provided IO state pointer into `png_struct::io_ptr`.
 */
extern "C" void png_set_io_ptr(png_structp png_ptr, void* io_ptr)
{
  // png_struct::io_ptr at +0x54 (same lane returned by png_get_io_ptr).
  libpng_layout::Field<void*>(png_ptr, 0x54) = io_ptr;
}

/**
 * Address: 0x009E09BE (FUN_009E09BE)
 * Mangled: png_convert_to_rfc1123
 *
 * What it does:
 * Allocates `png_ptr->time_buffer` on first use and formats one PNG `tIME`
 * lane into RFC1123 UTC text.
 */
extern "C" char* png_convert_to_rfc1123(
  png_structp const png_ptr,
  const png_time* const ptime
)
{
  constexpr std::size_t kOffTimeBuffer = 0x210;
  static constexpr const char* kMonthNames[12] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
  };

  char*& timeBuffer = libpng_layout::Field<char*>(png_ptr, kOffTimeBuffer);
  if (timeBuffer == nullptr) {
    timeBuffer = static_cast<char*>(png_malloc(png_ptr, 0x1Du));
  }

  int monthIndex = (static_cast<int>(ptime->month) - 1) % 12;
  if (monthIndex < 0) {
    monthIndex += 12;
  }

  std::sprintf(
    timeBuffer,
    "%d %s %d %02d:%02d:%02d +0000",
    static_cast<int>(ptime->day & 0x1Fu),
    kMonthNames[monthIndex],
    static_cast<int>(ptime->year),
    static_cast<int>(ptime->hour) % 24,
    static_cast<int>(ptime->minute) % 60,
    static_cast<int>(ptime->second) % 61
  );
  return timeBuffer;
}

/**
 * Address: 0x009E7792 (FUN_009E7792)
 *
 * IDA signature:
 * int __cdecl sub_9E7792(int a1);
 *
 * What it does:
 * Returns the opaque libpng error-context pointer lane (`png_struct::error_ptr`).
 */
extern "C" void* png_get_error_ptr(png_structp png_ptr)
{
  // png_struct::error_ptr at +0x48.
  return libpng_layout::Field<void*>(png_ptr, 0x48);
}

/**
 * Address: 0x009E1E86 (FUN_009E1E86)
 *
 * IDA signature:
 * int __cdecl sub_9E1E86(int a1, int a2);
 *
 * What it does:
 * Stores one read-status callback pointer into `png_struct` lane `+0x198`.
 */
extern "C" void png_set_read_status_fn(png_structp png_ptr, void* read_status_fn)
{
  libpng_layout::Field<void*>(png_ptr, 0x198) = read_status_fn;
}

/**
 * Address: 0x009E0A5E (FUN_009E0A5E)
 *
 * IDA signature:
 * int __cdecl png_handle_as_unknown(png_structp png_ptr, const png_byte *chunk_name);
 *
 * What it does:
 * Looks up how a PNG chunk should be handled according to the user-registered
 * "keep" list (png_set_keep_unknown_chunks). Scans the 5-byte-per-entry keep
 * table in reverse, returning the stored keep value (last-match-wins) for a
 * matching 4-byte chunk name. Returns 0 when the table is empty or no entry
 * matches. Matches the binary's null-guard shape exactly: only the
 * (png_ptr==nullptr && chunk_name==nullptr) pair short-circuits to 0.
 */
extern "C" int png_handle_as_unknown(png_structp png_ptr, const std::uint8_t* chunk_name)
{
  // Binary null-guard shape (preserved 1:1): both null is the only
  // pre-dispatch early return; a single null will fall through to the
  // field access below, matching the original compiled behaviour.
  if (png_ptr == nullptr && chunk_name == nullptr) {
    return 0;
  }

  auto chunk_list = libpng_detail::GetChunkList(png_ptr);
  // Signed compare: binary uses `jg` on the dword at +0x220, so any value <=0
  // (including stale/negative uninitialised content) exits early.
  const std::int32_t num = static_cast<std::int32_t>(chunk_list.num);
  if (num <= 0) {
    return 0;
  }

  // Walk the keep-table backwards (last-match-wins semantics in libpng 1.2.x).
  std::uint8_t* cursor =
      chunk_list.entries +
      libpng_detail::kPngChunkListRecordSize * static_cast<std::size_t>(num) -
      libpng_detail::kPngChunkListRecordSize;

  for (std::int32_t remaining = num; remaining != 0; --remaining) {
    if (png_memcmp(chunk_name, cursor, libpng_detail::kPngChunkListNameSize) == 0) {
      return cursor[libpng_detail::kPngChunkListNameSize];
    }
    cursor -= libpng_detail::kPngChunkListRecordSize;
  }

  return 0;
}

/**
 * Address: 0x009E0ACC (FUN_009E0ACC)
 *
 * IDA signature:
 * void __cdecl png_init_mmx_flags(png_structp png_ptr);
 *
 * What it does:
 * Zeroes the MMX-assembly dispatch fields on png_struct (asm_flags low byte,
 * mmx_bitdepth_threshold, mmx_rowbytes_threshold). Called from
 * png_create_read_struct_2 / png_create_write_struct_2 when the MMX assembly
 * path is disabled at runtime, effectively turning off all MMX code routes.
 */
extern "C" void png_init_mmx_flags(png_structp png_ptr)
{
  libpng_detail::ClearMmxAndAsmFlags(png_ptr);
}
