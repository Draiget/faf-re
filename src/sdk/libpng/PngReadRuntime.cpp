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
#include <cmath>

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
void  png_calculate_crc(png_structp png_ptr, std::uint8_t* ptr, std::uint32_t length);
void  png_warning(png_structp png_ptr, const char* message);
void  png_format_buffer(png_structp png_ptr, char* buffer, const char* error_message);
void  png_chunk_error(png_structp png_ptr, const char* error_message);
void  png_chunk_warning(png_structp png_ptr, const char* warning_message);
int   png_crc_error(png_structp png_ptr);
void* png_malloc_warn(png_structp png_ptr, std::uint32_t size);
void* png_malloc(png_structp png_ptr, std::uint32_t size);
void  png_free(png_structp png_ptr, void* ptr);
void  png_check_chunk_name(png_structp png_ptr, const std::uint8_t* chunk_name);
void  png_set_unknown_chunks(png_structp png_ptr, png_infop info_ptr, png_unknown_chunkp unknowns, int num_unknowns);
int   png_handle_as_unknown(png_structp png_ptr, const std::uint8_t* chunk_name);
void  png_combine_row(png_structp png_ptr, std::uint8_t* row, int mask);
void  png_read_filter_row(png_structp png_ptr, void* row_info,
                          std::uint8_t* row, std::uint8_t* prev_row, int filter);
void  png_read_finish_row(png_structp png_ptr);
void  png_read_start_row(png_structp png_ptr);
void  png_init_read_transformations(png_structp png_ptr);  // FUN_009E674D (defined below)
void  png_build_gamma_table(png_structp png_ptr);           // FUN_009E6044 (defined below)
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
int   inflateReset(z_stream_s* strm);
int   inflateInit_(z_stream_s* strm, const char* version, int stream_size);
void  png_memset_check(png_structp png_ptr, void* s, int value, std::uint32_t length);

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
 * Address: 0x00A211E5 (FUN_00A211E5)
 * Mangled: png_crc_read
 *
 * IDA signature:
 * void __cdecl png_crc_read(png_structp png_ptr, png_bytep buf, png_size_t length);
 *
 * What it does:
 * Reads `length` bytes into `buf` through the registered read callback, then
 * folds those bytes into the running chunk CRC. This is the single primitive
 * every chunk handler uses to consume chunk payload while keeping the CRC in
 * sync (called from the read chunk-dispatch and each png_handle_* body).
 */
extern "C" void png_crc_read(png_structp png_ptr, std::uint8_t* buf, std::uint32_t length)
{
  png_push_fill_buffer(png_ptr, buf, length);
  png_calculate_crc(png_ptr, buf, length);
}

/**
 * Address: 0x00A2118A (FUN_00A2118A)
 * Mangled: png_get_uint_32
 *
 * IDA signature:
 * png_uint_32 __cdecl png_get_uint_32(png_bytep buf);
 *
 * What it does:
 * Reads a 32-bit big-endian (network byte order) integer from a 4-byte buffer.
 * Used across the read path to decode chunk lengths and integer chunk fields.
 * The binary spells this as nested shift-adds; the shift-or form below is the
 * identical libpng expression (bytes never overlap).
 */
extern "C" unsigned long png_get_uint_32(const std::uint8_t* buf)
{
  return (static_cast<unsigned long>(buf[0]) << 24) |
         (static_cast<unsigned long>(buf[1]) << 16) |
         (static_cast<unsigned long>(buf[2]) << 8) |
         static_cast<unsigned long>(buf[3]);
}

/**
 * Address: 0x00A211AD (FUN_00A211AD)
 * Mangled: png_get_int_32
 *
 * IDA signature:
 * png_int_32 __cdecl png_get_int_32(png_bytep buf);
 *
 * What it does:
 * Reads a signed 32-bit big-endian integer from a 4-byte buffer (the signed
 * companion to png_get_uint_32, used for oFFs/pCAL offset fields). The bit
 * pattern is assembled in unsigned arithmetic and reinterpreted as signed.
 */
extern "C" int png_get_int_32(const std::uint8_t* buf)
{
  return static_cast<int>((static_cast<std::uint32_t>(buf[0]) << 24) |
                          (static_cast<std::uint32_t>(buf[1]) << 16) |
                          (static_cast<std::uint32_t>(buf[2]) << 8) |
                          static_cast<std::uint32_t>(buf[3]));
}

/**
 * Address: 0x00A211D0 (FUN_00A211D0)
 * Mangled: png_get_uint_16
 *
 * IDA signature:
 * png_uint_16 __cdecl png_get_uint_16(png_bytep buf);
 *
 * What it does:
 * Reads a 16-bit big-endian integer from a 2-byte buffer (chunk fields such as
 * tIME year, hIST entries, sPLT samples).
 */
extern "C" std::uint16_t png_get_uint_16(const std::uint8_t* buf)
{
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(buf[0]) << 8) |
                                    static_cast<std::uint16_t>(buf[1]));
}

/**
 * Address: 0x009E75E2 (FUN_009E75E2)
 * Mangled: png_format_buffer
 *
 * What it does:
 * Renders the current 4-byte chunk name into `buffer`, hex-escaping any byte
 * outside the printable ranges [0x29..0x5A] or [0x61..0x7A] as "[HH]"; then,
 * when `error_message` is non-null, appends ": " followed by up to 64 bytes of
 * the message (NUL-terminating the 64th). Produces the chunk-tagged text that
 * png_chunk_error / png_chunk_warning hand to png_error / png_warning.
 */
extern "C" void png_format_buffer(png_structp png_ptr, char* buffer, const char* error_message)
{
  using namespace libpng_layout;

  // byte_D63374 in the binary; verified "0123456789ABCDEF" byte-for-byte from
  // the shipped PE .rdata at VA 0x00D63374.
  static constexpr char kHexDigits[] = "0123456789ABCDEF";

  int iout = 0;
  for (int iin = 0; iin < 4; ++iin) {
    const int c = Field<std::uint8_t>(png_ptr, kOffChunkName + static_cast<std::size_t>(iin));
    // Binary isnonalpha (FUN_009E75E2): emit verbatim only for c in [0x29..0x5A]
    // or [0x61..0x7A]; hex-escape everything else.
    if (static_cast<unsigned>(c - 0x29) > 0x51u || (c > 0x5A && c < 0x61)) {
      buffer[iout++] = '[';
      buffer[iout++] = kHexDigits[(c >> 4) & 0x0F];
      buffer[iout++] = kHexDigits[c & 0x0F];
      buffer[iout++] = ']';
    } else {
      buffer[iout++] = static_cast<char>(c);
    }
  }

  if (error_message == nullptr) {
    buffer[iout] = '\0';
  } else {
    buffer[iout++] = ':';
    buffer[iout++] = ' ';
    std::memcpy(buffer + iout, error_message, 0x40);
    buffer[iout + 0x3F] = '\0';
  }
}

/**
 * Address: 0x009E787D (FUN_009E787D)
 * Mangled: png_chunk_error
 *
 * What it does:
 * Formats the chunk-tagged error text and raises a fatal png_error (does not
 * return in practice; png_error longjmps to the caller's setjmp buffer).
 */
extern "C" void png_chunk_error(png_structp png_ptr, const char* error_message)
{
  char message[0x54];  // 16 ("[HH]"*4) + 2 (": ") + 64 text + NUL fits in 84
  png_format_buffer(png_ptr, message, error_message);
  png_error(png_ptr, message);
}

/**
 * Address: 0x009E78AB (FUN_009E78AB)
 * Mangled: png_chunk_warning
 *
 * What it does:
 * Formats the chunk-tagged warning text and reports it via png_warning.
 */
extern "C" void png_chunk_warning(png_structp png_ptr, const char* warning_message)
{
  char message[0x54];
  png_format_buffer(png_ptr, message, warning_message);
  png_warning(png_ptr, message);
}

/**
 * Address: 0x00A211FF (FUN_00A211FF)
 * Mangled: png_crc_error
 *
 * What it does:
 * Reads the 4-byte stored chunk CRC (always consumed to keep the stream
 * aligned) and reports whether it mismatches the running computed CRC. The
 * check is suppressed (returns 0) for ancillary chunks with both
 * CRC_ANCILLARY_USE|NOWARN set (flags & 0x300 == 0x300) and for critical
 * chunks with CRC_CRITICAL_IGNORE set (flags & 0x800).
 */
extern "C" int png_crc_error(png_structp png_ptr)
{
  using namespace libpng_layout;

  int need_crc = 1;
  if ((Field<std::uint8_t>(png_ptr, kOffChunkName) & 0x20) != 0) {
    if ((Flags(png_ptr) & 0x300u) == 0x300u) {
      need_crc = 0;
    }
  } else {
    if ((Flags(png_ptr) & 0x800u) != 0) {
      need_crc = 0;
    }
  }

  std::uint8_t crc_bytes[4];
  png_push_fill_buffer(png_ptr, crc_bytes, 4);
  if (need_crc == 0) {
    return 0;
  }
  return png_get_uint_32(crc_bytes) != Field<std::uint32_t>(png_ptr, kOffCrc);
}

/**
 * Address: 0x00A21FCC (FUN_00A21FCC)
 * Mangled: png_crc_finish
 *
 * What it does:
 * Consumes `skip` remaining payload bytes of the current chunk through the CRC
 * in zbuf-sized reads, then validates the chunk CRC. On mismatch, raises a
 * fatal png_chunk_error for critical chunks (unless CRC_CRITICAL_USE) and for
 * ancillary chunks flagged CRC_ANCILLARY_NOWARN; otherwise emits a
 * png_chunk_warning. Returns 1 on CRC error, 0 when the CRC matched.
 */
extern "C" int png_crc_finish(png_structp png_ptr, std::uint32_t skip)
{
  using namespace libpng_layout;

  const std::uint32_t zbufSize = Field<std::uint32_t>(png_ptr, kOffZbufSize);
  std::uint32_t remaining = skip;
  while (remaining > zbufSize) {
    png_crc_read(png_ptr, Field<std::uint8_t*>(png_ptr, kOffZbuf), zbufSize);
    remaining -= zbufSize;
  }
  if (remaining != 0) {
    png_crc_read(png_ptr, Field<std::uint8_t*>(png_ptr, kOffZbuf), remaining);
  }

  if (png_crc_error(png_ptr) == 0) {
    return 0;
  }

  const std::uint8_t nameByte = Field<std::uint8_t>(png_ptr, kOffChunkName);
  const std::uint16_t flags = Field<std::uint16_t>(png_ptr, kOffFlags);
  if (((nameByte & 0x20) == 0 || (flags & 0x200) != 0) &&
      ((nameByte & 0x20) != 0 || (flags & 0x400) == 0)) {
    png_chunk_error(png_ptr, "CRC error");
  }
  png_chunk_warning(png_ptr, "CRC error");
  return 1;
}

namespace {
// libpng isnonalpha as compiled in this build (FUN_009E75E2 / FUN_00A21599):
// a chunk-name byte is legal only when it lies in [0x29..0x5A] or [0x61..0x7A].
[[nodiscard]] inline bool IsNonAlphaChunkByte(int c) noexcept
{
  return static_cast<unsigned>(c - 0x29) > 0x51u || (c > 0x5A && c < 0x61);
}

// Signature of a user-registered unknown-chunk callback (read_user_chunk_fn):
// returns >0 if it consumed the chunk, 0 to defer, <0 on error.
using png_user_chunk_ptr = int (*)(png_structp, png_unknown_chunkp);
} // namespace

/**
 * Address: 0x00A21165 (FUN_00A21165)
 * Mangled: png_malloc_warn
 *
 * What it does:
 * Allocates `size` bytes with PNG_FLAG_MALLOC_NULL_MEM_OK (0x100000) set for
 * the duration, so png_malloc returns nullptr on failure instead of raising a
 * fatal error; the prior flags are restored before returning.
 */
extern "C" void* png_malloc_warn(png_structp png_ptr, std::uint32_t size)
{
  using namespace libpng_layout;

  const std::uint32_t saved_flags = Flags(png_ptr);
  Flags(png_ptr) = saved_flags | 0x100000u;
  void* const result = png_malloc(png_ptr, size);
  Flags(png_ptr) = saved_flags;
  return result;
}

/**
 * Address: 0x00A21599 (FUN_00A21599)
 * Mangled: png_check_chunk_name
 *
 * What it does:
 * Validates that all four chunk-name bytes are legal PNG chunk characters;
 * raises a fatal png_chunk_error("invalid chunk type") if any is out of range.
 */
extern "C" void png_check_chunk_name(png_structp png_ptr, const std::uint8_t* chunk_name)
{
  if (IsNonAlphaChunkByte(chunk_name[0]) || IsNonAlphaChunkByte(chunk_name[1]) ||
      IsNonAlphaChunkByte(chunk_name[2]) || IsNonAlphaChunkByte(chunk_name[3])) {
    png_chunk_error(png_ptr, "invalid chunk type");
  }
}

/**
 * Address: 0x009E9B7A (FUN_009E9B7A)
 * Mangled: png_set_unknown_chunks
 *
 * What it does:
 * Appends `num_unknowns` unknown-chunk records to info_ptr's stored array:
 * grows it via png_malloc_warn, copies the existing entries, then deep-copies
 * each new record's name and payload (payload via png_malloc, tagging its
 * location with the low byte of png_ptr->mode). Marks the array owned for free
 * (free_me |= 0x200). Silently no-ops when out of memory.
 */
extern "C" void png_set_unknown_chunks(png_structp png_ptr, png_infop info_ptr,
                                       png_unknown_chunkp unknowns, int num_unknowns)
{
  using namespace libpng_layout;

  if (png_ptr == nullptr || info_ptr == nullptr || num_unknowns == 0) {
    return;
  }

  const std::uint32_t old_num = info_ptr->unknown_chunks_num;
  auto* const np = static_cast<png_unknown_chunkp>(
      png_malloc_warn(png_ptr, 0x14u * (static_cast<std::uint32_t>(num_unknowns) + old_num)));
  if (np == nullptr) {
    png_warning(png_ptr, "Out of memory while processing unknown chunk.");
    return;
  }

  std::memcpy(np, info_ptr->unknown_chunks, 0x14u * old_num);
  png_free(png_ptr, info_ptr->unknown_chunks);
  info_ptr->unknown_chunks = nullptr;

  for (int i = 0; i < num_unknowns; ++i) {
    png_unknown_chunkp dest = &np[old_num + static_cast<std::uint32_t>(i)];
    const png_unknown_chunk& src = unknowns[i];
    std::strcpy(reinterpret_cast<char*>(dest->name), reinterpret_cast<const char*>(src.name));
    dest->data = static_cast<std::uint8_t*>(png_malloc(png_ptr, src.size));
    if (dest->data != nullptr) {
      std::memcpy(dest->data, src.data, src.size);
      dest->size = src.size;
      dest->location = static_cast<std::uint8_t>(Mode(png_ptr));
    } else {
      png_warning(png_ptr, "Out of memory while processing unknown chunk.");
    }
  }

  info_ptr->unknown_chunks = np;
  info_ptr->unknown_chunks_num += static_cast<std::uint32_t>(num_unknowns);
  info_ptr->free_me |= 0x200u;
}

/**
 * Address: 0x00A23A29 (FUN_00A23A29)
 * Mangled: png_handle_unknown
 *
 * What it does:
 * Reads a chunk that has no dedicated handler. Marks PNG_AFTER_IDAT for a
 * non-IDAT chunk seen after IDAT, validates the chunk name, and errors on an
 * unknown critical chunk that neither a keep-rule nor a user callback accepts.
 * When PNG_FLAG_KEEP_UNKNOWN_CHUNKS is clear the payload is simply CRC-skipped;
 * otherwise it is read and offered to any user chunk callback, and (unless the
 * callback consumed it) stored into info_ptr via png_set_unknown_chunks.
 */
extern "C" void png_handle_unknown(png_structp png_ptr, png_infop info_ptr, std::uint32_t length)
{
  using namespace libpng_layout;

  std::uint8_t* const chunk_name = RawBase(png_ptr) + kOffChunkName;

  if ((Mode(png_ptr) & 4u) != 0 && png_memcmp(chunk_name, "IDAT", 4u) != 0) {
    Mode(png_ptr) |= 8u;  // PNG_AFTER_IDAT
  }
  png_check_chunk_name(png_ptr, chunk_name);

  if ((chunk_name[0] & 0x20) == 0
      && png_handle_as_unknown(png_ptr, chunk_name) != 3
      && Field<png_user_chunk_ptr>(png_ptr, kOffReadUserChunkFn) == nullptr) {
    png_chunk_error(png_ptr, "unknown critical chunk");
  }

  // The binary tests SLOWORD(flags) >= 0 — i.e. PNG_FLAG_KEEP_UNKNOWN_CHUNKS
  // (0x8000, the sign bit of the low 16 flag bits) is clear: skip the chunk.
  if (static_cast<std::int16_t>(Field<std::uint16_t>(png_ptr, kOffFlags)) >= 0) {
    png_crc_finish(png_ptr, length);
    return;
  }

  png_unknown_chunk chunk;
  std::strcpy(reinterpret_cast<char*>(chunk.name), reinterpret_cast<const char*>(chunk_name));
  chunk.data = static_cast<std::uint8_t*>(png_malloc(png_ptr, length));
  chunk.size = length;
  png_crc_read(png_ptr, chunk.data, length);

  const png_user_chunk_ptr read_user_chunk_fn =
      Field<png_user_chunk_ptr>(png_ptr, kOffReadUserChunkFn);
  bool store = false;
  if (read_user_chunk_fn == nullptr) {
    store = true;
  } else if (read_user_chunk_fn(png_ptr, &chunk) <= 0) {
    if ((chunk_name[0] & 0x20) == 0 && png_handle_as_unknown(png_ptr, chunk_name) != 3) {
      png_free(png_ptr, chunk.data);
      png_chunk_error(png_ptr, "unknown critical chunk");
    }
    store = true;
  }
  if (store) {
    png_set_unknown_chunks(png_ptr, info_ptr, &chunk, 1);
  }

  png_free(png_ptr, chunk.data);
  png_crc_finish(png_ptr, 0);
}

/**
 * Address: 0x00A21C16 (FUN_00A21C16)
 * Mangled: png_read_filter_row
 *
 * What it does:
 * Reconstructs one decoded scanline in place by undoing its PNG row filter
 * (None/Sub/Up/Average/Paeth) using the previous scanline. `bpp` is the filter
 * stride in bytes ((pixel_depth+7)/8). An unrecognized filter byte is warned
 * about and the row's first byte zeroed, matching the binary.
 */
extern "C" void png_read_filter_row(png_structp png_ptr, void* row_info_raw,
                                    std::uint8_t* row, std::uint8_t* prev_row, int filter)
{
  if (filter == 0) {
    return;  // PNG_FILTER_VALUE_NONE: bytes already final.
  }

  const auto* const row_info = static_cast<const png_row_info*>(row_info_raw);
  const std::uint32_t rowbytes = row_info->rowbytes;
  const std::uint32_t bpp = (static_cast<std::uint32_t>(row_info->pixel_depth) + 7u) >> 3;

  switch (filter) {
    case 1:  // Sub: predictor is the pixel bpp bytes to the left.
      for (std::uint32_t i = bpp; i < rowbytes; ++i) {
        row[i] = static_cast<std::uint8_t>(row[i] + row[i - bpp]);
      }
      break;

    case 2:  // Up: predictor is the pixel directly above.
      for (std::uint32_t i = 0; i < rowbytes; ++i) {
        row[i] = static_cast<std::uint8_t>(row[i] + prev_row[i]);
      }
      break;

    case 3:  // Average: mean of left and above (left = 0 for the first pixel).
      for (std::uint32_t i = 0; i < bpp; ++i) {
        row[i] = static_cast<std::uint8_t>(row[i] + (prev_row[i] >> 1));
      }
      for (std::uint32_t i = bpp; i < rowbytes; ++i) {
        row[i] = static_cast<std::uint8_t>(
            row[i] + ((static_cast<int>(prev_row[i]) + row[i - bpp]) >> 1));
      }
      break;

    case 4:  // Paeth: nearest of left/above/upper-left by the Paeth predictor.
      for (std::uint32_t i = 0; i < bpp; ++i) {
        row[i] = static_cast<std::uint8_t>(row[i] + prev_row[i]);
      }
      for (std::uint32_t i = bpp; i < rowbytes; ++i) {
        const int a = row[i - bpp];       // left
        const int b = prev_row[i];        // above
        const int c = prev_row[i - bpp];  // upper-left
        const int pa = std::abs(b - c);
        const int pb = std::abs(a - c);
        const int pc = std::abs(a + b - 2 * c);
        int pred = a;
        if (pa > pb || pa > pc) {
          pred = (pb > pc) ? c : b;
        }
        row[i] = static_cast<std::uint8_t>(row[i] + pred);
      }
      break;

    default:
      png_warning(png_ptr, "Ignoring bad adaptive filter type");
      row[0] = 0;
      break;
  }
}

/**
 * Address: 0x00A2106A (FUN_00A2106A)
 * Mangled: png_memcpy_check
 *
 * What it does:
 * Copies `length` bytes from `src` to `dst`. The length bound check present in
 * some libpng builds compiled away here to a plain memcpy; png_ptr is unused.
 */
extern "C" void png_memcpy_check(png_structp png_ptr, void* dst, void* src, std::uint32_t length)
{
  (void)png_ptr;
  std::memcpy(dst, src, length);
}

/**
 * Address: 0x009E6646 (FUN_009E6646)
 * Mangled: png_do_read_intrapixel
 *
 * What it does:
 * Reverses MNG intrapixel differencing on an RGB/RGBA scanline: restores each
 * pixel's red and blue channels by adding back its green channel (8-bit) or the
 * 16-bit big-endian green sample (16-bit). No-op for non-RGB color types or
 * non-8/16 bit depths. `row_addr_plus1` is the pixel data (row buffer + 1,
 * past the filter byte); `row_info_raw` aliases the png_row_info at +0x100.
 */
extern "C" void png_do_read_intrapixel(int* row_info_raw, std::uint32_t row_addr_plus1)
{
  const auto* const row_info = reinterpret_cast<const png_row_info*>(row_info_raw);
  if ((row_info->color_type & 2) == 0) {
    return;
  }

  const std::uint32_t width = row_info->width;
  auto* const row = reinterpret_cast<std::uint8_t*>(static_cast<std::uintptr_t>(row_addr_plus1));

  if (row_info->bit_depth == 8) {
    int bytes_per_pixel;
    if (row_info->color_type == 2) {
      bytes_per_pixel = 3;
    } else if (row_info->color_type == 6) {
      bytes_per_pixel = 4;
    } else {
      return;
    }
    for (std::uint32_t i = 0; i < width; ++i) {
      std::uint8_t* const rp = row + static_cast<std::size_t>(i) * bytes_per_pixel;
      const std::uint8_t green = rp[1];
      rp[0] = static_cast<std::uint8_t>(rp[0] + green);
      rp[2] = static_cast<std::uint8_t>(rp[2] + green);
    }
  } else if (row_info->bit_depth == 16) {
    int bytes_per_pixel;
    if (row_info->color_type == 2) {
      bytes_per_pixel = 6;
    } else if (row_info->color_type == 6) {
      bytes_per_pixel = 8;
    } else {
      return;
    }
    for (std::uint32_t i = 0; i < width; ++i) {
      std::uint8_t* const rp = row + static_cast<std::size_t>(i) * bytes_per_pixel;
      const int green = (rp[2] << 8) | rp[3];
      const int red = ((rp[0] << 8) | rp[1]) + green;
      const int blue = ((rp[4] << 8) | rp[5]) + green;
      rp[0] = static_cast<std::uint8_t>(red >> 8);
      rp[1] = static_cast<std::uint8_t>(red);
      rp[4] = static_cast<std::uint8_t>(blue >> 8);
      rp[5] = static_cast<std::uint8_t>(blue);
    }
  }
}

namespace {
// Adam7 interlace pass geometry (png_uint_32[7]), verified byte-for-byte from
// the shipped PE .rdata: png_pass_start @0x00D62B88, png_pass_inc @0x00D62BA4,
// png_pass_ystart @0x00D62BC0, png_pass_yinc @0x00D62BDC.
constexpr std::uint32_t kPngPassStart[7]  = {0, 4, 0, 2, 0, 1, 0};
constexpr std::uint32_t kPngPassInc[7]    = {8, 8, 4, 4, 2, 2, 1};
constexpr std::uint32_t kPngPassYStart[7] = {0, 0, 4, 0, 2, 0, 1};
constexpr std::uint32_t kPngPassYInc[7]   = {8, 8, 8, 4, 4, 2, 2};
} // namespace

/**
 * Address: 0x00A2107F (FUN_00A2107F)
 * Mangled: png_memset_check
 *
 * What it does:
 * Fills `length` bytes at `s` with `value`. The length bound check present in
 * some libpng builds compiled away here to a plain memset; png_ptr is unused.
 */
extern "C" void png_memset_check(png_structp png_ptr, void* s, int value, std::uint32_t length)
{
  (void)png_ptr;
  std::memset(s, value, length);
}

/**
 * Address: 0x00A23B54 (FUN_00A23B54)
 * Mangled: png_read_finish_row
 *
 * What it does:
 * Advances past a just-decoded scanline. Within a pass it only bumps
 * row_number. At end-of-pass, for an interlaced image it advances the Adam7
 * pass (recomputing iwidth/irowbytes, and num_rows unless the interlace
 * transform handles expansion), skipping passes with no pixels. After the final
 * pass (or immediately for a non-interlaced image) it drains the remaining
 * IDAT/zlib data to Z_STREAM_END — pulling successive IDAT chunks as needed —
 * warns on any trailing compressed data, then resets the inflate state and
 * marks the datastream complete (PNG_HAVE_IEND | PNG_FLAG_ZLIB_FINISHED).
 */
extern "C" void png_read_finish_row(png_structp png_ptr)
{
  using namespace libpng_layout;

  if (++Field<std::uint32_t>(png_ptr, kOffRowNumber) < Field<std::uint32_t>(png_ptr, kOffNumRows)) {
    return;
  }

  if (*(RawBase(png_ptr) + kOffInterlaced) != 0) {
    Field<std::uint32_t>(png_ptr, kOffRowNumber) = 0;
    png_memset_check(png_ptr, Field<std::uint8_t*>(png_ptr, kOffPrevRow), 0,
                     Field<std::uint32_t>(png_ptr, kOffRowbytes) + 1);

    while (true) {
      const std::uint8_t pass = static_cast<std::uint8_t>(++*(RawBase(png_ptr) + kOffPass));
      if (pass >= 7) {
        break;  // no more passes; finish the datastream below
      }
      const std::uint32_t iwidth =
          (Field<std::uint32_t>(png_ptr, kOffWidth) - kPngPassStart[pass] + kPngPassInc[pass] - 1) /
          kPngPassInc[pass];
      Field<std::uint32_t>(png_ptr, kOffIwidth) = iwidth;
      Field<std::uint32_t>(png_ptr, kOffIrowbytes) =
          ((iwidth * *(RawBase(png_ptr) + kOffPixelDepth) + 7) >> 3) + 1;

      if ((Field<std::uint32_t>(png_ptr, kOffTransformations) & 2) == 0) {
        Field<std::uint32_t>(png_ptr, kOffNumRows) =
            (Field<std::uint32_t>(png_ptr, kOffHeight) - kPngPassYStart[pass] + kPngPassYInc[pass] - 1) /
            kPngPassYInc[pass];
        if (iwidth == 0) {
          continue;  // pass has no pixels; advance to the next one
        }
      }
      return;  // next pass is set up
    }
  }

  if ((Flags(png_ptr) & 0x20u) == 0) {  // PNG_FLAG_ZLIB_FINISHED not yet set
    std::uint8_t scratch = 0;
    Field<std::uint8_t*>(png_ptr, kOffZstreamNextOut) = &scratch;
    Field<std::uint32_t>(png_ptr, kOffZstreamAvailOut) = 1;

    bool extra_seen = false;
    while (true) {
      if (Field<std::uint32_t>(png_ptr, kOffZstreamAvailIn) == 0) {
        while (Field<std::uint32_t>(png_ptr, kOffIdatSize) == 0) {
          png_crc_finish(png_ptr, 0);
          std::uint8_t length_buf[4];
          png_push_fill_buffer(png_ptr, length_buf, 4);
          Field<std::uint32_t>(png_ptr, kOffIdatSize) = png_get_uint_32(length_buf);
          png_reset_crc(png_ptr);
          png_crc_read(png_ptr, RawBase(png_ptr) + kOffChunkName, 4);
          if (png_memcmp(RawBase(png_ptr) + kOffChunkName, "IDAT", 4u) != 0) {
            png_error(png_ptr, "Not enough image data");
          }
        }
        std::uint32_t avail_in = Field<std::uint32_t>(png_ptr, kOffZbufSize);
        if (avail_in > Field<std::uint32_t>(png_ptr, kOffIdatSize)) {
          avail_in = Field<std::uint32_t>(png_ptr, kOffIdatSize);
        }
        Field<std::uint32_t>(png_ptr, kOffZstreamAvailIn) = avail_in;
        Field<std::uint8_t*>(png_ptr, kOffZstreamNextIn) = Field<std::uint8_t*>(png_ptr, kOffZbuf);
        png_crc_read(png_ptr, Field<std::uint8_t*>(png_ptr, kOffZbuf), avail_in);
        Field<std::uint32_t>(png_ptr, kOffIdatSize) -= avail_in;
      }

      const int ret = inflate(reinterpret_cast<z_stream_s*>(RawBase(png_ptr) + kOffZstream), 1);
      if (ret == 1) {  // Z_STREAM_END
        break;
      }
      if (ret != 0) {
        const char* msg = Field<const char*>(png_ptr, kOffZstreamMsg);
        if (msg == nullptr) {
          msg = "Decompression Error";
        }
        png_error(png_ptr, msg);
      }
      if (Field<std::uint32_t>(png_ptr, kOffZstreamAvailOut) == 0) {
        png_warning(png_ptr, "Extra compressed data.");
        extra_seen = true;
        break;
      }
    }

    if (!extra_seen &&
        (Field<std::uint32_t>(png_ptr, kOffZstreamAvailOut) == 0 ||
         Field<std::uint32_t>(png_ptr, kOffZstreamAvailIn) != 0 ||
         Field<std::uint32_t>(png_ptr, kOffIdatSize) != 0)) {
      png_warning(png_ptr, "Extra compressed data");
    }

    Mode(png_ptr) |= 8u;
    Flags(png_ptr) |= 0x20u;
    Field<std::uint32_t>(png_ptr, kOffZstreamAvailOut) = 0;
  }

  if (Field<std::uint32_t>(png_ptr, kOffIdatSize) != 0 ||
      Field<std::uint32_t>(png_ptr, kOffZstreamAvailIn) != 0) {
    png_warning(png_ptr, "Extra compression data");
  }
  inflateReset(reinterpret_cast<z_stream_s*>(RawBase(png_ptr) + kOffZstream));
  Mode(png_ptr) |= 8u;
}

// ============================================================================
// Read-transform initialization: gamma tables + one-time transform setup.
// png_build_gamma_table (FUN_009E6044) + png_init_read_transformations
// (FUN_009E674D). Transcribed from the embedded wxWindows 2.4.2 libpng 1.2.x
// source (pngrtran.c) and verified 1:1 against the binary .asm.
// ============================================================================

namespace {

// pngrtran.c:3895  static int png_gamma_shift[] = {...};  (in-binary at 0x00F37DE0)
constexpr int kPngGammaShift[8] = {0x10, 0x21, 0x42, 0x84, 0x110, 0x248, 0x550, 0xff0};

// libpng PNG_MAX_GAMMA_8: pngrtran uses (16 - PNG_MAX_GAMMA_8) == 5 (asm push 5).
constexpr int kPngMaxGamma8 = 11;

// pngconf.h PNG_GAMMA_THRESHOLD.
constexpr double kPngGammaThreshold = 0.05;

// png_composite() accurate macro form: temp = fg*a + bg*(255-a) + 128;
// composite = (temp + (temp>>8)) >> 8.  FA compiled this variant (add si,80h).
[[nodiscard]] inline std::uint8_t PngComposite8(std::uint32_t fg,
                                                std::uint32_t alpha,
                                                std::uint32_t bg) noexcept
{
  const std::uint16_t temp = static_cast<std::uint16_t>(
      static_cast<std::uint16_t>(fg) * static_cast<std::uint16_t>(alpha) +
      static_cast<std::uint16_t>(bg) *
          static_cast<std::uint16_t>(255 - static_cast<std::uint16_t>(alpha)) +
      static_cast<std::uint16_t>(128));
  return static_cast<std::uint8_t>((temp + (temp >> 8)) >> 8);
}

// One 256-entry 16-bit gamma sub-table: malloc 512 bytes, fill via pow(). This
// is the identical inner body pngrtran.c emits for gamma_16_table (non-bg
// branch), gamma_16_to_1 and gamma_16_from_1, so it is lifted once.
[[nodiscard]] inline std::uint16_t* PngBuildGamma16SubTable(png_structp png_ptr,
                                                            int i, int shift, double g)
{
  using namespace libpng_layout;
  auto* const sub =
      static_cast<std::uint16_t*>(png_malloc(png_ptr, 256u * sizeof(std::uint16_t)));
  const std::uint32_t ig =
      (static_cast<std::uint32_t>(i) *
       static_cast<std::uint32_t>(kPngGammaShift[shift])) >> 4;
  for (int j = 0; j < 256; ++j) {
    sub[j] = static_cast<std::uint16_t>(
        std::pow(static_cast<double>(ig + (static_cast<std::uint32_t>(j) << 8)) / 65535.0, g) *
            65535.0 +
        .5);
  }
  return sub;
}

void InitReadTransformGammaBackgroundPalette(png_structp png_ptr);
void InitReadTransformGammaBackgroundNonPalette(png_structp png_ptr);

}  // namespace

/**
 * Address: 0x009E6044 (FUN_009E6044)
 * Mangled: png_build_gamma_table  (libpng 1.2.x, PRIVATE)
 *
 * IDA signature:
 * void __usercall png_build_gamma_table(png_structp png_ptr);
 * (the xmm0..xmm7 args in the raw IDA prototype are SSE-scratch noise the
 *  decompiler attaches to the variadic-looking pow() thunk; png_ptr is the only
 *  real argument.)
 *
 * What it does:
 * Builds the 8- or 16-bit gamma lookup tables from png_ptr->gamma and
 * screen_gamma using pow(). For bit_depth<=8 fills gamma_table, plus
 * gamma_to_1/gamma_from_1 when BACKGROUND|RGB_TO_GRAY is set. For >8-bit builds
 * the segmented gamma_16_table (a run-length fill when 16_TO_8|BACKGROUND is
 * set, else a per-cell pow() fill), plus gamma_16_to_1/gamma_16_from_1 when
 * BACKGROUND|RGB_TO_GRAY is set. Rounding is (cast)(pow(...)*scale + .5).
 */
extern "C" void png_build_gamma_table(png_structp png_ptr)
{
  using namespace libpng_layout;

  // gamma @0x15C is a 32-bit float (asm fcomp dword ptr [esi+15Ch]).
  if (Field<float>(png_ptr, kOffGamma) == 0.0f) {
    return;
  }

  const double gamma_d        = static_cast<double>(Field<float>(png_ptr, kOffGamma));
  const double screen_gamma_d = static_cast<double>(Field<float>(png_ptr, kOffScreenGamma));
  const std::uint32_t transformations = Field<std::uint32_t>(png_ptr, kOffTransformations);

  if (BitDepth(png_ptr) <= 8) {
    double g;
    if (screen_gamma_d > .000001) {
      g = 1.0 / (gamma_d * screen_gamma_d);
    } else {
      g = 1.0;
    }

    auto* const gamma_table = static_cast<std::uint8_t*>(png_malloc(png_ptr, 256u));
    Field<std::uint8_t*>(png_ptr, kOffGammaTable) = gamma_table;
    for (int i = 0; i < 256; ++i) {
      gamma_table[i] = static_cast<std::uint8_t>(
          std::pow(static_cast<double>(i) / 255.0, g) * 255.0 + .5);
    }

    if ((transformations & (kPngBackground | kPngRgbToGray)) != 0) {
      g = 1.0 / gamma_d;
      auto* const gamma_to_1 = static_cast<std::uint8_t*>(png_malloc(png_ptr, 256u));
      Field<std::uint8_t*>(png_ptr, kOffGammaTo1) = gamma_to_1;
      for (int i = 0; i < 256; ++i) {
        gamma_to_1[i] = static_cast<std::uint8_t>(
            std::pow(static_cast<double>(i) / 255.0, g) * 255.0 + .5);
      }

      auto* const gamma_from_1 = static_cast<std::uint8_t*>(png_malloc(png_ptr, 256u));
      Field<std::uint8_t*>(png_ptr, kOffGammaFrom1) = gamma_from_1;
      if (screen_gamma_d > .000001) {
        g = 1.0 / screen_gamma_d;
      } else {
        g = gamma_d;  // probably doing rgb_to_gray
      }
      for (int i = 0; i < 256; ++i) {
        gamma_from_1[i] = static_cast<std::uint8_t>(
            std::pow(static_cast<double>(i) / 255.0, g) * 255.0 + .5);
      }
    }
    return;
  }

  // ---- 16-bit path ----
  double g;
  int sig_bit;
  if ((ColorType(png_ptr) & kPngColorMaskColor) != 0) {
    sig_bit = static_cast<int>(Field<std::uint8_t>(png_ptr, kOffSigBitRed));
    if (static_cast<int>(Field<std::uint8_t>(png_ptr, kOffSigBitGreen)) > sig_bit) {
      sig_bit = Field<std::uint8_t>(png_ptr, kOffSigBitGreen);
    }
    if (static_cast<int>(Field<std::uint8_t>(png_ptr, kOffSigBitBlue)) > sig_bit) {
      sig_bit = Field<std::uint8_t>(png_ptr, kOffSigBitBlue);
    }
  } else {
    sig_bit = static_cast<int>(Field<std::uint8_t>(png_ptr, kOffSigBitGray));
  }

  int shift;
  if (sig_bit > 0) {
    shift = 16 - sig_bit;
  } else {
    shift = 0;
  }
  if ((transformations & kPng16To8) != 0) {
    if (shift < (16 - kPngMaxGamma8)) {
      shift = (16 - kPngMaxGamma8);
    }
  }
  if (shift > 8) shift = 8;
  if (shift < 0) shift = 0;

  Field<std::uint8_t>(png_ptr, kOffGammaShift) = static_cast<std::uint8_t>(shift);
  const int num = (1 << (8 - shift));

  if (screen_gamma_d > .000001) {
    g = 1.0 / (gamma_d * screen_gamma_d);
  } else {
    g = 1.0;
  }

  auto* const gamma_16_table = static_cast<std::uint16_t**>(
      png_malloc(png_ptr, static_cast<std::uint32_t>(num) * sizeof(std::uint16_t*)));
  Field<std::uint16_t**>(png_ptr, kOffGamma16Table) = gamma_16_table;

  if ((transformations & (kPng16To8 | kPngBackground)) != 0) {
    for (int i = 0; i < num; ++i) {
      gamma_16_table[i] = static_cast<std::uint16_t*>(
          png_malloc(png_ptr, 256u * sizeof(std::uint16_t)));
    }

    g = 1.0 / g;
    std::uint32_t last = 0;
    const double num_shifted = static_cast<double>(static_cast<std::uint32_t>(num) << 8);
    for (int i = 0; i < 256; ++i) {
      const double fout = (static_cast<double>(i) + 0.5) / 256.0;
      const double fin  = std::pow(fout, g);
      const std::uint32_t max = static_cast<std::uint32_t>(fin * num_shifted);
      while (last <= max) {
        gamma_16_table[static_cast<int>(last & (0xffu >> shift))]
                      [static_cast<int>(last >> (8 - shift))] =
            static_cast<std::uint16_t>(static_cast<std::uint16_t>(i) |
                                       (static_cast<std::uint16_t>(i) << 8));
        ++last;
      }
    }
    while (last < (static_cast<std::uint32_t>(num) << 8)) {
      gamma_16_table[static_cast<int>(last & (0xffu >> shift))]
                    [static_cast<int>(last >> (8 - shift))] =
          static_cast<std::uint16_t>(65535L);
      ++last;
    }
  } else {
    for (int i = 0; i < num; ++i) {
      gamma_16_table[i] = PngBuildGamma16SubTable(png_ptr, i, shift, g);
    }
  }

  if ((transformations & (kPngBackground | kPngRgbToGray)) != 0) {
    // gamma_16_to_1 built first (stored at 0x178).
    g = 1.0 / gamma_d;
    auto* const gamma_16_to_1 = static_cast<std::uint16_t**>(
        png_malloc(png_ptr, static_cast<std::uint32_t>(num) * sizeof(std::uint16_t*)));
    Field<std::uint16_t**>(png_ptr, kOffGamma16To1) = gamma_16_to_1;
    for (int i = 0; i < num; ++i) {
      gamma_16_to_1[i] = PngBuildGamma16SubTable(png_ptr, i, shift, g);
    }

    // gamma_16_from_1 (stored at 0x174).
    if (screen_gamma_d > .000001) {
      g = 1.0 / screen_gamma_d;
    } else {
      g = gamma_d;  // probably doing rgb_to_gray
    }
    auto* const gamma_16_from_1 = static_cast<std::uint16_t**>(
        png_malloc(png_ptr, static_cast<std::uint32_t>(num) * sizeof(std::uint16_t*)));
    Field<std::uint16_t**>(png_ptr, kOffGamma16From1) = gamma_16_from_1;
    for (int i = 0; i < num; ++i) {
      gamma_16_from_1[i] = PngBuildGamma16SubTable(png_ptr, i, shift, g);
    }
  }
}

namespace {

// pngrtran.c:784-881 — PNG_BACKGROUND + PALETTE gamma composite.
void InitReadTransformGammaBackgroundPalette(png_structp png_ptr)
{
  using namespace libpng_layout;

  auto* const palette     = Field<std::uint8_t*>(png_ptr, kOffPalette);
  const int   num_palette = static_cast<int>(Field<std::uint16_t>(png_ptr, kOffNumPalette));
  const std::uint8_t bg_gamma_type = Field<std::uint8_t>(png_ptr, kOffBackgroundGammaType);

  std::uint8_t back_r, back_g, back_b;
  std::uint8_t back1_r, back1_g, back1_b;

  const std::uint8_t bg_red   = static_cast<std::uint8_t>(Field<std::uint16_t>(png_ptr, kOffBackgroundRed));
  const std::uint8_t bg_green = static_cast<std::uint8_t>(Field<std::uint16_t>(png_ptr, kOffBackgroundGreen));
  const std::uint8_t bg_blue  = static_cast<std::uint8_t>(Field<std::uint16_t>(png_ptr, kOffBackgroundBlue));

  if (bg_gamma_type == kPngBackgroundGammaFile) {
    const std::uint8_t* const gamma_table = Field<std::uint8_t*>(png_ptr, kOffGammaTable);
    const std::uint8_t* const gamma_to_1  = Field<std::uint8_t*>(png_ptr, kOffGammaTo1);
    back_r  = gamma_table[bg_red];  back_g  = gamma_table[bg_green];  back_b  = gamma_table[bg_blue];
    back1_r = gamma_to_1[bg_red];   back1_g = gamma_to_1[bg_green];   back1_b = gamma_to_1[bg_blue];
  } else {
    double g, gs;
    const double gamma_d        = static_cast<double>(Field<float>(png_ptr, kOffGamma));
    const double screen_gamma_d = static_cast<double>(Field<float>(png_ptr, kOffScreenGamma));
    const double bg_gamma_d     = static_cast<double>(Field<float>(png_ptr, kOffBackgroundGamma));
    switch (bg_gamma_type) {
      case kPngBackgroundGammaScreen: g = screen_gamma_d;   gs = 1.0;                                 break;
      case kPngBackgroundGammaFile:   g = 1.0 / gamma_d;    gs = 1.0 / (gamma_d * screen_gamma_d);    break;
      case kPngBackgroundGammaUnique: g = 1.0 / bg_gamma_d; gs = 1.0 / (bg_gamma_d * screen_gamma_d); break;
      default:                        g = 1.0;              gs = 1.0;                                 break;
    }

    if (std::fabs(gs - 1.0) < kPngGammaThreshold) {
      back_r = bg_red;  back_g = bg_green;  back_b = bg_blue;
    } else {
      back_r = static_cast<std::uint8_t>(std::pow(static_cast<double>(bg_red)   / 255, gs) * 255.0 + .5);
      back_g = static_cast<std::uint8_t>(std::pow(static_cast<double>(bg_green) / 255, gs) * 255.0 + .5);
      back_b = static_cast<std::uint8_t>(std::pow(static_cast<double>(bg_blue)  / 255, gs) * 255.0 + .5);
    }
    back1_r = static_cast<std::uint8_t>(std::pow(static_cast<double>(bg_red)   / 255, g) * 255.0 + .5);
    back1_g = static_cast<std::uint8_t>(std::pow(static_cast<double>(bg_green) / 255, g) * 255.0 + .5);
    back1_b = static_cast<std::uint8_t>(std::pow(static_cast<double>(bg_blue)  / 255, g) * 255.0 + .5);
  }

  const int num_trans = static_cast<int>(Field<std::uint16_t>(png_ptr, kOffNumTrans));
  const std::uint8_t* const trans        = Field<std::uint8_t*>(png_ptr, kOffTrans);
  const std::uint8_t* const gamma_to_1   = Field<std::uint8_t*>(png_ptr, kOffGammaTo1);
  const std::uint8_t* const gamma_from_1 = Field<std::uint8_t*>(png_ptr, kOffGammaFrom1);
  const std::uint8_t* const gamma_table  = Field<std::uint8_t*>(png_ptr, kOffGammaTable);

  for (int i = 0; i < num_palette; ++i) {
    std::uint8_t* const e = palette + 3u * i;  // png_color is 3 bytes
    if (i < num_trans && trans[i] != 0xff) {
      if (trans[i] == 0) {
        e[0] = back_r;  e[1] = back_g;  e[2] = back_b;
      } else {
        std::uint8_t v, w;
        v = gamma_to_1[e[0]];  w = PngComposite8(v, trans[i], back1_r);  e[0] = gamma_from_1[w];
        v = gamma_to_1[e[1]];  w = PngComposite8(v, trans[i], back1_g);  e[1] = gamma_from_1[w];
        v = gamma_to_1[e[2]];  w = PngComposite8(v, trans[i], back1_b);  e[2] = gamma_from_1[w];
      }
    } else {
      e[0] = gamma_table[e[0]];  e[1] = gamma_table[e[1]];  e[2] = gamma_table[e[2]];
    }
  }
}

// pngrtran.c:883-938 — PNG_BACKGROUND + non-PALETTE gamma composite.
void InitReadTransformGammaBackgroundNonPalette(png_structp png_ptr)
{
  using namespace libpng_layout;

  const double m = static_cast<double>(
      static_cast<std::uint32_t>((1u << BitDepth(png_ptr)) - 1u));
  double g  = 1.0;
  double gs = 1.0;

  const double gamma_d        = static_cast<double>(Field<float>(png_ptr, kOffGamma));
  const double screen_gamma_d = static_cast<double>(Field<float>(png_ptr, kOffScreenGamma));
  const double bg_gamma_d     = static_cast<double>(Field<float>(png_ptr, kOffBackgroundGamma));
  switch (Field<std::uint8_t>(png_ptr, kOffBackgroundGammaType)) {
    case kPngBackgroundGammaScreen: g = screen_gamma_d;   gs = 1.0;                                 break;
    case kPngBackgroundGammaFile:   g = 1.0 / gamma_d;    gs = 1.0 / (gamma_d * screen_gamma_d);    break;
    case kPngBackgroundGammaUnique: g = 1.0 / bg_gamma_d; gs = 1.0 / (bg_gamma_d * screen_gamma_d); break;
    default: break;
  }

  auto bg = [&](std::size_t off) -> std::uint16_t& { return Field<std::uint16_t>(png_ptr, off); };

  bg(kOffBackground1Gray) = static_cast<std::uint16_t>(std::pow(static_cast<double>(bg(kOffBackgroundGray)) / m, g)  * m + .5);
  bg(kOffBackgroundGray)  = static_cast<std::uint16_t>(std::pow(static_cast<double>(bg(kOffBackgroundGray)) / m, gs) * m + .5);

  if (bg(kOffBackgroundRed) != bg(kOffBackgroundGreen) ||
      bg(kOffBackgroundRed) != bg(kOffBackgroundBlue) ||
      bg(kOffBackgroundRed) != bg(kOffBackgroundGray)) {
    bg(kOffBackground1Red)   = static_cast<std::uint16_t>(std::pow(static_cast<double>(bg(kOffBackgroundRed))   / m, g) * m + .5);
    bg(kOffBackground1Green) = static_cast<std::uint16_t>(std::pow(static_cast<double>(bg(kOffBackgroundGreen)) / m, g) * m + .5);
    bg(kOffBackground1Blue)  = static_cast<std::uint16_t>(std::pow(static_cast<double>(bg(kOffBackgroundBlue))  / m, g) * m + .5);
    bg(kOffBackgroundRed)    = static_cast<std::uint16_t>(std::pow(static_cast<double>(bg(kOffBackgroundRed))   / m, gs) * m + .5);
    bg(kOffBackgroundGreen)  = static_cast<std::uint16_t>(std::pow(static_cast<double>(bg(kOffBackgroundGreen)) / m, gs) * m + .5);
    bg(kOffBackgroundBlue)   = static_cast<std::uint16_t>(std::pow(static_cast<double>(bg(kOffBackgroundBlue))  / m, gs) * m + .5);
  } else {
    bg(kOffBackground1Red) = bg(kOffBackground1Green) = bg(kOffBackground1Blue) = bg(kOffBackground1Gray);
    bg(kOffBackgroundRed)  = bg(kOffBackgroundGreen)  = bg(kOffBackgroundBlue)  = bg(kOffBackgroundGray);
  }
}

}  // namespace

/**
 * Address: 0x009E674D (FUN_009E674D)
 * Mangled: png_init_read_transformations  (libpng 1.2.x, PRIVATE)
 *
 * What it does:
 * One-time read-setup dispatcher, run from png_read_start_row before the first
 * row. Expands the background chunk for gray/palette images, snapshots
 * background_1 = background, drops PNG_GAMMA for fully opaque/transparent
 * palettes, then (if GAMMA|RGB_TO_GRAY) builds the gamma tables and applies
 * gamma+background compositing to the palette / background values. Finally, for
 * palette images, applies a no-gamma background composite (if BACKGROUND) and
 * the PNG_SHIFT right-shifts. (The PNG_INVERT_ALPHA tRNS-invert block and the
 * PNG_USELESS_TESTS null-check present in the reference source were not compiled
 * into this binary; the .asm has neither.)
 */
extern "C" void png_init_read_transformations(png_structp png_ptr)
{
  using namespace libpng_layout;

  const int color_type = static_cast<int>(ColorType(png_ptr));

  // ---- Background-expand for gray / palette ----
  if ((Transformations(png_ptr) & kPngBackgroundExpand) != 0 &&
      (Transformations(png_ptr) & kPngExpand) != 0) {
    if ((color_type & kPngColorMaskColor) == 0) {  // GRAY or GRAY_ALPHA
      switch (BitDepth(png_ptr)) {
        case 1:
          Field<std::uint16_t>(png_ptr, kOffBackgroundGray) *= static_cast<std::uint16_t>(0xff);
          Field<std::uint16_t>(png_ptr, kOffBackgroundRed) =
          Field<std::uint16_t>(png_ptr, kOffBackgroundGreen) =
          Field<std::uint16_t>(png_ptr, kOffBackgroundBlue) =
              Field<std::uint16_t>(png_ptr, kOffBackgroundGray);
          break;
        case 2:
          Field<std::uint16_t>(png_ptr, kOffBackgroundGray) *= static_cast<std::uint16_t>(0x55);
          Field<std::uint16_t>(png_ptr, kOffBackgroundRed) =
          Field<std::uint16_t>(png_ptr, kOffBackgroundGreen) =
          Field<std::uint16_t>(png_ptr, kOffBackgroundBlue) =
              Field<std::uint16_t>(png_ptr, kOffBackgroundGray);
          break;
        case 4:
          Field<std::uint16_t>(png_ptr, kOffBackgroundGray) *= static_cast<std::uint16_t>(0x11);
          Field<std::uint16_t>(png_ptr, kOffBackgroundRed) =
          Field<std::uint16_t>(png_ptr, kOffBackgroundGreen) =
          Field<std::uint16_t>(png_ptr, kOffBackgroundBlue) =
              Field<std::uint16_t>(png_ptr, kOffBackgroundGray);
          break;
        case 8:
        case 16:
          Field<std::uint16_t>(png_ptr, kOffBackgroundRed) =
          Field<std::uint16_t>(png_ptr, kOffBackgroundGreen) =
          Field<std::uint16_t>(png_ptr, kOffBackgroundBlue) =
              Field<std::uint16_t>(png_ptr, kOffBackgroundGray);
          break;
        default:
          break;
      }
    } else if (color_type == kColorTypePalette) {
      const std::uint8_t* const pal_entry =
          Field<std::uint8_t*>(png_ptr, kOffPalette) +
          3u * Field<std::uint8_t>(png_ptr, kOffBackgroundIndex);
      Field<std::uint16_t>(png_ptr, kOffBackgroundRed)   = pal_entry[0];
      Field<std::uint16_t>(png_ptr, kOffBackgroundGreen) = pal_entry[1];
      Field<std::uint16_t>(png_ptr, kOffBackgroundBlue)  = pal_entry[2];
    }
  }

  // background_1 = background (10-byte png_color_16 copy).
  Field<std::uint16_t>(png_ptr, kOffBackground1Index) = Field<std::uint16_t>(png_ptr, kOffBackgroundIndex);
  Field<std::uint16_t>(png_ptr, kOffBackground1Red)   = Field<std::uint16_t>(png_ptr, kOffBackgroundRed);
  Field<std::uint16_t>(png_ptr, kOffBackground1Green) = Field<std::uint16_t>(png_ptr, kOffBackgroundGreen);
  Field<std::uint16_t>(png_ptr, kOffBackground1Blue)  = Field<std::uint16_t>(png_ptr, kOffBackgroundBlue);
  Field<std::uint16_t>(png_ptr, kOffBackground1Gray)  = Field<std::uint16_t>(png_ptr, kOffBackgroundGray);

  // ---- Drop PNG_GAMMA for fully opaque/transparent palettes ----
  if (color_type == kColorTypePalette &&
      Field<std::uint16_t>(png_ptr, kOffNumTrans) != 0 &&
      std::fabs(static_cast<double>(Field<float>(png_ptr, kOffScreenGamma)) *
                    static_cast<double>(Field<float>(png_ptr, kOffGamma)) -
                1.0) < kPngGammaThreshold) {
    int k = 0;
    const std::uint8_t* const trans = Field<std::uint8_t*>(png_ptr, kOffTrans);
    const int istop = static_cast<int>(Field<std::uint16_t>(png_ptr, kOffNumTrans));
    for (int i = 0; i < istop; ++i) {
      if (trans[i] != 0 && trans[i] != 0xff) {
        k = 1;  // partial transparency present
      }
    }
    if (k == 0) {
      Transformations(png_ptr) &= ~kPngGamma;
    }
  }

  // ---- Gamma / RGB-to-gray path ----
  if ((Transformations(png_ptr) & (kPngGamma | kPngRgbToGray)) != 0) {
    png_build_gamma_table(png_ptr);

    if ((Transformations(png_ptr) & kPngBackground) != 0) {
      if (color_type == kColorTypePalette) {
        InitReadTransformGammaBackgroundPalette(png_ptr);
      } else {
        InitReadTransformGammaBackgroundNonPalette(png_ptr);
      }
    } else if (color_type == kColorTypePalette) {
      // palette[i].rgb = gamma_table[palette[i].rgb]
      const std::uint16_t num_palette = Field<std::uint16_t>(png_ptr, kOffNumPalette);
      auto* const palette = Field<std::uint8_t*>(png_ptr, kOffPalette);
      const std::uint8_t* const gamma_table = Field<std::uint8_t*>(png_ptr, kOffGammaTable);
      for (std::uint16_t i = 0; i < num_palette; ++i) {
        std::uint8_t* const e = palette + 3u * i;
        e[0] = gamma_table[e[0]];  e[1] = gamma_table[e[1]];  e[2] = gamma_table[e[2]];
      }
    }
  } else if ((Transformations(png_ptr) & kPngBackground) != 0 &&
             color_type == kColorTypePalette) {
    // ---- No-gamma background composite for palette ----
    const int istop = static_cast<int>(Field<std::uint16_t>(png_ptr, kOffNumTrans));
    auto* const palette = Field<std::uint8_t*>(png_ptr, kOffPalette);
    const std::uint8_t* const trans = Field<std::uint8_t*>(png_ptr, kOffTrans);
    const std::uint8_t back_r = static_cast<std::uint8_t>(Field<std::uint16_t>(png_ptr, kOffBackgroundRed));
    const std::uint8_t back_g = static_cast<std::uint8_t>(Field<std::uint16_t>(png_ptr, kOffBackgroundGreen));
    const std::uint8_t back_b = static_cast<std::uint8_t>(Field<std::uint16_t>(png_ptr, kOffBackgroundBlue));
    for (int i = 0; i < istop; ++i) {
      std::uint8_t* const e = palette + 3u * i;
      if (trans[i] == 0) {
        e[0] = back_r;  e[1] = back_g;  e[2] = back_b;
      } else if (trans[i] != 0xff) {
        e[0] = PngComposite8(e[0], trans[i], back_r);
        e[1] = PngComposite8(e[1], trans[i], back_g);
        e[2] = PngComposite8(e[2], trans[i], back_b);
      }
    }
  }

  // ---- PNG_SHIFT for palette ----
  if ((Transformations(png_ptr) & kPngShift) != 0 && color_type == kColorTypePalette) {
    int sr = 8 - Field<std::uint8_t>(png_ptr, kOffSigBitRed);
    int sg = 8 - Field<std::uint8_t>(png_ptr, kOffSigBitGreen);
    int sb = 8 - Field<std::uint8_t>(png_ptr, kOffSigBitBlue);
    if (sr < 0 || sr > 8) sr = 0;
    if (sg < 0 || sg > 8) sg = 0;
    if (sb < 0 || sb > 8) sb = 0;
    const std::uint16_t istop = Field<std::uint16_t>(png_ptr, kOffNumPalette);
    auto* const palette = Field<std::uint8_t*>(png_ptr, kOffPalette);
    for (std::uint16_t i = 0; i < istop; ++i) {
      std::uint8_t* const e = palette + 3u * i;
      e[0] >>= sr;  e[1] >>= sg;  e[2] >>= sb;
    }
  }
}

/**
 * Address: 0x00A21D8F (FUN_00A21D8F)
 * Mangled: png_read_start_row
 *
 * What it does:
 * Prepares row decoding: initializes the read transformations, sets the first
 * pass's iwidth/irowbytes/num_rows (Adam7 geometry for interlaced images, full
 * dimensions otherwise), then computes the maximum pixel depth any enabled
 * transformation can produce and allocates the working row buffer (row_buf, 32
 * bytes into big_row_buf) and the zeroed previous-row buffer accordingly.
 * Finally sets PNG_FLAG_ROW_INIT.
 */
extern "C" void png_read_start_row(png_structp png_ptr)
{
  using namespace libpng_layout;

  Field<std::uint32_t>(png_ptr, kOffZstreamAvailIn) = 0;
  png_init_read_transformations(png_ptr);

  const std::uint32_t width = Field<std::uint32_t>(png_ptr, kOffWidth);
  const std::uint32_t transformations = Field<std::uint32_t>(png_ptr, kOffTransformations);

  if (*(RawBase(png_ptr) + kOffInterlaced) != 0) {
    std::uint32_t num_rows = Field<std::uint32_t>(png_ptr, kOffHeight);
    if ((transformations & 2) == 0) {  // interlace not expanded by a transform
      num_rows = (num_rows + 7) / 8;   // pass 0 covers every 8th row
    }
    Field<std::uint32_t>(png_ptr, kOffNumRows) = num_rows;

    const std::uint8_t pass = *(RawBase(png_ptr) + kOffPass);
    const std::uint32_t iwidth =
        (width - kPngPassStart[pass] + kPngPassInc[pass] - 1) / kPngPassInc[pass];
    Field<std::uint32_t>(png_ptr, kOffIwidth) = iwidth;
    Field<std::uint32_t>(png_ptr, kOffIrowbytes) =
        ((iwidth * *(RawBase(png_ptr) + kOffPixelDepth) + 7) >> 3) + 1;
  } else {
    Field<std::uint32_t>(png_ptr, kOffNumRows) = Field<std::uint32_t>(png_ptr, kOffHeight);
    Field<std::uint32_t>(png_ptr, kOffIwidth) = width;
    Field<std::uint32_t>(png_ptr, kOffIrowbytes) = Field<std::uint32_t>(png_ptr, kOffRowbytes) + 1;
  }

  // Largest pixel depth any enabled transformation can yield (governs row-buffer size).
  int max_pixel_depth = *(RawBase(png_ptr) + kOffPixelDepth);
  const std::uint8_t color_type = *(RawBase(png_ptr) + kOffColorType);
  const std::uint8_t bit_depth  = *(RawBase(png_ptr) + kOffBitDepth);
  const std::uint16_t num_trans = Field<std::uint16_t>(png_ptr, kOffNumTrans);

  if ((transformations & 4) != 0 && bit_depth < 8) {
    max_pixel_depth = 8;
  }

  if ((transformations & 0x1000) != 0) {  // PNG_EXPAND
    if (color_type == 3) {
      max_pixel_depth = 8 * (num_trans != 0) + 24;
    } else if (color_type != 0) {
      if (color_type == 2 && num_trans != 0) {
        max_pixel_depth = 4 * max_pixel_depth / 3;
      }
    } else {
      if (max_pixel_depth < 8) {
        max_pixel_depth = 8;
      }
      if (num_trans != 0) {
        max_pixel_depth *= 2;
      }
    }
  }

  if ((transformations & 0x8000) != 0) {  // PNG_FILLER
    if (color_type == 3) {
      max_pixel_depth = 32;
    } else if (color_type == 0) {
      max_pixel_depth = (max_pixel_depth > 8) ? 32 : 16;
    } else if (color_type == 2) {
      max_pixel_depth = (max_pixel_depth > 32) ? 64 : 32;
    }
  }

  if ((transformations & 0x4000) != 0) {  // PNG_GRAY_TO_RGB
    if ((num_trans != 0 && (transformations & 0x1000) != 0) ||
        (transformations & 0x8000) != 0 || color_type == 4) {
      max_pixel_depth = (max_pixel_depth > 16) ? 64 : 32;
    } else if (max_pixel_depth > 8) {
      max_pixel_depth = (color_type != 6) ? 48 : 64;
    } else {
      max_pixel_depth = 8 * (color_type == 6) + 24;
    }
  }

  if ((transformations & 0x100000) != 0) {  // PNG_USER_TRANSFORM
    const int user_depth = *(RawBase(png_ptr) + kOffUserTransformDepth) *
                           *(RawBase(png_ptr) + kOffUserTransformChannels);
    if (user_depth > max_pixel_depth) {
      max_pixel_depth = user_depth;
    }
  }

  auto* const big_row_buf = static_cast<std::uint8_t*>(png_malloc(
      png_ptr,
      ((static_cast<std::uint32_t>(max_pixel_depth) * ((width + 7) & ~7u) + 7) >> 3) +
          ((max_pixel_depth + 7) >> 3) + 65));
  Field<std::uint8_t*>(png_ptr, kOffBigRowBuf) = big_row_buf;
  Field<std::uint8_t*>(png_ptr, kOffRowBuf) = big_row_buf + 32;

  const std::uint32_t prev_row_size = Field<std::uint32_t>(png_ptr, kOffRowbytes) + 1;
  auto* const prev_row = static_cast<std::uint8_t*>(png_malloc(png_ptr, prev_row_size));
  Field<std::uint8_t*>(png_ptr, kOffPrevRow) = prev_row;
  png_memset_check(png_ptr, prev_row, 0, prev_row_size);

  Flags(png_ptr) |= 0x40u;  // PNG_FLAG_ROW_INIT
}

/**
 * Address: 0x00A2186D (FUN_00A2186D)
 * Mangled: png_do_read_interlace
 *
 * What it does:
 * Expands one sparse Adam7 interlace-pass scanline in place into a full-width
 * row: each source pixel is replicated png_pass_inc[pass] times so the pass
 * pixels land at their final horizontal positions. Walks source and destination
 * pointers backwards from the end of the row, honoring PNG_PACKSWAP bit order,
 * with per-depth destination masks for 1/2/4-bit sub-byte packing and whole-byte
 * memcpy for >=8-bit pixels, then rewrites row_info width/rowbytes to the
 * expanded dimensions. This build reads everything from png_ptr (row_buf +0xEC,
 * transformations +0x70, pass +0x124, row_info sub-struct +0x100).
 */
extern "C" void png_do_read_interlace(png_structp png_ptr)
{
  using namespace libpng_layout;

  auto* const row_info = reinterpret_cast<png_row_info*>(RawBase(png_ptr) + 0x100);
  std::uint8_t* const row = Field<std::uint8_t*>(png_ptr, kOffRowBuf) + 1;  // skip filter byte
  const std::uint32_t transformations = Field<std::uint32_t>(png_ptr, kOffTransformations);

  // Binary guard: row_buf != (void*)-1 (i.e. row != null) and png_ptr's row_info
  // pointer non-null. In practice always true once the row buffers are allocated.
  if (row == nullptr || row_info == nullptr) {
    return;
  }

  const std::uint32_t width       = row_info->width;
  const std::uint8_t  pixel_depth = row_info->pixel_depth;
  const std::uint8_t  pass        = *(RawBase(png_ptr) + kOffPass);
  const std::uint32_t pass_inc    = kPngPassInc[pass];
  const std::uint32_t final_width = width * pass_inc;

  constexpr std::uint32_t PNG_PACKSWAP = 0x10000;
  const bool packswap = (transformations & PNG_PACKSWAP) != 0;

  switch (pixel_depth) {
    case 1: {
      std::uint8_t* sp = row + ((width - 1) >> 3);
      std::uint8_t* dp = row + ((final_width - 1) >> 3);
      int sshift, dshift, s_start, s_end, s_inc;
      if (packswap) {
        sshift = static_cast<int>((width - 1) & 7);
        dshift = static_cast<int>((final_width - 1) & 7);
        s_start = 7; s_end = 0; s_inc = -1;
      } else {
        sshift = 7 - static_cast<int>((width - 1) & 7);
        dshift = 7 - static_cast<int>((final_width - 1) & 7);
        s_start = 0; s_end = 7; s_inc = 1;
      }
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint8_t v = static_cast<std::uint8_t>((*sp >> sshift) & 0x01);
        for (std::uint32_t j = 0; j < pass_inc; ++j) {
          *dp = static_cast<std::uint8_t>(
              (v << dshift) | (*dp & static_cast<std::uint8_t>(0x7F7F >> (7 - dshift))));
          if (dshift == s_end) { dshift = s_start; --dp; } else { dshift += s_inc; }
        }
        if (sshift == s_end) { sshift = s_start; --sp; } else { sshift += s_inc; }
      }
      break;
    }

    case 2: {
      std::uint8_t* sp = row + ((width - 1) >> 2);
      std::uint8_t* dp = row + ((final_width - 1) >> 2);
      int sshift, dshift, s_start, s_end, s_inc;
      if (packswap) {
        sshift = static_cast<int>((2 * width - 1) & 6);
        dshift = static_cast<int>((2 * final_width - 1) & 6);
        s_start = 6; s_end = 0; s_inc = -2;
      } else {
        sshift = 2 * (3 - static_cast<int>((width - 1) & 3));
        dshift = 2 * (3 - static_cast<int>((final_width - 1) & 3));
        s_start = 0; s_end = 6; s_inc = 2;
      }
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint8_t v = static_cast<std::uint8_t>((*sp >> sshift) & 0x03);
        for (std::uint32_t j = 0; j < pass_inc; ++j) {
          *dp = static_cast<std::uint8_t>(
              (v << dshift) | (*dp & static_cast<std::uint8_t>(0x3F3F >> (6 - dshift))));
          if (dshift == s_end) { dshift = s_start; --dp; } else { dshift += s_inc; }
        }
        if (sshift == s_end) { sshift = s_start; --sp; } else { sshift += s_inc; }
      }
      break;
    }

    case 4: {
      std::uint8_t* sp = row + ((width - 1) >> 1);
      std::uint8_t* dp = row + ((final_width - 1) >> 1);
      int sshift, dshift, s_start, s_end, s_inc;
      if (packswap) {
        sshift = static_cast<int>((-1 - 4 * width) & 4);
        dshift = static_cast<int>((-1 - 4 * final_width) & 4);
        s_start = 4; s_end = 0; s_inc = -4;
      } else {
        sshift = 4 - 4 * static_cast<int>((width - 1) & 1);
        dshift = 4 - 4 * static_cast<int>((final_width - 1) & 1);
        s_start = 0; s_end = 4; s_inc = 4;
      }
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint8_t v = static_cast<std::uint8_t>((*sp >> sshift) & 0x0F);
        for (std::uint32_t j = 0; j < pass_inc; ++j) {
          *dp = static_cast<std::uint8_t>(
              (v << dshift) | (*dp & static_cast<std::uint8_t>(0x0F0F >> (4 - dshift))));
          if (dshift == s_end) { dshift = s_start; --dp; } else { dshift += s_inc; }
        }
        if (sshift == s_end) { sshift = s_start; --sp; } else { sshift += s_inc; }
      }
      break;
    }

    default: {
      // 8-bit and wider: replicate whole pixels (pixel_depth>>3 bytes each).
      const std::size_t bytes_per_pixel = pixel_depth >> 3;
      std::uint8_t* sp = row + bytes_per_pixel * (width - 1);
      std::uint8_t* dp = row + bytes_per_pixel * (final_width - 1);
      std::uint8_t pixel[8];  // scratch: up to a 64-bit (RGBA16) pixel
      for (std::uint32_t i = 0; i < width; ++i) {
        std::memcpy(pixel, sp, bytes_per_pixel);
        for (std::uint32_t j = 0; j < pass_inc; ++j) {
          std::memcpy(dp, pixel, bytes_per_pixel);
          dp -= bytes_per_pixel;
        }
        sp -= bytes_per_pixel;
      }
      break;
    }
  }

  row_info->width = final_width;
  row_info->rowbytes = (static_cast<std::uint32_t>(pixel_depth) * final_width + 7) >> 3;
}

/**
 * Address: 0x00A215FB (FUN_00A215FB)
 * Mangled: png_combine_row
 *
 * What it does:
 * Combines the just-decoded interlace-pass scanline (row_buf + 1) into a
 * display/output row using an 8-bit interlace selector `mask`. The selector
 * starts at 0x80 and rotates right (wrapping to 0x80); for each group of 8
 * pixels, `mask & selector` decides whether the source pixel replaces the
 * destination. mask == 255 is the whole-row memcpy fast path. Sub-byte depths
 * (1/2/4) merge the selected pixel into the packed destination byte with a
 * keep-mask honoring PNG_PACKSWAP; 8-bit-and-wider copies pixel_depth>>3 bytes.
 */
extern "C" void png_combine_row(png_structp png_ptr, std::uint8_t* row, int mask)
{
  using namespace libpng_layout;

  auto* const row_info = reinterpret_cast<png_row_info*>(RawBase(png_ptr) + 0x100);
  const std::uint8_t pixel_depth = row_info->pixel_depth;

  if (mask == 255) {
    const std::uint32_t width = Field<std::uint32_t>(png_ptr, kOffWidth);
    std::uint8_t* const sp = Field<std::uint8_t*>(png_ptr, kOffRowBuf) + 1;
    std::memcpy(row, sp, (width * pixel_depth + 7) >> 3);
    return;
  }

  std::uint8_t* const src_base = Field<std::uint8_t*>(png_ptr, kOffRowBuf);
  std::uint8_t* dp = row;
  const bool packswap = (Field<std::uint32_t>(png_ptr, kOffTransformations) & 0x10000u) != 0;
  const std::uint32_t width = Field<std::uint32_t>(png_ptr, kOffWidth);

  switch (pixel_depth) {
    case 1: {
      const std::uint8_t* sp = src_base + 1;
      std::uint8_t m = 0x80;
      int s_start, s_end, s_inc;
      if (packswap) { s_start = 0; s_end = 7; s_inc = 1; }
      else          { s_start = 7; s_end = 0; s_inc = -1; }
      int shift = s_start;
      for (std::uint32_t i = 0; i < width; ++i) {
        if (mask & m) {
          const std::uint8_t value = static_cast<std::uint8_t>(((*sp >> shift) & 0x01) << shift);
          *dp = static_cast<std::uint8_t>(value | (*dp & static_cast<std::uint8_t>(0x7F7F >> (7 - shift))));
        }
        if (shift == s_end) { shift = s_start; ++sp; ++dp; } else { shift += s_inc; }
        m = (m == 1) ? 0x80 : static_cast<std::uint8_t>(m >> 1);
      }
      break;
    }

    case 2: {
      const std::uint8_t* sp = src_base + 1;
      std::uint8_t m = 0x80;
      int s_start, s_end, s_inc;
      if (packswap) { s_start = 0; s_end = 6; s_inc = 2; }
      else          { s_start = 6; s_end = 0; s_inc = -2; }
      int shift = s_start;
      for (std::uint32_t i = 0; i < width; ++i) {
        if (mask & m) {
          const std::uint8_t value = static_cast<std::uint8_t>(((*sp >> shift) & 0x03) << shift);
          *dp = static_cast<std::uint8_t>(value | (*dp & static_cast<std::uint8_t>(0x3F3F >> (6 - shift))));
        }
        if (shift == s_end) { shift = s_start; ++sp; ++dp; } else { shift += s_inc; }
        m = (m == 1) ? 0x80 : static_cast<std::uint8_t>(m >> 1);
      }
      break;
    }

    case 4: {
      const std::uint8_t* sp = src_base + 1;
      std::uint8_t m = 0x80;
      int s_start, s_end, s_inc;
      if (packswap) { s_start = 0; s_end = 4; s_inc = 4; }
      else          { s_start = 4; s_end = 0; s_inc = -4; }
      int shift = s_start;
      for (std::uint32_t i = 0; i < width; ++i) {
        if (mask & m) {
          const std::uint8_t value = static_cast<std::uint8_t>(((*sp >> shift) & 0x0F) << shift);
          *dp = static_cast<std::uint8_t>(value | (*dp & static_cast<std::uint8_t>(0x0F0F >> (4 - shift))));
        }
        if (shift == s_end) { shift = s_start; ++sp; ++dp; } else { shift += s_inc; }
        m = (m == 1) ? 0x80 : static_cast<std::uint8_t>(m >> 1);
      }
      break;
    }

    default: {
      // 8-bit and wider: whole-pixel copy of pixel_depth>>3 bytes.
      const std::size_t bytes_per_pixel = pixel_depth >> 3;
      const std::uint8_t* sp = src_base + 1;
      std::uint8_t m = 0x80;
      for (std::uint32_t i = 0; i < width; ++i) {
        if (mask & m) {
          std::memcpy(dp, sp, bytes_per_pixel);
        }
        sp += bytes_per_pixel;
        dp += bytes_per_pixel;
        m = (m == 1) ? 0x80 : static_cast<std::uint8_t>(m >> 1);
      }
      break;
    }
  }
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
  using namespace libpng_layout;

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
  const std::uint32_t height = Field<std::uint32_t>(png_ptr, kOffHeight);
  Field<std::uint32_t>(png_ptr, kOffNumRows) = height;  // num_rows starts at the image height

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
  // Fixed swapped offsets: png_handle_IHDR stores pixel_depth (channels*bit_depth)
  // at 0x129 and channels (1/2/3/4) at 0x12A; png_read_row's binary (FUN_009E1383)
  // copies 0x12A->row_info.channels and 0x129->row_info.pixel_depth. The prior read
  // had these transposed, so row_info.pixel_depth and the row_bytes below were
  // computed from the channel count instead of the true pixel depth.
  const std::uint8_t channels   = *(RawBase(png_ptr) + 0x12A);
  const std::uint8_t pixel_depth= *(RawBase(png_ptr) + 0x129);
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
 * Address: 0x00A2293C (FUN_00A2293C)
 * Mangled: png_handle_sRGB
 *
 * IDA signature:
 * void __cdecl png_handle_sRGB(png_structp png_ptr, png_infop info_ptr, png_size_t length);
 *
 * What it does:
 * Parses an sRGB (rendering intent) chunk: enforces chunk ordering and the
 * 1-byte length, reads the intent, rejects an unknown intent (>= 4), and — when
 * a gAMA or cHRM chunk is already present and disagrees with the canonical sRGB
 * values — warns (echoing the offending gamma). Applies the sRGB gamma +
 * chromaticities via png_set_sRGB_gAMA_and_cHRM.
 */
extern "C" void png_handle_sRGB(png_structp png_ptr, png_infop info_ptr, std::uint32_t length)
{
  using namespace libpng_layout;

  if ((Mode(png_ptr) & kPngHaveIhdr) == 0) {
    png_error(png_ptr, "Missing IHDR before sRGB");
  } else if ((Mode(png_ptr) & kPngHaveIdat) != 0) {
    png_warning(png_ptr, "Invalid sRGB after IDAT");
    png_crc_finish(png_ptr, length);
    return;
  } else if ((Mode(png_ptr) & kPngHavePlte) != 0) {
    png_warning(png_ptr, "Out of place sRGB chunk");
  } else if (info_ptr != nullptr && (info_ptr->valid & kPngInfoSrgb) != 0) {
    png_warning(png_ptr, "Duplicate sRGB chunk");
    png_crc_finish(png_ptr, length);
    return;
  }

  if (length != 1) {
    png_warning(png_ptr, "Incorrect sRGB chunk length");
    png_crc_finish(png_ptr, length);
    return;
  }

  std::uint8_t intent;
  png_crc_read(png_ptr, &intent, 1);
  if (png_crc_finish(png_ptr, 0) != 0) {
    return;
  }

  if (intent >= 4) {
    png_warning(png_ptr, "Unknown sRGB intent");
    return;
  }

  // A present gAMA whose value disagrees with sRGB is ignored (echoing the
  // png_ptr-side fixed-point gamma the binary prints to stderr).
  if ((info_ptr->valid & kPngInfoGamma) != 0) {
    const std::int32_t igamma = info_ptr->int_gamma;
    if (igamma < 45000 || igamma > 46000) {
      png_warning(png_ptr, "Ignoring incorrect gAMA value when sRGB is also present");
      std::fprintf(stderr, "incorrect gamma=(%d/100000)\n",
                   static_cast<int>(Field<std::int32_t>(png_ptr, kOffIntGamma)));
    }
  }

  // A present cHRM whose chromaticities differ from sRGB (by > 0.01) is ignored.
  if ((info_ptr->valid & kPngInfoChrm) != 0 &&
      (std::abs(info_ptr->int_x_white - 31270) > 1000 ||
       std::abs(info_ptr->int_y_white - 32900) > 1000 ||
       std::abs(info_ptr->int_x_red   - 64000) > 1000 ||
       std::abs(info_ptr->int_y_red   - 33000) > 1000 ||
       std::abs(info_ptr->int_x_green - 30000) > 1000 ||
       std::abs(info_ptr->int_y_green - 60000) > 1000 ||
       std::abs(info_ptr->int_x_blue  - 15000) > 1000 ||
       std::abs(info_ptr->int_y_blue  -  6000) > 1000)) {
    png_warning(png_ptr, "Ignoring incorrect cHRM value when sRGB is also present");
  }

  png_set_sRGB_gAMA_and_cHRM(png_ptr, info_ptr, intent);
}

/**
 * Address: 0x00A23718 (FUN_00A23718)
 * Mangled: png_handle_tIME
 *
 * IDA signature:
 * void __cdecl png_handle_tIME(png_structp png_ptr, png_infop info_ptr, png_size_t length);
 *
 * What it does:
 * Parses a tIME (image modification time) chunk: requires IHDR, rejects a
 * duplicate, notes AFTER_IDAT when it arrives past the image data, enforces the
 * 7-byte length, reads the year (big-endian u16) + month/day/hour/minute/second
 * bytes into a png_time, and stores it via png_set_tIME.
 */
extern "C" void png_handle_tIME(png_structp png_ptr, png_infop info_ptr, std::uint32_t length)
{
  using namespace libpng_layout;

  if ((Mode(png_ptr) & kPngHaveIhdr) == 0) {
    png_error(png_ptr, "Out of place tIME chunk");
  }
  if (info_ptr != nullptr && (info_ptr->valid & kPngInfoTime) != 0) {
    png_warning(png_ptr, "Duplicate tIME chunk");
    png_crc_finish(png_ptr, length);
    return;
  }
  if ((Mode(png_ptr) & kPngHaveIdat) != 0) {
    Mode(png_ptr) |= kPngAfterIdat;
  }
  if (length != 7) {
    png_warning(png_ptr, "Incorrect tIME chunk length");
    png_crc_finish(png_ptr, length);
    return;
  }

  std::uint8_t buf[7];
  png_crc_read(png_ptr, buf, 7);
  if (png_crc_finish(png_ptr, 0) != 0) {
    return;
  }

  png_time mod_time;
  mod_time.year   = png_get_uint_16(buf);
  mod_time.month  = buf[2];
  mod_time.day    = buf[3];
  mod_time.hour   = buf[4];
  mod_time.minute = buf[5];
  mod_time.second = buf[6];
  png_set_tIME(png_ptr, info_ptr, reinterpret_cast<const std::uint8_t*>(&mod_time));
}

/**
 * Address: 0x00A2326F (FUN_00A2326F)
 * Mangled: png_handle_pHYs
 *
 * IDA signature:
 * void __cdecl png_handle_pHYs(png_structp png_ptr, png_infop info_ptr, png_size_t length);
 *
 * What it does:
 * Parses a pHYs (physical pixel dimensions) chunk: enforces chunk ordering and
 * the 9-byte length, reads x/y pixels-per-unit (big-endian u32) and the unit
 * byte, and stores them into the info struct via png_set_pHYs.
 */
extern "C" void png_handle_pHYs(png_structp png_ptr, png_infop info_ptr, std::uint32_t length)
{
  using namespace libpng_layout;
  std::uint8_t buf[9];

  if ((Mode(png_ptr) & kPngHaveIhdr) == 0) {
    png_error(png_ptr, "Missing IHDR before pHYs");
  } else if ((Mode(png_ptr) & kPngHaveIdat) != 0) {
    png_warning(png_ptr, "Invalid pHYs after IDAT");
    png_crc_finish(png_ptr, length);
    return;
  } else if (info_ptr != nullptr && (info_ptr->valid & kPngInfoPhys) != 0) {
    png_warning(png_ptr, "Duplicate pHYs chunk");
    png_crc_finish(png_ptr, length);
    return;
  }

  if (length != 9) {
    png_warning(png_ptr, "Incorrect pHYs chunk length");
    png_crc_finish(png_ptr, length);
    return;
  }

  png_crc_read(png_ptr, buf, 9);
  if (png_crc_finish(png_ptr, 0) != 0) {
    return;
  }

  const std::uint32_t res_x = static_cast<std::uint32_t>(png_get_uint_32(buf));
  const std::uint32_t res_y = static_cast<std::uint32_t>(png_get_uint_32(buf + 4));
  png_set_pHYs(png_ptr, info_ptr, res_x, res_y, buf[8]);
}

/**
 * Address: 0x00A23324 (FUN_00A23324)
 * Mangled: png_handle_oFFs
 *
 * IDA signature:
 * void __cdecl png_handle_oFFs(png_structp png_ptr, png_infop info_ptr, png_size_t length);
 *
 * What it does:
 * Parses an oFFs (image offset) chunk: enforces chunk ordering and the 9-byte
 * length, reads x/y offsets (big-endian signed i32) and the unit byte, and
 * stores them into the info struct via png_set_oFFs.
 */
extern "C" void png_handle_oFFs(png_structp png_ptr, png_infop info_ptr, std::uint32_t length)
{
  using namespace libpng_layout;
  std::uint8_t buf[9];

  if ((Mode(png_ptr) & kPngHaveIhdr) == 0) {
    png_error(png_ptr, "Missing IHDR before oFFs");
  } else if ((Mode(png_ptr) & kPngHaveIdat) != 0) {
    png_warning(png_ptr, "Invalid oFFs after IDAT");
    png_crc_finish(png_ptr, length);
    return;
  } else if (info_ptr != nullptr && (info_ptr->valid & kPngInfoOffs) != 0) {
    png_warning(png_ptr, "Duplicate oFFs chunk");
    png_crc_finish(png_ptr, length);
    return;
  }

  if (length != 9) {
    png_warning(png_ptr, "Incorrect oFFs chunk length");
    png_crc_finish(png_ptr, length);
    return;
  }

  png_crc_read(png_ptr, buf, 9);
  if (png_crc_finish(png_ptr, 0) != 0) {
    return;
  }

  const std::int32_t offset_x = png_get_int_32(buf);
  const std::int32_t offset_y = png_get_int_32(buf + 4);
  png_set_oFFs(png_ptr, info_ptr, offset_x, offset_y, buf[8]);
}

/**
 * Address: 0x00A222DD (FUN_00A222DD)
 * Mangled: png_handle_IEND
 *
 * IDA signature:
 * void __cdecl png_handle_IEND(png_structp png_ptr, png_infop info_ptr, png_size_t length);
 *
 * What it does:
 * Handles the terminal IEND chunk: errors if the file carried no image (IHDR and
 * IDAT not both seen), marks the stream finished (PNG_AFTER_IDAT | PNG_HAVE_IEND),
 * warns on any non-zero chunk length, and finishes the CRC.
 */
extern "C" void png_handle_IEND(png_structp png_ptr, [[maybe_unused]] png_infop info_ptr,
                                std::uint32_t length)
{
  using namespace libpng_layout;

  if ((Mode(png_ptr) & kPngHaveIhdr) == 0 || (Mode(png_ptr) & kPngHaveIdat) == 0) {
    png_error(png_ptr, "No image in file");
  }
  Mode(png_ptr) |= (kPngAfterIdat | kPngHaveIend);
  if (length != 0) {
    png_warning(png_ptr, "Incorrect IEND chunk length");
  }
  png_crc_finish(png_ptr, length);
}

/**
 * Address: 0x00A2244A (FUN_00A2244A)
 * Mangled: png_handle_sBIT
 *
 * IDA signature:
 * void __cdecl png_handle_sBIT(png_structp png_ptr, png_infop info_ptr, png_size_t length);
 *
 * What it does:
 * Parses an sBIT (significant bits) chunk. Enforces chunk ordering and the
 * per-color-type length (3 for palette, else png_ptr->channels), reads the
 * significant-bit depths into png_ptr->sig_bit (broadcasting the single gray
 * value across r/g/b for grayscale; taking r/g/b/a in order for colour), and
 * stores them into the info struct via png_set_sBIT.
 */
extern "C" void png_handle_sBIT(png_structp png_ptr, png_infop info_ptr, std::uint32_t length)
{
  using namespace libpng_layout;
  std::uint8_t buf[4] = {0, 0, 0, 0};

  if ((Mode(png_ptr) & kPngHaveIhdr) == 0) {
    png_error(png_ptr, "Missing IHDR before sBIT");
  } else if ((Mode(png_ptr) & kPngHaveIdat) != 0) {
    png_warning(png_ptr, "Invalid sBIT after IDAT");
    png_crc_finish(png_ptr, length);
    return;
  } else if ((Mode(png_ptr) & kPngHavePlte) != 0) {
    png_warning(png_ptr, "Out of place sBIT chunk");
  } else if (info_ptr != nullptr && (info_ptr->valid & kPngInfoSbit) != 0) {
    png_warning(png_ptr, "Duplicate sBIT chunk");
    png_crc_finish(png_ptr, length);
    return;
  }

  const std::uint32_t channels =
      (ColorType(png_ptr) == kColorTypePalette) ? 3u
                                                : Field<std::uint8_t>(png_ptr, kOffChannels);
  if (length != channels) {
    png_warning(png_ptr, "Incorrect sBIT chunk length");
    png_crc_finish(png_ptr, length);
    return;
  }

  png_crc_read(png_ptr, buf, channels);
  if (png_crc_finish(png_ptr, 0) != 0) {
    return;
  }

  Field<std::uint8_t>(png_ptr, kOffSigBitRed) = buf[0];
  std::uint8_t alpha_sig;
  if ((ColorType(png_ptr) & kPngColorMaskColor) == 0) {  // grayscale
    Field<std::uint8_t>(png_ptr, kOffSigBitGray)  = buf[0];
    Field<std::uint8_t>(png_ptr, kOffSigBitGreen) = buf[0];
    Field<std::uint8_t>(png_ptr, kOffSigBitBlue)  = buf[0];
    alpha_sig = buf[1];
  } else {  // colour
    Field<std::uint8_t>(png_ptr, kOffSigBitGreen) = buf[1];
    Field<std::uint8_t>(png_ptr, kOffSigBitBlue)  = buf[2];
    alpha_sig = buf[3];
  }
  Field<std::uint8_t>(png_ptr, kOffSigBitAlpha) = alpha_sig;
  png_set_sBIT(png_ptr, info_ptr, RawBase(png_ptr) + kOffSigBitRed);
}

/**
 * Address: 0x00A22320 (FUN_00A22320)
 * Mangled: png_handle_gAMA
 *
 * IDA signature:
 * void __cdecl png_handle_gAMA(png_structp png_ptr, png_infop info_ptr, png_size_t length);
 *
 * What it does:
 * Parses a gAMA (image gamma) chunk. Enforces chunk ordering (IHDR seen, not
 * after IDAT, warn-and-cope if after PLTE, reject a duplicate that is not being
 * overridden by sRGB) and the 4-byte length, reads the fixed-point gamma, and —
 * unless it contradicts an already-present sRGB chunk (in which case it warns
 * and prints the ignored value) — records it into png_ptr->gamma and the info
 * struct via png_set_gAMA / png_set_gAMA_fixed.
 */
extern "C" void png_handle_gAMA(png_structp png_ptr, png_infop info_ptr, std::uint32_t length)
{
  using namespace libpng_layout;
  std::uint8_t buf[4];

  if ((Mode(png_ptr) & kPngHaveIhdr) == 0) {
    png_error(png_ptr, "Missing IHDR before gAMA");
  } else if ((Mode(png_ptr) & kPngHaveIdat) != 0) {
    png_warning(png_ptr, "Invalid gAMA after IDAT");
    png_crc_finish(png_ptr, length);
    return;
  } else if ((Mode(png_ptr) & kPngHavePlte) != 0) {
    png_warning(png_ptr, "Out of place gAMA chunk");
  } else if (info_ptr != nullptr && (info_ptr->valid & kPngInfoGamma) != 0 &&
             (info_ptr->valid & kPngInfoSrgb) == 0) {
    png_warning(png_ptr, "Duplicate gAMA chunk");
    png_crc_finish(png_ptr, length);
    return;
  }

  if (length != 4) {
    png_warning(png_ptr, "Incorrect gAMA chunk length");
    png_crc_finish(png_ptr, length);
    return;
  }

  png_crc_read(png_ptr, buf, 4);
  if (png_crc_finish(png_ptr, 0) != 0) {
    return;
  }

  const std::uint32_t igamma = static_cast<std::uint32_t>(png_get_uint_32(buf));
  if (igamma == 0) {
    png_warning(png_ptr, "Ignoring gAMA chunk with gamma=0");
    return;
  }

  if ((info_ptr->valid & kPngInfoSrgb) != 0 && (igamma < 45000u || igamma > 46000u)) {
    png_warning(png_ptr, "Ignoring incorrect gAMA value when sRGB is also present");
    std::fprintf(stderr, "gamma = (%d/100000)\n", static_cast<int>(igamma));
    return;
  }

  const float file_gamma = static_cast<float>(static_cast<double>(igamma) / 100000.0);
  Field<float>(png_ptr, kOffGamma) = file_gamma;
  png_set_gAMA(png_ptr, info_ptr, file_gamma);
  png_set_gAMA_fixed(png_ptr, info_ptr, static_cast<std::int32_t>(igamma));
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
