// libpng write-path runtime recovery.
// Source: embedded wxWindows 2.4.2 libpng (dependencies/wxWindows-2.4.2/src/png/pngwrite.c).
// The ForgedAlliance.exe binary links libpng statically as png.lib; these recovered
// functions match the binary at their given addresses.

#include "libpng/PngWriteRuntime.h"
#include "libpng/PngStructLayout.h"
#include "libpng/PngCommonRuntime.h"  // png_reset_crc / png_calculate_crc
#include "libpng/PngMemRuntime.h"     // png_zalloc / png_zfree
#include "libpng/PngSetRuntime.h"     // png_info_struct, png_sPLT_t, png_text, png_unknown_chunk

#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" {
void png_save_uint_32(std::uint8_t* buf, std::uint32_t value);
void png_write_chunk(png_structp png_ptr, std::uint8_t* chunk_name, std::uint8_t* data, std::uint32_t length);
void png_write_data(png_structp png_ptr, const std::uint8_t* data, std::uint32_t length);
void png_error(png_structp png_ptr, const char* message);
std::FILE* __cdecl __iob_func(void);
struct z_stream_s;
int deflate(z_stream_s* strm, int flush);
int deflateEnd(z_stream_s* strm);
int deflateReset(z_stream_s* strm);
int deflateInit2_(z_stream_s* strm, int level, int method, int windowBits,
                   int memLevel, int strategy, const char* version, int stream_size);
// Shared read/write-path helper (recovered in PngReadRuntime.cpp @ 0x009E0A5E):
// classifies an unknown chunk name against the user-registered keep list.
int png_handle_as_unknown(png_structp png_ptr, const std::uint8_t* chunk_name);
}

// Fixed-point scale constants from libpng 1.2.x:
//   PNG_WEIGHT_FACTOR = 1 << PNG_WEIGHT_SHIFT = 1 << 8 = 256
//   PNG_COST_FACTOR   = 1 << PNG_COST_SHIFT   = 1 << 3 = 8
static constexpr int kPngWeightFactor = 256;
static constexpr int kPngCostFactor   = 8;
static constexpr double kPngChrmMaxPoint = 0.8;
static constexpr double kPngChrmScale = 100000.0;
static constexpr double kPngRoundBias = 0.5;

/**
 * Address: 0x00A23D8B (FUN_00A23D8B)
 * Mangled: png_save_uint_32
 *
 * IDA signature:
 * png_bytep __cdecl png_save_uint_32(png_bytep buf, png_uint_32 i);
 *
 * What it does:
 * Stores a 32-bit value into a 4-byte buffer in big-endian (network) byte
 * order. The write-path mirror of png_get_uint_32; used to lay down chunk
 * lengths and integer chunk fields (cHRM, pHYs, tIME, ...). The binary returns
 * buf, which every caller discards.
 */
extern "C" void png_save_uint_32(std::uint8_t* buf, std::uint32_t value)
{
  buf[0] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
  buf[1] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
  buf[2] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
  buf[3] = static_cast<std::uint8_t>(value & 0xFF);
}

/**
 * Address: 0x009E9F07 (FUN_009E9F07)
 * Mangled: png_write_data
 *
 * What it does:
 * Writes `length` bytes through the png_struct output callback (+0x4C), or
 * raises png_error when no write function is installed.
 */
extern "C" void png_write_data(png_structp png_ptr, const std::uint8_t* data, std::uint32_t length)
{
  using namespace libpng_layout;
  using png_rw_ptr = void (*)(png_structp, const std::uint8_t*, std::uint32_t);
  const auto write_data_fn = Field<png_rw_ptr>(png_ptr, kOffWriteDataFn);
  if (write_data_fn == nullptr) {
    png_error(png_ptr, "Call to NULL write function");
  }
  write_data_fn(png_ptr, data, length);
}

/**
 * Address: 0x00A23DE4 (FUN_00A23DE4)
 * Mangled: png_write_chunk_start
 *
 * What it does:
 * Emits a chunk header: the 4-byte big-endian length and the 4-byte chunk name,
 * then resets the running CRC and seeds it with the chunk name.
 */
extern "C" void png_write_chunk_start(png_structp png_ptr, const char* chunkName, std::uint32_t length)
{
  std::uint8_t buf[4];
  png_save_uint_32(buf, length);
  png_write_data(png_ptr, buf, 4);
  png_write_data(png_ptr, reinterpret_cast<const std::uint8_t*>(chunkName), 4);
  png_reset_crc(png_ptr);
  png_calculate_crc(png_ptr, reinterpret_cast<std::uint8_t*>(const_cast<char*>(chunkName)), 4);
}

/**
 * Address: 0x00A23E26 (FUN_00A23E26)
 * Mangled: png_write_chunk_data
 *
 * What it does:
 * Folds `length` chunk-payload bytes into the running CRC and writes them out.
 * A null pointer or zero length is a no-op.
 */
extern "C" void png_write_chunk_data(png_structp png_ptr, const std::uint8_t* chunkData, std::uint32_t length)
{
  if (chunkData != nullptr && length != 0) {
    png_calculate_crc(png_ptr, const_cast<std::uint8_t*>(chunkData), length);
    png_write_data(png_ptr, chunkData, length);
  }
}

/**
 * Address: 0x00A23E4E (FUN_00A23E4E)
 * Mangled: png_write_chunk_end
 *
 * What it does:
 * Writes the 4-byte big-endian chunk CRC (png_struct+0x110) that closes a chunk.
 */
extern "C" void png_write_chunk_end(png_structp png_ptr)
{
  using namespace libpng_layout;
  std::uint8_t buf[4];
  png_save_uint_32(buf, Field<std::uint32_t>(png_ptr, kOffCrc));
  png_write_data(png_ptr, buf, 4);
}

/**
 * Address: 0x00A24B64 (FUN_00A24B64)
 * Mangled: png_write_chunk
 *
 * What it does:
 * Writes a complete chunk (header + data + CRC) in one call.
 */
extern "C" void png_write_chunk(png_structp png_ptr, std::uint8_t* chunk_name, std::uint8_t* data, std::uint32_t length)
{
  png_write_chunk_start(png_ptr, reinterpret_cast<const char*>(chunk_name), length);
  png_write_chunk_data(png_ptr, data, length);
  png_write_chunk_end(png_ptr);
}

namespace {
// libpng text-compression state — the `int* compressedState` the write-text
// helpers thread through, laid out as consecutive machine words.
struct PngCompressionState
{
  std::uint8_t*  input;           // +0x00  single pre-formed input buffer (or null)
  std::uint32_t  input_len;       // +0x04
  int            num_output_ptr;  // +0x08  count of accumulated deflate output blocks
  int            max_output_ptr;  // +0x0C  allocated size of output_ptr array
  std::uint8_t** output_ptr;      // +0x10  array of deflate output blocks
};
}  // namespace

/**
 * Address: 0x00A24139 (FUN_00A24139)
 * Mangled: png_write_compressed_data_out
 *
 * What it does:
 * Flushes a text chunk's compressed payload. If the state carries a single
 * pre-formed input buffer it is written directly; otherwise each accumulated
 * deflate output block is written (as full zbuf-sized runs) and freed, the
 * block array is released, any bytes still sitting in zbuf are written, and the
 * deflate stream is reset for reuse.
 */
extern "C" void png_write_compressed_data_out(png_structp png_ptr, int* compressedState)
{
  using namespace libpng_layout;

  auto* const comp = reinterpret_cast<PngCompressionState*>(compressedState);
  const std::uint32_t zbuf_size = Field<std::uint32_t>(png_ptr, kOffZbufSize);

  if (comp->input != nullptr) {
    png_write_chunk_data(png_ptr, comp->input, comp->input_len);
    return;
  }

  for (int i = 0; i < comp->num_output_ptr; ++i) {
    png_write_chunk_data(png_ptr, comp->output_ptr[i], zbuf_size);
    png_free(png_ptr, comp->output_ptr[i]);
    comp->output_ptr[i] = nullptr;
  }
  if (comp->max_output_ptr != 0) {
    png_free(png_ptr, comp->output_ptr);
  }
  comp->output_ptr = nullptr;

  const std::uint32_t avail_out = Field<std::uint32_t>(png_ptr, kOffZstreamAvailOut);
  if (avail_out < zbuf_size) {
    png_write_chunk_data(png_ptr, Field<std::uint8_t*>(png_ptr, kOffZbuf), zbuf_size - avail_out);
  }
  deflateReset(reinterpret_cast<z_stream_s*>(RawBase(png_ptr) + kOffZstream));
}

namespace {
// Append the freshly-filled deflate window (png_ptr->zbuf) to the compression
// state's list of accumulated output blocks, growing the block-pointer array by
// four slots whenever it is exhausted, then rearm the deflate stream so its
// next_out/avail_out point back at the start of zbuf. Lifted out of
// png_text_compress because the binary emits this identical sequence twice — once
// in the Z_NO_FLUSH pass and once in the Z_FINISH flush.
void png_text_compress_store_block(png_structp png_ptr, PngCompressionState* comp, std::uint32_t zbuf_size)
{
  using namespace libpng_layout;

  if (comp->num_output_ptr >= comp->max_output_ptr) {
    std::uint8_t** const old_array = comp->output_ptr;
    const int old_max = comp->max_output_ptr;
    comp->max_output_ptr = comp->num_output_ptr + 4;
    comp->output_ptr = static_cast<std::uint8_t**>(
      png_malloc(png_ptr, 4u * static_cast<std::uint32_t>(comp->max_output_ptr)));
    if (old_array != nullptr) {
      std::memcpy(comp->output_ptr, old_array, 4u * static_cast<std::uint32_t>(old_max));
      png_free(png_ptr, old_array);
    }
  }

  comp->output_ptr[comp->num_output_ptr] =
    static_cast<std::uint8_t*>(png_malloc(png_ptr, zbuf_size));
  std::memcpy(comp->output_ptr[comp->num_output_ptr], Field<std::uint8_t*>(png_ptr, kOffZbuf), zbuf_size);
  ++comp->num_output_ptr;

  Field<std::uint32_t>(png_ptr, kOffZstreamAvailOut) = zbuf_size;
  Field<std::uint8_t*>(png_ptr, kOffZstreamNextOut) = Field<std::uint8_t*>(png_ptr, kOffZbuf);
}
}  // namespace

/**
 * Address: 0x00A23EE2 (FUN_00A23EE2)
 * Mangled: png_text_compress
 *
 * IDA signature:
 * int __usercall png_text_compress@<eax>(png_struct *png_ptr@<edx>,
 *     unsigned int text_len@<ecx>, png_bytepp comp@<esi>, png_bytep text, int compression);
 *
 * What it does:
 * Deflates a text/profile payload into a compression_state (the `int*
 * compressedState` overlay). compression == -1 defers compression: the raw input
 * pointer + length are stashed for a later direct write and the length is
 * returned unchanged. Otherwise the payload is run through zlib deflate() in
 * zbuf-sized chunks (Z_NO_FLUSH until the input is drained, then Z_FINISH to
 * flush the tail); every filled zbuf block is copied into a growing output-block
 * array. Raises png_error on any deflate error or if the final flush does not
 * report Z_STREAM_END. Returns the total compressed byte count. Callers:
 * png_write_iCCP (0x00A24FB5), png_write_zTXt (0x00A2455B).
 */
extern "C" int png_text_compress(
  png_structp png_ptr, char* text, int textLength, int compression, int* compressedState)
{
  using namespace libpng_layout;

  auto* const comp = reinterpret_cast<PngCompressionState*>(compressedState);
  comp->num_output_ptr = 0;
  comp->max_output_ptr = 0;
  comp->output_ptr = nullptr;
  comp->input = nullptr;

  // compression == -1: stash the input for a later verbatim write, no deflate.
  if (compression == -1) {
    comp->input = reinterpret_cast<std::uint8_t*>(text);
    comp->input_len = static_cast<std::uint32_t>(textLength);
    return textLength;
  }

  if (compression >= 3) {
    char msg[52];
    std::sprintf(msg, "Unknown compression type %d", compression);
    png_warning(png_ptr, msg);
  }

  const std::uint32_t zbuf_size = Field<std::uint32_t>(png_ptr, kOffZbufSize);
  Field<std::uint8_t*>(png_ptr, kOffZstreamNextIn) = reinterpret_cast<std::uint8_t*>(text);
  Field<std::uint32_t>(png_ptr, kOffZstreamAvailOut) = zbuf_size;
  Field<std::uint32_t>(png_ptr, kOffZstreamAvailIn) = static_cast<std::uint32_t>(textLength);
  Field<std::uint8_t*>(png_ptr, kOffZstreamNextOut) = Field<std::uint8_t*>(png_ptr, kOffZbuf);

  auto* const zstream = reinterpret_cast<z_stream_s*>(RawBase(png_ptr) + kOffZstream);

  // Compress the whole input, banking each window as it fills (Z_NO_FLUSH == 0).
  do {
    if (deflate(zstream, 0) != 0) {
      const char* const zmsg = Field<const char*>(png_ptr, kOffZstreamMsg);
      png_error(png_ptr, zmsg != nullptr ? zmsg : "zlib error");
    }
    if (Field<std::uint32_t>(png_ptr, kOffZstreamAvailOut) == 0) {
      if (Field<std::uint32_t>(png_ptr, kOffZstreamAvailIn) == 0) {
        break;
      }
      png_text_compress_store_block(png_ptr, comp, zbuf_size);
    }
  } while (Field<std::uint32_t>(png_ptr, kOffZstreamAvailIn) != 0);

  // Flush the deflate tail (Z_FINISH == 4), banking any window that fills.
  int status;
  while ((status = deflate(zstream, 4)) == 0) {
    if (Field<std::uint32_t>(png_ptr, kOffZstreamAvailOut) == 0) {
      png_text_compress_store_block(png_ptr, comp, zbuf_size);
    }
  }
  // deflate(Z_FINISH) must report Z_STREAM_END (1); the decompiler mislabels
  // this constant Z_PARTIAL_FLUSH, but the compare is against raw return code 1.
  if (status != 1) {
    const char* const zmsg = Field<const char*>(png_ptr, kOffZstreamMsg);
    png_error(png_ptr, zmsg != nullptr ? zmsg : "zlib error");
  }

  const std::uint32_t avail_out = Field<std::uint32_t>(png_ptr, kOffZstreamAvailOut);
  int result = static_cast<int>(zbuf_size) * comp->num_output_ptr;
  if (avail_out < zbuf_size) {
    result += static_cast<int>(zbuf_size - avail_out);
  }
  return result;
}

/**
 * Address: 0x00A242E3 (FUN_00A242E3)
 * Mangled: png_check_keyword
 *
 * What it does:
 * Validates and normalizes a PNG text keyword into a freshly allocated buffer
 * (*newKeyword): control/DEL characters become spaces (each warned), then
 * leading and trailing spaces are stripped and runs of interior spaces are
 * collapsed to a single space (each condition warned). Returns the resulting
 * length; a keyword that normalizes to empty is freed and returns 0, and a
 * keyword longer than 79 characters is truncated to 79.
 */
extern "C" int png_check_keyword(png_structp png_ptr, char* keyword, char** newKeyword)
{
  *newKeyword = nullptr;
  if (keyword == nullptr) {
    png_warning(png_ptr, "zero length keyword");
    return 0;
  }
  std::uint32_t key_len = static_cast<std::uint32_t>(std::strlen(keyword));
  if (key_len == 0) {
    png_warning(png_ptr, "zero length keyword");
    return 0;
  }

  char* const buffer = static_cast<char*>(png_malloc(png_ptr, key_len + 2));
  *newKeyword = buffer;

  // Copy, replacing control and DEL characters with a space.
  char* dst = buffer;
  for (const char* src = keyword; *src != '\0'; ++src, ++dst) {
    const char ch = *src;
    if (ch < 32 || ch == 127) {
      char msg[40];
      std::sprintf(msg, "invalid keyword character 0x%02X", ch);
      png_warning(png_ptr, msg);
      *dst = ' ';
    } else {
      *dst = ch;
    }
  }
  *dst = '\0';

  // Strip trailing spaces.
  char* tail = &(*newKeyword)[key_len - 1];
  if (*tail == ' ') {
    png_warning(png_ptr, "trailing spaces removed from keyword");
    while (*tail == ' ') { *tail-- = '\0'; --key_len; }
  }

  // Strip leading spaces.
  char* head = *newKeyword;
  if (**newKeyword == ' ') {
    png_warning(png_ptr, "leading spaces removed from keyword");
    while (*head == ' ') { ++head; --key_len; }
  }

  // Collapse runs of interior spaces, compacting toward the buffer front.
  char* out = *newKeyword;
  bool prev_space = false;
  bool collapsed = false;
  while (*head != '\0') {
    const char ch = *head;
    if (ch == ' ') {
      if (prev_space) {
        --key_len;
        collapsed = true;
      } else {
        *out++ = ' ';
        prev_space = true;
      }
    } else {
      *out++ = ch;
      prev_space = false;
    }
    ++head;
  }
  *out = '\0';
  if (collapsed) {
    png_warning(png_ptr, "extra interior spaces removed from keyword");
  }

  if (key_len == 0) {
    png_free(png_ptr, *newKeyword);
    *newKeyword = nullptr;
    png_warning(png_ptr, "Zero length keyword");
  }
  if (key_len > 79) {
    png_warning(png_ptr, "keyword length must be 1 - 79 characters");
    (*newKeyword)[79] = '\0';
    return 79;
  }
  return static_cast<int>(key_len);
}

/**
 * Address: 0x00A23E76 (FUN_00A23E76)
 * Mangled: png_write_sig
 *
 * What it does:
 * Writes the remaining PNG signature bytes based on `sig_bytes` and marks
 * PNG_HAVE_PNG_SIGNATURE on png_ptr->mode when fewer than three bytes were
 * already present.
 *
 * Sole caller: png_write_info_before_PLTE (0x009E78EB).
 */
extern "C" void png_write_sig(
  png_structp const png_ptr
)
{
  if (png_ptr == nullptr) {
    return;
  }

  static constexpr std::uint8_t kPngSignature[8] = {
    0x89u, 0x50u, 0x4Eu, 0x47u, 0x0Du, 0x0Au, 0x1Au, 0x0Au
  };

  std::uint8_t& sigBytes = libpng_layout::Field<std::uint8_t>(png_ptr, libpng_layout::kOffSigBytes);
  const std::uint8_t writtenPrefixBytes = sigBytes <= 8u ? sigBytes : 8u;

  png_write_data(
    png_ptr,
    kPngSignature + writtenPrefixBytes,
    static_cast<std::uint32_t>(8u - writtenPrefixBytes)
  );

  if (sigBytes < 3u) {
    libpng_layout::Mode(png_ptr) |= libpng_layout::kPngHavePngSignature;
  }
}

/**
 * Address: 0x009E8194 (FUN_009E8194, png_write_destroy)
 * Mangled: png_write_destroy
 *
 * IDA signature:
 * void __cdecl png_write_destroy(png_structp png_ptr);
 *
 * What it does:
 * Releases write-side zlib/output buffers from one png struct, then zeroes
 * the struct while preserving the callback/memory-function lanes required by
 * `png_destroy_write_struct`.
 */
extern "C" void png_write_destroy(png_structp const png_ptr)
{
  using namespace libpng_layout;

  if (png_ptr == nullptr) {
    return;
  }

  auto field32 = [&](const std::size_t index) -> std::uint32_t& {
    return Field<std::uint32_t>(png_ptr, index * sizeof(std::uint32_t));
  };
  auto fieldp = [&](const std::size_t index) -> void*& {
    return Field<void*>(png_ptr, index * sizeof(std::uint32_t));
  };

  auto* const zstream = reinterpret_cast<z_stream_s*>(RawBase(png_ptr) + kOffZstream);
  (void)deflateEnd(zstream);

  png_free(png_ptr, fieldp(43));
  png_free(png_ptr, fieldp(59));
  png_free(png_ptr, fieldp(58));
  png_free(png_ptr, fieldp(60));
  png_free(png_ptr, fieldp(61));
  png_free(png_ptr, fieldp(62));
  png_free(png_ptr, fieldp(63));
  png_free(png_ptr, fieldp(132));
  png_free(png_ptr, fieldp(127));
  png_free(png_ptr, fieldp(128));
  png_free(png_ptr, fieldp(129));
  png_free(png_ptr, fieldp(130));
  png_free(png_ptr, fieldp(131));

  std::uint8_t preservedJmpState[0x40]{};
  std::memcpy(preservedJmpState, png_ptr, sizeof(preservedJmpState));

  const std::uint32_t savedErrorPtr = field32(16);
  void* const savedErrorFn = fieldp(17);
  const std::uint32_t savedWarningFn = field32(18);
  const std::uint32_t savedFreeFn = field32(147);

  std::memset(png_ptr, 0, kPngStructSize);

  fieldp(17) = savedErrorFn;
  field32(18) = savedWarningFn;
  field32(147) = savedFreeFn;
  field32(16) = savedErrorPtr;

  std::memcpy(png_ptr, preservedJmpState, sizeof(preservedJmpState));
}

/**
 * Address: 0x009E86B4 (FUN_009E86B4)
 * Mangled: png_set_compression_window_bits
 *
 * IDA signature:
 * void __cdecl png_set_compression_window_bits(png_structp png_ptr, int window_bits);
 *
 * What it does:
 * Validates one zlib window-bit override, warns on out-of-range values,
 * normalizes `8` to `9`, and stores both the custom-window flag and effective
 * window-bit value into the write struct.
 */
extern "C" void png_set_compression_window_bits(
  png_structp const png_ptr,
  int               window_bits
)
{
  using namespace libpng_layout;

  if (png_ptr == nullptr) {
    return;
  }

  if (window_bits > 15) {
    png_warning(png_ptr, "Only compression windows <= 32k supported by PNG");
  } else if (window_bits < 8) {
    png_warning(png_ptr, "Only compression windows >= 256 supported by PNG");
  }

  if (window_bits == 8) {
    png_warning(png_ptr, "Compression window is being reset to 512");
    window_bits = 9;
  }

  Flags(png_ptr) |= kPngFlagZlibCustomWindowBits;
  ZlibWindowBits(png_ptr) = window_bits;
}

/**
 * Address: 0x009E86FE (FUN_009E86FE)
 * Mangled: png_set_compression_method
 *
 * IDA signature:
 * void __cdecl png_set_compression_method(png_structp png_ptr, int method);
 *
 * What it does:
 * Validates one zlib compression-method override (PNG requires method `8`),
 * emits one warning for unsupported values, and stores the method plus
 * custom-method flag on the write struct.
 */
extern "C" void png_set_compression_method(
  png_structp const png_ptr,
  int               method
)
{
  using namespace libpng_layout;

  if (png_ptr == nullptr) {
    return;
  }

  if (method != 8) {
    png_warning(png_ptr, "Only compression method 8 is supported by PNG");
  }

  Flags(png_ptr) |= kPngFlagZlibCustomMethod;
  ZlibMethod(png_ptr) = method;
}

/**
 * Address: 0x009E8727 (FUN_009E8727)
 *
 * IDA signature:
 * int __cdecl sub_9E8727(int a1, int a2);
 *
 * What it does:
 * Stores one write-status callback pointer into `png_struct` lane `+0x19C`.
 */
extern "C" void png_set_write_status_fn(
  png_structp const png_ptr,
  void* const       write_status_fn
)
{
  libpng_layout::Field<void*>(png_ptr, 0x19C) = write_status_fn;
}

/**
 * Address: 0x009E9DE7 (FUN_009E9DE7)
 * Mangled: png_set_read_user_chunk_fn
 *
 * IDA signature:
 * int __cdecl sub_9E9DE7(int a1, int a2, int a3);
 *
 * What it does:
 * Stores one user chunk context pointer plus one user chunk callback pointer
 * for read-side unknown chunk handling in `png_struct` lanes `+0x218/+0x21C`.
 */
extern "C" void png_set_read_user_chunk_fn(
  png_structp const png_ptr,
  void* const       user_chunk_ptr,
  void* const       read_user_chunk_fn
)
{
  libpng_layout::Field<void*>(png_ptr, 0x21C) = read_user_chunk_fn;
  libpng_layout::Field<void*>(png_ptr, 0x218) = user_chunk_ptr;
}

/**
 * Address: 0x009E9EC2 (FUN_009E9EC2)
 * Mangled: png_set_mmx_thresholds
 *
 * IDA signature:
 * int __cdecl sub_9E9EC2(int a1, char a2, int a3);
 *
 * What it does:
 * Stores one MMX pixel-depth threshold byte and one MMX row-byte threshold
 * dword into `png_struct` lanes `+0x239/+0x23C`.
 */
extern "C" void png_set_mmx_thresholds(
  png_structp const  png_ptr,
  const std::uint8_t mmx_bitdepth_threshold,
  const std::uint32_t mmx_rowbytes_threshold
)
{
  libpng_layout::Field<std::uint8_t>(png_ptr, 0x239) = mmx_bitdepth_threshold;
  libpng_layout::Field<std::uint32_t>(png_ptr, 0x23C) = mmx_rowbytes_threshold;
}

/**
 * Address: 0x009E8473 (FUN_009E8473)
 * Mangled: png_set_filter_heuristics
 *
 * IDA signature:
 * void __cdecl png_set_filter_heuristics(
 *   png_structp png_ptr, int heuristic_method, int num_weights,
 *   const double *filter_weights, const double *filter_costs);
 *
 * What it does:
 * Initializes the adaptive filter-selection heuristic tables on a libpng write
 * struct. Validates the heuristic method (must be < 3; issues png_warning and
 * returns on unknown values). Normalises DEFAULT (0) to UNWEIGHTED (1).
 *
 * When num_weights > 0 and filter_weights/heuristic_method permit it, allocates
 * prev_filters, filter_weights, and inv_filter_weights arrays; converts each
 * supplied weight to fixed-point (256 scale). When filter_costs is supplied,
 * converts each per-filter cost to fixed-point (8 scale). Both tables default
 * to their identity values (256 / 8 respectively) when not supplied or
 * out-of-range.
 */
extern "C" void png_set_filter_heuristics(
  png_structp   png_ptr,
  int           heuristic_method,
  int           num_weights,
  const double* filter_weights,
  const double* filter_costs
)
{
  // Validate heuristic method: must be in [0, kPngFilterHeuristicLast).
  // Values >= 3 are unsupported — issue warning and return early.
  if (heuristic_method >= kPngFilterHeuristicLast) {
    png_warning(png_ptr, "Unknown filter heuristic method");
    return;
  }

  // Reinterpret the png_struct as a typed view of the weighted-filter fields.
  // Evidence: heuristic_method stored at offset 0x1F8, other fields follow.
  auto* const pngFilter = reinterpret_cast<PngStructWeightedFilterView*>(
    reinterpret_cast<std::uint8_t*>(png_ptr) + kPngStructWeightedFilterOffset
  );

  // Normalise DEFAULT (0) to UNWEIGHTED (1).
  if (heuristic_method == kPngFilterHeuristicDefault) {
    heuristic_method = kPngFilterHeuristicUnweighted;
  }

  // Suppress weight processing when num_weights is negative, no weight array is
  // given, or the heuristic method is UNWEIGHTED (no history weighting applies).
  if (num_weights < 0 || filter_weights == nullptr ||
      heuristic_method == kPngFilterHeuristicUnweighted)
  {
    num_weights = 0;
  }

  pngFilter->num_prev_filters = static_cast<std::uint8_t>(num_weights);
  pngFilter->heuristic_method = static_cast<std::uint8_t>(heuristic_method);

  if (num_weights > 0) {
    // Allocate prev_filters history buffer on first use.
    if (pngFilter->prev_filters == nullptr) {
      pngFilter->prev_filters = static_cast<std::uint8_t*>(
        png_malloc(png_ptr, static_cast<std::uint32_t>(num_weights))
      );
      // Initialise all history slots to 0xFF (no valid previous filter type).
      for (int i = 0; i < num_weights; ++i) {
        pngFilter->prev_filters[i] = 0xFF;
      }
    }

    // Allocate filter_weights / inv_filter_weights arrays on first use.
    if (pngFilter->filter_weights == nullptr) {
      pngFilter->filter_weights = static_cast<std::uint16_t*>(
        png_malloc(png_ptr, static_cast<std::uint32_t>(2 * num_weights))
      );
      pngFilter->inv_filter_weights = static_cast<std::uint16_t*>(
        png_malloc(png_ptr, static_cast<std::uint32_t>(2 * num_weights))
      );
      for (int j = 0; j < num_weights; ++j) {
        pngFilter->filter_weights[j]     = static_cast<std::uint16_t>(kPngWeightFactor);
        pngFilter->inv_filter_weights[j] = static_cast<std::uint16_t>(kPngWeightFactor);
      }
    }

    // Convert supplied per-history weights to fixed-point (256 scale).
    for (int k = 0; k < num_weights; ++k) {
      if (filter_weights[k] < 0.0) {
        // Negative or out-of-range: reset this slot to the identity weight.
        pngFilter->filter_weights[k]     = static_cast<std::uint16_t>(kPngWeightFactor);
        pngFilter->inv_filter_weights[k] = static_cast<std::uint16_t>(kPngWeightFactor);
      } else {
        // inv_weight = weight * 256 + 0.5 (rounded to nearest).
        pngFilter->inv_filter_weights[k] = static_cast<std::uint16_t>(
          static_cast<unsigned long long>(filter_weights[k] * kPngWeightFactor + 0.5)
        );
        // weight = 256 / weight + 0.5 (reciprocal, rounded to nearest).
        pngFilter->filter_weights[k] = static_cast<std::uint16_t>(
          static_cast<unsigned long long>(
            static_cast<double>(kPngWeightFactor) / filter_weights[k] + 0.5
          )
        );
      }
    }
  }

  // Allocate filter_costs / inv_filter_costs for all 5 libpng filter types on first use.
  if (pngFilter->filter_costs == nullptr) {
    pngFilter->filter_costs = static_cast<std::uint16_t*>(
      png_malloc(png_ptr, static_cast<std::uint32_t>(2 * kPngFilterValueLast))
    );
    pngFilter->inv_filter_costs = static_cast<std::uint16_t*>(
      png_malloc(png_ptr, static_cast<std::uint32_t>(2 * kPngFilterValueLast))
    );
    for (int m = 0; m < kPngFilterValueLast; ++m) {
      pngFilter->filter_costs[m]     = static_cast<std::uint16_t>(kPngCostFactor);
      pngFilter->inv_filter_costs[m] = static_cast<std::uint16_t>(kPngCostFactor);
    }
  }

  // Apply supplied per-filter costs (fixed-point, 8 scale) for each of the 5 types.
  for (int n = 0; n < kPngFilterValueLast; ++n) {
    if (filter_costs == nullptr || filter_costs[n] < 0.0) {
      // No cost or negative cost: use the default identity cost.
      pngFilter->filter_costs[n]     = static_cast<std::uint16_t>(kPngCostFactor);
      pngFilter->inv_filter_costs[n] = static_cast<std::uint16_t>(kPngCostFactor);
    } else if (filter_costs[n] >= 1.0) {
      // Valid cost in [1.0, inf): convert to fixed-point.
      // inv_cost = 8 / cost + 0.5 (rounded to nearest).
      pngFilter->inv_filter_costs[n] = static_cast<std::uint16_t>(
        static_cast<unsigned long long>(
          static_cast<double>(kPngCostFactor) / filter_costs[n] + 0.5
        )
      );
      // cost = cost * 8 + 0.5 (rounded to nearest).
      pngFilter->filter_costs[n] = static_cast<std::uint16_t>(
        static_cast<unsigned long long>(filter_costs[n] * kPngCostFactor + 0.5)
      );
    }
    // If 0.0 <= cost < 1.0: no-op (leave existing value, matching binary behavior).
  }
}

/**
 * Address: 0x00A25228 (FUN_00A25228)
 * Mangled: png_write_cHRM
 *
 * What it does:
 * Validates cHRM chromaticity points and writes one `cHRM` chunk payload to
 * the output stream when all points are in-range.
 */
extern "C" void png_write_cHRM(
  png_structp const png_ptr,
  const double white_x,
  const double white_y,
  const double red_x,
  const double red_y,
  const double green_x,
  const double green_y,
  const double blue_x,
  const double blue_y)
{
  auto invalid_point = [](const double x, const double y) noexcept -> bool {
    return x < 0.0 || x > kPngChrmMaxPoint || y < 0.0 || y > kPngChrmMaxPoint || (x + y) > 1.0;
  };

  std::uint8_t chunk_data[0x20]{};
  if (invalid_point(white_x, white_y)) {
    png_warning(png_ptr, "Invalid cHRM white point specified");
    std::FILE* const io_base = __iob_func();
    std::fprintf(io_base + 2, "white_x=%f, white_y=%f\n", white_x, white_y);
    return;
  }

  png_save_uint_32(chunk_data + 0x00, static_cast<std::uint32_t>(white_x * kPngChrmScale + kPngRoundBias));
  png_save_uint_32(chunk_data + 0x04, static_cast<std::uint32_t>(white_y * kPngChrmScale + kPngRoundBias));

  if (invalid_point(red_x, red_y)) {
    png_warning(png_ptr, "Invalid cHRM red point specified");
    return;
  }
  png_save_uint_32(chunk_data + 0x08, static_cast<std::uint32_t>(red_x * kPngChrmScale + kPngRoundBias));
  png_save_uint_32(chunk_data + 0x0C, static_cast<std::uint32_t>(red_y * kPngChrmScale + kPngRoundBias));

  if (invalid_point(green_x, green_y)) {
    png_warning(png_ptr, "Invalid cHRM green point specified");
    return;
  }
  png_save_uint_32(chunk_data + 0x10, static_cast<std::uint32_t>(green_x * kPngChrmScale + kPngRoundBias));
  png_save_uint_32(chunk_data + 0x14, static_cast<std::uint32_t>(green_y * kPngChrmScale + kPngRoundBias));

  if (invalid_point(blue_x, blue_y)) {
    png_warning(png_ptr, "Invalid cHRM blue point specified");
    return;
  }
  png_save_uint_32(chunk_data + 0x18, static_cast<std::uint32_t>(blue_x * kPngChrmScale + kPngRoundBias));
  png_save_uint_32(chunk_data + 0x1C, static_cast<std::uint32_t>(blue_y * kPngChrmScale + kPngRoundBias));
  std::uint8_t chunk_name[4]{'c', 'H', 'R', 'M'};
  png_write_chunk(png_ptr, chunk_name, chunk_data, 0x20u);
}

/**
 * Address: 0x00A24EBD (FUN_00A24EBD)
 * Mangled: png_write_gAMA
 *
 * What it does:
 * Encodes one PNG `gAMA` (image gamma) chunk payload by quantizing the input
 * gamma to fixed-point 1e5 with a +0.5 round-bias and emitting it via
 * `png_write_chunk`.
 */
extern "C" void png_write_gAMA(
  png_structp const png_ptr,
  const double file_gamma
)
{
  std::uint8_t chunk_data[4]{};
  png_save_uint_32(
    chunk_data,
    static_cast<std::uint32_t>(file_gamma * kPngChrmScale + kPngRoundBias)
  );

  std::uint8_t chunk_name[4]{'g', 'A', 'M', 'A'};
  png_write_chunk(png_ptr, chunk_name, chunk_data, 4u);
}

/**
 * Address: 0x00A24F1E (FUN_00A24F1E)
 * Mangled: png_write_sRGB
 *
 * What it does:
 * Emits one-byte `sRGB` rendering-intent chunk payload and warns when the
 * supplied rendering intent is outside the valid [0, 3] range.
 */
extern "C" void png_write_sRGB(
  png_structp const png_ptr,
  const int rendering_intent
)
{
  if (rendering_intent >= 4) {
    png_warning(png_ptr, "Invalid sRGB rendering intent specified");
  }

  std::uint8_t chunk_name[4]{'s', 'R', 'G', 'B'};
  std::uint8_t chunk_data[1]{
    static_cast<std::uint8_t>(rendering_intent),
  };
  png_write_chunk(png_ptr, chunk_name, chunk_data, 1u);
}

/**
 * Address: 0x00A25180 (FUN_00A25180)
 * Mangled: png_write_sBIT
 *
 * What it does:
 * Validates per-channel significant-bit depths against the active
 * `usr_bit_depth`, then writes one packed `sBIT` chunk payload in PNG channel
 * order. Invalid channel depths emit one warning and abort chunk emission.
 */
extern "C" void png_write_sBIT(
  png_structp const png_ptr,
  const std::uint8_t* const significant_bits,
  const int color_type
)
{
  if (png_ptr == nullptr || significant_bits == nullptr) {
    png_warning(png_ptr, "Invalid sBIT depth specified");
    return;
  }

  std::uint8_t chunk_data[4]{};
  std::uint32_t chunk_size = 0;

  if ((color_type & 0x2) != 0) {
    std::uint8_t channel_depth_limit = 8;
    if (color_type != 3) {
      channel_depth_limit = libpng_layout::UsrBitDepth(png_ptr);
    }

    const std::uint8_t red_depth = significant_bits[0];
    const std::uint8_t green_depth = significant_bits[1];
    const std::uint8_t blue_depth = significant_bits[2];
    if (red_depth == 0 || red_depth > channel_depth_limit || green_depth == 0 || green_depth > channel_depth_limit ||
        blue_depth == 0 || blue_depth > channel_depth_limit)
    {
      png_warning(png_ptr, "Invalid sBIT depth specified");
      return;
    }

    chunk_data[0] = red_depth;
    chunk_data[1] = green_depth;
    chunk_data[2] = blue_depth;
    chunk_size = 3;
  } else {
    const std::uint8_t gray_depth = significant_bits[3];
    const std::uint8_t channel_depth_limit = libpng_layout::UsrBitDepth(png_ptr);
    if (gray_depth == 0 || gray_depth > channel_depth_limit) {
      png_warning(png_ptr, "Invalid sBIT depth specified");
      return;
    }

    chunk_data[0] = gray_depth;
    chunk_size = 1;
  }

  if ((color_type & 0x4) != 0) {
    const std::uint8_t alpha_depth = significant_bits[4];
    const std::uint8_t alpha_depth_limit = libpng_layout::UsrBitDepth(png_ptr);
    if (alpha_depth == 0 || alpha_depth > alpha_depth_limit) {
      png_warning(png_ptr, "Invalid sBIT depth specified");
      return;
    }

    chunk_data[chunk_size++] = alpha_depth;
  }

  std::uint8_t chunk_name[4]{'s', 'B', 'I', 'T'};
  png_write_chunk(png_ptr, chunk_name, chunk_data, chunk_size);
}

/**
 * Address: 0x00A24F55 (FUN_00A24F55)
 * Mangled: png_write_iCCP
 *
 * What it does:
 * Validates the iCCP keyword, warns on unknown compression-type lanes,
 * optionally compresses profile payload bytes, writes a complete `iCCP` chunk,
 * then frees temporary keyword storage.
 */
extern "C" void png_write_iCCP(
  png_structp const png_ptr,
  char* profileKeyword,
  const int compressionType,
  char* profile,
  const int profileDataLength
)
{
  if (profileKeyword == nullptr) {
    png_warning(png_ptr, "Empty keyword in iCCP chunk");
    return;
  }

  int keywordLength = png_check_keyword(png_ptr, profileKeyword, &profileKeyword);
  if (keywordLength == 0) {
    png_warning(png_ptr, "Empty keyword in iCCP chunk");
    return;
  }

  if (compressionType != 0) {
    png_warning(png_ptr, "Unknown compression type in iCCP chunk");
  }

  // Compress the profile payload only when a non-empty buffer is supplied; the
  // binary gates on (profile != NULL) then compresses profileDataLength bytes.
  int compressedPayloadLength = (profile != nullptr) ? profileDataLength : 0;
  int compressedState[5]{};
  if (compressedPayloadLength != 0) {
    compressedPayloadLength =
      png_text_compress(png_ptr, profile, profileDataLength, 0, compressedState);
  }

  const std::uint32_t chunkLength =
    static_cast<std::uint32_t>(keywordLength + compressedPayloadLength + 2);
  png_write_chunk_start(png_ptr, "iCCP", chunkLength);

  profileKeyword[keywordLength + 1] = '\0';
  png_write_chunk_data(
    png_ptr,
    reinterpret_cast<const std::uint8_t*>(profileKeyword),
    static_cast<std::uint32_t>(keywordLength + 2)
  );

  if (compressedPayloadLength != 0) {
    png_write_compressed_data_out(png_ptr, compressedState);
  }

  png_write_chunk_end(png_ptr);
  png_free(png_ptr, profileKeyword);
}

// ============================================================================
// png_write_IHDR chain: IHDR chunk, ancillary chunk writers, png_write_info*
// ============================================================================
//
// Real upstream reference for this whole section:
// dependencies/wxWindows-2.4.2/src/png/pngwutil.c (png_save_uint_16/int_32,
// png_write_sig, png_write_IHDR, png_write_PLTE, png_write_sPLT,
// png_write_tRNS, png_write_bKGD, png_write_hIST, png_write_tEXt,
// png_write_zTXt, png_write_oFFs, png_write_pCAL, png_write_sCAL,
// png_write_pHYs, png_write_tIME) and
// dependencies/wxWindows-2.4.2/src/png/pngwrite.c (png_write_info_before_PLTE,
// png_write_info).

/**
 * Address: 0x00A23DD1 (FUN_00A23DD1)
 * Mangled: png_save_uint_16
 *
 * What it does:
 * Stores a 16-bit value into a 2-byte buffer in big-endian order. The write
 * -path mirror of png_get_uint_16; every caller discards the binary's
 * returned buf pointer.
 */
extern "C" void png_save_uint_16(std::uint8_t* buf, std::uint16_t value)
{
  buf[0] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
  buf[1] = static_cast<std::uint8_t>(value & 0xFF);
}

/**
 * Address: 0x00A23DAE (FUN_00A23DAE)
 * Mangled: png_save_int_32
 *
 * What it does:
 * Stores a signed 32-bit value into a 4-byte buffer in big-endian order
 * (two's complement, same bit pattern as png_save_uint_32). Kept as a
 * distinct entry point because libpng's signed ancillary chunks (oFFs,
 * pCAL) call it by name.
 */
extern "C" void png_save_int_32(std::uint8_t* buf, std::int32_t value)
{
  buf[0] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
  buf[1] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
  buf[2] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
  buf[3] = static_cast<std::uint8_t>(value & 0xFF);
}

/**
 * Address: 0x00A24B90 (FUN_00A24B90)
 * Mangled: png_write_IHDR
 *
 * IDA signature:
 * int __cdecl sub_A24B90(int a1, png_uint_32 a2, png_uint_32 arg8, int a4,
 *   int a5, int a6, int a7, unsigned int a8);
 *
 * What it does:
 * Validates bit_depth against color_type (png_error on an unsupported
 * combination) and derives png_ptr->channels. Normalises an invalid
 * compression_type/filter_type/interlace_type to its default (each with a
 * warning); the MNG intrapixel-differencing filter_type(64) exception is
 * honoured for RGB/RGBA images that have not yet written their PNG
 * signature and have mng_features_permitted's FILTER_64 bit set. Stores
 * bit_depth/color_type/interlaced/filter_type/compression_type/width/
 * height/pixel_depth/rowbytes/usr_width/usr_bit_depth/usr_channels, writes
 * the 13-byte IHDR chunk, seeds do_filter (NONE for paletted/sub-8-bit
 * images, ALL_FILTERS otherwise) and the zlib level/method/window_bits/
 * mem_level/strategy defaults (only the lanes not already overridden via
 * png_set_compression_*), calls deflateInit2_, points zstream.next_out/
 * avail_out at zbuf, and sets png_ptr->mode = PNG_HAVE_IHDR.
 */
extern "C" void png_write_IHDR(
  png_structp   png_ptr,
  std::uint32_t width,
  std::uint32_t height,
  int           bit_depth,
  int           color_type,
  int           compression_type,
  int           filter_type,
  int           interlace_type)
{
  using namespace libpng_layout;

  std::uint8_t channels = 0;
  switch (color_type) {
    case kColorTypeGray:
      switch (bit_depth) {
        case 1: case 2: case 4: case 8: case 16: channels = 1; break;
        default: png_error(png_ptr, "Invalid bit depth for grayscale image");
      }
      break;
    case kColorTypeRgb:
      if (bit_depth != 8 && bit_depth != 16) {
        png_error(png_ptr, "Invalid bit depth for RGB image");
      }
      channels = 3;
      break;
    case kColorTypePalette:
      switch (bit_depth) {
        case 1: case 2: case 4: case 8: channels = 1; break;
        default: png_error(png_ptr, "Invalid bit depth for paletted image");
      }
      break;
    case kColorTypeGrayAlpha:
      if (bit_depth != 8 && bit_depth != 16) {
        png_error(png_ptr, "Invalid bit depth for grayscale+alpha image");
      }
      channels = 2;
      break;
    case kColorTypeRgbAlpha:
      if (bit_depth != 8 && bit_depth != 16) {
        png_error(png_ptr, "Invalid bit depth for RGBA image");
      }
      channels = 4;
      break;
    default:
      png_error(png_ptr, "Invalid image color type specified");
  }

  if (compression_type != 0 /* PNG_COMPRESSION_TYPE_BASE */) {
    png_warning(png_ptr, "Invalid compression type specified");
    compression_type = 0;
  }

  const bool mngIntrapixelOk =
    (MngFeaturesPermitted(png_ptr) & kPngFlagMngFilter64) != 0 &&
    (Mode(png_ptr) & kPngHavePngSignature) == 0 &&
    (color_type == kColorTypeRgb || color_type == kColorTypeRgbAlpha) &&
    filter_type == 64 /* PNG_INTRAPIXEL_DIFFERENCING */;
  if (!mngIntrapixelOk && filter_type != 0 /* PNG_FILTER_TYPE_BASE */) {
    png_warning(png_ptr, "Invalid filter type specified");
    filter_type = 0;
  }

  if (interlace_type >= 2 /* PNG_INTERLACE_LAST (MNG-features build) */) {
    png_warning(png_ptr, "Invalid interlace type specified");
    interlace_type = 1 /* PNG_INTERLACE_ADAM7 */;
  }

  ColorType(png_ptr) = static_cast<std::uint8_t>(color_type);
  Interlaced(png_ptr) = static_cast<std::uint8_t>(interlace_type);
  Field<std::uint8_t>(png_ptr, kOffFilterType) = static_cast<std::uint8_t>(filter_type);
  // Note: compression_type is written into the IHDR chunk bytes below but is
  // never stored back on png_ptr — neither upstream libpng (pngwutil.c
  // png_write_IHDR) nor this binary's decompile do so (PNG has exactly one
  // compression_type value, so there is nothing later to consult it for).

  const std::uint8_t pixelDepth = static_cast<std::uint8_t>(bit_depth * channels);
  BitDepth(png_ptr) = static_cast<std::uint8_t>(bit_depth);
  Field<std::uint8_t>(png_ptr, kOffPixelDepth) = pixelDepth;
  Field<std::uint32_t>(png_ptr, kOffWidth) = width;
  Field<std::uint32_t>(png_ptr, kOffHeight) = height;
  Field<std::uint32_t>(png_ptr, kOffRowbytes) = (width * static_cast<std::uint32_t>(pixelDepth) + 7u) >> 3;
  UsrWidth(png_ptr) = width;
  UsrBitDepth(png_ptr) = static_cast<std::uint8_t>(bit_depth);
  Field<std::uint8_t>(png_ptr, kOffChannels) = channels;
  UsrChannels(png_ptr) = channels;

  std::uint8_t ihdrData[13];
  png_save_uint_32(ihdrData, width);
  png_save_uint_32(ihdrData + 4, height);
  ihdrData[8]  = static_cast<std::uint8_t>(bit_depth);
  ihdrData[9]  = static_cast<std::uint8_t>(color_type);
  ihdrData[10] = static_cast<std::uint8_t>(compression_type);
  ihdrData[11] = static_cast<std::uint8_t>(filter_type);
  ihdrData[12] = static_cast<std::uint8_t>(interlace_type);
  std::uint8_t chunkName[4]{'I', 'H', 'D', 'R'};
  png_write_chunk(png_ptr, chunkName, ihdrData, 13u);

  using PngZAllocFn = void* (*)(png_structp, std::uint32_t, std::uint32_t);
  using PngZFreeFn  = void  (*)(png_structp, void*);
  Field<PngZAllocFn>(png_ptr, kOffZstreamZalloc) = png_zalloc;
  Field<PngZFreeFn>(png_ptr, kOffZstreamZfree)   = png_zfree;
  Field<void*>(png_ptr, kOffZstreamOpaque)       = png_ptr;

  if (DoFilter(png_ptr) == 0) {
    DoFilter(png_ptr) = (color_type == kColorTypePalette || bit_depth < 8) ? kPngFilterNone : kPngAllFilters;
  }
  if ((Flags(png_ptr) & kPngFlagZlibCustomStrategy) == 0) {
    Field<int>(png_ptr, kOffZlibStrategy) = (DoFilter(png_ptr) != kPngFilterNone) ? 1 /* Z_FILTERED */ : 0 /* Z_DEFAULT_STRATEGY */;
  }
  if ((Flags(png_ptr) & kPngFlagZlibCustomLevel) == 0) {
    Field<int>(png_ptr, kOffZlibLevel) = -1 /* Z_DEFAULT_COMPRESSION */;
  }
  if ((Flags(png_ptr) & kPngFlagZlibCustomMemLevel) == 0) {
    Field<int>(png_ptr, kOffZlibMemLevel) = 8;
  }
  if ((Flags(png_ptr) & kPngFlagZlibCustomWindowBits) == 0) {
    ZlibWindowBits(png_ptr) = 15;
  }
  if ((Flags(png_ptr) & kPngFlagZlibCustomMethod) == 0) {
    ZlibMethod(png_ptr) = 8;
  }

  auto* const zstream = reinterpret_cast<z_stream_s*>(RawBase(png_ptr) + kOffZstream);
  deflateInit2_(
    zstream,
    Field<int>(png_ptr, kOffZlibLevel),
    ZlibMethod(png_ptr),
    ZlibWindowBits(png_ptr),
    Field<int>(png_ptr, kOffZlibMemLevel),
    Field<int>(png_ptr, kOffZlibStrategy),
    "1.1.4",
    56
  );
  Field<std::uint8_t*>(png_ptr, kOffZstreamNextOut)  = Field<std::uint8_t*>(png_ptr, kOffZbuf);
  Field<std::uint32_t>(png_ptr, kOffZstreamAvailOut) = Field<std::uint32_t>(png_ptr, kOffZbufSize);

  Mode(png_ptr) = kPngHaveIhdr;
}

/**
 * Address: 0x00A241CB (FUN_00A241CB)
 * Mangled: png_write_PLTE
 *
 * What it does:
 * Validates the palette entry count (0 or >256 raises png_error for a
 * paletted image, or warns-and-skips otherwise; MNG's empty-PLTE exception
 * via mng_features_permitted bit 0 is honoured) and requires a colour image
 * type (warns and skips for grayscale). Stores num_pal into
 * png_ptr->num_palette, writes one PLTE chunk (3 packed bytes per entry:
 * red, green, blue), and sets PNG_HAVE_PLTE on png_ptr->mode.
 */
extern "C" void png_write_PLTE(png_structp png_ptr, const std::uint8_t* palette, std::uint32_t num_pal)
{
  using namespace libpng_layout;

  if (((MngFeaturesPermitted(png_ptr) & kPngFlagMngEmptyPlte) == 0 && num_pal == 0) || num_pal > 256u) {
    if (ColorType(png_ptr) == kColorTypePalette) {
      png_error(png_ptr, "Invalid number of colors in palette");
    } else {
      png_warning(png_ptr, "Invalid number of colors in palette");
      return;
    }
  }

  if ((ColorType(png_ptr) & kPngColorMaskColor) == 0) {
    png_warning(png_ptr, "Ignoring request to write a PLTE chunk in grayscale PNG");
    return;
  }

  NumPalette(png_ptr) = static_cast<std::uint16_t>(num_pal);

  png_write_chunk_start(png_ptr, "PLTE", num_pal * 3u);
  for (std::uint32_t i = 0; i < num_pal; ++i) {
    png_write_chunk_data(png_ptr, palette + 3u * i, 3u);
  }
  png_write_chunk_end(png_ptr);
  Mode(png_ptr) |= kPngHavePlte;
}

/**
 * Address: 0x00A24274 (FUN_00A24274)
 * Mangled: png_write_hIST
 *
 * What it does:
 * Warns and skips when num_hist exceeds png_ptr->num_palette; otherwise
 * writes one hIST chunk (one big-endian uint16 frequency value per entry).
 */
extern "C" void png_write_hIST(png_structp png_ptr, const std::uint16_t* hist, int num_hist)
{
  using namespace libpng_layout;

  if (num_hist > NumPalette(png_ptr)) {
    png_warning(png_ptr, "Invalid number of histogram entries specified");
    return;
  }

  png_write_chunk_start(png_ptr, "hIST", static_cast<std::uint32_t>(num_hist) * 2u);
  for (int i = 0; i < num_hist; ++i) {
    std::uint8_t buf[2];
    png_save_uint_16(buf, hist[i]);
    png_write_chunk_data(png_ptr, buf, 2u);
  }
  png_write_chunk_end(png_ptr);
}

/**
 * Address: 0x00A2446B (FUN_00A2446B)
 * Mangled: png_write_tEXt
 *
 * What it does:
 * Normalises `key` via png_check_keyword (warns and returns on a null or
 * empty keyword). Measures text_len via strlen (the binary never reads its
 * own text_len parameter; MSVC dropped it, so this recovery's real 3
 * -argument entry point matches every observed call site). Writes one tEXt
 * chunk (checked key + NUL + optional text bytes) and frees the checked
 * keyword buffer.
 */
extern "C" void png_write_tEXt(png_structp png_ptr, char* key, char* text)
{
  if (key == nullptr) {
    png_warning(png_ptr, "Empty keyword in tEXt chunk");
    return;
  }

  char* newKey = nullptr;
  const int keyLen = png_check_keyword(png_ptr, key, &newKey);
  if (keyLen == 0) {
    png_warning(png_ptr, "Empty keyword in tEXt chunk");
    return;
  }

  std::uint32_t textLen = 0;
  if (text != nullptr && *text != '\0') {
    textLen = static_cast<std::uint32_t>(std::strlen(text));
  }

  png_write_chunk_start(png_ptr, "tEXt", static_cast<std::uint32_t>(keyLen) + textLen + 1u);
  png_write_chunk_data(png_ptr, reinterpret_cast<std::uint8_t*>(newKey), static_cast<std::uint32_t>(keyLen) + 1u);
  if (textLen != 0) {
    png_write_chunk_data(png_ptr, reinterpret_cast<std::uint8_t*>(text), textLen);
  }
  png_write_chunk_end(png_ptr);
  png_free(png_ptr, newKey);
}

/**
 * Address: 0x00A244FB (FUN_00A244FB)
 * Mangled: png_write_zTXt
 *
 * What it does:
 * Normalises `key` via png_check_keyword, but only when key is non-null
 * (matches the binary's short-circuit shape, so a null key produces this
 * function's own warning rather than png_check_keyword's). When text is
 * empty or compression is PNG_TEXT_COMPRESSION_NONE(-1), falls back to
 * png_write_tEXt with the *checked* keyword and frees it. Otherwise
 * measures text_len via strlen, frees the checked keyword immediately
 * (binary quirk: the chunk itself is written later from the *original*,
 * unchecked `key` pointer — only the checked length is used), deflates the
 * text through png_text_compress, writes one zTXt chunk (original key +
 * NUL + compression byte + compressed payload), and closes it. The
 * binary's text_len parameter is never read (every call site passes a
 * literal 0), so this recovery drops it, matching png_write_tEXt.
 */
extern "C" void png_write_zTXt(png_structp png_ptr, std::uint8_t* key, char* text, int compression)
{
  char* newKey = nullptr;
  int keyLen = 0;
  if (key != nullptr) {
    keyLen = png_check_keyword(png_ptr, reinterpret_cast<char*>(key), &newKey);
  }
  if (key == nullptr || keyLen == 0) {
    png_warning(png_ptr, "Empty keyword in zTXt chunk");
    return;
  }

  if (text == nullptr || *text == '\0' || compression == -1 /* PNG_TEXT_COMPRESSION_NONE */) {
    png_write_tEXt(png_ptr, newKey, text);
    png_free(png_ptr, newKey);
    return;
  }

  const std::uint32_t textLen = static_cast<std::uint32_t>(std::strlen(text));
  png_free(png_ptr, newKey);

  int compressedState[5]{};
  const int compressedLen = png_text_compress(
    png_ptr, text, static_cast<int>(textLen), compression, compressedState);

  png_write_chunk_start(
    png_ptr, "zTXt", static_cast<std::uint32_t>(keyLen) + static_cast<std::uint32_t>(compressedLen) + 2u);
  // Binary quirk (matches upstream libpng 1.2.5rc3 exactly): writes the
  // ORIGINAL unchecked `key`, using only the checked keyword's length.
  png_write_chunk_data(png_ptr, key, static_cast<std::uint32_t>(keyLen) + 1u);
  const std::uint8_t compressionByte = static_cast<std::uint8_t>(compression);
  png_write_chunk_data(png_ptr, &compressionByte, 1u);
  png_write_compressed_data_out(png_ptr, compressedState);
  png_write_chunk_end(png_ptr);
}

/**
 * Address: 0x00A245CB (FUN_00A245CB)
 * Mangled: png_write_pCAL
 *
 * What it does:
 * Warns on an unrecognised equation type (>= 4). Normalises `purpose` via
 * png_check_keyword; measures `units` and each of the `nparams` parameter
 * strings via strlen (each NUL-separated except the last), summing the
 * total chunk length; writes the pCAL chunk (checked purpose, X0, X1,
 * type, nparams, units, then each parameter string in turn); frees the
 * checked purpose buffer and the temporary parameter-length array.
 */
extern "C" void png_write_pCAL(
  png_structp png_ptr, char* purpose, std::int32_t X0, std::int32_t X1,
  int type, int nparams, char* units, char** params)
{
  if (type >= 4 /* PNG_EQUATION_LAST */) {
    png_warning(png_ptr, "Unrecognized equation type for pCAL chunk");
  }

  char* newPurpose = nullptr;
  const std::uint32_t purposeLen = static_cast<std::uint32_t>(png_check_keyword(png_ptr, purpose, &newPurpose)) + 1u;
  const std::uint32_t unitsLen = static_cast<std::uint32_t>(std::strlen(units)) + (nparams == 0 ? 0u : 1u);
  std::uint32_t totalLen = purposeLen + unitsLen + 10u;

  auto* const paramsLen = static_cast<std::uint32_t*>(
    png_malloc(png_ptr, static_cast<std::uint32_t>(nparams) * static_cast<std::uint32_t>(sizeof(std::uint32_t))));

  for (int i = 0; i < nparams; ++i) {
    paramsLen[i] = static_cast<std::uint32_t>(std::strlen(params[i])) + (i == nparams - 1 ? 0u : 1u);
    totalLen += paramsLen[i];
  }

  png_write_chunk_start(png_ptr, "pCAL", totalLen);
  png_write_chunk_data(png_ptr, reinterpret_cast<std::uint8_t*>(newPurpose), purposeLen);

  std::uint8_t buf[10];
  png_save_int_32(buf, X0);
  png_save_int_32(buf + 4, X1);
  buf[8] = static_cast<std::uint8_t>(type);
  buf[9] = static_cast<std::uint8_t>(nparams);
  png_write_chunk_data(png_ptr, buf, 10u);
  png_write_chunk_data(png_ptr, reinterpret_cast<std::uint8_t*>(units), unitsLen);

  png_free(png_ptr, newPurpose);

  for (int i = 0; i < nparams; ++i) {
    png_write_chunk_data(png_ptr, reinterpret_cast<std::uint8_t*>(params[i]), paramsLen[i]);
  }

  png_free(png_ptr, paramsLen);
  png_write_chunk_end(png_ptr);
}

/**
 * Address: 0x00A24733 (FUN_00A24733)
 * Mangled: png_write_sCAL
 *
 * What it does:
 * Formats width and height as "%12.12e" C strings and writes one sCAL
 * chunk (unit byte, width string + NUL, height string).
 */
extern "C" void png_write_sCAL(png_structp png_ptr, int unit, double width, double height)
{
  char wbuf[32];
  char hbuf[32];
  std::sprintf(wbuf, "%12.12e", width);
  std::sprintf(hbuf, "%12.12e", height);

  const std::uint32_t wlen = static_cast<std::uint32_t>(std::strlen(wbuf));
  const std::uint32_t hlen = static_cast<std::uint32_t>(std::strlen(hbuf));
  png_write_chunk_start(png_ptr, "sCAL", 1u + wlen + 1u + hlen);
  const std::uint8_t unitByte = static_cast<std::uint8_t>(unit);
  png_write_chunk_data(png_ptr, &unitByte, 1u);
  png_write_chunk_data(png_ptr, reinterpret_cast<std::uint8_t*>(wbuf), wlen + 1u);
  png_write_chunk_data(png_ptr, reinterpret_cast<std::uint8_t*>(hbuf), hlen);
  png_write_chunk_end(png_ptr);
}

/**
 * Address: 0x00A25023 (FUN_00A25023)
 * Mangled: png_write_sPLT
 *
 * What it does:
 * Normalises spalette->name via png_check_keyword (warns and returns on a
 * null or empty keyword). Computes entry_size (6 bytes for depth 8, 10
 * bytes for depth 16) and writes one sPLT chunk: checked name + NUL, depth
 * byte, then each of spalette->nentries palette entries packed to
 * entry_size bytes (depth 8 truncates red/green/blue/alpha to their low
 * byte but keeps frequency as a full big-endian uint16; depth 16 writes
 * all five fields as big-endian uint16). Frees the checked name buffer.
 */
extern "C" void png_write_sPLT(png_structp png_ptr, const png_sPLT_t* spalette)
{
  const int entrySize = (spalette->depth == 8) ? 6 : 10;
  const std::uint32_t paletteSize =
    static_cast<std::uint32_t>(entrySize) * static_cast<std::uint32_t>(spalette->nentries);

  if (spalette->name == nullptr) {
    png_warning(png_ptr, "Empty keyword in sPLT chunk");
    return;
  }
  char* newName = nullptr;
  const int nameLen = png_check_keyword(png_ptr, spalette->name, &newName);
  if (nameLen == 0) {
    png_warning(png_ptr, "Empty keyword in sPLT chunk");
    return;
  }

  png_write_chunk_start(png_ptr, "sPLT", static_cast<std::uint32_t>(nameLen) + 2u + paletteSize);
  png_write_chunk_data(png_ptr, reinterpret_cast<std::uint8_t*>(newName), static_cast<std::uint32_t>(nameLen) + 1u);
  png_write_chunk_data(png_ptr, &spalette->depth, 1u);

  for (std::int32_t i = 0; i < spalette->nentries; ++i) {
    const png_sPLT_entry& ep = spalette->entries[i];
    std::uint8_t entryBuf[10];
    if (spalette->depth == 8) {
      entryBuf[0] = static_cast<std::uint8_t>(ep.red);
      entryBuf[1] = static_cast<std::uint8_t>(ep.green);
      entryBuf[2] = static_cast<std::uint8_t>(ep.blue);
      entryBuf[3] = static_cast<std::uint8_t>(ep.alpha);
      png_save_uint_16(entryBuf + 4, ep.frequency);
    } else {
      png_save_uint_16(entryBuf + 0, ep.red);
      png_save_uint_16(entryBuf + 2, ep.green);
      png_save_uint_16(entryBuf + 4, ep.blue);
      png_save_uint_16(entryBuf + 6, ep.alpha);
      png_save_uint_16(entryBuf + 8, ep.frequency);
    }
    png_write_chunk_data(png_ptr, entryBuf, static_cast<std::uint32_t>(entrySize));
  }

  png_write_chunk_end(png_ptr);
  png_free(png_ptr, newName);
}

/**
 * Address: 0x00A25649 (FUN_00A25649)
 * Mangled: png_write_tRNS
 *
 * What it does:
 * For PNG_COLOR_TYPE_PALETTE, validates num_trans against
 * png_ptr->num_palette and writes the raw per-palette-entry alpha bytes
 * verbatim. For PNG_COLOR_TYPE_GRAY, writes trans_values->gray as one
 * big-endian uint16 (after an out-of-range-for-bit_depth check). For
 * PNG_COLOR_TYPE_RGB, writes trans_values->red/green/blue as three
 * big-endian uint16 values (warns and skips if bit_depth is 8 but any high
 * byte is non-zero). Any other color_type (an alpha channel already
 * present) warns and writes nothing.
 */
extern "C" void png_write_tRNS(
  png_structp png_ptr, const std::uint8_t* trans, const png_color_16* trans_values,
  int num_trans, int color_type)
{
  using namespace libpng_layout;

  std::uint8_t chunkName[4]{'t', 'R', 'N', 'S'};

  if (color_type == kColorTypePalette) {
    if (num_trans <= 0 || num_trans > NumPalette(png_ptr)) {
      png_warning(png_ptr, "Invalid number of transparent colors specified");
      return;
    }
    png_write_chunk(png_ptr, chunkName, const_cast<std::uint8_t*>(trans), static_cast<std::uint32_t>(num_trans));
    return;
  }

  if (color_type == kColorTypeGray) {
    if (trans_values->gray >= (1u << BitDepth(png_ptr))) {
      png_warning(png_ptr, "Ignoring attempt to write tRNS chunk out-of-range for bit_depth");
      return;
    }
    std::uint8_t buf[2];
    png_save_uint_16(buf, trans_values->gray);
    png_write_chunk(png_ptr, chunkName, buf, 2u);
    return;
  }

  if (color_type == kColorTypeRgb) {
    std::uint8_t buf[6];
    png_save_uint_16(buf, trans_values->red);
    png_save_uint_16(buf + 2, trans_values->green);
    png_save_uint_16(buf + 4, trans_values->blue);
    if (BitDepth(png_ptr) == 8 && (buf[0] | buf[2] | buf[4]) != 0) {
      png_warning(png_ptr, "Ignoring attempt to write 16-bit tRNS chunk when bit_depth is 8");
      return;
    }
    png_write_chunk(png_ptr, chunkName, buf, 6u);
    return;
  }

  png_warning(png_ptr, "Can't write tRNS with an alpha channel");
}

/**
 * Address: 0x00A25753 (FUN_00A25753)
 * Mangled: png_write_bKGD
 *
 * What it does:
 * For PNG_COLOR_TYPE_PALETTE, writes back->index as one byte (validated
 * against png_ptr->num_palette, with the MNG empty-PLTE exception). For
 * colour types, writes back->red/green/blue as three big-endian uint16
 * values (warns and skips if bit_depth is 8 but any high byte is
 * non-zero). Otherwise writes back->gray as one big-endian uint16 (after
 * an out-of-range-for-bit_depth check).
 */
extern "C" void png_write_bKGD(png_structp png_ptr, const png_color_16* back, int color_type)
{
  using namespace libpng_layout;

  std::uint8_t chunkName[4]{'b', 'K', 'G', 'D'};

  if (color_type == kColorTypePalette) {
    const std::uint16_t numPalette = NumPalette(png_ptr);
    const bool emptyPlteOk = numPalette == 0 && (MngFeaturesPermitted(png_ptr) & kPngFlagMngEmptyPlte) != 0;
    if (!(emptyPlteOk || back->index <= numPalette)) {
      png_warning(png_ptr, "Invalid background palette index");
      return;
    }
    std::uint8_t buf[1]{back->index};
    png_write_chunk(png_ptr, chunkName, buf, 1u);
    return;
  }

  if ((color_type & kPngColorMaskColor) != 0) {
    std::uint8_t buf[6];
    png_save_uint_16(buf, back->red);
    png_save_uint_16(buf + 2, back->green);
    png_save_uint_16(buf + 4, back->blue);
    if (BitDepth(png_ptr) == 8 && (buf[0] | buf[2] | buf[4]) != 0) {
      png_warning(png_ptr, "Ignoring attempt to write 16-bit bKGD chunk when bit_depth is 8");
      return;
    }
    png_write_chunk(png_ptr, chunkName, buf, 6u);
    return;
  }

  if (back->gray >= (1u << BitDepth(png_ptr))) {
    png_warning(png_ptr, "Ignoring attempt to write bKGD chunk out-of-range for bit_depth");
    return;
  }
  std::uint8_t buf[2];
  png_save_uint_16(buf, back->gray);
  png_write_chunk(png_ptr, chunkName, buf, 2u);
}

/**
 * Address: 0x00A25857 (FUN_00A25857)
 * Mangled: png_write_oFFs
 *
 * What it does:
 * Warns on an unrecognised unit_type (>= 2, PNG_OFFSET_LAST) and writes
 * one 9-byte oFFs chunk (signed x_offset, signed y_offset, unit_type
 * byte).
 */
extern "C" void png_write_oFFs(png_structp png_ptr, std::int32_t x_offset, std::int32_t y_offset, int unit_type)
{
  if (unit_type >= 2 /* PNG_OFFSET_LAST */) {
    png_warning(png_ptr, "Unrecognized unit type for oFFs chunk");
  }

  std::uint8_t buf[9];
  png_save_int_32(buf, x_offset);
  png_save_int_32(buf + 4, y_offset);
  buf[8] = static_cast<std::uint8_t>(unit_type);

  std::uint8_t chunkName[4]{'o', 'F', 'F', 's'};
  png_write_chunk(png_ptr, chunkName, buf, 9u);
}

/**
 * Address: 0x00A258BE (FUN_00A258BE)
 * Mangled: png_write_pHYs
 *
 * What it does:
 * Warns on an unrecognised unit_type (>= 2, PNG_RESOLUTION_LAST) and
 * writes one 9-byte pHYs chunk (x/y pixels-per-unit, unit_type byte).
 */
extern "C" void png_write_pHYs(
  png_structp png_ptr, std::uint32_t x_pixels_per_unit, std::uint32_t y_pixels_per_unit, int unit_type)
{
  if (unit_type >= 2 /* PNG_RESOLUTION_LAST */) {
    png_warning(png_ptr, "Unrecognized unit type for pHYs chunk");
  }

  std::uint8_t buf[9];
  png_save_uint_32(buf, x_pixels_per_unit);
  png_save_uint_32(buf + 4, y_pixels_per_unit);
  buf[8] = static_cast<std::uint8_t>(unit_type);

  std::uint8_t chunkName[4]{'p', 'H', 'Y', 's'};
  png_write_chunk(png_ptr, chunkName, buf, 9u);
}

/**
 * Address: 0x00A25925 (FUN_00A25925)
 * Mangled: png_write_tIME
 *
 * What it does:
 * Validates month/day/hour/second ranges (warns and returns on any
 * violation; minute is unchecked, matching upstream libpng) and writes one
 * 7-byte tIME chunk (big-endian uint16 year, then month/day/hour/minute/
 * second bytes). Takes a raw 8-byte png_time image, matching
 * png_set_tIME's established convention in this codebase.
 */
extern "C" void png_write_tIME(png_structp png_ptr, const std::uint8_t* mod_time)
{
  const std::uint8_t month  = mod_time[2];
  const std::uint8_t day    = mod_time[3];
  const std::uint8_t hour   = mod_time[4];
  const std::uint8_t minute = mod_time[5];
  const std::uint8_t second = mod_time[6];

  if (month > 12 || month < 1 || day > 31 || day < 1 || hour > 23 || second > 60) {
    png_warning(png_ptr, "Invalid time specified for tIME chunk");
    return;
  }

  std::uint16_t year;
  std::memcpy(&year, mod_time, sizeof(year));

  std::uint8_t buf[7];
  png_save_uint_16(buf, year);
  buf[2] = month;
  buf[3] = day;
  buf[4] = hour;
  buf[5] = minute;
  buf[6] = second;

  std::uint8_t chunkName[4]{'t', 'I', 'M', 'E'};
  png_write_chunk(png_ptr, chunkName, buf, 7u);
}

/**
 * Address: 0x009E78EB (FUN_009E78EB)
 * Mangled: png_write_info_before_PLTE
 *
 * What it does:
 * One-shot guard on PNG_WROTE_INFO_BEFORE_PLTE (png_ptr->mode & 0x400):
 * writes the PNG signature (png_write_sig), clears mng_features_permitted
 * with a warning if MNG features were permitted but the signature was
 * already written, writes the IHDR chunk (png_write_IHDR) from
 * info_ptr->width/height/bit_depth/color_type/compression_type/
 * filter_type/interlace_type, then conditionally writes gAMA / sRGB / iCCP
 * / sBIT / cHRM per info_ptr->valid, then walks info_ptr->unknown_chunks
 * for entries not yet located after PLTE that are safe (or forced) to
 * copy, writing each via png_write_chunk. Finally sets
 * PNG_WROTE_INFO_BEFORE_PLTE on png_ptr->mode.
 */
extern "C" void png_write_info_before_PLTE(png_structp png_ptr, png_infop info_ptr)
{
  using namespace libpng_layout;

  if ((Mode(png_ptr) & kPngWroteInfoBeforePlte) != 0) {
    return;
  }

  png_write_sig(png_ptr);

  if ((Mode(png_ptr) & kPngHavePngSignature) != 0 && MngFeaturesPermitted(png_ptr) != 0) {
    png_warning(png_ptr, "MNG features are not allowed in a PNG datastream\n");
    MngFeaturesPermitted(png_ptr) = 0;
  }

  png_write_IHDR(
    png_ptr, info_ptr->width, info_ptr->height, info_ptr->bit_depth, info_ptr->color_type,
    info_ptr->compression_type, info_ptr->filter_type, info_ptr->interlace_type);

  if ((info_ptr->valid & kPngInfoGamma) != 0) {
    png_write_gAMA(png_ptr, info_ptr->gamma);
  }
  if ((info_ptr->valid & kPngInfoSrgb) != 0) {
    png_write_sRGB(png_ptr, info_ptr->srgb_intent);
  }
  if ((info_ptr->valid & kPngInfoIccp) != 0) {
    png_write_iCCP(
      png_ptr, info_ptr->iccp_name, 0 /* PNG_COMPRESSION_TYPE_BASE */,
      reinterpret_cast<char*>(info_ptr->iccp_profile), static_cast<int>(info_ptr->iccp_proflen));
  }
  if ((info_ptr->valid & kPngInfoSbit) != 0) {
    png_write_sBIT(png_ptr, info_ptr->sig_bit, info_ptr->color_type);
  }
  if ((info_ptr->valid & kPngInfoChrm) != 0) {
    png_write_cHRM(
      png_ptr, info_ptr->x_white, info_ptr->y_white, info_ptr->x_red, info_ptr->y_red,
      info_ptr->x_green, info_ptr->y_green, info_ptr->x_blue, info_ptr->y_blue);
  }

  for (std::uint32_t i = 0; i < info_ptr->unknown_chunks_num; ++i) {
    const png_unknown_chunk& chunk = info_ptr->unknown_chunks[i];
    const int keep = png_handle_as_unknown(png_ptr, chunk.name);
    if (keep != 1 /* HANDLE_CHUNK_NEVER */ && chunk.location != 0 &&
        (chunk.location & kPngHavePlte) == 0 &&
        ((chunk.name[3] & kPngChunkAncillaryBit) != 0 || keep == 3 /* HANDLE_CHUNK_ALWAYS */ ||
         (Flags(png_ptr) & kPngFlagKeepUnsafeChunks) != 0)) {
      png_write_chunk(png_ptr, const_cast<std::uint8_t*>(chunk.name), chunk.data, chunk.size);
    }
  }

  Mode(png_ptr) |= kPngWroteInfoBeforePlte;
}

/**
 * Address: 0x009E7A92 (FUN_009E7A92)
 * Mangled: png_write_info
 *
 * What it does:
 * Calls png_write_info_before_PLTE, then writes PLTE (or raises png_error
 * for a paletted image with no palette supplied), tRNS (inverting the
 * palette alpha array first when PNG_INVERT_ALPHA is active), bKGD, hIST,
 * oFFs, pCAL, sCAL, pHYs, tIME, and each sPLT record, each gated on the
 * corresponding info_ptr->valid bit. Walks info_ptr->text, writing each
 * record as tEXt/zTXt (international/iTXt-compression records are
 * unsupported here and only warned) and marking each record's compression
 * field with its "already written" sentinel so a second call is a no-op
 * for it. Finally walks info_ptr->unknown_chunks for entries located after
 * PLTE but before IDAT that are safe (or forced) to copy, writing each via
 * png_write_chunk.
 */
extern "C" void png_write_info(png_structp png_ptr, png_infop info_ptr)
{
  using namespace libpng_layout;

  png_write_info_before_PLTE(png_ptr, info_ptr);

  if ((info_ptr->valid & kPngInfoPlte) != 0) {
    png_write_PLTE(png_ptr, info_ptr->palette, info_ptr->num_palette);
  } else if (info_ptr->color_type == kColorTypePalette) {
    png_error(png_ptr, "Valid palette required for paletted images\n");
  }

  if ((info_ptr->valid & kPngInfoTrns) != 0) {
    if ((Transformations(png_ptr) & kPngInvertAlpha) != 0 && info_ptr->color_type == kColorTypePalette) {
      for (std::int32_t j = 0; j < info_ptr->num_trans; ++j) {
        info_ptr->trans[j] = static_cast<std::uint8_t>(255 - info_ptr->trans[j]);
      }
    }
    png_write_tRNS(
      png_ptr, info_ptr->trans, reinterpret_cast<const png_color_16*>(info_ptr->trans_values),
      info_ptr->num_trans, info_ptr->color_type);
  }

  if ((info_ptr->valid & kPngInfoBkgd) != 0) {
    png_write_bKGD(png_ptr, reinterpret_cast<const png_color_16*>(info_ptr->background), info_ptr->color_type);
  }
  if ((info_ptr->valid & kPngInfoHist) != 0) {
    png_write_hIST(png_ptr, info_ptr->hist, info_ptr->num_palette);
  }
  if ((info_ptr->valid & kPngInfoOffs) != 0) {
    png_write_oFFs(png_ptr, info_ptr->x_offset, info_ptr->y_offset, info_ptr->offset_unit_type);
  }
  if ((info_ptr->valid & kPngInfoPcal) != 0) {
    png_write_pCAL(
      png_ptr, info_ptr->pcal_purpose, info_ptr->pcal_X0, info_ptr->pcal_X1,
      info_ptr->pcal_type, info_ptr->pcal_nparams, info_ptr->pcal_units, info_ptr->pcal_params);
  }
  if ((info_ptr->valid & kPngInfoScal) != 0) {
    png_write_sCAL(png_ptr, info_ptr->scal_unit, info_ptr->scal_width, info_ptr->scal_height);
  }
  if ((info_ptr->valid & kPngInfoPhys) != 0) {
    png_write_pHYs(png_ptr, info_ptr->x_pixels_per_unit, info_ptr->y_pixels_per_unit, info_ptr->phys_unit_type);
  }
  if ((info_ptr->valid & kPngInfoTime) != 0) {
    png_write_tIME(png_ptr, info_ptr->mod_time);
    Mode(png_ptr) |= kPngWroteTime;
  }
  if ((info_ptr->valid & kPngInfoSplt) != 0) {
    for (std::int32_t i = 0; i < info_ptr->splt_palettes_num; ++i) {
      png_write_sPLT(png_ptr, &info_ptr->splt_palettes[i]);
    }
  }

  // Text chunk pass: write each record as tEXt/zTXt (international/iTXt
  // records are unsupported by this binary's write path and only warned),
  // then mark the record's sentinel so re-invoking png_write_info on the
  // same info_ptr is a no-op for it. Sentinel values match libpng's
  // PNG_TEXT_COMPRESSION_* constants exactly (png.h).
  constexpr std::int32_t kTextCompressionNoneWr = -3;  // already written, uncompressed
  constexpr std::int32_t kTextCompressionZtxtWr = -2;  // already written, compressed
  constexpr std::int32_t kTextCompressionNone   = -1;  // write as tEXt
  constexpr std::int32_t kTextCompressionZtxt   = 0;   // write as zTXt
  for (std::int32_t i = 0; i < info_ptr->num_text; ++i) {
    png_text& textRecord = info_ptr->text[i];
    if (textRecord.compression > 0) {
      png_warning(png_ptr, "Unable to write international text\n");
      textRecord.compression = kTextCompressionNoneWr;
    } else if (textRecord.compression == kTextCompressionZtxt) {
      png_write_zTXt(
        png_ptr, reinterpret_cast<std::uint8_t*>(textRecord.key), textRecord.text, textRecord.compression);
      textRecord.compression = kTextCompressionZtxtWr;
    } else if (textRecord.compression == kTextCompressionNone) {
      png_write_tEXt(png_ptr, textRecord.key, textRecord.text);
      textRecord.compression = kTextCompressionNoneWr;
    }
  }

  for (std::uint32_t i = 0; i < info_ptr->unknown_chunks_num; ++i) {
    const png_unknown_chunk& chunk = info_ptr->unknown_chunks[i];
    const int keep = png_handle_as_unknown(png_ptr, chunk.name);
    if (keep != 1 /* HANDLE_CHUNK_NEVER */ && chunk.location != 0 &&
        (chunk.location & kPngHavePlte) != 0 && (chunk.location & kPngHaveIdat) == 0 &&
        ((chunk.name[3] & kPngChunkAncillaryBit) != 0 || keep == 3 /* HANDLE_CHUNK_ALWAYS */ ||
         (Flags(png_ptr) & kPngFlagKeepUnsafeChunks) != 0)) {
      png_write_chunk(png_ptr, const_cast<std::uint8_t*>(chunk.name), chunk.data, chunk.size);
    }
  }
}
