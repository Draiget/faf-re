#pragma once

#include <cstddef>
#include <cstdint>

// Minimal view of the libpng png_struct fields accessed by the recovered write-path
// functions. The full png_struct_def is defined in wxWindows 2.4.2 src/png/png.h;
// this partial layout is used here to avoid pulling in the wxWindows build system.
//
// Binary evidence: png_set_filter_heuristics (0x009E8473) accesses fields at these
// offsets relative to png_structp:
//   +0x1F8: heuristic_method   (png_byte)
//   +0x1F9: num_prev_filters   (png_byte)
//   +0x1FA: pad (2 bytes, alignment)
//   +0x1FC: prev_filters       (png_bytep = uint8_t*)
//   +0x200: filter_weights     (png_uint_16p = uint16_t*)
//   +0x204: inv_filter_weights (png_uint_16p = uint16_t*)
//   +0x208: filter_costs       (png_uint_16p = uint16_t*)
//   +0x20C: inv_filter_costs   (png_uint_16p = uint16_t*)

struct PngStructWeightedFilterView
{
  std::uint8_t  heuristic_method    = 0;   // +0x00
  std::uint8_t  num_prev_filters    = 0;   // +0x01
  std::uint8_t  pad02[2]            = {};  // +0x02
  std::uint8_t* prev_filters        = nullptr; // +0x04
  std::uint16_t* filter_weights     = nullptr; // +0x08
  std::uint16_t* inv_filter_weights = nullptr; // +0x0C
  std::uint16_t* filter_costs       = nullptr; // +0x10
  std::uint16_t* inv_filter_costs   = nullptr; // +0x14
};
static_assert(sizeof(PngStructWeightedFilterView) == 0x18, "PngStructWeightedFilterView size must be 0x18");
static_assert(offsetof(PngStructWeightedFilterView, heuristic_method)    == 0x00);
static_assert(offsetof(PngStructWeightedFilterView, num_prev_filters)    == 0x01);
static_assert(offsetof(PngStructWeightedFilterView, prev_filters)        == 0x04);
static_assert(offsetof(PngStructWeightedFilterView, filter_weights)      == 0x08);
static_assert(offsetof(PngStructWeightedFilterView, inv_filter_weights)  == 0x0C);
static_assert(offsetof(PngStructWeightedFilterView, filter_costs)        == 0x10);
static_assert(offsetof(PngStructWeightedFilterView, inv_filter_costs)    == 0x14);

// Opaque png_struct forward declaration — layout not exposed here.
struct png_struct_def;
using png_structp = png_struct_def*;

// Opaque png_info forward declaration. The full layout (png_info_struct) is
// defined in PngSetRuntime.h; declarations here only need the pointer type.
struct png_info_struct;
using png_infop  = png_info_struct*;
using png_infopp = png_info_struct**;

// Opaque png_sPLT_t forward declaration (full layout in PngSetRuntime.h).
struct png_sPLT_t;

// Opaque png_row_info forward declaration (full layout in PngSetRuntime.h;
// same guarded typedef pattern as PngTransformRuntime.h so all three headers
// can be included in any order).
struct png_row_info;
#ifndef FA_LIBPNG_PNG_ROW_INFOP_DEFINED
#define FA_LIBPNG_PNG_ROW_INFOP_DEFINED
using png_row_infop = png_row_info*;
#endif

// libpng png_color_16 (10-byte record): palette index + 16-bit RGB + gray.
// Used verbatim (no byte-swap) as the in-memory representation of
// png_info::trans_values (tRNS) and png_info::background (bKGD); only the
// PNG chunk bytes written to the stream are big-endian (via png_save_uint_16).
//
// Binary evidence: png_write_tRNS (0x00A25649) and png_write_bKGD
// (0x00A25753) both index a supplied png_color_16* as
// ((uint16_t*)p)[1..3] for red/green/blue and ((uint16_t*)p)[4] for gray,
// matching {index; pad; red; green; blue; gray;} with red at +0x02.
struct png_color_16
{
  std::uint8_t  index;    // +0x00  palette index (PNG_COLOR_TYPE_PALETTE)
  std::uint8_t  pad_01;   // +0x01  alignment
  std::uint16_t red;      // +0x02
  std::uint16_t green;    // +0x04
  std::uint16_t blue;     // +0x06
  std::uint16_t gray;     // +0x08
};
static_assert(sizeof(png_color_16) == 0x0A, "png_color_16 size must be 0x0A");
static_assert(offsetof(png_color_16, index) == 0x00, "png_color_16::index at +0x00");
static_assert(offsetof(png_color_16, red)   == 0x02, "png_color_16::red at +0x02");
static_assert(offsetof(png_color_16, green) == 0x04, "png_color_16::green at +0x04");
static_assert(offsetof(png_color_16, blue)  == 0x06, "png_color_16::blue at +0x06");
static_assert(offsetof(png_color_16, gray)  == 0x08, "png_color_16::gray at +0x08");
using png_color_16p = const png_color_16*;

// Libpng helper: issue a warning message via the struct's error handler.
extern "C" void png_warning(png_structp png_ptr, const char* message);
extern "C" void png_error(png_structp png_ptr, const char* message);
// Libpng memory allocator.
extern "C" void* png_malloc(png_structp png_ptr, std::uint32_t size);
extern "C" void png_free(png_structp png_ptr, void* ptr);
extern "C" int png_check_keyword(png_structp png_ptr, char* keyword, char** newKeyword);
extern "C" int png_text_compress(
  png_structp png_ptr, char* text, int textLength, int compression, int* compressedState
);
extern "C" void png_write_chunk_start(png_structp png_ptr, const char* chunkName, std::uint32_t length);
extern "C" void png_write_chunk_data(png_structp png_ptr, const std::uint8_t* chunkData, std::uint32_t length);
extern "C" void png_write_compressed_data_out(png_structp png_ptr, int* compressedState);
extern "C" void png_write_chunk_end(png_structp png_ptr);

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
extern "C" void png_write_destroy(png_structp png_ptr);

/**
 * Address: 0x009E86B4 (FUN_009E86B4)
 * Mangled: png_set_compression_window_bits
 *
 * IDA signature:
 * void __cdecl png_set_compression_window_bits(png_structp png_ptr, int window_bits);
 *
 * What it does:
 * Validates and stores one zlib compression window size override on the write
 * struct. Values outside [8, 15] issue libpng warnings; input 8 is normalized
 * to 9 (512-byte window) with warning. Marks the custom-window flag lane.
 */
extern "C" void png_set_compression_window_bits(
  png_structp png_ptr,
  int         window_bits
);

/**
 * Address: 0x009E86FE (FUN_009E86FE)
 * Mangled: png_set_compression_method
 *
 * IDA signature:
 * void __cdecl png_set_compression_method(png_structp png_ptr, int method);
 *
 * What it does:
 * Validates one zlib compression-method override (PNG requires method `8`),
 * emits one warning for unsupported methods, and stores the method plus
 * custom-method flag on the write struct.
 */
extern "C" void png_set_compression_method(
  png_structp png_ptr,
  int         method
);

/**
 * Address: 0x009E8727 (FUN_009E8727)
 *
 * IDA signature:
 * int __cdecl sub_9E8727(int a1, int a2);
 *
 * What it does:
 * Stores one write-status callback lane in `png_struct` at offset `+0x19C`.
 */
extern "C" void png_set_write_status_fn(
  png_structp png_ptr,
  void*       write_status_fn
);

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
  png_structp png_ptr,
  void*       user_chunk_ptr,
  void*       read_user_chunk_fn
);

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
  png_structp    png_ptr,
  std::uint8_t   mmx_bitdepth_threshold,
  std::uint32_t  mmx_rowbytes_threshold
);

// Heuristic method constants matching libpng 1.2.x:
//   PNG_FILTER_HEURISTIC_DEFAULT    = 0
//   PNG_FILTER_HEURISTIC_UNWEIGHTED = 1
//   PNG_FILTER_HEURISTIC_WEIGHTED   = 2
//   PNG_FILTER_HEURISTIC_LAST       = 3
constexpr int kPngFilterHeuristicDefault    = 0;
constexpr int kPngFilterHeuristicUnweighted = 1;
constexpr int kPngFilterHeuristicWeighted   = 2;
constexpr int kPngFilterHeuristicLast       = 3;

// Filter type count: None, Sub, Up, Average, Paeth.
constexpr int kPngFilterValueLast = 5;

// Byte offset of the PngStructWeightedFilterView within a full png_struct.
// Evidence: ASM `mov [esi+1F8h], al` for heuristic_method from png_set_filter_heuristics.
constexpr std::size_t kPngStructWeightedFilterOffset = 0x1F8;

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
);

/**
 * Address: 0x00A25228 (FUN_00A25228)
 * Mangled: png_write_cHRM
 *
 * IDA signature:
 * void __cdecl png_write_cHRM(
 *   png_structp, double, double, double, double, double, double, double, double);
 *
 * What it does:
 * Validates floating-point cHRM white/red/green/blue points, serializes them
 * into one 32-byte chunk payload (100000x fixed-point), and emits the `cHRM`
 * PNG chunk. Invalid points raise `png_warning` and abort chunk emission.
 */
extern "C" void png_write_cHRM(
  png_structp png_ptr,
  double white_x,
  double white_y,
  double red_x,
  double red_y,
  double green_x,
  double green_y,
  double blue_x,
  double blue_y
);

/**
 * Address: 0x00A24EBD (FUN_00A24EBD)
 * Mangled: png_write_gAMA
 *
 * IDA signature:
 * void __cdecl png_write_gAMA(png_structp, double);
 *
 * What it does:
 * Encodes one PNG `gAMA` (image gamma) chunk payload by quantizing the input
 * gamma to fixed-point 1e5 with a +0.5 round-bias and emitting it via
 * `png_write_chunk`.
 */
extern "C" void png_write_gAMA(
  png_structp png_ptr,
  double file_gamma
);

/**
 * Address: 0x00A24F1E (FUN_00A24F1E)
 * Mangled: png_write_sRGB
 *
 * IDA signature:
 * void __cdecl png_write_sRGB(png_structp, int);
 *
 * What it does:
 * Emits one-byte `sRGB` rendering-intent chunk payload, warning when the
 * intent code is out of the valid [0, 3] range.
 */
extern "C" void png_write_sRGB(
  png_structp png_ptr,
  int renderingIntent
);

/**
 * Address: 0x00A25180 (FUN_00A25180)
 * Mangled: png_write_sBIT
 *
 * IDA signature:
 * void __cdecl png_write_sBIT(png_structp, png_color_8*, int);
 *
 * What it does:
 * Validates per-channel significant-bit depths against `usr_bit_depth`,
 * assembles a packed `sBIT` payload in PNG channel order, and emits one
 * `sBIT` chunk or warns on invalid lane values.
 */
extern "C" void png_write_sBIT(
  png_structp png_ptr,
  const std::uint8_t* significantBits,
  int colorType
);

/**
 * Address: 0x00A24F55 (FUN_00A24F55)
 * Mangled: png_write_iCCP
 *
 * IDA signature:
 * void __cdecl png_write_iCCP(png_structp, char*, int, int, int);
 *
 * What it does:
 * Validates the iCCP profile keyword, emits one warning for unknown
 * compression-type flags, optionally compresses profile payload data, then
 * writes one complete `iCCP` chunk (`keyword + NUL + compression byte +
 * payload`) and frees the temporary keyword buffer.
 */
extern "C" void png_write_iCCP(
  png_structp png_ptr,
  char* profileKeyword,
  int compressionType,
  char* profile,
  int profileDataLength
);

// ============================================================================
// png_write_IHDR chain: IHDR chunk, ancillary chunk writers, png_write_info*
// ============================================================================

/**
 * Address: 0x00A23DD1 (FUN_00A23DD1)
 * Mangled: png_save_uint_16
 *
 * IDA signature:
 * png_bytep __cdecl png_save_uint_16(png_bytep buf, unsigned int i);
 *
 * What it does:
 * Stores a 16-bit value into a 2-byte buffer in big-endian (network) byte
 * order. The binary returns buf, which every caller discards (matching
 * png_save_uint_32's convention in this file).
 */
extern "C" void png_save_uint_16(std::uint8_t* buf, std::uint16_t value);

/**
 * Address: 0x00A23DAE (FUN_00A23DAE)
 * Mangled: png_save_int_32
 *
 * IDA signature:
 * png_bytep __cdecl png_save_int_32(png_bytep buf, png_int_32 i);
 *
 * What it does:
 * Stores a signed 32-bit value into a 4-byte buffer in big-endian order
 * (identical bit pattern to png_save_uint_32; libpng keeps it as a distinct
 * entry point for the signed ancillary chunks oFFs/pCAL). Return value
 * (buf) is discarded by every caller.
 */
extern "C" void png_save_int_32(std::uint8_t* buf, std::int32_t value);

/**
 * Address: 0x00A24B90 (FUN_00A24B90)
 * Mangled: png_write_IHDR
 *
 * IDA signature:
 * int __cdecl png_write_IHDR(png_structp png_ptr, png_uint_32 width,
 *   png_uint_32 height, int bit_depth, int color_type, int compression_type,
 *   int filter_type, int interlace_type);
 *
 * What it does:
 * Validates bit_depth against color_type (raises png_error on an invalid
 * combination) and derives png_ptr->channels. Normalises out-of-range
 * compression_type / filter_type / interlace_type to their defaults
 * (warning each). Stores bit_depth/color_type/interlaced/compression_type/
 * width/height/pixel_depth/rowbytes/usr_width/usr_bit_depth/usr_channels on
 * png_ptr, writes the 13-byte IHDR chunk, then seeds png_ptr->do_filter and
 * the zlib level/method/window_bits/mem_level/strategy defaults (only the
 * lanes not already overridden via png_set_compression_*) before calling
 * deflateInit2_ and pointing zstream.next_out/avail_out at zbuf. Sets
 * png_ptr->mode = PNG_HAVE_IHDR.
 *
 * Sole caller: png_write_info_before_PLTE (0x009E78EB).
 */
extern "C" void png_write_IHDR(
  png_structp   png_ptr,
  std::uint32_t width,
  std::uint32_t height,
  int           bit_depth,
  int           color_type,
  int           compression_type,
  int           filter_type,
  int           interlace_type
);

/**
 * Address: 0x00A23E76 (FUN_00A23E76)
 * Mangled: png_write_sig
 *
 * IDA signature:
 * void __cdecl png_write_sig(png_structp png_ptr);
 *
 * What it does:
 * Writes the remaining PNG signature bytes based on `sig_bytes` (bytes
 * already written, e.g. via png_set_sig_bytes) and marks
 * PNG_HAVE_PNG_SIGNATURE on png_ptr->mode when fewer than three bytes were
 * already present.
 *
 * Sole caller: png_write_info_before_PLTE (0x009E78EB).
 */
extern "C" void png_write_sig(png_structp png_ptr);

/**
 * Address: 0x00A241CB (FUN_00A241CB)
 * Mangled: png_write_PLTE
 *
 * IDA signature:
 * void __cdecl png_write_PLTE(png_structp png_ptr, png_colorp palette, png_uint_32 num_pal);
 *
 * What it does:
 * Validates the palette entry count (0 or >256 is an error for paletted
 * images, a warning-and-skip otherwise; MNG's empty-PLTE exception via
 * mng_features_permitted is honoured) and that the image is a colour type
 * (warns and skips for grayscale). Stores num_pal into png_ptr->num_palette,
 * writes one PLTE chunk (3 bytes per entry: red, green, blue — packed
 * png_color, no byte-swap), and sets PNG_HAVE_PLTE on png_ptr->mode.
 *
 * Caller: png_write_info (0x009E7A92).
 */
extern "C" void png_write_PLTE(png_structp png_ptr, const std::uint8_t* palette, std::uint32_t num_pal);

/**
 * Address: 0x00A24274 (FUN_00A24274)
 * Mangled: png_write_hIST
 *
 * IDA signature:
 * void __cdecl png_write_hIST(png_structp png_ptr, png_uint_16p hist, int num_hist);
 *
 * What it does:
 * Warns and skips when num_hist exceeds png_ptr->num_palette; otherwise
 * writes one hIST chunk (one big-endian uint16 frequency value per palette
 * entry).
 *
 * Caller: png_write_info (0x009E7A92).
 */
extern "C" void png_write_hIST(png_structp png_ptr, const std::uint16_t* hist, int num_hist);

/**
 * Address: 0x00A2446B (FUN_00A2446B)
 * Mangled: png_write_tEXt
 *
 * IDA signature:
 * void __cdecl png_write_tEXt(png_structp png_ptr, png_charp key, png_charp text, png_size_t text_len);
 *
 * What it does:
 * Normalises `key` via png_check_keyword (warns and returns on an empty
 * keyword); measures text_len itself via strlen (the binary's text_len
 * parameter is never read — MSVC dropped it from this compiled entry
 * point's real 3-argument call sites). Writes one tEXt chunk
 * (key + NUL + optional text bytes) and frees the checked keyword buffer.
 *
 * Caller: png_write_info (0x009E7A92), and png_write_zTXt's uncompressed
 * fallback (0x00A244FB).
 */
extern "C" void png_write_tEXt(png_structp png_ptr, char* key, char* text);

/**
 * Address: 0x00A244FB (FUN_00A244FB)
 * Mangled: png_write_zTXt
 *
 * IDA signature:
 * void __cdecl png_write_zTXt(png_structp png_ptr, png_charp key, png_charp text,
 *   png_size_t text_len, int compression);
 *
 * What it does:
 * Normalises `key` via png_check_keyword. When text is empty or compression
 * is PNG_TEXT_COMPRESSION_NONE(-1), falls back to png_write_tEXt with the
 * *checked* keyword and frees it. Otherwise measures text_len via strlen,
 * frees the checked keyword immediately (binary quirk: the chunk itself is
 * later written from the *original*, unchecked `key` pointer, using only
 * the checked length), deflates the text through png_text_compress, writes
 * one zTXt chunk (key + NUL + compression byte + compressed payload), and
 * closes it. The binary's text_len parameter is never read (its call sites
 * pass a literal 0) so this recovery drops it, matching png_write_tEXt.
 *
 * Caller: png_write_info (0x009E7A92).
 */
extern "C" void png_write_zTXt(png_structp png_ptr, std::uint8_t* key, char* text, int compression);

/**
 * Address: 0x00A245CB (FUN_00A245CB)
 * Mangled: png_write_pCAL
 *
 * IDA signature:
 * void __cdecl png_write_pCAL(png_structp png_ptr, png_charp purpose, png_int_32 X0,
 *   png_int_32 X1, int type, int nparams, png_charp units, png_charpp params);
 *
 * What it does:
 * Warns on an unrecognised equation type. Normalises `purpose` via
 * png_check_keyword, measures `units` and each of the `nparams` parameter
 * strings via strlen (each NUL-separated except the very last), sums the
 * total chunk length, writes the pCAL chunk (purpose, X0, X1, type,
 * nparams, units, then each parameter string in turn), and frees the
 * checked purpose buffer plus the temporary parameter-length array.
 *
 * Caller: png_write_info (0x009E7A92).
 */
extern "C" void png_write_pCAL(
  png_structp png_ptr, char* purpose, std::int32_t X0, std::int32_t X1,
  int type, int nparams, char* units, char** params
);

/**
 * Address: 0x00A24733 (FUN_00A24733)
 * Mangled: png_write_sCAL
 *
 * IDA signature:
 * void __cdecl png_write_sCAL(png_structp png_ptr, int unit, double width, double height);
 *
 * What it does:
 * Formats width and height as "%12.12e" C strings and writes one sCAL
 * chunk (unit byte, width string + NUL, height string).
 *
 * Caller: png_write_info (0x009E7A92).
 */
extern "C" void png_write_sCAL(png_structp png_ptr, int unit, double width, double height);

/**
 * Address: 0x00A25023 (FUN_00A25023)
 * Mangled: png_write_sPLT
 *
 * IDA signature:
 * void __cdecl png_write_sPLT(png_structp png_ptr, png_sPLT_tp spalette);
 *
 * What it does:
 * Normalises spalette->name via png_check_keyword (warns and returns on an
 * empty keyword). Computes entry_size (6 bytes for depth 8, 10 bytes for
 * depth 16) and writes one sPLT chunk: checked name + NUL, depth byte, then
 * each of spalette->nentries palette entries packed to entry_size bytes
 * (depth 8 truncates each 16-bit red/green/blue/alpha to its low byte but
 * keeps frequency as a full big-endian uint16; depth 16 writes all five
 * fields as big-endian uint16). Frees the checked name buffer.
 *
 * Caller: png_write_info (0x009E7A92).
 */
extern "C" void png_write_sPLT(png_structp png_ptr, const png_sPLT_t* spalette);

/**
 * Address: 0x00A25649 (FUN_00A25649)
 * Mangled: png_write_tRNS
 *
 * IDA signature:
 * void __cdecl png_write_tRNS(png_structp png_ptr, png_bytep trans, png_color_16p tran,
 *   int num_trans, int color_type);
 *
 * What it does:
 * For PNG_COLOR_TYPE_PALETTE, validates num_trans against
 * png_ptr->num_palette and writes the raw per-palette-entry alpha bytes
 * verbatim. For PNG_COLOR_TYPE_GRAY, writes tran->gray as one big-endian
 * uint16 (after an out-of-range-for-bit_depth check). For
 * PNG_COLOR_TYPE_RGB, writes tran->red/green/blue as three big-endian
 * uint16 values (warns and skips if bit_depth is 8 but any high byte is
 * non-zero). Any other color_type (an alpha channel already present) warns
 * and writes nothing.
 *
 * Caller: png_write_info (0x009E7A92).
 */
extern "C" void png_write_tRNS(
  png_structp png_ptr, const std::uint8_t* trans, const png_color_16* trans_values,
  int num_trans, int color_type
);

/**
 * Address: 0x00A25753 (FUN_00A25753)
 * Mangled: png_write_bKGD
 *
 * IDA signature:
 * void __cdecl png_write_bKGD(png_structp png_ptr, png_color_16p back, int color_type);
 *
 * What it does:
 * For PNG_COLOR_TYPE_PALETTE, writes back->index as one byte (validated
 * against png_ptr->num_palette, with the MNG empty-PLTE exception). For
 * colour types, writes back->red/green/blue as three big-endian uint16
 * values (warns and skips if bit_depth is 8 but any high byte is non-zero).
 * Otherwise writes back->gray as one big-endian uint16 (after an
 * out-of-range-for-bit_depth check).
 *
 * Caller: png_write_info (0x009E7A92).
 */
extern "C" void png_write_bKGD(png_structp png_ptr, const png_color_16* back, int color_type);

/**
 * Address: 0x00A25857 (FUN_00A25857)
 * Mangled: png_write_oFFs
 *
 * IDA signature:
 * void __cdecl png_write_oFFs(png_structp png_ptr, png_int_32 x_offset,
 *   png_int_32 y_offset, int unit_type);
 *
 * What it does:
 * Warns on an unrecognised unit_type (>= PNG_OFFSET_LAST) and writes one
 * 9-byte oFFs chunk (signed x_offset, signed y_offset, unit_type byte).
 *
 * Caller: png_write_info (0x009E7A92).
 */
extern "C" void png_write_oFFs(png_structp png_ptr, std::int32_t x_offset, std::int32_t y_offset, int unit_type);

/**
 * Address: 0x00A258BE (FUN_00A258BE)
 * Mangled: png_write_pHYs
 *
 * IDA signature:
 * void __cdecl png_write_pHYs(png_structp png_ptr, png_uint_32 x_pixels_per_unit,
 *   png_uint_32 y_pixels_per_unit, int unit_type);
 *
 * What it does:
 * Warns on an unrecognised unit_type (>= PNG_RESOLUTION_LAST) and writes
 * one 9-byte pHYs chunk (x/y pixels-per-unit, unit_type byte).
 *
 * Caller: png_write_info (0x009E7A92).
 */
extern "C" void png_write_pHYs(png_structp png_ptr, std::uint32_t x_pixels_per_unit, std::uint32_t y_pixels_per_unit, int unit_type);

/**
 * Address: 0x00A25925 (FUN_00A25925)
 * Mangled: png_write_tIME
 *
 * IDA signature:
 * void __cdecl png_write_tIME(png_structp png_ptr, png_timep mod_time);
 *
 * What it does:
 * Validates month/day/hour/second ranges (warns and returns on any
 * violation; minute is unchecked, matching upstream libpng) and writes one
 * 7-byte tIME chunk (big-endian uint16 year, then month/day/hour/minute/
 * second bytes). Takes a raw 8-byte png_time image (year u16 + m/d/h/m/s),
 * matching png_set_tIME's established convention in this codebase.
 *
 * Caller: png_write_info (0x009E7A92).
 */
extern "C" void png_write_tIME(png_structp png_ptr, const std::uint8_t* mod_time);

/**
 * Address: 0x009E78EB (FUN_009E78EB)
 * Mangled: png_write_info_before_PLTE
 *
 * IDA signature:
 * void __cdecl png_write_info_before_PLTE(png_structp png_ptr, png_infop info_ptr);
 *
 * What it does:
 * One-shot guard on PNG_WROTE_INFO_BEFORE_PLTE (png_ptr->mode & 0x400):
 * writes the PNG signature (png_write_sig), clears mng_features_permitted
 * with a warning if MNG features were permitted but the signature was
 * already written, writes the IHDR chunk (png_write_IHDR) from
 * info_ptr->width/height/bit_depth/color_type/compression_type/
 * filter_type/interlace_type, then conditionally writes gAMA / sRGB / iCCP
 * / sBIT / cHRM per info_ptr->valid, then walks info_ptr->unknown_chunks
 * looking for entries not yet located after PLTE that are safe (or forced)
 * to copy, writing each via png_write_chunk. Finally sets
 * PNG_WROTE_INFO_BEFORE_PLTE on png_ptr->mode.
 *
 * Sole caller: png_write_info (0x009E7A92).
 */
extern "C" void png_write_info_before_PLTE(png_structp png_ptr, png_infop info_ptr);

/**
 * Address: 0x009E7A92 (FUN_009E7A92)
 * Mangled: png_write_info
 *
 * IDA signature:
 * void __cdecl png_write_info(png_structp png_ptr, png_infop info_ptr);
 *
 * What it does:
 * Calls png_write_info_before_PLTE, then writes PLTE (or raises png_error
 * for a paletted image with no palette supplied), tRNS, bKGD, hIST, oFFs,
 * pCAL, sCAL, pHYs, tIME, and each sPLT record, each gated on the
 * corresponding info_ptr->valid bit. Walks info_ptr->text, writing each
 * record as tEXt/zTXt (international/iTXt-compression records are
 * unsupported here and only warned) and marking each record's compression
 * field with its "already written" sentinel so a second call is a no-op.
 * Finally walks info_ptr->unknown_chunks for entries located after PLTE but
 * before IDAT that are safe (or forced) to copy, writing each via
 * png_write_chunk.
 *
 * Callers: wxPNGHandler::SaveFile (0x00975370, still unrecovered -- see
 * decomp/recovery/reports/FUN_00975370.md for the wxImage/vtable evidence
 * and the ready-to-execute plan, blocked on a concurrently-locked file) and
 * png_write_png (0x009E8AB8, recovered below).
 */
extern "C" void png_write_info(png_structp png_ptr, png_infop info_ptr);

// ============================================================================
// png_write_row chain: row buffering, Adam7 pass skip, adaptive filtering,
// zlib deflate draining, and the two top-level entry points.
// ============================================================================

/**
 * Address: 0x00A24E7F (FUN_00A24E7F)
 * Mangled: png_write_IDAT
 *
 * What it does:
 * Emits one IDAT chunk carrying `length` bytes of already-deflated image
 * data, then marks PNG_HAVE_IDAT on png_ptr->mode.
 */
extern "C" void png_write_IDAT(png_structp png_ptr, std::uint8_t* data, std::uint32_t length);

/**
 * Address: 0x009E9F5E (FUN_009E9F5E)
 * Mangled: png_flush
 *
 * What it does:
 * Invokes the installed output_flush_fn callback, if any (no-op otherwise).
 */
extern "C" void png_flush(png_structp png_ptr);

/**
 * Address: 0x00A247E4 (FUN_00A247E4)
 * Mangled: png_write_start_row
 *
 * What it does:
 * One-time (per image) row-pipeline setup: allocates row_buf and the
 * per-filter-type scratch buffers (sub_row/up_row/avg_row/paeth_row) that
 * do_filter enables, seeds each with its PNG_FILTER_VALUE_* tag byte, and
 * computes num_rows/usr_width for the first Adam7 pass or the whole image.
 */
extern "C" void png_write_start_row(png_structp png_ptr);

/**
 * Address: 0x00A259BC (FUN_00A259BC)
 * Mangled: png_write_finish_row
 *
 * What it does:
 * Advances row_number/pass bookkeeping; once the whole datastream's rows are
 * written, flushes the deflate stream to completion (Z_FINISH), draining
 * zbuf through png_write_IDAT.
 */
extern "C" void png_write_finish_row(png_structp png_ptr);

/**
 * Address: 0x00A25B38 (FUN_00A25B38)
 * Mangled: png_write_filtered_row
 *
 * What it does:
 * Feeds one already-filtered scanline through zlib deflate (Z_NO_FLUSH),
 * draining zbuf into IDAT chunks; swaps row_buf/prev_row; advances to
 * png_write_finish_row; periodically flushes early per flush_dist.
 */
extern "C" void png_write_filtered_row(png_structp png_ptr, std::uint8_t* filteredRow);

/**
 * Address: 0x009E80D0 (FUN_009E80D0)
 * Mangled: png_write_flush
 *
 * What it does:
 * Early-flushes the deflate stream mid-image (Z_SYNC_FLUSH), draining zbuf
 * into IDAT chunks, then invokes the user-visible png_flush callback.
 */
extern "C" void png_write_flush(png_structp png_ptr);

/**
 * Address: 0x00A25BF5 (FUN_00A25BF5)
 * Mangled: png_write_find_filter
 *
 * What it does:
 * Chooses which PNG filter type (None/Sub/Up/Average/Paeth) best compresses
 * the current scanline (or applies the sole enabled filter unconditionally),
 * using libpng's "minimum sum of absolute differences" heuristic (optionally
 * weighted by recent filter-type history), then writes it via
 * png_write_filtered_row.
 */
extern "C" void png_write_find_filter(png_structp png_ptr, png_row_infop row_info);

/**
 * Address: 0x009E7EC5 (FUN_009E7EC5)
 * Mangled: png_write_row
 *
 * What it does:
 * Writes one scanline: lazily runs png_write_start_row on the first call,
 * skips rows outside the current Adam7 pass, copies/transforms the pixel
 * data into row_buf, and dispatches to png_write_find_filter.
 *
 * Callers: png_write_rows (0x009E89A2, still unrecovered), png_write_image
 * (0x009E89C6, below), wxPNGHandler::SaveFile (0x00975370, still unrecovered).
 */
extern "C" void png_write_row(png_structp png_ptr, std::uint8_t* row);

/**
 * Address: 0x009E89C6 (FUN_009E89C6)
 * Mangled: png_write_image
 *
 * What it does:
 * Writes every scanline of a full in-memory image, one png_write_row call
 * per row per Adam7 pass (png_set_interlace_handling supplies the pass count).
 *
 * Sole caller: png_write_png (0x009E8AB8), below.
 */
extern "C" void png_write_image(png_structp png_ptr, std::uint8_t** image);

/**
 * Address: 0x00A24EA0 (FUN_00A24EA0)
 * Mangled: png_write_IEND
 *
 * What it does:
 * Writes the empty IEND chunk and marks PNG_HAVE_IEND on png_ptr->mode.
 *
 * Sole caller: png_write_end (0x009E7D38), below.
 */
extern "C" void png_write_IEND(png_structp png_ptr);

/**
 * Address: 0x009E7D38 (FUN_009E7D38)
 * Mangled: png_write_end
 *
 * What it does:
 * Finishes writing a PNG datastream: trailing tIME/text/unknown-chunk pass
 * (matching png_write_info's chunk-writing conventions), then PNG_AFTER_IDAT
 * + IEND.
 *
 * Callers: wxPNGHandler::SaveFile (0x00975370, still unrecovered),
 * png_write_png (0x009E8AB8, below).
 */
extern "C" void png_write_end(png_structp png_ptr, png_infop info_ptr);

/**
 * Address: 0x009E8AB8 (FUN_009E8AB8)
 * Mangled: png_write_png
 *
 * What it does:
 * libpng's "write the whole image in one call" convenience API: applies the
 * caller-selected PNG_TRANSFORM_* pixel transforms around png_write_info /
 * png_write_image / png_write_end. See the .cpp definition's doc comment for
 * this token's callsite-evidence exception (zero binary callers, proven via
 * exhaustive PE byte-scan, recorded recovered rather than skip/external
 * because the source identity is proven beyond doubt).
 */
extern "C" void png_write_png(png_structp png_ptr, png_infop info_ptr, int transforms, void* params);
