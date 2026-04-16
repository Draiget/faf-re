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

// Libpng helper: issue a warning message via the struct's error handler.
extern "C" void png_warning(png_structp png_ptr, const char* message);
// Libpng memory allocator.
extern "C" void* png_malloc(png_structp png_ptr, std::uint32_t size);
extern "C" void png_free(png_structp png_ptr, void* ptr);
extern "C" int png_check_keyword(png_structp png_ptr, char* keyword, char** newKeyword);
extern "C" int png_text_compress(
  int textLength, png_structp png_ptr, int compressionType, int compressionFlags, int* compressedState
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
  int unknownCompressionTypeFlag,
  int compressionType,
  int profileDataLength
);
