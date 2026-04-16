// libpng write-path runtime recovery.
// Source: embedded wxWindows 2.4.2 libpng (dependencies/wxWindows-2.4.2/src/png/pngwrite.c).
// The ForgedAlliance.exe binary links libpng statically as png.lib; these recovered
// functions match the binary at their given addresses.

#include "libpng/PngWriteRuntime.h"
#include "libpng/PngStructLayout.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" {
void png_save_uint_32(std::uint8_t* buf, std::uint32_t value);
void png_write_chunk(png_structp png_ptr, std::uint8_t* chunk_name, std::uint8_t* data, std::uint32_t length);
void png_write_data(png_structp png_ptr, const std::uint8_t* data, std::uint32_t length);
std::FILE* __cdecl __iob_func(void);
struct z_stream_s;
int deflateEnd(z_stream_s* strm);
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
 * Address: 0x00A23E76 (FUN_00A23E76)
 *
 * What it does:
 * Writes the remaining PNG signature bytes based on `sig_bytes` and marks the
 * signature-written mode bit when fewer than three bytes were already present.
 */
[[maybe_unused]] void png_write_sig_runtime(
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
    libpng_layout::Mode(png_ptr) |= 0x1000u;
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
  const int unknownCompressionTypeFlag,
  const int compressionType,
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

  if (unknownCompressionTypeFlag != 0) {
    png_warning(png_ptr, "Unknown compression type in iCCP chunk");
  }

  int compressedPayloadLength = 0;
  int compressedState[5]{};
  if (compressionType != 0) {
    compressedPayloadLength =
      png_text_compress(profileDataLength, png_ptr, compressionType, 0, compressedState);
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
