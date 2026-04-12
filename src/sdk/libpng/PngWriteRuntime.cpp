// libpng write-path runtime recovery.
// Source: embedded wxWindows 2.4.2 libpng (dependencies/wxWindows-2.4.2/src/png/pngwrite.c).
// The ForgedAlliance.exe binary links libpng statically as png.lib; these recovered
// functions match the binary at their given addresses.

#include "libpng/PngWriteRuntime.h"

#include <cstdlib>

// Fixed-point scale constants from libpng 1.2.x:
//   PNG_WEIGHT_FACTOR = 1 << PNG_WEIGHT_SHIFT = 1 << 8 = 256
//   PNG_COST_FACTOR   = 1 << PNG_COST_SHIFT   = 1 << 3 = 8
static constexpr int kPngWeightFactor = 256;
static constexpr int kPngCostFactor   = 8;

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
