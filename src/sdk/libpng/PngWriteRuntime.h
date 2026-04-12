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
