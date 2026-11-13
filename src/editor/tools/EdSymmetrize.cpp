#include "editor/tools/EdSymmetrize.h"

#include "editor/terrain/EdFieldCore.h"

#include <algorithm>
#include <cmath>
#include <memory>

namespace faf::editor
{
  namespace
  {
    namespace field = faf::editor::field;

    /** The op's mode for a symmetry (its group and the order of its parts). */
    [[nodiscard]] const char* OpMode(
      const Symmetry symmetry
    )
    {
      switch (symmetry) {
      case Symmetry::LeftRight:
        return "mirror_x";
      case Symmetry::TopBottom:
        return "mirror_z";
      case Symmetry::DiagonalBack:
        return "diag";
      case Symmetry::DiagonalForward:
        return "adiag";
      case Symmetry::HalfTurn:
        return "rot2";
      case Symmetry::BothAxes:
        return "mirror_xz";
      case Symmetry::BothDiagonals:
        return "diag_both";
      case Symmetry::QuarterTurns:
        return "rot4";
      case Symmetry::NWay:
        return "rotn";
      default:
        return nullptr;
      }
    }

    [[nodiscard]] const char* CombineName(
      const SymmetryCombine combine
    )
    {
      switch (combine) {
      case SymmetryCombine::Average:
        return "avg";
      case SymmetryCombine::Max:
        return "max";
      case SymmetryCombine::Min:
        return "min";
      default:
        return "copy";
      }
    }

    /**
     * One grid through the op. Its samples lie at world (ox + x * cell, oz + z * cell), world being height samples;
     * the centre is in the same units.
     */
    bool Run(
      field::Grid& grid,
      const int fieldWidth,
      const int fieldHeight,
      const SymmetrizeOptions& options,
      const bool nearest,
      std::string& error
    )
    {
      const char* const mode = OpMode(options.symmetry);
      if (mode == nullptr) {
        error = "no symmetry chosen";
        return false;
      }
      field::OpArgs args;
      args.p.str["mode"] = mode;
      args.p.str["combine"] = CombineName(options.combine);
      args.p.num["n"] = std::clamp(options.turns, 2, 16);
      args.p.num["side"] = options.part;
      args.p.num["seam"] = options.combine == SymmetryCombine::Copy ? std::max(0.0f, options.seam) : 0.0f;
      args.p.num["nearest"] = nearest ? 1.0 : 0.0;
      args.p.num["cx"] = options.centreX >= 0.0f ? options.centreX : 0.5 * (fieldWidth - 1);
      args.p.num["cz"] = options.centreZ >= 0.0f ? options.centreZ : 0.5 * (fieldHeight - 1);
      args.in["a"] = std::make_shared<const field::Grid>(grid);
      field::Grid out;
      if (!field::RunOpCpu("symmetrize", args, out, error)) {
        return false;
      }
      if (!out.SameShape(grid)) {
        error = "symmetrize: the result has another size";
        return false;
      }
      grid.v = std::move(out.v);
      return true;
    }

    /** A grid over the map of `n x m` cells whose middles lie where they cover. */
    [[nodiscard]] field::Grid CellGrid(
      const int cellWidth,
      const int cellHeight,
      const int fieldWidth,
      const int fieldHeight
    )
    {
      const float cell = static_cast<float>(fieldWidth - 1) / static_cast<float>(cellWidth);
      (void)fieldHeight;
      return field::Grid(cellWidth, cellHeight, cell, 0.5f * cell, 0.5f * cell);
    }
  } // namespace

  int SymmetryParts(
    const Symmetry symmetry,
    const int turns
  )
  {
    switch (symmetry) {
    case Symmetry::LeftRight:
    case Symmetry::TopBottom:
    case Symmetry::DiagonalBack:
    case Symmetry::DiagonalForward:
    case Symmetry::HalfTurn:
      return 2;
    case Symmetry::BothAxes:
    case Symmetry::BothDiagonals:
    case Symmetry::QuarterTurns:
      return 4;
    case Symmetry::NWay:
      return std::clamp(turns, 2, 16);
    default:
      return 1;
    }
  }

  bool SymmetrizeHeights(
    std::uint16_t* const heights,
    const int width,
    const int height,
    const SymmetrizeOptions& options,
    std::string& error
  )
  {
    if (heights == nullptr || width < 2 || height < 2) {
      error = "no heights";
      return false;
    }
    field::Grid grid(width, height, 1.0f, 0.0f, 0.0f);
    for (std::size_t i = 0; i < grid.v.size(); ++i) {
      grid.v[i] = static_cast<float>(heights[i]);
    }
    if (!Run(grid, width, height, options, false, error)) {
      return false;
    }
    for (std::size_t i = 0; i < grid.v.size(); ++i) {
      heights[i] = static_cast<std::uint16_t>(std::lround(std::clamp(grid.v[i], 0.0f, 65535.0f)));
    }
    return true;
  }

  bool SymmetrizeMasks(
    std::uint64_t* const texels,
    const int maskWidth,
    const int maskHeight,
    const int fieldWidth,
    const int fieldHeight,
    const SymmetrizeOptions& options,
    std::string& error
  )
  {
    if (texels == nullptr || maskWidth < 2 || maskHeight < 2) {
      error = "no masks";
      return false;
    }
    const std::size_t count = static_cast<std::size_t>(maskWidth) * static_cast<std::size_t>(maskHeight);
    for (int stratum = 0; stratum < 8; ++stratum) {
      field::Grid grid = CellGrid(maskWidth, maskHeight, fieldWidth, fieldHeight);
      const int shift = 8 * stratum;
      for (std::size_t i = 0; i < count; ++i) {
        grid.v[i] = static_cast<float>((texels[i] >> shift) & 0xFFu);
      }
      if (!Run(grid, fieldWidth, fieldHeight, options, false, error)) {
        return false;
      }
      for (std::size_t i = 0; i < count; ++i) {
        const auto byte = static_cast<std::uint64_t>(std::lround(std::clamp(grid.v[i], 0.0f, 255.0f)));
        texels[i] = (texels[i] & ~(std::uint64_t{0xFF} << shift)) | (byte << shift);
      }
    }
    return true;
  }

  bool SymmetrizeCells(
    std::uint8_t* const cells,
    const int cellWidth,
    const int cellHeight,
    const int fieldWidth,
    const int fieldHeight,
    const SymmetrizeOptions& options,
    std::string& error
  )
  {
    if (cells == nullptr || cellWidth < 2 || cellHeight < 2) {
      error = "no cells";
      return false;
    }
    SymmetrizeOptions codes = options;
    if (codes.combine == SymmetryCombine::Average) {
      codes.combine = SymmetryCombine::Copy; // an average of codes is no code
    }
    field::Grid grid = CellGrid(cellWidth, cellHeight, fieldWidth, fieldHeight);
    for (std::size_t i = 0; i < grid.v.size(); ++i) {
      grid.v[i] = static_cast<float>(cells[i]);
    }
    if (!Run(grid, fieldWidth, fieldHeight, codes, true, error)) {
      return false;
    }
    for (std::size_t i = 0; i < grid.v.size(); ++i) {
      cells[i] = static_cast<std::uint8_t>(std::lround(std::clamp(grid.v[i], 0.0f, 255.0f)));
    }
    return true;
  }
} // namespace faf::editor
