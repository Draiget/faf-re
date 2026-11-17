#pragma once

#include "editor/terrain/EdFieldCore.h"

#include <expected>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * The Fields panel's model (FAF Studio's panels_fields.lua): the map's heights as a field, then field-library ops one
   * at a time, each on the result before it, kept as a stack; Back drops the last. The panel shows the top and puts
   * it on the map as one undo step.
   */
  class FieldStack
  {
  public:
    /** A new stack on `base` (the map's heights, in map units). */
    void Start(field::Grid base);
    /** `op` with `params` on the top (its input `a`, and `like` for ops that size their output by it). */
    [[nodiscard]] std::expected<void, std::string> Apply(const std::string& op, const field::Params& params);
    /** The last op undone; false when only the base is left. */
    bool Back();
    void Clear();
    [[nodiscard]] bool Empty() const noexcept
    {
      return mGrids.empty();
    }
    [[nodiscard]] const field::Grid* Top() const noexcept
    {
      return mGrids.empty() ? nullptr : &mGrids.back();
    }
    /** The ops applied so far, oldest first, as "op (key=value ...)". */
    [[nodiscard]] const std::vector<std::string>& Steps() const noexcept
    {
      return mSteps;
    }

  private:
    std::vector<field::Grid> mGrids;
    std::vector<std::string> mSteps;
  };

  /**
   * An op's parameters typed one a line, `key = value`: numbers go to `num`, lists of numbers (`1, 2, 3`) to `arr`,
   * anything else (quotes taken off) to `str`. Empty lines and lines starting with `--` or `#` are skipped.
   */
  [[nodiscard]] field::Params ParseOpParams(const std::string& text);

  /** The parameters as one line ("radius=4 mode=soft"), for the steps list and the log. */
  [[nodiscard]] std::string ParamsText(const field::Params& params);
} // namespace faf::editor
