#pragma once

#include "editor/terrain/EdFieldCore.h"
#include "editor/tools/EdFieldStack.h"

#include <functional>
#include <string>

namespace faf::editor
{
  /**
   * Terrain > Fields (FAF Studio's Fields panel, "advanced"): the field library op by op on the map's heights. Pick an
   * op, type its parameters, Apply onto the stack (each result the next one's input), Back drops the last; the top is
   * shown as a picture; "Put on the map" writes it as one undo step.
   */
  class EdFieldsPanel
  {
  public:
    /** The map's heights now, in map units (false when no map is open). */
    void SetGroundSource(
      std::function<bool(field::Grid&)> source
    )
    {
      mGround = std::move(source);
    }
    void Draw(bool& open, bool mapOpen);
    /** The heights to put on the map, once each time "Put on the map" was pressed. */
    bool TakeCommit(field::Grid& out);
    /** Test runs: start from the map, apply `op` with `params`; the status says how it went. */
    bool RunForTest(const std::string& op, const std::string& params, std::string& status);
    [[nodiscard]] const FieldStack& Stack() const noexcept
    {
      return mStack;
    }

  private:
    std::function<bool(field::Grid&)> mGround;
    FieldStack mStack;
    int mOp = 0;
    char mFilter[64] = {};
    char mParams[1024] = "radius = 4\n";
    std::string mStatus;
    bool mCommitAsked = false;
  };
} // namespace faf::editor
