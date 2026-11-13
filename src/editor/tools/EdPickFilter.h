#pragma once

#include "editor/tools/EdMarkers.h"

namespace faf::editor
{
  /**
   * What the Select tool's click, hover and box may pick, by kind. The view still draws what is filtered out; it just
   * can't be picked, so working on units or props doesn't grab or move a decal or a path node by accident.
   */
  struct PickFilter
  {
    bool markers = true;   // every marker but the path nodes
    bool pathNodes = true; // the path nodes (their own kind: they crowd the ground)
    bool units = true;
    bool props = true;
    bool decals = true;

    /** Whether a marker of this group may be picked. */
    [[nodiscard]] bool Marker(
      const MarkerGroup group
    ) const noexcept
    {
      return group == MarkerGroup::PathNodes ? pathNodes : markers;
    }
    /** Whether every kind may be picked (nothing filtered). */
    [[nodiscard]] bool All() const noexcept
    {
      return markers && pathNodes && units && props && decals;
    }
  };
} // namespace faf::editor
