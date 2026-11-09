#pragma once

#include <filesystem>
#include <string>

namespace faf::editor
{
  class EdDocument;

  /** What one map's save round trip found. */
  struct RoundTripResult
  {
    bool ok = false;
    /** Saving the map a second time gave the same bytes. */
    bool stable = false;
    /** The map has a file of its own on disk, and the first save has its exact bytes. */
    bool hasDiskFile = false;
    bool sameAsOriginal = false;
    /** What differed, or why it failed; empty when nothing did. */
    std::string differences;
  };

  /**
   * The save check of board task WPE.5 for the open map: writes its `.scmap` into `folder`, reads that file
   * back into a second map and compares what was read (heights, water, the twenty layer textures and their
   * sizes, the terrain shader, props with blueprints and transforms, the decal count), then saves the map
   * a second time and compares the two files byte for byte. The map itself is not changed.
   */
  RoundTripResult RoundTripMap(EdDocument& document, const std::filesystem::path& folder);
} // namespace faf::editor
