#pragma once

#include "editor/tools/EdArrange.h"

#include <string>

namespace faf::editor
{
  /**
   * G and R in the view (the consolidated design's Object > Transform, as Blender's): the selection follows the cursor
   * (G moves, R turns it about its middle) until a click or Enter keeps it or Escape or a right click puts it back. X
   * or Z locks the move to that axis; a typed number moves exactly that far (along X unless Z is locked) or turns that
   * many degrees.
   */
  struct ModalInput
  {
    bool rotate = false;
    char axis = 0;         // 0, 'X' or 'Z'
    std::string typed;     // the number typed so far ("", "-", "12.5")
    float cursorDX = 0.0f; // the cursor's ground point now, less where it started
    float cursorDZ = 0.0f;
    float startAngle = 0.0f; // the cursor's angle about the middle when it started, and now (radians)
    float nowAngle = 0.0f;
  };

  struct ModalDelta
  {
    float dx = 0.0f;
    float dz = 0.0f;
    float turn = 0.0f; // radians, the heading's change (positive turns +z towards +x, as a heading)
  };

  /** The move or turn the input asks for. */
  [[nodiscard]] ModalDelta ModalDeltaFor(const ModalInput& input);

  /** `start` moved by `delta`, or turned by it about (cx, cz) with every heading turned as much. */
  [[nodiscard]] ArrangePlaces ApplyModalDelta(const ArrangePlaces& start, float cx, float cz, const ModalDelta& delta);

  /** A key typed into the number: digits, '.', '-' (first only) and Backspace (8); false for any other key. */
  bool TypeIntoNumber(std::string& typed, int key);

  /** The HUD's words: "Move  X  12.5" / "Turn  45 degrees". */
  [[nodiscard]] std::string ModalHudText(const ModalInput& input, const ModalDelta& delta);
} // namespace faf::editor
