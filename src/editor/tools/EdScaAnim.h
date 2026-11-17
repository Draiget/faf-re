#pragma once

// A unit animation (`.sca`, version 5) read for the unit viewer (FAF Studio's unitview.lua plays the game's animations
// on the unit): its bones (names and parents), its frames (time, a position and a rotation per bone, relative to the
// parent bone) and its length; sampled at any time, looping or held at the ends. Engine independent
// (tests/editor/ScaAnimTests.cpp).

#include <array>
#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace faf::editor
{
  struct ScaKey
  {
    std::array<float, 3> position{};
    std::array<float, 4> rotation{1.0f, 0.0f, 0.0f, 0.0f}; // w, x, y, z
  };

  struct ScaAnimation
  {
    int version = 0;
    float duration = 0.0f;
    std::vector<std::string> bones;
    std::vector<int> parents; // -1: none
    /** The root's offset at the start (position and rotation). */
    ScaKey rootStart;
    struct Frame
    {
      float time = 0.0f;
      std::uint32_t flags = 0;
      std::vector<ScaKey> keys; // one per bone
    };
    std::vector<Frame> frames;
  };

  /** Reads a `.sca`; the error for a file that isn't one. */
  [[nodiscard]] std::expected<void, std::string> ReadSca(const std::vector<std::uint8_t>& bytes, ScaAnimation& out);

  /**
   * The bones' keys at `time` (seconds): between the two frames around it, positions blended straight, rotations along
   * the shorter arc. `loop` wraps the time over the length, else it is held at the ends.
   */
  [[nodiscard]] std::vector<ScaKey> SampleSca(const ScaAnimation& anim, float time, bool loop);

  /** Where each bone is in the model (its keys chained through the parents), for drawing the skeleton. */
  [[nodiscard]] std::vector<std::array<float, 3>>
  ScaBoneWorld(const ScaAnimation& anim, const std::vector<ScaKey>& keys);
} // namespace faf::editor
