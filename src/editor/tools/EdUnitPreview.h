#pragma once

// What the unit viewer and the view share for the animated unit (FAF Studio's unitview.lua): the unit shown in the view
// with the game's own mesh renderer, an animation of it played (play, loop, rate, scrub), and its bones, collision box,
// footprint and skirt, weapon ranges and senses drawn over it, with a level of detail and an army colour.

#include <string>
#include <vector>

namespace faf::editor
{
  struct UnitPreviewState
  {
    bool active = false;
    std::string unit; // blueprint id
    /** A `.sca` game path (empty: the unit stands in its rest pose). */
    std::string animation;
    bool playing = true;
    bool loop = true;
    float rate = 1.0f;
    float time = 0.0f;
    bool scrubbed = false; // the panel moved the time
    bool bones = true;
    bool hitbox = true;
    bool footprint = true;
    bool ranges = true;
    bool senses = false;
    int army = 0; // the army colour's index (0..7)
    bool lockCamera = true;
    /** Filled by the view: the animations the blueprint names, the animation's length, what happened. */
    std::vector<std::string> animations;
    float duration = 0.0f;
    std::string status;
  };
} // namespace faf::editor
