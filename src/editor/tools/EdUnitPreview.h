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
    /**
     * The mesh LOD to look at (Studio's ShowLOD): -1 leaves the camera alone; n puts the camera at the middle of LOD
     * n's distance range (the engine picks a LOD by the camera's distance). Filled by the view: each LOD's cutoff.
     */
    int lod = -1;
    std::vector<float> lodCutoffs;
    /** Studio's viewer stage: the map's terrain, sky, water and border not drawn while the unit is shown. */
    bool stage = false;
    /** Studio's light presets for the map (one undo step each): Map (the map's own, back), Noon, Evening, Overcast,
     * Night, Icon. */
    std::string light = "Map";
    /** Fire (Studio's Effects panel fires a projectile from the viewer's unit): the weapon whose projectile flies from
     * the unit; `fire` asks for one shot (the view clears it). */
    int fireWeapon = 0;
    bool fire = false;
    std::string fireStatus;
    /** Studio's camera presets for the unit: iso, front, side, back, top, fit (asked; the view clears it). */
    std::string frame;
    /** Bone picking: the bones of the shown mesh (filled by the view) and the picked one (-1 none), whose axes are
     * drawn. */
    std::vector<std::string> boneNames;
    int bone = -1;
    /** A floor grid around the unit on the empty stage. */
    bool grid = true;
    /** Studio's named team colours: Army (the army colour slider), Red, Blue, Green, Yellow, White, Black. */
    std::string colour = "Army";
    /** Filled by the view: the animations the blueprint names, the animation's length, what happened. */
    std::vector<std::string> animations;
    float duration = 0.0f;
    std::string status;
  };
} // namespace faf::editor
