#pragma once

#include <string>

#include <memory>

namespace moho
{
  struct GeomCamera3;
  class ID3DTextureSheet;
} // namespace moho

// Water that moves when things move in it (docs/WATER_SIMULATION.md): a damped height-field wave simulation on the GPU,
// a toroidal grid of 1024 x 1024 cells of one world unit that follows the camera over the water. Units standing in the
// water leave wakes, the impacts and explosions at the surface throw rings. The result (slope and height, one RGBA16F
// texture) bends the normal the water pixel shader uses, so the reflection, the refraction, the sun glints and the
// light glints of the field all see the waves, and pushes the wave crest colour (foam) where the water is high.
//
// Render only: the simulation never sees any of it (replays stay in step), and nothing here feeds back to the units.
// Cost: one compute dispatch of 1024 x 1024 cells per step (at most 6 steps a frame, 90 a second) and one copy draw.
namespace moho
{
  class CArmyImpl;
}

namespace moho::water
{
  // Whether an event of this army is the local player's own or an ally's (it is then shown where it happens, in the fog
  // too: a dying unit takes its own vision with it). False for an enemy, a neutral or no army.
  bool SimIsOwnSide(const CArmyImpl* army);

  // 1 (the default): the simulation runs and the water shader reads it; 0: the shipped water.
  extern int ren_WaterSim;

  // A source of waves for the next steps: a disc of `radius` world units at (x, z) that pushes the water by `strength`
  // (world units per second; negative pulls it down). Collected over the frame, applied by the next step. `kind`: 0 a
  // disc, 1 a crater with a rim (zero volume; see WaterImpact.h). `foam` is how much foam it throws per frame (0 none;
  // a wash of 0.005 to 0.01 is a steady band). `shown`: the place is known to be in view (a mesh that is being drawn,
  // an event of the player's own or an ally's); otherwise a place the player cannot see (fog) takes no wave: the waves
  // would tell what happens there.
  void SimAddSource(
    float x,
    float z,
    float radius,
    float strength,
    float foam = 0.0f,
    bool shown = false,
    float kind = 0.0f
  );

  // How strongly the wakes of ships and the splashes of impacts push the water, as factors (1 = the tuned default):
  // ren_WaterSimWake and ren_WaterSimImpact in percent. A landing on or under the sea: `size` is the cube root of the
  // energy (a shell of 100 damage: 4.6, a nuke: 20) and sets the radius, the hump and the foam of the splash; `scale`
  // is 1 on the surface, less below it. Render only: nothing feeds back into the sim.
  void SimImpact(float x, float z, float size, float scale, bool shown = false);
  // A hull going down: `mass` is its build cost in mass. Airborne wrecks and wrecks ashore move nothing.
  void SimUnitDeath(float x, float y, float z, float mass, bool shown = false);

  float SimWakeScale();
  float SimFoamScale();
  float SimBodyScale(); // 0: bodies do not push the water by their volume (ships fall back on the hand-made wake)
  float SimBodyFoamScale();
  // The game time of the last frame in steps of the simulation (0 while the game is paused): continuous sources (a hull
  // under way) are weighed with it so that what they push per second does not depend on the frame rate. One-off events
  // (a shell, a death) are not.
  float SimSourceWeight();
  // The time of the simulation in seconds (it stands while the game is paused): the feeds that leave things behind in
  // the water date them with it.
  float SimTime();
  // Recorder (ren_WaterRec, tools/waterrec.py): the feeds report the hulls they push for, the simulation writes what it
  // holds around them.
  bool SimRecording();
  void SimRecordHull(float x, float z, float hx, float hz, float speed, float halfLength, float halfBeam, float radius);
  bool SimDiagnostics(); // ren_WaterSimLog is on: the feeds log what they see
  float SimImpactScale();

  // The level the simulation is built for (the sea's; the first wet water body's when the map has no sea); false when
  // the map has no water or the simulation is off.
  bool SimWaterLevel(float& elevation);

  // The water level at world (x, z): the one level of a map without water bodies, the level of the lake, the polder or
  // the sea that owns the place (STIMap::GetWaterElevationAt) with them. False where there is no water (a dry body, no
  // sea outside the bodies) or the simulation is off. What the sources are compared with: nothing that happens ashore
  // or over a dry polder moves the water.
  bool SimLevelAt(float x, float z, float& level);

  // Once per frame before the water is drawn: steps the simulation, makes the texture and binds it to the water effect.
  void StepWaterSimulation(const GeomCamera3& camera);

  // The projected grid (docs/WATER_SIMULATION.md): while the simulation is on, the water surface is drawn as a grid of
  // vertices that the vertex shader shoots along the camera rays onto the water plane and lifts by the height of the
  // simulation, so the waves are geometry, not only shading. Binds the grid's shader variables for this draw; false
  // when the grid is off (the shipped quad is drawn). It is off on a map with water bodies: WaterBodySurfaces draws one
  // water at a time there, and the grid of each is BindWaterGridLevel's.
  bool BindWaterGrid(const GeomCamera3& camera, float mapExtentX, float mapExtentZ);

  // One water of a map with water bodies, for the grid: the level, the number of the water (0 the sea), its rectangle
  // in world units, the map's extent and whether the grid's vertex sheet exists.
  struct GridLevel
  {
    float elevation = 0.0f;
    int body = 0;
    float x0 = 0.0f;
    float z0 = 0.0f;
    float x1 = 0.0f;
    float z1 = 0.0f;
    float extentX = 0.0f;
    float extentZ = 0.0f;
    bool sheetReady = false;
  };

  // The grid of one water: like BindWaterGrid, but for a map with water bodies, where the surface is drawn one water at
  // a time. The grid covers the part of the screen that holds the water's rectangle and the shader drops the pixels the
  // water does not own (`owner` is WaterBodySurfaces::OwnerTexture). False when the water is drawn as its meshes (the
  // grid is off, the water is off the screen, too many grids this frame): the call has switched the grid off then. Call
  // EndWaterGridLevels after the last water.
  bool
  BindWaterGridLevel(const GeomCamera3& camera, const GridLevel& level, const std::shared_ptr<ID3DTextureSheet>& owner);
  void EndWaterGridLevels();

  // Switches the projected grid off for the draw that follows (a river's mesh, which keeps its own heights): the grid
  // of the water drawn before it leaves its variables on.
  void BindWaterGridLevelOff();

  // Source patch of water2.fx: declares the variables and lets the ripples bend the normal and raise the wave crest.
  // Text in, text out.
  struct SimPatchResult
  {
    bool patched = false;
    std::string error;
  };
  SimPatchResult PatchWaterSimulation(std::string& source);

  // Whether the water effect should be patched (the option is on).
  bool SimWanted();

  // Frees the GPU resources (a device reset, shutdown).
  void ReleaseWaterSimulation();
} // namespace moho::water
