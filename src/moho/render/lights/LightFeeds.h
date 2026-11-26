#pragma once

#include "gpg/gal/DeviceContext.hpp"

#include <cstddef>
#include <string>
#include <vector>

#include "moho/render/lights/LightCollector.h"
#include "moho/render/lights/LightGrid.h"

namespace moho
{
  struct SParticleBuffer;
  struct GeomCamera3;
} // namespace moho

// Engine side of the dynamic lights: reads the engine's effect records into the light pool (LightCollector) and
// evaluates the pool once per rendered frame. Render only; nothing here reads or writes sim state, so replay parity is
// unaffected.
//
// Stage 1 (docs/DYNAMIC_LIGHTS.md): the "TLight" particles of CreateLightParticle.
// Stage 2: BeginFrame also builds the light textures' CPU image (LightGrid) for the active map and uploads and binds it
// (LightBinding). Nothing draws the lights yet (the shaders do not declare the parameters); see ren_DynLightsView for a
// debug view of the grid.
namespace moho::lights
{
  // Quality level, model::kOff..model::kUltra (Options > Video > Dynamic Lights later; console variable ren_DynLights
  // meanwhile).
  extern int ren_DynLights;

  // The one pool of the render thread.
  LightCollector& Collector();

  // Whether the effects are patched with the light pass on this API: the Dynamic Lights option is not Off (render
  // features registry), or /dynlights is on the command line.
  bool LightsWanted(gpg::gal::DeviceApi api);

  // Whether the engine's two effect-light systems must yield to this one: the Dynamic Lights option is not Off and the
  // mesh or terrain effect in use carries the light pass (CD3DEffect::InitEffectFromFile tells through
  // NoteEffectPatched). The screen-space explosion and weapon lights of DynamicLights.h (ren_DynamicLights) neither
  // collect nor draw while this is true: the two never run together, and the lights of the irradiance field are the
  // ones that have shadows and are shaded by the materials. When the patch is refused (a FAF update changed the shader)
  // this stays false and the screen-space lights work as their own option says.
  bool Enabled();

  // The effect `baseName` ("mesh", "terrain", "water2") was (re)built with (patched) or without the light pass. Not for
  // the background compile of a live switch, which builds throw-away effects.
  void NoteEffectPatched(const std::string& baseName, bool patched);

  // The calling thread is one of the background compiles of a live switch, which build throw-away effects (not to be
  // reported to the renderer features as the effects in use).
  bool OnWarmupThread();

  // Called once at the start of a rendered frame, before anything is drawn. When the lights were switched on (Options
  // or ren_DynLights) after the effects were built without the light pass, the effects that carry it (mesh, terrain,
  // water2) are rebuilt once with it: the game stands still for the compile, and the lights are on afterwards without a
  // restart. Returns true when it rebuilt them: whatever was set once on those effects (the water and terrain variables
  // the terrain renderer sets when it is created) is lost with the old effects, so the caller makes the terrain
  // renderers again.
  bool ApplyLiveLevel();

  // Applies the console variable to the pool (a lower level drops the lights it no longer admits).
  void SyncQuality();

  // Called when the user sync of a beat adds its particle buffer to the world particles (CWldSession); `beatTick` is
  // the tick of that beat.
  void FeedParticleBuffer(const SParticleBuffer& batch, int beatTick);

  // Called once per rendered frame after MeshRenderer::Batch: the glowing unit and projectile meshes on screen become
  // lights (nowTick = tick + frame alpha).
  void FeedMeshes(float nowTick);

  // The beams of the last beats, with their endpoints worked out for this frame (the beam renderer's own interpolation,
  // so the light sits where the beam is drawn). Called by BeginFrame.
  void FeedBeamsForFrame(int tick, float frameAlpha);

  // Called once per rendered world view before the terrain is composited, with the clock the particle shaders use (tick
  // + frame alpha).
  void BeginFrame(int tick, float frameAlpha);

  // Called after BeginFrame for each world view that is about to draw: tells the shaders where the camera is, and feeds
  // the test light.
  void SetView(GeomCamera3& camera);

  // Console variable ren_DynLightsTest N: every N ticks a flash (size 12, 2 seconds) appears on the ground in the
  // middle of the view.
  extern int ren_DynLightsTest;

  // Console variable ren_DynLightsShadows (default 1): the shadow casters of the view shade the dynamic lights
  // (docs/DYNAMIC_LIGHTS.md, "Shadows").
  extern int ren_DynLightsShadows;

  // The shadow casters of the last FeedMeshes (the previous frame's batch: the terrain is lit before this frame's
  // meshes are batched).
  const std::vector<Occluder>& FrameOccluders();

  // The lights of the last BeginFrame, strongest first.
  const std::vector<Light>& FrameLights();

  // The texture images built from them (empty while no map is loaded); what LightBinding uploads and the debug view
  // draws.
  const LightGridImage& FrameImage();

  constexpr std::size_t kMaxFrameLights =
    4096; // = kMaxGridLights: the lights of a frame are limited by the data texture, not by shader registers
} // namespace moho::lights
