#pragma once

#include <string>

#include "moho/render/lights/LightTexture.h"

// The colour of effect and unit textures read from the game's files, cached by path (docs/DYNAMIC_LIGHTS.md, "Colour").
// Render thread only (the worker that reads the files is private to the cache).
namespace moho::lights
{
  struct TexEntry
  {
    bool ok = false;
    TextureColour colour;
    Rgba8Image image; // the decoded top mip that fits 256 x 256: kept for ramps and for the unit glow analysis
  };

  enum class TextureState
  {
    Ready,   // `out` is the texture
    Pending, // a worker thread is reading it: ask again in a later frame, and use the neutral answer meanwhile
    Failed,  // the file cannot be read or decoded (remembered, the file is not tried again)
  };

  // Looks up the DDS file of a virtual path ("/textures/particles/glow_03.dds"). The first call for a path hands the
  // read and the decode to a worker thread (the render thread spent up to 14 ms of a frame on two maps), later calls
  // answer Pending until TrimTextureCache, once a frame, has taken the result into the cache. The pointer stays valid
  // until the next TrimTextureCache. FAF_LIGHT_TEXTURES_SYNC=1 reads on the calling thread as before (never Pending).
  [[nodiscard]] TextureState FindTexture(const std::string& path, const TexEntry*& out);

  // FindTexture as one pointer: nullptr while the texture is pending or when it failed. For callers whose answer for a
  // texture they do not have is the same either way and is asked for again every frame.
  const TexEntry* LoadTexture(const std::string& path);

  // The render thread analyses the textures of units it sees for the first time; on a first sight with dozens of unit
  // types that was one frame of 100 ms. A feed that can come back next frame asks first whether this frame's budget
  // (2 ms of reading and analysing) is spent, and leaves the rest for the following frames.
  [[nodiscard]] bool TextureBudgetLeft();
  // Analysis time (ms) the feed spent on textures it read, counted against the same budget.
  void NoteTextureWork(double milliseconds);

  // Clears the cache when it holds 512 textures. Called once a frame, before any feed holds a pointer (clearing inside
  // LoadTexture left the albedo of a unit dangling while its specular map loaded: a crash after a long game).
  void TrimTextureCache();
} // namespace moho::lights
