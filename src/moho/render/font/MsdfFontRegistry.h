#pragma once

#include <cstddef>
#include <memory>

#include "moho/render/font/MsdfFontCook.h"

namespace moho
{
  /**
   * FAF addition, not in the shipped binary (issue #306).
   *
   * Which font files the engine has, and their MSDF atlases. A font is cooked the first time text asks
   * for it, on one background thread at below-normal priority, and the atlas is kept in
   * `<local data>/fontcache` under a hash of the file and the cook settings, so a later start reads it
   * back. The folder sits beside the engine's cache folder, which `/purgecache` empties.
   *
   * Asking never waits: until an atlas is ready the caller draws the way it did before.
   */
  void MSDF_RegisterFontFile(const char* path, const void* fontBytes, std::size_t byteCount);

  /**
   * The atlas for a face name, as `CD3DFont::Create` gets it (any case). Null while it is cooking, and
   * for names no registered file answers to, such as a system font.
   */
  [[nodiscard]] std::shared_ptr<const SMsdfFontAtlas> MSDF_FindAtlas(const char* faceName);

  /** Lets the background thread finish its current font and stop. Safe to call more than once. */
  void MSDF_ShutdownFontRegistry();
} // namespace moho
