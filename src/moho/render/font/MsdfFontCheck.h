#pragma once

#include <cstddef>
#include <string>

#include "moho/render/font/MsdfFontCook.h"

namespace moho
{
  /** The largest mod font. The game's biggest font is 367 KB. */
  constexpr std::size_t kMsdfMaxFontBytes = 32u * 1024u * 1024u;

  /**
   * FAF addition, not in the shipped binary (issue #305).
   *
   * What a file from a mod has to be before any parser sees it: a plain TrueType or OpenType file whose
   * every byte belongs to a table on the allowed list, or pads one to four bytes. That leaves no place to
   * append a program or hide one in a private table. Bytes inside an allowed table aren't checked here:
   * they only matter through a parser bug, and the cook meets them with FreeType's hinting programs off and
   * its memory, work and time limited (`MSDF_MakeModCookOptions`).
   *
   * It reads nothing but the header and the table directory, and never calls a font library, so it runs
   * before any parser sees the file. False with `reason` set for anything else.
   */
  [[nodiscard]] bool MSDF_CheckFontStructure(const void* bytes, std::size_t byteCount, std::string& reason);

  /**
   * Whether Lua may load a font from this path: under `/mods/<mod>/fonts/`, a `.ttf` or `.otf`, and nothing that
   * could climb out of the folder. The path still goes through the virtual file system, so it never reaches
   * past the mounted game folders anyway.
   */
  [[nodiscard]] bool MSDF_IsAllowedModFontPath(const char* path, std::string& reason);

  /**
   * Whether an atlas that passed `MSDF_LoadAtlas`, so one with sound counts and rectangles, can have come
   * from these options: its size and range, codepoints that were asked for, and quads of a sane size. A
   * cache file is shared by every game on the machine, so it isn't trusted to have kept to them.
   */
  [[nodiscard]] bool MSDF_CheckCookedAtlas(const SMsdfFontAtlas& atlas, const SMsdfCookOptions& options, std::string& reason);
} // namespace moho
