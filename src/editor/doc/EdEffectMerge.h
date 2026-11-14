#pragma once

#include "editor/doc/EdEmitter.h"

#include <string>

namespace faf::editor
{
  /**
   * An effect blueprint for a mod project (FAF Studio's effects output, design §8 Assets and mods): what an edited game
   * emitter, beam or trail changes, as a merge blueprint naming the game's file (`Merge = true`, `Source = '<path>'`;
   * FAF's EmitterBlueprint / BeamBlueprint / TrailEmitterBlueprint take their id from Source and merge into the game's
   * one). Entries are compared as the full writer writes them (WriteEmitter, WriteFlatBlueprint), so a changed field is
   * one line and a changed curve its whole block.
   *
   * FAF merges table by table and can't take a key away: a curve with fewer keys than the game's, or a field the game
   * has and the edit dropped, can't be a merge. The blueprint then replaces the game's whole (no Merge, the same
   * Source), and `replaced` says why.
   */
  struct EffectModBlueprint
  {
    std::string text; // empty: nothing changed
    int changed = 0;  // entries written (a merge) or that differ (a replacement)
    bool replaced = false;
    std::string why;
  };

  [[nodiscard]] EffectModBlueprint
  EmitterModBlueprint(const EmitterBlueprint& game, const EmitterBlueprint& edited, const std::string& source);
  [[nodiscard]] EffectModBlueprint
  FlatModBlueprint(const FlatBlueprint& game, const FlatBlueprint& edited, const std::string& source);
  /** Where a game effect's mod blueprint goes in the project: `/effects/emitters/x.bp` -> `effects/emitters/x.bp`. */
  [[nodiscard]] std::string EffectModFile(const std::string& source);
} // namespace faf::editor
