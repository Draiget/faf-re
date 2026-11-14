#pragma once

// Mission import (FAF Studio's missionimport.lua): a hand-written campaign `_script.lua` shown in the mission editor
// without touching it. The script is read as TEXT and never run; strings and comments are blanked first, so a keyword,
// bracket or call inside them is ignored. A `_strings.lua` is read the same way for its dialogues.
//
// Engine independent (tests/editor/MissionImportTests.cpp).

#include "editor/tools/EdMission.h"

#include <map>
#include <string>
#include <vector>

namespace faf::editor
{
  struct ImportedFunction
  {
    std::string name;
    int line = 0;
    int endLine = 0;
    int stage = -1;  // -1: none
    std::string how; // sets | name | called | ""
    std::string role;
  };

  struct ImportedObjective
  {
    std::string call;
    std::string name;
    std::string var;
    std::string otype;
    std::string complete;
    std::string title;
    std::string titleExpr;
    std::string description;
    std::string descriptionExpr;
    bool group = false;
    int line = 0;
    std::string fn;
    int stage = -1;
  };

  struct ImportedTrigger
  {
    std::string kind;
    std::string target;
    std::string callback;
    int line = 0;
    std::string fn;
    int stage = -1;
  };

  struct ImportedHelper
  {
    std::string name;
    std::string kind; // ai module | opai | platoon
    int count = 0;
    int line = 0;
    std::string fn;
    int stage = -1;
  };

  struct ImportedImport
  {
    std::string var;
    std::string path;
    int line = 0;
    bool ai = false;
  };

  struct ImportedDialogueRef
  {
    std::string name;
    int count = 0;
    int line = 0;
    std::string fn;
    int stage = -1;
  };

  struct ImportedOption
  {
    std::string key;
    int count = 0;
    int line = 0;
  };

  struct ImportedStage
  {
    int number = 0;
    std::string name;
    std::string entry;
    int line = 0;
  };

  /** The outline of a hand-written script. */
  struct MissionOutline
  {
    int lineCount = 0;
    std::vector<ImportedStage> stages; // by number
    std::vector<ImportedFunction> functions;
    std::vector<ImportedObjective> objectives;
    std::vector<ImportedTrigger> triggers;
    std::vector<ImportedHelper> helpers;
    std::vector<ImportedImport> imports;
    std::vector<ImportedDialogueRef> dialogueRefs;
    std::vector<ImportedOption> options;
    int difficultyUses = 0;
    int difficultyBranches = 0;
    int difficultyLine = 0;
    std::vector<std::string> notes;
  };

  /** Strings and comments blanked (`plain`, the quotes of a string kept) and comments blanked (`code`); same length. */
  void MaskLua(const std::string& text, std::string& plain, std::string& code);

  [[nodiscard]] MissionOutline ParseMissionScript(const std::string& text);

  /** One row of an imported stage for the Stages panel: text, extra (line numbers), kind. */
  struct ImportedRow
  {
    std::string text;
    std::string extra;
    std::string kind; // note | function | objective | trigger | ai | detail
  };
  /** An imported stage: number 0 is what the script does outside the numbered stages. */
  struct ImportedStageRows
  {
    int number = 0;
    std::string name;
    std::vector<ImportedRow> rows;
  };
  [[nodiscard]] std::vector<ImportedStageRows> ImportedStages(const MissionOutline& outline);

  /** The dialogues of a `_strings.lua` (tables of lines with text, character, delay; and the plain strings). */
  [[nodiscard]] std::vector<MissionDialogue> ParseMissionStrings(const std::string& text);
} // namespace faf::editor
