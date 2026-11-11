#pragma once

#include <string>
#include <vector>

namespace faf::editor
{
  /** One lobby option of a map's `_options.lua`: its key, label and values (each a key the script reads and a text). */
  struct LobbyOptionInfo
  {
    struct Value
    {
      /** The value's key as written: `2` or `'true'`. */
      std::string key;
      bool number = false;
      double numberKey = 0.0;
      std::string text;
      std::string help;
    };
    std::string key;
    std::string label;
    std::string help;
    std::vector<Value> values;
    /** `default`: the lobby's first pick, an index into `values` from 1 (FAF's lobby reads it so); 0 when none. */
    int defaultIndex = 0;
  };
  /** The options in an `_options.lua`'s text (`options = { {...}, ... }`); commented-out ones are not there. */
  std::vector<LobbyOptionInfo> ParseLobbyOptions(const std::string& optionsText);

  /**
   * Which lobby settings make a map's script create a unit group, read from the script itself: the `if`, `elseif`,
   * `else`, `for` and `while` around each `CreateArmyGroup(army, 'name', wreckage)` (and its kin), the functions that
   * call the one it is in, and the options the script reads (`local x = ScenarioInfo.Options.key or 1`). A name made as
   * `'Optional_Wreckage_' .. w` in `for w = 2, optional_wreckage` exists for w within the loop's bounds. Conditions on
   * anything else (who plays which slot, factions) are "maybe".
   */
  struct GroupLobbyRule
  {
    enum class Made
    {
      No,
      Yes,
      Maybe,
    };
    struct Case
    {
      /** A value index (into the option's values) per key in `keys`; -1 for a key the lobby doesn't offer. */
      std::vector<int> picks;
      Made made = Made::No;
      /** What it is made as, in the settings where it may be made. */
      bool asWreck = false;
      bool asUnit = false;
    };
    /** Some creation in the script names the group. */
    bool scriptNames = false;
    /** The options the decision reads, in the script's order. */
    std::vector<std::string> keys;
    /** Per key: its option in `_options.lua`, or -1 when the lobby doesn't offer it (the script's default then). */
    std::vector<int> optionIndex;
    /** Per key: the script's default (`or 1`) as written, empty when it has none. */
    std::vector<std::string> scriptDefault;
    /** Every combination of the keys' values (at most 256). */
    std::vector<Case> cases;
    /** No setting creates it. */
    [[nodiscard]] bool Never() const;
  };
  GroupLobbyRule LobbyRuleOfGroup(const std::string& script, const std::vector<LobbyOptionInfo>& options, const std::string& group);

  /** The rule as lines for the Properties panel: which option, and what each of its values does to the group. */
  std::vector<std::string> DescribeLobbyRule(const GroupLobbyRule& rule, const std::vector<LobbyOptionInfo>& options);

  /**
   * A level loop in a map's script: `for w = 2, optional_wreckage do CreateArmyGroup('ARMY_17', 'Optional_Wreckage_' .. w,
   * true) end`: the lobby option's value v creates the groups `<prefix>from` .. `<prefix>v`.
   */
  struct ScriptGroupLoop
  {
    std::string prefix;
    std::string army; // as written; empty when made at run time
    std::string key;  // the option the loop's end reads
    int from = 2;
    bool wreck = false;
  };
  std::vector<ScriptGroupLoop> ScriptGroupLoops(const std::string& script);

  /** The first lobby setting that creates the group, as `Wreckage = "T3 wreckage"`; "every game"; or why never. */
  std::string LobbyRuleWhen(const GroupLobbyRule& rule, const std::vector<LobbyOptionInfo>& options);

  /**
   * A group a unit of `army` can be put in so that the script brings it into games (user ask 2026-11-11: edit the
   * adaptive groups, not only read about them): each group the script creates for the army (the names it writes, and
   * `'Name_' .. k` for each level an option reaches), the next level of a looped option, and groups whose option the
   * lobby lacks. Where no lobby setting creates the group yet, `optionsWith` is `_options.lua` with the value (or the
   * whole option) that does, kept only when reading the rule again with it shows the group created.
   */
  struct SpawnTarget
  {
    /** Its path in the army's tree (an existing group's own; a new one at the top). */
    std::vector<std::string> path;
    bool exists = false;
    GroupLobbyRule rule;
    /** LobbyRuleWhen, with `optionsWith` applied when there is one. */
    std::string when;
    bool wreck = false;
    bool unit = false;
    /** `_options.lua` with what makes it spawn added; empty when it already spawns with some setting. */
    std::string optionsWith;
    /** What `optionsWith` adds, in a few words. */
    std::string optionsChange;
  };
  std::vector<SpawnTarget> SpawnTargets(const std::string& script, const std::string& optionsText, const std::string& army,
                                        const std::vector<std::vector<std::string>>& groupPaths);
} // namespace faf::editor
