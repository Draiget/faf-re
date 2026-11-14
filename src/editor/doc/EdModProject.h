#pragma once

#include <filesystem>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * A mod project (FAF Studio's mod projects, design §8 Assets and mods): a folder in the vault's `mods` folder, so
   * the game lists it as a mod, with a generated `mod_info.lua` (a uid made once and kept), `editor_project.json`
   * (the project's changes, so it reopens; the previous good copy kept as `.bak`) and one merge blueprint per changed
   * unit: `units/<id>/<id>_unit.bp` with only the changed fields and `Merge = true`.
   *
   * A change's key is a path of the blueprint (`Economy.BuildCostMass`) or a weapon field by the weapon's label
   * (`Weapon:<Label>.Damage`). FAF merges a merge blueprint into the game's one table by table
   * (`lua/system/Blueprints.lua` StoreBlueprint, `table.merged`), so a weapon is written by its place in the unit's
   * `Weapon` list (`Weapon = { [2] = { Damage = 50 } }`), found from its label when the project is written.
   */
  /**
   * A derived unit: a new unit id made from one of the game's units without copying a file. The project's blueprint
   * hook (`hook/lua/system/Blueprints.lua`, FAF's ModBlueprints chain) deep-copies the base unit's blueprint under the
   * new id, merges the derived unit's changes into it (weapons by their place, as merge blueprints do) and sets its
   * name and description. Mesh, script, sounds and build menu entries stay the base unit's.
   */
  struct ModDerived
  {
    std::string base;
    std::string name;
    std::string description;
    /** It has an icon of its own in the project (`icons/units/<id>_icon.dds`): the hook names it (Display.IconName). */
    bool icon = false;
    /**
     * It has a script of its own (`units/<id>/<id>_script.lua`, a class built on the base unit's): the hook sets the
     * blueprint's ScriptModule to it (the engine otherwise runs the script beside the base's blueprint). The file is
     * written once and then the modder's.
     */
    bool script = false;
    /** Its model is the project's `units/<id>/<id>_lod0.scm` (made from an OBJ): the hook points every LOD at it. */
    bool model = false;
    bool operator==(const ModDerived&) const = default;
  };

  struct ModProject
  {
    std::string name;
    std::string uid;
    std::string author;
    std::string description;
    int version = 1;
    /** unit id -> key -> value (a derived unit's id too) */
    std::map<std::string, std::map<std::string, double>> edits;
    /** derived unit id -> what it is made from */
    std::map<std::string, ModDerived> derived;
    /**
     * The binary files the project wrote (icons), relative to its folder: they can't carry the generated mark, so this
     * list says they are the project's to write over.
     */
    std::set<std::string> files;

    [[nodiscard]] bool Empty() const noexcept
    {
      return edits.empty() && derived.empty();
    }
  };

  /** What a project's undo step holds: its changes and its derived units. */
  struct ModChanges
  {
    std::map<std::string, std::map<std::string, double>> edits;
    std::map<std::string, ModDerived> derived;
    bool operator==(const ModChanges&) const = default;
  };
  [[nodiscard]] inline ModChanges ModChangesOf(
    const ModProject& p
  )
  {
    return {p.edits, p.derived};
  }
  inline void ApplyModChanges(
    ModProject& p,
    const ModChanges& c
  )
  {
    p.edits = c.edits;
    p.derived = c.derived;
  }

  /** The first line of every file the project writes; a file without it is never overwritten. */
  extern const char* const kModProjectMark;

  /** A project name: letters, digits, spaces, _ and - (it is the folder's name too). */
  [[nodiscard]] bool ModProjectNameOk(const std::string& name);
  /** A unit id: lower case letters and digits, starting with a letter. */
  [[nodiscard]] bool ModUnitIdOk(const std::string& id);
  /** A new uid (a random UUID in mod_info's usual form). */
  [[nodiscard]] std::string NewModUid();

  /** Sets a change (a value back at the game's `base` removes it); false when nothing changed. */
  bool SetModEdit(ModProject& project, const std::string& id, const std::string& key, double value, double base);
  /** The weapon label and field of a `Weapon:<Label>.<Field>` key; false for any other key. */
  [[nodiscard]] bool ModWeaponKey(const std::string& key, std::string& label, std::string& field);

  /**
   * Adds a derived unit: `id` lower case letters and digits, at least 6, not a unit the game has (`gameHas`) or the
   * project derived already; `base` one the game has. False with `error`.
   */
  bool AddModDerived(
    ModProject& project,
    const std::string& id,
    const std::string& base,
    const std::string& name,
    const std::string& description,
    const std::function<bool(const std::string&)>& gameHas,
    std::string& error
  );
  /** The unit whose blueprint a unit's fields and weapons come from: a derived unit's base, else itself. */
  [[nodiscard]] std::string ModSourceUnit(const ModProject& project, const std::string& id);

  /** The game's `mod_info.lua` of the project. */
  [[nodiscard]] std::string ModInfoText(const ModProject& project);
  /** The uid of a `mod_info.lua` text (empty when it has none). */
  [[nodiscard]] std::string ModInfoUid(const std::string& text);

  /** A unit's weapon place in its `Weapon` list by label (1-based; 0 when it has no such weapon). */
  using ModWeaponIndex = std::function<int(const std::string& id, const std::string& label)>;
  /**
   * A unit's merge blueprint (only its changes). A weapon change whose label the unit doesn't have is left out and
   * named in `dropped`. Empty when the unit has no change left.
   */
  [[nodiscard]] std::string ModMergeBlueprint(
    const std::string& id,
    const std::map<std::string, double>& edits,
    const ModWeaponIndex& weaponIndex,
    std::vector<std::string>* dropped = nullptr
  );

  /**
   * The project's blueprint hook for its derived units (FAF's ModBlueprints chained); empty without derived units.
   * Weapon changes are found by label in the base unit; one it doesn't have is named in `dropped`.
   */
  [[nodiscard]] std::string ModDerivedHook(
    const ModProject& project,
    const ModWeaponIndex& weaponIndex,
    std::vector<std::string>* dropped = nullptr
  );
  /**
   * Where a unit's own icon goes in the project: FAF's UI finds a unit's icon in an active mod's folder as
   * `<mod>/icons/units/<IconName>_icon.dds` (UIUtil.UIFile with checkMods, the "Unit Icons" case).
   */
  [[nodiscard]] std::string ModUnitIconFile(const std::string& id);
  /** A derived unit's own script: its file in the project and its first text (a class on the base unit's). */
  [[nodiscard]] std::string ModUnitScriptFile(const std::string& id);
  /** A derived unit's own model in the project. */
  [[nodiscard]] std::string ModUnitModelFile(const std::string& id);
  [[nodiscard]] std::string ModUnitScriptText(const std::string& id, const std::string& base);
  /** Where the hook goes in the project's folder. */
  extern const char* const kModHookFile;

  [[nodiscard]] std::string SaveModProject(const ModProject& project);
  bool LoadModProject(const std::string& text, ModProject& project, std::string& error);

  /** Whether a text compiles as Lua (the editor's Lua; empty: it does). */
  using ModLuaCheck = std::function<std::string(const std::string& text, const std::string& name)>;

  struct ModWriteReport
  {
    std::vector<std::string> written;  // project-relative paths
    std::vector<std::string> problems; // what wasn't written, and why
  };

  /**
   * Writes the project into `folder`: mod_info.lua, editor_project.json (+ .bak of the one before), the merge
   * blueprints. A file that doesn't compile, or one the project didn't write (no mark), is left alone and named in
   * the report. Merge blueprints of units without changes any more are removed if the project wrote them.
   */
  ModWriteReport WriteModProject(
    const std::filesystem::path& folder,
    const ModProject& project,
    const ModWeaponIndex& weaponIndex,
    const ModLuaCheck& check
  );
  /**
   * Writes one generated file into a project folder (through a temporary file), unless a file is there the project
   * didn't make (no mark on its first line); false with `error`.
   */
  bool ModWriteGenerated(
    const std::filesystem::path& folder,
    const std::string& relative,
    const std::string& text,
    std::string& error
  );
  /**
   * Writes a binary file into the project (an icon), over one there only when the project wrote it (its `files`
   * list), and adds it to that list; false with `error`.
   */
  bool ModWriteBinary(
    ModProject& project,
    const std::filesystem::path& folder,
    const std::string& relative,
    const std::string& bytes,
    std::string& error
  );
  /** What the checks know about the game and the disk. */
  struct ModCheckFacts
  {
    std::function<bool(const std::string&)> gameHas;     // the game has this unit
    ModWeaponIndex weaponIndex;                          // a unit's weapon place by label (0: none)
    std::function<bool(const std::string&)> gameHasFile; // the game's files have this path (a derived unit's icon)
    std::string diskUid;                                 // mod_info.lua's uid on disk ("" when none)
    bool written = true;                                 // the project hasn't changed since it was written
  };
  struct ModIssue
  {
    char level = 'W'; // 'E' the game won't take it as meant, 'W' likely a mistake, 'I' worth knowing
    std::string text;
  };
  /**
   * The open project's checks (FAF Studio's modcheck): its name and uid, mod_info.lua on disk, unit ids, units the
   * game doesn't have, derived units' bases and ids, weapon changes whose label the unit doesn't have, keys that aren't
   * blueprint paths, values that break a unit (no health, nothing to build it), derived units without a name or an
   * icon, and changes not written yet.
   */
  [[nodiscard]] std::vector<ModIssue> CheckModProject(const ModProject& project, const ModCheckFacts& facts);

  /**
   * A release of the project for the vault: the files under its folder but the editor's own (editor_project.json and
   * its .bak, half-written files), in the zip under one folder named for the project; with the version in the name.
   */
  struct ModRelease
  {
    std::string folder; // the zip's top folder
    std::string zipName;
    std::vector<std::string> files;
  };
  [[nodiscard]] ModRelease PlanModRelease(const ModProject& project, const std::vector<std::string>& files);

  /** Reads a project folder: editor_project.json, else its .bak (`fromBackup`); the uid from mod_info.lua. */
  bool OpenModProject(
    const std::filesystem::path& folder,
    ModProject& project,
    std::string& error,
    bool* fromBackup = nullptr
  );
  /** The projects in a mods folder (folders with an editor_project.json), sorted. */
  [[nodiscard]] std::vector<std::string> ModProjectsIn(const std::filesystem::path& mods);
} // namespace faf::editor
