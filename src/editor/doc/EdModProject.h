#pragma once

#include <filesystem>
#include <functional>
#include <map>
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
  struct ModProject
  {
    std::string name;
    std::string uid;
    std::string author;
    std::string description;
    int version = 1;
    /** unit id -> key -> value */
    std::map<std::string, std::map<std::string, double>> edits;

    [[nodiscard]] bool Empty() const noexcept
    {
      return edits.empty();
    }
  };

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
