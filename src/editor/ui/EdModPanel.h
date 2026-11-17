#pragma once

#include "editor/doc/EdModProject.h"
#include "editor/tools/EdUnitLab.h"

#include <expected>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace faf::editor
{
  class EdDocument;

  /**
   * Mod project (the Units workspace): the projects in the vault's `mods` folder, New and Open, the open one's name,
   * author, description and its changes per unit, and Write (mod_info.lua, the project file, a merge blueprint per
   * changed unit). The unit lab sets the changes.
   */
  class EdModPanel
  {
  public:
    explicit EdModPanel(EdDocument& document);

    void Draw(bool& open);

    /** The folder the projects are in: the vault's `mods`. */
    [[nodiscard]] std::filesystem::path Root() const;
    /** Makes a project and opens it; the error for a bad or taken name. */
    [[nodiscard]] std::expected<void, std::string> Create(const std::string& name);
    [[nodiscard]] std::expected<void, std::string> Open(const std::string& name);
    /** Writes the open project; its report. */
    ModWriteReport Write();
    /** The open project's checks now. */
    [[nodiscard]] std::vector<ModIssue> Check();
    /**
     * Zip for the vault: the project written, then its files but the editor's own zipped under one folder into the
     * vault's `editor_releases` folder; the zip's path, or the error.
     */
    [[nodiscard]] std::expected<std::filesystem::path, std::string> Release();
    [[nodiscard]] ModProject* Project() noexcept
    {
      return mProject ? &*mProject : nullptr;
    }
    [[nodiscard]] const std::filesystem::path& Folder() const noexcept
    {
      return mFolder;
    }
    /** Marks the open project as changed since it was written. */
    void Touch() noexcept
    {
      mDirty = true;
    }
    [[nodiscard]] bool Dirty() const noexcept
    {
      return mDirty;
    }
    /** The open project's undo history (cleared when another project opens). */
    [[nodiscard]] ModEditHistory& History() noexcept
    {
      return mHistory;
    }
    /** A unit's weapon place by label in the game's blueprint (1-based; 0 when none). */
    [[nodiscard]] static int WeaponIndex(const std::string& id, const std::string& label);
    /** The same for a project's unit (a derived unit's weapons are its base unit's). */
    [[nodiscard]] static int WeaponIndexIn(const ModProject& project, const std::string& id, const std::string& label);

  private:
    EdDocument& mDocument;
    std::optional<ModProject> mProject;
    std::filesystem::path mFolder;
    bool mDirty = false;
    char mNewName[65] = {};
    std::string mMessage;
    std::vector<std::string> mReport;
    ModEditHistory mHistory;
    std::map<std::string, bool> mIcons; // derived unit icon path -> the game has it
  };
} // namespace faf::editor
