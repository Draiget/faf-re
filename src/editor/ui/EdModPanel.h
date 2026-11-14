#pragma once

#include "editor/doc/EdModProject.h"

#include <filesystem>
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
    /** Makes a project and opens it; false with `error` (a bad or taken name). */
    bool Create(const std::string& name, std::string& error);
    bool Open(const std::string& name, std::string& error);
    /** Writes the open project; its report. */
    ModWriteReport Write();
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
    /** A unit's weapon place by label in the game's blueprint (1-based; 0 when none). */
    [[nodiscard]] static int WeaponIndex(const std::string& id, const std::string& label);

  private:
    EdDocument& mDocument;
    std::optional<ModProject> mProject;
    std::filesystem::path mFolder;
    bool mDirty = false;
    char mNewName[65] = {};
    std::string mMessage;
    std::vector<std::string> mReport;
  };
} // namespace faf::editor
