#pragma once

#include "editor/tools/EdUnitLab.h"
#include "editor/ui/EdUnitCatalog.h"

#include <string>
#include <vector>

namespace faf::editor
{
  class EdModPanel;

  /**
   * Unit lab (the Units workspace): a unit picked from the game's units, its fields from the game's blueprint
   * (economy, defence, movement, intel, weapons) as sliders over the game's value, changes into the open mod project
   * (each one an undo step of the project; a drag is one), a field or the whole unit back to the game's values, and
   * Test: the project written and played with its mod on.
   */
  class EdUnitLabPanel
  {
  public:
    explicit EdUnitLabPanel(EdModPanel& project);

    void Draw(bool& open, const std::vector<EdUnitInfo>& units, bool canPlay);

    /** The unit's values from the game's rules (empty when the rules or the unit aren't there). */
    [[nodiscard]] static UnitLabSource ReadUnit(const std::string& id);
    /** Whether the game's rules have the unit. */
    [[nodiscard]] static bool GameHasUnit(const std::string& id);
    /** Makes a derived unit of the selected one (an undo step) and selects it; false with `error`. */
    bool Derive(const std::string& id, const std::string& name, const std::string& description, std::string& error);
    void SelectUnit(
      const std::string& id
    )
    {
      mUnit = id;
    }
    [[nodiscard]] const std::string& Unit() const noexcept
    {
      return mUnit;
    }
    /** Changes a field of the selected unit (an undo step merged with the last one of the same key); false when it
     * didn't change. */
    bool SetField(const UnitLabField& field, double value, bool merge);
    /** Model from an OBJ was pressed for this derived unit (the app asks for the file and makes the model). */
    [[nodiscard]] bool TakeModelAsk(
      std::string& unit
    )
    {
      if (mModelAsk.empty()) {
        return false;
      }
      unit = std::exchange(mModelAsk, {});
      return true;
    }
    /** Test was pressed (the app writes, mounts and plays). */
    [[nodiscard]] bool TakeTestAsk() noexcept
    {
      const bool asked = mTestAsked;
      mTestAsked = false;
      return asked;
    }

  private:
    EdModPanel& mProject;
    std::string mUnit;
    char mFilter[64] = {};
    char mDeriveId[16] = {};
    char mDeriveName[64] = {};
    char mDeriveDescription[128] = {};
    bool mDeriveScript = false;
    std::string mDeriveError;
    bool mTestAsked = false;
    std::string mModelAsk;
  };
} // namespace faf::editor
