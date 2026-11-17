#pragma once

#include "editor/tools/EdUnitLab.h"
#include "editor/ui/EdUnitCatalog.h"

#include <expected>
#include <string>
#include <utility>
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
    /** Makes a derived unit of the selected one (an undo step) and selects it; or the error. */
    [[nodiscard]] std::expected<void, std::string>
    Derive(const std::string& id, const std::string& name, const std::string& description);
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

    /**
     * Test in game (FAF Studio's unittest.lua): Test, then the selected unit and dummy targets (ground, structure,
     * air, and a ship where there is water) placed for an enemy army near the first start, with quick orders and the
     * sim's state once a second. The app drives it; the panel asks and shows.
     */
    [[nodiscard]] bool TakeTestInGameAsk() noexcept
    {
      return std::exchange(mTestInGameAsked, false);
    }
    /** As the panel's buttons do (`/unittestgame`). */
    void AskTestInGame() noexcept
    {
      mTestInGameAsked = true;
    }
    void AskTestOrder(
      const std::string& order
    )
    {
      mTestOrder = order;
    }
    /** A quick order asked for: attack, move, patrol, stop, kill, heal, respawn, end ("" none). */
    [[nodiscard]] std::string TakeTestOrder()
    {
      return std::exchange(mTestOrder, {});
    }
    /** The test running (the unit under test, empty when none) and the sim's last state line. */
    std::string testUnit;
    std::string testStatus;
    std::string testNote; // the sim's last note (which builder builds it, ...)
    /** Studio's Effects panel in the test play: every projectile of the game (read before the play), the one picked and
     * its speed; an effect template (EffectTemplates.lua's name) and its height above the unit. */
    std::vector<std::string> testProjectiles;
    int testProjectile = 0;
    float testProjectileSpeed = 15.0f;
    char testEffect[96] = "ConcussionRingMed01";
    float testEffectHeight = 1.0f;

  private:
    /** The selected unit's weapons' projectiles: their numbers as project changes (Studio's fxedit.lua). */
    void DrawProjectiles();
    bool mTestInGameAsked = false;
    std::string mTestOrder;
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
