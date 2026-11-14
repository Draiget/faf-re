#pragma once

// The New unit panel (FAF Studio's panels_unitwiz.lua): the project's wizard units (`editor_newunits.json`), a new one
// from a template and faction, its settings, Write (the files into the project) and Check (the validators).

#include "editor/tools/EdUnitWizard.h"

#include <functional>
#include <string>
#include <vector>

namespace faf::editor
{
  class EdModPanel;

  class EdUnitWizardPanel
  {
  public:
    explicit EdUnitWizardPanel(EdModPanel& project);
    void Draw(bool& open);
    /** What the checks and the id test ask of the game (set by the app). */
    std::function<bool(const std::string&)> gameHasUnit;
    std::function<bool(const std::string&)> gameFileExists;
    /** Test runs (`/unitwiztest <template>,<faction>`): a unit made, written and checked in the open project. */
    std::string Test(const std::string& templateId, const std::string& faction);

  private:
    bool Data();
    void LoadSpecs();
    void SaveSpecs();
    bool Taken(const std::string& id) const;
    void DrawSpec(UnitWizardSpec& spec);

    EdModPanel& mProject;
    UnitWizardData mData;
    bool mDataTried = false;
    std::string mDataError;
    std::string mFolder; // the project folder the specs were read from
    std::vector<UnitWizardSpec> mSpecs;
    int mCurrent = -1;
    int mNewTemplate = 0;
    int mNewFaction = 0;
    int mNewWeaponKind = 0;
    bool mDirty = false;
    std::vector<std::string> mReport;
    std::vector<UnitCheck> mChecks;
  };
} // namespace faf::editor
