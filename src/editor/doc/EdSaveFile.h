#pragma once

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace faf::editor
{
  /**
   * One named entry of a `_save.lua` block (a marker, an area): its name and its properties in file order,
   * each as its key and its value's text as written (`STRING( 'Mass' )`, `VECTOR3( 1, 2, 3 )`), so
   * properties the editor has no use for are written back unchanged.
   */
  struct SaveEntry
  {
    std::string name;
    std::vector<std::pair<std::string, std::string>> properties;

    /** A property's value text, or empty. */
    [[nodiscard]] std::string Get(const std::string& key) const;
    /** Sets a property's value text, appending it when new. */
    void Set(const std::string& key, const std::string& value);
    bool operator==(const SaveEntry& other) const { return name == other.name && properties == other.properties; }
  };

  /** A marker or area value's numbers (`VECTOR3( 1, 2, 3 )` gives 1, 2, 3). */
  std::vector<double> ValueNumbers(const std::string& value);
  /** The text inside a value's quotes (`STRING( 'Mass' )` gives Mass). */
  std::string ValueString(const std::string& value);
  /** `VECTOR3( x, y, z )`, `RECTANGLE( x0, y0, x1, y1 )` and `STRING( 'text' )` as the game's saves write them. */
  std::string Vector3Value(double x, double y, double z);
  std::string RectangleValue(double x0, double y0, double x1, double y1);
  std::string StringValue(const std::string& text);

  /**
   * A map's `_save.lua` as the editor keeps it: the file's text, with the master chain's markers and the
   * areas parsed out. Text writes the file again: unchanged, or with only the blocks whose entries
   * changed written anew in the game's own layout, everything else as it was.
   */
  /** Where a save entry was in the text: what came before it (space, banners), itself with its comma, its values. */
  struct SaveEntrySpan
  {
    std::size_t lead = 0;
    std::size_t start = 0;
    std::size_t end = 0;
    std::vector<std::pair<std::size_t, std::size_t>> values;
  };

  class SaveFile
  {
  public:
    /** Parses the file's text; false (with `error`) when the blocks can't be found or read. */
    bool Parse(std::string text, std::string& error);

    [[nodiscard]] std::vector<SaveEntry>& Markers() noexcept { return mMarkers; }
    [[nodiscard]] std::vector<SaveEntry>& Areas() noexcept { return mAreas; }
    [[nodiscard]] std::vector<SaveEntry>& Armies() noexcept { return mArmies; }
    [[nodiscard]] const std::vector<SaveEntry>& Markers() const noexcept { return mMarkers; }
    [[nodiscard]] const std::vector<SaveEntry>& Areas() const noexcept { return mAreas; }
    [[nodiscard]] const std::vector<SaveEntry>& Armies() const noexcept { return mArmies; }

    /** The file's text with the current markers and areas. */
    [[nodiscard]] std::string Text() const;
    /** True when Text() differs from the text parsed. */
    [[nodiscard]] bool Changed() const;
    /** After the file was written: what it holds now is the text parsed. */
    void MarkSaved();
    [[nodiscard]] bool Loaded() const noexcept { return !mText.empty(); }

  private:
    struct Block
    {
      std::size_t open = 0;  // the '{'
      std::size_t close = 0; // the matching '}'
      int indent = 0;        // the entries' indent
      bool found = false;
      std::vector<SaveEntrySpan> spans; // the entries as read
    };
    /**
     * A changed block's new text: unchanged entries as they were read (with the space and banners before them), a
     * changed entry with the same keys as its old text with only the changed values replaced, other entries written
     * in the game's layout with the file's line ends.
     */
    std::string Rebuild(const Block& block, const std::vector<SaveEntry>& now, const std::vector<SaveEntry>& read) const;
    std::string mText;
    Block mMarkerBlock;
    Block mAreaBlock;
    Block mArmyBlock;
    std::vector<SaveEntry> mArmies;
    std::vector<SaveEntry> mArmiesRead;
    std::vector<SaveEntry> mMarkers;
    std::vector<SaveEntry> mAreas;
    std::vector<SaveEntry> mMarkersRead;
    std::vector<SaveEntry> mAreasRead;
  };

  /** A new army's entry for `_save.lua`'s Armies, as the game's saves write one (no units, no plans). */
  SaveEntry NewArmyEntry(const std::string& name);

  /** A team of a `_scenario.lua`'s standard configuration: its name and its armies, in order. */
  struct ScenarioTeam
  {
    std::string name;
    std::vector<std::string> armies;
    bool operator==(const ScenarioTeam& other) const { return name == other.name && armies == other.armies; }
  };
  /** The teams of the scenario's `teams = { { name = 'FFA', armies = {...} }, ... }`, in order. */
  std::vector<ScenarioTeam> ScenarioTeams(const std::string& scenario);
  /**
   * The scenario with its `teams` block written from `teams`, each team on one line as the game's scenarios write
   * them; the text around it is kept.
   */
  std::string WithScenarioTeams(const std::string& scenario, const std::vector<ScenarioTeam>& teams);

  /** The armies of a `_scenario.lua`'s first team (`armies = {'ARMY_1', ...}`), in order. */
  std::vector<std::string> ScenarioArmies(const std::string& scenario);
  /** The scenario with its first team's armies replaced. */
  std::string WithScenarioArmies(const std::string& scenario, const std::vector<std::string>& armies);
  /** The scenario's extra armies (`customprops`' `ExtraArmies`, names split on spaces). */
  std::vector<std::string> ScenarioExtraArmies(const std::string& scenario);
  std::string WithScenarioExtraArmies(const std::string& scenario, const std::vector<std::string>& armies);

  /**
   * The playable area a map's `_script.lua` sets (`ScenarioFramework.SetPlayableArea('AREA_1', ...)`, FAF's
   * way: simInit runs OnPopulate and OnStart, and the area is a rectangle of `_save.lua`), or none.
   */
  std::optional<std::string> ScriptPlayableArea(const std::string& script);

  /**
   * The script with its playable area set to `area` (the call added to OnPopulate after
   * `ScenarioUtils.InitializeArmies()`, or its area name replaced), or removed when `area` is empty.
   */
  std::string WithScriptPlayableArea(const std::string& script, const std::string& area);
} // namespace faf::editor
