#pragma once

#include "editor/tools/EdMission.h"
#include "editor/tools/EdMissionImport.h"

#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace faf::editor
{
  class EdDocument;

  /** The map's armies, unit groups, chains, areas and markers, for the mission's fields and checks. */
  [[nodiscard]] MissionFacts MissionFactsOf(const EdDocument& document);

  /**
   * The Mission workspace's panels (FAF Studio's mission panels): Stages (the mode, the stages, each one's enter and
   * ready nodes as a tree with containers, the selected node's settings) and Strings (the dialogues and their lines).
   * Every change is an undo step of the map; Save compiles the mission into the script.
   */
  class EdMissionPanel
  {
  public:
    explicit EdMissionPanel(EdDocument& document);
    void DrawStagesPanel(bool& open, bool mapOpen);
    void DrawStringsPanel(bool& open, bool mapOpen);
    /** Bases: the mission's BaseManagers (groups, engineers, switches) and their attacks (OpAI). */
    void DrawBasesPanel(bool& open, bool mapOpen);
    /** Platoons: the mission's platoon templates (a unit type per row) and order queues. */
    void DrawPlatoonsPanel(bool& open, bool mapOpen);
    /**
     * Run: a test play's progress (the stage it is in, the nodes it reached, a trigger dropped because its stage had
     * moved on), each entry a jump to its node in Stages; Play from a stage.
     */
    void DrawRunPanel(
      bool& open,
      bool mapOpen,
      bool playing,
      const std::vector<std::string>& newTrace,
      const std::string* live = nullptr
    );
    /** The newest state the play reported (the Live section). */
    [[nodiscard]] const MissionLive& Live() const noexcept
    {
      return mLive;
    }
    /** Bases > Define from area (FAF Studio's mbase.lua DefineFromArea): what the map gets (the app does it). */
    struct DefineBaseAsk
    {
      std::string name;
      std::string army;
      float x = 0.0f; // the area's middle
      float z = 0.0f;
      std::vector<std::string> units; // the army's units inside the area
    };
    [[nodiscard]] bool TakeDefineBaseAsk(
      DefineBaseAsk& ask
    )
    {
      if (mDefineAsk.name.empty()) {
        return false;
      }
      ask = std::exchange(mDefineAsk, {});
      return true;
    }
    /** Test runs (`/definebase <name>,<army>,<area>`): as the section's button. */
    [[nodiscard]] std::expected<void, std::string>
    DefineBaseFromArea(const std::string& name, const std::string& army, const std::string& area);
    /** Play from a stage was pressed (the shell starts the open map). */
    [[nodiscard]] bool TakePlayAsk() noexcept
    {
      const bool asked = mPlayAsked;
      mPlayAsked = false;
      return asked;
    }
    [[nodiscard]] std::size_t TraceCount() const noexcept
    {
      return mTrace.size();
    }

  private:
    /** An edit made now (a button): `before` is the mission as it was. */
    void Edited(Mission before);
    void BeginField();
    void EndField(bool edited);
    void DrawNodes(std::vector<MissionNode>& list, int section, std::vector<int> path, int depth);
    void DrawParams(MissionNode& node, const MissionFacts& facts);
    [[nodiscard]] std::vector<MissionNode>* ListOf(Mission& m, int section, const std::vector<int>& path);
    [[nodiscard]] MissionNode* NodeAt(Mission& m, int section, const std::vector<int>& path);

    /** The Platoons panel's builders view: an army's PlatoonBuilders listed, edited, added, deleted. */
    void DrawBuilders();
    /**
     * Stages > Hand-written script (Studio's missionimport.lua): the map's own `_script.lua` read as text into an
     * outline (stages, functions, objectives, triggers, AI, dialogues, options), shown read-only; the `_strings.lua`
     * dialogues can be added to the Strings.
     */
    void DrawImported();
    void ReadImported();
    bool mImportedRead = false;
    MissionOutline mImported;
    std::vector<ImportedStageRows> mImportedRows;
    std::vector<MissionDialogue> mImportedDialogues;
    std::string mImportNote;
    std::string mImportedFor; // the map it was read for
    EdDocument& mDocument;
    int mStage = 0;
    int mSection = 0;       // 0 enter, 1 ready
    int mAddSection = 1;    // where Add puts a node when none is selected (Add here)
    std::vector<int> mPath; // the selected node (0-based through the children); empty: none
    int mDialogue = 0;
    std::optional<Mission> mFieldBefore; // a text field being typed in: the mission before it
    std::vector<std::string> mTrace;
    int mBase = -1;
    int mPlatoon = -1;
    int mQueue = -1;
    std::string mFromArmy;
    std::string mFromGroup;
    int mAttack = -1;
    bool mWasPlaying = false;
    bool mPlayAsked = false;
    int mTimerScale = 0;
    MissionLive mLive;
    bool mHasLive = false;
    /** Platoons: a template's or an order queue's used-by line, Copy, Rename (with its references), Assign to group. */
    void DrawPlatoonTools(bool templateKind, const std::string& name, const MissionFacts& facts);
    char mRenameTemplate[64] = "";
    char mRenameQueue[64] = "";
    std::string mAssignArmy;
    std::string mAssignGroup;
    DefineBaseAsk mDefineAsk;
    char mDefineName[48] = "Base1";
    int mDefineArmy = 0;
    int mDefineArea = 0;
    char mNewFlag[64] = "";
    double mLiveAskedAt = -10.0;
    bool mFocusStages = false;
  };
} // namespace faf::editor
