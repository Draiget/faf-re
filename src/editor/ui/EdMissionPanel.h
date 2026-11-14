#pragma once

#include "editor/tools/EdMission.h"

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
    void DrawRunPanel(bool& open, bool mapOpen, bool playing, const std::vector<std::string>& newTrace);
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

    EdDocument& mDocument;
    int mStage = 0;
    int mSection = 0;       // 0 enter, 1 ready
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
    bool mFocusStages = false;
  };
} // namespace faf::editor
