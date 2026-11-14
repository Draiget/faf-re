#pragma once

#include <array>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * Missions (FAF Studio's mission.lua): stages of action, objective, trigger and flow nodes, compiled into the map's
   * `_script.lua` between `-- >>> EDITOR MISSION v1` and `-- <<< EDITOR MISSION` with a hash (a region edited by hand
   * is left alone). A stage is one forked function: its enter nodes, then its ready nodes; the objectives of a stage
   * are one group whose completion starts the next stage (the last ends the operation with a win unless it has an End
   * node); a stage without objectives starts the next at once unless it has a failsafe timer, an End or a Next stage
   * node. A failsafe timer starts the next stage after that many seconds whatever the objectives. Every value a mapper
   * types reaches the script through one of the quoting helpers: a string literal, a finite number, an identifier, or
   * one category expression of a small alphabet.
   */
  struct MissionNode
  {
    std::string type;
    std::map<std::string, std::string> p; // parameter values as text (numbers as text, booleans "true" / "false")
    std::vector<MissionNode> children;    // container nodes only
  };

  struct MissionStage
  {
    std::string name;
    double failsafe = 0.0; // seconds; 0 = none
    std::vector<MissionNode> enter;
    std::vector<MissionNode> ready;
  };

  struct MissionDialogueLine
  {
    std::string text;
    std::string speaker;
    double seconds = 5.0;
  };

  struct MissionDialogue
  {
    std::string name;
    std::vector<MissionDialogueLine> lines;
  };

  /**
   * A base (FAF Studio's mbase.lua): a BaseManager the mission starts with a Start a base node. It is set up with the
   * army's unit groups and their priorities, spawns them (or starts empty for its engineers to build), and arms its
   * attack AIs (OpAI: platoons of a kind built and sent along patrol chains). The campaign AI brain builds them.
   */
  struct MissionBaseGroup
  {
    std::string name;
    double priority = 100.0;
  };

  struct MissionOpAI
  {
    std::string name = "Attack1";
    std::string ptype = "BasicLandAttack"; // MissionOpAITypes
    std::vector<std::string> children;     // the platoon kinds (MissionOpAIChildren)
    std::array<double, 3> qty{4.0, 6.0, 8.0};
    std::string master = "patrol chain picker"; // MissionOpAIMasters
    std::vector<std::string> chains;
    double priority = 100.0;
    std::string lock = "None"; // MissionOpAILocks
    double lockSecs = 60.0;
    std::array<std::string, 2> cond{"none", "none"}; // MissionOpAIConditions
    std::array<std::array<double, 3>, 2> condCount{{{10.0, 6.0, 4.0}, {10.0, 6.0, 4.0}}};
    std::array<double, 2> condStage{1.0, 1.0};
    std::array<std::string, 2> condFlag;
  };

  struct MissionBase
  {
    std::string name;
    std::string army;
    std::string marker;
    double radius = 40.0;
    bool diff = false;       // groups per difficulty (<group>_D1 .. _D3)
    bool startEmpty = false; // engineers build it (else all groups are spawned)
    std::array<double, 3> engineers{2.0, 4.0, 6.0};
    std::array<double, 3> assist{0.0, 0.0, 0.0};
    double maxBuild = 0.0;
    bool alwaysAssist = false;
    double supportAcus = 0.0;
    std::vector<std::string> switchOn;
    std::vector<std::string> switchOff;
    std::vector<std::string> noBuild;
    std::vector<MissionBaseGroup> groups;
    std::vector<MissionOpAI> opai;
  };

  [[nodiscard]] const std::vector<std::string>& MissionBaseActive(); // Shields, Fabrication, ... (SetActive)
  [[nodiscard]] const std::vector<std::string>& MissionBaseBuild();  // Engineers, AntiAir, ... (SetBuild)
  [[nodiscard]] const std::vector<std::string>& MissionOpAITypes();
  [[nodiscard]] const std::vector<std::string>& MissionOpAIChildren(const std::string& type);
  [[nodiscard]] const std::vector<std::string>& MissionOpAIMasters();
  [[nodiscard]] const std::vector<std::string>& MissionOpAILocks();
  [[nodiscard]] const std::vector<std::string>& MissionOpAIConditions();
  /** A new base on an army, with its marker named `<name>_Marker`. */
  [[nodiscard]] MissionBase NewMissionBase(const std::string& name, const std::string& army);

  /**
   * A platoon template (the save file's `Platoons` layout: name, AI plan, one row per unit type), registered in
   * `Scenario.Platoons` when the script loads: a Spawn a group as a platoon node can make a group's units that platoon.
   */
  struct MissionPlatoonRow
  {
    std::string bp;
    double min = 1.0;
    double max = 1.0;
    std::string squad = "attack";   // MissionPlatoonSquads
    std::string formation = "None"; // MissionPlatoonFormations
  };

  struct MissionPlatoon
  {
    std::string name;
    std::string plan;
    std::vector<MissionPlatoonRow> rows;
  };

  /** An order queue: orders given in turn to a platoon (along a chain or to one marker). */
  struct MissionOrder
  {
    std::string type = "Move"; // MissionOrderTypes
    std::string target;        // a marker
    std::string chain;         // a chain (used before the marker)
  };

  struct MissionOrderQueue
  {
    std::string name;
    std::vector<MissionOrder> orders;
  };

  [[nodiscard]] const std::vector<std::string>& MissionPlatoonSquads();
  [[nodiscard]] const std::vector<std::string>& MissionPlatoonFormations();
  [[nodiscard]] const std::vector<std::string>& MissionOrderTypes();
  /** A template or queue name: letters, digits, _ and -. */
  [[nodiscard]] bool MissionIsTemplateName(const std::string& text);
  /** The builder names of an army's `PlatoonBuilders` table text (`{ Builders = { name = {...}, ... } }`). */
  [[nodiscard]] std::vector<std::string> MissionBuilderNames(const std::string& platoonBuilders);

  struct Mission
  {
    std::string mode = "campaign"; // campaign, coop, both
    std::vector<MissionStage> stages;
    std::vector<MissionDialogue> dialogues;
    std::vector<MissionBase> bases;
    std::vector<MissionPlatoon> platoons;
    std::vector<MissionOrderQueue> orderQueues;
    [[nodiscard]] bool Empty() const noexcept
    {
      return stages.empty();
    }
  };

  /** A parameter of a node type. `kind`: army, group, var, text, number, bool, choice, chain, area, marker, unit,
   * dialogue, base. */
  struct MissionParam
  {
    std::string key;
    std::string label;
    std::string kind;
    std::string value; // the default as text
    std::vector<std::string> choices;
    double min = 0.0;
    double max = 0.0;
    bool defines = false;  // a var parameter that sets the variable (others read it)
    bool optional = false; // may stay empty
    std::string vtype;     // var: "objective" for objective names
  };

  /** A node's parameters as its emitter reads them: the default where the node has none. */
  struct MissionValues
  {
    const MissionNode* node = nullptr;
    const std::vector<MissionParam>* params = nullptr;
    [[nodiscard]] std::string S(const std::string& key) const;
    [[nodiscard]] double N(const std::string& key) const;
    [[nodiscard]] bool B(const std::string& key) const;
  };

  struct MissionEmit;
  using MissionEmitter = std::function<std::vector<std::string>(const MissionValues&, const MissionEmit&)>;

  struct MissionNodeType
  {
    std::string id;
    std::string family; // action, objective, flow, trigger, coop
    std::string title;
    bool container = false;
    bool callback = false; // a container whose children run later (a trigger): a stage guard keeps them quiet after
    std::vector<MissionParam> params;
    MissionEmitter emit;
  };

  /** The catalogue, in the palette's order. */
  [[nodiscard]] const std::vector<MissionNodeType>& MissionNodeTypes();
  [[nodiscard]] const MissionNodeType* FindMissionNodeType(const std::string& id);
  /** A new node of a type with its parameters at their defaults. */
  [[nodiscard]] MissionNode NewMissionNode(const std::string& type);

  /** Whether code compiles (the editor's Lua; null in tests: the compile checks are skipped). */
  using LuaCompiles = std::function<bool(const std::string& code, std::string& error)>;

  struct MissionProblem
  {
    char level = 'W'; // 'E', 'W', 'I'
    std::string text;
    int stage = 0; // 1-based; 0 for the mission
    std::string section;
    std::vector<int> path;
  };

  /** What emitters ask: the stage, the next stage's call, the node's address, whether in a callback or a test run. */
  struct MissionEmit
  {
    int stage = 0;
    std::string nextCall;
    bool inCallback = false;
    bool test = false;
    bool strict = false;
    std::string section;
    std::vector<int> path;
    std::vector<MissionProblem>* problems = nullptr;
    const LuaCompiles* compiles = nullptr;
    const Mission* mission = nullptr; // its order queues
    [[nodiscard]] std::string Addr() const;
    /** A container's children as lines, each with `prefix` in front (a callback's children run in it). */
    [[nodiscard]] std::vector<std::string>
    Body(const MissionNode& node, const std::string& prefix, bool callback) const;
  };

  /** The quoting helpers (exposed for tests): a Lua string literal, a finite number, an identifier, a variable field.
   */
  [[nodiscard]] std::string MissionQuote(const std::string& text);
  [[nodiscard]] std::string MissionNumber(double value, double fallback = 0.0);
  [[nodiscard]] bool MissionIsName(const std::string& text);
  [[nodiscard]] std::string MissionVar(const std::string& name);
  /** One category expression of the allowed alphabet, in parentheses; else `fallback`. */
  [[nodiscard]] std::string
  MissionExpr(const std::string& text, const std::string& fallback, const LuaCompiles* compiles);

  /** The node with values its emitter can take: an unknown choice, a number that isn't finite, a bad boolean become
   * the defaults; `fixed` counts them. */
  [[nodiscard]] MissionNode
  CleanMissionNode(const MissionNode& node, const MissionNodeType& type, int* fixed = nullptr);

  struct MissionCompileOptions
  {
    bool withEntry = true; // OnPopulate / OnStart (a script that has its own gets EditorMissionStart only)
    bool test = false;     // a test run: traces (EdTrace), the run state, start at any stage
    bool hasArea1 = false; // OnPopulate sets the playable area AREA_1
    int startStage = 1;    // a test run starts here (ScenarioInfo.EditorStartStage overrides it)
    LuaCompiles compiles;
  };

  /** The region's body: the header, helpers, one function per stage, the entry functions. */
  [[nodiscard]] std::string CompileMission(
    const Mission& mission,
    const MissionCompileOptions& options,
    std::vector<MissionProblem>* problems = nullptr
  );

  /**
   * A trace id of a test play: `stage.<n>` (a stage entered) or `<stage>.<section>.<path>` with `!` (a trigger's
   * callback ran) or `~` (it was dropped: its stage had moved on) at the end. `path` is 1-based through the children.
   */
  struct MissionTraceId
  {
    int stage = 0;
    std::string section; // empty: the stage itself
    std::vector<int> path;
    char mark = 0; // 0, '!' or '~'
  };
  bool ParseMissionTrace(const std::string& id, MissionTraceId& out);

  /** The region's hash (Studio's: Adler-like sums, two five-digit numbers). */
  [[nodiscard]] std::string MissionHash(const std::string& text);

  enum class MissionPatch
  {
    None,     // no mission: the script as it was
    Written,  // the region written or replaced
    Detached, // the region was edited by hand: left alone
  };
  /** The script with the mission's region written (or replaced); `status` says what happened. */
  [[nodiscard]] std::string PatchMissionScript(
    const std::string& script,
    const Mission& mission,
    const MissionCompileOptions& options,
    MissionPatch& status
  );

  /** What the checks look at besides the mission: the map's armies, unit groups, chains, areas and markers. */
  struct MissionFacts
  {
    std::vector<std::string> armies;
    std::map<std::string, std::vector<std::string>> groups; // army -> its group names
    std::vector<std::string> chains;
    std::vector<std::string> areas;
    std::vector<std::string> markers;
    std::map<std::string, std::vector<std::string>> builders; // army -> its platoon builders
  };

  /** The lines that give platoon expression `target` the orders of queue `queue` (a comment when there's none). */
  [[nodiscard]] std::vector<std::string>
  MissionOrderLines(const Mission& mission, const std::string& target, const std::string& queue);

  /**
   * Checks: an empty stage, an unknown node, a value that had to be replaced, a missing army / group / chain / area /
   * marker / dialogue, a variable read before any node sets it, a coop node in a campaign mission, a Next stage node in
   * the last stage, a failsafe without a next stage, a mission that never ends, an empty dialogue, a broken category.
   */
  [[nodiscard]] std::vector<MissionProblem>
  CheckMission(const Mission& mission, const MissionFacts& facts, const LuaCompiles* compiles = nullptr);

  /** The mission as JSON (kept beside the map); empty for no stages and no dialogues. */
  [[nodiscard]] std::string SaveMission(const Mission& mission);
  bool LoadMission(const std::string& text, Mission& mission, std::string& error);
} // namespace faf::editor
