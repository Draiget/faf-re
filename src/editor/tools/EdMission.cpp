#include "editor/tools/EdMission.h"

#include "editor/doc/EdJson.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <set>

namespace faf::editor
{
  namespace
  {
    const char* const kBegin = "-- >>> EDITOR MISSION v1";
    const char* const kFinish = "-- <<< EDITOR MISSION";
    const char* const kCountCat = "categories.ALLUNITS";

    using Lines = std::vector<std::string>;

    bool Finite(
      const double v
    )
    {
      return std::isfinite(v) && v > -1e300 && v < 1e300;
    }

    std::string OneLine(
      std::string text
    )
    {
      for (char& c : text) {
        if (static_cast<unsigned char>(c) < 32) {
          c = ' ';
        }
      }
      return text;
    }

    Lines SplitLines(
      const std::string& text
    )
    {
      Lines out;
      std::size_t at = 0;
      while (true) {
        const std::size_t nl = text.find('\n', at);
        out.push_back(text.substr(at, nl == std::string::npos ? std::string::npos : nl - at));
        if (nl == std::string::npos) {
          break;
        }
        at = nl + 1;
      }
      return out;
    }

    std::string Join(
      const Lines& lines
    )
    {
      std::string out;
      for (std::size_t i = 0; i < lines.size(); ++i) {
        out += lines[i];
        if (i + 1 < lines.size()) {
          out += '\n';
        }
      }
      return out;
    }

    Lines Wrap(
      const std::string& head,
      const Lines& body,
      const std::string& tail
    )
    {
      Lines out{head};
      out.insert(out.end(), body.begin(), body.end());
      out.push_back(tail);
      return out;
    }

    MissionParam P(
      std::string key,
      std::string label,
      std::string kind,
      std::string value = {},
      std::vector<std::string> choices = {},
      const double min = 0.0,
      const double max = 0.0
    )
    {
      MissionParam p;
      p.key = std::move(key);
      p.label = std::move(label);
      p.kind = std::move(kind);
      p.value = std::move(value);
      p.choices = std::move(choices);
      p.min = min;
      p.max = max;
      return p;
    }

    MissionParam Defines(
      MissionParam p,
      const std::string& vtype = {}
    )
    {
      p.defines = true;
      p.optional = true;
      p.vtype = vtype;
      return p;
    }

    MissionParam Optional(
      MissionParam p
    )
    {
      p.optional = true;
      return p;
    }

    const std::vector<std::string> kObjTypes = {"primary", "secondary", "bonus"};
    const std::vector<std::string> kFormations = {"GrowthFormation", "AttackFormation", "NoFormation"};
    const std::vector<std::string> kCompare = {">=", "<=", "==", ">", "<"};
    const std::vector<std::string> kIcons = {"kill", "protect", "move", "build", "capture", "reclaim", "repair"};

    std::string Q(
      const std::string& s
    )
    {
      return MissionQuote(s);
    }
    std::string Num(
      const double v,
      const double fallback = 0.0
    )
    {
      return MissionNumber(v, fallback);
    }
    std::string Var(
      const std::string& name
    )
    {
      return MissionVar(name);
    }

    MissionParam StageOnly()
    {
      return P("stageOnly", "Only while this stage runs", "bool", "true");
    }

    std::vector<MissionParam> ObjHead(
      const std::string& title,
      const std::string& description
    )
    {
      MissionParam reminder = Optional(P("reminder", "Reminder dialogue (optional)", "dialogue"));
      return {
        P("otype", "Type", "choice", "primary", kObjTypes),
        P("title", "Title", "text", title),
        P("description", "Description", "text", description),
        Defines(P("name", "Name for triggers (optional)", "var"), "objective"),
        reminder,
        P("reminderSecs", "Reminder every (seconds)", "number", "120", {}, 10, 1800),
      };
    }

    std::vector<MissionParam> Concat(
      std::vector<MissionParam> a,
      const std::vector<MissionParam>& b
    )
    {
      a.insert(a.end(), b.begin(), b.end());
      return a;
    }

    /** The lines after an objective was made: its name, the stage's group, the reminder. */
    Lines ObjTail(
      const MissionValues& n,
      const MissionEmit& C
    )
    {
      Lines out;
      if (!n.S("name").empty()) {
        out.push_back(Var(n.S("name")) + " = obj");
      }
      if (!C.inCallback) {
        out.push_back("Group:AddObjective(obj)");
      }
      out.push_back("table.insert(AssignedObjectives, obj)");
      if (!n.S("reminder").empty()) {
        out.push_back("do");
        out.push_back("    local o = obj");
        out.push_back("    ForkThread(function()");
        out.push_back("        while true do");
        out.push_back("            Wait(" + Num(n.N("reminderSecs"), 120) + ")");
        out.push_back(
          std::string("            if not o.Active") +
          (C.inCallback ? "" : " or ScenarioInfo.MissionNumber ~= " + std::to_string(C.stage)) + " then return end"
        );
        out.push_back("            ScenarioFramework.Dialogue(Strings[" + Q(n.S("reminder")) + "])");
        out.push_back("        end");
        out.push_back("    end)");
        out.push_back("end");
      }
      return out;
    }

    Lines Objective(
      const std::string& call,
      const MissionValues& n,
      const std::string& target,
      const MissionEmit& C
    )
    {
      Lines lines{
        std::string(C.inCallback ? "local obj = " : "obj = ") + "Objectives." + call + "(" + Q(n.S("otype")) +
        ", 'incomplete', " + Q(n.S("title")) + ", " + Q(n.S("description")) + target + ")"
      };
      for (const std::string& l : ObjTail(n, C)) {
        lines.push_back(l);
      }
      return lines;
    }

    /** A callback's body: the stage guard, then the children; `fork` puts it in its own thread. */
    Lines CallbackBody(
      const MissionValues& n,
      const MissionEmit& C,
      const bool fork
    )
    {
      Lines lines;
      const std::string pad = fork ? "        " : "    ";
      if (fork) {
        lines.push_back("    ForkThread(function()");
      }
      if (n.B("stageOnly")) {
        lines.push_back(
          pad + "if ScenarioInfo.MissionNumber ~= " + std::to_string(C.stage) + " then " +
          (C.test ? "EdTrace(" + Q(C.Addr() + "~") + ") " : std::string()) + "return end"
        );
      }
      if (C.test) {
        lines.push_back(pad + "EdTrace(" + Q(C.Addr() + "!") + ")");
      }
      const Lines body = C.Body(*n.node, pad, true);
      lines.insert(lines.end(), body.begin(), body.end());
      if (body.empty()) {
        lines.push_back(pad + "-- (nothing to do)");
      }
      if (fork) {
        lines.push_back("    end)");
      }
      return lines;
    }

    Lines Container(
      const std::string& head,
      const MissionValues& n,
      const MissionEmit& C
    )
    {
      Lines body = C.Body(*n.node, "    ", false);
      if (body.empty()) {
        body.push_back("    -- (nothing to do)");
      }
      return Wrap(head, body, "end");
    }

    std::vector<MissionNodeType> BuildCatalogue()
    {
      std::vector<MissionNodeType> c;
      const auto add = [&](
                         std::string id,
                         std::string family,
                         std::string title,
                         std::vector<MissionParam> params,
                         MissionEmitter emit,
                         const bool container = false,
                         const bool callback = false
                       ) {
        MissionNodeType t;
        t.id = std::move(id);
        t.family = std::move(family);
        t.title = std::move(title);
        t.params = std::move(params);
        t.emit = std::move(emit);
        t.container = container;
        t.callback = callback;
        c.push_back(std::move(t));
      };
      const MissionParam army = P("army", "Army", "army");
      const MissionParam group = P("group", "Group", "group");
      const MissionParam var = P("var", "Group variable", "var");
      const MissionParam keepVar = Defines(P("var", "Keep as variable (optional)", "var"));

      add(
        "spawn",
        "action",
        "Spawn group",
        {army,
         group,
         P("bydiff", "Group per difficulty (<group>_D1 .. _D3)", "bool", "false"),
         keepVar,
         P("wreck", "As wreckage", "bool", "false")},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        const std::string g = Q(n.S("group")) + (n.B("bydiff") ? " .. '_D' .. Difficulty" : "");
        const std::string call =
          "ScenarioUtils.CreateArmyGroup(" + Q(n.S("army")) + ", " + g + (n.B("wreck") ? ", true" : "") + ")";
        if (!n.S("var").empty()) {
          return {Var(n.S("var")) + " = " + call};
        }
        return {call};
      }
      );
      add(
        "platoon_patrol",
        "action",
        "Spawn platoon on a patrol chain",
        {army,
         group,
         P("chain", "Chain", "chain"),
         P("formation", "Formation", "choice", "GrowthFormation", kFormations),
         keepVar},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        const std::string target = !n.S("var").empty() ? Var(n.S("var")) : "platoon";
        return {
          std::string(target == "platoon" ? "local " : "") + target + " = ScenarioUtils.CreateArmyGroupAsPlatoon(" +
            Q(n.S("army")) + ", " + Q(n.S("group")) + ", " + Q(n.S("formation")) + ")",
          "ScenarioFramework.PlatoonPatrolChain(" + target + ", " + Q(n.S("chain")) + ")"
        };
      }
      );
      add(
        "group_patrol",
        "action",
        "Send a spawned group on a patrol chain",
        {var, P("chain", "Chain", "chain")},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        return {"ScenarioFramework.GroupPatrolChain(" + Var(n.S("var")) + ", " + Q(n.S("chain")) + ")"};
      }
      );
      add(
        "dialogue",
        "action",
        "Mission text",
        {P("text", "Text", "text"), P("seconds", "Shown for (seconds)", "number", "5", {}, 0, 60)},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        return {
          "ScenarioFramework.Dialogue({ { text = " + Q(n.S("text")) + ", delay = " + Num(n.N("seconds"), 5) +
          " } }, nil, true)"
        };
      }
      );
      add(
        "wait",
        "flow",
        "Wait",
        {P("seconds", "Seconds", "number", "10", {}, 0, 3600)},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        return {"Wait(" + Num(n.N("seconds"), 10) + ")"};
      }
      );
      add(
        "restrict",
        "action",
        "Restrict / allow units",
        {P("mode", "Mode", "choice", "restrict", {"restrict", "allow"}),
         army,
         P("categories", "Categories (e.g. categories.TECH3)", "text", "categories.TECH3")},
        [](const MissionValues& n, const MissionEmit& C) -> Lines {
        const std::string fn = n.S("mode") == "allow" ? "RemoveRestriction" : "AddRestriction";
        return {
          "ScenarioFramework." + fn + "(" + Q(n.S("army")) + ", " +
          MissionExpr(n.S("categories"), kCountCat, C.compiles) + ")"
        };
      }
      );
      add(
        "resources",
        "action",
        "Give resources",
        {army, P("mass", "Mass", "number", "0", {}, 0, 100000), P("energy", "Energy", "number", "0", {}, 0, 500000)},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        Lines out;
        if (n.N("mass") != 0.0) {
          out.push_back("GetArmyBrain(" + Q(n.S("army")) + "):GiveResource('MASS', " + Num(n.N("mass")) + ")");
        }
        if (n.N("energy") != 0.0) {
          out.push_back("GetArmyBrain(" + Q(n.S("army")) + "):GiveResource('ENERGY', " + Num(n.N("energy")) + ")");
        }
        if (out.empty()) {
          out.push_back("-- (no resources given)");
        }
        return out;
      }
      );
      add(
        "playable",
        "action",
        "Set playable area",
        {P("area", "Area", "area")},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        return {"ScenarioFramework.SetPlayableArea(" + Q(n.S("area")) + ", true)"};
      }
      );
      add(
        "vision",
        "action",
        "Reveal a place",
        {P("marker", "Marker", "marker"),
         P("radius", "Radius", "number", "40", {}, 1, 500),
         P("seconds", "Seconds (0 = forever)", "number", "30", {}, 0, 3600),
         army},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        return {
          "ScenarioFramework.CreateVisibleAreaLocation(" + Num(n.N("radius"), 40) +
          ", ScenarioUtils.MarkerToPosition(" + Q(n.S("marker")) + "), " + Num(n.N("seconds"), 30) + ", GetArmyBrain(" +
          Q(n.S("army")) + "))"
        };
      }
      );
      add(
        "wait_dead",
        "flow",
        "Wait until a group is destroyed",
        {var, P("remaining", "Until at most this many are left", "number", "0", {}, 0, 500)},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        return {"while Alive(" + Var(n.S("var")) + ") > " + Num(n.N("remaining")) + " do Wait(1) end"};
      }
      );
      const MissionParam area = P("area", "Area", "area");
      const MissionParam counted = P("army", "Army whose units count", "army");
      const MissionParam category = P("category", "Category", "text", kCountCat);
      const MissionParam compare = P("compare", "Compare", "choice", ">=", kCompare);
      const MissionParam count = P("value", "Count", "number", "1", {}, 0, 500);
      add(
        "wait_area",
        "flow",
        "Wait until units are in an area",
        {area, counted, category, compare, count},
        [](const MissionValues& n, const MissionEmit& C) -> Lines {
        const std::string cat = MissionExpr(n.S("category"), kCountCat, C.compiles);
        return {
          "while not (CountInArea(" + Q(n.S("area")) + ", " + Q(n.S("army")) + ", " + cat + ") " + n.S("compare") +
          " " + Num(n.N("value"), 1) + ") do Wait(1) end"
        };
      }
      );
      add(
        "set_alliance",
        "action",
        "Set alliance",
        {army, P("other", "Towards army", "army"), P("state", "State", "choice", "Ally", {"Ally", "Enemy", "Neutral"})},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        return {"SetAlliance(" + Q(n.S("army")) + ", " + Q(n.S("other")) + ", " + Q(n.S("state")) + ")"};
      }
      );
      add("kill_group", "action", "Destroy a group", {var}, [](const MissionValues& n, const MissionEmit&) -> Lines {
        return {"for _, u in " + Var(n.S("var")) + " or {} do if u and not u.Dead then u:Kill() end end"};
      });
      add(
        "give_group",
        "action",
        "Give a group to an army",
        {var, P("army", "To army", "army")},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        return {
          "for _, u in " + Var(n.S("var")) +
          " or {} do if u and not u.Dead then ScenarioFramework.GiveUnitToArmy(u, GetArmyBrain(" + Q(n.S("army")) +
          "):GetArmyIndex()) end end"
        };
      }
      );
      add(
        "set_flag",
        "action",
        "Set a flag (read by OpAI build conditions)",
        {P("flag", "Flag name", "text", "ATTACK_NOW"), P("value", "Value", "bool", "true")},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        return {"ScenarioInfo.VarTable[" + Q(n.S("flag")) + "] = " + (n.B("value") ? "true" : "false")};
      }
      );
      add(
        "transport_drop",
        "action",
        "Drop reinforcements by transport",
        {army,
         P("group", "Group (transports and cargo)", "group"),
         P("landing", "Landing chain (one of its markers)", "chain"),
         P("attack", "Patrol chain after the drop", "chain"),
         P("instant", "Cargo is attached at once (no loading trip)", "bool", "true"),
         P("formation", "Formation", "choice", "GrowthFormation", kFormations)},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        return {
          "ScenarioFramework.PlatoonAttackWithTransports(ScenarioUtils.CreateArmyGroupAsPlatoon(" + Q(n.S("army")) +
          ", " + Q(n.S("group")) + ", " + Q(n.S("formation")) + "), " + Q(n.S("landing")) + ", " + Q(n.S("attack")) +
          ", " + (n.B("instant") ? "true" : "false") + ")"
        };
      }
      );
      add(
        "taunt",
        "action",
        "Play a multiplayer taunt",
        {P("head", "Head (1-8)", "number", "1", {}, 1, 8), P("taunt", "Taunt number (1-48)", "number", "1", {}, 1, 48)},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        return {"ScenarioFramework.PlayTaunt(" + Num(n.N("head"), 1) + ", " + Num(n.N("taunt"), 1) + ")"};
      }
      );
      add(
        "nuke_barrage",
        "action",
        "Nuke barrage: launchers of a group fire at a place",
        {P("var", "Launcher group variable", "var"),
         P("marker", "Target marker", "marker"),
         P("count", "Missiles per launcher", "number", "1", {}, 1, 10),
         P("spread", "Scatter radius", "number", "0", {}, 0, 200),
         P("fill", "Load the silos first (no build time)", "bool", "true")},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        const int missiles = std::clamp(static_cast<int>(std::floor(Finite(n.N("count")) ? n.N("count") : 1.0)), 1, 50);
        const std::string spread = Num(n.N("spread"));
        return {
          "do",
          "    local target = ScenarioUtils.MarkerToPosition(" + Q(n.S("marker")) + ")",
          "    for _, u in " + Var(n.S("var")) + " or {} do",
          "        if u and not u.Dead then",
          n.B("fill") ? "            u:GiveNukeSiloAmmo(" + std::to_string(missiles) + ")" : std::string(),
          "            for i = 1, " + std::to_string(missiles) + " do",
          "                IssueNuke({ u }, { target[1] + (Random() - 0.5) * 2 * " + spread +
            ", target[2], target[3] + (Random() - 0.5) * 2 * " + spread + " })",
          "            end",
          "        end",
          "    end",
          "end"
        };
      }
      );
      add(
        "dialogue_table",
        "action",
        "Play a dialogue (from the Strings panel)",
        {P("name", "Dialogue", "dialogue")},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        return {"ScenarioFramework.Dialogue(Strings[" + Q(n.S("name")) + "], nil, true)"};
      }
      );
      add(
        "coop_commanders",
        "coop",
        "Coop: spawn player commanders",
        {P("unit", "Unit name in the army (Commander)", "text", "Commander"),
         P("byFaction", "Use UEFPlayer / AeonPlayer / CybranPlayer by faction", "bool", "true"),
         P("effect", "Arrival effect", "choice", "Warp", {"Warp", "Gate", "none"}),
         P("death", "Lose the mission when all commanders are dead", "bool", "true")},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        const std::string effect = n.S("effect") == "none" ? "false" : Q(n.S("effect"));
        std::string unit = Q(n.S("unit"));
        if (n.B("byFaction")) {
          unit = "({ 'UEFPlayer', 'AeonPlayer', 'CybranPlayer' })[GetArmyBrain(name):GetFactionIndex()] or " + unit;
        }
        const std::string trigger =
          n.B("death") ? "function(cdr) ScenarioFramework.PlayerDeath(cdr, nil, AssignedObjectives) end" : "nil";
        return {
          "ScenarioInfo.CoopCDR = ScenarioInfo.CoopCDR or {}",
          "for name, _ in ScenarioInfo.HumanPlayers or {} do",
          "    ScenarioInfo.CoopCDR[name] = ScenarioFramework.SpawnCommander(name, " + unit + ", " + effect +
            ", true, true, " + trigger + ")",
          "end"
        };
      }
      );
      add(
        "coop_unitcap",
        "coop",
        "Coop: shared unit cap",
        {P("cap", "Cap shared by the living players", "number", "1000", {}, 100, 4000)},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        return {
          "if rawget(ScenarioFramework, 'SetSharedUnitCap') then ScenarioFramework.SetSharedUnitCap(" +
          Num(n.N("cap"), 1000) + ") end"
        };
      }
      );
      add(
        "coop_restrict",
        "coop",
        "Coop: restrict / allow units for all humans",
        {P("mode", "Mode", "choice", "restrict", {"restrict", "allow"}),
         P("categories", "Categories", "text", "categories.TECH3"),
         P("unlock", "Play the unlock voice when allowing", "bool", "false")},
        [](const MissionValues& n, const MissionEmit& C) -> Lines {
        const std::string cats = MissionExpr(n.S("categories"), kCountCat, C.compiles);
        if (n.S("mode") == "allow") {
          return {
            "if rawget(ScenarioFramework, 'RemoveRestrictionForAllHumans') then "
            "ScenarioFramework.RemoveRestrictionForAllHumans(" +
            cats + ", " + (n.B("unlock") ? "true" : "false") + ") end"
          };
        }
        return {
          "if rawget(ScenarioFramework, 'AddRestrictionForAllHumans') then "
          "ScenarioFramework.AddRestrictionForAllHumans(" +
          cats + ") end"
        };
      }
      );
      add(
        "coop_announce",
        "coop",
        "Coop: announcement on screen",
        {P("text", "Headline", "text"), Optional(P("second", "Second line (optional)", "text"))},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        return {
          "if rawget(ScenarioFramework, 'SimAnnouncement') then ScenarioFramework.SimAnnouncement(" + Q(n.S("text")) +
          ", " + Q(n.S("second")) + ") end"
        };
      }
      );
      add(
        "coop_player_death",
        "coop",
        "Coop: lose when all player commanders are dead",
        {Optional(P("dialogue", "Failure dialogue (optional)", "dialogue"))},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        const std::string fail = n.S("dialogue").empty() ? "nil" : "Strings[" + Q(n.S("dialogue")) + "]";
        return {
          "for _, index in ScenarioInfo.HumanPlayers or {} do",
          "    for _, cdr in ArmyBrains[index]:GetListOfUnits(categories.COMMAND, false) do",
          "        ScenarioFramework.CreateUnitDeathTrigger(function(unit) ScenarioFramework.PlayerDeath(unit, " +
            fail + ", AssignedObjectives) end, cdr)",
          "    end",
          "end"
        };
      }
      );
      add(
        "if_players",
        "flow",
        "If the number of human players is ...",
        {compare, P("count", "Players (1 in single player)", "number", "2", {}, 1, 8)},
        [](const MissionValues& n, const MissionEmit& C) -> Lines {
        return Container(
          "if math.max(1, table.getsize(ScenarioInfo.HumanPlayers or {})) " + n.S("compare") + " " +
            Num(n.N("count"), 2) + " then",
          n,
          C
        );
      },
        true
      );
      add(
        "base_start",
        "action",
        "Start a base (BaseManager)",
        {P("base", "Base", "base")},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        if (!MissionIsName(n.S("base"))) {
          return {"-- (no base chosen)"};
        }
        return {"Base.Start_" + n.S("base") + "()"};
      }
      );
      add(
        "base_active",
        "action",
        "Switch a base on / off",
        {P("base", "Base", "base"), P("on", "Active", "bool", "true")},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        if (!MissionIsName(n.S("base"))) {
          return {"-- (no base chosen)"};
        }
        const std::string b = "Base.Manager_" + n.S("base");
        return {"if " + b + " then " + b + ":BaseActive(" + (n.B("on") ? "true" : "false") + ") end"};
      }
      );
      add(
        "raw",
        "action",
        "Raw Lua",
        {P("code", "Lua", "text")},
        [](const MissionValues& n, const MissionEmit& C) -> Lines {
        const std::string code = n.S("code");
        Lines lines = SplitLines(code);
        // Code that ends its block (a trailing return) is wrapped in do ... end, so more can follow it in the stage.
        if (C.compiles != nullptr && *C.compiles) {
          std::string error;
          if (
            !(*C.compiles)("local function f()\n" + code + "\nlocal _ = 0\nend", error) &&
            (*C.compiles)("local function f()\n" + code + "\nend", error)
          ) {
            lines.insert(lines.begin(), "do");
            lines.push_back("end");
          }
        }
        return lines;
      }
      );
      add(
        "end",
        "flow",
        "End the mission",
        {P("result", "Result", "choice", "win", {"win", "lose"})},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        if (n.S("result") == "lose") {
          return {"ScenarioFramework.EndOperation(false, false, false)"};
        }
        return {"ScenarioFramework.EndOperation(true, true, true)"};
      }
      );
      add("next_stage", "flow", "Start next stage", {}, [](const MissionValues&, const MissionEmit& C) -> Lines {
        return {C.nextCall.empty() ? "-- (no next stage)" : C.nextCall};
      });

      // Triggers: containers whose children run when the event happens.
      add(
        "trg_timer",
        "trigger",
        "When a timer runs out",
        {P("seconds", "Seconds", "number", "30", {}, 1, 7200), StageOnly()},
        [](const MissionValues& n, const MissionEmit& C) -> Lines {
        return Wrap("Timer(function()", CallbackBody(n, C, false), "end, " + Num(n.N("seconds"), 30) + ")");
      },
        true,
        true
      );
      add(
        "trg_group_dead",
        "trigger",
        "When a group is destroyed",
        {var, P("count", "Number of dead units (0 = all)", "number", "0", {}, 0, 500), StageOnly()},
        [](const MissionValues& n, const MissionEmit& C) -> Lines {
        const std::string units = "(" + Var(n.S("var")) + " or {})";
        const double dead = Finite(n.N("count")) ? n.N("count") : 0.0;
        if (dead > 0.0) {
          return Wrap(
            "ScenarioFramework.CreateSubGroupDeathTrigger(function()",
            CallbackBody(n, C, false),
            "end, " + units + ", " + Num(dead) + ")"
          );
        }
        return Wrap(
          "ScenarioFramework.CreateGroupDeathTrigger(function()", CallbackBody(n, C, false), "end, " + units + ")"
        );
      },
        true,
        true
      );
      add(
        "trg_unit_killed",
        "trigger",
        "When a unit is killed",
        {army, P("unit", "Unit", "unit"), StageOnly()},
        [](const MissionValues& n, const MissionEmit& C) -> Lines {
        Lines out{
          "do",
          "    local u = ScenarioInfo.UnitNames[GetArmyBrain(" + Q(n.S("army")) + "):GetArmyIndex()][" +
            Q(n.S("unit")) + "]",
          "    if u then",
          "        ScenarioFramework.CreateUnitDeathTrigger(function()"
        };
        for (const std::string& l : CallbackBody(n, C, true)) {
          out.push_back("            " + l);
        }
        out.push_back("        end, u)");
        out.push_back("    end");
        out.push_back("end");
        return out;
      },
        true,
        true
      );
      add(
        "trg_area",
        "trigger",
        "When units are in an area",
        {area, counted, category, compare, count, P("once", "Only the first time", "bool", "true"), StageOnly()},
        [](const MissionValues& n, const MissionEmit& C) -> Lines {
        const std::string cat = MissionExpr(n.S("category"), kCountCat, C.compiles);
        const std::string test = "CountInArea(" + Q(n.S("area")) + ", " + Q(n.S("army")) + ", " + cat + ") " +
          n.S("compare") + " " + Num(n.N("value"), 1);
        Lines out{
          "WatchArea(" + (n.B("stageOnly") ? std::to_string(C.stage) : std::string("nil")) + ", function() return " +
          test + " end, function()"
        };
        if (C.test) {
          out.push_back("    EdTrace(" + Q(C.Addr() + "!") + ")");
        }
        const Lines body = C.Body(*n.node, "    ", true);
        out.insert(out.end(), body.begin(), body.end());
        if (body.empty()) {
          out.push_back("    -- (nothing to do)");
        }
        out.push_back(std::string("end, ") + (n.B("once") ? "true" : "false") + ")");
        return out;
      },
        true,
        true
      );
      add(
        "trg_objective",
        "trigger",
        "When an objective is decided",
        {[] {
        MissionParam p = P("objective", "Objective", "var");
        p.vtype = "objective";
        return p;
      }(), P("result", "Result", "choice", "complete", {"complete", "failed"}), StageOnly()},
        [](const MissionValues& n, const MissionEmit& C) -> Lines {
        const std::string want = n.S("result") == "failed" ? "false" : "true";
        Lines out{
          "if " + Var(n.S("objective")) + " then",
          "    " + Var(n.S("objective")) + ":AddResultCallback(function(result)",
          "        if result ~= " + want + " then return end"
        };
        for (const std::string& l : CallbackBody(n, C, true)) {
          out.push_back("        " + l);
        }
        out.push_back("    end)");
        out.push_back("end");
        return out;
      },
        true,
        true
      );

      // Flow containers.
      add(
        "if_difficulty",
        "flow",
        "If the difficulty is ...",
        {compare, P("level", "Difficulty (1 easy, 2 normal, 3 hard)", "number", "2", {}, 1, 3)},
        [](const MissionValues& n, const MissionEmit& C) -> Lines {
        return Container("if Difficulty " + n.S("compare") + " " + Num(n.N("level"), 2) + " then", n, C);
      },
        true
      );
      add(
        "cutscene",
        "flow",
        "Cutscene (camera moves, input locked)",
        {},
        [](const MissionValues& n, const MissionEmit& C) -> Lines {
        Lines out{"Cinematics.EnterNISMode()"};
        const Lines body = C.Body(*n.node, "", false);
        out.insert(out.end(), body.begin(), body.end());
        out.push_back("Cinematics.ExitNISMode()");
        return out;
      },
        true
      );
      add(
        "cam_area",
        "action",
        "Cutscene camera: move to an area",
        {area, P("seconds", "Seconds", "number", "4", {}, 0, 120)},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        return {"Cinematics.CameraMoveToArea(" + Q(n.S("area")) + ", " + Num(n.N("seconds"), 4) + ")"};
      }
      );
      add(
        "cam_marker",
        "action",
        "Cutscene camera: move to a camera marker",
        {P("marker", "Camera Info marker", "marker"), P("seconds", "Seconds", "number", "4", {}, 0, 120)},
        [](const MissionValues& n, const MissionEmit&) -> Lines {
        return {
          "Cinematics.CameraMoveToMarker(ScenarioUtils.GetMarker(" + Q(n.S("marker")) + "), " + Num(n.N("seconds"), 4) +
          ")"
        };
      }
      );
      add(
        "cam_reset",
        "action",
        "Cutscene camera: return to player",
        {},
        [](const MissionValues&, const MissionEmit&) -> Lines {
        return {"Cinematics.CameraReset()"};
      }
      );

      // Objectives.
      add(
        "obj_kill",
        "objective",
        "Objective: destroy a group",
        Concat(ObjHead("Destroy the enemy", "Destroy all enemy units."), {var}),
        [](const MissionValues& n, const MissionEmit& C) -> Lines {
        return Objective("Kill", n, ", { Units = " + Var(n.S("var")) + ", MarkUnits = true }", C);
      }
      );
      add(
        "obj_protect",
        "objective",
        "Objective: protect a group",
        Concat(ObjHead("Protect the convoy", "Keep these units alive."), {var}),
        [](const MissionValues& n, const MissionEmit& C) -> Lines {
        return Objective("Protect", n, ", { Units = " + Var(n.S("var")) + ", MarkUnits = true }", C);
      }
      );
      add(
        "obj_timer",
        "objective",
        "Objective: survive a time",
        Concat(
          ObjHead("Hold out", "Survive until the time is up."),
          {P("seconds", "Seconds", "number", "600", {}, 10, 7200),
           P("expire", "When it runs out", "choice", "complete", {"complete", "failed"})}
        ),
        [](const MissionValues& n, const MissionEmit& C) -> Lines {
        return Objective(
          "Timer", n, ", { Timer = " + Num(n.N("seconds"), 600) + ", ExpireResult = " + Q(n.S("expire")) + " }", C
        );
      }
      );
      add(
        "obj_area",
        "objective",
        "Objective: units in an area",
        Concat(
          ObjHead("Reach the area", "Move units into the marked area."),
          {P("icon", "Icon", "choice", "move", kIcons), area, category, compare, count, counted}
        ),
        [](const MissionValues& n, const MissionEmit& C) -> Lines {
        const std::string req = "{ Area = " + Q(n.S("area")) +
          ", Category = " + MissionExpr(n.S("category"), kCountCat, C.compiles) + ", CompareOp = " + Q(n.S("compare")) +
          ", Value = " + Num(n.N("value"), 1) + ", ArmyIndex = GetArmyBrain(" + Q(n.S("army")) + "):GetArmyIndex() }";
        Lines lines{
          std::string(C.inCallback ? "local obj = " : "obj = ") + "Objectives.CategoriesInArea(" + Q(n.S("otype")) +
          ", 'incomplete', " + Q(n.S("title")) + ", " + Q(n.S("description")) + ", " + Q(n.S("icon")) +
          ", { MarkArea = true, ShowProgress = true, Requirements = { " + req + " } })"
        };
        for (const std::string& l : ObjTail(n, C)) {
          lines.push_back(l);
        }
        return lines;
      }
      );
      return c;
    }

    std::string PathText(
      const std::vector<int>& path
    )
    {
      std::string out;
      for (std::size_t i = 0; i < path.size(); ++i) {
        out += (i > 0 ? "." : "") + std::to_string(path[i]);
      }
      return out;
    }

    /** The lines of a list of nodes: an emitter that fails, or (strict / raw) a node whose lines don't compile, is left
     * out with a comment and a WARN; a test run traces each node it reaches. */
    Lines EmitList(
      const std::vector<MissionNode>& list,
      MissionEmit C,
      const std::string& prefix
    )
    {
      Lines out;
      const std::vector<int> base = C.path;
      for (std::size_t i = 0; i < list.size(); ++i) {
        const MissionNode& node = list[i];
        C.path = base;
        C.path.push_back(static_cast<int>(i) + 1);
        const MissionNodeType* t = FindMissionNodeType(node.type);
        if (t == nullptr) {
          const std::string text = "unknown node type " + OneLine(node.type);
          if (C.problems != nullptr) {
            C.problems->push_back({'E', text, C.stage, C.section, C.path});
          }
          out.push_back(prefix + "-- " + text);
          continue;
        }
        const MissionNode clean = CleanMissionNode(node, *t);
        const MissionValues values{&clean, &t->params};
        Lines lines;
        std::string why;
        try {
          lines = t->emit(values, C);
        } catch (const std::exception& error) {
          why = std::string("could not be generated (") + OneLine(error.what()) + ")";
        }
        if (why.empty() && (node.type == "raw" || C.strict) && C.compiles != nullptr && *C.compiles) {
          std::string error;
          if (!(*C.compiles)(Join(lines), error)) {
            why = "does not compile (" + OneLine(error) + ")";
          }
        }
        if (why.empty()) {
          if (C.test) {
            out.push_back(prefix + "EdTrace(" + Q(C.Addr()) + ")");
          }
          for (const std::string& line : lines) {
            out.push_back(prefix + line);
          }
        } else {
          const std::string text = t->title + ": " + why + ": the node is left out of the script";
          if (C.problems != nullptr) {
            C.problems->push_back({'E', text, C.stage, C.section, C.path});
          }
          out.push_back(prefix + "-- " + text);
          out.push_back(
            prefix + "WARN(" +
            Q("EDITOR mission: stage " + std::to_string(C.stage) + ", node " + PathText(C.path) + ": " + text) + ")"
          );
        }
      }
      return out;
    }

    template <typename Pred>
    bool Any(
      const std::vector<MissionNode>& list,
      Pred pred,
      const bool intoCallbacks
    )
    {
      for (const MissionNode& n : list) {
        if (pred(n)) {
          return true;
        }
        const MissionNodeType* t = FindMissionNodeType(n.type);
        if (t != nullptr && t->container && (intoCallbacks || !t->callback) && Any(n.children, pred, intoCallbacks)) {
          return true;
        }
      }
      return false;
    }

    bool HasObjectives(
      const MissionStage& stage
    )
    {
      return Any(stage.ready, [](const MissionNode& n) {
        const MissionNodeType* t = FindMissionNodeType(n.type);
        return t != nullptr && t->family == "objective";
      }, false);
    }

    bool HasNode(
      const MissionStage& stage,
      const std::string& type
    )
    {
      const auto is = [&](const MissionNode& n) {
        return n.type == type;
      };
      return Any(stage.enter, is, true) || Any(stage.ready, is, true);
    }

    bool UsesType(
      const Mission& m,
      const std::string& type
    )
    {
      return std::any_of(m.stages.begin(), m.stages.end(), [&](const MissionStage& s) {
        return HasNode(s, type);
      });
    }

    Lines StageLines(
      const Mission& m,
      const int i,
      const MissionStage& stage,
      const MissionCompileOptions& o,
      const bool strict,
      std::vector<MissionProblem>* problems
    )
    {
      Lines out;
      out.push_back("-- stage " + std::to_string(i) + ": " + OneLine(stage.name));
      out.push_back("Stage[" + std::to_string(i) + "] = function()");
      out.push_back("    if ScenarioInfo.MissionNumber >= " + std::to_string(i) + " then return end");
      out.push_back("    ScenarioInfo.MissionNumber = " + std::to_string(i));
      if (o.test) {
        out.push_back("    EdTrace(" + Q("stage." + std::to_string(i)) + ")");
      }
      const bool objectives = HasObjectives(stage);
      const bool last = i >= static_cast<int>(m.stages.size());
      const std::string nextCall = last ? std::string() : "ForkThread(Stage[" + std::to_string(i + 1) + "])";
      const bool failsafe = Finite(stage.failsafe) && stage.failsafe > 0.0;
      if (objectives) {
        std::string callback;
        if (!nextCall.empty()) {
          // One tick later: the objectives' result callbacks run in the same tick and still find this stage current.
          callback = "function() ForkThread(function() WaitTicks(1) " + nextCall + " end) end";
        } else if (HasNode(stage, "end")) {
          callback = "function() end";
        } else {
          callback = "function() ScenarioFramework.EndOperation(true, true, true) end";
        }
        out.push_back("    local obj");
        out.push_back(
          "    local Group = Objectives.CreateGroup(" + Q("Stage" + std::to_string(i)) + ", " + callback + ")"
        );
      }
      if (failsafe && !nextCall.empty()) {
        out.push_back("    Timer(function() " + nextCall + " end, " + Num(stage.failsafe) + ")");
      }
      for (const char* section : {"enter", "ready"}) {
        MissionEmit C;
        C.stage = i;
        C.nextCall = nextCall;
        C.test = o.test;
        C.strict = strict;
        C.section = section;
        C.problems = problems;
        C.compiles = &o.compiles;
        for (const std::string& line :
             EmitList(std::string(section) == "enter" ? stage.enter : stage.ready, C, "    ")) {
          out.push_back(line);
        }
      }
      if (!objectives && !nextCall.empty() && !HasNode(stage, "end") && !HasNode(stage, "next_stage") && !failsafe) {
        out.push_back("    " + nextCall);
      }
      out.push_back("end");
      return out;
    }

    Lines StageStub(
      const Mission& m,
      const int i,
      const std::string& why
    )
    {
      Lines out{
        "Stage[" + std::to_string(i) + "] = function()",
        "    if ScenarioInfo.MissionNumber >= " + std::to_string(i) + " then return end",
        "    ScenarioInfo.MissionNumber = " + std::to_string(i),
        "    WARN(" + Q("EDITOR mission: stage " + std::to_string(i) + " could not be generated: " + OneLine(why)) + ")"
      };
      if (i < static_cast<int>(m.stages.size())) {
        out.push_back("    ForkThread(Stage[" + std::to_string(i + 1) + "])");
      }
      out.push_back("end");
      return out;
    }

    std::size_t FindAtLineStart(
      const std::string& text,
      const std::string& marker,
      std::size_t from = 0
    )
    {
      while (true) {
        const std::size_t at = text.find(marker, from);
        if (at == std::string::npos) {
          return at;
        }
        if (at == 0 || text[at - 1] == '\n') {
          return at;
        }
        from = at + 1;
      }
    }

    bool IsStub(
      const std::string& text
    )
    {
      std::size_t functions = 0;
      for (std::size_t at = text.find("function"); at != std::string::npos; at = text.find("function", at + 1)) {
        ++functions;
      }
      return functions <= 2 && text.find("function OnPopulate") != std::string::npos &&
        text.find("function OnStart") != std::string::npos && text.find("ForkThread") == std::string::npos &&
        text.size() < 600;
    }

    std::string Region(
      const std::string& body
    )
    {
      return std::string(kBegin) +
        " (generated: edit the mission in the editor, not between these lines) hash=" + MissionHash(body) + "\n" +
        body + kFinish;
    }

    /** CompileMission, but never a script that doesn't load: a last resort stub when the whole text doesn't compile. */
    std::string SafeCompile(
      const Mission& mission,
      const MissionCompileOptions& options
    )
    {
      const std::string body = CompileMission(mission, options);
      std::string error;
      if (!options.compiles || options.compiles(body, error)) {
        return body;
      }
      std::string stub =
        "local ScenarioUtils = import('/lua/sim/ScenarioUtilities.lua')\n\n"
        "local MISSION_ERROR = 'The mission script of this map has errors and was not generated: open the "
        "map in the editor, fix the findings of the Stages panel and save again.'\n";
      stub += options.withEntry ? "function OnPopulate() ScenarioUtils.InitializeScenarioArmies() end\n"
                                  "function OnStart(self) WARN(MISSION_ERROR) end\n"
                                : "function EditorMissionStart() WARN(MISSION_ERROR) end\n";
      return stub;
    }

    // ---- JSON
    void WriteNode(
      std::string& out,
      const MissionNode& node,
      const std::string& indent
    )
    {
      out += indent + "{\"type\": " + JsonQuoted(node.type) + ", \"p\": {";
      bool first = true;
      for (const auto& [key, value] : node.p) {
        out += std::string(first ? "" : ", ") + JsonQuoted(key) + ": " + JsonQuoted(value);
        first = false;
      }
      out += "}";
      if (!node.children.empty()) {
        out += ", \"children\": [\n";
        for (std::size_t i = 0; i < node.children.size(); ++i) {
          WriteNode(out, node.children[i], indent + "  ");
          out += i + 1 < node.children.size() ? ",\n" : "\n";
        }
        out += indent + "]";
      }
      out += "}";
    }

    void WriteList(
      std::string& out,
      const char* key,
      const std::vector<MissionNode>& list,
      const std::string& indent
    )
    {
      out += indent + "\"" + key + "\": [\n";
      for (std::size_t i = 0; i < list.size(); ++i) {
        WriteNode(out, list[i], indent + "  ");
        out += i + 1 < list.size() ? ",\n" : "\n";
      }
      out += indent + "]";
    }

    // String-aware reading of the mission file: text (Raw Lua, dialogue lines) may hold braces and brackets.
    std::size_t SkipString(
      const std::string& t,
      std::size_t at
    )
    {
      for (++at; at < t.size(); ++at) {
        if (t[at] == '\\') {
          ++at;
        } else if (t[at] == '"') {
          return at + 1;
        }
      }
      return t.size();
    }

    /** The balanced {...} or [...] that starts at `at` (strings skipped); empty when it doesn't close. */
    std::string Balanced(
      const std::string& t,
      const std::size_t at
    )
    {
      if (at >= t.size() || (t[at] != '{' && t[at] != '[')) {
        return {};
      }
      int depth = 0;
      for (std::size_t i = at; i < t.size();) {
        const char c = t[i];
        if (c == '"') {
          i = SkipString(t, i);
          continue;
        }
        if (c == '{' || c == '[') {
          ++depth;
        } else if ((c == '}' || c == ']') && --depth == 0) {
          return t.substr(at, i - at + 1);
        }
        ++i;
      }
      return {};
    }

    /** Where `key`'s value starts in an object's own level (not inside a nested value); npos when absent. */
    std::size_t ValueAt(
      const std::string& object,
      const std::string& key
    )
    {
      int depth = 0;
      for (std::size_t i = 0; i < object.size();) {
        const char c = object[i];
        if (c == '"') {
          const std::size_t end = SkipString(object, i);
          if (depth == 1 && object.compare(i + 1, key.size(), key) == 0 && i + 1 + key.size() + 1 == end) {
            std::size_t v = end;
            while (v < object.size() &&
                   (object[v] == ' ' || object[v] == ':' || object[v] == '\n' || object[v] == '\r')) {
              ++v;
            }
            return v;
          }
          i = end;
          continue;
        }
        depth += c == '{' || c == '[' ? 1 : c == '}' || c == ']' ? -1 : 0;
        ++i;
      }
      return std::string::npos;
    }

    bool StringOf(
      const std::string& object,
      const std::string& key,
      std::string& out
    )
    {
      const std::size_t at = ValueAt(object, key);
      if (at == std::string::npos || at >= object.size() || object[at] != '"') {
        return false;
      }
      out.clear();
      for (std::size_t i = at + 1; i < object.size(); ++i) {
        if (object[i] == '\\' && i + 1 < object.size()) {
          out += object[++i];
        } else if (object[i] == '"') {
          return true;
        } else {
          out += object[i];
        }
      }
      return false;
    }

    bool NumberOf(
      const std::string& object,
      const std::string& key,
      double& out
    )
    {
      const std::size_t at = ValueAt(object, key);
      if (at == std::string::npos) {
        return false;
      }
      char* end = nullptr;
      const double v = std::strtod(object.c_str() + at, &end);
      if (end == object.c_str() + at || !Finite(v)) {
        return false;
      }
      out = v;
      return true;
    }

    std::string NestedOf(
      const std::string& object,
      const std::string& key
    )
    {
      const std::size_t at = ValueAt(object, key);
      return at == std::string::npos ? std::string() : Balanced(object, at);
    }

    /** The {...} items of a [...] array. */
    std::vector<std::string> Items(
      const std::string& array
    )
    {
      std::vector<std::string> out;
      for (std::size_t i = 1; i + 1 < array.size();) {
        if (array[i] == '{') {
          std::string item = Balanced(array, i);
          if (item.empty()) {
            break;
          }
          i += item.size();
          out.push_back(std::move(item));
        } else if (array[i] == '"') {
          i = SkipString(array, i);
        } else {
          ++i;
        }
      }
      return out;
    }

    bool ReadNode(
      const std::string& object,
      MissionNode& node,
      const int depth
    )
    {
      if (depth > 8 || !StringOf(object, "type", node.type)) {
        return false;
      }
      const std::string params = NestedOf(object, "p");
      for (std::size_t i = 1; i + 1 < params.size();) {
        if (params[i] != '"') {
          ++i;
          continue;
        }
        // "key": "value" (keys are plain names; values with \" and \\ escaped).
        const std::size_t keyEnd = SkipString(params, i);
        const std::string key = params.substr(i + 1, keyEnd - i - 2);
        std::size_t v = keyEnd;
        while (v < params.size() && params[v] != '"') {
          ++v;
        }
        if (v >= params.size()) {
          break;
        }
        std::string value;
        std::size_t k = v + 1;
        for (; k < params.size() && params[k] != '"'; ++k) {
          if (params[k] == '\\' && k + 1 < params.size()) {
            ++k;
          }
          value += params[k];
        }
        node.p[key] = value;
        i = k + 1;
      }
      for (const std::string& child : Items(NestedOf(object, "children"))) {
        MissionNode c;
        if (ReadNode(child, c, depth + 1)) {
          node.children.push_back(std::move(c));
        }
      }
      return true;
    }
  } // namespace

  // ---- values
  std::string MissionValues::S(
    const std::string& key
  ) const
  {
    if (node != nullptr) {
      if (const auto it = node->p.find(key); it != node->p.end()) {
        return it->second;
      }
    }
    if (params != nullptr) {
      for (const MissionParam& p : *params) {
        if (p.key == key) {
          return p.value;
        }
      }
    }
    return {};
  }

  double MissionValues::N(
    const std::string& key
  ) const
  {
    const std::string text = S(key);
    char* end = nullptr;
    const double v = std::strtod(text.c_str(), &end);
    if (end == text.c_str() || !Finite(v)) {
      return 0.0;
    }
    return v;
  }

  bool MissionValues::B(
    const std::string& key
  ) const
  {
    return S(key) == "true";
  }

  std::string MissionEmit::Addr() const
  {
    return std::to_string(stage) + "." + section + "." + PathText(path);
  }

  std::vector<std::string> MissionEmit::Body(
    const MissionNode& node,
    const std::string& prefix,
    const bool callback
  ) const
  {
    MissionEmit c = *this;
    c.inCallback = inCallback || callback;
    return EmitList(node.children, c, prefix);
  }

  // ---- quoting
  std::string MissionQuote(
    const std::string& s
  )
  {
    std::string out = "'";
    for (const char ch : s) {
      const auto c = static_cast<unsigned char>(ch);
      if (ch == '\\') {
        out += "\\\\";
      } else if (ch == '\'') {
        out += "\\'";
      } else if (c < 32 || c == 127) {
        char buf[8];
        (void)std::snprintf(buf, sizeof(buf), "\\%03d", c);
        out += buf;
      } else {
        out += ch;
      }
    }
    return out + "'";
  }

  std::string MissionNumber(
    double v,
    const double fallback
  )
  {
    if (!Finite(v)) {
      v = Finite(fallback) ? fallback : 0.0;
    }
    char buf[64];
    if (v == std::floor(v) && v > -1000000.0 && v < 1000000.0) {
      (void)std::snprintf(buf, sizeof(buf), "%d", static_cast<int>(v));
    } else {
      (void)std::snprintf(buf, sizeof(buf), "%.3f", v);
    }
    return buf;
  }

  bool MissionIsName(
    const std::string& s
  )
  {
    static const std::set<std::string> kKeywords = {"and", "break",    "do",     "else", "elseif", "end",   "false",
                                                    "for", "function", "if",     "in",   "local",  "nil",   "not",
                                                    "or",  "repeat",   "return", "then", "true",   "until", "while"};
    if (s.empty() || s.size() > 64 || std::isdigit(static_cast<unsigned char>(s[0])) != 0 || kKeywords.count(s) != 0) {
      return false;
    }
    return std::all_of(s.begin(), s.end(), [](const char c) {
      return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
    });
  }

  std::string MissionVar(
    const std::string& name
  )
  {
    return MissionIsName(name) ? "V." + name : "V.UNSET";
  }

  std::string MissionExpr(
    const std::string& text,
    const std::string& fallback,
    const LuaCompiles* compiles
  )
  {
    if (text.empty()) {
      return fallback;
    }
    // The alphabet a category expression needs: nothing that opens a table, a long string, a comment or a statement.
    if (text.size() > 300 || text.find("--") != std::string::npos) {
      return fallback;
    }
    int depth = 0;
    char quote = 0;
    for (const char c : text) {
      const bool allowed = std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_' || c == '.' || c == ' ' ||
        c == '\t' || c == '(' || c == ')' || c == '+' || c == '-' || c == '*' || c == '/' || c == ',' || c == '\'' ||
        c == '"';
      if (!allowed) {
        return fallback;
      }
      if (quote != 0) {
        quote = c == quote ? 0 : quote;
        continue;
      }
      if (c == '\'' || c == '"') {
        quote = c;
      } else if (c == '(') {
        ++depth;
      } else if (c == ')' && --depth < 0) {
        return fallback;
      }
    }
    if (depth != 0 || quote != 0) {
      return fallback;
    }
    if (compiles != nullptr && *compiles) {
      std::string error;
      if (!(*compiles)("return (" + text + ")", error)) {
        return fallback;
      }
    }
    return "(" + text + ")";
  }

  // ---- catalogue
  const std::vector<MissionNodeType>& MissionNodeTypes()
  {
    static const std::vector<MissionNodeType> kTypes = BuildCatalogue();
    return kTypes;
  }

  const MissionNodeType* FindMissionNodeType(
    const std::string& id
  )
  {
    for (const MissionNodeType& t : MissionNodeTypes()) {
      if (t.id == id) {
        return &t;
      }
    }
    return nullptr;
  }

  MissionNode NewMissionNode(
    const std::string& type
  )
  {
    MissionNode node;
    node.type = type;
    if (const MissionNodeType* t = FindMissionNodeType(type)) {
      for (const MissionParam& p : t->params) {
        node.p[p.key] = p.value;
      }
    }
    return node;
  }

  MissionNode CleanMissionNode(
    const MissionNode& node,
    const MissionNodeType& t,
    int* fixed
  )
  {
    MissionNode c = node;
    int n = 0;
    for (const MissionParam& p : t.params) {
      const auto it = c.p.find(p.key);
      if (it == c.p.end()) {
        continue;
      }
      std::string& v = it->second;
      if (p.kind == "choice") {
        if (std::find(p.choices.begin(), p.choices.end(), v) == p.choices.end()) {
          v = p.value;
          ++n;
        }
      } else if (p.kind == "number") {
        char* end = nullptr;
        const double x = std::strtod(v.c_str(), &end);
        if (v.empty() || end == v.c_str() || *end != '\0' || !Finite(x)) {
          v = p.value;
          ++n;
        }
      } else if (p.kind == "bool") {
        if (v != "true" && v != "false") {
          v = p.value;
          ++n;
        }
      }
    }
    if (fixed != nullptr) {
      *fixed = n;
    }
    return c;
  }

  bool ParseMissionTrace(
    const std::string& id,
    MissionTraceId& out
  )
  {
    out = MissionTraceId{};
    std::string text = id;
    while (!text.empty() && (text.back() == ' ' || text.back() == '\r' || text.back() == '\n')) {
      text.pop_back();
    }
    if (!text.empty() && (text.back() == '!' || text.back() == '~')) {
      out.mark = text.back();
      text.pop_back();
    }
    if (text.rfind("stage.", 0) == 0) {
      out.stage = std::atoi(text.c_str() + 6);
      return out.stage > 0;
    }
    const std::size_t a = text.find('.');
    const std::size_t b = a == std::string::npos ? a : text.find('.', a + 1);
    if (b == std::string::npos) {
      return false;
    }
    out.stage = std::atoi(text.substr(0, a).c_str());
    out.section = text.substr(a + 1, b - a - 1);
    for (std::size_t at = b + 1; at < text.size();) {
      const std::size_t dot = text.find('.', at);
      out.path.push_back(std::atoi(text.substr(at, dot == std::string::npos ? std::string::npos : dot - at).c_str()));
      at = dot == std::string::npos ? text.size() : dot + 1;
    }
    return out.stage > 0 && (out.section == "enter" || out.section == "ready") && !out.path.empty() &&
      std::all_of(out.path.begin(), out.path.end(), [](const int i) {
      return i > 0;
    });
  }

  // ---- compile
  std::string MissionHash(
    const std::string& text
  )
  {
    unsigned a = 1;
    unsigned b = 0;
    for (const char c : text) {
      a = (a + static_cast<unsigned char>(c)) % 65521U;
      b = (b + a) % 65521U;
    }
    char buf[16];
    (void)std::snprintf(buf, sizeof(buf), "%05u%05u", a, b);
    return buf;
  }

  std::string CompileMission(
    const Mission& m,
    const MissionCompileOptions& o,
    std::vector<MissionProblem>* problems
  )
  {
    Lines out;
    const auto add = [&](const std::string& line) {
      out.push_back(line);
    };
    add("local ScenarioUtils = import('/lua/sim/ScenarioUtilities.lua')");
    add("local ScenarioFramework = import('/lua/ScenarioFramework.lua')");
    add("local Objectives = ScenarioFramework.Objectives");
    if (UsesType(m, "cutscene")) {
      add("local Cinematics = import('/lua/cinematics.lua')");
    }
    add("");
    add("-- variables the nodes keep (spawned groups, objectives); stage progress");
    add("local V = {}");
    add("local Stage = {}");
    add("local Base = {}");
    add("local AssignedObjectives = {}");
    add("local Difficulty = ScenarioInfo.Options.Difficulty or 2");
    add("local Strings = {");
    for (const MissionDialogue& d : m.dialogues) {
      add("    [" + Q(d.name) + "] = {");
      for (const MissionDialogueLine& l : d.lines) {
        const std::string text = l.speaker.empty() ? l.text : l.speaker + ": " + l.text;
        add("        { text = " + Q(text) + ", delay = " + Num(l.seconds, 5) + " },");
      }
      add("    },");
    }
    add("}");
    add("");
    if (o.test) {
      add("-- test run of the map editor: waits and timers honour the run panel's Skip and speed");
      add("local function Wait(seconds)");
      add("    local skip = ScenarioInfo.EditorSkip or 0");
      add("    local left = seconds * 10");
      add("    while left > 0 do");
      add("        if (ScenarioInfo.EditorSkip or 0) ~= skip then return end");
      add("        WaitTicks(1)");
      add("        left = left - (ScenarioInfo.EditorTimeScale or 1)");
      add("    end");
      add("end");
    } else {
      add("-- waits and timers run in game time");
      add("local function Wait(seconds)");
      add("    WaitSeconds(seconds)");
      add("end");
    }
    add("");
    add("local function Timer(callback, seconds)");
    add("    return ForkThread(function() Wait(seconds) callback() end)");
    add("end");
    add("");
    if (o.test) {
      add("-- what the editor's run panel looks at: the state, and every node the script reaches");
      add(
        "ScenarioInfo.EditorMission = { Stage = Stage, V = V, Objectives = AssignedObjectives, Trace = {}, TraceCount "
        "= 0 }"
      );
      add("local function EdTrace(id)");
      add("    local m = ScenarioInfo.EditorMission");
      add("    m.TraceCount = m.TraceCount + 1");
      add("    m.Trace[m.TraceCount] = id");
      add("    LOG('EDMISSION trace ' .. id)");
      add("end");
      add("");
    }
    add("-- helpers of the wait and trigger nodes");
    add("local function Alive(units)");
    add("    local n = 0");
    add("    for _, u in units or {} do");
    add("        if u and not u.Dead then n = n + 1 end");
    add("    end");
    add("    return n");
    add("end");
    add("");
    add("-- the units of an area, asked from the game once per tick however many nodes look at it");
    add("local areaTick, areaUnits = -1, {}");
    add("local function UnitsInArea(area)");
    add("    local tick = GetGameTick()");
    add("    if tick ~= areaTick then areaTick, areaUnits = tick, {} end");
    add("    local list = areaUnits[area]");
    add("    if not list then");
    add("        list = GetUnitsInRect(ScenarioUtils.AreaToRect(area)) or {}");
    add("        areaUnits[area] = list");
    add("    end");
    add("    return list");
    add("end");
    add("");
    add("local function CountInArea(area, army, category)");
    add("    local index = GetArmyBrain(army):GetArmyIndex()");
    add("    local n = 0");
    add("    for _, u in UnitsInArea(area) do");
    add("        if not u.Dead and u:GetArmy() == index and EntityCategoryContains(category, u) then n = n + 1 end");
    add("    end");
    add("    return n");
    add("end");
    add("");
    if (UsesType(m, "trg_area")) {
      add("-- area triggers: ONE thread polls them all once a second");
      add("local AreaWatchers, AreaPoller = {}, nil");
      add("local function WatchArea(stage, test, body, once)");
      add(
        "    table.insert(AreaWatchers, { stage = stage, test = test, body = body, once = once, live = true, armed = "
        "true, busy = false })"
      );
      add("    if AreaPoller then return end");
      add("    AreaPoller = ForkThread(function()");
      add("        while true do");
      add("            Wait(1)");
      add("            local live = 0");
      add("            for _, w in AreaWatchers do");
      add("                local item = w");
      add("                if item.live then");
      add("                    if item.stage and ScenarioInfo.MissionNumber ~= item.stage then");
      add("                        item.live = false");
      add("                    else");
      add("                        live = live + 1");
      add("                        if item.armed and not item.busy and item.test() then");
      add("                            if item.once then item.live = false else item.armed = false end");
      add("                            item.busy = true");
      add("                            ForkThread(function() item.body() item.busy = false end)");
      add("                        elseif not item.armed and not item.busy and not item.test() then");
      add("                            item.armed = true");
      add("                        end");
      add("                    end");
      add("                end");
      add("            end");
      add("            if live == 0 then AreaPoller = nil AreaWatchers = {} return end");
      add("        end");
      add("    end)");
      add("end");
      add("");
    }
    add("ScenarioInfo.MissionNumber = 0");
    add("");
    if (!m.stages.empty()) {
      add("-- the first stage (a map editor session that opens this map waits for its Play button first)");
      add("function EditorMissionStart()");
      add("    if ScenarioInfo.Options.EditorMode then");
      add("        while not ScenarioInfo.EditorPlaying do WaitSeconds(0.2) end");
      add("    end");
      const int start = std::clamp(o.startStage, 1, static_cast<int>(m.stages.size()));
      add(o.test ? "    Stage[ScenarioInfo.EditorStartStage or " + std::to_string(start) + "]()" : "    Stage[1]()");
      add("end");
      add("");
    }
    for (std::size_t s = 0; s < m.stages.size(); ++s) {
      const int i = static_cast<int>(s) + 1;
      std::vector<MissionProblem> stageProblems;
      Lines lines = StageLines(m, i, m.stages[s], o, false, &stageProblems);
      std::string error;
      if (o.compiles && !o.compiles(Join(lines), error)) {
        // A node doesn't load: each checked on its own, the broken ones left out; as a last resort the whole stage.
        stageProblems.clear();
        lines = StageLines(m, i, m.stages[s], o, true, &stageProblems);
        if (!o.compiles(Join(lines), error)) {
          stageProblems.push_back(
            {'E',
             "stage " + std::to_string(i) + " could not be generated: it starts the next stage and says so in the log",
             i,
             {},
             {}}
          );
          lines = StageStub(m, i, "its code does not compile");
        }
      }
      if (problems != nullptr) {
        problems->insert(problems->end(), stageProblems.begin(), stageProblems.end());
      }
      out.insert(out.end(), lines.begin(), lines.end());
      add("");
    }
    if (o.withEntry) {
      add("function OnPopulate()");
      add("    ScenarioUtils.InitializeScenarioArmies()");
      if (o.hasArea1) {
        add("    ScenarioFramework.SetPlayableArea('AREA_1', false)");
      }
      add("end");
      add("");
      add("function OnStart(self)");
      if (!m.stages.empty()) {
        add("    ForkThread(EditorMissionStart)");
      }
      add("end");
    }
    return Join(out) + "\n";
  }

  std::string PatchMissionScript(
    const std::string& text,
    const Mission& mission,
    const MissionCompileOptions& options,
    MissionPatch& status
  )
  {
    status = MissionPatch::None;
    if (mission.stages.empty()) {
      return text;
    }
    const std::size_t s = FindAtLineStart(text, kBegin);
    const std::size_t f = s == std::string::npos ? std::string::npos : FindAtLineStart(text, kFinish, s);
    if (s != std::string::npos && f != std::string::npos) {
      const std::size_t e = f + std::string(kFinish).size();
      const std::string region = text.substr(s, e - s);
      const std::size_t hashAt = region.find("hash=");
      const std::size_t bodyAt = region.find('\n');
      const std::string body = bodyAt == std::string::npos
        ? std::string()
        : region.substr(bodyAt + 1, region.size() - std::string(kFinish).size() - bodyAt - 1);
      if (hashAt != std::string::npos && hashAt < bodyAt) {
        const std::string stored = region.substr(hashAt + 5, std::min<std::size_t>(10, bodyAt - hashAt - 5));
        if (stored != MissionHash(body)) {
          status = MissionPatch::Detached;
          return text;
        }
      }
      const std::string outside = text.substr(0, s) + text.substr(e);
      MissionCompileOptions o = options;
      o.withEntry = outside.find("function OnPopulate") == std::string::npos &&
        outside.find("function OnStart") == std::string::npos;
      status = MissionPatch::Written;
      return text.substr(0, s) + Region(SafeCompile(mission, o)) + text.substr(e);
    }
    const bool stub = IsStub(text);
    MissionCompileOptions o = options;
    o.withEntry = stub ||
      (text.find("function OnPopulate") == std::string::npos && text.find("function OnStart") == std::string::npos);
    const std::string region = Region(SafeCompile(mission, o)) + "\n";
    status = MissionPatch::Written;
    if (stub) {
      return region;
    }
    return text + (text.empty() || text.back() == '\n' ? "" : "\n") + "\n" + region;
  }

  // ---- checks
  std::vector<MissionProblem> CheckMission(
    const Mission& m,
    const MissionFacts& facts,
    const LuaCompiles* compiles
  )
  {
    std::vector<MissionProblem> out;
    std::set<std::string> defined;
    std::set<std::string> dialogues;
    for (const MissionDialogue& d : m.dialogues) {
      dialogues.insert(d.name);
      if (d.lines.empty()) {
        out.push_back({'W', "dialogue " + d.name + " has no lines", 0, {}, {}});
      }
    }
    const auto has = [](const std::vector<std::string>& list, const std::string& v) {
      return std::find(list.begin(), list.end(), v) != list.end();
    };
    bool ends = false;
    for (std::size_t s = 0; s < m.stages.size(); ++s) {
      const MissionStage& stage = m.stages[s];
      const int i = static_cast<int>(s) + 1;
      const bool last = s + 1 == m.stages.size();
      if (stage.enter.empty() && stage.ready.empty()) {
        out.push_back({'W', "stage " + std::to_string(i) + " has no nodes", i, {}, {}});
      }
      if (stage.failsafe > 0.0 && last) {
        out.push_back({'W', "stage " + std::to_string(i) + " has a failsafe timer but no next stage", i, {}, {}});
      }
      if (HasNode(stage, "end") || (last && HasObjectives(stage))) {
        ends = true;
      }
      std::function<void(const std::vector<MissionNode>&, const std::string&, std::vector<int>)> walk;
      walk = [&](const std::vector<MissionNode>& list, const std::string& section, std::vector<int> path) {
        for (std::size_t k = 0; k < list.size(); ++k) {
          std::vector<int> here = path;
          here.push_back(static_cast<int>(k) + 1);
          const MissionNode& n = list[k];
          const MissionNodeType* t = FindMissionNodeType(n.type);
          const auto problem = [&](const char level, const std::string& text) {
            out.push_back({level, (t != nullptr ? t->title : n.type) + ": " + text, i, section, here});
          };
          if (t == nullptr) {
            problem('E', "unknown node type");
            continue;
          }
          int fixed = 0;
          const MissionNode clean = CleanMissionNode(n, *t, &fixed);
          if (fixed > 0) {
            problem('W', std::to_string(fixed) + " value(s) out of range were replaced by the defaults");
          }
          if (t->family == "coop" && m.mode == "campaign") {
            problem('W', "a coop node in a campaign mission");
          }
          if (n.type == "next_stage" && last) {
            problem('W', "there is no next stage after the last one");
          }
          const MissionValues v{&clean, &t->params};
          for (const MissionParam& p : t->params) {
            const std::string value = v.S(p.key);
            if (value.empty()) {
              if (!p.optional && p.kind != "text" && p.kind != "number" && p.kind != "bool" && p.kind != "choice") {
                problem('E', p.label + " is not set");
              }
              continue;
            }
            if (p.kind == "army" && !facts.armies.empty() && !has(facts.armies, value)) {
              problem('E', "no army " + value);
            } else if (p.kind == "group") {
              const auto armyGroups = facts.groups.find(v.S("army"));
              if (armyGroups != facts.groups.end() && !has(armyGroups->second, value)) {
                problem('E', "army " + v.S("army") + " has no group " + value);
              }
            } else if (p.kind == "chain" && !has(facts.chains, value)) {
              problem('E', "no chain " + value);
            } else if (p.kind == "area" && !has(facts.areas, value)) {
              problem('E', "no area " + value);
            } else if (p.kind == "marker" && !has(facts.markers, value)) {
              problem('E', "no marker " + value);
            } else if (p.kind == "dialogue" && dialogues.count(value) == 0) {
              problem('E', "no dialogue " + value);
            } else if (p.kind == "var") {
              if (!MissionIsName(value)) {
                problem('E', p.label + " is not a name (letters, digits and _)");
              } else if (p.defines) {
                defined.insert(value);
              } else if (defined.count(value) == 0) {
                problem('W', "variable " + value + " is read before any node sets it");
              }
            }
            if ((p.key == "category" || p.key == "categories") && MissionExpr(value, "", compiles).empty()) {
              problem('E', p.label + " is not one category expression");
            }
          }
          if (t->container) {
            walk(n.children, section, here);
          }
        }
      };
      walk(stage.enter, "enter", {});
      walk(stage.ready, "ready", {});
    }
    if (!m.stages.empty() && !ends) {
      out.push_back({'W', "the mission never ends (no End node, and the last stage has no objectives)", 0, {}, {}});
    }
    return out;
  }

  // ---- save and load
  std::string SaveMission(
    const Mission& m
  )
  {
    if (m.stages.empty() && m.dialogues.empty()) {
      return {};
    }
    std::string out = "{\n  \"schema\": 1,\n  \"mode\": " + JsonQuoted(m.mode) + ",\n  \"stages\": [\n";
    for (std::size_t s = 0; s < m.stages.size(); ++s) {
      const MissionStage& st = m.stages[s];
      out += "    {\"name\": " + JsonQuoted(st.name) +
        ", \"failsafe\": " + JsonNumber(static_cast<float>(st.failsafe)) + ",\n";
      WriteList(out, "enter", st.enter, "      ");
      out += ",\n";
      WriteList(out, "ready", st.ready, "      ");
      out += "\n    }" + std::string(s + 1 < m.stages.size() ? ",\n" : "\n");
    }
    out += "  ],\n  \"dialogues\": [\n";
    for (std::size_t d = 0; d < m.dialogues.size(); ++d) {
      const MissionDialogue& dl = m.dialogues[d];
      out += "    {\"name\": " + JsonQuoted(dl.name) + ", \"lines\": [";
      for (std::size_t l = 0; l < dl.lines.size(); ++l) {
        out += std::string(l > 0 ? ", " : "") + "{\"text\": " + JsonQuoted(dl.lines[l].text) +
          ", \"speaker\": " + JsonQuoted(dl.lines[l].speaker) +
          ", \"seconds\": " + JsonNumber(static_cast<float>(dl.lines[l].seconds)) + "}";
      }
      out += "]}" + std::string(d + 1 < m.dialogues.size() ? ",\n" : "\n");
    }
    out += "  ]\n}\n";
    return out;
  }

  bool LoadMission(
    const std::string& text,
    Mission& mission,
    std::string& error
  )
  {
    const std::size_t open = text.find('{');
    const std::string root = open == std::string::npos ? std::string() : Balanced(text, open);
    const std::string stages = NestedOf(root, "stages");
    if (stages.empty()) {
      error = "no stages";
      return false;
    }
    Mission m;
    std::string mode;
    if (StringOf(root, "mode", mode) && (mode == "campaign" || mode == "coop" || mode == "both")) {
      m.mode = mode;
    }
    for (const std::string& stageText : Items(stages)) {
      MissionStage stage;
      (void)StringOf(stageText, "name", stage.name);
      double failsafe = 0.0;
      if (NumberOf(stageText, "failsafe", failsafe) && failsafe > 0.0) {
        stage.failsafe = failsafe;
      }
      for (const std::string& n : Items(NestedOf(stageText, "enter"))) {
        MissionNode node;
        if (ReadNode(n, node, 0)) {
          stage.enter.push_back(std::move(node));
        }
      }
      for (const std::string& n : Items(NestedOf(stageText, "ready"))) {
        MissionNode node;
        if (ReadNode(n, node, 0)) {
          stage.ready.push_back(std::move(node));
        }
      }
      m.stages.push_back(std::move(stage));
    }
    for (const std::string& d : Items(NestedOf(root, "dialogues"))) {
      MissionDialogue dialogue;
      (void)StringOf(d, "name", dialogue.name);
      for (const std::string& l : Items(NestedOf(d, "lines"))) {
        MissionDialogueLine line;
        (void)StringOf(l, "text", line.text);
        (void)StringOf(l, "speaker", line.speaker);
        double seconds = 5.0;
        if (NumberOf(l, "seconds", seconds)) {
          line.seconds = seconds;
        }
        dialogue.lines.push_back(std::move(line));
      }
      m.dialogues.push_back(std::move(dialogue));
    }
    mission = std::move(m);
    return true;
  }
} // namespace faf::editor
