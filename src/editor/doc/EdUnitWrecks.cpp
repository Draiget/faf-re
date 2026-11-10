#include "editor/doc/EdUnitWrecks.h"

#include <map>
#include <utility>
#include <vector>

#include "editor/doc/EdDocument.h"
#include "editor/doc/EdMapFile.h"
#include "editor/doc/EdUnits.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/RRuleGameRules.h"

namespace faf::editor
{
  namespace
  {
    struct BlueprintFacts
    {
      bool found = false;
      double mass = 0.0;
      double energy = 0.0;
      std::string text;
    };

    /** A blueprint's costs and `.bp` text, read once per id (not cached until the rules are built). */
    const BlueprintFacts* FactsOf(const std::string& id)
    {
      static std::map<std::string, BlueprintFacts> cache;
      if (const auto found = cache.find(id); found != cache.end()) {
        return &found->second;
      }
      moho::RRuleGameRules* const rules = moho::RULE_PeekKept();
      if (rules == nullptr) {
        return nullptr;
      }
      BlueprintFacts facts;
      moho::RResId resId{};
      resId.name.assign(id.c_str());
      if (const moho::RUnitBlueprint* const blueprint = rules->GetUnitBlueprint(resId); blueprint != nullptr) {
        facts.mass = blueprint->Economy.BuildCostMass;
        facts.energy = blueprint->Economy.BuildCostEnergy;
        facts.found = ReadGameFile(blueprint->mSource.c_str(), facts.text);
      }
      return &cache.emplace(id, std::move(facts)).first->second;
    }

    /** Each unit of a group tree with the groups from the root down to it. */
    void Walk(const UnitGroup& group, std::vector<std::string>& path,
              std::vector<std::pair<const SaveUnit*, std::vector<std::string>>>& out)
    {
      for (const SaveUnit& unit : group.units) {
        out.emplace_back(&unit, path);
      }
      for (const UnitGroup& child : group.groups) {
        path.push_back(child.name);
        Walk(child, path, out);
        path.pop_back();
      }
    }
  } // namespace

  BlueprintWreck UnitBlueprintWreck(const std::string& id, const bool underwater)
  {
    BlueprintWreck result;
    const BlueprintFacts* const facts = FactsOf(id);
    if (facts == nullptr || !facts->found) {
      return result;
    }
    result.known = true;
    result.buildMass = facts->mass;
    result.buildEnergy = facts->energy;
    result.wreck = WreckOfUnit(facts->text, facts->mass, facts->energy, underwater);
    return result;
  }

  bool UnderWater(const EdDocument& document, const float x, const float z)
  {
    const moho::CWldMap* const map = document.Map();
    if (map == nullptr || map->mTerrainRes == nullptr || !document.Facts().water) {
      return false;
    }
    return map->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(x), static_cast<std::int32_t>(z)) < document.Facts().waterElevation;
  }

  UnitWreckTotals MapUnitWrecks(const EdDocument& document)
  {
    UnitWreckTotals totals;
    for (const SaveEntry& army : document.SaveData().Armies()) {
      UnitGroup root;
      std::string error;
      if (!ParseUnitGroup(army.Get("Units"), root, error)) {
        continue;
      }
      std::vector<std::pair<const SaveUnit*, std::vector<std::string>>> units;
      std::vector<std::string> path;
      Walk(root, path, units);
      for (const auto& [unit, groups] : units) {
        const UnitFate fate = FateOfUnit(groups, true, document.Script());
        // A group the lobby may make wrecks or units counts with the script's wreck groups (all options on).
        if (fate.kind != UnitFate::Kind::Wreck && fate.kind != UnitFate::Kind::ScriptWreck && fate.kind != UnitFate::Kind::ScriptEither) {
          continue;
        }
        const BlueprintWreck value = UnitBlueprintWreck(unit->type, UnderWater(document, unit->position[0], unit->position[2]));
        if (!value.known) {
          ++totals.unknown;
          continue;
        }
        if (!value.wreck.exists) {
          continue;
        }
        if (fate.kind == UnitFate::Kind::Wreck) {
          ++totals.startCount;
          totals.startMass += value.wreck.mass;
          totals.startEnergy += value.wreck.energy;
        } else {
          ++totals.scriptCount;
          totals.scriptMass += value.wreck.mass;
          totals.scriptEnergy += value.wreck.energy;
        }
      }
    }
    return totals;
  }
} // namespace faf::editor
