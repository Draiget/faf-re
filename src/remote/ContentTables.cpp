#include "remote/ContentTables.h"

#include <string>
#include <vector>

#include "moho/sim/RRuleGameRules.h"

// Engine addition, server mode: see ContentTables.h. Reads the rules' blueprint maps only.

namespace faf::remote
{
  namespace
  {
    void AppendKeys(const moho::RRuleGameRulesBlueprintMap& map, std::vector<std::string>& names)
    {
      for (const auto& [id, blueprint] : map) {
        if (blueprint != nullptr) {
          names.emplace_back(id.c_str());
        }
      }
    }
  } // namespace

  wire::SContentTables BuildContentTables(moho::RRuleGameRules& rules)
  {
    std::vector<std::string> blueprints;
    AppendKeys(rules.GetUnitBlueprints(), blueprints);
    AppendKeys(rules.GetPropBlueprints(), blueprints);
    AppendKeys(rules.GetProjectileBlueprints(), blueprints);

    std::vector<std::string> meshes;
    AppendKeys(rules.GetMeshBlueprints(), meshes);

    wire::SContentTables tables;
    tables.blueprints = wire::COrdinalTable::Build(blueprints);
    tables.meshes = wire::COrdinalTable::Build(meshes);
    tables.sounds = wire::COrdinalTable::Build({});
    return tables;
  }
} // namespace faf::remote
