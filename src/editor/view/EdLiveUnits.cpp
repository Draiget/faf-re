#include "editor/view/EdLiveUnits.h"

#include <cstdio>
#include <cstdlib>
#include <sstream>

#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/console/CConCommand.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/entity/UserEntity.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/mesh/Mesh.h"
#include "moho/resource/blueprints/RBlueprint.h"
#include "moho/sim/CWldSession.h"

namespace faf::editor
{
  namespace
  {
    bool gHidden = false;
    bool gWasHidden = false;

    /** The units' entities, each with the action. */
    template <class Action>
    void EachUnit(
      Action&& action
    )
    {
      moho::CWldSession* const session = moho::WLD_GetActiveSession();
      if (session == nullptr) {
        return;
      }
      for (const auto& [id, entity] : session->mEntities) {
        if (entity != nullptr && entity->IsUserUnit() != nullptr) {
          action(id, *entity);
        }
      }
    }
  } // namespace

  std::vector<LiveUnit> LiveUnits()
  {
    std::vector<LiveUnit> units;
    EachUnit([&](const std::uint32_t id, moho::UserEntity& entity) {
      LiveUnit unit;
      unit.id = id;
      if (entity.mParams.mBlueprint != nullptr) {
        unit.blueprint = entity.mParams.mBlueprint->mBlueprintId.c_str();
      }
      const Wm3::Vec3f at = entity.GetInterpolatedPosition(1.0f);
      unit.x = at.x;
      unit.y = at.y;
      unit.z = at.z;
      units.push_back(std::move(unit));
    });
    // Hidden: their meshes culled every frame (the game sets them again as it shows them); shown again, the game's
    // own visibility given back once.
    if (gHidden || gWasHidden) {
      EachUnit([](std::uint32_t, moho::UserEntity& entity) {
        if (gHidden) {
          if (moho::MeshInstance* const mesh = entity.GetMeshInstance(); mesh != nullptr) {
            mesh->Cull(true);
          }
        } else {
          entity.UpdateVisibility();
        }
      });
      gWasHidden = gHidden;
    }
    return units;
  }

  void SetLiveUnitsHidden(
    const bool hidden
  )
  {
    gHidden = hidden;
  }

  std::string ToggleName(
    const std::string& cap
  )
  {
    std::string name = cap;
    if (name.rfind("RULEUTC_", 0) == 0) {
      name = name.substr(8);
    }
    if (const std::size_t toggle = name.rfind("Toggle"); toggle != std::string::npos && toggle + 6 == name.size()) {
      name.erase(toggle);
    }
    return name;
  }

  LiveUnitInfo ReadLiveUnit(
    const std::uint32_t id
  )
  {
    LiveUnitInfo info;
    moho::CWldSession* const session = moho::WLD_GetActiveSession();
    if (session == nullptr || session->mState == nullptr) {
      return info;
    }
    // The game's UI Lua reads it as its interface does; the result as lines, read back as one string.
    char script[3000];
    (void)std::snprintf(
      script,
      sizeof(script),
      R"lua(
__EditorLiveUnit = ''
local u = GetUnitById('%u')
if u and not u:IsDead() then
    local bp = u:GetBlueprint()
    local out = {}
    table.insert(out, 'bp=' .. tostring(bp.BlueprintId or ''))
    local name = (bp.General and bp.General.UnitName) or bp.Description or ''
    table.insert(out, 'name=' .. tostring(LOC(name) or name))
    table.insert(out, 'army=' .. tostring(u:GetArmy()))
    table.insert(out, 'health=' .. tostring(u:GetHealth()) .. ',' .. tostring(u:GetMaxHealth()))
    if u.GetVeterancyLevel then table.insert(out, 'vet=' .. tostring(u:GetVeterancyLevel() or 0)) end
    local bits = { RULEUTC_ShieldToggle = 0, RULEUTC_WeaponToggle = 1, RULEUTC_JammingToggle = 2, RULEUTC_IntelToggle = 3,
                   RULEUTC_ProductionToggle = 4, RULEUTC_StealthToggle = 5, RULEUTC_GenericToggle = 6, RULEUTC_SpecialToggle = 7,
                   RULEUTC_CloakToggle = 8 }
    local caps = {}
    if bp.General and type(bp.General.ToggleCaps) == 'table' then caps = bp.General.ToggleCaps end
    for cap, on in pairs(caps) do
        if on and bits[cap] then
            table.insert(out, 'toggle=' .. cap .. ',' .. tostring(u:GetScriptBit(bits[cap])))
        end
    end
    local has = import('/lua/enhancementcommon.lua').GetEnhancements(u:GetEntityId())
    if type(has) ~= 'table' then has = {} end
    local enhancements = {}
    if type(bp.Enhancements) == 'table' then enhancements = bp.Enhancements end
    for name, e in pairs(enhancements) do
        if type(e) == 'table' and name ~= 'Slots' and not string.find(name, 'Remove$') then
            local on = false
            for _, n in pairs(has) do
                if n == name then on = true end
            end
            local removable = enhancements[name .. 'Remove'] ~= nil
            table.insert(out, 'enh=' .. name .. ',' .. tostring(e.Slot or '') .. ',' .. tostring(on) .. ',' .. tostring(e.Prerequisite or '') ..
                              ',' .. tostring(removable))
        end
    end
    __EditorLiveUnit = table.concat(out, '\n')
end
)lua",
      id
    );
    if (!moho::SCR_LuaDoString(script, session->mState)) {
      return info;
    }
    const char* const text = session->mState->GetGlobal("__EditorLiveUnit").ToString();
    if (text == nullptr || *text == '\0') {
      return info;
    }
    info.found = true;
    std::istringstream lines(text);
    std::string line;
    const auto split = [](const std::string& value) {
      std::vector<std::string> parts;
      std::size_t at = 0;
      while (at <= value.size()) {
        const std::size_t comma = value.find(',', at);
        parts.push_back(value.substr(at, comma == std::string::npos ? std::string::npos : comma - at));
        at = comma == std::string::npos ? value.size() + 1 : comma + 1;
      }
      return parts;
    };
    while (std::getline(lines, line)) {
      const std::size_t eq = line.find('=');
      if (eq == std::string::npos) {
        continue;
      }
      const std::string key = line.substr(0, eq);
      const std::string value = line.substr(eq + 1);
      if (key == "bp") {
        info.blueprint = value;
      } else if (key == "name") {
        info.name = value;
      } else if (key == "army") {
        info.army = std::atoi(value.c_str());
      } else if (key == "health") {
        const std::vector<std::string> parts = split(value);
        info.health = static_cast<float>(std::atof(parts[0].c_str()));
        info.maxHealth = parts.size() > 1 ? static_cast<float>(std::atof(parts[1].c_str())) : 0.0f;
      } else if (key == "vet") {
        info.veteran = std::atoi(value.c_str());
      } else if (key == "toggle") {
        const std::vector<std::string> parts = split(value);
        info.toggles.push_back({parts[0], parts.size() > 1 && parts[1] == "true"});
      } else if (key == "enh") {
        const std::vector<std::string> parts = split(value);
        LiveUnitInfo::Enhancement enhancement;
        enhancement.name = parts[0];
        enhancement.slot = parts.size() > 1 ? parts[1] : std::string();
        enhancement.has = parts.size() > 2 && parts[2] == "true";
        enhancement.prerequisite = parts.size() > 3 ? parts[3] : std::string();
        enhancement.removable = parts.size() > 4 && parts[4] == "true";
        info.enhancements.push_back(std::move(enhancement));
      }
    }
    return info;
  }

  void LiveUnitDo(
    const std::uint32_t id,
    const std::string& lua
  )
  {
    // SimLua (a sim console command, the play's cheats on): one line, the unit found by its id.
    std::string command =
      "SimLua local u = GetEntityById(" + std::to_string(id) + ") if u and not u:IsDead() then " + lua + " end";
    for (char& c : command) {
      if (c == '\n' || c == '\r') {
        c = ' ';
      }
    }
    moho::CON_Execute(command.c_str());
    gpg::Logf("editor: live unit %u: %s", id, lua.c_str());
  }

  void LiveUnitWarp(
    const std::uint32_t id,
    const float x,
    const float z
  )
  {
    char lua[200];
    (void)std::snprintf(
      lua,
      sizeof(lua),
      "Warp(u, {%g, GetSurfaceHeight(%g, %g), %g})",
      static_cast<double>(x),
      static_cast<double>(x),
      static_cast<double>(z),
      static_cast<double>(z)
    );
    LiveUnitDo(id, lua);
  }
} // namespace faf::editor
