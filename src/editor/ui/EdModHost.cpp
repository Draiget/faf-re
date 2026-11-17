#include "editor/ui/EdModHost.h"

#include "editor/doc/EdDocument.h"
#include "editor/doc/EdSaveFile.h"
#include "editor/tools/EdMarkers.h"
#include "editor/ui/EdCommands.h"
#include "editor/ui/EdControls.h"
#include "editor/ui/EdUiScale.h"
#include "editor/ui/EdWorkspaces.h"
#include "gpg/core/utils/Logging.h"
#include "imgui.h"
#include "lua/LuaObject.h"
#include "lua/LuaPrimitives.h"
#include "lua/luaplus/include/lauxlib.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <ranges>

namespace faf::editor
{
  namespace
  {
    using Mod = EdModHost::Mod;

    EdModHost* gHost = nullptr;

    Mod* ModOf(
      lua_State* L
    )
    {
      return static_cast<Mod*>(lua_touserdata(L, lua_upvalueindex(1)));
    }

    std::string ArgString(
      lua_State* L,
      const int index
    )
    {
      const char* const text = lua_isstring(L, index) != 0 ? lua_tostring(L, index) : nullptr;
      return text != nullptr ? text : std::string();
    }

    /** Editor.Command(id, title, fn [, keys]) */
    int LuaCommand(
      lua_State* L
    )
    {
      Mod* const mod = ModOf(L);
      const std::string id = ArgString(L, 1);
      const std::string title = ArgString(L, 2);
      if (mod == nullptr || gHost == nullptr || id.empty() || lua_type(L, 3) != LUA_TFUNCTION) {
        lua_pushstring(L, "Editor.Command(id, title, fn [, keys]): an id, a title and a function");
        lua_error(L);
        return 0;
      }
      const std::string keys = ArgString(L, 4);
      lua_pushvalue(L, 3);
      const int ref = luaL_ref(L, LUA_REGISTRYINDEX);
      gHost->AddCommand(*mod, id, title.empty() ? id : title, keys, ref);
      return 0;
    }

    /** Editor.Log(text) */
    int LuaLog(
      lua_State* L
    )
    {
      Mod* const mod = ModOf(L);
      gpg::Logf("editor mod %s: %s", mod != nullptr ? mod->info.name.c_str() : "?", ArgString(L, 1).c_str());
      return 0;
    }

    /** Editor.Run(commandId) -> bool */
    int LuaRun(
      lua_State* L
    )
    {
      lua_pushboolean(L, gHost != nullptr && gHost->RunCommand(ArgString(L, 1)) ? 1 : 0);
      return 1;
    }

    void SetString(
      lua_State* L,
      const char* key,
      const std::string& value
    )
    {
      lua_pushstring(L, key);
      lua_pushstring(L, value.c_str());
      lua_settable(L, -3);
    }

    void SetNumber(
      lua_State* L,
      const char* key,
      const double value
    )
    {
      lua_pushstring(L, key);
      lua_pushnumber(L, static_cast<lua_Number>(value));
      lua_settable(L, -3);
    }

    /** The ground's height at a point (the height field, as the layout generator reads it); 0 without one. */
    float GroundHeight(
      const moho::CWldMap& map,
      const float x,
      const float z
    )
    {
      const moho::CHeightField* const field = map.mTerrainRes != nullptr ? map.mTerrainRes->GetHeightField() : nullptr;
      if (field == nullptr || field->width <= 0 || field->height <= 0) {
        return 0.0f;
      }
      const int ix = std::clamp(static_cast<int>(x), 0, field->width - 1);
      const int iz = std::clamp(static_cast<int>(z), 0, field->height - 1);
      return static_cast<float>(field->data[static_cast<std::size_t>(iz) * field->width + ix]) / 128.0f;
    }

    /** Editor.Map() -> { path, name, width, height, water (level, or nil), markers, props } or nil */
    int LuaMap(
      lua_State* L
    )
    {
      if (gHost == nullptr || gHost->Document().Path().empty() || gHost->Document().Map() == nullptr) {
        lua_pushnil(L);
        return 1;
      }
      EdDocument& document = gHost->Document();
      const MapFacts& facts = document.Facts();
      lua_newtable(L);
      SetString(L, "path", document.Path());
      SetString(L, "name", facts.name);
      SetNumber(L, "width", std::max(0, facts.fieldWidth - 1));
      SetNumber(L, "height", std::max(0, facts.fieldHeight - 1));
      if (facts.water) {
        SetNumber(L, "water", facts.waterElevation);
      }
      SetNumber(L, "markers", static_cast<double>(document.SaveData().Markers().size()));
      SetNumber(L, "props", facts.props);
      return 1;
    }

    /** Editor.HeightAt(x, z) -> the ground's height there, or nil without a map */
    int LuaHeightAt(
      lua_State* L
    )
    {
      moho::CWldMap* const map = gHost != nullptr ? gHost->Document().Map() : nullptr;
      if (map == nullptr || map->mTerrainRes == nullptr) {
        lua_pushnil(L);
        return 1;
      }
      const float x = static_cast<float>(lua_tonumber(L, 1));
      const float z = static_cast<float>(lua_tonumber(L, 2));
      lua_pushnumber(L, static_cast<lua_Number>(GroundHeight(*map, x, z)));
      return 1;
    }

    /** Editor.Markers() -> { { name, type, x, y, z }, ... } */
    int LuaMarkers(
      lua_State* L
    )
    {
      lua_newtable(L);
      if (gHost == nullptr || gHost->Document().Map() == nullptr) {
        return 1;
      }
      int n = 0;
      for (const SaveEntry& marker : gHost->Document().SaveData().Markers()) {
        float x = 0.0f, y = 0.0f, z = 0.0f;
        (void)MarkerPosition(marker, x, y, z);
        lua_newtable(L);
        SetString(L, "name", marker.name);
        SetString(L, "type", MarkerTypeOf(marker));
        SetNumber(L, "x", x);
        SetNumber(L, "y", y);
        SetNumber(L, "z", z);
        lua_rawseti(L, -2, ++n);
      }
      return 1;
    }

    /** Editor.AddMarker(type, x, z) -> its name, or nil and why (one undo step) */
    /** Editor.SetMarker(name, key, value) -> true, or nil and why (one undo step). A number is a FLOAT, a boolean a
     * BOOLEAN, a string a STRING, a table of three numbers a VECTOR3 (position, orientation). */
    int LuaSetMarker(
      lua_State* L
    )
    {
      const std::string name = ArgString(L, 1);
      const std::string key = ArgString(L, 2);
      std::string value;
      if (lua_type(L, 3) == LUA_TNUMBER) {
        value = FloatValue(lua_tonumber(L, 3));
      } else if (lua_type(L, 3) == LUA_TBOOLEAN) {
        value = lua_toboolean(L, 3) != 0 ? "BOOLEAN( true )" : "BOOLEAN( false )";
      } else if (lua_type(L, 3) == LUA_TSTRING) {
        value = StringValue(lua_tostring(L, 3));
      } else if (lua_type(L, 3) == LUA_TTABLE) {
        double v[3] = {};
        for (int i = 0; i < 3; ++i) {
          lua_rawgeti(L, 3, i + 1);
          v[i] = lua_tonumber(L, -1);
          lua_pop(L, 1);
        }
        value = Vector3Value(v[0], v[1], v[2]);
      }
      if (gHost == nullptr || gHost->Document().Map() == nullptr || key.empty() || value.empty() || key == "type") {
        lua_pushnil(L);
        lua_pushstring(L, "Editor.SetMarker(name, key, value): a map, a key other than type, and a value");
        return 2;
      }
      EdDocument& document = gHost->Document();
      EdDocument::SaveSnapshot before = document.SaveDataNow();
      for (SaveEntry& marker : document.SaveData().Markers()) {
        if (marker.name == name) {
          marker.Set(key, value);
          document.SaveDataEdited(std::move(before));
          lua_pushboolean(L, 1);
          return 1;
        }
      }
      lua_pushnil(L);
      lua_pushstring(L, ("no marker named " + name).c_str());
      return 2;
    }

    int LuaAddMarker(
      lua_State* L
    )
    {
      moho::CWldMap* const map = gHost != nullptr ? gHost->Document().Map() : nullptr;
      const MarkerType* const type = FindMarkerType(ArgString(L, 1));
      if (map == nullptr || type == nullptr || map->mTerrainRes == nullptr) {
        lua_pushnil(L);
        lua_pushstring(L, map == nullptr ? "no map is open" : "no marker type of that name");
        return 2;
      }
      const float x = static_cast<float>(lua_tonumber(L, 2));
      const float z = static_cast<float>(lua_tonumber(L, 3));
      EdDocument& document = gHost->Document();
      EdDocument::SaveSnapshot before = document.SaveDataNow();
      std::vector<SaveEntry>& markers = document.SaveData().Markers();
      SaveEntry marker = NewMarker(*type, NextMarkerName(markers, *type), x, GroundHeight(*map, x, z), z);
      const std::string name = marker.name;
      markers.push_back(std::move(marker));
      document.SaveDataEdited(std::move(before));
      lua_pushstring(L, name.c_str());
      return 1;
    }

    /** Editor.Panel(id, title, draw) */
    int LuaPanel(
      lua_State* L
    )
    {
      Mod* const mod = ModOf(L);
      const std::string id = ArgString(L, 1);
      if (mod == nullptr || gHost == nullptr || gHost->Loading() != mod) {
        lua_pushstring(L, "Editor.Panel: panels are added while editor/commands.lua loads");
        lua_error(L);
        return 0;
      }
      const bool taken = std::any_of(gHost->Panels().begin(), gHost->Panels().end(), [&](const auto& panel) {
        return panel.mod == mod && panel.id == id;
      });
      if (id.empty() || taken || lua_type(L, 3) != LUA_TFUNCTION) {
        lua_pushstring(L, "Editor.Panel(id, title, draw): a new id, a title and a function draw(ui)");
        lua_error(L);
        return 0;
      }
      const std::string title = ArgString(L, 2);
      lua_pushvalue(L, 3);
      const int ref = luaL_ref(L, LUA_REGISTRYINDEX);
      gHost->AddPanel(*mod, id, title.empty() ? id : title, ref);
      return 0;
    }

    /** Editor.Tool(id, title, click) */
    /**
     * Editor.MissionNode(id, title, params, code): a mission node type (Studio's Mission.Register). `params` a list of
     * { key, label, kind ('text', 'number', 'bool', 'army', 'chain', 'marker' ...), value }, `code(values)` returns the
     * Lua the node compiles to (a string; lines split at line breaks). While editor/commands.lua loads.
     */
    int LuaMissionNode(
      lua_State* L
    )
    {
      Mod* const mod = ModOf(L);
      const std::string id = ArgString(L, 1);
      if (
        mod == nullptr || gHost == nullptr || gHost->Loading() != mod || id.empty() || lua_type(L, 3) != LUA_TTABLE ||
        lua_type(L, 4) != LUA_TFUNCTION
      ) {
        lua_pushstring(
          L,
          "Editor.MissionNode(id, title, params, code): an id, a title, a list of params and a function, while "
          "editor/commands.lua loads"
        );
        lua_error(L);
        return 0;
      }
      MissionNodeType type;
      type.id = id;
      type.title = ArgString(L, 2).empty() ? id : ArgString(L, 2);
      type.family = "mod";
      const auto field = [L](const char* key) {
        lua_pushstring(L, key);
        lua_gettable(L, -2);
        std::string value = lua_isstring(L, -1) != 0 ? lua_tostring(L, -1) : "";
        lua_pop(L, 1);
        return value;
      };
      for (int i = 1;; ++i) {
        lua_rawgeti(L, 3, i);
        if (lua_type(L, -1) != LUA_TTABLE) {
          lua_pop(L, 1);
          break;
        }
        MissionParam p;
        p.key = field("key");
        p.label = field("label");
        p.kind = field("kind");
        p.value = field("value");
        if (p.label.empty()) {
          p.label = p.key;
        }
        if (p.kind.empty()) {
          p.kind = "text";
        }
        lua_pop(L, 1);
        if (!p.key.empty()) {
          type.params.push_back(std::move(p));
        }
      }
      lua_pushvalue(L, 4);
      const int ref = luaL_ref(L, LUA_REGISTRYINDEX);
      auto keys = type.params | std::views::transform([&](const MissionParam& p) {
        return p.key;
      }) |
        std::ranges::to<std::vector<std::string>>();
      const std::string title = type.title;
      Mod* const owner = mod;
      type.emit = [owner, ref, keys, title](const MissionValues& values, const MissionEmit&) {
        std::vector<std::string> lines;
        if (!owner->running || owner->lua == nullptr) {
          lines.push_back("-- " + title + ": its editor mod isn't running");
          return lines;
        }
        lua_State* const S = owner->lua->GetCState();
        lua_rawgeti(S, LUA_REGISTRYINDEX, ref);
        lua_newtable(S);
        for (const std::string& key : keys) {
          lua_pushstring(S, key.c_str());
          const std::string v = values.S(key);
          lua_pushstring(S, v.c_str());
          lua_settable(S, -3);
        }
        if (LuaCallProtected(S, 1, 1) != 0) {
          const std::string message = lua_isstring(S, -1) != 0 ? lua_tostring(S, -1) : "an error";
          lua_settop(S, 0);
          lines.push_back("-- " + title + ": its code failed: " + message);
          return lines;
        }
        const std::string code = lua_isstring(S, -1) != 0 ? lua_tostring(S, -1) : "";
        lua_settop(S, 0);
        std::size_t at = 0;
        while (at <= code.size()) {
          const std::size_t nl = std::min(code.find('\n', at), code.size());
          if (nl > at) {
            lines.push_back(code.substr(at, nl - at));
          }
          at = nl + 1;
        }
        return lines;
      };
      if (const auto registered = RegisterMissionNodeType(std::move(type)); !registered) {
        lua_pushstring(L, ("Editor.MissionNode: " + registered.error()).c_str());
        lua_error(L);
        return 0;
      }
      return 0;
    }

    /** Editor.On(event, fn): `fn(arg)` after `map` (a map opened: its path), `save` (saved) and `edit` (an undo step
     * ended: what it was). The editor's hook points for mods (Studio's mods hook its Lua modules). */
    int LuaOn(
      lua_State* L
    )
    {
      Mod* const mod = ModOf(L);
      const std::string event = ArgString(L, 1);
      if (
        mod == nullptr || gHost == nullptr || gHost->Loading() != mod ||
        (event != "map" && event != "save" && event != "edit") || lua_type(L, 2) != LUA_TFUNCTION
      ) {
        lua_pushstring(
          L, "Editor.On(event, fn): event 'map', 'save' or 'edit' and a function, while editor/commands.lua loads"
        );
        lua_error(L);
        return 0;
      }
      lua_pushvalue(L, 2);
      const int ref = luaL_ref(L, LUA_REGISTRYINDEX);
      gHost->AddListener(*mod, event, ref);
      return 0;
    }

    int LuaTool(
      lua_State* L
    )
    {
      Mod* const mod = ModOf(L);
      const std::string id = ArgString(L, 1);
      if (
        mod == nullptr || gHost == nullptr || gHost->Loading() != mod || id.empty() || lua_type(L, 3) != LUA_TFUNCTION
      ) {
        lua_pushstring(
          L, "Editor.Tool(id, title, click): an id, a title and a function, while editor/commands.lua loads"
        );
        lua_error(L);
        return 0;
      }
      const std::string title = ArgString(L, 2);
      lua_pushvalue(L, 3);
      const int ref = luaL_ref(L, LUA_REGISTRYINDEX);
      gHost->AddTool(*mod, id, title.empty() ? id : title, ref);
      return 0;
    }

    /** Editor.SetHeights(x0, z0, w, h, list) -> true, or nil and why (one undo step) */
    int LuaSetHeights(
      lua_State* L
    )
    {
      if (gHost == nullptr || !gHost->writeHeights || lua_type(L, 5) != LUA_TTABLE) {
        lua_pushnil(L);
        lua_pushstring(L, "Editor.SetHeights(x0, z0, w, h, list): no map, or no list of heights");
        return 2;
      }
      const int x0 = static_cast<int>(lua_tonumber(L, 1));
      const int z0 = static_cast<int>(lua_tonumber(L, 2));
      const int w = static_cast<int>(lua_tonumber(L, 3));
      const int h = static_cast<int>(lua_tonumber(L, 4));
      // At most a 1025 x 1025 block in one call.
      if (w <= 0 || h <= 0 || w > 1025 || h > 1025) {
        lua_pushnil(L);
        lua_pushstring(L, "w and h are 1 to 1025");
        return 2;
      }
      std::vector<float> heights(static_cast<std::size_t>(w) * static_cast<std::size_t>(h), 0.0f);
      for (std::size_t i = 0; i < heights.size(); ++i) {
        lua_rawgeti(L, 5, static_cast<int>(i) + 1);
        heights[i] = static_cast<float>(lua_tonumber(L, -1));
        lua_pop(L, 1);
      }
      if (const auto written = gHost->writeHeights(x0, z0, w, h, heights); !written) {
        lua_pushnil(L);
        lua_pushstring(L, written.error().c_str());
        return 2;
      }
      lua_pushboolean(L, 1);
      return 1;
    }

    /** Editor.LayerAt(layer, x, z) -> 0..1, or nil (no map, no masks, off the map) */
    int LuaLayerAt(
      lua_State* L
    )
    {
      const float weight = gHost != nullptr && gHost->layerAt ? gHost->layerAt(
                                                                  static_cast<int>(lua_tonumber(L, 1)),
                                                                  static_cast<float>(lua_tonumber(L, 2)),
                                                                  static_cast<float>(lua_tonumber(L, 3))
                                                                )
                                                              : -1.0f;
      if (weight < 0.0f) {
        lua_pushnil(L);
      } else {
        lua_pushnumber(L, static_cast<lua_Number>(weight));
      }
      return 1;
    }

    /** Pushes nil and why (a failed change), or true. */
    int Result(
      lua_State* L,
      const std::string& why
    )
    {
      if (why.empty()) {
        lua_pushboolean(L, 1);
        return 1;
      }
      lua_pushnil(L);
      lua_pushstring(L, why.c_str());
      return 2;
    }

    /** Editor.SetLayer(layer, x0, z0, w, h, list) -> true, or nil and why (one undo step): weights 0..1 in paint texels
     */
    int LuaSetLayer(
      lua_State* L
    )
    {
      if (gHost == nullptr || !gHost->writeLayer || lua_type(L, 6) != LUA_TTABLE) {
        return Result(L, "Editor.SetLayer(layer, x0, z0, w, h, list): no map, or no list of weights");
      }
      const int w = static_cast<int>(lua_tonumber(L, 4));
      const int h = static_cast<int>(lua_tonumber(L, 5));
      if (w <= 0 || h <= 0 || w > 4096 || h > 4096) {
        return Result(L, "w and h are 1 to 4096");
      }
      std::vector<float> weights(static_cast<std::size_t>(w) * static_cast<std::size_t>(h), 0.0f);
      for (std::size_t i = 0; i < weights.size(); ++i) {
        lua_rawgeti(L, 6, static_cast<int>(i) + 1);
        weights[i] = static_cast<float>(lua_tonumber(L, -1));
        lua_pop(L, 1);
      }
      if (
        const auto written = gHost->writeLayer(
          static_cast<int>(lua_tonumber(L, 1)),
          static_cast<int>(lua_tonumber(L, 2)),
          static_cast<int>(lua_tonumber(L, 3)),
          w,
          h,
          weights
        );
        !written
      ) {
        return Result(L, written.error().empty() ? std::string("the paint couldn't be written") : written.error());
      }
      return Result(L, {});
    }

    /** Editor.PaintSize() -> width, height in texels, or nil */
    int LuaPaintSize(
      lua_State* L
    )
    {
      int w = 0;
      int h = 0;
      if (gHost == nullptr || !gHost->paintSize || !gHost->paintSize(w, h)) {
        lua_pushnil(L);
        return 1;
      }
      lua_pushnumber(L, w);
      lua_pushnumber(L, h);
      return 2;
    }

    /** Editor.Props() / Decals() / Units() -> a list of tables (the kind is the upvalue's second string) */
    int ListOf(
      lua_State* L,
      const char* kind
    )
    {
      lua_newtable(L);
      if (gHost == nullptr || !gHost->listObjects) {
        return 1;
      }
      int n = 0;
      const std::string k = kind;
      for (const EdModHost::MapObject& o : gHost->listObjects(k)) {
        lua_newtable(L);
        SetString(L, k == "props" ? "blueprint" : k == "decals" ? "texture" : "type", o.what);
        if (k == "units") {
          SetString(L, "name", o.name);
          SetString(L, "army", o.army);
        }
        if (k == "decals") {
          SetNumber(L, "size", o.size);
        }
        SetNumber(L, "x", o.x);
        SetNumber(L, "y", o.y);
        SetNumber(L, "z", o.z);
        lua_rawseti(L, -2, ++n);
      }
      return 1;
    }
    int LuaProps(
      lua_State* L
    )
    {
      return ListOf(L, "props");
    }
    int LuaDecals(
      lua_State* L
    )
    {
      return ListOf(L, "decals");
    }
    int LuaUnits(
      lua_State* L
    )
    {
      return ListOf(L, "units");
    }

    /** Editor.AddProp(blueprint, x, z [, scale]) -> true, or nil and why */
    int LuaAddProp(
      lua_State* L
    )
    {
      if (gHost == nullptr || !gHost->addProp) {
        return Result(L, "no map is open");
      }
      const float scale = lua_type(L, 4) == LUA_TNUMBER ? static_cast<float>(lua_tonumber(L, 4)) : 1.0f;
      return Result(
        L,
        gHost->addProp(
          ArgString(L, 1), static_cast<float>(lua_tonumber(L, 2)), static_cast<float>(lua_tonumber(L, 3)), scale
        )
      );
    }

    /** Editor.RemoveProp(index) -> true, or nil and why (the index Props() gives, from 1) */
    int LuaRemoveProp(
      lua_State* L
    )
    {
      if (gHost == nullptr || !gHost->removeProp) {
        return Result(L, "no map is open");
      }
      return Result(L, gHost->removeProp(static_cast<int>(lua_tonumber(L, 1)) - 1));
    }

    /** Editor.AddDecal(texture, x, z, size [, heading]) -> true, or nil and why */
    int LuaAddDecal(
      lua_State* L
    )
    {
      if (gHost == nullptr || !gHost->addDecal) {
        return Result(L, "no map is open");
      }
      const float heading = lua_type(L, 5) == LUA_TNUMBER ? static_cast<float>(lua_tonumber(L, 5)) : 0.0f;
      return Result(
        L,
        gHost->addDecal(
          ArgString(L, 1),
          static_cast<float>(lua_tonumber(L, 2)),
          static_cast<float>(lua_tonumber(L, 3)),
          static_cast<float>(lua_tonumber(L, 4)),
          heading
        )
      );
    }

    /** Editor.AddUnit(type, army, x, z) -> its name, or nil and why */
    int LuaAddUnit(
      lua_State* L
    )
    {
      if (gHost == nullptr || !gHost->addUnit) {
        return Result(L, "no map is open");
      }
      std::string name;
      const std::string why = gHost->addUnit(
        ArgString(L, 1),
        ArgString(L, 2),
        static_cast<float>(lua_tonumber(L, 3)),
        static_cast<float>(lua_tonumber(L, 4)),
        name
      );
      if (!why.empty()) {
        return Result(L, why);
      }
      lua_pushstring(L, name.c_str());
      return 1;
    }

    /** Editor.MapData(key) -> the mod's value kept with the open map (a string), or nil */
    int LuaMapData(
      lua_State* L
    )
    {
      Mod* const mod = ModOf(L);
      const std::string value =
        mod != nullptr && gHost != nullptr ? gHost->MapData(mod->info.uid, ArgString(L, 1)) : "";
      if (value.empty()) {
        lua_pushnil(L);
      } else {
        lua_pushstring(L, value.c_str());
      }
      return 1;
    }

    /** Editor.SetMapData(key, value) -> true, or nil and why (a string, number or boolean; nil removes the key) */
    int LuaSetMapData(
      lua_State* L
    )
    {
      Mod* const mod = ModOf(L);
      if (mod == nullptr || gHost == nullptr) {
        return Result(L, "no mod");
      }
      std::string value;
      const bool remove = lua_type(L, 2) <= LUA_TNIL; // nil or none
      if (lua_type(L, 2) == LUA_TBOOLEAN) {
        value = lua_toboolean(L, 2) != 0 ? "true" : "false";
      } else if (!remove) {
        value = ArgString(L, 2);
      }
      const auto set = gHost->SetMapData(mod->info.uid, ArgString(L, 1), value, remove);
      return Result(L, set ? std::string() : set.error());
    }

    /** Editor.Menu(commandId [, label]) */
    int LuaMenu(
      lua_State* L
    )
    {
      Mod* const mod = ModOf(L);
      if (mod == nullptr || gHost == nullptr || gHost->Loading() != mod || ArgString(L, 1).empty()) {
        lua_pushstring(L, "Editor.Menu(commandId [, label]): a command id, while editor/commands.lua loads");
        lua_error(L);
        return 0;
      }
      gHost->AddMenu(*mod, ArgString(L, 1), ArgString(L, 2));
      return 0;
    }

    /** What this editor offers mods, and at which version (FAF Studio's Editor.Capabilities). */
    const std::vector<std::pair<const char*, int>>& Capabilities()
    {
      static const std::vector<std::pair<const char*, int>> kPoints = {
        {"commands", 1},
        {"panels", 1},
        {"menus", 1},
        {"tools", 1},
        {"map", 1},
        {"markers", 1},
        {"heights", 1},
        {"layers", 1},
        {"mission_nodes", 1},
        {"events", 1},
        {"sim_hooks", 1},
        // Studio's points as this editor gives them: `hooks` the On events (Studio's mods hook its Lua modules; this
        // editor is C++), `sidecar` the per-map store, `safe` the sandbox and the start-up trial.
        {"hooks", 1},
        {"sidecar", 1},
        {"safe", 1},
        {"paint", 1},
        {"props", 1},
        {"decals", 1},
        {"units", 1}
      };
      return kPoints;
    }

    /** Editor.Has(point [, version]) -> bool */
    int LuaHas(
      lua_State* L
    )
    {
      const std::string point = ArgString(L, 1);
      const int wanted = lua_isnumber(L, 2) != 0 ? static_cast<int>(lua_tonumber(L, 2)) : 1;
      bool has = false;
      for (const auto& [name, version] : Capabilities()) {
        has = has || (point == name && version >= wanted);
      }
      lua_pushboolean(L, has ? 1 : 0);
      return 1;
    }

    // ---- the `ui` table a panel draws with (immediate: each call draws a control now, in the panel's window)
    std::string UiLabel(
      lua_State* L,
      const int index
    )
    {
      std::string label = ArgString(L, index);
      return label.empty() ? std::string("##unnamed") : label;
    }

    int UiText(
      lua_State* L
    )
    {
      ImGui::TextWrapped("%s", ArgString(L, 1).c_str());
      return 0;
    }

    int UiNote(
      lua_State* L
    )
    {
      ImGui::PushTextWrapPos(0.0f);
      ImGui::TextDisabled("%s", ArgString(L, 1).c_str());
      ImGui::PopTextWrapPos();
      return 0;
    }

    int UiButton(
      lua_State* L
    )
    {
      lua_pushboolean(L, ImGui::Button(UiLabel(L, 1).c_str()) ? 1 : 0);
      return 1;
    }

    int UiCheckbox(
      lua_State* L
    )
    {
      bool value = lua_toboolean(L, 2) != 0;
      (void)ImGui::Checkbox(UiLabel(L, 1).c_str(), &value);
      lua_pushboolean(L, value ? 1 : 0);
      return 1;
    }

    int UiSlider(
      lua_State* L
    )
    {
      float value = static_cast<float>(lua_tonumber(L, 2));
      const float low = lua_isnumber(L, 3) != 0 ? static_cast<float>(lua_tonumber(L, 3)) : 0.0f;
      const float high = lua_isnumber(L, 4) != 0 ? static_cast<float>(lua_tonumber(L, 4)) : 1.0f;
      const std::string label = UiLabel(L, 1);
      const std::string format = label.substr(0, label.find("##")) + " %.2f";
      ImGui::SetNextItemWidth(-1.0f);
      (void)FillSliderFloat(("##" + label).c_str(), &value, low, high, format.c_str());
      lua_pushnumber(L, static_cast<lua_Number>(value));
      return 1;
    }

    int UiInput(
      lua_State* L
    )
    {
      char buffer[512];
      (void)std::snprintf(buffer, sizeof(buffer), "%s", ArgString(L, 2).c_str());
      ImGui::SetNextItemWidth(-1.0f);
      const std::string label = UiLabel(L, 1);
      (void)ImGui::InputTextWithHint(
        ("##" + label).c_str(), label.substr(0, label.find("##")).c_str(), buffer, sizeof(buffer)
      );
      lua_pushstring(L, buffer);
      return 1;
    }

    int UiSeparator(
      lua_State*
    )
    {
      ImGui::Separator();
      return 0;
    }

    int UiSameLine(
      lua_State*
    )
    {
      ImGui::SameLine();
      return 0;
    }

    int UiTooltip(
      lua_State* L
    )
    {
      if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayShort)) {
        EdSetTooltip("%s", ArgString(L, 1).c_str());
      }
      return 0;
    }

    void SetFunction(
      lua_State* L,
      const char* name,
      lua_CFunction function,
      Mod* mod
    )
    {
      lua_pushstring(L, name);
      lua_pushlightuserdata(L, mod);
      lua_pushcclosure(L, function, 1);
      lua_settable(L, -3);
    }
  } // namespace

  EdModHost::EdModHost(
    EdDocument& document
  )
    : mDocument(document)
  {
    gHost = this;
  }

  EdModHost::~EdModHost()
  {
    if (gHost == this) {
      gHost = nullptr;
    }
  }

  void EdModHost::SetEnabledFile(
    const std::filesystem::path& file
  )
  {
    mEnabledFile = file;
    std::ifstream in(file, std::ios::binary);
    if (in) {
      std::ostringstream text;
      text << in.rdbuf();
      mEnabled = ParseEnabledMods(text.str());
    }
  }

  void EdModHost::SaveEnabled()
  {
    if (!mEnabledFile.empty()) {
      std::ofstream out(mEnabledFile, std::ios::binary | std::ios::trunc);
      out << SaveEnabledMods(mEnabled);
    }
  }

  void EdModHost::AddListener(
    Mod& mod,
    const std::string& event,
    const int ref
  )
  {
    mListeners.push_back({&mod, event, ref});
  }

  void EdModHost::Notify(
    const std::string& event,
    const std::string& arg
  )
  {
    for (const Listener& l : mListeners) {
      if (l.event != event || l.mod == nullptr || !l.mod->running || l.mod->lua == nullptr) {
        continue;
      }
      lua_State* const L = l.mod->lua->GetCState();
      lua_rawgeti(L, LUA_REGISTRYINDEX, l.ref);
      lua_pushstring(L, arg.c_str());
      if (LuaCallProtected(L, 1, 0) != 0) {
        const std::string message = lua_isstring(L, -1) != 0 ? lua_tostring(L, -1) : "an error";
        lua_settop(L, 0);
        Fail(*l.mod, "its " + event + " listener failed: " + message);
      }
    }
  }

  std::vector<std::string> EdModHost::SimHookMods() const
  {
    std::vector<std::string> out;
    for (const std::unique_ptr<Mod>& mod : mMods) {
      if (mod->info.simHooks && mEnabled.contains(mod->info.uid) && !mod->info.uid.empty()) {
        out.push_back(mod->info.uid);
      }
    }
    return out;
  }

  namespace
  {
    /** The mods' store beside the open map's file (empty: no map on disk). */
    std::filesystem::path MapDataFile(
      const EdDocument& document
    )
    {
      const std::filesystem::path map = document.MapDiskFile();
      return map.empty() ? std::filesystem::path{} : map.parent_path() / (map.stem().string() + "_moddata.editor");
    }

    /** Tabs and line ends kept out of a stored field (they separate the fields and the lines). */
    std::string StoreEscape(
      const std::string& text
    )
    {
      std::string out;
      for (const char c : text) {
        out += c == '\\' ? "\\\\" : c == '\t' ? "\\t" : c == '\n' ? "\\n" : c == '\r' ? "\\r" : std::string(1, c);
      }
      return out;
    }

    std::string StoreUnescape(
      const std::string& text
    )
    {
      std::string out;
      for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\\' && i + 1 < text.size()) {
          const char c = text[++i];
          out += c == 't' ? '\t' : c == 'n' ? '\n' : c == 'r' ? '\r' : c;
        } else {
          out += text[i];
        }
      }
      return out;
    }

    /** The store's lines as (uid, key) -> value. */
    std::map<std::pair<std::string, std::string>, std::string> ReadStore(
      const std::filesystem::path& file
    )
    {
      std::map<std::pair<std::string, std::string>, std::string> out;
      std::ifstream in(file, std::ios::binary);
      std::string line;
      while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') {
          line.pop_back();
        }
        const std::size_t a = line.find('\t');
        const std::size_t b = a == std::string::npos ? std::string::npos : line.find('\t', a + 1);
        if (b == std::string::npos || line[0] == '#') {
          continue;
        }
        out[{StoreUnescape(line.substr(0, a)), StoreUnescape(line.substr(a + 1, b - a - 1))}] =
          StoreUnescape(line.substr(b + 1));
      }
      return out;
    }
  } // namespace

  std::string EdModHost::MapData(
    const std::string& uid,
    const std::string& key
  ) const
  {
    const std::filesystem::path file = MapDataFile(mDocument);
    if (file.empty() || key.empty()) {
      return {};
    }
    const auto store = ReadStore(file);
    const auto it = store.find({uid, key});
    return it != store.end() ? it->second : std::string();
  }

  std::expected<void, std::string> EdModHost::SetMapData(
    const std::string& uid,
    const std::string& key,
    const std::string& value,
    const bool remove
  )
  {
    const std::filesystem::path file = MapDataFile(mDocument);
    if (file.empty()) {
      return std::unexpected("the open map isn't on disk yet (save it first)");
    }
    if (key.empty() || key.size() > 200 || value.size() > 65536) {
      return std::unexpected("a key of 1 to 200 characters and a value up to 64 KB");
    }
    auto store = ReadStore(file);
    if (remove) {
      store.erase({uid, key});
    } else {
      store[{uid, key}] = value;
    }
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    out << "# Editor mods' data for this map (FAF map editor): mod uid, key, value, a tab between\n";
    for (const auto& [where, v] : store) {
      out << StoreEscape(where.first) << '\t' << StoreEscape(where.second) << '\t' << StoreEscape(v) << '\n';
    }
    if (!out) {
      return std::unexpected("couldn't write " + file.filename().string());
    }
    return {};
  }

  void EdModHost::EndTrial()
  {
    if (!mTrialFile.empty() && mTrialOpen) {
      std::error_code ec;
      std::filesystem::remove(mTrialFile, ec);
      mTrialOpen = false;
      gpg::Logf("editor: editor mods: the editor came up with its mods (start-up trial passed)");
    }
  }

  void EdModHost::Scan(
    const std::filesystem::path& mods
  )
  {
    mFolder = mods;
    // The start-up trial (Studio's mods.lua): the mods turned on are written down before they run and the note is taken
    // away once the editor is up (EndTrial). A note still there means the editor didn't come up with them last time:
    // they are turned off now and the panel says so.
    std::error_code ec;
    if (!mEnabledFile.empty()) {
      mTrialFile = mEnabledFile;
      mTrialFile += ".trial";
      std::ifstream trial(mTrialFile, std::ios::binary);
      if (trial) {
        std::string uid;
        while (std::getline(trial, uid)) {
          if (!uid.empty() && uid.back() == '\r') {
            uid.pop_back();
          }
          if (!uid.empty() && mEnabled.erase(uid) != 0) {
            mTrialOff.insert(uid);
          }
        }
        trial.close();
        if (!mTrialOff.empty()) {
          gpg::Warnf(
            "editor: editor mods: the editor didn't come up last time with these turned on: %zu %s off now",
            mTrialOff.size(),
            mTrialOff.size() == 1 ? "mod is" : "mods are"
          );
          SaveEnabled();
        }
      }
      // New mods start turned on (Studio's are always loaded); a mod the user turned off stays off.
      std::filesystem::path knownFile = mEnabledFile;
      knownFile += ".known";
      std::set<std::string> known;
      {
        std::ifstream in(knownFile, std::ios::binary);
        std::string uid;
        while (std::getline(in, uid)) {
          if (!uid.empty() && uid.back() == '\r') {
            uid.pop_back();
          }
          known.insert(uid);
        }
      }
      bool added = false;
      for (const EditorModInfo& info : FindEditorMods(mods)) {
        if (known.insert(info.uid).second) {
          if (mNewModsOn && !mTrialOff.contains(info.uid)) {
            mEnabled.insert(info.uid);
          }
          added = true;
        }
      }
      if (added) {
        std::ofstream out(knownFile, std::ios::binary | std::ios::trunc);
        for (const std::string& uid : known) {
          out << uid << "\n";
        }
        SaveEnabled();
      }
      std::ofstream note(mTrialFile, std::ios::binary | std::ios::trunc);
      for (const std::string& uid : mEnabled) {
        note << uid << "\n";
      }
      mTrialOpen = static_cast<bool>(note);
    }
    for (EditorModInfo& info : FindEditorMods(mods)) {
      const bool known = std::any_of(mMods.begin(), mMods.end(), [&](const std::unique_ptr<Mod>& m) {
        return m->info.uid == info.uid;
      });
      if (known) {
        continue;
      }
      auto mod = std::make_unique<Mod>();
      mod->info = std::move(info);
      Mod& added = *mod;
      mMods.push_back(std::move(mod));
      if (mEnabled.contains(added.info.uid)) {
        Start(added);
      }
    }
    gpg::Logf("editor: %zu editor mods in %s, %zu turned on", mMods.size(), mods.string().c_str(), mEnabled.size());
  }

  bool EdModHost::SetEnabled(
    const std::string& uid,
    const bool on
  )
  {
    for (const std::unique_ptr<Mod>& mod : mMods) {
      if (mod->info.uid != uid) {
        continue;
      }
      if (on) {
        mEnabled.insert(uid);
        Start(*mod);
      } else {
        mEnabled.erase(uid);
        Stop(*mod, "turned off");
        // Turned off on purpose: its panels close (a failed mod's stay, saying why).
        for (ModPanel& panel : mPanels) {
          panel.shown = panel.shown && panel.mod != mod.get();
        }
      }
      SaveEnabled();
      return true;
    }
    return false;
  }

  void EdModHost::Start(
    Mod& mod
  )
  {
    if (mod.running) {
      return;
    }
    mod.commands.clear();
    if (const std::string why = EditorModIncompatibility(mod.info.api); !why.empty()) {
      mod.error = why;
      gpg::Warnf("editor mod %s not started: %s", mod.info.name.c_str(), why.c_str());
      return;
    }
    std::ifstream in(mod.info.folder / "editor" / "commands.lua", std::ios::binary);
    if (!in) {
      mod.error = "it has no editor/commands.lua";
      return;
    }
    std::ostringstream text;
    text << in.rdbuf();
    const std::string script = text.str();
    // Lua's base library without its file loading, and the Editor table.
    mod.lua = std::make_unique<LuaPlus::LuaState>(LuaPlus::LuaState::LIB_BASE);
    lua_State* const L = mod.lua->GetCState();
    for (const char* name : {"dofile", "loadfile", "require", "loadlib"}) {
      lua_pushstring(L, name);
      lua_pushnil(L);
      lua_settable(L, LUA_GLOBALSINDEX);
    }
    lua_pushstring(L, "Editor");
    lua_newtable(L);
    SetFunction(L, "Command", &LuaCommand, &mod);
    SetFunction(L, "Log", &LuaLog, &mod);
    SetFunction(L, "Run", &LuaRun, &mod);
    SetFunction(L, "Map", &LuaMap, &mod);
    SetFunction(L, "HeightAt", &LuaHeightAt, &mod);
    SetFunction(L, "Markers", &LuaMarkers, &mod);
    SetFunction(L, "AddMarker", &LuaAddMarker, &mod);
    SetFunction(L, "SetMarker", &LuaSetMarker, &mod);
    SetFunction(L, "Panel", &LuaPanel, &mod);
    SetFunction(L, "Menu", &LuaMenu, &mod);
    SetFunction(L, "Has", &LuaHas, &mod);
    SetFunction(L, "Tool", &LuaTool, &mod);
    SetFunction(L, "MissionNode", &LuaMissionNode, &mod);
    SetFunction(L, "On", &LuaOn, &mod);
    SetFunction(L, "SetHeights", &LuaSetHeights, &mod);
    SetFunction(L, "LayerAt", &LuaLayerAt, &mod);
    SetFunction(L, "SetLayer", &LuaSetLayer, &mod);
    SetFunction(L, "PaintSize", &LuaPaintSize, &mod);
    SetFunction(L, "Props", &LuaProps, &mod);
    SetFunction(L, "AddProp", &LuaAddProp, &mod);
    SetFunction(L, "RemoveProp", &LuaRemoveProp, &mod);
    SetFunction(L, "Decals", &LuaDecals, &mod);
    SetFunction(L, "AddDecal", &LuaAddDecal, &mod);
    SetFunction(L, "Units", &LuaUnits, &mod);
    SetFunction(L, "AddUnit", &LuaAddUnit, &mod);
    SetFunction(L, "MapData", &LuaMapData, &mod);
    SetFunction(L, "SetMapData", &LuaSetMapData, &mod);
    lua_pushstring(L, "ApiVersion");
    lua_pushnumber(L, kEditorApiVersion);
    lua_settable(L, -3);
    lua_pushstring(L, "Capabilities");
    lua_newtable(L);
    for (const auto& [name, version] : Capabilities()) {
      lua_pushstring(L, name);
      lua_pushnumber(L, version);
      lua_settable(L, -3);
    }
    lua_settable(L, -3);
    lua_settable(L, LUA_GLOBALSINDEX);
    // The `ui` table the mod's panels draw with, kept in its registry.
    lua_newtable(L);
    SetFunction(L, "Text", &UiText, &mod);
    SetFunction(L, "Note", &UiNote, &mod);
    SetFunction(L, "Button", &UiButton, &mod);
    SetFunction(L, "Checkbox", &UiCheckbox, &mod);
    SetFunction(L, "Slider", &UiSlider, &mod);
    SetFunction(L, "Input", &UiInput, &mod);
    SetFunction(L, "Separator", &UiSeparator, &mod);
    SetFunction(L, "SameLine", &UiSameLine, &mod);
    SetFunction(L, "Tooltip", &UiTooltip, &mod);
    mod.uiRef = luaL_ref(L, LUA_REGISTRYINDEX);
    // A restart drops what the mod's last run registered.
    mPanels.erase(
      std::remove_if(
        mPanels.begin(),
        mPanels.end(),
        [&mod](const ModPanel& panel) {
      return panel.mod == &mod;
    }
      ),
      mPanels.end()
    );
    mMenus.erase(
      std::remove_if(
        mMenus.begin(),
        mMenus.end(),
        [&mod](const ModMenu& menu) {
      return menu.mod == &mod;
    }
      ),
      mMenus.end()
    );
    mTools.erase(
      std::remove_if(
        mTools.begin(),
        mTools.end(),
        [&mod](const ModTool& tool) {
      return tool.mod == &mod;
    }
      ),
      mTools.end()
    );
    mListeners.erase(
      std::remove_if(
        mListeners.begin(),
        mListeners.end(),
        [&mod](const Listener& l) {
      return l.mod == &mod;
    }
      ),
      mListeners.end()
    );
    mod.running = true;
    mod.error.clear();
    const std::string chunk = "=" + mod.info.name + "/editor/commands.lua";
    mLoading = &mod;
    const bool loaded =
      luaL_loadbuffer(L, script.data(), script.size(), chunk.c_str()) == 0 && LuaCallProtected(L, 0, 0) == 0;
    mLoading = nullptr;
    if (!loaded) {
      const std::string message = lua_isstring(L, -1) != 0 ? lua_tostring(L, -1) : "an error";
      lua_settop(L, 0);
      Fail(mod, message);
      return;
    }
    gpg::Logf(
      "editor mod %s started: %zu commands, %zu panels",
      mod.info.name.c_str(),
      mod.commands.size(),
      static_cast<std::size_t>(std::count_if(mPanels.begin(), mPanels.end(), [&mod](const ModPanel& panel) {
      return panel.mod == &mod;
    }))
    );
  }

  void EdModHost::Stop(
    Mod& mod,
    const std::string& why
  )
  {
    mod.running = false;
    mod.error = why;
    if (mod.lua) {
      lua_State* const L = mod.lua->GetCState();
      for (const int ref : mod.refs) {
        luaL_unref(L, LUA_REGISTRYINDEX, ref);
      }
    }
    mod.refs.clear();
    mod.uiRef = -1;
    // A mod can fail while its own Lua is still running (a panel or command running one that raises): its state is
    // then kept until the outermost call has returned.
    if (mRunDepth > 0 && mod.lua) {
      mRetired.push_back(std::move(mod.lua));
    }
    mod.lua.reset();
  }

  void EdModHost::DropRetired()
  {
    if (mRunDepth == 0) {
      mRetired.clear();
    }
  }

  void EdModHost::Fail(
    Mod& mod,
    const std::string& what
  )
  {
    gpg::Warnf(
      "editor mod %s failed: %s; its commands are off until the editor starts again",
      mod.info.name.c_str(),
      what.c_str()
    );
    Stop(mod, "failed: " + what);
  }

  void EdModHost::AddCommand(
    Mod& mod,
    const std::string& id,
    const std::string& title,
    const std::string& keys,
    const int ref
  )
  {
    if (mCommands == nullptr) {
      return;
    }
    const std::string full = EditorModCommandId(mod.info.name, id);
    Mod* const owner = &mod;
    const std::size_t index = mod.refs.size();
    mod.refs.push_back(ref);
    mod.commands.push_back(full);
    EdCommand command;
    command.id = full;
    command.title = title;
    command.category = "Mod: " + mod.info.name;
    command.keys = keys;
    command.description = "From the editor mod " + mod.info.name;
    command.run = [this, owner, index, full] {
      if (!owner->running || owner->lua == nullptr || index >= owner->refs.size()) {
        return;
      }
      lua_State* const L = owner->lua->GetCState();
      lua_rawgeti(L, LUA_REGISTRYINDEX, owner->refs[index]);
      ++mRunDepth;
      const int result = LuaCallProtected(L, 0, 0);
      --mRunDepth;
      if (result != 0) {
        const std::string message = lua_isstring(L, -1) != 0 ? lua_tostring(L, -1) : "an error";
        lua_settop(L, 0);
        Fail(*owner, full + ": " + message);
      }
      DropRetired();
    };
    command.why = [owner] {
      return owner->running ? std::string() : "the editor mod " + owner->info.name + " is " + owner->error;
    };
    mCommands->Add(std::move(command));
  }

  void EdModHost::AddPanel(
    Mod& mod,
    const std::string& id,
    const std::string& title,
    const int ref
  )
  {
    mPanels.push_back(ModPanel{&mod, id, title, ref, false, {}});
    if (mCommands == nullptr) {
      return;
    }
    // Its show command (palette, menus): `mod.<mod>.panel.<id>`.
    const std::string full = EditorModCommandId(mod.info.name, "panel." + id);
    Mod* const owner = &mod;
    // The panel found by its mod and id each time (a restart registers the mod's panels again).
    const auto find = [this, owner, id]() -> ModPanel* {
      for (ModPanel& panel : mPanels) {
        if (panel.mod == owner && panel.id == id) {
          return &panel;
        }
      }
      return nullptr;
    };
    EdCommand command;
    command.id = full;
    command.title = title + " (panel)";
    command.category = "Mod: " + mod.info.name;
    command.description = "Shows or hides the panel of the editor mod " + mod.info.name;
    command.run = [find] {
      if (ModPanel* const panel = find()) {
        panel->shown = !panel->shown;
      }
    };
    command.why = [owner] {
      return owner->running ? std::string() : "the editor mod " + owner->info.name + " is " + owner->error;
    };
    command.checked = [find] {
      const ModPanel* const panel = find();
      return panel != nullptr && panel->shown;
    };
    mCommands->Add(std::move(command));
    mMenus.push_back(ModMenu{&mod, full, title});
  }

  void EdModHost::AddMenu(
    Mod& mod,
    const std::string& command,
    const std::string& label
  )
  {
    // A mod names its own commands by their short id; the editor's (view.frame) by theirs.
    const std::string own = EditorModCommandId(mod.info.name, command);
    const bool ownCommand = mCommands != nullptr && mCommands->Find(own) != nullptr;
    mMenus.push_back(ModMenu{&mod, ownCommand ? own : command, label});
  }

  void EdModHost::AddTool(
    Mod& mod,
    const std::string& id,
    const std::string& title,
    const int ref
  )
  {
    mTools.push_back(ModTool{&mod, id, title, ref});
    if (mCommands == nullptr) {
      return;
    }
    // Its command turns it on and off: `mod.<mod>.tool.<id>`.
    const std::string full = EditorModCommandId(mod.info.name, "tool." + id);
    const std::string key = mod.info.uid + "/" + id;
    Mod* const owner = &mod;
    EdCommand command;
    command.id = full;
    command.title = title + " (tool)";
    command.category = "Mod: " + mod.info.name;
    command.description = "Turns on or off the view tool of the editor mod " + mod.info.name +
      ": while it is on, a left click on the map goes to the mod";
    command.run = [this, key] {
      mActiveTool = mActiveTool == key ? std::string() : key;
    };
    command.why = [owner] {
      return owner->running ? std::string() : "the editor mod " + owner->info.name + " is " + owner->error;
    };
    command.checked = [this, key] {
      return mActiveTool == key;
    };
    mCommands->Add(std::move(command));
    mMenus.push_back(ModMenu{&mod, full, title});
  }

  const EdModHost::ModTool* EdModHost::ActiveTool() const
  {
    for (const ModTool& tool : mTools) {
      if (tool.mod != nullptr && tool.mod->running && tool.mod->info.uid + "/" + tool.id == mActiveTool) {
        return &tool;
      }
    }
    return nullptr;
  }

  bool EdModHost::ClickTool(
    const float x,
    const float z,
    const bool shift,
    const bool ctrl
  )
  {
    const ModTool* const tool = ActiveTool();
    if (tool == nullptr) {
      mActiveTool.clear();
      return false;
    }
    Mod* const owner = tool->mod;
    lua_State* const L = owner->lua->GetCState();
    lua_rawgeti(L, LUA_REGISTRYINDEX, tool->ref);
    lua_pushnumber(L, static_cast<lua_Number>(x));
    lua_pushnumber(L, static_cast<lua_Number>(z));
    lua_pushboolean(L, shift ? 1 : 0);
    lua_pushboolean(L, ctrl ? 1 : 0);
    const std::string where = EditorModCommandId(owner->info.name, "tool." + tool->id);
    ++mRunDepth;
    const int result = LuaCallProtected(L, 4, 0);
    --mRunDepth;
    if (result != 0) {
      const std::string message = lua_isstring(L, -1) != 0 ? lua_tostring(L, -1) : "an error";
      lua_settop(L, 0);
      mActiveTool.clear();
      Fail(*owner, where + ": " + message);
    }
    DropRetired();
    return true;
  }

  std::vector<EdModHost::ModMenu> EdModHost::MenuEntries() const
  {
    std::vector<ModMenu> out;
    for (const ModMenu& menu : mMenus) {
      if (menu.mod != nullptr && menu.mod->running) {
        out.push_back(menu);
      }
    }
    return out;
  }

  void EdModHost::DrawPanels()
  {
    for (ModPanel& panel : mPanels) {
      if (!panel.shown || panel.mod == nullptr) {
        continue;
      }
      bool open = true;
      const std::string window = panel.title + "###modpanel." + panel.mod->info.uid + "." + panel.id;
      // First shown: floating over the view, the mods' panels side by side (three to a row).
      const ImGuiViewport* const main = ImGui::GetMainViewport();
      const auto slot = static_cast<float>(&panel - mPanels.data());
      const float column = slot - 3.0f * static_cast<float>(static_cast<int>(slot / 3.0f));
      const float row = static_cast<float>(static_cast<int>(slot / 3.0f));
      ImGui::SetNextWindowPos(
        ImVec2(
          main->WorkPos.x + main->WorkSize.x * 0.3f + column * Em(340.0f),
          main->WorkPos.y + main->WorkSize.y * 0.15f + row * Em(40.0f)
        ),
        ImGuiCond_FirstUseEver
      );
      ImGui::SetNextWindowSize(ImVec2(Em(320.0f), Em(300.0f)), ImGuiCond_FirstUseEver);
      if (ImGui::Begin(Panel(window.c_str()), &open)) {
        if (!panel.mod->running || panel.mod->lua == nullptr) {
          ImGui::TextDisabled("The editor mod %s is %s.", panel.mod->info.name.c_str(), panel.mod->error.c_str());
        } else if (!panel.error.empty()) {
          ImGui::PushTextWrapPos(0.0f);
          ImGui::TextColored(ImVec4(1.0f, 0.75f, 0.35f, 1.0f), "This panel stopped: %s", panel.error.c_str());
          ImGui::PopTextWrapPos();
        } else {
          lua_State* const L = panel.mod->lua->GetCState();
          lua_rawgeti(L, LUA_REGISTRYINDEX, panel.ref);
          lua_rawgeti(L, LUA_REGISTRYINDEX, panel.mod->uiRef);
          ++mRunDepth;
          const int result = LuaCallProtected(L, 1, 0);
          --mRunDepth;
          if (result != 0) {
            panel.error = lua_isstring(L, -1) != 0 ? lua_tostring(L, -1) : "an error";
            lua_settop(L, 0);
            gpg::Warnf(
              "editor mod %s: its panel %s stopped: %s",
              panel.mod->info.name.c_str(),
              panel.id.c_str(),
              panel.error.c_str()
            );
          }
        }
      }
      ImGui::End();
      panel.shown = open;
    }
    DropRetired();
  }

  bool EdModHost::RunCommand(
    const std::string& id
  )
  {
    // A mod's command may run the editor's (and other mods'), a few deep at most.
    if (mCommands == nullptr || mRunDepth > 4) {
      return false;
    }
    return mCommands->Run(id);
  }

  void EdModHost::Draw(
    bool& open
  )
  {
    if (!ImGui::Begin(Panel("Editor mods###EditorMods"), &open)) {
      ImGui::End();
      return;
    }
    ImGui::TextWrapped(
      "Mods that add commands, panels, menu entries, view tools and mission node types to the editor (mod_info.lua: "
      "editor_mod = true; editor/commands.lua). A new mod starts turned on; they run apart from the game (no files, no "
      "engine functions); a mod whose command fails is turned off until the editor starts again, a panel that fails "
      "stops drawing, and a mod the editor didn't come up with last time is turned off."
    );
    if (!mTrialOff.empty()) {
      std::string names;
      for (const std::string& uid : mTrialOff) {
        for (const std::unique_ptr<Mod>& mod : mMods) {
          if (mod->info.uid == uid) {
            names += (names.empty() ? "" : ", ") + mod->info.name;
          }
        }
      }
      ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 190, 90, 255));
      ImGui::TextWrapped(
        "Turned off by the start-up trial (the editor didn't come up with them last time): %s", names.c_str()
      );
      ImGui::PopStyleColor();
    }
    ImGui::TextDisabled("In %s", mFolder.string().c_str());
    if (mMods.empty()) {
      ImGui::TextDisabled("No editor mods there.");
    }
    for (const std::unique_ptr<Mod>& mod : mMods) {
      ImGui::PushID(mod->info.uid.c_str());
      bool on = mEnabled.contains(mod->info.uid);
      if (ImGui::Checkbox(mod->info.name.c_str(), &on)) {
        (void)SetEnabled(mod->info.uid, on);
      }
      ImGui::SameLine();
      if (mod->running) {
        const auto panels = std::count_if(mPanels.begin(), mPanels.end(), [&mod](const ModPanel& panel) {
          return panel.mod == mod.get();
        });
        ImGui::TextDisabled("%zu commands, %d panels", mod->commands.size(), static_cast<int>(panels));
      } else if (!mod->error.empty()) {
        ImGui::TextColored(ImVec4(1.0f, 0.75f, 0.35f, 1.0f), "%s", mod->error.c_str());
      }
      if (!mod->info.description.empty()) {
        ImGui::TextDisabled("  %s", mod->info.description.c_str());
      }
      ImGui::PopID();
    }
    ImGui::End();
  }
} // namespace faf::editor
