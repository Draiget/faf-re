#include "moho/render/RenderFeatures.h"

#include <algorithm>
#include <cstring>
#include <string>

#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/misc/StartupHelpers.h"

namespace moho::render
{
  namespace
  {
    std::vector<Feature>& Registry()
    {
      static std::vector<Feature> registry;
      return registry;
    }

    Api gActive = Api::D3D11;
    bool gActiveKnown = false;

    int LimitLevel(
      const Feature& feature,
      const Api api,
      int level
    )
    {
      const int top = static_cast<int>(feature.states.size()) - 1;
      const int apiTop = feature.apis[static_cast<int>(api)].maxLevel;
      const int maxLevel = (apiTop >= 0) ? std::min(top, apiTop) : top;
      return std::clamp(level, 0, std::max(0, maxLevel));
    }

    int DefaultLevel(
      const Feature& feature,
      const Api api
    )
    {
      const int apiDefault = feature.apis[static_cast<int>(api)].defaultLevel;
      return LimitLevel(feature, api, apiDefault >= 0 ? apiDefault : feature.defaultLevel);
    }

  } // namespace
  namespace detail
  {
    [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
    {
      if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("User"); set != nullptr) {
        return *set;
      }
      static moho::CScrLuaInitFormSet fallbackSet("User");
      return fallbackSet;
    }

    // GetRenderFeatures() -> { api = "d3d12", features = { { key, title, tip, console, default, restart, states = { {
    // text, key }, ... } }, ... } } Only the features the active API supports, each with the states and the default of
    // that API; the unsupported ones are listed in `unsupported` with the reason, so that the Options screen can say
    // why a setting is missing.
    int cfunc_GetRenderFeaturesL(
      LuaPlus::LuaState* const state
    )
    {
      const Api api = ActiveApi();
      LuaPlus::LuaObject result;
      result.AssignNewTable(state, 0, 0);
      // Before the device exists the API is not known: an empty name and no features, so that the caller asks again
      // later.
      result.SetString("api", ActiveApiKnown() ? ApiName(api) : "");
      LuaPlus::LuaObject list;
      list.AssignNewTable(state, 0, 0);
      LuaPlus::LuaObject missing;
      missing.AssignNewTable(state, 0, 0);
      int listIndex = 1;
      int missingIndex = 1;
      for (const Feature& feature : Features()) {
        if (!ActiveApiKnown()) {
          break;
        }
        const ApiSupport& support = feature.apis[static_cast<int>(api)];
        if (!support.supported) {
          LuaPlus::LuaObject entry;
          entry.AssignNewTable(state, 0, 0);
          entry.SetString("key", feature.key.c_str());
          entry.SetString("title", feature.title.c_str());
          entry.SetString("reason", support.reason.c_str());
          missing.SetObject(missingIndex++, entry);
          continue;
        }
        LuaPlus::LuaObject entry;
        entry.AssignNewTable(state, 0, 0);
        entry.SetString("key", feature.key.c_str());
        entry.SetString("title", feature.title.c_str());
        std::string tip = feature.tip;
        if (!support.reason.empty()) {
          tip += " (" + support.reason + ")";
        }
        entry.SetString("tip", tip.c_str());
        entry.SetString("console", feature.console.c_str());
        entry.SetBoolean("restart", feature.needsRestart);
        const int top = LimitLevel(feature, api, static_cast<int>(feature.states.size()) - 1);
        const int defaultLevel = DefaultLevel(feature, api);
        entry.SetString("default", feature.states[static_cast<std::size_t>(defaultLevel)].key.c_str());
        LuaPlus::LuaObject states;
        states.AssignNewTable(state, 0, 0);
        for (int level = 0; level <= top; ++level) {
          LuaPlus::LuaObject stateEntry;
          stateEntry.AssignNewTable(state, 0, 0);
          stateEntry.SetString("text", feature.states[static_cast<std::size_t>(level)].text.c_str());
          stateEntry.SetString("key", feature.states[static_cast<std::size_t>(level)].key.c_str());
          stateEntry.SetNumber("level", static_cast<float>(level));
          states.SetObject(level + 1, stateEntry);
        }
        entry.SetObject("states", states);
        list.SetObject(listIndex++, entry);
      }
      result.SetObject("features", list);
      result.SetObject("unsupported", missing);
      result.PushStack(state);
      return 1;
    }

    int cfunc_GetRenderFeatures(
      lua_State* const luaContext
    )
    {
      return cfunc_GetRenderFeaturesL(moho::SCR_ResolveBindingState(luaContext));
    }
  } // namespace detail

  Api ApiFromDevice(
    const gpg::gal::DeviceApi api
  ) noexcept
  {
    switch (api) {
    case gpg::gal::DeviceApi::Direct3D9:
      return Api::D3D9;
    case gpg::gal::DeviceApi::Direct3D10:
      return Api::D3D10;
    case gpg::gal::DeviceApi::Direct3D11:
      return Api::D3D11;
    case gpg::gal::DeviceApi::Direct3D12:
      return Api::D3D12;
    case gpg::gal::DeviceApi::Vulkan:
      return Api::Vulkan;
    default:
      return Api::D3D11;
    }
  }

  const char* ApiName(
    const Api api
  ) noexcept
  {
    switch (api) {
    case Api::D3D9:
      return "d3d9";
    case Api::D3D10:
      return "d3d10";
    case Api::D3D11:
      return "d3d11";
    case Api::D3D12:
      return "d3d12";
    case Api::Vulkan:
      return "vulkan";
    default:
      return "unknown";
    }
  }

  void RegisterFeature(
    const Feature& feature
  )
  {
    if (feature.key.empty() || feature.states.size() < 2U) {
      return;
    }
    std::vector<Feature>& registry = Registry();
    for (Feature& existing : registry) {
      if (existing.key == feature.key) {
        existing = feature;
        return;
      }
    }
    registry.push_back(feature);
  }

  const std::vector<Feature>& Features()
  {
    return Registry();
  }

  const Feature* FindFeature(
    const std::string& key
  )
  {
    for (const Feature& feature : Registry()) {
      if (feature.key == key) {
        return &feature;
      }
    }
    return nullptr;
  }

  void SetActiveApi(
    const gpg::gal::DeviceApi api
  ) noexcept
  {
    gActive = ApiFromDevice(api);
    gActiveKnown = true;
  }

  Api ActiveApi() noexcept
  {
    return gActive;
  }

  bool ActiveApiKnown() noexcept
  {
    return gActiveKnown;
  }

  bool Supported(
    const Feature& feature,
    const Api api
  ) noexcept
  {
    return feature.apis[static_cast<int>(api)].supported;
  }

  int FeatureLevel(
    const std::string& key,
    const Api api,
    const bool fromOption
  )
  {
    const Feature* const feature = FindFeature(key);
    if (feature == nullptr || !Supported(*feature, api)) {
      return -1;
    }
    int level = DefaultLevel(*feature, api);
    if (fromOption) {
      const fa::string chosen = moho::OPTIONS_GetString(feature->key.c_str());
      if (!chosen.empty()) {
        for (std::size_t i = 0; i < feature->states.size(); ++i) {
          if (feature->states[i].key == chosen.c_str()) {
            level = LimitLevel(*feature, api, static_cast<int>(i));
            break;
          }
        }
      }
    }
    return level;
  }

  void ApplyStartupSettings()
  {
    const Api api = ActiveApi();
    for (const Feature& feature : Registry()) {
      if (!Supported(feature, api)) {
        gpg::Logf(
          "render feature %s: not supported on %s (%s)",
          feature.key.c_str(),
          ApiName(api),
          feature.apis[static_cast<int>(api)].reason.c_str()
        );
        continue;
      }
      const int level = FeatureLevel(feature.key, api);
      gpg::Logf(
        "render feature %s on %s: level %d (%s)",
        feature.key.c_str(),
        ApiName(api),
        level,
        feature.states[static_cast<std::size_t>(level)].key.c_str()
      );
      if (feature.apply != nullptr) {
        feature.apply(level);
      }
    }
  }
} // namespace moho::render

namespace
{
  // As the camera's definitions: a binder is built (and joins the User Lua init-form set) when something names it; this
  // object does, before main, so that GetRenderFeatures exists in the user interface's Lua state.
  struct RenderFeaturesLuaBootstrap
  {
    RenderFeaturesLuaBootstrap()
    {
      static moho::CScrLuaBinder binder(
        moho::render::detail::UserLuaInitSet(),
        "GetRenderFeatures",
        &moho::render::detail::cfunc_GetRenderFeatures,
        nullptr,
        "<global>",
        "GetRenderFeatures() - the renderer features of the active graphics API, for the Options screen"
      );
      (void)binder;
    }
  } gRenderFeaturesLuaBootstrap;
} // namespace
