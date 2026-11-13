#pragma once

#include <string>
#include <vector>

#include "gpg/gal/DeviceContext.hpp"

// FAF addition: the registry of renderer features (docs/RENDERER_BACKENDS.md, "Render features").
//
// Every visual feature the engine adds on top of the shipped renderer (dynamic lights, post-process anti-aliasing,
// ambient occlusion, large-particle quality, ...) is registered here once, with what each render API can do with it.
// The registry does three things:
//   - the Options > Video entry of the feature is built from it (data/fafengine/lua/options/options.lua asks the engine
//   for the features of
//     the active API through the Lua function GetRenderFeatures), so a feature appears only on the APIs that support
//     it, with the levels and the default that API supports;
//   - the engine asks it for the level the player chose (FeatureLevel) instead of reading a command-line switch and a
//   console variable of its own;
//   - the support table is the one place that says why an API does not get a feature (shown as the tip's last line and
//   in the docs).
//
// The level of a feature is the index of the chosen state (0 = off). It is stored in the profile as the *key string* of
// the state, like the Graphics API option, so a profile survives a reordered list.
namespace moho::render
{
  enum class Api : int
  {
    D3D9 = 0,
    D3D10,
    D3D11,
    D3D12,
    Vulkan,
    Count
  };

  [[nodiscard]] Api ApiFromDevice(gpg::gal::DeviceApi api) noexcept;
  [[nodiscard]] const char* ApiName(Api api) noexcept; // "d3d11", "d3d12", ... (the values of the graphics_api option)

  struct FeatureState
  {
    std::string text;    // what the Options screen shows
    std::string key;     // stored in the profile
    std::string value{}; // what is sent to the console variable when the state is chosen; empty = the level index
  };

  struct ApiSupport
  {
    bool supported = false;
    std::string reason;    // why not (or a remark when supported but limited), shown in the tip
    int maxLevel = -1;     // highest state index this API offers; -1 = all
    int defaultLevel = -1; // the default on this API; -1 = the feature's default
  };

  struct Feature
  {
    std::string key; // the Options entry key and profile option, e.g. "dynlights_quality"
    std::string title;
    std::string tip;
    std::string console;              // console variable that takes the level live ("ren_DynLights"); empty = none
    std::string after;                // key of the entry this one is listed after; empty or absent = after Graphics API
    bool numericKeys = false;         // the state keys are numbers in the profile (0, 1, 2), not strings
    std::vector<FeatureState> states; // index = level
    int defaultLevel = 0;
    bool needsRestart = false;
    // The feature does something only on a device that traces rays (inline ray queries): the others do not list it
    // (it shows in `unsupported` with that reason), whatever the API.
    bool needsRayTracing = false;
    ApiSupport apis[static_cast<int>(Api::Count)];
    // Called once after the device exists, with the level the player chose, when the feature is supported on the active
    // API.
    void (*apply)(int level) = nullptr;
  };

  void RegisterFeature(const Feature& feature);
  [[nodiscard]] const std::vector<Feature>& Features();
  [[nodiscard]] const Feature* FindFeature(const std::string& key);

  // The API the running device uses; set by the application when it creates the device.
  void SetActiveApi(gpg::gal::DeviceApi api) noexcept;
  [[nodiscard]] Api ActiveApi() noexcept;
  [[nodiscard]] bool
  ActiveApiKnown() noexcept; // false until the device exists (the options module may load before that)

  [[nodiscard]] bool Supported(const Feature& feature, Api api) noexcept;

  // The level the player chose for the feature (profile option, else the API's default), limited to what the API
  // offers; -1 when the feature does not exist or the API does not support it. `fromOption` reads the profile; without
  // it only the default is returned (the profile is not available that early).
  [[nodiscard]] int FeatureLevel(const std::string& key, Api api, bool fromOption = true);

  // Calls every supported feature's `apply` with its level. Called once after the device has been created.
  void ApplyStartupSettings();
} // namespace moho::render
