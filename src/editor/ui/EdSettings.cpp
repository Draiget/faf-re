#include "editor/ui/EdSettings.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>

namespace faf::editor
{
  namespace
  {
    struct Definition
    {
      const char* key;
      const char* initial;
      std::vector<std::string> allowed; // empty: "0" or "1"
    };

    const std::vector<Definition>& Definitions()
    {
      static const std::vector<Definition> kDefinitions = {
        {EdSettings::kTitleBar, "own", {"own", "windows"}},
        {EdSettings::kRenderer, "auto", {"auto", "d3d12", "vulkan"}},
        {EdSettings::kBackgroundFps, "30", {"0", "10", "30", "60"}},
        {EdSettings::kFullHelp, "0", {}},
        {EdSettings::kPanelsWhilePlaying, "1", {}},
        {EdSettings::kStartScreen, "1", {}},
        {EdSettings::kVaultItems, "1", {}},
        {EdSettings::kAutosave, "1", {}},
        {EdSettings::kAutosaveMinutes, "1", {"1", "2", "5", "10"}},
        {EdSettings::kBackups, "10", {"0", "3", "10", "30"}},
        {EdSettings::kPopouts, "1", {}},
        {EdSettings::kIdleFps, "30", {"0", "10", "30", "60"}},
        {EdSettings::kGfxShadows, "auto", {"auto", "on", "off"}},
        {EdSettings::kGfxShadowSize, "auto", {"auto", "512", "1024", "1536", "2048", "4096"}},
        {EdSettings::kGfxBloom, "auto", {"auto", "on", "off"}},
        {EdSettings::kGfxFxaa, "auto", {"auto", "on", "off"}},
        {EdSettings::kGfxAo, "auto", {"auto", "on", "off"}},
        {EdSettings::kGfxTextureDetail, "auto", {"auto", "high", "medium", "low"}},
        {EdSettings::kGfxAnisotropy, "auto", {"auto", "0", "4", "8", "16"}},
        {EdSettings::kGfxFidelity, "auto", {"auto", "low", "medium", "high"}},
        {EdSettings::kGfxShadowDistance, "auto", {"auto", "short", "normal", "long", "longest"}},
        {EdSettings::kGfxModelDetail, "auto", {"auto", "low", "medium", "high"}},
        {EdSettings::kGfxVsync, "auto", {"auto", "on", "off"}},
        {EdSettings::kGfxShadowQuality, "auto", {"auto", "off", "low", "medium", "high"}},
        {EdSettings::kGpuCompute, "1", {}},
        {EdSettings::kGpuMinCells, "65536", {"16384", "65536", "262144", "1048576"}},
      };
      return kDefinitions;
    }

    const Definition* Find(
      std::string_view key
    )
    {
      for (const Definition& d : Definitions()) {
        if (key == d.key) {
          return &d;
        }
      }
      return nullptr;
    }

    [[nodiscard]] std::string_view Trim(
      std::string_view text
    )
    {
      while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front())) != 0) {
        text.remove_prefix(1);
      }
      while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())) != 0) {
        text.remove_suffix(1);
      }
      return text;
    }
  } // namespace

  std::vector<std::string> EdSettings::Allowed(
    std::string_view key
  )
  {
    const Definition* const d = Find(key);
    return d != nullptr ? d->allowed : std::vector<std::string>{};
  }

  bool EdSettings::Known(
    std::string_view key
  )
  {
    return Find(key) != nullptr;
  }

  std::vector<std::string> EdSettings::Read(
    std::string_view text
  )
  {
    std::vector<std::string> problems;
    int number = 0;
    while (!text.empty()) {
      const std::size_t end = text.find('\n');
      const std::string_view line = Trim(text.substr(0, end));
      text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);
      ++number;
      if (line.empty() || line.front() == ';' || line.front() == '#' || line.front() == '[') {
        continue;
      }
      const std::size_t equals = line.find('=');
      const std::string_view key = Trim(line.substr(0, equals));
      const std::string_view value =
        equals == std::string_view::npos ? std::string_view{} : Trim(line.substr(equals + 1));
      if (equals != std::string_view::npos && key == kFormat) {
        mFileFormat = std::atoi(std::string(value).c_str());
        continue;
      }
      if (equals == std::string_view::npos || !Known(key)) {
        problems.push_back("line " + std::to_string(number) + ": no setting \"" + std::string(key) + "\"");
      } else if (!Set(key, value)) {
        problems.push_back(
          "line " + std::to_string(number) + ": " + std::string(key) + " can't be \"" + std::string(value) + "\""
        );
      }
    }
    return problems;
  }

  std::string EdSettings::Write() const
  {
    std::string out = "; The map editor's settings (Settings in the editor). <key>=<value>.\n[Settings]\n";
    out += std::string(kFormat) + "=" + std::to_string(kFormatNow) + "\n";
    for (const Definition& d : Definitions()) {
      out += std::string(d.key) + "=" + Get(d.key) + "\n";
    }
    return out;
  }

  std::string EdSettings::Get(
    std::string_view key
  ) const
  {
    if (const auto found = mValues.find(key); found != mValues.end()) {
      return found->second;
    }
    const Definition* const d = Find(key);
    return d != nullptr ? d->initial : std::string();
  }

  bool EdSettings::GetBool(
    std::string_view key
  ) const
  {
    return Get(key) == "1";
  }

  int EdSettings::GetInt(
    std::string_view key
  ) const
  {
    return std::atoi(Get(key).c_str());
  }

  bool EdSettings::Set(
    std::string_view key,
    std::string_view value
  )
  {
    const Definition* const d = Find(key);
    if (d == nullptr) {
      return false;
    }
    const std::string v(value);
    const bool ok = d->allowed.empty() ? (v == "0" || v == "1")
                                       : std::find(d->allowed.begin(), d->allowed.end(), v) != d->allowed.end();
    if (!ok) {
      return false;
    }
    mValues[std::string(key)] = v;
    return true;
  }

  bool EdSettings::SetBool(
    std::string_view key,
    const bool value
  )
  {
    return Set(key, value ? "1" : "0");
  }

  bool EdSettings::SetInt(
    std::string_view key,
    const int value
  )
  {
    return Set(key, std::to_string(value));
  }
  std::vector<std::string> EdSettings::GraphicsCommands() const
  {
    std::vector<std::string> out;
    const auto onOff = [&](const char* key, const char* var, const char* on, const char* off) {
      const std::string value = Get(key);
      if (value == "on" || value == "off") {
        out.push_back(std::string(var) + " " + (value == "on" ? on : off));
      }
    };
    onOff(kGfxShadows, "ren_Shadows", "true", "false");
    if (const std::string size = Get(kGfxShadowSize); size != "auto" && !size.empty()) {
      out.push_back("ren_ShadowSize " + size);
    }
    onOff(kGfxBloom, "ren_Bloom", "true", "false");
    onOff(kGfxFxaa, "ren_Fxaa", "1", "0");
    onOff(kGfxAo, "ren_Ao", "1", "0");
    if (const std::string detail = Get(kGfxTextureDetail); detail == "high" || detail == "medium" || detail == "low") {
      out.push_back(std::string("ren_MipSkipLevels ") + (detail == "high" ? "0" : detail == "medium" ? "1" : "2"));
    }
    if (const std::string aniso = Get(kGfxAnisotropy); aniso != "auto" && !aniso.empty()) {
      out.push_back("ren_TextureAnisotropy " + aniso);
    }
    // Studio's (graphics.lua): the game's fidelity, the shadow distance in units, the cameras' model detail, vsync.
    const auto level = [](const std::string& v) {
      return v == "low" ? "0" : v == "medium" ? "1" : v == "high" ? "2" : "";
    };
    if (const char* f = level(Get(kGfxFidelity)); *f != '\0') {
      out.push_back(std::string("graphics_Fidelity ") + f);
    }
    if (const std::string d = Get(kGfxShadowDistance); d != "auto" && !d.empty()) {
      out.push_back(
        std::string("ren_ShadowLOD ") +
        (d == "short"      ? "200"
           : d == "normal" ? "260"
           : d == "long"   ? "340"
                           : "440")
      );
    }
    if (const char* m = level(Get(kGfxModelDetail)); *m != '\0') {
      out.push_back(std::string("SC_CameraScaleLOD ") + m);
    }
    onOff(kGfxVsync, "SC_VerticalSync", "1", "0");
    if (const std::string q = Get(kGfxShadowQuality); q == "off" || q == "low" || q == "medium" || q == "high") {
      out.push_back(
        std::string("shadow_Fidelity ") +
        (q == "off"        ? "0"
           : q == "low"    ? "1"
           : q == "medium" ? "2"
                           : "3")
      );
    }
    return out;
  }

  namespace
  {
    // Studio's presets (graphics.lua Presets), in this editor's settings: fidelity, shadows and their size and
    // distance, texture detail, model detail.
    struct GraphicsPresetRow
    {
      const char* name;
      const char* fidelity;
      const char* shadows;
      const char* shadowQuality;
      const char* shadowSize;
      const char* shadowDistance;
      const char* texture;
      const char* model;
      const char* bloom; // Studio's presets turn bloom off
    };
    constexpr GraphicsPresetRow kGraphicsPresets[] = {
      // Studio's numbers: shadow quality 0..3 and the shadow map 512, 1024, 1536, 2048.
      {"low", "low", "off", "off", "512", "short", "low", "low", "off"},
      {"medium", "medium", "on", "low", "1024", "normal", "medium", "medium", "off"},
      {"high", "high", "on", "medium", "1536", "long", "high", "high", "off"},
      {"ultra", "high", "on", "high", "2048", "longest", "high", "high", "off"},
    };
  } // namespace

  bool EdSettings::ApplyGraphicsPreset(
    const std::string& preset
  )
  {
    for (const GraphicsPresetRow& p : kGraphicsPresets) {
      if (preset == p.name) {
        (void)Set(kGfxFidelity, p.fidelity);
        (void)Set(kGfxShadows, p.shadows);
        (void)Set(kGfxShadowQuality, p.shadowQuality);
        (void)Set(kGfxShadowSize, p.shadowSize);
        (void)Set(kGfxShadowDistance, p.shadowDistance);
        (void)Set(kGfxTextureDetail, p.texture);
        (void)Set(kGfxModelDetail, p.model);
        (void)Set(kGfxBloom, p.bloom);
        return true;
      }
    }
    return false;
  }

  std::string EdSettings::GraphicsPreset() const
  {
    for (const GraphicsPresetRow& p : kGraphicsPresets) {
      if (
        Get(kGfxFidelity) == p.fidelity && Get(kGfxShadows) == p.shadows && Get(kGfxShadowQuality) == p.shadowQuality &&
        Get(kGfxShadowSize) == p.shadowSize && Get(kGfxShadowDistance) == p.shadowDistance &&
        Get(kGfxTextureDetail) == p.texture && Get(kGfxModelDetail) == p.model && Get(kGfxBloom) == p.bloom
      ) {
        return p.name;
      }
    }
    return "custom";
  }

} // namespace faf::editor
