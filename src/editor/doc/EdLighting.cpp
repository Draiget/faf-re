#include "editor/doc/EdLighting.h"

#include "editor/doc/EdJson.h"

#include <cstdint>
#include <cstring>

namespace faf::editor
{
  std::string LightingToScmlighting(const LightingState& lighting)
  {
    // LightingData's fields in its order (FAForeverMapEditor, UI/Tools/Lighting/LightingInfo.cs).
    std::string out = "{\n";
    out += "    \"LightingMultiplier\": " + JsonNumber(lighting.multiplier) + ",\n";
    out += "    \"SunDirection\": " + JsonVectorText(lighting.sunDirection, 3, "    ") + ",\n";
    out += "    \"SunAmbience\": " + JsonVectorText(lighting.sunAmbience, 3, "    ") + ",\n";
    out += "    \"SunColor\": " + JsonVectorText(lighting.sunColor, 3, "    ") + ",\n";
    out += "    \"ShadowFillColor\": " + JsonVectorText(lighting.shadowFill, 3, "    ") + ",\n";
    out += "    \"SpecularColor\": " + JsonVectorText(lighting.specular, 4, "    ") + ",\n";
    out += "    \"Bloom\": " + JsonNumber(lighting.bloom) + ",\n";
    out += "    \"FogColor\": " + JsonVectorText(lighting.fogColor, 3, "    ") + ",\n";
    out += "    \"FogStart\": " + JsonNumber(lighting.fogStart) + ",\n";
    out += "    \"FogEnd\": " + JsonNumber(lighting.fogEnd) + "\n";
    return out + "}";
  }

  bool LightingFromScmlighting(const std::string& text, LightingState& lighting, std::string& error)
  {
    std::string probe;
    if (!JsonValue(text, "LightingMultiplier", probe) || !JsonValue(text, "SunDirection", probe)) {
      error = "not a lighting settings file (no LightingMultiplier or SunDirection)";
      return false;
    }
    (void)JsonFloat(text, "LightingMultiplier", lighting.multiplier);
    JsonVector(text, "SunDirection", lighting.sunDirection, 3);
    JsonVector(text, "SunAmbience", lighting.sunAmbience, 3);
    JsonVector(text, "SunColor", lighting.sunColor, 3);
    JsonVector(text, "ShadowFillColor", lighting.shadowFill, 3);
    JsonVector(text, "SpecularColor", lighting.specular, 4);
    (void)JsonFloat(text, "Bloom", lighting.bloom);
    JsonVector(text, "FogColor", lighting.fogColor, 3);
    (void)JsonFloat(text, "FogStart", lighting.fogStart);
    (void)JsonFloat(text, "FogEnd", lighting.fogEnd);
    return true;
  }
  bool LightingFromScmap(const std::string& bytes, LightingState& lighting, std::string& error)
  {
    std::size_t at = 0;
    const auto take = [&](void* const out, const std::size_t size) {
      if (at + size > bytes.size()) {
        return false;
      }
      std::memcpy(out, bytes.data() + at, size);
      at += size;
      return true;
    };
    const auto skipString = [&]() {
      const std::size_t end = bytes.find('\0', at);
      if (end == std::string::npos) {
        return false;
      }
      at = end + 1;
      return true;
    };
    if (bytes.compare(0, 4, "Map\x1a") != 0) {
      error = "not a .scmap (no Map header)";
      return false;
    }
    // Magic, major version, two words, width and height as floats, a float, a short; then the preview.
    at = 4 + 4 + 4 + 4 + 4 + 4 + 4 + 2;
    std::int32_t previewBytes = 0;
    std::int32_t version = 0;
    std::int32_t width = 0;
    std::int32_t height = 0;
    float heightScale = 0.0f;
    if (!take(&previewBytes, 4) || previewBytes < 0 || (at += static_cast<std::size_t>(previewBytes)) > bytes.size() || !take(&version, 4) ||
        !take(&width, 4) || !take(&height, 4) || !take(&heightScale, 4) || width <= 0 || height <= 0) {
      error = "the .scmap ends early";
      return false;
    }
    if (version <= 0) {
      version = 56;
    }
    at += static_cast<std::size_t>(width + 1) * static_cast<std::size_t>(height + 1) * 2;
    if (version >= 56) {
      ++at;
    }
    // The terrain shader, the background, the sky cubemap.
    if (at > bytes.size() || !skipString() || !skipString() || !skipString()) {
      error = "the .scmap ends early";
      return false;
    }
    if (version < 0x37) {
      if (!skipString()) {
        error = "the .scmap ends early";
        return false;
      }
    } else {
      std::int32_t count = 0;
      if (!take(&count, 4) || count < 0 || count > 1024) {
        error = "the .scmap's environment cubemaps can't be read";
        return false;
      }
      for (std::int32_t i = 0; i < count; ++i) {
        if (!skipString() || !skipString()) {
          error = "the .scmap ends early";
          return false;
        }
      }
    }
    float values[23];
    if (!take(values, sizeof(values))) {
      error = "the .scmap ends early";
      return false;
    }
    LightingState read;
    read.multiplier = values[0];
    std::memcpy(read.sunDirection, values + 1, sizeof(read.sunDirection));
    std::memcpy(read.sunAmbience, values + 4, sizeof(read.sunAmbience));
    std::memcpy(read.sunColor, values + 7, sizeof(read.sunColor));
    std::memcpy(read.shadowFill, values + 10, sizeof(read.shadowFill));
    std::memcpy(read.specular, values + 13, sizeof(read.specular));
    read.bloom = values[17];
    std::memcpy(read.fogColor, values + 18, sizeof(read.fogColor));
    read.fogStart = values[21];
    read.fogEnd = values[22];
    lighting = read;
    return true;
  }
} // namespace faf::editor
