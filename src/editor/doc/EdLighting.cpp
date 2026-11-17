#include "editor/doc/EdLighting.h"
#include "editor/doc/EdLooks.h"

#include "editor/doc/EdJson.h"

#include <cstdint>
#include <cstring>

namespace faf::editor
{
  std::string LightingToScmlighting(
    const LightingState& lighting
  )
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

  std::expected<void, std::string> LightingFromScmlighting(
    const std::string& text,
    LightingState& lighting
  )
  {
    std::string probe;
    if (!JsonValue(text, "LightingMultiplier", probe) || !JsonValue(text, "SunDirection", probe)) {
      return std::unexpected("not a lighting settings file (no LightingMultiplier or SunDirection)");
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
    return {};
  }
  std::expected<LightingState, std::string> LightingFromScmap(
    const std::string& bytes
  )
  {
    // One reader of a map's environment (EdLooks' walk of the .scmap); the lighting is its first part.
    const std::expected<Look, std::string> look = LookFromScmap(bytes);
    if (!look) {
      return std::unexpected(look.error());
    }
    return look->lighting;
  }
} // namespace faf::editor
