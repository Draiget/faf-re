#include "editor/doc/EdWaterPreset.h"

#include "editor/doc/EdJson.h"

namespace faf::editor
{
  std::string WaterToScmwtr(const WaterState& water)
  {
    const WaterNumbers& s = water.shader;
    std::string out = "{\n";
    const auto line = [&out](const std::string& key, const std::string& value, const bool last = false) {
      out += "    \"" + key + "\": " + value + (last ? "\n" : ",\n");
    };
    line("HasWater", water.enabled ? "true" : "false");
    line("Elevation", JsonNumber(water.elevation));
    line("ElevationDeep", JsonNumber(water.deep));
    line("ElevationAbyss", JsonNumber(water.abyss));
    line("SurfaceColor", JsonVectorText(s.mWaterColor, 3, "    "));
    line("ColorLerp", JsonVectorText(s.mWaterLerp, 2, "    "));
    line("RefractionScale", JsonNumber(s.mRefractionScale));
    line("FresnelBias", JsonNumber(s.mFresnelBias));
    line("FresnelPower", JsonNumber(s.mFresnelPower));
    line("UnitReflection", JsonNumber(s.mUnitReflectionAmount));
    line("SkyReflection", JsonNumber(s.mSkyReflectionAmount));
    line("SunShininess", JsonNumber(s.mSunShininess));
    line("SunStrength", JsonNumber(s.mSunStrength));
    line("SunDirection", JsonVectorText(s.mSunDirection, 3, "    "));
    line("SunColor", JsonVectorText(s.mSunColor, 3, "    "));
    line("SunReflection", JsonNumber(s.mSunReflectionAmount));
    line("SunGlow", JsonNumber(s.mSunGlow));
    line("TexPathCubemap", JsonQuoted(water.textures[0]));
    line("TexPathWaterRamp", JsonQuoted(water.textures[1]));
    const float* const movements[4] = {s.mNormal1Movement, s.mNormal2Movement, s.mNormal3Movement, s.mNormal4Movement};
    std::string waves = "[\n";
    for (int i = 0; i < 4; ++i) {
      waves += "        {\n";
      waves += "            \"TexPath\": " + JsonQuoted(water.textures[2 + i]) + ",\n";
      waves += "            \"NormalMovement\": " + JsonVectorText(movements[i], 2, "            ") + ",\n";
      waves += "            \"NormalRepeat\": " + JsonNumber(s.mNormalRepeatRate[i]) + "\n";
      waves += std::string("        }") + (i < 3 ? ",\n" : "\n");
    }
    waves += "    ]";
    line("WaveTextures", waves, true);
    return out + "}";
  }

  bool WaterFromScmwtr(const std::string& text, WaterState& water, std::string& error)
  {
    std::string probe;
    if (!JsonValue(text, "SurfaceColor", probe) || !JsonValue(text, "WaveTextures", probe)) {
      error = "not a water settings file (no SurfaceColor or WaveTextures)";
      return false;
    }
    WaterNumbers& s = water.shader;
    std::string has;
    if (JsonValue(text, "HasWater", has)) {
      water.enabled = has == "true";
    }
    (void)JsonFloat(text, "Elevation", water.elevation);
    (void)JsonFloat(text, "ElevationDeep", water.deep);
    (void)JsonFloat(text, "ElevationAbyss", water.abyss);
    JsonVector(text, "SurfaceColor", s.mWaterColor, 3);
    JsonVector(text, "ColorLerp", s.mWaterLerp, 2);
    (void)JsonFloat(text, "RefractionScale", s.mRefractionScale);
    (void)JsonFloat(text, "FresnelBias", s.mFresnelBias);
    (void)JsonFloat(text, "FresnelPower", s.mFresnelPower);
    (void)JsonFloat(text, "UnitReflection", s.mUnitReflectionAmount);
    (void)JsonFloat(text, "SkyReflection", s.mSkyReflectionAmount);
    (void)JsonFloat(text, "SunShininess", s.mSunShininess);
    (void)JsonFloat(text, "SunStrength", s.mSunStrength);
    JsonVector(text, "SunDirection", s.mSunDirection, 3);
    JsonVector(text, "SunColor", s.mSunColor, 3);
    (void)JsonFloat(text, "SunReflection", s.mSunReflectionAmount);
    (void)JsonFloat(text, "SunGlow", s.mSunGlow);
    (void)JsonValue(text, "TexPathCubemap", water.textures[0]);
    (void)JsonValue(text, "TexPathWaterRamp", water.textures[1]);
    // The four wave layers, in order.
    std::string array;
    (void)JsonValue(text, "WaveTextures", array);
    float* const movements[4] = {s.mNormal1Movement, s.mNormal2Movement, s.mNormal3Movement, s.mNormal4Movement};
    std::size_t at = 1;
    for (int i = 0; i < 4; ++i) {
      const std::size_t open = array.find('{', at);
      if (open == std::string::npos) {
        break;
      }
      int depth = 0;
      std::size_t close = open;
      for (; close < array.size(); ++close) {
        depth += array[close] == '{' ? 1 : array[close] == '}' ? -1 : 0;
        if (depth == 0) {
          break;
        }
      }
      const std::string layer = array.substr(open, close - open + 1);
      (void)JsonValue(layer, "TexPath", water.textures[2 + i]);
      JsonVector(layer, "NormalMovement", movements[i], 2);
      (void)JsonFloat(layer, "NormalRepeat", s.mNormalRepeatRate[i]);
      at = close + 1;
    }
    return true;
  }
} // namespace faf::editor
