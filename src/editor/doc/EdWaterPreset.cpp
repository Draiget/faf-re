#include "editor/doc/EdWaterPreset.h"

#include <cstdio>
#include <cstdlib>
#include <regex>
#include <vector>

namespace faf::editor
{
  namespace
  {
    std::string Number(const float value)
    {
      char text[48];
      (void)std::snprintf(text, sizeof(text), "%.9g", static_cast<double>(value));
      return text;
    }

    std::string Quoted(const std::string& text)
    {
      std::string out = "\"";
      for (const char c : text) {
        if (c == '"' || c == '\\') {
          out += '\\';
        }
        out += c;
      }
      return out + "\"";
    }

    std::string Vector(const float* const v, const int n, const std::string& indent)
    {
      static const char* const kAxes[3] = {"x", "y", "z"};
      std::string out = "{\n";
      for (int i = 0; i < n; ++i) {
        out += indent + "    \"" + kAxes[i] + "\": " + Number(v[i]) + (i + 1 < n ? ",\n" : "\n");
      }
      return out + indent + "}";
    }

    /** The text of a key's value: a number, true/false, a "string", or an {object} / [array] with its brackets. */
    bool Value(const std::string& text, const std::string& key, std::string& out, const std::size_t from = 0, const std::size_t to = std::string::npos)
    {
      const std::string needle = "\"" + key + "\"";
      std::size_t at = text.find(needle, from);
      if (at == std::string::npos || (to != std::string::npos && at >= to)) {
        return false;
      }
      at = text.find(':', at + needle.size());
      if (at == std::string::npos) {
        return false;
      }
      ++at;
      while (at < text.size() && (text[at] == ' ' || text[at] == '\t' || text[at] == '\r' || text[at] == '\n')) {
        ++at;
      }
      if (at >= text.size()) {
        return false;
      }
      const char first = text[at];
      if (first == '"') {
        std::string value;
        for (std::size_t i = at + 1; i < text.size(); ++i) {
          if (text[i] == '\\' && i + 1 < text.size()) {
            value += text[++i];
          } else if (text[i] == '"') {
            out = value;
            return true;
          } else {
            value += text[i];
          }
        }
        return false;
      }
      if (first == '{' || first == '[') {
        const char close = first == '{' ? '}' : ']';
        int depth = 0;
        for (std::size_t i = at; i < text.size(); ++i) {
          if (text[i] == first) {
            ++depth;
          } else if (text[i] == close && --depth == 0) {
            out = text.substr(at, i - at + 1);
            return true;
          }
        }
        return false;
      }
      std::size_t end = at;
      while (end < text.size() && text[end] != ',' && text[end] != '}' && text[end] != '\n' && text[end] != '\r') {
        ++end;
      }
      out = text.substr(at, end - at);
      while (!out.empty() && out.back() == ' ') {
        out.pop_back();
      }
      return true;
    }

    bool Float(const std::string& text, const std::string& key, float& out)
    {
      std::string value;
      if (!Value(text, key, value)) {
        return false;
      }
      out = std::strtof(value.c_str(), nullptr);
      return true;
    }

    void Vec(const std::string& text, const std::string& key, float* const out, const int n)
    {
      std::string object;
      if (!Value(text, key, object)) {
        return;
      }
      static const char* const kAxes[3] = {"x", "y", "z"};
      for (int i = 0; i < n; ++i) {
        (void)Float(object, kAxes[i], out[i]);
      }
    }
  } // namespace

  std::string WaterToScmwtr(const WaterState& water)
  {
    const WaterNumbers& s = water.shader;
    std::string out = "{\n";
    const auto line = [&out](const std::string& key, const std::string& value, const bool last = false) {
      out += "    \"" + key + "\": " + value + (last ? "\n" : ",\n");
    };
    line("HasWater", water.enabled ? "true" : "false");
    line("Elevation", Number(water.elevation));
    line("ElevationDeep", Number(water.deep));
    line("ElevationAbyss", Number(water.abyss));
    line("SurfaceColor", Vector(s.mWaterColor, 3, "    "));
    line("ColorLerp", Vector(s.mWaterLerp, 2, "    "));
    line("RefractionScale", Number(s.mRefractionScale));
    line("FresnelBias", Number(s.mFresnelBias));
    line("FresnelPower", Number(s.mFresnelPower));
    line("UnitReflection", Number(s.mUnitReflectionAmount));
    line("SkyReflection", Number(s.mSkyReflectionAmount));
    line("SunShininess", Number(s.mSunShininess));
    line("SunStrength", Number(s.mSunStrength));
    line("SunDirection", Vector(s.mSunDirection, 3, "    "));
    line("SunColor", Vector(s.mSunColor, 3, "    "));
    line("SunReflection", Number(s.mSunReflectionAmount));
    line("SunGlow", Number(s.mSunGlow));
    line("TexPathCubemap", Quoted(water.textures[0]));
    line("TexPathWaterRamp", Quoted(water.textures[1]));
    const float* const movements[4] = {s.mNormal1Movement, s.mNormal2Movement, s.mNormal3Movement, s.mNormal4Movement};
    std::string waves = "[\n";
    for (int i = 0; i < 4; ++i) {
      waves += "        {\n";
      waves += "            \"TexPath\": " + Quoted(water.textures[2 + i]) + ",\n";
      waves += "            \"NormalMovement\": " + Vector(movements[i], 2, "            ") + ",\n";
      waves += "            \"NormalRepeat\": " + Number(s.mNormalRepeatRate[i]) + "\n";
      waves += std::string("        }") + (i < 3 ? ",\n" : "\n");
    }
    waves += "    ]";
    line("WaveTextures", waves, true);
    return out + "}";
  }

  bool WaterFromScmwtr(const std::string& text, WaterState& water, std::string& error)
  {
    std::string probe;
    if (!Value(text, "SurfaceColor", probe) || !Value(text, "WaveTextures", probe)) {
      error = "not a water settings file (no SurfaceColor or WaveTextures)";
      return false;
    }
    WaterNumbers& s = water.shader;
    std::string has;
    if (Value(text, "HasWater", has)) {
      water.enabled = has == "true";
    }
    (void)Float(text, "Elevation", water.elevation);
    (void)Float(text, "ElevationDeep", water.deep);
    (void)Float(text, "ElevationAbyss", water.abyss);
    Vec(text, "SurfaceColor", s.mWaterColor, 3);
    Vec(text, "ColorLerp", s.mWaterLerp, 2);
    (void)Float(text, "RefractionScale", s.mRefractionScale);
    (void)Float(text, "FresnelBias", s.mFresnelBias);
    (void)Float(text, "FresnelPower", s.mFresnelPower);
    (void)Float(text, "UnitReflection", s.mUnitReflectionAmount);
    (void)Float(text, "SkyReflection", s.mSkyReflectionAmount);
    (void)Float(text, "SunShininess", s.mSunShininess);
    (void)Float(text, "SunStrength", s.mSunStrength);
    Vec(text, "SunDirection", s.mSunDirection, 3);
    Vec(text, "SunColor", s.mSunColor, 3);
    (void)Float(text, "SunReflection", s.mSunReflectionAmount);
    (void)Float(text, "SunGlow", s.mSunGlow);
    (void)Value(text, "TexPathCubemap", water.textures[0]);
    (void)Value(text, "TexPathWaterRamp", water.textures[1]);
    // The four wave layers, in order.
    std::string array;
    (void)Value(text, "WaveTextures", array);
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
      (void)Value(layer, "TexPath", water.textures[2 + i]);
      Vec(layer, "NormalMovement", movements[i], 2);
      (void)Float(layer, "NormalRepeat", s.mNormalRepeatRate[i]);
      at = close + 1;
    }
    return true;
  }
} // namespace faf::editor
