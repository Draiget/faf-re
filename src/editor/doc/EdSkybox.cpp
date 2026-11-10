#include "editor/doc/EdSkybox.h"

#include <cstdlib>

#include "editor/doc/EdJson.h"

namespace faf::editor
{
  namespace
  {
    // JsonUtility writes a Color as {r, g, b, a}.
    std::string ColorText(const float (&rgb)[3], const std::string& indent)
    {
      const std::string in = indent + "    ";
      return "{\n" + in + "\"r\": " + JsonNumber(rgb[0]) + ",\n" + in + "\"g\": " + JsonNumber(rgb[1]) + ",\n" + in + "\"b\": " +
             JsonNumber(rgb[2]) + ",\n" + in + "\"a\": 1.0\n" + indent + "}";
    }

    void ReadColor(const std::string& text, const std::string& key, float (&rgb)[3])
    {
      std::string object;
      if (!JsonValue(text, key, object)) {
        return;
      }
      (void)JsonFloat(object, "r", rgb[0]);
      (void)JsonFloat(object, "g", rgb[1]);
      (void)JsonFloat(object, "b", rgb[2]);
    }

    void ReadInt(const std::string& text, const std::string& key, int& out)
    {
      std::string number;
      if (JsonValue(text, key, number)) {
        out = std::atoi(number.c_str());
      }
    }
  } // namespace

  bool SkyboxState::operator==(const SkyboxState& other) const
  {
    const auto same = [](const void* a, const void* b, const std::size_t size) { return std::memcmp(a, b, size) == 0; };
    return same(position, other.position, sizeof(position)) && horizonHeight == other.horizonHeight && scale == other.scale &&
           subtractHeight == other.subtractHeight && subdivisionsAxis == other.subdivisionsAxis &&
           subdivisionsHeight == other.subdivisionsHeight && zenithHeight == other.zenithHeight &&
           same(horizonColor, other.horizonColor, sizeof(horizonColor)) && same(zenithColor, other.zenithColor, sizeof(zenithColor)) &&
           decalGlow == other.decalGlow && albedo == other.albedo && glow == other.glow && planets.size() == other.planets.size() &&
           (planets.empty() || same(planets.data(), other.planets.data(), planets.size() * sizeof(SkyboxPlanet))) &&
           cirrusMultiplier == other.cirrusMultiplier && same(cirrusColor, other.cirrusColor, sizeof(cirrusColor)) &&
           cirrusTexture == other.cirrusTexture && same(cirrus, other.cirrus, sizeof(cirrus));
  }

  std::string SkyboxToScmskybox(const SkyboxState& sky)
  {
    // SkyboxValues' fields in its declaration order, inside SkyboxData's "Data".
    const std::string in = "        ";
    std::string out = "{\n    \"Data\": {\n";
    const auto line = [&](const std::string& key, const std::string& value, const bool last = false) {
      out += in + "\"" + key + "\": " + value + (last ? "\n" : ",\n");
    };
    line("Position", JsonVectorText(sky.position, 3, in));
    line("Scale", JsonNumber(sky.scale));
    line("SubtractHeight", JsonNumber(sky.subtractHeight));
    line("SubdivisionsAxis", std::to_string(sky.subdivisionsAxis));
    line("SubdivisionsHeight", std::to_string(sky.subdivisionsHeight));
    line("HorizonHeight", JsonNumber(sky.horizonHeight));
    line("ZenithHeight", JsonNumber(sky.zenithHeight));
    line("HorizonColor", ColorText(sky.horizonColor, in));
    line("ZenithColor", ColorText(sky.zenithColor, in));
    line("DecalGlowMultiplier", JsonNumber(sky.decalGlow));
    line("Albedo", JsonQuoted(sky.albedo));
    line("Glow", JsonQuoted(sky.glow));
    std::string planets = "[";
    const std::string pin = in + "    ";
    for (std::size_t i = 0; i < sky.planets.size(); ++i) {
      const SkyboxPlanet& planet = sky.planets[i];
      planets += (i == 0 ? "\n" : ",\n") + pin + "{\n";
      planets += pin + "    \"Position\": " + JsonVectorText(planet.position, 3, pin + "    ") + ",\n";
      planets += pin + "    \"Rotation\": " + JsonNumber(planet.rotation) + ",\n";
      planets += pin + "    \"Scale\": " + JsonVectorText(planet.scale, 2, pin + "    ") + ",\n";
      planets += pin + "    \"Uv\": " + JsonVectorText(planet.uv, 4, pin + "    ") + "\n";
      planets += pin + "}";
    }
    planets += sky.planets.empty() ? "]" : "\n" + in + "]";
    line("Planets", planets);
    line("MidRgbColor", "{\n" + in + "    \"r\": 0,\n" + in + "    \"g\": 0,\n" + in + "    \"b\": 0,\n" + in + "    \"a\": 0\n" + in + "}");
    line("CirrusMultiplier", JsonNumber(sky.cirrusMultiplier));
    line("CirrusColor", ColorText(sky.cirrusColor, in));
    line("CirrusTexture", JsonQuoted(sky.cirrusTexture));
    std::string layers = "[";
    for (int i = 0; i < 4; ++i) {
      const SkyboxCirrusLayer& layer = sky.cirrus[i];
      layers += (i == 0 ? "\n" : ",\n") + pin + "{\n";
      layers += pin + "    \"frequency\": " + JsonVectorText(layer.frequency, 2, pin + "    ") + ",\n";
      layers += pin + "    \"Speed\": " + JsonNumber(layer.speed) + ",\n";
      layers += pin + "    \"Direction\": " + JsonVectorText(layer.direction, 2, pin + "    ") + "\n";
      layers += pin + "}";
    }
    layers += "\n" + in + "]";
    line("CirrusLayers", layers);
    line("Clouds7", "0.0", true);
    return out + "    }\n}";
  }

  bool SkyboxFromScmskybox(const std::string& text, SkyboxState& sky, std::string& error)
  {
    std::string data;
    std::string probe;
    if (!JsonValue(text, "Data", data) || !JsonValue(data, "SubdivisionsAxis", probe) || !JsonValue(data, "CirrusTexture", probe)) {
      error = "not a sky file (no Data with SubdivisionsAxis and CirrusTexture)";
      return false;
    }
    SkyboxState read;
    // The planets' and layers' own keys (Position, Scale) also name the sky's: read the arrays first, then the rest
    // from the text without them.
    std::string planets;
    std::string layers;
    (void)JsonValue(data, "Planets", planets);
    (void)JsonValue(data, "CirrusLayers", layers);
    std::string rest = data;
    for (const std::string* const array : {&planets, &layers}) {
      if (!array->empty()) {
        if (const std::size_t at = rest.find(*array); at != std::string::npos) {
          rest.erase(at, array->size());
        }
      }
    }
    JsonVector(rest, "Position", read.position, 3);
    (void)JsonFloat(rest, "Scale", read.scale);
    (void)JsonFloat(rest, "SubtractHeight", read.subtractHeight);
    ReadInt(rest, "SubdivisionsAxis", read.subdivisionsAxis);
    ReadInt(rest, "SubdivisionsHeight", read.subdivisionsHeight);
    (void)JsonFloat(rest, "HorizonHeight", read.horizonHeight);
    (void)JsonFloat(rest, "ZenithHeight", read.zenithHeight);
    ReadColor(rest, "HorizonColor", read.horizonColor);
    ReadColor(rest, "ZenithColor", read.zenithColor);
    (void)JsonFloat(rest, "DecalGlowMultiplier", read.decalGlow);
    (void)JsonValue(rest, "Albedo", read.albedo);
    (void)JsonValue(rest, "Glow", read.glow);
    (void)JsonFloat(rest, "CirrusMultiplier", read.cirrusMultiplier);
    ReadColor(rest, "CirrusColor", read.cirrusColor);
    (void)JsonValue(rest, "CirrusTexture", read.cirrusTexture);
    for (const std::string& object : JsonObjects(planets)) {
      SkyboxPlanet planet;
      JsonVector(object, "Position", planet.position, 3);
      (void)JsonFloat(object, "Rotation", planet.rotation);
      JsonVector(object, "Scale", planet.scale, 2);
      JsonVector(object, "Uv", planet.uv, 4);
      read.planets.push_back(planet);
    }
    // The game keeps four layers; more are dropped, fewer leave the rest zero.
    int index = 0;
    for (const std::string& object : JsonObjects(layers)) {
      if (index == 4) {
        break;
      }
      SkyboxCirrusLayer& layer = read.cirrus[index++];
      JsonVector(object, "frequency", layer.frequency, 2);
      (void)JsonFloat(object, "Speed", layer.speed);
      JsonVector(object, "Direction", layer.direction, 2);
    }
    sky = std::move(read);
    return true;
  }
} // namespace faf::editor
