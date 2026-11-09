#include "editor/doc/EdNewMap.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace faf::editor
{
  namespace
  {
    constexpr double kPi = 3.141592653589793;

    [[nodiscard]] int SizeUnits(const NewMapSettings& settings)
    {
      return kNewMapSizes[std::clamp(settings.size, 0, kNewMapSizeCount - 1)].units;
    }

    [[nodiscard]] int Players(const NewMapSettings& settings)
    {
      return std::clamp(settings.players, 1, kNewMapMaxPlayers);
    }

    /** The title for a Lua string in double quotes. */
    [[nodiscard]] std::string Quoted(const std::string& text)
    {
      std::string out = "\"";
      for (const char c : text) {
        if (c == '"' || c == '\\') {
          out += '\\';
        }
        if (c == '\n' || c == '\r') {
          out += ' ';
          continue;
        }
        out += c;
      }
      return out + "\"";
    }

    [[nodiscard]] std::string Number(const double value)
    {
      char text[48];
      (void)std::snprintf(text, sizeof(text), "%g", value);
      return text;
    }

    void AppendWord(std::vector<char>& out, const std::uint32_t value)
    {
      char bytes[4];
      std::memcpy(bytes, &value, 4);
      out.insert(out.end(), bytes, bytes + 4);
    }

    void AppendFloat(std::vector<char>& out, const float value)
    {
      char bytes[4];
      std::memcpy(bytes, &value, 4);
      out.insert(out.end(), bytes, bytes + 4);
    }

    /** One army's entry in the save file, as the game's own maps write it. */
    void AppendArmy(std::string& text, const std::string& name)
    {
      text += "        --[[                                                                           ]]--\n"
              "        --[[  Army                                                                     ]]--\n"
              "        --[[                                                                           ]]--\n"
              "        ['" + name + "'] =  \n"
              "        {\n"
              "            personality = '',\n"
              "            plans = '',\n"
              "            color = 0,\n"
              "            faction = 0,\n"
              "            Economy = {\n"
              "                mass = 0,\n"
              "                energy = 0,\n"
              "            },\n"
              "            Alliances = {\n"
              "            },\n"
              "            ['Units'] = GROUP {\n"
              "                orders = '',\n"
              "                platoon = '',\n"
              "                Units = {\n"
              "                    ['INITIAL'] = GROUP {\n"
              "                        orders = '',\n"
              "                        platoon = '',\n"
              "                        Units = {\n"
              "                        },\n"
              "                    },\n"
              "                },\n"
              "            },\n"
              "            PlatoonBuilders = {\n"
              "                next_platoon_builder_id = '0',\n"
              "                Builders = {\n"
              "                },\n"
              "            },\n"
              "        },\n";
    }
  } // namespace

  std::vector<NewMapSpawn> NewMapSpawns(const NewMapSettings& settings)
  {
    const int players = Players(settings);
    const double size = SizeUnits(settings);
    const double centre = size * 0.5;
    std::vector<NewMapSpawn> spawns;
    if (players == 1) {
      spawns.push_back({static_cast<float>(centre), static_cast<float>(centre)});
      return spawns;
    }
    const double radius = size * 0.35;
    for (int i = 0; i < players; ++i) {
      // From the top (smallest z), going round clockwise as seen from above.
      const double angle = -kPi * 0.5 + 2.0 * kPi * i / players;
      spawns.push_back({static_cast<float>(std::round((centre + radius * std::cos(angle)) * 2.0) * 0.5),
                        static_cast<float>(std::round((centre + radius * std::sin(angle)) * 2.0) * 0.5)});
    }
    return spawns;
  }

  std::string NewMapScenarioText(const NewMapSettings& settings, const std::string& base)
  {
    const int size = SizeUnits(settings);
    const int players = Players(settings);
    const std::string prefix = "/maps/" + settings.folder + "/" + base;
    std::string armies;
    for (int i = 1; i <= players; ++i) {
      armies += "'ARMY_" + std::to_string(i) + "',";
    }
    std::string text;
    text += "version = 3 -- Lua Version. Dont touch this\n";
    text += "ScenarioInfo = {\n";
    text += "    name = " + Quoted(settings.title) + ",\n";
    text += "    description = \"\",\n";
    text += "    preview = '',\n";
    text += "    map_version = 1,\n";
    text += std::string("    type = '") + (settings.campaign ? "campaign" : "skirmish") + "',\n";
    text += "    starts = true,\n";
    text += "    size = {" + std::to_string(size) + ", " + std::to_string(size) + "},\n";
    text += "    reclaim = {0, 0},\n";
    text += "    map = '" + prefix + ".scmap',\n";
    text += "    save = '" + prefix + "_save.lua',\n";
    text += "    script = '" + prefix + "_script.lua',\n";
    text += "    norushradius = 40,\n";
    text += "    Configurations = {\n";
    text += "        ['standard'] = {\n";
    text += "            teams = {\n";
    text += "                {\n";
    text += "                    name = 'FFA',\n";
    text += "                    armies = {" + armies + "}\n";
    text += "                },\n";
    text += "            },\n";
    text += "            customprops = {\n";
    text += "                ['ExtraArmies'] = STRING( 'ARMY_17 NEUTRAL_CIVILIAN' ),\n";
    text += "            },\n";
    text += "        },\n";
    text += "    },\n";
    text += "}\n";
    return text;
  }

  std::string NewMapSaveText(const NewMapSettings& settings)
  {
    const std::vector<NewMapSpawn> spawns = NewMapSpawns(settings);
    std::string text;
    text += "--[[                                                                           ]]--\n"
            "--[[  Automatically generated code (do not edit)                               ]]--\n"
            "--[[                                                                           ]]--\n"
            "--[[                                                                           ]]--\n"
            "--[[  Scenario                                                                 ]]--\n"
            "--[[                                                                           ]]--\n"
            "Scenario = {\n"
            "    next_area_id = '1',\n"
            "    Props = {\n"
            "    },\n"
            "    Areas = {\n"
            "    },\n"
            "    MasterChain = {\n"
            "        ['_MASTERCHAIN_'] = {\n"
            "            Markers = {\n";
    for (std::size_t i = 0; i < spawns.size(); ++i) {
      text += "                ['ARMY_" + std::to_string(i + 1) + "'] = {\n";
      text += "                    ['color'] = STRING( 'ff800080' ),\n";
      text += "                    ['type'] = STRING( 'Blank Marker' ),\n";
      text += "                    ['prop'] = STRING( '/env/common/props/markers/M_Blank_prop.bp' ),\n";
      text += "                    ['orientation'] = VECTOR3( 0, 0, 0 ),\n";
      text += "                    ['position'] = VECTOR3( " + Number(spawns[i].x) + ", " + Number(settings.height) + ", " +
              Number(spawns[i].z) + " ),\n";
      text += "                },\n";
    }
    text += "            },\n"
            "        },\n"
            "    },\n"
            "    Chains = {\n"
            "    },\n"
            "    next_queue_id = '1',\n"
            "    Orders = {\n"
            "    },\n"
            "    next_platoon_id = '1',\n"
            "    Platoons = {\n"
            "    },\n"
            "    next_army_id = '" + std::to_string(spawns.size() + 3) + "',\n"
            "    next_group_id = '0',\n"
            "    next_unit_id = '0',\n"
            "    Armies = {\n";
    for (std::size_t i = 0; i < spawns.size(); ++i) {
      AppendArmy(text, "ARMY_" + std::to_string(i + 1));
    }
    AppendArmy(text, "ARMY_17");
    AppendArmy(text, "NEUTRAL_CIVILIAN");
    text += "    },\n"
            "}\n";
    return text;
  }

  std::string NewMapScriptText()
  {
    return "local ScenarioUtils = import('/lua/sim/ScenarioUtilities.lua')\n"
           "\n"
           "function OnPopulate()\n"
           "\tScenarioUtils.InitializeArmies()\n"
           "end\n"
           "\n"
           "function OnStart(self)\n"
           "end\n";
  }

  std::vector<char> NewMapPreviewRecord(const NewMapSettings& settings)
  {
    constexpr std::uint32_t kSide = 256;
    const float size = static_cast<float>(SizeUnits(settings));
    std::vector<char> out;
    AppendWord(out, 0xBEEFFEEDu);
    AppendWord(out, 2u);
    AppendFloat(out, size);
    AppendFloat(out, size);
    out.push_back(0); // the name: empty, in UTF-16
    out.push_back(0);
    AppendWord(out, 0u); // no tag/value pairs

    // The DDS: the classic 124-byte header (caps, height, width, pixel format), 32-bit BGRA, no mips.
    std::vector<char> dds;
    dds.insert(dds.end(), {'D', 'D', 'S', ' '});
    AppendWord(dds, 124u);
    AppendWord(dds, 0x1007u);
    AppendWord(dds, kSide);
    AppendWord(dds, kSide);
    for (int i = 0; i < 2 + 1 + 11; ++i) {
      AppendWord(dds, 0u); // pitch, depth, mip count, reserved
    }
    AppendWord(dds, 32u);
    AppendWord(dds, 0x41u); // RGB with alpha
    AppendWord(dds, 0u);
    AppendWord(dds, 32u);
    AppendWord(dds, 0x00FF0000u);
    AppendWord(dds, 0x0000FF00u);
    AppendWord(dds, 0x000000FFu);
    AppendWord(dds, 0xFF000000u);
    AppendWord(dds, 0x1000u); // a texture
    for (int i = 0; i < 4; ++i) {
      AppendWord(dds, 0u);
    }
    const bool underSea = settings.sea && settings.height < settings.seaLevel;
    const std::uint32_t ground = underSea ? 0xFF2E5A8Cu : 0xFF5E7F3Au;
    std::vector<std::uint32_t> pixels(static_cast<std::size_t>(kSide) * kSide, ground);
    for (const NewMapSpawn& spawn : NewMapSpawns(settings)) {
      const int cx = static_cast<int>(spawn.x / size * kSide);
      const int cz = static_cast<int>(spawn.z / size * kSide);
      for (int dz = -3; dz <= 3; ++dz) {
        for (int dx = -3; dx <= 3; ++dx) {
          const int x = cx + dx;
          const int z = cz + dz;
          if (dx * dx + dz * dz <= 9 && x >= 0 && z >= 0 && x < static_cast<int>(kSide) && z < static_cast<int>(kSide)) {
            pixels[static_cast<std::size_t>(z) * kSide + static_cast<std::size_t>(x)] = 0xFFFFFFFFu;
          }
        }
      }
    }
    const auto* const bytes = reinterpret_cast<const char*>(pixels.data());
    dds.insert(dds.end(), bytes, bytes + pixels.size() * 4);

    AppendWord(out, static_cast<std::uint32_t>(dds.size()));
    out.insert(out.end(), dds.begin(), dds.end());
    return out;
  }
} // namespace faf::editor
