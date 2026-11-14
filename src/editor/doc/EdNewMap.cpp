#include "editor/doc/EdNewMap.h"
#include "editor/doc/EdPreview.h"

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

    [[nodiscard]] int Players(
      const NewMapSettings& settings
    )
    {
      return std::clamp(settings.players, 1, kNewMapMaxPlayers);
    }

    /** The title for a Lua string in double quotes. */
    [[nodiscard]] std::string Quoted(
      const std::string& text
    )
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

    [[nodiscard]] std::string Number(
      const double value
    )
    {
      char text[48];
      (void)std::snprintf(text, sizeof(text), "%g", value);
      return text;
    }

    void AppendWord(
      std::vector<char>& out,
      const std::uint32_t value
    )
    {
      char bytes[4];
      std::memcpy(bytes, &value, 4);
      out.insert(out.end(), bytes, bytes + 4);
    }

    void AppendFloat(
      std::vector<char>& out,
      const float value
    )
    {
      char bytes[4];
      std::memcpy(bytes, &value, 4);
      out.insert(out.end(), bytes, bytes + 4);
    }

    /** One army's entry in the save file, as the game's own maps write it. */
    void AppendArmy(
      std::string& text,
      const std::string& name
    )
    {
      text += "        --[[                                                                           ]]--\n"
              "        --[[  Army                                                                     ]]--\n"
              "        --[[                                                                           ]]--\n"
              "        ['" +
        name +
        "'] =  \n"
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

  int NewMapWidth(
    const NewMapSettings& settings
  )
  {
    return kNewMapSizes[std::clamp(settings.size, 0, kNewMapSizeCount - 1)].units;
  }

  int NewMapDepth(
    const NewMapSettings& settings
  )
  {
    return settings.sizeZ < 0 ? NewMapWidth(settings)
                              : kNewMapSizes[std::clamp(settings.sizeZ, 0, kNewMapSizeCount - 1)].units;
  }

  std::vector<NewMapSpawn> NewMapSpawns(
    const NewMapSettings& settings
  )
  {
    const int players = Players(settings);
    const double width = NewMapWidth(settings);
    const double depth = NewMapDepth(settings);
    const double cx = width * 0.5;
    const double cz = depth * 0.5;
    std::vector<NewMapSpawn> spawns;
    if (players == 1) {
      spawns.push_back({static_cast<float>(cx), static_cast<float>(cz)});
      return spawns;
    }
    for (int i = 0; i < players; ++i) {
      // From the top (smallest z), going round clockwise as seen from above.
      const double angle = -kPi * 0.5 + 2.0 * kPi * i / players;
      spawns.push_back(
        {static_cast<float>(std::round((cx + width * 0.35 * std::cos(angle)) * 2.0) * 0.5),
         static_cast<float>(std::round((cz + depth * 0.35 * std::sin(angle)) * 2.0) * 0.5)}
      );
    }
    return spawns;
  }

  std::string NewMapScenarioText(
    const NewMapSettings& settings,
    const std::string& base
  )
  {
    const int width = NewMapWidth(settings);
    const int depth = NewMapDepth(settings);
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
    text += "    size = {" + std::to_string(width) + ", " + std::to_string(depth) + "},\n";
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

  std::string NewMapSaveText(
    const NewMapSettings& settings
  )
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
      text += "                    ['position'] = VECTOR3( " + Number(spawns[i].x) + ", " + Number(settings.height) +
        ", " + Number(spawns[i].z) + " ),\n";
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
            "    next_army_id = '" +
      std::to_string(spawns.size() + 3) +
      "',\n"
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

  std::vector<char> NewMapPreviewRecord(
    const NewMapSettings& settings
  )
  {
    const float width = static_cast<float>(NewMapWidth(settings));
    const float depth = static_cast<float>(NewMapDepth(settings));
    const PreviewFrame frame = PreviewFrameOf(width, depth);
    const bool underSea = settings.sea && settings.height < settings.seaLevel;
    const std::uint32_t ground = underSea ? 0xFF2E5A8Cu : 0xFF5E7F3Au;
    // The map's square at its longer side's scale, centred; around it black.
    std::vector<std::uint32_t> pixels(static_cast<std::size_t>(kPreviewSide) * kPreviewSide, 0xFF000000u);
    for (int y = 0; y < kPreviewSide; ++y) {
      for (int x = 0; x < kPreviewSide; ++x) {
        const float wx = (static_cast<float>(x) + 0.5f - frame.offsetX) * frame.scale;
        const float wz = (static_cast<float>(y) + 0.5f - frame.offsetZ) * frame.scale;
        if (wx >= 0.0f && wz >= 0.0f && wx <= width && wz <= depth) {
          pixels[static_cast<std::size_t>(y) * kPreviewSide + x] = ground;
        }
      }
    }
    for (const NewMapSpawn& spawn : NewMapSpawns(settings)) {
      const int cx = static_cast<int>(spawn.x / frame.scale + frame.offsetX);
      const int cz = static_cast<int>(spawn.z / frame.scale + frame.offsetZ);
      for (int dz = -3; dz <= 3; ++dz) {
        for (int dx = -3; dx <= 3; ++dx) {
          const int x = cx + dx;
          const int z = cz + dz;
          if (dx * dx + dz * dz <= 9 && x >= 0 && z >= 0 && x < kPreviewSide && z < kPreviewSide) {
            pixels[static_cast<std::size_t>(z) * kPreviewSide + x] = 0xFFFFFFFFu;
          }
        }
      }
    }
    return PreviewRecord(width, depth, pixels);
  }
} // namespace faf::editor
