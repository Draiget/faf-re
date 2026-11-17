#include "editor/tools/EdTextureSets.h"

#include "editor/tools/EdTexScale.h"

#include <utility>

namespace faf::editor
{
  namespace
  {
    using enum GroundKind;
    using Paths = std::vector<const char*>;

    std::array<Paths, 9> Kinds(
      Paths grass,
      Paths rock,
      Paths sand,
      Paths dirt,
      Paths wet,
      Paths highrock,
      Paths darkrock,
      Paths snow
    )
    {
      std::array<Paths, 9> k;
      k[static_cast<std::size_t>(Grass)] = std::move(grass);
      k[static_cast<std::size_t>(Rock)] = std::move(rock);
      k[static_cast<std::size_t>(Sand)] = std::move(sand);
      k[static_cast<std::size_t>(Dirt)] = std::move(dirt);
      k[static_cast<std::size_t>(Wet)] = std::move(wet);
      k[static_cast<std::size_t>(HighRock)] = std::move(highrock);
      k[static_cast<std::size_t>(DarkRock)] = std::move(darkrock);
      k[static_cast<std::size_t>(Snow)] = std::move(snow);
      return k;
    }
  } // namespace

  const std::vector<TextureTheme>& TextureThemes()
  {
    // FAF Studio's texsets.lua Themes, in its ThemeOrder.
    static const std::vector<TextureTheme> themes = {
      {"temperate",
       "Temperate (Evergreen)",
       12,
       {"/env/Evergreen/layers/grass001_albedo.dds"},
       {"/env/Evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/Evergreen/layers/grass000_albedo.dds", "/env/Evergreen/layers/grass001_albedo.dds"},
         {"/env/Evergreen/layers/RockMed_albedo.dds"},
         {"/env/Evergreen/layers/SandLight_albedo.dds"},
         {"/env/Evergreen/layers/Dirt001_albedo.dds"},
         {"/env/Evergreen/layers/Sandwet_albedo.dds"},
         {"/env/Evergreen/layers/RockLight_albedo.dds"},
         {"/env/Evergreen/layers/SandRock_albedo.dds"},
         {"/env/Evergreen/layers/snow001_albedo.dds"}
       )},
      {"valley",
       "Open valley (Evergreen 2: green hills, tan plains)",
       12,
       {"/env/Evergreen2/Layers/EvGrass005a_albedo.dds",
        "/env/Evergreen2/Layers/EG_Grass001_albedo.dds",
        "/env/Evergreen/layers/grass001_albedo.dds"},
       {"/env/Evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/Evergreen2/Layers/EvGrass005a_albedo.dds",
          "/env/Evergreen2/Layers/EG_Grass001_albedo.dds",
          "/env/Evergreen/layers/grass000_albedo.dds"},
         {"/env/Evergreen2/Layers/EvRock006c_albedo.dds",
          "/env/Evergreen2/Layers/EG_Rock_albedo.dds",
          "/env/Evergreen/layers/RockMed_albedo.dds"},
         {"/env/Evergreen2/Layers/EV_Reef_sand_albedo.dds", "/env/Evergreen/layers/SandLight_albedo.dds"},
         {"/env/Desert/Layers/Des_Gravel01_albedo.dds",
          "/env/Evergreen2/Layers/Eg_Gravel01_albedo.dds",
          "/env/Evergreen/layers/Dirt001_albedo.dds"},
         {"/env/Evergreen2/Layers/Eg_Dirt003_albedo.dds",
          "/env/Evergreen2/Layers/Eg_Dirt001_albedo.dds",
          "/env/Evergreen/layers/Sandwet_albedo.dds"},
         {"/env/Evergreen2/Layers/EvRock002_albedo.dds",
          "/env/Evergreen2/Layers/EG_Rock_albedo.dds",
          "/env/Evergreen/layers/RockLight_albedo.dds"},
         {"/env/Evergreen2/Layers/EvRock008_albedo.dds",
          "/env/Evergreen2/Layers/EvRock004_albedo.dds",
          "/env/Evergreen/layers/SandRock_albedo.dds"},
         {"/env/Evergreen2/Layers/EG_Snow_albedo.dds", "/env/Evergreen/layers/snow001_albedo.dds"}
       )},
      {"desert",
       "Desert",
       14,
       {"/env/Desert/Layers/Des_SandMed_albedo.dds"},
       {"/env/Evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/Desert/Layers/Des_SandMed02_albedo.dds", "/env/Desert/Layers/Des_SandMed_albedo.dds"},
         {"/env/Desert/Layers/Des_Rock_albedo.dds",
          "/env/Desert/Layers/Des_Rock01_albedo.dds",
          "/env/Desert/Decals/Des_Rock01_albedo.dds"},
         {"/env/Desert/Layers/Des_sandLight_albedo.dds"},
         {"/env/Desert/Layers/Des_Gravel_albedo.dds"},
         {"/env/Desert/Layers/Des_Sandwet_albedo.dds"},
         {"/env/Desert/Layers/Des_Rock03_albedo.dds", "/env/Desert/Decals/Des_Rock03_albedo.dds"},
         {"/env/Desert/Layers/Des_SandDark_albedo.dds"},
         {"/env/Desert/Layers/Des_sandLight_albedo.dds"}
       )},
      {"redbarrens",
       "Mars (tan sand, red-brown rock)",
       14,
       {"/env/Desert/Layers/Des_SandMed01_albedo.dds"},
       {"/env/Red Barrens/Layers/macrotexture001_albedo.dds", "/env/Evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/Desert/Layers/Des_SandMed01_albedo.dds"},
         {"/env/Desert/Layers/Des_Rock_albedo.dds", "/env/Red Barrens/Layers/RB_Rock04_albedo.dds"},
         {"/env/Desert/Layers/Des_SandMed_albedo.dds"},
         {"/env/Desert/Layers/Des_Gravel_albedo.dds", "/env/Red Barrens/Layers/RB_Gravel01_albedo.dds"},
         {"/env/Desert/Layers/Des_SandDark02_albedo.dds", "/env/Desert/Layers/Des_SandDark_albedo.dds"},
         {"/env/Desert/Layers/Des_Rock03_albedo.dds", "/env/Red Barrens/Layers/RB_Rock02_albedo.dds"},
         {"/env/Desert/Layers/Des_Rock06_albedo.dds", "/env/Red Barrens/Layers/RB_Rock09_albedo.dds"},
         {"/env/Desert/Layers/Des_SandMed_albedo.dds"}
       )},
      {"tropical",
       "Tropical",
       12,
       {"/env/Tropical/Layers/TrGrass002_albedo.dds"},
       {"/env/Evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/Tropical/Layers/TrGrass005_albedo.dds", "/env/Tropical/Layers/TrGrass002_albedo.dds"},
         {"/env/Tropical/Layers/TrRock002_albedo.dds"},
         {"/env/Tropical/Layers/DrySand001_albedo.dds"},
         {"/env/Tropical/Layers/Tr_ground001_albedo.dds"},
         {"/env/Tropical/Layers/TrBush_moss_albedo.dds"},
         {"/env/Tropical/Layers/TrRock005_albedo.dds"},
         {"/env/Tropical/Layers/TrRock003_albedo.dds", "/env/Tropical/Layers/TrRock006_albedo.dds"},
         {"/env/Tropical/Layers/DrySand002_albedo.dds"}
       )},
      {"tundra",
       "Tundra",
       14,
       {"/env/Tundra/Layers/Tund_Grass_albedo.DDS"},
       {"/env/Tundra/Layers/MacroIce_albedo.dds"},
       Kinds(
         {"/env/Tundra/Layers/Tund_Grass_albedo.DDS"},
         {"/env/Tundra/Layers/Tund_Rock02_albedo.DDS", "/env/Tundra/Layers/Tund_Rock03_albedo.DDS"},
         {"/env/Tundra/Layers/Tund_gravil_albedo.dds"},
         {"/env/Tundra/Layers/_TundraDirt001_albedo.dds", "/env/Tundra/Layers/Tund_sandLight2_albedo.dds"},
         {"/env/Tundra/Layers/Tund_melt001_albedo.dds"},
         {"/env/Tundra/Layers/Tund_iceRock_albedo.dds"},
         {"/env/Tundra/Layers/Tund_Ice004_albedo.DDS", "/env/Tundra/Layers/Tund_Ice001_albedo.DDS"},
         {"/env/Tundra/Layers/Tund_Snow_albedo.DDS"}
       )},
      {"lava",
       "Lava",
       14,
       {"/env/Lava/Layers/LAV_Gravel_albedo.dds"},
       {"/env/Lava/Layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/Lava/Layers/LAV_Gravel_albedo.dds"},
         {"/env/Lava/Layers/LAV_Rock01_albedo.dds"},
         {"/env/Lava/Layers/LAV_Cracked_albedo.dds"},
         {"/env/Lava/Layers/LAV_Rock02_albedo.dds"},
         {"/env/Lava/Layers/LAV_Lava01_albedo.dds"},
         {"/env/Lava/Layers/LAV_Rock05_albedo.dds"},
         {"/env/Lava/Layers/LAV_Rock09_albedo.dds"},
         {"/env/Lava/Layers/LAV_Ribbon01_albedo.dds"}
       )},
      {"swamp",
       "Swamp",
       12,
       {"/env/Swamp/layers/Sw_Grass_01_albedo.dds"},
       {"/env/Evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/Swamp/layers/Sw_Grass_01_albedo.dds"},
         {"/env/Swamp/layers/Sw_Rocky_01_albedo.dds"},
         {"/env/Swamp/layers/Sw_Mudder_01_albedo.dds"},
         {"/env/Swamp/layers/Sw_Mossy_01_albedo.dds"},
         {"/env/Swamp/layers/Sw_Sphagnum_01_albedo.dds"},
         {"/env/Swamp/layers/Sw_Rocky_02_albedo.dds"},
         {"/env/Swamp/layers/Sw_Mudder_03_albedo.dds"},
         {"/env/Swamp/layers/Sw_Ferns_01_albedo.dds"}
       )},
      {"geothermal",
       "Geothermal",
       14,
       {"/env/Geothermal/layers/Geo_Dirt_01_albedo.dds"},
       {"/env/Evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/Geothermal/layers/Geo_Dirt_01_albedo.dds"},
         {"/env/Geothermal/layers/Geo_Rock001_albedo.DDS", "/env/Geothermal/layers/Geo_Rock001_albedo.dds"},
         {"/env/Geothermal/layers/Geo_Ashley_01_albedo.dds"},
         {"/env/Geothermal/layers/Geo_Rock002_albedo.dds"},
         {"/env/Geothermal/layers/Geo_LavaDk_01_albedo.dds"},
         {"/env/Geothermal/layers/Geo_Rock002_albedo.dds"},
         {"/env/Geothermal/layers/Geo_LavaMd_01_albedo.dds"},
         {"/env/Geothermal/layers/Geo_LavaLt_01_albedo.dds"}
       )},
      // The sets measured on the reference maps (FAF Studio's mapsets.lua), by family.
      {"m_evergreen2_1",
       "Evergreen 2 - Variant 1 (reference maps)",
       12,
       {"/env/evergreen2/layers/eg_gravel005_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/evergreen2/layers/evgrass005_albedo.dds"},
         {"/env/evergreen2/layers/evrock008_albedo.dds"},
         {"/env/tropical/layers/tr_reef_coral2_albedo.dds"},
         {"/env/evergreen2/layers/eg_gravel005_albedo.dds"},
         {"/env/tundra/layers/tund_melt002_albedo.dds"},
         {"/env/evergreen2/layers/evrock006_albedo.dds"},
         {"/env/evergreen/layers/rocklight_albedo.dds"},
         {"/env/tundra/layers/tund_ice004a_albedo.dds"}
       )},
      {"m_evergreen2_2",
       "Evergreen 2 - Variant 2 (reference maps)",
       12,
       {"/env/paradise/layers/sand000_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/evergreen2/layers/evgrass005_albedo.dds"},
         {"/env/evergreen/layers/rocklight_albedo.dds"},
         {"/env/paradise/layers/sand000_albedo.dds"},
         {"/env/evergreen2/layers/evgrass005_albedo.dds"},
         {"/env/tundra/layers/tund_melt002_albedo.dds"},
         {"/env/evergreen2/layers/evrock006_albedo.dds"},
         {"/env/evergreen/layers/rocklight_albedo.dds"},
         {"/env/tundra/layers/tund_ice004a_albedo.dds"}
       )},
      {"m_evergreen2_3",
       "Evergreen 2 - Variant 3 (reference maps)",
       12,
       {"/env/evergreen2/layers/eg_gravel_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/evergreen2/layers/evgrass009_albedo.dds"},
         {"/env/evergreen2/layers/evrock006_albedo.dds"},
         {"/env/tropical/layers/tr_reef_coral2_albedo.dds"},
         {"/env/evergreen2/layers/evgrass003_albedo.dds"},
         {"/env/tundra/layers/tund_melt002_albedo.dds"},
         {"/env/evergreen2/layers/evrock006_albedo.dds"},
         {"/env/evergreen2/layers/eg_gravel_albedo.dds"},
         {"/env/tundra/layers/tund_ice004a_albedo.dds"}
       )},
      {"m_desert_1",
       "Desert - Variant 1 (reference maps)",
       12,
       {"/env/desert/layers/des_gravel01_albedo.dds"},
       {"/env/evergreen/layers/macrotexture001_albedo.dds"},
       Kinds(
         {"/env/desert/layers/des_gravel_albedo.dds"},
         {"/env/desert/layers/des_rock01_albedo.dds"},
         {"/env/desert/layers/des_sandmed02_albedo.dds"},
         {"/env/desert/layers/des_gravel01_albedo.dds"},
         {"/env/desert/layers/des_sandwet_albedo.dds"},
         {"/env/desert/layers/des_rock01_albedo.dds"},
         {"/env/desert/layers/des_rock05_albedo.dds"},
         {}
       )},
      {"m_desert_2",
       "Desert - Variant 2 (reference maps)",
       12,
       {"/env/evergreen2/layers/eg_gravel005_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/desert/layers/des_gravel01_albedo.dds"},
         {"/env/desert/layers/des_rock05_albedo.dds"},
         {"/env/tropical/layers/trop_sand_albedo.dds"},
         {"/env/evergreen2/layers/eg_gravel005_albedo.dds"},
         {"/env/desert/layers/des_sandwet_albedo.dds"},
         {"/env/desert/layers/des_rock01_albedo.dds"},
         {"/env/desert/layers/des_rock05_albedo.dds"},
         {}
       )},
      {"m_desert_3",
       "Desert - Variant 3 (reference maps)",
       12,
       {"/env/desert/layers/des_gravel_albedo.dds"},
       {"/env/red barrens/layers/macrotexture001_albedo.dds"},
       Kinds(
         {"/env/desert/layers/des_gravel01_albedo.dds"},
         {"/env/desert/layers/des_rock01_albedo.dds"},
         {"/env/desert/layers/des_sandmed01_albedo.dds"},
         {"/env/desert/layers/des_gravel_albedo.dds"},
         {"/env/desert/layers/des_sandwet_albedo.dds"},
         {"/env/desert/layers/des_rock01_albedo.dds"},
         {"/env/desert/layers/des_gravel_albedo.dds"},
         {}
       )},
      {"m_paradise_1",
       "Paradise - Variant 1 (reference maps)",
       12,
       {"/env/desert/layers/des_sanddark02_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/evergreen2/layers/eg_dirt002_albedo.dds"},
         {"/env/desert/layers/des_rock05_albedo.dds"},
         {"/env/desert/layers/des_sanddark02_albedo.dds"},
         {"/env/paradise/layers/sand000_albedo.dds"},
         {"/env/desert/layers/des_sandwet_albedo.dds"},
         {"/env/desert/layers/des_rock05_albedo.dds"},
         {"/env/lava/layers/lav_lava02_albedo.dds"},
         {"/env/tundra/layers/tund_ice005_albedo.dds"}
       )},
      {"m_paradise_2",
       "Paradise - Variant 2 (reference maps)",
       12,
       {"/env/tundra/layers/tund_ice005_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/evergreen2/layers/eg_dirt002_albedo.dds"},
         {"/env/tundra/layers/tund_rock_albedo.dds"},
         {"/env/paradise/layers/sandmed_albedo.dds"},
         {"/env/paradise/layers/lavarock_albedo.dds"},
         {"/env/tundra/layers/tund_melt001_albedo.dds"},
         {"/env/tundra/layers/tund_rock03_albedo.dds"},
         {"/env/lava/layers/lav_lava02_albedo.dds"},
         {"/env/tundra/layers/tund_ice005_albedo.dds"}
       )},
      {"m_paradise_3",
       "Paradise - Variant 3 (reference maps)",
       12,
       {"/env/paradise/layers/sandmed_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/evergreen2/layers/eg_grass002b_albedo.dds"},
         {"/env/lava/layers/macrotexture000_albedo.dds"},
         {"/env/paradise/layers/sandmed_albedo.dds"},
         {"/env/evergreen2/layers/evgrass005_albedo.dds"},
         {"/env/tundra/layers/tund_melt001_albedo.dds"},
         {"/env/desert/layers/des_rock06_albedo.dds"},
         {"/env/lava/layers/lav_lava02_albedo.dds"},
         {"/env/tundra/layers/tund_ice005_albedo.dds"}
       )},
      {"m_red_barrens_1",
       "Red barrens - Variant 1 (reference maps)",
       12,
       {"/env/red barrens/layers/rb_sand_albedo.dds"},
       {"/env/red barrens/layers/macrotexture001_albedo.dds"},
       Kinds(
         {"/env/red barrens/layers/rb_cracked_albedo.dds"},
         {"/env/red barrens/layers/rb_rock07_albedo.dds"},
         {"/env/red barrens/layers/rb_sand_albedo.dds"},
         {"/env/red barrens/layers/rb_redmud_albedo.dds"},
         {"/env/red barrens/layers/rb_sandwet_albedo.dds"},
         {"/env/red barrens/layers/rb_rock06_albedo.dds"},
         {"/env/red barrens/layers/rb_rock07_albedo.dds"},
         {"/env/tundra/layers/tund_snow_albedo.dds"}
       )},
      {"m_red_barrens_2",
       "Red barrens - Variant 2 (reference maps)",
       12,
       {"/env/red barrens/layers/rb_sand_albedo.dds"},
       {"/env/red barrens/layers/macrotexture001_albedo.dds"},
       Kinds(
         {"/env/red barrens/layers/rb_cracked_albedo.dds"},
         {"/env/red barrens/layers/rb_rock08_albedo.dds"},
         {"/env/red barrens/layers/rb_sand_albedo.dds"},
         {"/env/red barrens/layers/rb_cracked02_albedo.dds"},
         {"/env/red barrens/layers/rb_sandwet_albedo.dds"},
         {"/env/red barrens/layers/rb_rock06_albedo.dds"},
         {"/env/red barrens/layers/rb_rock07_albedo.dds"},
         {"/env/tundra/layers/tund_snow_albedo.dds"}
       )},
      {"m_red_barrens_3",
       "Red barrens - Variant 3 (reference maps)",
       12,
       {"/env/red barrens/layers/rb_cracked02_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/red barrens/layers/rb_cracked_albedo.dds"},
         {"/env/red barrens/layers/rb_rock08_albedo.dds"},
         {"/env/red barrens/layers/rb_sand_albedo.dds"},
         {"/env/red barrens/layers/rb_cracked02_albedo.dds"},
         {"/env/red barrens/layers/rb_sandwet_albedo.dds"},
         {"/env/red barrens/layers/rb_rock06_albedo.dds"},
         {"/env/red barrens/layers/rb_sand_albedo.dds"},
         {"/env/tundra/layers/tund_snow_albedo.dds"}
       )},
      {"m_tropical_1",
       "Tropical - Variant 1 (reference maps)",
       12,
       {"/env/tropical/layers/trgrass005_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/tropical/layers/trgrass005_albedo.dds"},
         {"/env/lava/layers/lav_cracked02b_albedo.dds"},
         {"/env/tropical/layers/trop_sand_albedo.dds"},
         {"/env/evergreen2/layers/eg_gravel005_albedo.dds"},
         {"/env/tropical/layers/wetsand002b_albedo.dds"},
         {"/env/evergreen2/layers/evrock004_albedo.dds"},
         {"/env/evergreen2/layers/evgrass005a_albedo.dds"},
         {"/env/tundra/layers/tund_ice006_albedo.dds"}
       )},
      {"m_tropical_2",
       "Tropical - Variant 2 (reference maps)",
       12,
       {"/env/tropical/layers/trop_dirt_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/tropical/layers/trgrass004_albedo.dds"},
         {"/env/tropical/layers/trrock006_albedo.dds"},
         {"/env/desert/layers/des_sanddark02_albedo.dds"},
         {"/env/tropical/layers/trop_dirt_albedo.dds"},
         {"/env/tropical/layers/wetsand002b_albedo.dds"},
         {"/env/tropical/layers/trrock007_albedo.dds"},
         {"/env/desert/layers/des_rock_albedo.dds"},
         {"/env/tundra/layers/tund_ice006_albedo.dds"}
       )},
      {"m_tropical_3",
       "Tropical - Variant 3 (reference maps)",
       12,
       {"/env/evergreen2/layers/eg_gravel005_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/evergreen2/layers/eg_gravel003_albedo.dds"},
         {"/env/crystalline/layers/crystalwerk03_albedo.dds"},
         {"/env/tropical/layers/trop_sand_albedo.dds"},
         {"/env/evergreen2/layers/eg_gravel005_albedo.dds"},
         {"/env/swamp/layers/sw_sphagnum_01_albedo.dds"},
         {"/env/evergreen2/layers/evrock004_albedo.dds"},
         {"/env/evergreen2/layers/evgrass005a_albedo.dds"},
         {"/env/tundra/layers/tund_ice006_albedo.dds"}
       )},
      {"m_ancient_earth_1",
       "Ancient earth - Variant 1 (reference maps)",
       12,
       {"/env/ancient-earth/layers/evgrass008_darker_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/ancient-earth/layers/evgrass008_darker_albedo.dds"},
         {"/env/ancient-earth/layers/evrock006_lighter_albedo.dds"},
         {"/env/ancient-earth/layers/sandlight002_citrine_tint_albedo.dds"},
         {"/env/ancient-earth/layers/evgrass004_grass_blend_albedo.dds"},
         {},
         {"/env/crystalline/layers/crystalwerk02b_albedo.dds"},
         {"/env/ancient-earth/layers/evrock006_lighter_albedo.dds"},
         {}
       )},
      {"m_ancient_earth_2",
       "Ancient earth - Variant 2 (reference maps)",
       12,
       {"/env/evergreen2/layers/evgrass006_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/evergreen2/layers/evgrass006_albedo.dds"},
         {"/env/ancient-earth/layers/evrock006_lighter_albedo.dds"},
         {"/env/ancient-earth/layers/sandlight002_citrine_tint_albedo.dds"},
         {"/env/tropical/layers/trop_grass_albedo.dds"},
         {},
         {"/env/crystalline/layers/crystalwerk02b_albedo.dds"},
         {"/env/ancient-earth/layers/evrock006_lighter_albedo.dds"},
         {}
       )},
      {"m_ancient_earth_3",
       "Ancient earth - Variant 3 (reference maps)",
       12,
       {"/env/evergreen2/layers/evgrass006_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/evergreen2/layers/evgrass006_albedo.dds"},
         {"/env/evergreen2/layers/evrock008_albedo.dds"},
         {"/env/desert/layers/des_sanddark_albedo.dds"},
         {"/env/ancient-earth/layers/evgrass004_grass_blend_albedo.dds"},
         {},
         {"/env/geothermal/layers/geo_rock001_albedo.dds"},
         {"/env/ancient-earth/layers/evgrass008_darker_albedo.dds"},
         {}
       )},
      {"m_evergreen_1",
       "Evergreen - Variant 1 (reference maps)",
       12,
       {"/env/evergreen/layers/grass000_albedo.dds"},
       {"/env/tundra/layers/macroice_albedo.dds"},
       Kinds(
         {"/env/evergreen/layers/grass000_albedo.dds"},
         {"/env/tundra/layers/tund_rock_albedo.dds"},
         {"/env/desert/layers/des_sanddark_albedo.dds"},
         {"/env/evergreen2/layers/eg_dirt001_albedo.dds"},
         {"/env/tundra/layers/tund_melt003_albedo.dds"},
         {"/env/desert/layers/des_rock01_albedo.dds"},
         {"/env/evergreen2/layers/evrock007c_albedo.dds"},
         {}
       )},
      {"m_evergreen_2",
       "Evergreen - Variant 2 (reference maps)",
       12,
       {"/env/desert/layers/des_sanddark_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/desert/layers/des_gravel01_albedo.dds"},
         {"/env/evergreen2/layers/evrock006c_albedo.dds"},
         {"/env/desert/layers/des_sanddark_albedo.dds"},
         {"/env/evergreen/layers/sandlight002_albedo.dds"},
         {"/env/tundra/layers/tund_melt003_albedo.dds"},
         {"/env/desert/layers/des_rock01_albedo.dds"},
         {"/env/evergreen2/layers/evrock007c_albedo.dds"},
         {}
       )},
      {"m_evergreen_3",
       "Evergreen - Variant 3 (reference maps)",
       12,
       {"/env/evergreen/layers/sandlight_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/paradise/layers/macrotexture001_albedo.dds"},
         {"/env/paradise/layers/rock001_albedo.dds"},
         {"/env/evergreen/layers/sandlight_albedo.dds"},
         {"/env/paradise/layers/sand000_albedo.dds"},
         {"/env/tundra/layers/tund_melt003_albedo.dds"},
         {"/env/desert/layers/des_rock01_albedo.dds"},
         {"/env/evergreen2/layers/evrock007c_albedo.dds"},
         {}
       )},
      {"m_swamp_1",
       "Swamp - Variant 1 (reference maps)",
       12,
       {"/env/evergreen/layers/rockmed_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/evergreen2/layers/eg_dirt001_albedo.dds"},
         {"/env/evergreen2/layers/eg_rock_albedo.dds"},
         {"/env/evergreen/layers/sandlight_albedo.dds"},
         {"/env/swamp/layers/sw_creeper_01_albedo.dds"},
         {"/env/tundra/layers/tund_melt003_albedo.dds"},
         {"/env/tropical/layers/trrock003_albedo.dds"},
         {"/env/evergreen/layers/rockmed_albedo.dds"},
         {"/env/tundra/layers/tund_ice002_albedo.dds"}
       )},
      {"m_swamp_2",
       "Swamp - Variant 2 (reference maps)",
       12,
       {"/env/tundra/layers/tund_melt003_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/tropical/layers/trop_dirt_albedo.dds"},
         {"/env/paradise/layers/lavarock_albedo.dds"},
         {"/env/evergreen/layers/sandlight_albedo.dds"},
         {"/env/swamp/layers/sw_mudder_03_albedo.dds"},
         {"/env/tundra/layers/tund_melt003_albedo.dds"},
         {"/env/tropical/layers/trrock003_albedo.dds"},
         {"/env/evergreen/layers/rockmed_albedo.dds"},
         {"/env/tundra/layers/tund_ice002_albedo.dds"}
       )},
      {"m_swamp_3",
       "Swamp - Variant 3 (reference maps)",
       12,
       {"/env/swamp/layers/sw_sphagnum_01_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/swamp/layers/sw_mudder_01_albedo.dds"},
         {"/env/swamp/layers/sw_rocky_03_albedo.dds"},
         {"/env/evergreen/layers/sandlight_albedo.dds"},
         {"/env/swamp/layers/sw_mudder_01_albedo.dds"},
         {"/env/swamp/layers/sw_sphagnum_01_albedo.dds"},
         {"/env/tropical/layers/trop_rock_albedo.dds"},
         {"/env/evergreen/layers/rockmed_albedo.dds"},
         {"/env/tundra/layers/tund_ice002_albedo.dds"}
       )},
      {"m_lava_1",
       "Lava - Variant 1 (reference maps)",
       12,
       {"/env/desert/layers/des_gravel_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/lava/layers/lav_gravel_albedo.dds"},
         {"/env/crystalline/layers/cr_rock004_albedo.dds"},
         {"/env/evergreen2/layers/ev_reef_coral_albedo.dds"},
         {"/env/desert/layers/des_gravel_albedo.dds"},
         {"/env/evergreen/layers/sandwet_albedo.dds"},
         {"/env/swamp/layers/sw_rocky_01_albedo.dds"},
         {"/env/crystalline/layers/cr_07_01b_albedo.dds"},
         {}
       )},
      {"m_lava_2",
       "Lava - Variant 2 (reference maps)",
       12,
       {"/env/tundra/layers/tund_rock_albedo.dds"},
       {"/env/lava/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/lava/layers/lav_gravel_albedo.dds"},
         {"/env/lava/layers/lav_rock09b_albedo.dds"},
         {"/env/evergreen2/layers/ev_reef_coral_albedo.dds"},
         {"/env/lava/layers/lav_cracked02b_albedo.dds"},
         {"/env/evergreen/layers/sandwet_albedo.dds"},
         {"/env/lava/layers/lav_rock09_albedo.dds"},
         {"/env/tundra/layers/tund_rock_albedo.dds"},
         {}
       )},
      {"m_lava_3",
       "Lava - Variant 3 (reference maps)",
       12,
       {"/env/evergreen2/layers/eg_dirt002_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/lava/layers/lav_cracked02b_albedo.dds"},
         {"/env/lava/layers/lav_rock09b_albedo.dds"},
         {"/env/evergreen2/layers/ev_reef_coral_albedo.dds"},
         {"/env/evergreen2/layers/eg_dirt002_albedo.dds"},
         {"/env/evergreen/layers/sandwet_albedo.dds"},
         {"/env/swamp/layers/sw_rocky_01_albedo.dds"},
         {"/env/crystalline/layers/cr_07_01b_albedo.dds"},
         {}
       )},
      {"m_geothermal_1",
       "Geothermal - Variant 1 (reference maps)",
       12,
       {"/env/geothermal/layers/geo_ashley_01_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/evergreen/layers/dirt001_albedo.dds"},
         {"/env/geothermal/layers/geo_ashley_01_albedo.dds"},
         {},
         {"/env/geothermal/layers/geo_dirt_01_albedo.dds"},
         {},
         {"/env/geothermal/layers/geo_lavamd_02_albedo.dds"},
         {"/env/geothermal/layers/geo_lavamd_02_albedo.dds"},
         {}
       )},
      {"m_geothermal_2",
       "Geothermal - Variant 2 (reference maps)",
       12,
       {"/env/geothermal/layers/geo_dirt_01_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/evergreen/layers/dirt001_albedo.dds"},
         {"/env/geothermal/layers/geo_lavamd_02_albedo.dds"},
         {},
         {"/env/geothermal/layers/geo_dirt_01_albedo.dds"},
         {},
         {"/env/geothermal/layers/geo_rock001_albedo.dds"},
         {"/env/geothermal/layers/geo_lavamd_02_albedo.dds"},
         {}
       )},
      {"m_crystalline_1",
       "Crystalline - Variant 1 (reference maps)",
       12,
       {"/env/crystalline/layers/crystalwerk01_albedo.dds"},
       {"/env/red barrens/layers/macrotexture001_albedo.dds"},
       Kinds(
         {"/env/crystalline/layers/crystalwerk01_albedo.dds"},
         {"/env/crystalline/layers/cryst013_albedo.dds"},
         {"/env/evergreen/layers/sandlight_albedo.dds"},
         {"/env/crystalline/layers/crystalwerk01_albedo.dds"},
         {"/env/crystalline/layers/cr_sandwet_albedo.dds"},
         {"/env/lava/layers/lav_rock09_albedo.dds"},
         {"/env/crystalline/layers/cr_rock001_albedo.dds"},
         {}
       )},
      {"m_crystalline_2",
       "Crystalline - Variant 2 (reference maps)",
       12,
       {"/env/evergreen/layers/sandlight_albedo.dds"},
       {"/env/lava/layers/lav_macrotexture000b_albedo.dds"},
       Kinds(
         {"/env/crystalline/layers/cr_07_01b_albedo.dds"},
         {"/env/crystalline/layers/cr_09_01_albedo.dds"},
         {"/env/evergreen/layers/sandlight_albedo.dds"},
         {"/env/crystalline/layers/crystalwerk03_albedo.dds"},
         {"/env/tundra/layers/tund_melt003_albedo.dds"},
         {"/env/evergreen2/layers/evrock006b_albedo.dds"},
         {"/env/crystalline/layers/cr_rock001_albedo.dds"},
         {}
       )},
      {"m_crystalline_3",
       "Crystalline - Variant 3 (reference maps)",
       12,
       {"/env/crystalline/layers/crystalwerk01_albedo.dds"},
       {},
       Kinds(
         {"/env/crystalline/layers/crystalwerk01_albedo.dds"},
         {"/env/crystalline/layers/cr_rock001_albedo.dds"},
         {"/env/evergreen/layers/sandlight_albedo.dds"},
         {"/env/crystalline/layers/crystalwerk01_albedo.dds"},
         {"/env/crystalline/layers/cr_sandwet_albedo.dds"},
         {"/env/crystalline/layers/crystalwerk02b_albedo.dds"},
         {"/env/crystalline/layers/cr_rock05_albedo.dds"},
         {}
       )},
      {"m_tundra_1",
       "Tundra - Variant 1 (reference maps)",
       12,
       {"/env/tundra/layers/tund_rock_albedo.dds"},
       {"/env/tundra/layers/macroice_albedo.dds"},
       Kinds(
         {"/env/evergreen2/layers/evgrass009_albedo.dds"},
         {"/env/evergreen2/layers/evrock007c_albedo.dds"},
         {"/env/tundra/layers/tund_sandlight2_albedo.dds"},
         {"/env/evergreen2/layers/eg_gravel002_albedo.dds"},
         {"/env/tundra/layers/tund_melt002_albedo.dds"},
         {"/env/evergreen/layers/rockmed_albedo.dds"},
         {"/env/tundra/layers/tund_rock_albedo.dds"},
         {"/env/tundra/layers/tund_ice001_albedo.dds"}
       )},
      {"m_tundra_2",
       "Tundra - Variant 2 (reference maps)",
       12,
       {"/env/tundra/layers/tund_rock03_albedo.dds"},
       {"/env/crystalline/layers/cr_09_01_albedo.dds"},
       Kinds(
         {"/env/evergreen2/layers/evgrass009_albedo.dds"},
         {"/env/evergreen/layers/rockmed_albedo.dds"},
         {"/env/tundra/layers/tund_sandlight2_albedo.dds"},
         {"/env/tundra/layers/_tundradirt001_albedo.dds"},
         {"/env/tundra/layers/tund_melt002_albedo.dds"},
         {"/env/evergreen/layers/rockmed_albedo.dds"},
         {"/env/tundra/layers/tund_rock03_albedo.dds"},
         {"/env/tundra/layers/tund_snow_albedo.dds"}
       )},
      {"m_tundra_3",
       "Tundra - Variant 3 (reference maps)",
       12,
       {"/env/tundra/layers/tund_snow_albedo.dds"},
       {"/env/evergreen/layers/macrotexture000_albedo.dds"},
       Kinds(
         {"/env/evergreen2/layers/evgrass009_albedo.dds"},
         {"/env/tundra/layers/tund_rock03_albedo.dds"},
         {"/env/tundra/layers/tund_sandlight2_albedo.dds"},
         {"/env/evergreen2/layers/eg_gravel002_albedo.dds"},
         {"/env/tundra/layers/tund_melt001_albedo.dds"},
         {"/env/evergreen/layers/rockmed_albedo.dds"},
         {"/env/tundra/layers/tund_rock02_albedo.dds"},
         {"/env/tundra/layers/tund_snow_albedo.dds"}
       )},
    };
    return themes;
  }

  std::array<int, 9> ThemeLayout(
    const int painted,
    const bool biplanar
  )
  {
    std::array<int, 9> layout{};
    const auto set = [&](const GroundKind kind, const int layer) {
      layout[static_cast<std::size_t>(kind)] = layer;
    };
    if (painted >= 8) {
      set(Grass, 1), set(Rock, 2), set(Sand, 3), set(Dirt, 4), set(Wet, 5), set(HighRock, 6), set(DarkRock, 7),
        set(Snow, 8);
    } else if (painted <= 4) {
      set(Rock, 1), set(Sand, 2), set(Dirt, 3), set(Snow, 4);
    } else if (biplanar) {
      set(Grass, 1), set(Sand, 2), set(Rock, 3), set(HighRock, 4), set(Wet, 5), set(Dirt, 6), set(Snow, 7);
    } else {
      set(Grass, 1), set(Rock, 2), set(Sand, 3), set(Dirt, 4), set(Wet, 5), set(HighRock, 6), set(Snow, 7);
    }
    return layout;
  }

  std::vector<ThemeSlot> ThemeSlots(
    const TextureTheme& theme,
    const int painted,
    const bool biplanar,
    const bool upperOverlay,
    const std::function<bool(const std::string&)>& exists,
    const std::function<int(const std::string&)>& pixels
  )
  {
    const auto first = [&](const Paths& list) {
      for (const char* const path : list) {
        if (exists(path)) {
          return std::string(path);
        }
      }
      return std::string();
    };
    const auto tile = [&](const std::string& path, const float fallback) {
      const int px = pixels(path);
      return px > 0 ? TileForPixels(px) : fallback;
    };
    std::vector<ThemeSlot> out;
    float baseTile = theme.size * 2.0f;
    if (const std::string base = first(theme.base); !base.empty()) {
      baseTile = tile(base, theme.size * 2.0f);
      out.push_back({0, Grass, base, baseTile});
    }
    const std::array<int, 9> layout = ThemeLayout(painted, biplanar);
    for (int kind = 1; kind <= 8; ++kind) {
      const int layer = layout[static_cast<std::size_t>(kind)];
      if (layer <= 0) {
        continue;
      }
      if (const std::string path = first(theme.kinds[static_cast<std::size_t>(kind)]); !path.empty()) {
        out.push_back({layer, static_cast<GroundKind>(kind), path, tile(path, theme.size)});
      }
    }
    if (upperOverlay) {
      if (const std::string upper = first(theme.upper); !upper.empty()) {
        out.push_back({9, Unknown, upper, MacroTile(baseTile)});
      }
    }
    return out;
  }
} // namespace faf::editor
