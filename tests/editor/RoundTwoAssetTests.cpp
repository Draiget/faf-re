// The FAF Studio features of the editor's second round that read and write asset files: the Lua table reader, the unit
// wizard on Studio's donor data, the skinned SCM writer, the unit animation reader and the mesh terrain checks.

#include "editor/doc/EdLuaTable.h"
#include "editor/tools/EdMeshData.h"
#include "editor/tools/EdMeshImport.h"
#include "editor/tools/EdMeshScan.h"
#include "editor/tools/EdScaAnim.h"
#include "editor/tools/EdScm.h"
#include "editor/tools/EdUnitWizard.h"

#include <gtest/gtest.h>

#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <set>

namespace faf::editor
{
  namespace
  {
    std::string ReadFile(
      const char* path
    )
    {
      std::ifstream in(path, std::ios::binary);
      return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }

    void Put(
      std::vector<std::uint8_t>& b,
      const void* data,
      const std::size_t n
    )
    {
      const auto* p = static_cast<const std::uint8_t*>(data);
      b.insert(b.end(), p, p + n);
    }
  } // namespace

  TEST(
    LuaTable,
    ReadsAssignmentsTablesAndCalls
  )
  {
    JsonTree root;
    const auto read = ParseLuaAssignments(
      R"(-- a comment
A = { x = 1, 'two', ['k k'] = { 3, 4 }, s = "q\"t", b = true, n = nil }
B = Sound { Bank = 'X', Cue = 'Y' }
--[[ long
comment ]]
C = [[long text]]
)",
      root
    );
    ASSERT_TRUE(read) << read.error();
    const JsonTree* a = root.Get("A");
    ASSERT_NE(a, nullptr);
    EXPECT_DOUBLE_EQ(a->Num("x", 0), 1.0);
    ASSERT_EQ(a->items.size(), 1U);
    EXPECT_EQ(a->items[0].s, "two");
    EXPECT_EQ(a->Get("k k")->items.size(), 2U);
    EXPECT_EQ(a->Str("s", ""), "q\"t");
    EXPECT_EQ(root.Get("B")->Str("__call", ""), "Sound");
    EXPECT_EQ(root.Get("C")->s, "long text");
  }

  TEST(
    UnitWizard,
    MakesABlueprintScriptAndMeshFromStudiosData
  )
  {
    UnitWizardData data;
    const auto loaded = LoadUnitWizardData(ReadFile(FAF_UNITWIZ_DATA), data);
    ASSERT_TRUE(loaded) << loaded.error();
    const std::string id = SuggestUnitId("bot", "UEF", [](const std::string& i) {
      return i == "zel0001";
    });
    EXPECT_EQ(id, "zel0002");
    const auto made = NewUnitSpec(data, "bot", "UEF", id);
    ASSERT_TRUE(made) << made.error();
    const UnitWizardSpec& spec = *made;
    ASSERT_EQ(spec.weapons.size(), 1U);
    const std::vector<std::string> cats = UnitCategories(data, spec);
    EXPECT_NE(std::find(cats.begin(), cats.end(), "UEF"), cats.end());
    EXPECT_NE(std::find(cats.begin(), cats.end(), "TECH1"), cats.end());
    EXPECT_NE(std::find(cats.begin(), cats.end(), "BUILTBYTIER1FACTORY"), cats.end());
    const std::string bp =
      UnitBlueprintText(data, spec, {{"Economy.BuildCostMass", 77.0}, {"Weapon:MainGun.Damage", 9.0}}, nullptr);
    EXPECT_EQ(bp.rfind(UnitWizardMark(), 0), 0U);
    EXPECT_NE(bp.find("BuildCostMass = 77"), std::string::npos);
    EXPECT_NE(bp.find("Damage = 9,"), std::string::npos);
    EXPECT_NE(bp.find("Sound {"), std::string::npos);
    // The blueprint reads back as a table.
    JsonTree parsed;
    const auto read = ParseLuaAssignments(bp, parsed);
    ASSERT_TRUE(read) << read.error();
    EXPECT_NE(parsed.Get("UnitBlueprint"), nullptr);
    const std::string script = UnitScriptText(data, spec);
    EXPECT_NE(script.find("MainGun = ClassWeapon("), std::string::npos);
    EXPECT_NE(script.find("TypeClass = ZEL0002"), std::string::npos);
    // The placeholder mesh in the donor's skeleton.
    UnitMeshInfo info;
    const auto scm = UnitMesh(data, spec, "", info);
    ASSERT_TRUE(scm) << scm.error();
    EXPECT_TRUE(info.placeholder);
    EXPECT_GT(info.bones, 1);
    const auto model = ReadScm(*scm);
    ASSERT_TRUE(model) << model.error();
    EXPECT_EQ(model->bones, info.bones);
    // The spec file reads back.
    const auto back = ReadUnitSpecs(UnitSpecsText({spec}));
    ASSERT_TRUE(back) << back.error();
    ASSERT_EQ(back->size(), 1U);
    EXPECT_EQ(UnitSpecsText(*back), UnitSpecsText({spec}));
  }

  TEST(
    Scm,
    SkinnedModelKeepsItsBones
  )
  {
    const auto parsed =
      ParseObj("o body\nv 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\ng turret\nv 0 2 0\nv 1 2 0\nv 0 3 0\nf 4 5 6\n");
    ASSERT_TRUE(parsed) << parsed.error();
    const ObjMesh& mesh = *parsed;
    ASSERT_EQ(mesh.groups.size(), 2U);
    ASSERT_EQ(mesh.triangleGroup.size(), 2U);
    EXPECT_EQ(mesh.triangleGroup[1], 1);
    std::vector<ScmBone> bones(2);
    bones[0].name = "Root";
    bones[1].name = "Turret";
    bones[1].parent = 0;
    bones[1].pos = {0.0f, 2.0f, 0.0f};
    const auto scm = ScmFromObjSkinned(mesh, bones, {0, 0, 0, 1, 1, 1}, 1.0f, "test");
    ASSERT_TRUE(scm) << scm.error();
    const auto model = ReadScm(*scm);
    ASSERT_TRUE(model) << model.error();
    EXPECT_EQ(model->bones, 2);
    const std::vector<std::array<float, 3>> at = ScmBonePositions(bones);
    EXPECT_NEAR(at[1][1], 2.0f, 1e-5f);
  }

  TEST(
    ScaAnim,
    ReadsAndSamplesFrames
  )
  {
    // An animation of two bones and two frames: the child moves 2 units up over a second.
    std::vector<std::uint8_t> b;
    const auto u32 = [&b](const std::uint32_t v) {
      Put(b, &v, 4);
    };
    const auto f32 = [&b](const float v) {
      Put(b, &v, 4);
    };
    Put(b, "ANIM", 4);
    u32(5);    // version
    u32(2);    // frames
    f32(1.0f); // duration
    u32(2);    // bones
    u32(0x24); // names
    u32(0x30); // links
    u32(0x38); // first frame
    u32(8 + 2 * 28);
    Put(b, "root\0arm\0\0\0", 12); // 0x24 .. 0x30
    u32(0xFFFFFFFFu);
    u32(0);
    for (int i = 0; i < 7; ++i) {
      f32(i == 3 ? 1.0f : 0.0f); // root start
    }
    for (int frame = 0; frame < 2; ++frame) {
      f32(static_cast<float>(frame));
      u32(0);
      for (int bone = 0; bone < 2; ++bone) {
        f32(0.0f);
        f32(bone == 1 ? static_cast<float>(frame) * 2.0f : 0.0f);
        f32(0.0f);
        f32(1.0f);
        f32(0.0f);
        f32(0.0f);
        f32(0.0f);
      }
    }
    ScaAnimation anim;
    const auto read = ReadSca(b, anim);
    ASSERT_TRUE(read) << read.error();
    ASSERT_EQ(anim.bones.size(), 2U);
    EXPECT_EQ(anim.bones[1], "arm");
    EXPECT_EQ(anim.parents[1], 0);
    const std::vector<ScaKey> half = SampleSca(anim, 0.5f, false);
    EXPECT_NEAR(half[1].position[1], 1.0f, 1e-5f);
    const std::vector<ScaKey> wrapped = SampleSca(anim, 1.25f, true);
    EXPECT_NEAR(wrapped[1].position[1], 0.5f, 1e-5f);
    EXPECT_NEAR(ScaBoneWorld(anim, half)[1][1], 1.0f, 1e-5f);
  }

  TEST(
    MeshTerrain,
    ManifestPatchesAndChecks
  )
  {
    // One patch: two triangles over a 64 x 64 square at height 5, written as the import writes it.
    const auto mesh = ParseObj("v 0 5 0\nv 64 5 0\nv 64 5 64\nv 0 5 64\nf 1 3 2\nf 1 4 3\n");
    ASSERT_TRUE(mesh) << mesh.error();
    const auto made = ScmFromObj(*mesh, "tile", 1.0f, "test");
    ASSERT_TRUE(made) << made.error();
    const std::vector<std::uint8_t>& scm = *made;
    std::map<std::pair<int, int>, std::string> files{{{0, 0}, "tile_0_0.scm"}};
    const std::string manifest = MeshTerrainManifest(files, 64.0f, 5.0f);
    std::map<std::string, std::vector<std::uint8_t>> disk{
      {"/maps/m/terrain/terrain.lua", std::vector<std::uint8_t>(manifest.begin(), manifest.end())},
      {"/maps/m/terrain/tile_0_0.scm", scm}
    };
    edmesh::SetMeshFileReader([&disk](const std::string& path) {
      const auto it = disk.find(path);
      return it != disk.end() ? it->second : std::vector<std::uint8_t>{};
    });
    edmesh::MeshMap map;
    ASSERT_TRUE(map.Load("/maps/m/terrain/terrain.lua")) << map.error;
    float y = 0.0f;
    ASSERT_TRUE(map.HeightAt(10.0f, 10.0f, 100.0f, y));
    EXPECT_NEAR(y, 5.0f, 1e-3f);
    const MeshScanResult scan = ScanMeshMap(map, true, 32);
    EXPECT_GT(scan.coverage, 95.0f);
    for (const MeshScanFinding& f : scan.findings) {
      EXPECT_NE(f.severity, 'E') << f.text;
      // The import's own manifest passes its own mesh_high check (it once wrote the bare highest vertex).
      if (f.text.contains("mesh_high")) {
        EXPECT_EQ(f.severity, 'I') << f.text;
      }
    }
    edmesh::SetMeshFileReader({});
  }

  TEST(
    MeshTerrain,
    SettingsSetUnsetAndRoundTrip
  )
  {
    // Every one of Studio's 34 manifest settings has a slot; set ones are written and read back, unset ones vanish.
    EXPECT_EQ(edmesh::SettingKeys().size(), 34U);
    edmesh::Settings s;
    for (const edmesh::SettingKey& key : edmesh::SettingKeys()) {
      const bool slot = edmesh::SettingNumber(s, key.key) != nullptr || edmesh::SettingText(s, key.key) != nullptr;
      EXPECT_TRUE(slot) << key.key;
      EXPECT_EQ(key.decimals == -2, edmesh::SettingText(s, key.key) != nullptr) << key.key;
    }
    edmesh::MeshMap map;
    map.patches.push_back({});
    map.patches.back().file = "tile.scm";
    map.patches.back().sky = true;
    map.materials.push_back({});
    map.materials.back().name = "Rock";
    map.materials.back().alphaTest = 100.0f;
    edmesh::SetSettingGiven(map.settings, "shadow_a", true);
    *edmesh::SettingNumber(map.settings, "shadow_a") = 0.25f;
    edmesh::SetSettingGiven(map.settings, "sun_x", true);
    *edmesh::SettingNumber(map.settings, "sun_x") = 0.5f;
    edmesh::SetSettingGiven(map.settings, "void_g", true);
    edmesh::SetSettingGiven(map.settings, "water_map", true);
    std::string text = map.ManifestText();
    EXPECT_NE(text.find("shadow_a = 0.25"), std::string::npos) << text;
    EXPECT_NE(text.find("sun_x = 0.5"), std::string::npos) << text;
    EXPECT_NE(text.find("water_map = 'watermap.dds'"), std::string::npos) << text;
    EXPECT_NE(text.find("alpha_test = 100"), std::string::npos) << text;
    EXPECT_NE(text.find("sky = 1"), std::string::npos) << text;
    EXPECT_EQ(text.find("shadow_r"), std::string::npos) << "an unset key isn't written";
    {
      edmesh::MeshMap tiny = map;
      edmesh::SetSettingGiven(tiny.settings, "sun_z", true);
      *edmesh::SettingNumber(tiny.settings, "sun_z") = 0.00005f;
      const std::string written = tiny.ManifestText();
      EXPECT_NE(written.find("sun_z = 0.00005"), std::string::npos) << written;
      EXPECT_EQ(written.find("e-"), std::string::npos) << "no exponent: " << written;
    }
    edmesh::SetSettingGiven(map.settings, "sun_x", false);
    EXPECT_EQ(*edmesh::SettingNumber(map.settings, "sun_x"), 0.0f);
    text = map.ManifestText();
    EXPECT_EQ(text.find("sun_x"), std::string::npos) << text;
    // Read back: the given keys come back given, a stray line is a V18 warning.
    text += "something odd\n";
    std::map<std::string, std::vector<std::uint8_t>> disk{
      {"/maps/m/terrain/terrain.lua", std::vector<std::uint8_t>(text.begin(), text.end())}
    };
    edmesh::SetMeshFileReader([&disk](const std::string& path) {
      const auto it = disk.find(path);
      return it != disk.end() ? it->second : std::vector<std::uint8_t>{};
    });
    edmesh::MeshMap back;
    (void)back.Load("/maps/m/terrain/terrain.lua");
    EXPECT_EQ(back.settings.given.count("shadow_a"), 1U);
    EXPECT_NEAR(back.settings.shadowColor[3], 0.25f, 1e-6f);
    EXPECT_TRUE(back.settings.haveVoid);
    ASSERT_EQ(back.warnings.size(), 1U);
    EXPECT_NE(back.warnings[0].find("something odd"), std::string::npos);
    edmesh::SetMeshFileReader({});
  }

  TEST(
    MeshTerrain,
    ManifestChecksAgainstTheMap
  )
  {
    // Studio's manifest checks: size, playable area, water, the scenario, unused materials, missing files.
    edmesh::MeshMap map;
    map.dir = "/maps/m/terrain";
    map.settings.given = {"size"};
    map.settings.size = 512.0f;
    map.settings.playable[2] = map.settings.playable[3] = 512.0f;
    map.settings.water = 20.0f;
    map.materials.resize(2);
    map.materials[0].files[0] = "rock_a.dds";
    map.patches.push_back({});
    map.patches.back().file = "tile.scm";
    MeshManifestFacts facts;
    facts.mapSize = 1024;
    facts.havePlayable = true;
    facts.playable[2] = facts.playable[3] = 1024.0f;
    facts.water = false;
    facts.groundHighest = 300.0f;
    facts.haveScenario = true;
    facts.terrainSystem = "mesh";
    facts.terrainMesh = "/maps/other/terrain/terrain.lua";
    facts.expectedMesh = "/maps/m/terrain/terrain.lua";
    facts.read = [](const std::string&) {
      return std::vector<std::uint8_t>{};
    };
    std::set<std::string> codes;
    std::string all;
    for (const MeshScanFinding& f : CheckMeshManifest(map, facts)) {
      codes.insert(f.code);
      all += f.code + " " + f.text + "\n";
    }
    for (const char* code : {"V19", "V11", "V9", "V12", "V14", "V2", "V1", "V5", "V20"}) {
      EXPECT_EQ(codes.count(code), 1U) << code << " missing in\n" << all;
    }
    EXPECT_NE(all.find("size 512 but the map is 1024"), std::string::npos) << all;
    EXPECT_NE(all.find("material 2 '' is not used"), std::string::npos) << all;
    EXPECT_NE(all.find("texture 'rock_a.dds'"), std::string::npos) << all;
  }
} // namespace faf::editor
