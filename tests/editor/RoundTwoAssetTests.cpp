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
    std::string error;
    ASSERT_TRUE(ParseLuaAssignments(
      R"(-- a comment
A = { x = 1, 'two', ['k k'] = { 3, 4 }, s = "q\"t", b = true, n = nil }
B = Sound { Bank = 'X', Cue = 'Y' }
--[[ long
comment ]]
C = [[long text]]
)",
      root,
      error
    )) << error;
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
    std::string error;
    ASSERT_TRUE(LoadUnitWizardData(ReadFile(FAF_UNITWIZ_DATA), data, error)) << error;
    UnitWizardSpec spec;
    const std::string id = SuggestUnitId("bot", "UEF", [](const std::string& i) {
      return i == "zel0001";
    });
    EXPECT_EQ(id, "zel0002");
    ASSERT_TRUE(NewUnitSpec(data, "bot", "UEF", id, spec, error)) << error;
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
    ASSERT_TRUE(ParseLuaAssignments(bp, parsed, error)) << error;
    EXPECT_NE(parsed.Get("UnitBlueprint"), nullptr);
    const std::string script = UnitScriptText(data, spec);
    EXPECT_NE(script.find("MainGun = ClassWeapon("), std::string::npos);
    EXPECT_NE(script.find("TypeClass = ZEL0002"), std::string::npos);
    // The placeholder mesh in the donor's skeleton.
    UnitMeshInfo info;
    const std::vector<std::uint8_t> scm = UnitMesh(data, spec, "", info, error);
    ASSERT_FALSE(scm.empty()) << error;
    EXPECT_TRUE(info.placeholder);
    EXPECT_GT(info.bones, 1);
    ScmModel model;
    ASSERT_TRUE(ReadScm(scm, model, error)) << error;
    EXPECT_EQ(model.bones, info.bones);
    // The spec file reads back.
    std::vector<UnitWizardSpec> back;
    ASSERT_TRUE(ReadUnitSpecs(UnitSpecsText({spec}), back, error)) << error;
    ASSERT_EQ(back.size(), 1U);
    EXPECT_EQ(UnitSpecsText(back), UnitSpecsText({spec}));
  }

  TEST(
    Scm,
    SkinnedModelKeepsItsBones
  )
  {
    ObjMesh mesh;
    std::string error;
    ASSERT_TRUE(ParseObj(
      "o body\nv 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\ng turret\nv 0 2 0\nv 1 2 0\nv 0 3 0\nf 4 5 6\n", mesh, error
    )) << error;
    ASSERT_EQ(mesh.groups.size(), 2U);
    ASSERT_EQ(mesh.triangleGroup.size(), 2U);
    EXPECT_EQ(mesh.triangleGroup[1], 1);
    std::vector<ScmBone> bones(2);
    bones[0].name = "Root";
    bones[1].name = "Turret";
    bones[1].parent = 0;
    bones[1].pos = {0.0f, 2.0f, 0.0f};
    const std::vector<std::uint8_t> scm = ScmFromObjSkinned(mesh, bones, {0, 0, 0, 1, 1, 1}, 1.0f, "test", error);
    ASSERT_FALSE(scm.empty()) << error;
    ScmModel model;
    ASSERT_TRUE(ReadScm(scm, model, error)) << error;
    EXPECT_EQ(model.bones, 2);
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
    std::string error;
    ASSERT_TRUE(ReadSca(b, anim, error)) << error;
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
    ObjMesh mesh;
    std::string error;
    ASSERT_TRUE(ParseObj("v 0 5 0\nv 64 5 0\nv 64 5 64\nv 0 5 64\nf 1 3 2\nf 1 4 3\n", mesh, error)) << error;
    const std::vector<std::uint8_t> scm = ScmFromObj(mesh, "tile", 1.0f, "test", error);
    ASSERT_FALSE(scm.empty()) << error;
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
      if (f.text.find("mesh_high") != std::string::npos) {
        EXPECT_EQ(f.severity, 'I') << f.text;
      }
    }
    edmesh::SetMeshFileReader({});
  }
} // namespace faf::editor
