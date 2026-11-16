// The .scm reader (back from the writer) and the mesh terrain import's tiles, wires and manifest.

#include "editor/tools/EdMeshImport.h"

#include <gtest/gtest.h>

#include <cstring>

namespace faf::editor
{
  namespace
  {
    [[nodiscard]] ObjMesh Quad()
    {
      auto mesh = ParseObj(
        "v 0 0 0\nv 10 0 0\nv 10 0 10\nv 0 0 10\nv 300 0 0\nv 310 0 0\nv 310 0 10\n"
        "vt 0 0\nvt 1 0\nvt 1 1\nvt 0 1\n"
        "f 1/1 2/2 3/3\nf 1/1 3/3 4/4\nf 5/1 6/2 7/3\n"
      );
      EXPECT_TRUE(mesh) << mesh.error();
      return mesh.value_or(ObjMesh{});
    }
  } // namespace

  TEST(
    Scm,
    ReaderReadsWhatTheWriterWrote
  )
  {
    const ObjMesh mesh = Quad();
    const auto made = ScmFromObj(mesh, "root", 2.0f, "a test");
    ASSERT_TRUE(made) << made.error();
    const std::vector<std::uint8_t>& bytes = *made;
    const auto read = ReadScm(bytes);
    ASSERT_TRUE(read) << read.error();
    const ScmModel& model = *read;
    EXPECT_EQ(model.version, 5);
    EXPECT_EQ(model.bones, 1);
    EXPECT_EQ(model.indexes.size(), 9U);
    EXPECT_EQ(model.info, "a test");
    bool found = false;
    for (const auto& p : model.positions) {
      found = found || (p[0] == 20.0f && p[2] == 20.0f); // (10, 0, 10) times 2
    }
    EXPECT_TRUE(found);
    // Back to OBJ and in again: the same triangles.
    const auto again = ParseObj(ObjFromScm(model, 2.0f));
    ASSERT_TRUE(again) << again.error();
    EXPECT_EQ(again->triangles.size(), 3U);
    EXPECT_FLOAT_EQ(again->positions[model.indexes[0]][0], model.positions[model.indexes[0]][0] / 2.0f);
    std::vector<std::uint8_t> bad = bytes;
    bad[0] = 'X';
    EXPECT_FALSE(ReadScm(bad));
  }

  TEST(
    MeshImport,
    TilesWiresAndManifest
  )
  {
    MeshImportOptions options;
    options.scale = 1.0f;
    options.tile = 256.0f;
    const ObjMesh placed = TransformMesh(Quad(), options);
    const auto tiles = SplitByTile(placed, options.tile);
    ASSERT_EQ(tiles.size(), 2U); // the square at 0, the triangle past 256
    EXPECT_EQ(tiles.at({0, 0}).triangles.size(), 2U);
    EXPECT_EQ(tiles.at({1, 0}).triangles.size(), 1U);
    // Two triangles sharing an edge: 5 edges; the lone one: 3.
    EXPECT_EQ(MeshWire(placed, 1000).size(), 16U);
    EXPECT_EQ(MeshWire(placed, 2).size(), 4U);
    // One mirror turns the corners round.
    options.flipX = true;
    const ObjMesh mirrored = TransformMesh(Quad(), options);
    EXPECT_FLOAT_EQ(mirrored.positions[1][0], -10.0f);
    EXPECT_EQ(mirrored.triangles[0][1].position, Quad().triangles[0][2].position);
    const std::string manifest = MeshManifest({{{0, 0}, "tile_0_0.scm"}, {{1, 0}, "tile_1_0.scm"}}, 256.0f);
    EXPECT_NE(manifest.find("tile = 256"), std::string::npos);
    EXPECT_NE(manifest.find("{ 1, 0, 'tile_1_0.scm' }"), std::string::npos);
  }

  TEST(
    MeshImport,
    MaterialsNormalsAndLightMaskCoordinates
  )
  {
    // FAF Studio's import options: a part a usemtl material, smooth or flat normals, light masks over the map.
    const auto parsed = ParseObj(
      "v 0 0 0\nv 10 0 0\nv 10 5 10\nv 0 5 10\n"
      "usemtl rock\nf 1 2 3\nusemtl grass\nf 1 3 4\n"
    );
    ASSERT_TRUE(parsed) << parsed.error();
    const ObjMesh& mesh = *parsed;
    ASSERT_EQ(mesh.materials.size(), 2U);
    const auto byMaterial = SplitByMaterial(mesh, 0);
    ASSERT_EQ(byMaterial.size(), 2U);
    EXPECT_EQ(byMaterial[0].first, "rock");
    EXPECT_EQ(byMaterial[1].first, "grass");
    EXPECT_EQ(SplitByMaterial(mesh, 2).size(), 1U);
    EXPECT_EQ(SplitByMaterial(mesh, 2)[0].first, "ground");

    MeshImportOptions options;
    options.normals = 2; // flat: every triangle its own normal
    const ObjMesh flat = TransformMesh(mesh, options);
    EXPECT_EQ(flat.normals.size(), 2U);
    EXPECT_NE(flat.triangles[0][0].normal, flat.triangles[1][0].normal);
    options.normals = 1; // smooth: the shared corner (position 0) has one normal in both triangles
    const ObjMesh smooth = TransformMesh(mesh, options);
    EXPECT_EQ(smooth.triangles[0][0].normal, smooth.triangles[1][0].normal);

    // The second coordinates over the map: a vertex at x 10, z 10 on a 20-unit map reads 0.5, 0.5.
    ObjMesh placed = TransformMesh(mesh, MeshImportOptions{});
    placed.uv2Size = 20.0f;
    const auto made = ScmFromObj(placed, "tile", 1.0f, "test");
    ASSERT_TRUE(made) << made.error();
    const std::vector<std::uint8_t>& scm = *made;
    std::uint32_t at = 0;
    std::uint32_t count = 0;
    std::memcpy(&at, scm.data() + 0x10, 4);
    std::memcpy(&count, scm.data() + 0x18, 4);
    bool found = false;
    for (std::uint32_t v = 0; v < count; ++v) {
      float x = 0.0f;
      float z = 0.0f;
      float u2 = 0.0f;
      float v2 = 0.0f;
      std::memcpy(&x, scm.data() + at + v * 68, 4);
      std::memcpy(&z, scm.data() + at + v * 68 + 8, 4);
      std::memcpy(&u2, scm.data() + at + v * 68 + 56, 4);
      std::memcpy(&v2, scm.data() + at + v * 68 + 60, 4);
      EXPECT_NEAR(u2, x / 20.0f, 1e-6f);
      EXPECT_NEAR(v2, z / 20.0f, 1e-6f);
      found = found || (x == 10.0f && z == 10.0f);
    }
    EXPECT_TRUE(found);
  }
} // namespace faf::editor
