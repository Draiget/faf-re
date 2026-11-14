// The .scm reader (back from the writer) and the mesh terrain import's tiles, wires and manifest.

#include "editor/tools/EdMeshImport.h"

#include <gtest/gtest.h>

namespace faf::editor
{
  namespace
  {
    [[nodiscard]] ObjMesh Quad()
    {
      ObjMesh mesh;
      std::string error;
      EXPECT_TRUE(ParseObj(
        "v 0 0 0\nv 10 0 0\nv 10 0 10\nv 0 0 10\nv 300 0 0\nv 310 0 0\nv 310 0 10\n"
        "vt 0 0\nvt 1 0\nvt 1 1\nvt 0 1\n"
        "f 1/1 2/2 3/3\nf 1/1 3/3 4/4\nf 5/1 6/2 7/3\n",
        mesh,
        error
      )) << error;
      return mesh;
    }
  } // namespace

  TEST(
    Scm,
    ReaderReadsWhatTheWriterWrote
  )
  {
    const ObjMesh mesh = Quad();
    std::string error;
    const std::vector<std::uint8_t> bytes = ScmFromObj(mesh, "root", 2.0f, "a test", error);
    ASSERT_FALSE(bytes.empty()) << error;
    ScmModel model;
    ASSERT_TRUE(ReadScm(bytes, model, error)) << error;
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
    ObjMesh again;
    ASSERT_TRUE(ParseObj(ObjFromScm(model, 2.0f), again, error)) << error;
    EXPECT_EQ(again.triangles.size(), 3U);
    EXPECT_FLOAT_EQ(again.positions[model.indexes[0]][0], model.positions[model.indexes[0]][0] / 2.0f);
    std::vector<std::uint8_t> bad = bytes;
    bad[0] = 'X';
    EXPECT_FALSE(ReadScm(bad, model, error));
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
} // namespace faf::editor
