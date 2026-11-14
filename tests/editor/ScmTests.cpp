#include "editor/tools/EdScm.h"

#include <gtest/gtest.h>

#include <cmath>
#include <cstring>

namespace faf::editor
{
  namespace
  {
    // A unit cube: 8 positions, 4 texture corners, 6 normals, 6 quads.
    const char* const kCube = "# a cube\n"
                              "v -1 -1 -1\nv 1 -1 -1\nv 1 1 -1\nv -1 1 -1\nv -1 -1 1\nv 1 -1 1\nv 1 1 1\nv -1 1 1\n"
                              "vt 0 0\nvt 1 0\nvt 1 1\nvt 0 1\n"
                              "vn 0 0 -1\nvn 0 0 1\nvn 0 -1 0\nvn 0 1 0\nvn -1 0 0\nvn 1 0 0\n"
                              "f 1/1/1 4/4/1 3/3/1 2/2/1\n"
                              "f 5/1/2 6/2/2 7/3/2 8/4/2\n"
                              "f 1/1/3 2/2/3 6/3/3 5/4/3\n"
                              "f 4/1/4 8/2/4 7/3/4 3/4/4\n"
                              "f 1/1/5 5/2/5 8/3/5 4/4/5\n"
                              "f -7/1/6 -6/2/6 -2/3/6 -3/4/6\n";

    std::uint32_t U32(
      const std::vector<std::uint8_t>& bytes,
      const std::size_t at
    )
    {
      std::uint32_t v = 0;
      std::memcpy(&v, bytes.data() + at, 4);
      return v;
    }
  } // namespace

  TEST(
    Scm,
    ObjFacesBecomeTriangles
  )
  {
    ObjMesh mesh;
    std::string error;
    ASSERT_TRUE(ParseObj(kCube, mesh, error)) << error;
    EXPECT_EQ(mesh.positions.size(), 8U);
    EXPECT_EQ(mesh.triangles.size(), 12U);
    EXPECT_EQ(mesh.triangles[10][0].position, 1) << "-7 of 8 is the second";
    EXPECT_FALSE(ParseObj("v 0 0 0\nf 1 2 3\n", mesh, error)) << "a face with vertices the file hasn't got";
    EXPECT_FALSE(ParseObj("v 0 0 0\n", mesh, error));
  }

  TEST(
    Scm,
    TheFileHasTheEnginesLayout
  )
  {
    ObjMesh mesh;
    std::string error;
    ASSERT_TRUE(ParseObj(kCube, mesh, error)) << error;
    const std::vector<std::uint8_t> scm = ScmFromObj(mesh, "Body", 2.0f, "made by a test", error);
    ASSERT_FALSE(scm.empty()) << error;
    EXPECT_EQ(std::memcmp(scm.data(), "MODL", 4), 0);
    EXPECT_EQ(U32(scm, 0x04), 5U);
    EXPECT_EQ(std::memcmp(scm.data() + 0x3C, "NAME", 4), 0);
    EXPECT_STREQ(reinterpret_cast<const char*>(scm.data() + 0x40), "Body") << "the names from 0x40";
    const std::uint32_t bones = U32(scm, 0x08);
    EXPECT_EQ(bones % 32, 0U);
    EXPECT_EQ(std::memcmp(scm.data() + bones - 4, "SKEL", 4), 0);
    EXPECT_EQ(U32(scm, 0x0C), 1U);
    EXPECT_EQ(U32(scm, 0x2C), 1U);
    std::int32_t parent = 0;
    std::memcpy(&parent, scm.data() + bones + 0x60, 4);
    EXPECT_EQ(parent, -1);
    const std::uint32_t vertices = U32(scm, 0x10);
    const std::uint32_t count = U32(scm, 0x18);
    EXPECT_EQ(count, 24U) << "4 corners a side, each its own normal";
    EXPECT_EQ(std::memcmp(scm.data() + vertices - 4, "VTXL", 4), 0);
    const std::uint32_t indexes = U32(scm, 0x1C);
    EXPECT_EQ(indexes, vertices + count * 0x44 + (indexes - (vertices + count * 0x44))) << "after the vertices";
    EXPECT_GE(indexes, vertices + count * 0x44 + 4);
    EXPECT_EQ(U32(scm, 0x20), 36U);
    // The first vertex: scaled, its normal unit length, its tangent square to it.
    float v[17];
    std::memcpy(v, scm.data() + vertices, sizeof(v));
    EXPECT_FLOAT_EQ(std::fabs(v[0]), 2.0f);
    EXPECT_NEAR(v[3] * v[3] + v[4] * v[4] + v[5] * v[5], 1.0f, 1e-5f);
    EXPECT_NEAR(v[3] * v[6] + v[4] * v[7] + v[5] * v[8], 0.0f, 1e-5f);
    EXPECT_STREQ(reinterpret_cast<const char*>(scm.data() + U32(scm, 0x24)), "made by a test");
  }
} // namespace faf::editor
