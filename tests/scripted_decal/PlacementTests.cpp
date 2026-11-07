// Engine addition: ScriptedDecalCornerForCentre (moho/script/ScriptedDecalPlacement.h) against
// CWldTerrainDecal::ComputeCorner's mapping (0x0089D9C0), written out here.

#include <cmath>
#include <cstdio>

#include "moho/script/ScriptedDecalPlacement.h"

namespace
{
  int gFailures = 0;

  void Expect(const char* what, const float actual, const float expected)
  {
    if (std::fabs(actual - expected) > 1e-4f) {
      std::printf("FAIL %s: %.6f, expected %.6f\n", what, actual, expected);
      ++gFailures;
    }
  }

  // ComputeCorner: position + u * sx * (cos h, sin h) + v * sz * (-sin h, cos h).
  void Corner(
    const moho::ScriptedDecalCorner& at, const float sx, const float sz, const float h, const float u, const float v,
    float& x, float& z
  )
  {
    x = at.x + v * (-sz * std::sin(h)) + u * (sx * std::cos(h));
    z = at.z + v * (sz * std::cos(h)) + u * (sx * std::sin(h));
  }

  void CheckCentre(const float cx, const float cz, const float sx, const float sz, const float h)
  {
    const moho::ScriptedDecalCorner corner = moho::ScriptedDecalCornerForCentre(cx, cz, sx, sz, h);
    float x = 0.0f;
    float z = 0.0f;
    Corner(corner, sx, sz, h, 0.5f, 0.5f, x, z);
    Expect("centre x", x, cx);
    Expect("centre z", z, cz);
  }
} // namespace

int main()
{
  // Heading 0 is the binary's centre - scale / 2 (0x0087ECE0), bit for bit.
  {
    const moho::ScriptedDecalCorner corner = moho::ScriptedDecalCornerForCentre(100.0f, 50.0f, 4.0f, 10.0f, 0.0f);
    if (corner.x != 98.0f || corner.z != 45.0f) {
      std::printf("FAIL heading 0: (%.6f, %.6f), expected (98, 45)\n", corner.x, corner.z);
      ++gFailures;
    }
  }

  // The middle of the quad is the centre at every heading, for square and long decals.
  const float headings[] = {0.0f, 0.3f, 0.785398f, 1.570796f, 2.5f, 3.141593f, -1.2f, 7.0f};
  for (const float h : headings) {
    CheckCentre(100.0f, 50.0f, 4.0f, 10.0f, h);
    CheckCentre(-3.0f, 812.5f, 1.0f, 1.0f, h);
    CheckCentre(0.0f, 0.0f, 25.0f, 2.0f, h);
  }

  // A quarter turn swaps the extents: the x edge runs along +z, the z edge along -x.
  {
    const float h = 1.5707963f;
    const moho::ScriptedDecalCorner corner = moho::ScriptedDecalCornerForCentre(0.0f, 0.0f, 4.0f, 10.0f, h);
    float minX = 1e9f;
    float maxX = -1e9f;
    float minZ = 1e9f;
    float maxZ = -1e9f;
    for (int u = 0; u <= 1; ++u) {
      for (int v = 0; v <= 1; ++v) {
        float x = 0.0f;
        float z = 0.0f;
        Corner(corner, 4.0f, 10.0f, h, static_cast<float>(u), static_cast<float>(v), x, z);
        minX = std::fmin(minX, x);
        maxX = std::fmax(maxX, x);
        minZ = std::fmin(minZ, z);
        maxZ = std::fmax(maxZ, z);
      }
    }
    Expect("quarter turn x extent", maxX - minX, 10.0f);
    Expect("quarter turn z extent", maxZ - minZ, 4.0f);
    Expect("quarter turn min x", minX, -5.0f);
    Expect("quarter turn min z", minZ, -2.0f);
  }

  std::printf("scripted decal placement: %d failures\n", gFailures);
  return gFailures == 0 ? 0 : 1;
}
