#include "editor/tools/EdDecalShape.h"

#include <algorithm>
#include <cctype>
#include <cmath>

namespace faf::editor
{
  DecalFootprint DecalAround(const float cx, const float cz, const float sizeX, const float sizeZ, const float yaw)
  {
    const float c = std::cos(yaw);
    const float s = std::sin(yaw);
    // The middle is corner (0.5, 0.5): half of each side back from it.
    DecalFootprint decal;
    decal.x = cx - 0.5f * (sizeX * c - sizeZ * s);
    decal.z = cz - 0.5f * (sizeX * s + sizeZ * c);
    decal.sizeX = sizeX;
    decal.sizeZ = sizeZ;
    decal.yaw = yaw;
    return decal;
  }

  void DecalCentre(const DecalFootprint& decal, float& cx, float& cz)
  {
    const float c = std::cos(decal.yaw);
    const float s = std::sin(decal.yaw);
    cx = decal.x + 0.5f * (decal.sizeX * c - decal.sizeZ * s);
    cz = decal.z + 0.5f * (decal.sizeX * s + decal.sizeZ * c);
  }

  void DecalCorners(const DecalFootprint& decal, float (&x)[4], float (&z)[4])
  {
    const float c = std::cos(decal.yaw);
    const float s = std::sin(decal.yaw);
    static constexpr float kU[4] = {0.0f, 1.0f, 1.0f, 0.0f};
    static constexpr float kV[4] = {0.0f, 0.0f, 1.0f, 1.0f};
    for (int i = 0; i < 4; ++i) {
      // ComputeCorner: x + v * (-sizeZ sin) + u * (sizeX cos), z + v * (sizeZ cos) + u * (sizeX sin).
      x[i] = decal.x + kV[i] * (-decal.sizeZ * s) + kU[i] * (decal.sizeX * c);
      z[i] = decal.z + kV[i] * (decal.sizeZ * c) + kU[i] * (decal.sizeX * s);
    }
  }

  bool DecalContains(const DecalFootprint& decal, const float x, const float z)
  {
    if (decal.sizeX <= 0.0f || decal.sizeZ <= 0.0f) {
      return false;
    }
    const float c = std::cos(decal.yaw);
    const float s = std::sin(decal.yaw);
    const float dx = x - decal.x;
    const float dz = z - decal.z;
    const float u = (dx * c + dz * s) / decal.sizeX;
    const float v = (-dx * s + dz * c) / decal.sizeZ;
    return u >= 0.0f && u < 1.0f && v >= 0.0f && v < 1.0f;
  }

  int DecalTypeForTexture(const std::string& path)
  {
    std::string lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](const unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    const std::size_t slash = lower.find_last_of('/');
    const std::string file = slash == std::string::npos ? lower : lower.substr(slash + 1);
    if (file.find("normal") != std::string::npos) {
      return 2;
    }
    if (file.find("glow") != std::string::npos) {
      return 6;
    }
    return 1;
  }

  const char* DecalTypeName(const int type)
  {
    switch (type) {
    case 1:
      return "albedo";
    case 2:
      return "normals";
    case 3:
      return "water mask";
    case 4:
      return "water albedo";
    case 5:
      return "water normals";
    case 6:
      return "glow";
    case 7:
      return "normals alpha";
    case 8:
      return "glow mask";
    case 9:
      return "albedo XP";
    default:
      return "undefined";
    }
  }
} // namespace faf::editor
