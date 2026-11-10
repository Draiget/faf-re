#include "editor/tools/EdShaderSlots.h"

#include <cctype>

namespace faf::editor
{
  namespace
  {
    /** "Terrain" and three digits (an optional B for biplanar mapping after them): the 0XX, 1XX, 2XX, 3XX shaders. */
    bool Numbered(const std::string& shader, std::string& digits)
    {
      if (shader.rfind("Terrain", 0) != 0 || shader.size() < 10) {
        return false;
      }
      digits = shader.substr(7, 3);
      for (const char c : digits) {
        if (std::isdigit(static_cast<unsigned char>(c)) == 0) {
          return false;
        }
      }
      return shader.size() == 10 || (shader.size() == 11 && shader[10] == 'B');
    }
  } // namespace

  bool MapWideOn(const float slotSize, const float mapSize)
  {
    return mapSize > 0.0f && slotSize > mapSize;
  }

  ShaderSlotUse ShaderSlotUseOf(const std::string& shader, const int slot)
  {
    ShaderSlotUse use;
    std::string digits;
    const bool numbered = Numbered(shader, digits);
    const bool pbr = shader == "TerrainPBR" || digits == "301";
    const bool xpExt = shader == "TTerrainXPExt";
    if (!numbered && !pbr && !xpExt) {
      return use; // the GPG shaders: every slot a stratum
    }
    if (pbr) {
      if (slot == 8) {
        use.text = "A stratum (alpha: transparency); its normal slot holds the layers' height and roughness";
      } else if (slot == 9) {
        use.mapWide = true;
        use.text = "Map-wide, not a stratum: the map's normals (x, z), water depth and shadow";
      }
      return use;
    }
    if (slot == 8) {
      use.mapWide = true;
      use.text = "Map-wide, not a stratum: water depth, ambient occlusion and shadow; its normal slot holds the map's normals";
    } else if (slot == 9) {
      if (xpExt || digits == "000" || digits == "050") {
        use.text = "A macrotexture over the whole map (alpha: opacity)";
      } else if (digits == "001" || digits == "051") {
        use.text = "A specular map (alpha: sharpness)";
      } else {
        use.mapWide = true;
        use.text = "Map-wide, not a stratum: the layers' height and roughness (lower to 3, 4 to 7)";
      }
    } else if (slot == 0 && digits[0] != '0') {
      use.text = "The lower layer (alpha: opacity where it serves as a macrotexture)";
    }
    return use;
  }
} // namespace faf::editor
