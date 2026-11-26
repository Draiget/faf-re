// The source patch of water2.fx for the banks of water bodies: see WaterBanks.h. Pure text in, text out (no engine
// types), so the host tests compile it on its own.
#include <cstddef>
#include <string>
#include <string_view>

#include "moho/terrain/water/WaterBanks.h"

namespace moho::water
{
  namespace
  {
    using std::size_t;
    using std::string;
    using std::string_view;

    constexpr size_t npos = string::npos;

    size_t CountOf(
      const string& text,
      const string_view needle
    )
    {
      size_t n = 0;
      for (size_t p = text.find(needle); p != npos; p = text.find(needle, p + needle.size())) {
        ++n;
      }
      return n;
    }

    // x 1 = the shoreline cut-out mask of a water body (a lake or a river, not the sea) is being drawn: its mask is the
    // depth test alone, the plane of the water nearer than the terrain, so the edge of the water is the true
    // intersection of the level with the ground and not the outline of the water map's blocks.
    constexpr const char* kDeclarations =
      R"HLSL(// ---- FAF banks of water bodies (WaterBankPatch.cpp, docs/WATER_SIMULATION.md): the cut-out of a body is the depth test alone ----
float4 waterBankParams;

)HLSL";

    constexpr string_view kMaskStruct = "struct MASK_OUTPUT";
    constexpr string_view kMaskResult = "return float4(0,0,0,output.b);";
    constexpr string_view kMaskShader = "float4 WaterLayAlphaMaskPS(";
  } // namespace

  BankPatchResult PatchWaterBanks(
    string& source
  )
  {
    BankPatchResult result;
    if (
      CountOf(source, kMaskStruct) != 1 || CountOf(source, kMaskResult) != 1 || CountOf(source, kMaskShader) != 1 ||
      source.find("waterBankParams") != npos
    ) {
      result.error = "MASK_OUTPUT, WaterLayAlphaMaskPS or its return line not found exactly once (or already patched)";
      return result;
    }
    const size_t structAt = source.find(kMaskStruct);
    const size_t shaderAt = source.find(kMaskShader);
    const size_t resultAt = source.find(kMaskResult);
    if (!(structAt < shaderAt && shaderAt < resultAt)) {
      result.error = "the anchor lines are not in the expected order";
      return result;
    }
    string text = source;
    // the later edit first, so the earlier anchor keeps its place
    text.replace(resultAt, kMaskResult.size(), "return float4(0,0,0,waterBankParams.x > 0.5 ? 0.0 : output.b);");
    text.insert(structAt, kDeclarations);
    source = std::move(text);
    result.patched = true;
    return result;
  }
} // namespace moho::water
