#include "editor/doc/EdRoundTrip.h"

#include <cstring>
#include <fstream>
#include <iterator>
#include <system_error>
#include <cstdio>
#include <vector>

#include "editor/doc/EdDocument.h"
#include "editor/doc/EdMapFile.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"
#include "moho/terrain/StratumMaterial.h"
#include "moho/terrain/splat/CWldSplat.h"

namespace faf::editor
{
  namespace
  {
    [[nodiscard]] std::vector<char> FileBytes(const std::filesystem::path& path)
    {
      std::ifstream in(path, std::ios::binary);
      return std::vector<char>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }

    void Note(std::string& differences, const std::string& what)
    {
      if (!differences.empty()) {
        differences += "; ";
      }
      differences += what;
    }

    void CompareMaps(moho::CWldMap& a, moho::CWldMap& b, std::string& differences)
    {
      const moho::CHeightField* const fa = a.mTerrainRes->GetHeightField();
      const moho::CHeightField* const fb = b.mTerrainRes->GetHeightField();
      if (fa == nullptr || fb == nullptr || fa->width != fb->width || fa->height != fb->height) {
        Note(differences, "height field size");
      } else if (std::memcmp(fa->data, fb->data, static_cast<std::size_t>(fa->width) * static_cast<std::size_t>(fa->height) * 2u) != 0) {
        Note(differences, "heights");
      }
      // The eight stratum masks, texel for texel, once both maps are ready for drawing (Finalize sets the
      // masks' size and makes them the textures the masks are read from, as drawing a map first does).
      if (!b.mTerrainRes->GetBool()) {
        (void)b.mTerrainRes->Finalize();
      }
      if (a.mTerrainRes->GetBool() && b.mTerrainRes->GetBool()) {
        const moho::StratumMaterial& sa = a.mTerrainRes->GetStratumMaterial();
        const moho::StratumMaterial& sb = b.mTerrainRes->GetStratumMaterial();
        if (sa.mStratumMaskWidth != sb.mStratumMaskWidth || sa.mStratumMaskHeight != sb.mStratumMaskHeight) {
          Note(differences, "mask size " + std::to_string(sa.mStratumMaskWidth) + "x" + std::to_string(sa.mStratumMaskHeight) + " vs " + std::to_string(sb.mStratumMaskWidth) + "x" + std::to_string(sb.mStratumMaskHeight));
        } else {
          const std::size_t count = static_cast<std::size_t>(sa.mStratumMaskWidth) * sa.mStratumMaskHeight;
          std::vector<std::uint8_t> ma(count, 1);
          std::vector<std::uint8_t> mb(count, 2);
          for (int layer = 0; layer < 8; ++layer) {
            a.mTerrainRes->GetStratumMask(layer, ma.data());
            b.mTerrainRes->GetStratumMask(layer, mb.data());
            if (ma != mb) {
              Note(differences, "mask of stratum " + std::to_string(layer + 1));
            }
          }
        }
      }
      if (a.mTerrainRes->IsWaterEnabled() != b.mTerrainRes->IsWaterEnabled() ||
          a.mTerrainRes->GetWaterElevation() != b.mTerrainRes->GetWaterElevation()) {
        Note(differences, "water");
      }
      const moho::StratumMaterial& sa = a.mTerrainRes->GetStratumMaterial();
      const moho::StratumMaterial& sb = b.mTerrainRes->GetStratumMaterial();
      if (std::strcmp(sa.mShaderName.c_str(), sb.mShaderName.c_str()) != 0) {
        Note(differences, "terrain shader");
      }
      using Layer = moho::CStratumMaterial moho::StratumMaterial::*;
      static constexpr Layer kLayers[] = {
        &moho::StratumMaterial::mLowerAlbedoTexture,    &moho::StratumMaterial::mStratum0AlbedoTexture,
        &moho::StratumMaterial::mStratum1AlbedoTexture, &moho::StratumMaterial::mStratum2AlbedoTexture,
        &moho::StratumMaterial::mStratum3AlbedoTexture, &moho::StratumMaterial::mStratum4AlbedoTexture,
        &moho::StratumMaterial::mStratum5AlbedoTexture, &moho::StratumMaterial::mStratum6AlbedoTexture,
        &moho::StratumMaterial::mStratum7AlbedoTexture, &moho::StratumMaterial::mUpperAlbedoTexture,
        &moho::StratumMaterial::mLowerNormalTexture,    &moho::StratumMaterial::mStratum0NormalTexture,
        &moho::StratumMaterial::mStratum1NormalTexture, &moho::StratumMaterial::mStratum2NormalTexture,
        &moho::StratumMaterial::mStratum3NormalTexture, &moho::StratumMaterial::mStratum4NormalTexture,
        &moho::StratumMaterial::mStratum5NormalTexture, &moho::StratumMaterial::mStratum6NormalTexture,
        &moho::StratumMaterial::mStratum7NormalTexture, &moho::StratumMaterial::mUpperNormalTexture,
      };
      for (std::size_t i = 0; i < std::size(kLayers); ++i) {
        const moho::CStratumMaterial& la = sa.*kLayers[i];
        const moho::CStratumMaterial& lb = sb.*kLayers[i];
        if (std::strcmp(la.mPath.c_str(), lb.mPath.c_str()) != 0 || la.mSize != lb.mSize) {
          Note(differences, "texture layer " + std::to_string(i));
          break;
        }
      }
      const auto& pa = a.mProps->mEntries;
      const auto& pb = b.mProps->mEntries;
      if (pa.size() != pb.size()) {
        Note(differences, "prop count");
      } else {
        for (std::size_t i = 0; i < pa.size(); ++i) {
          const bool path = std::strcmp(pa[i].mBlueprintPath.c_str(), pb[i].mBlueprintPath.c_str()) != 0;
          const bool position = std::memcmp(&pa[i].mTransform.pos_, &pb[i].mTransform.pos_, sizeof(pa[i].mTransform.pos_)) != 0;
          const bool orientation = std::memcmp(&pa[i].mTransform.orient_, &pb[i].mTransform.orient_, sizeof(pa[i].mTransform.orient_)) != 0;
          if (path || position || orientation) {
            char values[200];
            const Wm3::Quatf& qa = pa[i].mTransform.orient_;
            const Wm3::Quatf& qb = pb[i].mTransform.orient_;
            (void)std::snprintf(values, sizeof(values), " (%.9g %.9g %.9g %.9g vs %.9g %.9g %.9g %.9g)", qa.w, qa.x, qa.y, qa.z, qb.w, qb.x, qb.y, qb.z);
            Note(differences, "prop " + std::to_string(i) + (path ? " path" : "") + (position ? " position" : "") + (orientation ? " rotation" : "") +
                                (orientation ? values : ""));
            break;
          }
        }
      }
      if (a.mTerrainRes->GetDecalManager()->GetDecalCount() != b.mTerrainRes->GetDecalManager()->GetDecalCount()) {
        Note(differences, "decal count");
      }
    }
  } // namespace

  RoundTripResult RoundTripMap(EdDocument& document, const std::filesystem::path& folder)
  {
    RoundTripResult result;
    moho::CWldMap* const map = document.Map();
    if (map == nullptr) {
      result.differences = "no map open";
      return result;
    }
    std::error_code ignored;
    std::filesystem::create_directories(folder, ignored);
    std::string name = document.Facts().scenarioPath;
    name = name.substr(name.find_last_of('/') + 1);
    const std::filesystem::path first = folder / (name + ".1.scmap");
    const std::filesystem::path second = folder / (name + ".2.scmap");

    std::string error;
    if (!WriteMapFile(*map, document.FileRecords(), first, error)) {
      result.differences = "save: " + error;
      return result;
    }
    MapFileRecords rereadRecords;
    std::unique_ptr<moho::CWldMap> reread = ReadMapFile(first, document.Lua(), rereadRecords, error);
    if (reread == nullptr) {
      result.differences = "read back: " + error;
      return result;
    }
    CompareMaps(*map, *reread, result.differences);
    // Saving the same map again gives the same bytes. (The re-read map is compared by its data: its terrain
    // isn't drawn, so it has no normal map to write, while the drawn map writes its tiles, as the game's
    // own files have them.)
    if (!WriteMapFile(*map, document.FileRecords(), second, error)) {
      Note(result.differences, "second save: " + error);
      return result;
    }
    const std::vector<char> firstBytes = FileBytes(first);
    result.stable = !firstBytes.empty() && firstBytes == FileBytes(second);
    if (!result.stable) {
      Note(result.differences, "saving it again gave other bytes");
    }
    if (const std::filesystem::path original = document.MapDiskFile(); !original.empty()) {
      result.hasDiskFile = true;
      result.sameAsOriginal = FileBytes(original) == firstBytes;
    }
    result.ok = result.differences.empty();
    if (result.stable) {
      std::filesystem::remove(second, ignored);
    }
    return result;
  }
} // namespace faf::editor
