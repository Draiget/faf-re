// Engine addition, server mode (plan WPL.4, WPR.11): see ReplayTerrainCheck.h.

#include "replay/ReplayTerrainCheck.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>

#include "gpg/core/containers/String.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/Stream.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"

namespace faf::replay
{
  namespace
  {
    constexpr std::uint32_t kWorldMapFileMagic = 0x1A70614DU; // CWldMap::MapLoad's
    constexpr std::uint32_t kWorldMapFileVersion = 2U;

    /// What one load of a map produced, for comparison.
    struct SLoadedMap
    {
      bool loaded = false;
      std::string error;
      std::uint64_t terrainEnd = 0; // stream position after the terrain payload
      std::uint64_t propsEnd = 0;
      std::uint32_t width = 0;
      std::uint32_t height = 0;
      std::string heights;      // heightfield samples
      std::string terrainTypes; // terrain-type grid
      std::string water;        // enabled + three elevations
      std::string props;        // every prop's blueprint path and transform
    };

    void AppendBytes(std::string& out, const void* const data, const std::size_t size)
    {
      out.append(static_cast<const char*>(data), size);
    }

    /**
     * CWldMap::MapLoad's reads (magic, version, preview chunk, terrain, props) into the
     * terrain resource `terrainRes` takes; the preview is read without its texture.
     */
    SLoadedMap LoadMap(const std::string& path, moho::IWldTerrainRes* const terrainRes)
    {
      SLoadedMap result{};
      std::unique_ptr<moho::IWldTerrainRes> owner(terrainRes);
      if (terrainRes == nullptr) {
        result.error = "no terrain resource";
        return result;
      }

      msvc8::auto_ptr<gpg::Stream> stream = moho::DISK_OpenFileRead(path.c_str());
      if (!stream.get()) {
        result.error = "cannot open";
        return result;
      }
      gpg::BinaryReader reader(stream.get());
      moho::CBackgroundTaskControl loadControl{};

      std::uint32_t fileMagic = 0;
      std::uint32_t fileVersion = 0;
      reader.ReadExact(fileMagic);
      reader.ReadExact(fileVersion);
      if (fileMagic != kWorldMapFileMagic || fileVersion != kWorldMapFileVersion) {
        result.error = "not a map";
        return result;
      }

      {
        const moho::PreviewTextureLoadHook previewTextureLoad = moho::sPreviewTextureLoad;
        moho::sPreviewTextureLoad = nullptr;
        moho::RWldMapPreviewChunk preview{};
        const bool previewLoaded = preview.Load(reader, loadControl);
        moho::sPreviewTextureLoad = previewTextureLoad;
        if (!previewLoaded) {
          result.error = "preview";
          return result;
        }
      }

      if (!terrainRes->Load(reader, nullptr, loadControl)) {
        result.error = "terrain";
        return result;
      }
      result.terrainEnd = stream->VirtTell(gpg::Stream::ModeReceive);

      const moho::STIMap* const map = terrainRes->mMap;
      const moho::CHeightField* const field = map->mHeightField.get();
      result.width = static_cast<std::uint32_t>(field->width);
      result.height = static_cast<std::uint32_t>(field->height);
      AppendBytes(result.heights, field->data, static_cast<std::size_t>(2 * field->width * field->height));
      AppendBytes(
        result.terrainTypes,
        map->mTerrainType.data,
        static_cast<std::size_t>(map->mTerrainType.width * map->mTerrainType.height)
      );
      AppendBytes(result.water, &map->mWaterEnabled, sizeof(map->mWaterEnabled));
      AppendBytes(result.water, &map->mWaterElevation, sizeof(map->mWaterElevation));
      AppendBytes(result.water, &map->mWaterElevationDeep, sizeof(map->mWaterElevationDeep));
      AppendBytes(result.water, &map->mWaterElevationAbyss, sizeof(map->mWaterElevationAbyss));

      std::unique_ptr<moho::CWldProps> props(moho::WLD_CreateProps());
      if (props == nullptr || !props->Load(reader, loadControl)) {
        result.error = "props";
        return result;
      }
      result.propsEnd = stream->VirtTell(gpg::Stream::ModeReceive);
      for (const moho::CWldPropEntry& entry : props->mEntries) {
        result.props.append(entry.mBlueprintPath.c_str());
        result.props.push_back('\0');
        AppendBytes(result.props, &entry.mTransform, sizeof(entry.mTransform));
      }

      result.loaded = true;
      return result;
    }
  } // namespace

  STerrainCheckResult RunTerrainCheck(const std::string& listPath)
  {
    STerrainCheckResult result{};
    if (moho::sTerrainResFactory == nullptr) {
      result.error = "this build has no client terrain resource to compare with (run faf-replay-full)";
      return result;
    }
    std::ifstream list(listPath);
    if (!list) {
      result.error = "cannot read " + listPath;
      return result;
    }
    result.ran = true;

    std::ostringstream report;
    std::string path;
    while (std::getline(list, path)) {
      while (!path.empty() && (path.back() == '\r' || path.back() == ' ')) {
        path.pop_back();
      }
      if (path.empty()) {
        continue;
      }
      ++result.maps;

      const SLoadedMap client =
        LoadMap(path, moho::sTerrainResFactory != nullptr ? moho::sTerrainResFactory() : nullptr);
      const SLoadedMap headless = LoadMap(path, moho::WLD_CreateHeadlessTerrainRes());

      std::string verdict;
      if (!client.loaded || !headless.loaded) {
        verdict = "LOADFAIL client=" + (client.loaded ? std::string("ok") : client.error) +
                  " headless=" + (headless.loaded ? std::string("ok") : headless.error);
        if (client.loaded != headless.loaded || client.error != headless.error) {
          ++result.differences;
        }
      } else {
        std::string diffs;
        if (client.terrainEnd != headless.terrainEnd) diffs += " terrain-end";
        if (client.propsEnd != headless.propsEnd) diffs += " props-end";
        if (client.width != headless.width || client.height != headless.height) diffs += " size";
        if (client.heights != headless.heights) diffs += " heights";
        if (client.terrainTypes != headless.terrainTypes) diffs += " terrain-types";
        if (client.water != headless.water) diffs += " water";
        if (client.props != headless.props) diffs += " props";
        if (diffs.empty()) {
          verdict = "same";
        } else {
          verdict = "DIFF" + diffs;
          ++result.differences;
        }
      }

      char sizes[96];
      std::snprintf(
        sizes,
        sizeof(sizes),
        " %ux%u terrain-end=%llu/%llu",
        client.width,
        client.height,
        static_cast<unsigned long long>(client.terrainEnd),
        static_cast<unsigned long long>(headless.terrainEnd)
      );
      report << "TERRAINCHECK " << verdict << sizes << " " << path << "\n";
    }

    report << "TERRAINCHECK maps=" << result.maps << " differences=" << result.differences;
    result.report = report.str();
    return result;
  }
} // namespace faf::replay
