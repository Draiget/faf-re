// Engine addition (dedicated-server plan WPL.4, WPR.11): the client's and the headless
// terrain resource, compared on real maps.
//
// A map without a client loads into the headless terrain resource
// (moho/sim/WldTerrainResHeadless.cpp), which reads the terrain payload of a `.scmap` without
// the renderer's objects; headless and the game server load maps that way. This program
// links every engine object, so it has the client's CWldTerrainRes too, and loads every map
// named in a list (one `.scmap` path per line) both ways. It compares where the terrain
// payload ends in the stream, the map data the simulation copies (heightfield, terrain-type
// grid, water) and the props read after it.
//
// Usage: faf_terrain_check --maps <list> /init <init.lua> [/log <file>]
//
// Prints one `TERRAINCHECK same` or `TERRAINCHECK DIFF <what>` line per map and
// `TERRAINCHECK maps= differences=`. Exit 0 when nothing differs, 1 when something does,
// 2 on bad arguments, 3 on a fatal error.

#include <Windows.h>
#include <objbase.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>

#include "gpg/core/containers/String.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/Stream.h"
#include "gpg/core/utils/Global.h"
#include "moho/app/IWinApp.h"
#include "moho/app/WinApp.h"
#include "moho/core/ThreadPlacement.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"
#include "platform/X87Precision.h"

namespace
{
  constexpr int kExitSame = 0;
  constexpr int kExitDifferent = 1;
  constexpr int kExitBadInput = 2;
  constexpr int kExitFatal = 3;

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

  struct STerrainCheckResult
  {
    int maps = 0;
    int differences = 0;
    std::string report; // one line per map, then a summary line
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

  /** Every map in `list`, through the client's and the headless terrain resource. */
  STerrainCheckResult RunTerrainCheck(std::ifstream& list)
  {
    STerrainCheckResult result{};
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

      const SLoadedMap client = LoadMap(path, moho::sTerrainResFactory());
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

  [[noreturn]] void EndProcess(const int exitCode)
  {
    std::fflush(stdout);
    std::fflush(stderr);
    // Loader threads may still run; nothing after the verdict is observed.
    ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(exitCode));
    std::_Exit(exitCode);
  }

  void TerrainCheckDieHandler(const char* const message)
  {
    std::printf("TERRAINCHECK FATAL %s\n", message != nullptr ? message : "engine Die()");
    EndProcess(kExitFatal);
  }

  /** The common services every engine app sets up (`IWinApp::AppInitCommonServices`). */
  class TerrainCheckApp final : public moho::IWinApp
  {
  public:
    TerrainCheckApp()
      : moho::IWinApp("SupCom", "SupremeCommander")
    {}

    bool Init() override { return AppInitCommonServices(); }
    void Main() override {}
    void Destroy() override {}
  };
} // namespace

int main()
{
  ::SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
  gpg::SetDieHandler(&TerrainCheckDieHandler);

  msvc8::vector<msvc8::string> mapsArgs;
  if (!moho::CFG_GetArgOption("--maps", 1, &mapsArgs) || mapsArgs.empty() || !moho::CFG_GetArgOption("/init", 1, nullptr)) {
    std::printf("usage: faf_terrain_check --maps <list> /init <init.lua> [/log <file>]\n");
    return kExitBadInput;
  }
  const std::string listPath = mapsArgs[0].c_str();
  std::ifstream list(listPath);
  if (!list) {
    std::printf("TERRAINCHECK error: cannot read %s\n", listPath.c_str());
    return kExitBadInput;
  }
  if (moho::sTerrainResFactory == nullptr) {
    std::printf("TERRAINCHECK error: no client terrain resource linked\n");
    return kExitFatal;
  }

  // The game's startup up to its data paths, as headless runs it (replay/ReplayMain.cpp).
  moho::APP_InitializeIdentity();
  (void)::CoInitialize(nullptr);
  moho::PLAT_Init();
  TerrainCheckApp app;
  if (!app.Init()) {
    std::printf("TERRAINCHECK FATAL app init\n");
    EndProcess(kExitFatal);
  }
  platform::SetX87PrecisionControl(_PC_24);
  moho::PlaceCurrentThread(moho::EThreadRole::Main);

  const STerrainCheckResult check = RunTerrainCheck(list);
  std::printf("%s\n", check.report.c_str());
  EndProcess(check.differences == 0 ? kExitSame : kExitDifferent);
}
