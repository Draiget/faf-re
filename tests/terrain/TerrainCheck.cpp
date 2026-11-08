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
// Usage: faf_terrain_check --maps <list> /init <init.lua> [/log <file>] [gtest flags]
//
// Each map is checked under SCOPED_TRACE(path), and one `TERRAINCHECK same` or
// `TERRAINCHECK DIFF <what>` line per map is printed. Without --maps the test is skipped.
// Exit 0 when every check passes, 1 when one fails, 3 on a fatal engine error.

#include <Windows.h>
#include <objbase.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <memory>
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

    fa::auto_ptr<gpg::Stream> stream = moho::DISK_OpenFileRead(path.c_str());
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

  std::string gMapList; // --maps

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

// Every map in the list, through the client's and the headless terrain resource.
TEST(TerrainCheck, ClientAndHeadlessLoadTheSame)
{
  if (gMapList.empty()) {
    GTEST_SKIP() << "needs --maps <list> /init <init.lua> and the game data";
  }
  ASSERT_NE(moho::sTerrainResFactory, nullptr) << "no client terrain resource linked";
  std::ifstream list(gMapList);
  ASSERT_TRUE(list) << "cannot read " << gMapList;

  int maps = 0;
  int differences = 0;
  std::string path;
  while (std::getline(list, path)) {
    while (!path.empty() && (path.back() == '\r' || path.back() == ' ')) {
      path.pop_back();
    }
    if (path.empty()) {
      continue;
    }
    ++maps;
    SCOPED_TRACE(path);

    const SLoadedMap client = LoadMap(path, moho::sTerrainResFactory());
    const SLoadedMap headless = LoadMap(path, moho::WLD_CreateHeadlessTerrainRes());

    std::string verdict;
    if (!client.loaded || !headless.loaded) {
      // A map neither resource can read is the same result both ways.
      EXPECT_EQ(client.loaded, headless.loaded);
      EXPECT_EQ(client.error, headless.error);
      if (client.loaded != headless.loaded || client.error != headless.error) {
        ++differences;
      }
      verdict = "LOADFAIL client=" + (client.loaded ? std::string("ok") : client.error) +
                " headless=" + (headless.loaded ? std::string("ok") : headless.error);
    } else {
      // The parts compared as bytes, named; gtest would print megabytes of heightfield.
      std::string diffs;
      if (client.terrainEnd != headless.terrainEnd) diffs += " terrain-end";
      if (client.propsEnd != headless.propsEnd) diffs += " props-end";
      if (client.width != headless.width || client.height != headless.height) diffs += " size";
      if (client.heights != headless.heights) diffs += " heights";
      if (client.terrainTypes != headless.terrainTypes) diffs += " terrain-types";
      if (client.water != headless.water) diffs += " water";
      if (client.props != headless.props) diffs += " props";
      EXPECT_EQ(diffs, "") << "parts that differ between the client and the headless load";
      verdict = diffs.empty() ? "same" : "DIFF" + diffs;
      differences += diffs.empty() ? 0 : 1;
    }
    std::printf(
      "TERRAINCHECK %s %ux%u terrain-end=%llu/%llu %s\n",
      verdict.c_str(),
      client.width,
      client.height,
      static_cast<unsigned long long>(client.terrainEnd),
      static_cast<unsigned long long>(headless.terrainEnd),
      path.c_str()
    );
  }
  std::printf("TERRAINCHECK maps=%d differences=%d\n", maps, differences);
  EXPECT_GT(maps, 0) << "the list names no map";
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  ::SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
  gpg::SetDieHandler(&TerrainCheckDieHandler);

  fa::vector<fa::string> mapsArgs;
  if (moho::CFG_GetArgOption("--maps", 1, &mapsArgs) && !mapsArgs.empty()) {
    if (!moho::CFG_GetArgOption("/init", 1, nullptr)) {
      std::printf("usage: faf_terrain_check --maps <list> /init <init.lua> [/log <file>]\n");
      return 2;
    }
    gMapList = mapsArgs[0].c_str();

    // The game's startup up to its data paths, as headless runs it (replay/ReplayMain.cpp).
    moho::APP_InitializeIdentity();
    (void)::CoInitialize(nullptr);
    moho::PLAT_Init();
    static TerrainCheckApp app;
    if (!app.Init()) {
      std::printf("TERRAINCHECK FATAL app init\n");
      EndProcess(kExitFatal);
    }
    platform::SetX87PrecisionControl(_PC_24);
    moho::PlaceCurrentThread(moho::EThreadRole::Main);
  }

  EndProcess(RUN_ALL_TESTS());
}
