#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "editor/doc/EdPackage.h"

namespace faf::editor
{
  /** Where the FAF vault serves its map archives (public; the FAF client downloads from here too). */
  constexpr const char kVaultMapUrl[] = "https://content.faforever.com/maps/";

  /** A vault map named by its folder (`dualgap_adaptive.v0012`) and where its archive downloads from. */
  struct VaultMapName
  {
    std::string folder;
    std::string url;
  };

  /**
   * A map named as a user would paste it: its folder name (`dualgap_adaptive.v0012`, with or without `.zip`), or the
   * archive's link (`https://content.faforever.com/maps/dualgap_adaptive.v0012.zip`). False with `error` otherwise.
   */
  bool ParseVaultMapName(const std::string& text, VaultMapName& out, std::string& error);

  /** The entries of a zip archive in memory (stored or deflated; sizes from the central directory). */
  bool ReadZip(const std::string& zip, std::vector<ZipEntry>& entries, std::string& error);

  /**
   * Where a zip entry goes inside the map's folder: its path below the archive's top folder, which must be `folder`
   * (case aside). Empty for a folder entry, or for one that would leave the folder (`..`, a drive, an absolute path).
   */
  std::string MapEntryPath(const std::string& entry, const std::string& folder);

  /**
   * A map archive's files written into `mapsFolder/<folder>/`; false with `error` when the archive isn't that map's
   * (no `_scenario.lua`, an entry outside its folder) or a file can't be written.
   */
  bool InstallMapZip(const std::string& zip, const std::string& folder, const std::filesystem::path& mapsFolder, std::string& error);

  /** One map download from the vault, on its own thread: download, then install into the vault's maps folder. */
  class EdVaultDownload
  {
  public:
    enum class State
    {
      Idle,
      Working,
      Done,
      Failed,
    };

    ~EdVaultDownload();
    /** Starts it; false while another runs. */
    bool Start(const VaultMapName& map, const std::filesystem::path& mapsFolder);
    [[nodiscard]] State GetState() const noexcept { return mState.load(); }
    /** What it is doing, or why it failed. */
    [[nodiscard]] std::string Message() const;
    /** The map installed: its folder name and where it is on disk. */
    [[nodiscard]] const VaultMapName& Map() const noexcept { return mMap; }
    [[nodiscard]] std::filesystem::path Folder() const { return mMapsFolder / mMap.folder; }
    /** Bytes received so far. */
    [[nodiscard]] std::uint64_t Received() const noexcept { return mReceived.load(); }
    /** The archive's size as the vault announced it, 0 until known. */
    [[nodiscard]] std::uint64_t Total() const noexcept { return mTotal.load(); }
    /** Back to Idle once the caller has taken the result. */
    void Reset();

  private:
    void Run();
    void SetMessage(std::string message);

    std::thread mThread;
    std::atomic<State> mState{State::Idle};
    std::atomic<std::uint64_t> mReceived{0};
    std::atomic<std::uint64_t> mTotal{0};
    mutable std::mutex mLock;
    std::string mMessage;
    VaultMapName mMap;
    std::filesystem::path mMapsFolder;
  };
} // namespace faf::editor
