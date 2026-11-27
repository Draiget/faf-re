#include "editor/doc/EdVault.h"
#include "editor/EdPath.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>

#include "platform/Http.h"

#include "zlib.h"

namespace faf::editor
{
  namespace
  {
    std::string Lower(
      std::string text
    )
    {
      for (char& c : text) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      return text;
    }

    /** `url` (https) into `body`; false with `error`. `received` follows the bytes as they come. */
    std::expected<void, std::string> HttpGet(
      const std::string& url,
      std::string& body,
      std::atomic<std::uint64_t>& received,
      std::atomic<std::uint64_t>& total
    )
    {
      platform::http::Call call;
      call.url = url;
      long status = 0;
      if (const auto sent = platform::http::Request(call, status, body, &received, &total); !sent) {
        return std::unexpected(sent.error());
      }
      if (status != 200) {
        return std::unexpected(
          status == 404 ? "the vault has no map by that name" : "the vault answered " + std::to_string(status)
        );
      }
      return {};
    }
  } // namespace

  std::expected<VaultMapName, std::string> ParseVaultMapName(
    const std::string& text
  )
  {
    std::string name = text;
    while (!name.empty() && std::isspace(static_cast<unsigned char>(name.back())) != 0) {
      name.pop_back();
    }
    name.erase(0, (std::min)(name.size(), name.find_first_not_of(" \t")));
    // A link: the last part of its path.
    if (const std::size_t slash = name.find_last_of('/'); slash != std::string::npos) {
      name = name.substr(slash + 1);
    }
    if (const std::size_t query = name.find_first_of("?#"); query != std::string::npos) {
      name.resize(query);
    }
    if (name.size() > 4 && Lower(name.substr(name.size() - 4)) == ".zip") {
      name.resize(name.size() - 4);
    }
    // The vault's folder names: letters, digits and _ . - (spaces and quotes are written as %20 and the like).
    std::string decoded;
    for (std::size_t i = 0; i < name.size(); ++i) {
      if (
        name[i] == '%' && i + 2 < name.size() && std::isxdigit(static_cast<unsigned char>(name[i + 1])) != 0 &&
        std::isxdigit(static_cast<unsigned char>(name[i + 2])) != 0
      ) {
        decoded += static_cast<char>(std::stoi(name.substr(i + 1, 2), nullptr, 16));
        i += 2;
      } else {
        decoded += name[i];
      }
    }
    name = decoded;
    if (name.empty() || name == "." || name == ".." || std::any_of(name.begin(), name.end(), [](const char c) {
      return c == '\\' || c == ':' || static_cast<unsigned char>(c) < 32;
    })) {
      return std::unexpected("give a vault map's folder name (dualgap_adaptive.v0012) or its download link");
    }
    if (!name.contains(".v")) {
      return std::unexpected("a vault map's name ends in its version, as dualgap_adaptive.v0012");
    }
    VaultMapName out;
    out.folder = Lower(name);
    std::string encoded;
    for (const char c : out.folder) {
      if (std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_' || c == '.' || c == '-') {
        encoded += c;
      } else {
        char hex[4];
        (void)std::snprintf(hex, sizeof(hex), "%%%02X", static_cast<unsigned char>(c));
        encoded += hex;
      }
    }
    out.url = std::string(kVaultMapUrl) + encoded + ".zip";
    return out;
  }

  std::string MapEntryPath(
    const std::string& entry,
    const std::string& folder
  )
  {
    std::string path = entry;
    std::replace(path.begin(), path.end(), '\\', '/');
    const std::size_t slash = path.find('/');
    if (slash == std::string::npos || Lower(path.substr(0, slash)) != Lower(folder)) {
      return {};
    }
    std::string rest = path.substr(slash + 1);
    if (rest.empty() || rest.back() == '/' || rest.front() == '/' || rest.contains(':')) {
      return {};
    }
    std::size_t at = 0;
    while (at <= rest.size()) {
      const std::size_t next = rest.find('/', at);
      const std::string part = rest.substr(at, next == std::string::npos ? std::string::npos : next - at);
      if (part.empty() || part == "." || part == "..") {
        return {};
      }
      if (next == std::string::npos) {
        break;
      }
      at = next + 1;
    }
    return rest;
  }

  std::expected<void, std::string> InstallMapZip(
    const std::string& zip,
    const std::string& folder,
    const std::filesystem::path& mapsFolder
  )
  {
    const auto read = ReadZip(zip);
    if (!read) {
      return std::unexpected(read.error());
    }
    const std::vector<ZipEntry>& entries = *read;
    bool scenario = false;
    std::vector<std::pair<std::string, const ZipEntry*>> files;
    for (const ZipEntry& entry : entries) {
      if (!entry.name.empty() && entry.name.back() == '/') {
        continue; // a folder
      }
      const std::string path = MapEntryPath(entry.name, folder);
      if (path.empty()) {
        return std::unexpected("the archive holds " + entry.name + ", outside the map's folder " + folder);
      }
      scenario = scenario ||
        (!path.contains('/') && Lower(path).size() > 13 &&
         Lower(path).compare(path.size() - 13, 13, "_scenario.lua") == 0);
      files.emplace_back(path, &entry);
    }
    if (!scenario) {
      return std::unexpected("the archive has no _scenario.lua in " + folder);
    }
    const std::filesystem::path target = mapsFolder / PathFromUtf8(folder);
    std::error_code code;
    for (const auto& [path, entry] : files) {
      const std::filesystem::path file = target / PathFromUtf8(path);
      std::filesystem::create_directories(file.parent_path(), code);
      std::ofstream out(file, std::ios::binary | std::ios::trunc);
      out.write(entry->data.data(), static_cast<std::streamsize>(entry->data.size()));
      if (!out) {
        return std::unexpected("couldn't write " + file.string());
      }
    }
    return {};
  }

  EdVaultDownload::~EdVaultDownload()
  {
    if (mThread.joinable()) {
      mThread.join();
    }
  }

  bool EdVaultDownload::Start(
    const VaultMapName& map,
    const std::filesystem::path& mapsFolder
  )
  {
    if (mState.load() == State::Working) {
      return false;
    }
    if (mThread.joinable()) {
      mThread.join();
    }
    mMap = map;
    mMapsFolder = mapsFolder;
    mReceived = 0;
    mTotal = 0;
    SetMessage("Downloading " + map.folder);
    mState = State::Working;
    mThread = std::thread([this] {
      Run();
    });
    return true;
  }

  void EdVaultDownload::Run()
  {
    std::string zip;
    if (const auto got = HttpGet(mMap.url, zip, mReceived, mTotal); !got) {
      SetMessage(got.error());
      mState = State::Failed;
      return;
    }
    SetMessage("Unpacking " + mMap.folder);
    if (const auto installed = InstallMapZip(zip, mMap.folder, mMapsFolder); !installed) {
      SetMessage(installed.error());
      mState = State::Failed;
      return;
    }
    SetMessage("Installed " + mMap.folder + " (" + std::to_string(zip.size() / 1024) + " KB)");
    mState = State::Done;
  }

  std::string EdVaultDownload::Message() const
  {
    std::lock_guard<std::mutex> lock(mLock);
    return mMessage;
  }

  void EdVaultDownload::SetMessage(
    std::string message
  )
  {
    std::lock_guard<std::mutex> lock(mLock);
    mMessage = std::move(message);
  }

  void EdVaultDownload::Reset()
  {
    if (mState.load() != State::Working) {
      mState = State::Idle;
    }
  }
} // namespace faf::editor
