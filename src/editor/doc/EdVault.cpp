#include "editor/doc/EdVault.h"
#include "editor/EdPath.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>

#include "editor/doc/EdHttp.h"

#include "zlib.h"

namespace faf::editor
{
  namespace
  {
    std::string Lower(std::string text)
    {
      for (char& c : text) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      return text;
    }

    std::uint32_t Get32(const std::string& data, const std::size_t at)
    {
      std::uint32_t value = 0;
      std::memcpy(&value, data.data() + at, sizeof(value));
      return value;
    }

    std::uint16_t Get16(const std::string& data, const std::size_t at)
    {
      std::uint16_t value = 0;
      std::memcpy(&value, data.data() + at, sizeof(value));
      return value;
    }

    /** `url` (https) into `body`; false with `error`. `received` follows the bytes as they come. */
    bool HttpGet(const std::string& url, std::string& body, std::string& error, std::atomic<std::uint64_t>& received,
                 std::atomic<std::uint64_t>& total)
    {
      HttpCall call;
      call.url = url;
      long status = 0;
      if (!HttpRequest(call, status, body, error, &received, &total)) {
        return false;
      }
      if (status != 200) {
        error = status == 404 ? "the vault has no map by that name" : "the vault answered " + std::to_string(status);
        return false;
      }
      return true;
    }
  } // namespace

  bool ParseVaultMapName(const std::string& text, VaultMapName& out, std::string& error)
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
      if (name[i] == '%' && i + 2 < name.size() && std::isxdigit(static_cast<unsigned char>(name[i + 1])) != 0 &&
          std::isxdigit(static_cast<unsigned char>(name[i + 2])) != 0) {
        decoded += static_cast<char>(std::stoi(name.substr(i + 1, 2), nullptr, 16));
        i += 2;
      } else {
        decoded += name[i];
      }
    }
    name = decoded;
    if (name.empty() || name == "." || name == ".." ||
        std::any_of(name.begin(), name.end(), [](const char c) { return c == '\\' || c == ':' || static_cast<unsigned char>(c) < 32; })) {
      error = "give a vault map's folder name (dualgap_adaptive.v0012) or its download link";
      return false;
    }
    if (name.find(".v") == std::string::npos) {
      error = "a vault map's name ends in its version, as dualgap_adaptive.v0012";
      return false;
    }
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
    return true;
  }

  bool ReadZip(const std::string& zip, std::vector<ZipEntry>& entries, std::string& error)
  {
    // The end of central directory record: its signature within the last 64 KB and 22 bytes.
    std::size_t end = std::string::npos;
    for (std::size_t at = zip.size() >= 22 ? zip.size() - 22 : std::string::npos; at != std::string::npos && zip.size() - at <= 65557; --at) {
      if (Get32(zip, at) == 0x06054B50u) {
        end = at;
        break;
      }
      if (at == 0) {
        break;
      }
    }
    if (end == std::string::npos) {
      error = "not a zip archive";
      return false;
    }
    const std::uint16_t count = Get16(zip, end + 10);
    std::size_t at = Get32(zip, end + 16);
    for (std::uint16_t i = 0; i < count; ++i) {
      if (at + 46 > zip.size() || Get32(zip, at) != 0x02014B50u) {
        error = "the archive's directory is broken";
        return false;
      }
      const std::uint16_t method = Get16(zip, at + 10);
      const std::uint32_t crc = Get32(zip, at + 16);
      const std::uint32_t packed = Get32(zip, at + 20);
      const std::uint32_t size = Get32(zip, at + 24);
      const std::uint16_t nameLength = Get16(zip, at + 28);
      const std::uint16_t extraLength = Get16(zip, at + 30);
      const std::uint16_t commentLength = Get16(zip, at + 32);
      const std::uint32_t local = Get32(zip, at + 42);
      if (at + 46 + nameLength > zip.size()) {
        error = "the archive's directory is broken";
        return false;
      }
      ZipEntry entry;
      entry.name = zip.substr(at + 46, nameLength);
      at += 46 + static_cast<std::size_t>(nameLength) + extraLength + commentLength;
      // The data follows the local header (its name and extra field can differ in length from the directory's).
      if (local + 30 > zip.size() || Get32(zip, local) != 0x04034B50u) {
        error = "the archive's entry " + entry.name + " is broken";
        return false;
      }
      const std::size_t data = local + 30 + Get16(zip, local + 26) + Get16(zip, local + 28);
      if (data + packed > zip.size()) {
        error = "the archive is cut short at " + entry.name;
        return false;
      }
      if (method == 0) {
        entry.data = zip.substr(data, packed);
      } else if (method == 8) {
        entry.data.resize(size);
        z_stream stream{};
        stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(zip.data() + data));
        stream.avail_in = packed;
        stream.next_out = reinterpret_cast<Bytef*>(entry.data.data());
        stream.avail_out = size;
        const bool inflated = inflateInit2(&stream, -MAX_WBITS) == Z_OK && inflate(&stream, Z_FINISH) == Z_STREAM_END && stream.total_out == size;
        inflateEnd(&stream);
        if (!inflated) {
          error = "the archive's entry " + entry.name + " doesn't unpack";
          return false;
        }
      } else {
        error = "the archive's entry " + entry.name + " is packed in a way the editor can't read (method " + std::to_string(method) + ")";
        return false;
      }
      if (crc32(0, reinterpret_cast<const Bytef*>(entry.data.data()), static_cast<uInt>(entry.data.size())) != crc) {
        error = "the archive's entry " + entry.name + " is damaged (its checksum differs)";
        return false;
      }
      entries.push_back(std::move(entry));
    }
    return true;
  }

  std::string MapEntryPath(const std::string& entry, const std::string& folder)
  {
    std::string path = entry;
    std::replace(path.begin(), path.end(), '\\', '/');
    const std::size_t slash = path.find('/');
    if (slash == std::string::npos || Lower(path.substr(0, slash)) != Lower(folder)) {
      return {};
    }
    std::string rest = path.substr(slash + 1);
    if (rest.empty() || rest.back() == '/' || rest.front() == '/' || rest.find(':') != std::string::npos) {
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

  bool InstallMapZip(const std::string& zip, const std::string& folder, const std::filesystem::path& mapsFolder, std::string& error)
  {
    std::vector<ZipEntry> entries;
    if (!ReadZip(zip, entries, error)) {
      return false;
    }
    bool scenario = false;
    std::vector<std::pair<std::string, const ZipEntry*>> files;
    for (const ZipEntry& entry : entries) {
      if (!entry.name.empty() && entry.name.back() == '/') {
        continue; // a folder
      }
      const std::string path = MapEntryPath(entry.name, folder);
      if (path.empty()) {
        error = "the archive holds " + entry.name + ", outside the map's folder " + folder;
        return false;
      }
      scenario = scenario || (path.find('/') == std::string::npos && Lower(path).size() > 13 &&
                              Lower(path).compare(path.size() - 13, 13, "_scenario.lua") == 0);
      files.emplace_back(path, &entry);
    }
    if (!scenario) {
      error = "the archive has no _scenario.lua in " + folder;
      return false;
    }
    const std::filesystem::path target = mapsFolder / PathFromUtf8(folder);
    std::error_code code;
    for (const auto& [path, entry] : files) {
      const std::filesystem::path file = target / PathFromUtf8(path);
      std::filesystem::create_directories(file.parent_path(), code);
      std::ofstream out(file, std::ios::binary | std::ios::trunc);
      out.write(entry->data.data(), static_cast<std::streamsize>(entry->data.size()));
      if (!out) {
        error = "couldn't write " + file.string();
        return false;
      }
    }
    return true;
  }

  EdVaultDownload::~EdVaultDownload()
  {
    if (mThread.joinable()) {
      mThread.join();
    }
  }

  bool EdVaultDownload::Start(const VaultMapName& map, const std::filesystem::path& mapsFolder)
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
    mThread = std::thread([this] { Run(); });
    return true;
  }

  void EdVaultDownload::Run()
  {
    std::string zip;
    std::string error;
    if (!HttpGet(mMap.url, zip, error, mReceived, mTotal)) {
      SetMessage(error);
      mState = State::Failed;
      return;
    }
    SetMessage("Unpacking " + mMap.folder);
    if (!InstallMapZip(zip, mMap.folder, mMapsFolder, error)) {
      SetMessage(error);
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

  void EdVaultDownload::SetMessage(std::string message)
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
