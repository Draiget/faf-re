#include "editor/doc/EdPackage.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <ctime>
#include <regex>

#include "zlib.h"

namespace faf::editor
{
  namespace
  {
    void Put16(
      std::string& out,
      const std::uint32_t value
    )
    {
      out += static_cast<char>(value & 0xFF);
      out += static_cast<char>((value >> 8) & 0xFF);
    }

    void Put32(
      std::string& out,
      const std::uint32_t value
    )
    {
      Put16(out, value & 0xFFFF);
      Put16(out, value >> 16);
    }

    /** Raw deflate (no zlib header), as zip's method 8 wants; empty when it fails. */
    std::string Deflate(
      const std::string& data
    )
    {
      z_stream stream{};
      if (deflateInit2(&stream, Z_BEST_COMPRESSION, Z_DEFLATED, -MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return {};
      }
      // zlib 1.2.3's deflateBound for any settings, by hand: the x86 build links wx's zlib 1.1.4 (as the game
      // does), which has no deflateBound, so the x86 editor didn't link.
      const std::size_t length = data.size();
      std::string out(length + ((length + 7) >> 3) + ((length + 63) >> 6) + 11 + 16, '\0');
      stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data.data()));
      stream.avail_in = static_cast<uInt>(data.size());
      stream.next_out = reinterpret_cast<Bytef*>(out.data());
      stream.avail_out = static_cast<uInt>(out.size());
      const int result = deflate(&stream, Z_FINISH);
      const std::size_t size = stream.total_out;
      deflateEnd(&stream);
      if (result != Z_STREAM_END) {
        return {};
      }
      out.resize(size);
      return out;
    }

    std::string Lower(
      std::string text
    )
    {
      std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return text;
    }
  } // namespace

  std::string WriteZip(
    const std::vector<ZipEntry>& entries
  )
  {
    // The DOS date and time of now, for every entry.
    const std::time_t now = std::time(nullptr);
    std::tm local{};
    localtime_s(&local, &now);
    const std::uint32_t dosTime =
      static_cast<std::uint32_t>((local.tm_hour << 11) | (local.tm_min << 5) | (local.tm_sec / 2));
    const std::uint32_t dosDate =
      static_cast<std::uint32_t>(((std::max(local.tm_year, 80) - 80) << 9) | ((local.tm_mon + 1) << 5) | local.tm_mday);

    std::string zip;
    std::string central;
    for (const ZipEntry& entry : entries) {
      const std::uint32_t crc = static_cast<std::uint32_t>(crc32(
        crc32(0L, Z_NULL, 0), reinterpret_cast<const Bytef*>(entry.data.data()), static_cast<uInt>(entry.data.size())
      ));
      std::string body = Deflate(entry.data);
      std::uint32_t method = 8;
      if (body.empty() && !entry.data.empty()) {
        method = 0;
        body = entry.data;
      } else if (body.size() >= entry.data.size()) {
        method = 0;
        body = entry.data;
      }
      const std::uint32_t offset = static_cast<std::uint32_t>(zip.size());
      // The local file header.
      Put32(zip, 0x04034B50u);
      Put16(zip, 20);
      Put16(zip, 0);
      Put16(zip, method);
      Put16(zip, dosTime);
      Put16(zip, dosDate);
      Put32(zip, crc);
      Put32(zip, static_cast<std::uint32_t>(body.size()));
      Put32(zip, static_cast<std::uint32_t>(entry.data.size()));
      Put16(zip, static_cast<std::uint32_t>(entry.name.size()));
      Put16(zip, 0);
      zip += entry.name;
      zip += body;
      // Its central directory record.
      Put32(central, 0x02014B50u);
      Put16(central, 20);
      Put16(central, 20);
      Put16(central, 0);
      Put16(central, method);
      Put16(central, dosTime);
      Put16(central, dosDate);
      Put32(central, crc);
      Put32(central, static_cast<std::uint32_t>(body.size()));
      Put32(central, static_cast<std::uint32_t>(entry.data.size()));
      Put16(central, static_cast<std::uint32_t>(entry.name.size()));
      Put16(central, 0);
      Put16(central, 0);
      Put16(central, 0);
      Put16(central, 0);
      Put32(central, 0);
      Put32(central, offset);
      central += entry.name;
    }
    const std::uint32_t centralOffset = static_cast<std::uint32_t>(zip.size());
    zip += central;
    // The end of the central directory.
    Put32(zip, 0x06054B50u);
    Put16(zip, 0);
    Put16(zip, 0);
    Put16(zip, static_cast<std::uint32_t>(entries.size()));
    Put16(zip, static_cast<std::uint32_t>(entries.size()));
    Put32(zip, static_cast<std::uint32_t>(central.size()));
    Put32(zip, centralOffset);
    Put16(zip, 0);
    return zip;
  }

  PackagePlan PlanPackage(
    const std::string& folder,
    const std::string& scenario,
    const std::vector<std::string>& files
  )
  {
    PackagePlan plan;
    plan.folder = folder;
    std::smatch match;
    if (std::regex_match(folder, match, std::regex(R"(([a-z0-9_]+)\.v(\d{4}))"))) {
      plan.version = std::stoi(match[2].str());
    } else {
      plan.errors.push_back(
        "the folder's name \"" + folder + "\" isn't name.vNNNN in lower case (letters, digits and _)"
      );
    }
    // The scenario's own fields.
    const auto field = [&scenario](const char* const key) {
      std::smatch value;
      const std::regex pattern(std::string(R"(\b)") + key + R"(\s*=\s*['"]([^'"]*)['"])");
      return std::regex_search(scenario, value, pattern) ? value[1].str() : std::string();
    };
    std::smatch versionMatch;
    if (std::regex_search(scenario, versionMatch, std::regex(R"(\bmap_version\s*=\s*(\d+))"))) {
      const int version = std::stoi(versionMatch[1].str());
      if (plan.version != 0 && version != plan.version) {
        plan.errors.push_back(
          "the scenario's map_version is " + std::to_string(version) + ", the folder's v" + std::to_string(plan.version)
        );
      }
    } else {
      plan.errors.push_back("the scenario has no map_version");
    }
    if (field("name").empty()) {
      plan.errors.push_back("the scenario has no name");
    }
    if (field("description").empty()) {
      plan.warnings.push_back("the scenario has no description");
    }
    // The files it names: inside /maps/<folder>/, and there.
    std::vector<std::string> lowerFiles;
    for (const std::string& file : files) {
      lowerFiles.push_back(Lower(file));
    }
    const std::string prefix = "/maps/" + Lower(folder) + "/";
    for (const char* const key : {"map", "save", "script"}) {
      const std::string path = field(key);
      if (path.empty()) {
        plan.errors.push_back(std::string("the scenario has no ") + key + " path");
        continue;
      }
      const std::string lower = Lower(path);
      if (lower.rfind(prefix, 0) != 0) {
        plan.errors.push_back(std::string("the scenario's ") + key + " path " + path + " isn't in " + prefix);
        continue;
      }
      if (std::find(lowerFiles.begin(), lowerFiles.end(), lower.substr(prefix.size())) == lowerFiles.end()) {
        plan.errors.push_back(std::string("the scenario's ") + key + " file " + path + " isn't in the folder");
      }
    }
    // What goes in: all but the editor's and the system's own files.
    for (const std::string& file : files) {
      const std::string lower = Lower(file);
      const std::size_t slash = lower.find_last_of('/');
      const std::string name = slash == std::string::npos ? lower : lower.substr(slash + 1);
      if (
        lower.rfind(".editor_backup/", 0) == 0 || lower.find("/.editor_backup/") != std::string::npos ||
        name == "thumbs.db" || name == "desktop.ini" ||
        (name.size() > 4 && name.compare(name.size() - 4, 4, ".bak") == 0) ||
        (name.size() > 7 && name.compare(name.size() - 7, 7, ".editor") == 0) || (!name.empty() && name[0] == '.')
      ) {
        continue;
      }
      plan.files.push_back(file);
    }
    bool hasScenario = false;
    for (const std::string& file : plan.files) {
      hasScenario = hasScenario || Lower(file).find("_scenario.lua") != std::string::npos;
    }
    if (!hasScenario) {
      plan.errors.push_back("the folder has no _scenario.lua");
    }
    return plan;
  }

  int FolderVersion(
    const std::string& folder
  )
  {
    std::smatch match;
    return std::regex_match(folder, match, std::regex(R"(.*\.v(\d{4}))")) ? std::stoi(match[1].str()) : 0;
  }

  std::string WithMapVersion(
    const std::string& scenario,
    const int version
  )
  {
    const std::regex existing(R"(\bmap_version\s*=\s*\d+)");
    if (std::regex_search(scenario, existing)) {
      return std::regex_replace(
        scenario, existing, "map_version = " + std::to_string(version), std::regex_constants::format_first_only
      );
    }
    std::smatch open;
    if (!std::regex_search(scenario, open, std::regex(R"(ScenarioInfo\s*=\s*\{[^\n]*\n)"))) {
      return scenario;
    }
    const std::size_t at = static_cast<std::size_t>(open.position(0) + open.length(0));
    const std::string nl = scenario.find("\r\n") != std::string::npos ? "\r\n" : "\n";
    return scenario.substr(0, at) + "    map_version = " + std::to_string(version) + "," + nl + scenario.substr(at);
  }

  std::vector<std::string> FilesUnder(
    const std::filesystem::path& folder
  )
  {
    std::vector<std::string> files;
    std::error_code error;
    for (auto it = std::filesystem::recursive_directory_iterator(folder, error);
         !error && it != std::filesystem::recursive_directory_iterator();
         it.increment(error)) {
      if (it->is_regular_file(error)) {
        files.push_back(std::filesystem::relative(it->path(), folder, error).generic_string());
      }
    }
    std::sort(files.begin(), files.end());
    return files;
  }
} // namespace faf::editor
