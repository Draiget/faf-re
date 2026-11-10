#include "editor/doc/EdRecentMaps.h"

#include <algorithm>
#include <cctype>
#include <fstream>

namespace faf::editor
{
  namespace
  {
    bool SameIgnoringCase(const std::string& a, const std::string& b)
    {
      return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](const char x, const char y) {
               return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
             });
    }
  } // namespace

  std::vector<std::string> ReadRecentMaps(const std::string& file)
  {
    std::vector<std::string> list;
    std::ifstream in(file);
    std::string line;
    while (std::getline(in, line)) {
      while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) {
        line.pop_back();
      }
      if (!line.empty() && std::none_of(list.begin(), list.end(), [&](const std::string& known) { return SameIgnoringCase(known, line); })) {
        list.push_back(line);
      }
    }
    if (list.size() > kRecentMapsKept) {
      list.resize(kRecentMapsKept);
    }
    return list;
  }

  std::vector<std::string> WithRecentMap(std::vector<std::string> list, const std::string& scenario, const std::size_t kept)
  {
    list.erase(std::remove_if(list.begin(), list.end(), [&](const std::string& known) { return SameIgnoringCase(known, scenario); }), list.end());
    list.insert(list.begin(), scenario);
    if (list.size() > kept) {
      list.resize(kept);
    }
    return list;
  }

  bool WriteRecentMaps(const std::string& file, const std::vector<std::string>& list)
  {
    std::ofstream out(file, std::ios::trunc);
    for (const std::string& scenario : list) {
      out << scenario << '\n';
    }
    return static_cast<bool>(out);
  }
} // namespace faf::editor
