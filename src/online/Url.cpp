// Engine addition (in-game launcher plan, WP1): UrlEncode moved from src/editor/doc/EdHttp.cpp, FormBody from
// src/editor/doc/EdFafApi.cpp (its Form), both unchanged.

#include "online/Url.h"

#include <cctype>
#include <cstdio>

namespace faf::online
{
  std::string UrlEncode(
    const std::string& text
  )
  {
    std::string out;
    for (const char c : text) {
      if (std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '-' || c == '_' || c == '.' || c == '~') {
        out += c;
      } else {
        char hex[4];
        (void)std::snprintf(hex, sizeof(hex), "%%%02X", static_cast<unsigned char>(c));
        out += hex;
      }
    }
    return out;
  }

  std::string FormBody(
    const std::vector<std::pair<std::string, std::string>>& fields
  )
  {
    std::string out;
    for (const auto& [key, value] : fields) {
      out += (out.empty() ? "" : "&") + UrlEncode(key) + "=" + UrlEncode(value);
    }
    return out;
  }
} // namespace faf::online
