#pragma once

// Engine addition (in-game launcher plan, WP1): URL and form encoding for FAF's login and API requests.

#include <string>
#include <utility>
#include <vector>

namespace faf::online
{
  /** Every byte but letters, digits and `-_.~` as %XX (RFC 3986's unreserved set). */
  [[nodiscard]] std::string UrlEncode(const std::string& text);
  /** An application/x-www-form-urlencoded body: `key=value&key=value`, both encoded. */
  [[nodiscard]] std::string FormBody(const std::vector<std::pair<std::string, std::string>>& fields);
} // namespace faf::online
