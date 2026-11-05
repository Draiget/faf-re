#pragma once

// Joins console tokens, for the command files of both sides.

#include <string>
#include "legacy/containers/String.h"

namespace moho
{
  /**
   * Address: 0x0047BB90 (FUN_0047BB90, func_AppendStrings)
   *
   * What it does:
   * Resets output string, appends first string in `[begin,end)`, then appends
   * `separator` + each subsequent item.
   */
  [[nodiscard]] inline fa::string AppendJoinedStringRange(
    const fa::string* const begin, const fa::string* const end, const char* separator
  )
  {
    std::string joined;
    if (separator == nullptr) {
      separator = "";
    }

    if (begin != nullptr && end != nullptr && begin < end) {
      joined.append(begin->view());
      for (const fa::string* cursor = begin + 1; cursor < end; ++cursor) {
        joined.append(separator);
        joined.append(cursor->view());
      }
    }

    fa::string out;
    out.assign_owned(joined);
    return out;
  }
} // namespace moho
