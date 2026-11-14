// The debugger's rules (EdLuaDebugger.h) apart from the Lua hook, so tests reach them without the engine.

#include <algorithm>
#include <cctype>

#include "editor/EdLuaDebugger.h"

namespace faf::editor
{
  bool SourceIsFile(
    std::string_view source,
    std::string_view file
  )
  {
    if (file.empty() || source.size() < file.size()) {
      return false;
    }
    const std::string_view tail = source.substr(source.size() - file.size());
    for (std::size_t i = 0; i < file.size(); ++i) {
      if (std::tolower(static_cast<unsigned char>(tail[i])) != std::tolower(static_cast<unsigned char>(file[i]))) {
        return false;
      }
    }
    // The whole name: what comes before is a folder's slash or the source's start.
    if (source.size() == file.size()) {
      return true;
    }
    const char before = source[source.size() - file.size() - 1];
    return before == '/' || before == '\\' || before == '@';
  }

  bool ShouldPause(
    const EdStepMode mode,
    const int depth,
    const int stepDepth,
    const bool atBreakpoint
  )
  {
    switch (mode) {
    case EdStepMode::Into:
      return true;
    case EdStepMode::Over:
      return depth <= stepDepth || atBreakpoint;
    case EdStepMode::Out:
      return depth < stepDepth || atBreakpoint;
    case EdStepMode::Run:
    default:
      return atBreakpoint;
    }
  }
} // namespace faf::editor
