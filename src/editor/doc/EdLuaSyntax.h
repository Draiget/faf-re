#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace faf::editor
{
  /** What a piece of Lua text is, for colouring it (the Script Editor). */
  enum class LuaSpanKind
  {
    Plain,
    Keyword,  // and, local, function, if ...
    Constant, // true, false, nil
    String,   // '...', "...", [[...]]
    Comment,  // -- ..., --[[ ... ]], GPG's # ...
    Number,
    Call,     // a name called: Foo( or obj:Foo(
    Engine,   // the game's globals the map scripts use: ScenarioInfo, ScenarioUtils, import, LOG, ForkThread ...
    Operator, // punctuation and operators
  };

  struct LuaSpan
  {
    std::size_t start = 0;
    std::size_t end = 0;
    LuaSpanKind kind = LuaSpanKind::Plain;
  };

  /** The text cut into coloured spans, in order and covering it (a span may run over lines: long comments and strings).
   */
  std::vector<LuaSpan> LuaSpans(const std::string& text);
} // namespace faf::editor
