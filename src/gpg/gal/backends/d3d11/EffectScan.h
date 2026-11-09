#pragma once

// Engine addition, not in the shipped binary. Plain scans over an effect's whole text, in place of
// std::regex searches that took about half of the time from process start to the lobby. Each one
// finds what the pattern above it finds, in the same order; tests/effect_scan checks that against
// std::regex on generated text. None of these patterns can backtrack into a different answer, so
// no backtracking is needed here.

#include <cstddef>
#include <initializer_list>
#include <string>
#include <string_view>

namespace gpg::gal::d3d11::scan
{
  [[nodiscard]] constexpr bool IsWord(const char c) noexcept
  {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
  }

  [[nodiscard]] constexpr bool IsSpace(const char c) noexcept
  {
    return c == ' ' || (c >= '\t' && c <= '\r');
  }

  [[nodiscard]] inline std::size_t SkipSpace(const std::string_view text, std::size_t at) noexcept
  {
    while (at < text.size() && IsSpace(text[at])) {
      ++at;
    }
    return at;
  }

  [[nodiscard]] inline std::size_t SkipWord(const std::string_view text, std::size_t at) noexcept
  {
    while (at < text.size() && IsWord(text[at])) {
      ++at;
    }
    return at;
  }

  /** `\b(keyword)\s+(\w+)`, where `tail` may go on from the name's end. Returns the match's end, or npos. */
  template <typename Tail>
  [[nodiscard]] std::size_t MatchKeywordName(
    const std::string_view text, const std::size_t at, const std::string_view keyword, std::string_view& name, Tail&& tail
  )
  {
    const std::size_t afterKeyword = at + keyword.size();
    const std::size_t nameBegin = SkipSpace(text, afterKeyword);
    if (nameBegin == afterKeyword) {
      return std::string_view::npos;
    }
    const std::size_t nameEnd = SkipWord(text, nameBegin);
    if (nameEnd == nameBegin) {
      return std::string_view::npos;
    }
    name = text.substr(nameBegin, nameEnd - nameBegin);
    return tail(nameEnd);
  }

  /** Calls `visit(position)` for each `\bkeyword` from `from` on and goes on where it says, or stops at npos. */
  template <typename Visit>
  void ForEachKeyword(const std::string_view text, const std::string_view keyword, const std::size_t from, Visit&& visit)
  {
    std::size_t at = text.find(keyword, from);
    while (at != std::string_view::npos) {
      std::size_t next = at + 1U;
      if (at == from || !IsWord(text[at - 1U])) {
        next = visit(at);
        if (next == std::string_view::npos) {
          return;
        }
      }
      at = text.find(keyword, next);
    }
  }

  /** `\bstruct\s+(\w+)`: `visit(name)`. */
  template <typename Visit>
  void ForEachStructName(const std::string_view text, Visit&& visit)
  {
    ForEachKeyword(text, "struct", 0U, [&](const std::size_t at) {
      std::string_view name;
      const std::size_t end = MatchKeywordName(text, at, "struct", name, [](const std::size_t nameEnd) { return nameEnd; });
      if (end == std::string_view::npos) {
        return at + 1U;
      }
      visit(name);
      return end;
    });
  }

  /** `\bstruct\s+(\w+)\s*\{`: `visit(name, position of the brace)`. */
  template <typename Visit>
  void ForEachStructHead(const std::string_view text, Visit&& visit)
  {
    ForEachKeyword(text, "struct", 0U, [&](const std::size_t at) {
      std::string_view name;
      const std::size_t end = MatchKeywordName(text, at, "struct", name, [&](const std::size_t nameEnd) {
        const std::size_t open = SkipSpace(text, nameEnd);
        return open < text.size() && text[open] == '{' ? open + 1U : std::string_view::npos;
      });
      if (end == std::string_view::npos) {
        return at + 1U;
      }
      visit(name, end - 1U);
      return end;
    });
  }

  /** `technique1[01]` at `at`. */
  [[nodiscard]] inline bool IsTechniqueKeyword(const std::string_view text, const std::size_t at) noexcept
  {
    return at + 11U <= text.size() && (text[at + 10U] == '0' || text[at + 10U] == '1');
  }

  /** `\btechnique1[01]\s+(\w+)`: `visit(name)`. */
  template <typename Visit>
  void ForEachTechniqueName(const std::string_view text, Visit&& visit)
  {
    ForEachKeyword(text, "technique1", 0U, [&](const std::size_t at) {
      if (!IsTechniqueKeyword(text, at)) {
        return at + 1U;
      }
      std::string_view name;
      const std::size_t end = MatchKeywordName(text, at, "technique10", name, [](const std::size_t nameEnd) { return nameEnd; });
      if (end == std::string_view::npos) {
        return at + 1U;
      }
      visit(name);
      return end;
    });
  }

  /** `(\btechnique1[01]\s+)faf_NAME\b` replaced by `$1NAME`, everywhere. */
  [[nodiscard]] inline std::string RestoreRenamedTechnique(const std::string_view text, const std::string_view name)
  {
    const std::string renamed = "faf_" + std::string(name);
    std::string result;
    result.reserve(text.size());
    std::size_t copied = 0U;
    ForEachKeyword(text, "technique1", 0U, [&](const std::size_t at) {
      if (!IsTechniqueKeyword(text, at)) {
        return at + 1U;
      }
      const std::size_t afterKeyword = at + 11U;
      const std::size_t nameBegin = SkipSpace(text, afterKeyword);
      if (nameBegin == afterKeyword || text.compare(nameBegin, renamed.size(), renamed) != 0) {
        return at + 1U;
      }
      const std::size_t nameEnd = nameBegin + renamed.size();
      if (nameEnd < text.size() && IsWord(text[nameEnd])) {
        return at + 1U;
      }
      result.append(text, copied, nameBegin - copied);
      result.append(name);
      copied = nameEnd;
      return nameEnd;
    });
    result.append(text, copied, std::string_view::npos);
    return result;
  }

  /** `\btechnique1[01]\s+(\w+)\s*(<(?:[^>"]|"[^"]*")*>)?\s*\{` from `from`, which counts as a word boundary. */
  [[nodiscard]] inline bool FindTechniqueHead(
    const std::string_view text, const std::size_t from, std::size_t& start, std::size_t& open, std::string_view& name
  )
  {
    bool found = false;
    ForEachKeyword(text, "technique1", from, [&](const std::size_t at) -> std::size_t {
      if (!IsTechniqueKeyword(text, at)) {
        return at + 1U;
      }
      const std::size_t end = MatchKeywordName(text, at, "technique10", name, [&](const std::size_t nameEnd) {
        std::size_t cursor = SkipSpace(text, nameEnd);
        if (cursor < text.size() && text[cursor] == '<') {
          ++cursor;
          while (cursor < text.size() && text[cursor] != '>') {
            if (text[cursor] == '"') {
              cursor = text.find('"', cursor + 1U);
              if (cursor == std::string_view::npos) {
                return std::string_view::npos;
              }
            }
            ++cursor;
          }
          if (cursor >= text.size()) {
            return std::string_view::npos;
          }
          ++cursor;
        }
        cursor = SkipSpace(text, cursor);
        return cursor < text.size() && text[cursor] == '{' ? cursor + 1U : std::string_view::npos;
      });
      if (end == std::string_view::npos) {
        return at + 1U;
      }
      start = at;
      open = end - 1U;
      found = true;
      return std::string_view::npos;
    });
    return found;
  }

  /** `\b(BlendState|DepthStencilState|RasterizerState)\s+(\w+)\s*\{`: `visit(kind, name, position of the brace)`. */
  template <typename Visit>
  void ForEachStateDeclaration(const std::string_view text, Visit&& visit)
  {
    // Every kind ends in "State", which is rarer in effect text than any of their first letters.
    std::size_t searchFrom = 0U;
    std::size_t state = text.find("State");
    while (state != std::string_view::npos) {
      std::string_view kind;
      for (const std::string_view candidate : {std::string_view("BlendState"), std::string_view("DepthStencilState"), std::string_view("RasterizerState")}) {
        const std::size_t prefix = candidate.size() - 5U;
        if (state >= prefix && text.compare(state - prefix, candidate.size(), candidate) == 0) {
          kind = candidate;
          break;
        }
      }
      std::size_t next = state + 1U;
      if (!kind.empty()) {
        const std::size_t at = state - (kind.size() - 5U);
        if (at >= searchFrom && (at == 0U || !IsWord(text[at - 1U]))) {
          std::string_view name;
          const std::size_t end = MatchKeywordName(text, at, kind, name, [&](const std::size_t nameEnd) {
            const std::size_t open = SkipSpace(text, nameEnd);
            return open < text.size() && text[open] == '{' ? open + 1U : std::string_view::npos;
          });
          if (end != std::string_view::npos) {
            visit(kind, name, end - 1U);
            searchFrom = end;
            next = end;
          }
        }
      }
      state = text.find("State", next);
    }
  }

  /**
   * `(\w+)\s+(\w+)\s*\(([^(){};]*)\)\s*(:\s*(\w+)\s*)?\{`:
   * `visit(return type, name, parameters, semantic, has semantic)`.
   */
  template <typename Visit>
  void ForEachFunctionHead(const std::string_view text, Visit&& visit)
  {
    std::size_t at = 0U;
    while (at < text.size()) {
      if (!IsWord(text[at])) {
        ++at;
        continue;
      }
      const std::size_t typeEnd = SkipWord(text, at);
      const std::size_t nameBegin = SkipSpace(text, typeEnd);
      const std::size_t nameEnd = SkipWord(text, nameBegin);
      if (nameBegin == typeEnd || nameEnd == nameBegin) {
        at = typeEnd;
        continue;
      }
      const std::size_t paren = SkipSpace(text, nameEnd);
      if (paren >= text.size() || text[paren] != '(') {
        at = typeEnd;
        continue;
      }
      const std::size_t close = text.find_first_of("(){};", paren + 1U);
      if (close == std::string_view::npos || text[close] != ')') {
        at = typeEnd;
        continue;
      }
      std::size_t cursor = SkipSpace(text, close + 1U);
      std::string_view semantic;
      bool hasSemantic = false;
      if (cursor < text.size() && text[cursor] == ':') {
        const std::size_t semanticBegin = SkipSpace(text, cursor + 1U);
        const std::size_t semanticEnd = SkipWord(text, semanticBegin);
        if (semanticEnd == semanticBegin) {
          at = typeEnd;
          continue;
        }
        semantic = text.substr(semanticBegin, semanticEnd - semanticBegin);
        hasSemantic = true;
        cursor = SkipSpace(text, semanticEnd);
      }
      if (cursor >= text.size() || text[cursor] != '{') {
        at = typeEnd;
        continue;
      }
      visit(
        text.substr(at, typeEnd - at), text.substr(nameBegin, nameEnd - nameBegin),
        text.substr(paren + 1U, close - paren - 1U), semantic, hasSemantic
      );
      at = cursor + 1U;
    }
  }

  /** Whether `\b\w+\s+FUNCTION\s*\([^;{]*\)\s*(:\s*\w+\s*)?\{` is in `text`. */
  [[nodiscard]] inline bool HasFunctionDefinition(const std::string_view text, const std::string_view function)
  {
    for (std::size_t at = text.find(function); at != std::string_view::npos; at = text.find(function, at + 1U)) {
      if (at == 0U || !IsSpace(text[at - 1U])) {
        continue;
      }
      std::size_t before = at;
      while (before > 0U && IsSpace(text[before - 1U])) {
        --before;
      }
      if (before == 0U || !IsWord(text[before - 1U])) {
        continue;
      }
      const std::size_t paren = SkipSpace(text, at + function.size());
      if (paren >= text.size() || text[paren] != '(') {
        continue;
      }
      // Nothing after the closing parenthesis can be `;` or `{`, so the brace is the first of the two.
      const std::size_t brace = text.find_first_of(";{", paren + 1U);
      if (brace == std::string_view::npos || text[brace] != '{') {
        continue;
      }
      std::size_t cursor = brace;
      while (cursor > paren + 1U && IsSpace(text[cursor - 1U])) {
        --cursor;
      }
      if (cursor > paren + 1U && IsWord(text[cursor - 1U])) {
        while (cursor > paren + 1U && IsWord(text[cursor - 1U])) {
          --cursor;
        }
        while (cursor > paren + 1U && IsSpace(text[cursor - 1U])) {
          --cursor;
        }
        if (cursor <= paren + 1U || text[cursor - 1U] != ':') {
          continue;
        }
        --cursor;
        while (cursor > paren + 1U && IsSpace(text[cursor - 1U])) {
          --cursor;
        }
      }
      if (cursor > paren + 1U && text[cursor - 1U] == ')') {
        return true;
      }
    }
    return false;
  }
} // namespace gpg::gal::d3d11::scan
