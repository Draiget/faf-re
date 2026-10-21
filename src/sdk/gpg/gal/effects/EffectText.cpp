// FAF addition, not in the shipped binary: see EffectText.h.

#include "EffectText.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <stdexcept>

namespace gpg::gal::effects::text
{
  std::string Lower(const std::string_view text)
  {
    std::string out(text);
    std::transform(out.begin(), out.end(), out.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
  }

  std::string Trim(const std::string_view text)
  {
    std::size_t begin = 0U;
    std::size_t end = text.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(text[begin])) != 0) {
      ++begin;
    }
    while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1U])) != 0) {
      --end;
    }
    return std::string(text.substr(begin, end - begin));
  }

  std::string Squeeze(const std::string_view text)
  {
    std::string out;
    bool space = false;
    for (const char c : text) {
      if (std::isspace(static_cast<unsigned char>(c)) != 0) {
        space = !out.empty();
        continue;
      }
      if (space) {
        out.push_back(' ');
        space = false;
      }
      out.push_back(c);
    }
    return out;
  }

  bool IsIdentifierChar(const char c) noexcept
  {
    return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
  }

  bool StartsWithWord(const std::string_view text, const std::string_view word) noexcept
  {
    return text.size() >= word.size() && text.compare(0U, word.size(), word) == 0 &&
      (text.size() == word.size() || !IsIdentifierChar(text[word.size()]));
  }

  std::size_t Matching(const std::string_view text, const std::size_t open)
  {
    const char opener = text[open];
    const char closer = (opener == '{') ? '}' : (opener == '(') ? ')' : (opener == '[') ? ']' : '>';
    int depth = 0;
    bool quoted = false;
    for (std::size_t index = open; index < text.size(); ++index) {
      const char c = text[index];
      if (c == '"') {
        quoted = !quoted;
        continue;
      }
      if (quoted) {
        continue;
      }
      if (c == opener) {
        ++depth;
      } else if (c == closer && --depth == 0) {
        return index;
      }
    }
    return std::string_view::npos;
  }

  std::vector<std::string> SplitTopLevel(const std::string_view text, const char separator)
  {
    std::vector<std::string> parts;
    int depth = 0;
    bool quoted = false;
    std::size_t start = 0U;
    for (std::size_t index = 0U; index < text.size(); ++index) {
      const char c = text[index];
      if (c == '"') {
        quoted = !quoted;
      } else if (quoted) {
        continue;
      } else if (c == '(' || c == '{' || c == '[') {
        ++depth;
      } else if (c == ')' || c == '}' || c == ']') {
        --depth;
      } else if (c == separator && depth == 0) {
        parts.emplace_back(text.substr(start, index - start));
        start = index + 1U;
      }
    }
    parts.emplace_back(text.substr(start));
    return parts;
  }

  std::vector<float> ParseNumbers(const std::string_view text)
  {
    std::vector<float> numbers;
    std::size_t index = 0U;
    while (index < text.size()) {
      const char c = text[index];
      const bool signedNumber = (c == '-' || c == '+') && index + 1U < text.size() &&
        [&] {
          std::size_t next = index + 1U;
          while (next < text.size() && text[next] == ' ') {
            ++next;
          }
          return next < text.size() && (std::isdigit(static_cast<unsigned char>(text[next])) != 0 || text[next] == '.');
        }();
      if (std::isdigit(static_cast<unsigned char>(c)) != 0 || (c == '.' && index + 1U < text.size() &&
                                                               std::isdigit(static_cast<unsigned char>(text[index + 1U])) != 0) ||
          signedNumber) {
        std::string literal;
        if (c == '-' || c == '+') {
          literal.push_back(c);
          ++index;
          while (index < text.size() && text[index] == ' ') {
            ++index;
          }
        }
        while (index < text.size() &&
               (IsIdentifierChar(text[index]) || text[index] == '.' ||
                ((text[index] == '-' || text[index] == '+') && (text[index - 1U] == 'e' || text[index - 1U] == 'E')))) {
          literal.push_back(text[index]);
          ++index;
        }
        const bool hex = literal.find("0x") != std::string::npos || literal.find("0X") != std::string::npos;
        while (!hex && !literal.empty() &&
               (literal.back() == 'f' || literal.back() == 'F' || literal.back() == 'h' || literal.back() == 'H' ||
                literal.back() == 'u' || literal.back() == 'U' || literal.back() == 'l' || literal.back() == 'L')) {
          literal.pop_back();
        }
        char* end = nullptr;
        const double value = hex ? static_cast<double>(std::strtoll(literal.c_str(), &end, 16)) : std::strtod(literal.c_str(), &end);
        if (end != nullptr && end != literal.c_str()) {
          numbers.push_back(static_cast<float>(value));
        }
        continue;
      }
      if (IsIdentifierChar(c)) {
        std::size_t end = index;
        while (end < text.size() && IsIdentifierChar(text[end])) {
          ++end;
        }
        const std::string_view word = text.substr(index, end - index);
        if (word == "true") {
          numbers.push_back(1.0f);
        } else if (word == "false") {
          numbers.push_back(0.0f);
        }
        index = end; // skips identifiers such as float4 with their digits
        continue;
      }
      ++index;
    }
    return numbers;
  }

  namespace
  {
    class ConstantParser
    {
    public:
      explicit ConstantParser(const std::string_view text)
        : mText(text)
      {}

      bool Parse(double& value)
      {
        value = Or();
        Skip();
        return mOk && mIndex == mText.size();
      }

    private:
      void Skip()
      {
        while (mIndex < mText.size() && std::isspace(static_cast<unsigned char>(mText[mIndex])) != 0) {
          ++mIndex;
        }
      }

      bool Take(const std::string_view op)
      {
        Skip();
        if (mText.substr(mIndex, op.size()) == op) {
          // "<" must not take the first half of "<<" and so on.
          const std::size_t after = mIndex + op.size();
          if (op.size() == 1U && after < mText.size() && (mText[after] == op[0]) && (op[0] == '<' || op[0] == '>' || op[0] == '|' || op[0] == '&')) {
            return false;
          }
          mIndex = after;
          return true;
        }
        return false;
      }

      static long long Int(const double value) { return static_cast<long long>(value); }

      double Or()
      {
        double value = Xor();
        while (Take("|")) {
          value = static_cast<double>(Int(value) | Int(Xor()));
        }
        return value;
      }

      double Xor()
      {
        double value = And();
        while (Take("^")) {
          value = static_cast<double>(Int(value) ^ Int(And()));
        }
        return value;
      }

      double And()
      {
        double value = Shift();
        while (Take("&")) {
          value = static_cast<double>(Int(value) & Int(Shift()));
        }
        return value;
      }

      double Shift()
      {
        double value = Sum();
        for (;;) {
          if (Take("<<")) {
            value = static_cast<double>(Int(value) << Int(Sum()));
          } else if (Take(">>")) {
            value = static_cast<double>(Int(value) >> Int(Sum()));
          } else {
            return value;
          }
        }
      }

      double Sum()
      {
        double value = Product();
        for (;;) {
          if (Take("+")) {
            value += Product();
          } else if (Take("-")) {
            value -= Product();
          } else {
            return value;
          }
        }
      }

      double Product()
      {
        double value = Unary();
        for (;;) {
          if (Take("*")) {
            value *= Unary();
          } else if (Take("/")) {
            const double divisor = Unary();
            value = (divisor != 0.0) ? value / divisor : 0.0;
          } else if (Take("%")) {
            const long long divisor = Int(Unary());
            value = (divisor != 0) ? static_cast<double>(Int(value) % divisor) : 0.0;
          } else {
            return value;
          }
        }
      }

      double Unary()
      {
        if (Take("-")) {
          return -Unary();
        }
        if (Take("+")) {
          return Unary();
        }
        if (Take("~")) {
          return static_cast<double>(~Int(Unary()));
        }
        if (Take("(")) {
          const double value = Or();
          if (!Take(")")) {
            mOk = false;
          }
          return value;
        }
        Skip();
        const std::size_t start = mIndex;
        while (mIndex < mText.size() && (IsIdentifierChar(mText[mIndex]) || mText[mIndex] == '.')) {
          ++mIndex;
        }
        std::string token(mText.substr(start, mIndex - start));
        if (token == "true") {
          return 1.0;
        }
        if (token == "false") {
          return 0.0;
        }
        const bool hex = token.size() > 2U && token[0] == '0' && (token[1] == 'x' || token[1] == 'X');
        while (!hex && !token.empty() && std::isalpha(static_cast<unsigned char>(token.back())) != 0) {
          token.pop_back(); // 1.0f, 2u, 3l
        }
        char* end = nullptr;
        const double value = hex ? static_cast<double>(std::strtoull(token.c_str(), &end, 16)) : std::strtod(token.c_str(), &end);
        if (token.empty() || end == nullptr || *end != '\0') {
          mOk = false;
        }
        return value;
      }

      std::string_view mText;
      std::size_t mIndex = 0;
      bool mOk = true;
    };
  } // namespace

  bool EvaluateConstant(const std::string_view text, double& value)
  {
    ConstantParser parser(text);
    return parser.Parse(value);
  }

  std::string ReplaceIdentifier(const std::string_view text, const std::string_view name, const std::string_view replacement)
  {
    std::string out;
    out.reserve(text.size());
    std::size_t index = 0U;
    while (index < text.size()) {
      const std::size_t found = text.find(name, index);
      if (found == std::string_view::npos) {
        out.append(text.substr(index));
        break;
      }
      const std::size_t after = found + name.size();
      bool whole = (found == 0U || !IsIdentifierChar(text[found - 1U])) && (after >= text.size() || !IsIdentifierChar(text[after]));
      if (whole) {
        // Skip member accesses: "a . name".
        std::size_t before = found;
        while (before > 0U && text[before - 1U] == ' ') {
          --before;
        }
        if (before > 0U && text[before - 1U] == '.') {
          whole = false;
        }
      }
      out.append(text.substr(index, found - index));
      out.append(whole ? replacement : name);
      index = after;
    }
    return out;
  }

  bool ContainsIdentifier(const std::string_view text, const std::string_view name)
  {
    std::size_t index = 0U;
    while ((index = text.find(name, index)) != std::string_view::npos) {
      const std::size_t after = index + name.size();
      if ((index == 0U || !IsIdentifierChar(text[index - 1U])) && (after >= text.size() || !IsIdentifierChar(text[after]))) {
        return true;
      }
      index = after;
    }
    return false;
  }

  bool HasTopLevelAssignment(const std::string_view text)
  {
    int depth = 0;
    bool quoted = false;
    for (std::size_t index = 0U; index < text.size(); ++index) {
      const char c = text[index];
      if (c == '"') {
        quoted = !quoted;
      } else if (quoted) {
        continue;
      } else if (c == '(' || c == '[' || c == '<' || c == '{') {
        ++depth;
      } else if (c == ')' || c == ']' || c == '>' || c == '}') {
        --depth;
      } else if (c == '=' && depth == 0) {
        const char before = (index > 0U) ? text[index - 1U] : '\0';
        const char after = (index + 1U < text.size()) ? text[index + 1U] : '\0';
        if (after != '=' && before != '=' && before != '!' && before != '<' && before != '>') {
          return true;
        }
      }
    }
    return false;
  }

  std::vector<Item> SplitItems(const std::string_view text)
  {
    std::vector<Item> items;
    std::size_t index = 0U;
    std::size_t itemBegin = std::string_view::npos;
    std::string buffer;

    const auto begin = [&](const std::size_t at) {
      if (itemBegin == std::string_view::npos) {
        itemBegin = at;
      }
    };

    while (index < text.size()) {
      const char c = text[index];
      if (std::isspace(static_cast<unsigned char>(c)) != 0) {
        buffer.push_back(c);
        ++index;
        continue;
      }
      if (c == '/' && index + 1U < text.size() && (text[index + 1U] == '/' || text[index + 1U] == '*')) {
        // A comment (the override layer adds a few): whitespace to the parser.
        const bool line = text[index + 1U] == '/';
        const std::size_t close = line ? text.find('\n', index) : text.find("*/", index + 2U);
        index = (close == std::string_view::npos) ? text.size() : close + (line ? 1U : 2U);
        buffer.push_back(' ');
        continue;
      }
      if (c == '#' && itemBegin == std::string_view::npos) {
        // A preprocessor line the override layer left in (its D3D9 math
        // #defines): an item of its own, to the end of the line and any
        // continuation lines, so it never swallows the declaration after it.
        std::size_t stop = index;
        while (true) {
          const std::size_t newline = text.find('\n', stop);
          if (newline == std::string_view::npos) {
            stop = text.size();
            break;
          }
          const std::size_t last = text.find_last_not_of(" \t\r", newline == 0U ? 0U : newline - 1U);
          stop = newline + 1U;
          if (last == std::string_view::npos || last < index || text[last] != '\\') {
            break;
          }
        }
        Item item;
        item.begin = index;
        item.end = stop;
        item.head = Trim(text.substr(index, stop - index));
        item.directive = true;
        items.push_back(std::move(item));
        buffer.clear();
        index = stop;
        continue;
      }
      begin(index);
      if (c == '"') {
        const std::size_t close = text.find('"', index + 1U);
        const std::size_t stop = (close == std::string_view::npos) ? text.size() : close + 1U;
        buffer.append(text.substr(index, stop - index));
        index = stop;
        continue;
      }
      if (c == '<' || c == '(' || c == '[') {
        // Annotation blocks and bracketed spans: their ';' do not end the item.
        // A '<' that is a comparison inside an initializer has no matching '>'
        // before the ';' that ends it, so fall through for it.
        const std::size_t close = Matching(text, index);
        const std::size_t semicolon = text.find(';', index);
        if (close != std::string_view::npos && (c != '<' || !HasTopLevelAssignment(buffer) || close < semicolon)) {
          buffer.append(text.substr(index, close + 1U - index));
          index = close + 1U;
          continue;
        }
      }
      if (c == '{') {
        const std::size_t close = Matching(text, index);
        if (close == std::string_view::npos) {
          throw std::runtime_error("unbalanced braces in effect source");
        }
        Item item;
        item.begin = itemBegin;
        item.head = Squeeze(buffer);
        item.body = std::string(text.substr(index + 1U, close - index - 1U));
        item.braced = true;
        index = close + 1U;
        // A struct, state object or initializer list ends with ';' (perhaps
        // after more declarator text); a function or technique body does not.
        std::size_t next = index;
        while (next < text.size() && std::isspace(static_cast<unsigned char>(text[next])) != 0) {
          ++next;
        }
        if (next < text.size() && text[next] == ';') {
          index = next + 1U;
        } else if (HasTopLevelAssignment(item.head) || StartsWithWord(item.head, "struct")) {
          const std::size_t semicolon = text.find(';', index);
          index = (semicolon == std::string_view::npos) ? text.size() : semicolon + 1U;
        }
        item.end = index;
        items.push_back(std::move(item));
        buffer.clear();
        itemBegin = std::string_view::npos;
        continue;
      }
      if (c == ';') {
        Item item;
        item.begin = itemBegin;
        item.head = Squeeze(buffer);
        item.end = index + 1U;
        if (!item.head.empty()) {
          items.push_back(std::move(item));
        }
        buffer.clear();
        itemBegin = std::string_view::npos;
        ++index;
        continue;
      }
      buffer.push_back(c);
      ++index;
    }
    return items;
  }
} // namespace gpg::gal::effects::text
