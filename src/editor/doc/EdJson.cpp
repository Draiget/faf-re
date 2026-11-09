#include "editor/doc/EdJson.h"

#include <cstdio>
#include <cstdlib>

namespace faf::editor
{
  namespace
  {
    const char* const kAxes[4] = {"x", "y", "z", "w"};
  } // namespace

  bool JsonValue(const std::string& text, const std::string& key, std::string& out)
  {
    const std::string needle = "\"" + key + "\"";
    std::size_t at = text.find(needle);
    if (at == std::string::npos) {
      return false;
    }
    at = text.find(':', at + needle.size());
    if (at == std::string::npos) {
      return false;
    }
    ++at;
    while (at < text.size() && (text[at] == ' ' || text[at] == '\t' || text[at] == '\r' || text[at] == '\n')) {
      ++at;
    }
    if (at >= text.size()) {
      return false;
    }
    const char first = text[at];
    if (first == '"') {
      std::string value;
      for (std::size_t i = at + 1; i < text.size(); ++i) {
        if (text[i] == '\\' && i + 1 < text.size()) {
          value += text[++i];
        } else if (text[i] == '"') {
          out = value;
          return true;
        } else {
          value += text[i];
        }
      }
      return false;
    }
    if (first == '{' || first == '[') {
      const char close = first == '{' ? '}' : ']';
      int depth = 0;
      for (std::size_t i = at; i < text.size(); ++i) {
        if (text[i] == first) {
          ++depth;
        } else if (text[i] == close && --depth == 0) {
          out = text.substr(at, i - at + 1);
          return true;
        }
      }
      return false;
    }
    std::size_t end = at;
    while (end < text.size() && text[end] != ',' && text[end] != '}' && text[end] != '\n' && text[end] != '\r') {
      ++end;
    }
    out = text.substr(at, end - at);
    while (!out.empty() && out.back() == ' ') {
      out.pop_back();
    }
    return true;
  }

  bool JsonFloat(const std::string& text, const std::string& key, float& out)
  {
    std::string value;
    if (!JsonValue(text, key, value)) {
      return false;
    }
    out = std::strtof(value.c_str(), nullptr);
    return true;
  }

  void JsonVector(const std::string& text, const std::string& key, float* const out, const int n)
  {
    std::string object;
    if (!JsonValue(text, key, object)) {
      return;
    }
    for (int i = 0; i < n && i < 4; ++i) {
      (void)JsonFloat(object, kAxes[i], out[i]);
    }
  }

  std::string JsonNumber(const float value)
  {
    char text[48];
    (void)std::snprintf(text, sizeof(text), "%.9g", static_cast<double>(value));
    return text;
  }

  std::string JsonQuoted(const std::string& text)
  {
    std::string out = "\"";
    for (const char c : text) {
      if (c == '"' || c == '\\') {
        out += '\\';
      }
      out += c;
    }
    return out + "\"";
  }

  std::string JsonVectorText(const float* const value, const int n, const std::string& indent)
  {
    std::string out = "{\n";
    for (int i = 0; i < n && i < 4; ++i) {
      out += indent + "    \"" + kAxes[i] + "\": " + JsonNumber(value[i]) + (i + 1 < n ? ",\n" : "\n");
    }
    return out + indent + "}";
  }
} // namespace faf::editor
