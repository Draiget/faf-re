#include "editor/doc/EdJson.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace faf::editor
{
  namespace
  {
    const char* const kAxes[4] = {"x", "y", "z", "w"};
    constexpr float kPi = 3.14159265358979323846f;
    constexpr float kRadToDeg = 180.0f / kPi;
    constexpr float kDegToRad = kPi / 180.0f;

    float Wrap360(float degrees)
    {
      degrees = std::fmod(degrees, 360.0f);
      return degrees < 0.0f ? degrees + 360.0f : degrees;
    }
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

  std::vector<std::string> JsonObjects(const std::string& array)
  {
    std::vector<std::string> objects;
    int depth = 0;
    std::size_t open = 0;
    for (std::size_t i = 0; i < array.size(); ++i) {
      if (array[i] == '{') {
        if (depth++ == 0) {
          open = i;
        }
      } else if (array[i] == '}' && depth > 0 && --depth == 0) {
        objects.push_back(array.substr(open, i - open + 1));
      }
    }
    return objects;
  }

  void GameToFafme(const float (&game)[3], float (&fafme)[3])
  {
    fafme[0] = game[0] / 10.0f;
    fafme[1] = game[1] / 10.0f;
    fafme[2] = -game[2] / 10.0f;
  }

  void FafmeToGame(const float (&fafme)[3], float (&game)[3])
  {
    game[0] = fafme[0] * 10.0f;
    game[1] = fafme[1] * 10.0f;
    game[2] = -fafme[2] * 10.0f;
  }

  void UnityEulerToQuaternion(const float (&degrees)[3], float (&quaternion)[4])
  {
    const float hx = degrees[0] * kDegToRad * 0.5f;
    const float hy = degrees[1] * kDegToRad * 0.5f;
    const float hz = degrees[2] * kDegToRad * 0.5f;
    const float sx = std::sin(hx), cx = std::cos(hx);
    const float sy = std::sin(hy), cy = std::cos(hy);
    const float sz = std::sin(hz), cz = std::cos(hz);
    // Qy * Qx * Qz.
    quaternion[0] = cy * sx * cz + sy * cx * sz;
    quaternion[1] = sy * cx * cz - cy * sx * sz;
    quaternion[2] = cy * cx * sz - sy * sx * cz;
    quaternion[3] = cy * cx * cz + sy * sx * sz;
  }

  void UnityQuaternionToEuler(const float (&quaternion)[4], float (&degrees)[3])
  {
    const float x = quaternion[0], y = quaternion[1], z = quaternion[2], w = quaternion[3];
    // The rotation matrix's entries a Y * X * Z rotation reads its angles from.
    const float m12 = 2.0f * (y * z - w * x);
    const float m02 = 2.0f * (x * z + w * y);
    const float m22 = 1.0f - 2.0f * (x * x + y * y);
    const float m10 = 2.0f * (x * y + w * z);
    const float m11 = 1.0f - 2.0f * (x * x + z * z);
    const float pitch = std::asin(std::clamp(-m12, -1.0f, 1.0f));
    degrees[0] = Wrap360(pitch * kRadToDeg);
    degrees[1] = Wrap360(std::atan2(m02, m22) * kRadToDeg);
    degrees[2] = Wrap360(std::atan2(m10, m11) * kRadToDeg);
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
