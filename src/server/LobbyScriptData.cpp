#include "server/LobbyScriptData.h"

#include <algorithm>
#include <cstring>

// Engine addition, dedicated server: see LobbyScriptData.h.

namespace faf::server
{
  namespace
  {
    constexpr std::uint8_t kTableEnd = 5;

    [[nodiscard]] bool Parse(const std::span<const std::uint8_t> bytes, std::size_t& at, SLuaBytesValue& out, const int depth)
    {
      if (at >= bytes.size() || depth > kLuaBytesMaxDepth) {
        return false;
      }
      const std::uint8_t tag = bytes[at++];
      switch (tag) {
      case static_cast<std::uint8_t>(SLuaBytesValue::EKind::Number):
        if (bytes.size() - at < 4u) {
          return false;
        }
        out.kind = SLuaBytesValue::EKind::Number;
        std::memcpy(out.raw, bytes.data() + at, 4u);
        at += 4u;
        return true;
      case static_cast<std::uint8_t>(SLuaBytesValue::EKind::String): {
        const auto end = std::find(bytes.begin() + static_cast<std::ptrdiff_t>(at), bytes.end(), std::uint8_t{0});
        if (end == bytes.end()) {
          return false;
        }
        const auto stop = static_cast<std::size_t>(end - bytes.begin());
        out.kind = SLuaBytesValue::EKind::String;
        out.text.assign(reinterpret_cast<const char*>(bytes.data() + at), stop - at);
        at = stop + 1u;
        return true;
      }
      case static_cast<std::uint8_t>(SLuaBytesValue::EKind::Nil):
        out.kind = SLuaBytesValue::EKind::Nil;
        return true;
      case static_cast<std::uint8_t>(SLuaBytesValue::EKind::Boolean):
        if (at >= bytes.size()) {
          return false;
        }
        out.kind = SLuaBytesValue::EKind::Boolean;
        out.raw[0] = bytes[at++];
        return true;
      case static_cast<std::uint8_t>(SLuaBytesValue::EKind::Table):
        out.kind = SLuaBytesValue::EKind::Table;
        while (at < bytes.size() && bytes[at] != kTableEnd) {
          SLuaBytesValue key;
          SLuaBytesValue value;
          if (!Parse(bytes, at, key, depth + 1) || !Parse(bytes, at, value, depth + 1)) {
            return false;
          }
          out.keys.push_back(std::move(key));
          out.values.push_back(std::move(value));
        }
        if (at >= bytes.size()) {
          return false;
        }
        ++at; // the end of the table
        return true;
      default:
        return false;
      }
    }
  } // namespace

  SLuaBytesValue* SLuaBytesValue::Field(const std::string_view key) noexcept
  {
    if (kind != EKind::Table) {
      return nullptr;
    }
    for (std::size_t i = 0; i < keys.size(); ++i) {
      if (keys[i].IsString(key)) {
        return &values[i];
      }
    }
    return nullptr;
  }

  bool ParseLuaBytes(const std::span<const std::uint8_t> bytes, SLuaBytesValue& out)
  {
    std::size_t at = 0;
    out = SLuaBytesValue{};
    return Parse(bytes, at, out, 0) && at == bytes.size();
  }

  void WriteLuaBytes(const SLuaBytesValue& value, std::vector<std::uint8_t>& out)
  {
    out.push_back(static_cast<std::uint8_t>(value.kind));
    switch (value.kind) {
    case SLuaBytesValue::EKind::Number:
      out.insert(out.end(), value.raw, value.raw + 4);
      return;
    case SLuaBytesValue::EKind::String:
      out.insert(out.end(), value.text.begin(), value.text.end());
      out.push_back(0u);
      return;
    case SLuaBytesValue::EKind::Nil:
      return;
    case SLuaBytesValue::EKind::Boolean:
      out.push_back(value.raw[0]);
      return;
    case SLuaBytesValue::EKind::Table:
      for (std::size_t i = 0; i < value.keys.size(); ++i) {
        WriteLuaBytes(value.keys[i], out);
        WriteLuaBytes(value.values[i], out);
      }
      out.push_back(kTableEnd);
      return;
    }
  }

  bool PinGameOptions(std::vector<std::uint8_t>& payload, const SPinnedOptions& pinned)
  {
    if (pinned.empty()) {
      return false;
    }
    SLuaBytesValue root;
    if (!ParseLuaBytes(payload, root) || root.kind != SLuaBytesValue::EKind::Table) {
      return false;
    }
    const SLuaBytesValue* const type = root.Field("Type");
    SLuaBytesValue* options = nullptr;
    bool everyKey = false;
    if (type != nullptr && type->IsString("GameOptions")) {
      options = root.Field("Options");
    } else if (type != nullptr && type->IsString("GameInfo")) {
      if (SLuaBytesValue* const info = root.Field("GameInfo"); info != nullptr) {
        options = info->Field("GameOptions");
        everyKey = true;
      }
    }
    if (options == nullptr || options->kind != SLuaBytesValue::EKind::Table) {
      return false;
    }

    bool changed = false;
    std::vector<std::uint8_t> written;
    for (const auto& [key, bytes] : pinned) {
      SLuaBytesValue wanted;
      if (!ParseLuaBytes(bytes, wanted)) {
        continue;
      }
      if (SLuaBytesValue* const have = options->Field(key); have != nullptr) {
        written.clear();
        WriteLuaBytes(*have, written);
        if (written != bytes) {
          *have = std::move(wanted);
          changed = true;
        }
      } else if (everyKey) {
        SLuaBytesValue name;
        name.kind = SLuaBytesValue::EKind::String;
        name.text = key;
        options->keys.push_back(std::move(name));
        options->values.push_back(std::move(wanted));
        changed = true;
      }
    }
    if (changed) {
      payload.clear();
      WriteLuaBytes(root, payload);
    }
    return changed;
  }
} // namespace faf::server
