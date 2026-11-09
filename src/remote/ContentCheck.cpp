#include "remote/ContentCheck.h"

#include <algorithm>
#include <exception>
#include <memory>

#include "gpg/core/containers/String.h"
#include "lua/LuaObject.h"
#include "lua/LuaTableIterator.h"
#include "moho/lua/SCR_String.h"
#include "remote/ContentTables.h"
#include "remote/net/Datagram.h"
#include "remote/net/GameLinks.h"

// Engine addition, server mode: see ContentCheck.h.

namespace faf::remote
{
  namespace
  {
    constexpr std::uint64_t kFnvOffset = 0xCBF29CE484222325ull;
    constexpr std::uint64_t kFnvPrime = 0x100000001B3ull;
    constexpr std::size_t kReportBytes = 1u + 2u * sizeof(std::uint64_t);

    void PutU64(std::vector<std::uint8_t>& out, const std::uint64_t value)
    {
      for (unsigned i = 0; i < 8u; ++i) {
        out.push_back(static_cast<std::uint8_t>(value >> (8u * i)));
      }
    }

    [[nodiscard]] std::uint64_t GetU64(const std::uint8_t* const bytes) noexcept
    {
      std::uint64_t value = 0;
      for (unsigned i = 0; i < 8u; ++i) {
        value |= static_cast<std::uint64_t>(bytes[i]) << (8u * i);
      }
      return value;
    }
  } // namespace

  std::uint64_t HashModUids(std::vector<std::string> uids) noexcept
  {
    std::sort(uids.begin(), uids.end());
    std::uint64_t hash = kFnvOffset;
    for (const std::string& uid : uids) {
      for (const char c : uid) {
        hash ^= static_cast<unsigned char>(c);
        hash *= kFnvPrime;
      }
      hash *= kFnvPrime; // the terminator, a zero byte
    }
    return hash;
  }

  std::vector<std::string> ReadModUids(const std::string& gameMods)
  {
    std::vector<std::string> uids;
    if (gameMods.empty()) {
      return uids;
    }
    const std::unique_ptr<LuaPlus::LuaState> state(new LuaPlus::LuaState(LuaPlus::LuaState::LIB_BASE));
    try {
      LuaPlus::LuaObject mods;
      (void)moho::SCR_FromString(&mods, fa::string(gameMods.c_str(), gameMods.size()), state.get());
      if (!mods.IsTable()) {
        return uids;
      }
      for (LuaPlus::LuaTableIterator it(&mods, 1); !it.m_isDone; it.Next()) {
        LuaPlus::LuaObject entry = it.GetValue();
        const LuaPlus::LuaObject uid = entry.IsTable() ? entry["uid"] : LuaPlus::LuaObject{};
        const LuaPlus::LuaObject key = it.GetKey();
        if (uid.IsString()) {
          uids.emplace_back(uid.GetString());
        } else if (key.IsString()) {
          uids.emplace_back(key.GetString());
        }
      }
    } catch (const std::exception&) {
      uids.push_back("?"); // unreadable: never the hash of an empty set
    }
    return uids;
  }

  SContentReport MakeContentReport(moho::RRuleGameRules& rules, const std::string& gameMods)
  {
    SContentReport report;
    report.blueprints = BuildContentTables(rules).Hash();
    report.mods = HashModUids(ReadModUids(gameMods));
    return report;
  }

  std::vector<std::uint8_t> EncodeContentReport(const SContentReport& report)
  {
    std::vector<std::uint8_t> message;
    message.reserve(kReportBytes);
    message.push_back(static_cast<std::uint8_t>(net::ESeatMessage::ContentReport));
    PutU64(message, report.blueprints);
    PutU64(message, report.mods);
    return message;
  }

  std::vector<std::uint8_t> EncodeModReport(const std::vector<SModEntry>& mods)
  {
    std::vector<std::uint8_t> message;
    net::ByteWriter writer(message);
    writer.Byte(static_cast<std::uint8_t>(net::ESeatMessage::ModReport));
    std::vector<const SModEntry*> kept;
    for (const SModEntry& mod : mods) {
      if (kept.size() < kMaxReportedMods && !mod.uid.empty() && mod.uid.size() <= kMaxModText && mod.version.size() <= kMaxModText) {
        kept.push_back(&mod);
      }
    }
    writer.Varint(kept.size());
    for (const SModEntry* const mod : kept) {
      writer.Byte(mod->ui ? 1u : 0u);
      writer.Varint(mod->uid.size());
      writer.Bytes(reinterpret_cast<const std::uint8_t*>(mod->uid.data()), mod->uid.size());
      writer.Varint(mod->version.size());
      writer.Bytes(reinterpret_cast<const std::uint8_t*>(mod->version.data()), mod->version.size());
    }
    return message;
  }

  bool DecodeModReport(const std::span<const std::uint8_t> message, std::vector<SModEntry>& out)
  {
    out.clear();
    if (message.empty() || message[0] != static_cast<std::uint8_t>(net::ESeatMessage::ModReport)) {
      return false;
    }
    net::ByteReader reader(message.data() + 1, message.size() - 1u);
    const std::uint64_t count = reader.Varint();
    if (!reader.Ok() || count > kMaxReportedMods) {
      return false;
    }
    const auto text = [&reader](std::string& into) {
      const std::uint64_t size = reader.Varint();
      if (!reader.Ok() || size > kMaxModText) {
        return false;
      }
      const std::uint8_t* const bytes = reader.Bytes(static_cast<std::size_t>(size));
      if (!reader.Ok()) {
        return false;
      }
      into.assign(reinterpret_cast<const char*>(bytes), static_cast<std::size_t>(size));
      return true;
    };
    for (std::uint64_t i = 0; i < count; ++i) {
      SModEntry mod;
      const std::uint8_t kind = reader.Byte();
      if (!reader.Ok() || kind > 1u || !text(mod.uid) || mod.uid.empty() || !text(mod.version)) {
        out.clear();
        return false;
      }
      mod.ui = kind == 1u;
      out.push_back(std::move(mod));
    }
    if (!reader.AtEnd()) {
      out.clear();
      return false;
    }
    return true;
  }

  std::vector<std::string> UiModsOutside(const std::vector<SModEntry>& mods, const std::vector<std::string>& allowed)
  {
    std::vector<std::string> outside;
    for (const SModEntry& mod : mods) {
      if (mod.ui && std::find(allowed.begin(), allowed.end(), mod.uid) == allowed.end()) {
        outside.push_back(mod.uid);
      }
    }
    return outside;
  }

  bool DecodeContentReport(const std::span<const std::uint8_t> message, SContentReport& out)
  {
    if (message.size() != kReportBytes || message[0] != static_cast<std::uint8_t>(net::ESeatMessage::ContentReport)) {
      return false;
    }
    out.blueprints = GetU64(message.data() + 1);
    out.mods = GetU64(message.data() + 1 + sizeof(std::uint64_t));
    return true;
  }

  std::optional<EContentCheck> ReadContentCheck(const std::string_view text)
  {
    if (text == "off") {
      return EContentCheck::Off;
    }
    if (text == "warn") {
      return EContentCheck::Warn;
    }
    if (text == "refuse") {
      return EContentCheck::Refuse;
    }
    return std::nullopt;
  }

  EContentVerdict JudgeContent(const SContentReport& expected, const SContentReport* const report) noexcept
  {
    if (report == nullptr) {
      return EContentVerdict::Missing;
    }
    return *report == expected ? EContentVerdict::Same : EContentVerdict::Differs;
  }

  bool RefusesPlayer(const EContentCheck mode, const EContentVerdict verdict) noexcept
  {
    return mode == EContentCheck::Refuse && verdict != EContentVerdict::Same;
  }
} // namespace faf::remote
