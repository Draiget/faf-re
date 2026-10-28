#include "headless/ReplayCommandCheck.h"

#include <algorithm>
#include <cstdio>

#include "gpg/core/streams/Stream.h"
#include "lua/LuaObject.h"
#include "moho/misc/CDecoder.h"
#include "moho/net/CMessage.h"

// Engine addition, server mode: see ReplayCommandCheck.h.

namespace faf::headless
{
  namespace
  {
    constexpr std::uint64_t kLoggedDifferences = 3; // per opcode

    [[nodiscard]] std::vector<char> MessageBytes(const moho::CMessage& message)
    {
      return std::vector<char>(message.mBuff.start_, message.mBuff.start_ + message.mBuff.Size());
    }

    [[nodiscard]] std::string Hex(const std::vector<char>& bytes)
    {
      std::string text;
      char part[4];
      for (std::size_t i = 0; i < bytes.size() && i < 160u; ++i) {
        std::snprintf(part, sizeof(part), "%02x", static_cast<unsigned>(static_cast<unsigned char>(bytes[i])));
        text += part;
      }
      if (bytes.size() > 160u) {
        text += "...";
      }
      return text;
    }
    /**
     * One Lua value of a command payload (`LuaObject::ToByteStream`: 0 number as a float, 1
     * string, 2 nil, 3 boolean, 4 table of key/value pairs up to 5) in a form that does not
     * depend on the order a table's pairs were written in. False when `bytes` does not hold one.
     */
    [[nodiscard]] bool CanonicalLua(const std::vector<char>& bytes, std::size_t& at, std::string& out, const int depth)
    {
      if (at >= bytes.size() || depth > 64) {
        return false;
      }
      const auto tag = static_cast<unsigned char>(bytes[at++]);
      switch (tag) {
      case 0: // number
        if (bytes.size() - at < 4u) {
          return false;
        }
        out.append("n").append(bytes.data() + at, 4);
        at += 4;
        return true;
      case 1: { // string
        const auto end = std::find(bytes.begin() + static_cast<std::ptrdiff_t>(at), bytes.end(), '\0');
        if (end == bytes.end()) {
          return false;
        }
        out.append("s").append(bytes.data() + at, static_cast<std::size_t>(end - bytes.begin()) - at).push_back('\0');
        at = static_cast<std::size_t>(end - bytes.begin()) + 1u;
        return true;
      }
      case 2: // nil
        out.append("z");
        return true;
      case 3: // boolean
        if (at >= bytes.size()) {
          return false;
        }
        out.append("b").push_back(bytes[at++]);
        return true;
      case 4: { // table
        std::vector<std::string> pairs;
        while (at < bytes.size() && static_cast<unsigned char>(bytes[at]) != 5u) {
          std::string pair;
          if (!CanonicalLua(bytes, at, pair, depth + 1) || !CanonicalLua(bytes, at, pair, depth + 1)) {
            return false;
          }
          pairs.push_back(std::move(pair));
        }
        if (at >= bytes.size()) {
          return false;
        }
        ++at; // the 5
        std::sort(pairs.begin(), pairs.end());
        out.append("{");
        for (const std::string& pair : pairs) {
          out.append(std::to_string(pair.size())).append(":").append(pair);
        }
        out.append("}");
        return true;
      }
      default:
        return false;
      }
    }

    /**
     * Whether two command messages differ only in the order a Lua table's pairs were written:
     * the same bytes up to a table, tables with the same pairs, the same bytes after it.
     */
    [[nodiscard]] bool SameButLuaKeyOrder(const std::vector<char>& a, const std::vector<char>& b)
    {
      if (a.size() != b.size()) {
        return false;
      }
      const auto mismatch = std::mismatch(a.begin(), a.end(), b.begin());
      if (mismatch.first == a.end()) {
        return true;
      }
      const auto first = static_cast<std::size_t>(mismatch.first - a.begin());
      for (std::size_t start = first + 1u; start-- > 3u;) { // the header's 3 bytes are no table
        if (static_cast<unsigned char>(a[start]) != 4u) {
          continue;
        }
        std::size_t endA = start;
        std::size_t endB = start;
        std::string canonicalA;
        std::string canonicalB;
        if (CanonicalLua(a, endA, canonicalA, 0) && CanonicalLua(b, endB, canonicalB, 0) && endA == endB
            && endA > first && canonicalA == canonicalB) {
          return SameButLuaKeyOrder(
            std::vector<char>(a.begin() + static_cast<std::ptrdiff_t>(endA), a.end()),
            std::vector<char>(b.begin() + static_cast<std::ptrdiff_t>(endB), b.end())
          );
        }
      }
      return false;
    }
  } // namespace

  CReplayCommandCheck::CReplayCommandCheck(moho::RRuleGameRules& rules)
    : mLuaState(new LuaPlus::LuaState(LuaPlus::LuaState::LIB_BASE))
    , mCapture([this](moho::CMessage& message) { mCaptured.push_back(MessageBytes(message)); }, nullptr)
    , mMarshaller(std::make_unique<moho::CMarshaller>(&mCapture))
    , mDecoder(std::make_unique<moho::CDecoder>(mMarshaller.get(), mNoRecording, &rules, mLuaState.get()))
  {}

  CReplayCommandCheck::~CReplayCommandCheck()
  {
    Uninstall();
  }

  void CReplayCommandCheck::Install()
  {
    moho::CDecoder::SetMessageObserver(&CReplayCommandCheck::Observe, this);
  }

  void CReplayCommandCheck::Uninstall()
  {
    moho::CDecoder::SetMessageObserver(nullptr, nullptr);
  }

  void CReplayCommandCheck::Observe(const moho::CMessage& message, void* const context)
  {
    static_cast<CReplayCommandCheck*>(context)->OnMessage(message);
  }

  void CReplayCommandCheck::OnMessage(const moho::CMessage& message)
  {
    if (mInside) {
      return; // this check's own decoder
    }
    // The sim's decoder calls this on the sim thread, one message at a time.
    struct SInside
    {
      bool& inside;
      explicit SInside(bool& flag) : inside(flag) { inside = true; }
      ~SInside() { inside = false; }
    };
    mCaptured.clear();
    {
      const SInside guard(mInside);
      mDecoder->ReceiveMessage(const_cast<moho::CMessage*>(&message), nullptr);
    }

    const std::vector<char> original = MessageBytes(message);
    const auto opcode = static_cast<std::uint8_t>(original.empty() ? 0 : original[0]);
    ++mMessages;
    ++mSeen[opcode];
    if (mCaptured.empty()) {
      ++mMissing[opcode];
    } else if (mCaptured.size() == 1u && mCaptured.front() == original) {
      ++mIdentical;
    } else if (mCaptured.size() == 1u && SameButLuaKeyOrder(original, mCaptured.front())) {
      ++mKeyOrderOnly[opcode];
    } else {
      if (mDiffering[opcode]++ < kLoggedDifferences) {
        std::printf(
          "command check: opcode %u differs: replay %s, round trip %s%s\n", static_cast<unsigned>(opcode),
          Hex(original).c_str(), Hex(mCaptured.front()).c_str(), mCaptured.size() > 1u ? " (and more)" : ""
        );
      }
    }
  }

  std::uint64_t CReplayCommandCheck::Failures() const noexcept
  {
    std::uint64_t failures = 0;
    for (const std::uint64_t count : mDiffering) {
      failures += count;
    }
    return failures;
  }

  std::string CReplayCommandCheck::Summary() const
  {
    std::uint64_t missing = 0;
    for (const std::uint64_t count : mMissing) {
      missing += count;
    }
    std::uint64_t keyOrderOnly = 0;
    for (const std::uint64_t count : mKeyOrderOnly) {
      keyOrderOnly += count;
    }
    char text[256];
    std::snprintf(
      text, sizeof(text),
      "command check: %llu messages, %llu identical after decode and marshal, %llu the same but for the order of "
      "a Lua table's pairs, %llu differing, %llu not marshalled again (dropped by the decoder, as the sim drops them)",
      static_cast<unsigned long long>(mMessages), static_cast<unsigned long long>(mIdentical),
      static_cast<unsigned long long>(keyOrderOnly), static_cast<unsigned long long>(Failures()),
      static_cast<unsigned long long>(missing)
    );
    std::string summary = text;
    std::string byOpcode;
    for (std::size_t op = 0; op < mSeen.size(); ++op) {
      if (mSeen[op] == 0u) {
        continue;
      }
      char part[128];
      std::snprintf(
        part, sizeof(part), " %zu:%llu%s", op, static_cast<unsigned long long>(mSeen[op]),
        mDiffering[op] != 0u || mMissing[op] != 0u || mKeyOrderOnly[op] != 0u
          ? (std::string("(") + std::to_string(mKeyOrderOnly[op]) + " key order, " + std::to_string(mDiffering[op])
             + " differ, " + std::to_string(mMissing[op]) + " dropped)")
              .c_str()
          : ""
      );
      byOpcode += part;
    }
    return summary + "; by opcode:" + byOpcode;
  }
} // namespace faf::headless
