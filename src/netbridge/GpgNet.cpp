#include "netbridge/GpgNet.h"

#include <cstring>

namespace faf::netbridge
{
  namespace
  {
    // Sanity limits only, as tools/gpgnet: far above anything the game sends
    // (end-of-game JsonStats alone passes 64 KiB).
    constexpr std::int32_t kMaxArgs = 1 << 12;
    constexpr std::int32_t kMaxString = 64 << 20;

    void PutInt(std::string& out, const std::int32_t v)
    {
      const auto u = static_cast<std::uint32_t>(v);
      const char b[4] = {static_cast<char>(u & 0xFF), static_cast<char>((u >> 8) & 0xFF),
                         static_cast<char>((u >> 16) & 0xFF), static_cast<char>((u >> 24) & 0xFF)};
      out.append(b, 4);
    }

    void PutString(std::string& out, const std::string& s)
    {
      PutInt(out, static_cast<std::int32_t>(s.size()));
      out += s;
    }

    bool GetInt(const std::string& buf, std::size_t& pos, std::int32_t& v)
    {
      if (pos + 4 > buf.size()) {
        return false;
      }
      std::uint32_t u = 0;
      for (int i = 3; i >= 0; --i) {
        u = (u << 8) | static_cast<unsigned char>(buf[pos + static_cast<std::size_t>(i)]);
      }
      v = static_cast<std::int32_t>(u);
      pos += 4;
      return true;
    }
  } // namespace

  std::string EncodeGpg(const GpgMessage& m)
  {
    std::string out;
    PutString(out, m.command);
    PutInt(out, static_cast<std::int32_t>(m.args.size()));
    for (const GpgArg& a : m.args) {
      out += static_cast<char>(a.kind);
      if (a.kind == GpgArg::Kind::Int) {
        PutInt(out, a.number);
      } else {
        PutString(out, a.text);
      }
    }
    return out;
  }

  std::optional<GpgMessage> GpgDecoder::Next(bool* bad)
  {
    *bad = false;
    std::size_t pos = 0;
    GpgMessage m;
    std::int32_t len = 0;
    if (!GetInt(mBuffer, pos, len)) {
      return std::nullopt;
    }
    if (len < 0 || len > kMaxString) {
      *bad = true;
      return std::nullopt;
    }
    if (pos + static_cast<std::size_t>(len) > mBuffer.size()) {
      return std::nullopt;
    }
    m.command = mBuffer.substr(pos, static_cast<std::size_t>(len));
    pos += static_cast<std::size_t>(len);
    std::int32_t count = 0;
    if (!GetInt(mBuffer, pos, count)) {
      return std::nullopt;
    }
    if (count < 0 || count > kMaxArgs) {
      *bad = true;
      return std::nullopt;
    }
    for (std::int32_t i = 0; i < count; ++i) {
      if (pos >= mBuffer.size()) {
        return std::nullopt;
      }
      const auto kind = static_cast<std::uint8_t>(mBuffer[pos++]);
      GpgArg a;
      if (kind == 0) {
        a.kind = GpgArg::Kind::Int;
        if (!GetInt(mBuffer, pos, a.number)) {
          return std::nullopt;
        }
      } else if (kind == 1 || kind == 2) {
        a.kind = static_cast<GpgArg::Kind>(kind);
        std::int32_t n = 0;
        if (!GetInt(mBuffer, pos, n)) {
          return std::nullopt;
        }
        if (n < 0 || n > kMaxString) {
          *bad = true;
          return std::nullopt;
        }
        if (pos + static_cast<std::size_t>(n) > mBuffer.size()) {
          return std::nullopt;
        }
        a.text = mBuffer.substr(pos, static_cast<std::size_t>(n));
        pos += static_cast<std::size_t>(n);
      } else {
        *bad = true;
        return std::nullopt;
      }
      m.args.push_back(std::move(a));
    }
    mBuffer.erase(0, pos);
    return m;
  }

  std::string DescribeGpg(const GpgMessage& m)
  {
    std::string s = m.command;
    for (const GpgArg& a : m.args) {
      s += ' ';
      if (a.kind == GpgArg::Kind::Int) {
        s += std::to_string(a.number);
      } else if (a.kind == GpgArg::Kind::Data) {
        s += "<data " + std::to_string(a.text.size()) + " bytes>";
      } else if (a.text.size() > 120) {
        s += '"' + a.text.substr(0, 120) + "\"...";
      } else {
        s += '"' + a.text + '"';
      }
    }
    return s;
  }
} // namespace faf::netbridge
