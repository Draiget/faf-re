#include "remote/net/LobbySignals.h"

#include "remote/net/Datagram.h"

// Engine addition, server mode: see LobbySignals.h.

namespace faf::remote::net
{
  namespace
  {
    void WriteText(ByteWriter& writer, const std::string& text)
    {
      writer.Varint(text.size());
      writer.Bytes(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
    }

    [[nodiscard]] bool ReadText(ByteReader& reader, const std::size_t limit, std::string& out)
    {
      const std::uint64_t size = reader.Varint();
      if (!reader.Ok() || size > limit) {
        return false;
      }
      const std::uint8_t* const bytes = reader.Bytes(static_cast<std::size_t>(size));
      if (bytes == nullptr && size != 0u) {
        return false;
      }
      out.assign(reinterpret_cast<const char*>(bytes), static_cast<std::size_t>(size));
      return reader.Ok();
    }
  } // namespace

  std::vector<std::uint8_t> EncodeLobbySignal(const SLobbySignal& signal)
  {
    std::vector<std::uint8_t> message;
    ByteWriter writer(message);
    writer.Byte(static_cast<std::uint8_t>(signal.kind));
    writer.Byte(signal.flags);
    writer.Varint(static_cast<std::uint64_t>(signal.uid < 0 ? 0 : signal.uid));
    WriteText(writer, signal.name.size() <= kLobbySignalMaxName ? signal.name : signal.name.substr(0, kLobbySignalMaxName));
    WriteText(writer, signal.text.size() <= kLobbySignalMaxText ? signal.text : signal.text.substr(0, kLobbySignalMaxText));
    return message;
  }

  bool DecodeLobbySignal(const std::span<const std::uint8_t> message, SLobbySignal& out)
  {
    ByteReader reader(message.data(), message.size());
    const std::uint8_t kind = reader.Byte();
    out.flags = reader.Byte();
    const std::uint64_t uid = reader.Varint();
    if (!reader.Ok() || kind < static_cast<std::uint8_t>(ELobbySignal::Host) || kind > static_cast<std::uint8_t>(ELobbySignal::Launching)
        || uid > 0x7FFFFFFFu) {
      return false;
    }
    out.kind = static_cast<ELobbySignal>(kind);
    out.uid = static_cast<std::int32_t>(uid);
    return ReadText(reader, kLobbySignalMaxName, out.name) && ReadText(reader, kLobbySignalMaxText, out.text) && reader.AtEnd();
  }

  std::vector<std::uint8_t> EncodeLaunchRequest(const std::span<const std::uint8_t> configuration)
  {
    std::vector<std::uint8_t> message;
    message.reserve(1u + configuration.size());
    message.push_back(kLobbyLaunchRequest);
    message.insert(message.end(), configuration.begin(), configuration.end());
    return message;
  }

  bool IsLaunchRequest(const std::span<const std::uint8_t> message, std::span<const std::uint8_t>& configuration)
  {
    if (message.size() < 2u || message[0] != kLobbyLaunchRequest) {
      return false;
    }
    configuration = message.subspan(1);
    return true;
  }
} // namespace faf::remote::net
