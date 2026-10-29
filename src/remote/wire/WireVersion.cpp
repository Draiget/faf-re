#include "remote/wire/WireVersion.h"

#include <cstdio>

// Engine addition, server mode: see WireVersion.h.

namespace faf::remote::wire
{
  namespace
  {
    constexpr std::uint32_t kHelloMagic = 0x46414657u; // "WFAF"
    constexpr std::uint32_t kMaxLanesOnWire = 64u;
  } // namespace

  const char* LaneName(const ELane lane) noexcept
  {
    switch (lane) {
    case ELane::Entities:
      return "entities";
    case ELane::Armies:
      return "armies";
    case ELane::Grids:
      return "grids";
    case ELane::Events:
      return "events";
    case ELane::LuaSync:
      return "lua sync";
    case ELane::Commands:
      return "commands";
    case ELane::Count:
      break;
    }
    return "?";
  }

  void SWireHello::Encode(BitWriter& writer) const
  {
    writer.WriteBits(kHelloMagic, 32);
    writer.WriteBits(protocolVersion, 16);
    writer.WriteVarUint(static_cast<std::uint32_t>(laneVersions.size()));
    for (const std::uint16_t version : laneVersions) {
      writer.WriteBits(version, 16);
    }
    writer.WriteBits(static_cast<std::uint32_t>(contentHash), 32);
    writer.WriteBits(static_cast<std::uint32_t>(contentHash >> 32), 32);
  }

  std::optional<SWireHello> SWireHello::Decode(BitReader& reader)
  {
    if (reader.ReadBits(32) != kHelloMagic) {
      return std::nullopt;
    }
    SWireHello hello{};
    hello.protocolVersion = static_cast<std::uint16_t>(reader.ReadBits(16));
    const std::uint32_t laneCount = reader.ReadVarUint();
    if (!reader.Ok() || laneCount > kMaxLanesOnWire) {
      return std::nullopt;
    }
    // Lanes this build does not know are read and dropped; lanes it knows but the peer did
    // not send stay 0, which never matches a real version.
    hello.laneVersions.fill(0);
    for (std::uint32_t lane = 0; lane < laneCount; ++lane) {
      const auto version = static_cast<std::uint16_t>(reader.ReadBits(16));
      if (lane < kLaneCount) {
        hello.laneVersions[lane] = version;
      }
    }
    const std::uint64_t low = reader.ReadBits(32);
    const std::uint64_t high = reader.ReadBits(32);
    hello.contentHash = low | (high << 32);
    if (!reader.Ok()) {
      return std::nullopt;
    }
    return hello;
  }

  std::optional<std::string> WireIncompatibility(const SWireHello& local, const SWireHello& remote)
  {
    char text[160];
    if (local.protocolVersion != remote.protocolVersion) {
      std::snprintf(
        text, sizeof(text), "protocol version %u here, %u on the other side", local.protocolVersion,
        remote.protocolVersion
      );
      return std::string(text);
    }
    for (std::size_t lane = 0; lane < kLaneCount; ++lane) {
      if (local.laneVersions[lane] != remote.laneVersions[lane]) {
        std::snprintf(
          text, sizeof(text), "%s lane version %u here, %u on the other side", LaneName(static_cast<ELane>(lane)),
          local.laneVersions[lane], remote.laneVersions[lane]
        );
        return std::string(text);
      }
    }
    if (local.contentHash != remote.contentHash) {
      return std::string("different game content (blueprints, meshes or sounds)");
    }
    return std::nullopt;
  }
} // namespace faf::remote::wire
