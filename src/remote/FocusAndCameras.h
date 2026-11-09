#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <vector>

#include "remote/net/Datagram.h"
#include "remote/net/GameLinks.h"

// Engine addition (plan WP11.1), not in the binary: two of a server-mode client's driver requests that go to the
// server. `SetArmyIndex` (the UI's `SetFocusArmy`) is a request the server answers with the army it grants: a player
// keeps their own; one defeated in a game whose defeated players observe may pick any, or -1 (the original client's
// `SetFocusArmy(-1)` on defeat). `SetGeomCams` goes at most every `kCameraPeriodMs`: what each camera sees (its
// view-projection) and its LOD scale, for the server's camera-ordered work (plan WP8.2).

namespace faf::remote
{
  /** The most armies a focus may name (a FAF game has at most 16; room for observer-only sources). */
  inline constexpr int kMaxFocusArmy = 63;

  /** `ESeatMessage::FocusArmy` either way: the kind, then varint (army + 1), so -1 (no army) is 0. */
  [[nodiscard]] inline std::vector<std::uint8_t> EncodeFocusArmy(const int army)
  {
    std::vector<std::uint8_t> message;
    net::ByteWriter writer(message);
    writer.Byte(static_cast<std::uint8_t>(net::ESeatMessage::FocusArmy));
    writer.Varint(static_cast<std::uint64_t>(army < -1 ? 0 : army + 1));
    return message;
  }

  [[nodiscard]] inline std::optional<int> DecodeFocusArmy(const std::span<const std::uint8_t> message)
  {
    if (message.empty() || message[0] != static_cast<std::uint8_t>(net::ESeatMessage::FocusArmy)) {
      return std::nullopt;
    }
    net::ByteReader reader(message.data() + 1, message.size() - 1u);
    const std::uint64_t shifted = reader.Varint();
    if (!reader.Ok() || !reader.AtEnd() || shifted > static_cast<std::uint64_t>(kMaxFocusArmy + 1)) {
      return std::nullopt;
    }
    return static_cast<int>(shifted) - 1;
  }

  /** What the server keeps of one camera. */
  struct SCameraReport
  {
    std::array<float, 16> viewProjection{}; // row-major, as `GeomCamera3::viewProjection`
    float lodScale = 1.0f;

    [[nodiscard]] bool operator==(const SCameraReport&) const = default;
  };

  inline constexpr std::size_t kMaxCameras = 4;  // the game draws one or two (split screen)
  inline constexpr int kCameraPeriodMs = 250;    // at most four updates a second

  /** `ESeatMessage::Cameras`: the kind, varint count (at most kMaxCameras), then per camera 17 little-endian floats. */
  [[nodiscard]] inline std::vector<std::uint8_t> EncodeCameras(const std::span<const SCameraReport> cameras)
  {
    std::vector<std::uint8_t> message;
    net::ByteWriter writer(message);
    writer.Byte(static_cast<std::uint8_t>(net::ESeatMessage::Cameras));
    const std::size_t count = cameras.size() < kMaxCameras ? cameras.size() : kMaxCameras;
    writer.Varint(count);
    for (std::size_t i = 0; i < count; ++i) {
      std::uint8_t bytes[17 * 4];
      std::memcpy(bytes, cameras[i].viewProjection.data(), 16 * 4);
      std::memcpy(bytes + 16 * 4, &cameras[i].lodScale, 4);
      writer.Bytes(bytes, sizeof(bytes));
    }
    return message;
  }

  [[nodiscard]] inline bool DecodeCameras(const std::span<const std::uint8_t> message, std::vector<SCameraReport>& out)
  {
    out.clear();
    if (message.empty() || message[0] != static_cast<std::uint8_t>(net::ESeatMessage::Cameras)) {
      return false;
    }
    net::ByteReader reader(message.data() + 1, message.size() - 1u);
    const std::uint64_t count = reader.Varint();
    if (!reader.Ok() || count > kMaxCameras) {
      return false;
    }
    for (std::uint64_t i = 0; i < count; ++i) {
      const std::uint8_t* const bytes = reader.Bytes(17 * 4);
      if (bytes == nullptr) {
        return false;
      }
      SCameraReport camera;
      std::memcpy(camera.viewProjection.data(), bytes, 16 * 4);
      std::memcpy(&camera.lodScale, bytes + 16 * 4, 4);
      out.push_back(camera);
    }
    return reader.AtEnd();
  }
} // namespace faf::remote
