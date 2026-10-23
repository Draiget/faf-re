#include "SfdHeaderParser.h"
#include <algorithm>
#include <limits>
#include <string_view>

namespace moho::sfd
{
  namespace
  {
    unsigned Byte(
      std::span<const std::byte> s,
      std::size_t i
    )
    {
      return std::to_integer<unsigned>(s[i]);
    }
    std::uint16_t Le16(
      std::span<const std::byte> s,
      std::size_t i
    )
    {
      return static_cast<std::uint16_t>(Byte(s, i) | (Byte(s, i + 1) << 8));
    }
    std::uint32_t Le32(
      std::span<const std::byte> s,
      std::size_t i
    )
    {
      return Le16(s, i) | (static_cast<std::uint32_t>(Le16(s, i + 2)) << 16);
    }
    constexpr int rates[] = {0, 23976, 24000, 25000, 29970, 30000, 50000, 59940, 60000};
  } // namespace
  bool ParseSfdHeader(
    std::span<const std::byte> data,
    HeaderInfo& result
  )
  {
    result = {};
    // Bound the work even when a caller provides a whole movie. Headers are normally
    // pack aligned, but signature scanning also accepts relocated metadata packs.
    data = data.first(std::min<std::size_t>(data.size(), 64 * 1024));
    // The identifier occupies 24 bytes: 12 letters and 12 spaces.
    // Use the on-disk field width, not a C string terminator.
    constexpr std::string_view signature = "SofdecStream            ";
    constexpr std::size_t table = 0x180, stride = 0x40;
    for (std::size_t base = 0; base + table <= data.size(); ++base) {
      auto s = data.subspan(base);
      bool matches = true;
      for (std::size_t j = 0; j < signature.size(); ++j)
        if (Byte(s, 0x20 + j) != static_cast<unsigned char>(signature[j])) {
          matches = false;
          break;
        }
      if (!matches)
        continue;
      HeaderInfo h{};
      h.metadataSize = Le32(s, 0x80);
      h.packType = static_cast<std::uint8_t>(Byte(s, 0x84));
      h.packetSizeFieldLength = Le16(s, 0x88);
      h.packSize = Le32(s, 0x8c);
      h.elementCount = static_cast<std::uint8_t>(Byte(s, 0xb0));
      h.audioStreams = static_cast<std::uint8_t>(Byte(s, 0xb1));
      h.videoStreams = static_cast<std::uint8_t>(Byte(s, 0xb2));
      h.privateStreams = static_cast<std::uint8_t>(Byte(s, 0xb3));
      if (!h.elementCount || h.elementCount > 26 || h.videoStreams != 1 ||
          h.elementCount != h.audioStreams + h.videoStreams + h.privateStreams ||
          table + h.elementCount * stride > s.size() || h.metadataSize < table + h.elementCount * stride ||
          h.metadataSize > 65536 || h.packSize < h.metadataSize || h.packSize > 65536 || h.packetSizeFieldLength != 2 ||
          h.packType != 0)
        continue;
      h.byteRate = Le32(s, 0xb4);
      h.audioLength = Le32(s, 0xb8);
      h.videoLength = Le32(s, 0xbc);
      h.frameCount = Le32(s, 0xc0);
      if (h.frameCount > static_cast<std::uint32_t>(std::numeric_limits<int>::max()))
        continue;
      unsigned videos = 0, audios = 0, privates = 0;
      bool valid = true;
      for (unsigned i = 0; i < h.elementCount; ++i) {
        const auto e = s.subspan(table + i * stride, stride);
        const auto id = static_cast<std::uint8_t>(Byte(e, 24));
        h.streamIds[i] = id;
        if (id >= 0xe0 && id <= 0xef) {
          auto& v = h.videos[videos++];
          v.streamId = id;
          v.codec = static_cast<std::uint8_t>(Byte(e, 25));
          v.bitrate = Le16(e, 26);
          v.width = (Byte(e, 28) << 4) | (Byte(e, 29) >> 4);
          v.height = ((Byte(e, 29) & 15) << 8) | Byte(e, 30);
          v.frameRateCode = static_cast<std::uint8_t>(Byte(e, 31));
          v.featureInfo = static_cast<std::uint8_t>(Byte(e, 32));
          v.colourType = static_cast<std::uint8_t>(Byte(e, 33));
          v.pictureType = static_cast<std::uint8_t>(Byte(e, 34));
          v.flags = static_cast<std::uint8_t>(Byte(e, 35));
          v.expand = static_cast<std::uint8_t>(Byte(e, 36));
          v.gopN = static_cast<std::uint8_t>(Byte(e, 37));
          v.gopM = static_cast<std::uint8_t>(Byte(e, 38));
          v.effect = static_cast<std::uint8_t>(Byte(e, 39));
          if (!v.width || !v.height || v.frameRateCode < 1 || v.frameRateCode > 8 || v.codec > 1) {
            valid = false;
            break;
          }
          h.width = v.width;
          h.height = v.height;
          h.fpsMilli = rates[v.frameRateCode];
          h.compositionMode = v.effect == 1 ? 33 : v.effect == 3 ? 81 : v.effect == 6 ? 97 : 0;
        } else if ((id >= 0xc0 && id <= 0xdf) || id == 0xbd) {
          ++audios;
          // Observed in e3_demo_cut.sfd: ADX descriptor codec 0, channels at
          // +27 and LE32 sample rate at +28. Leave other descriptors unknown.
          const auto rate = Le32(e, 28);
          if (Byte(e, 25) == 0 && Byte(e, 27) >= 1 && Byte(e, 27) <= 2 && rate >= 8000 && rate <= 192000) {
            h.audioChannels = Byte(e, 27);
            h.audioSampleRate = static_cast<int>(rate);
          }
        } else if (id == 0xbf || id == 0xbe)
          ++privates;
        else {
          valid = false;
          break;
        }
      }
      if (valid && videos == h.videoStreams && audios == h.audioStreams && privates == h.privateStreams) {
        result = h;
        return true;
      }
    }
    return false;
  }
} // namespace moho::sfd
