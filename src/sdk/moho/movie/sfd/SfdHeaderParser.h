#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace moho::sfd
{
  // Independent file-format metadata, not a middleware object layout.
  struct VideoDescriptor
  {
    std::uint8_t streamId{}, codec{}, frameRateCode{}, featureInfo{}, colourType{};
    std::uint8_t pictureType{}, flags{}, expand{}, gopN{}, gopM{}, effect{};
    std::uint16_t bitrate{};
    int width{}, height{};
  };
  struct HeaderInfo
  {
    std::uint32_t metadataSize{}, packSize{}, byteRate{}, audioLength{}, videoLength{}, frameCount{};
    std::uint16_t packetSizeFieldLength{};
    std::uint8_t packType{}, elementCount{}, audioStreams{}, videoStreams{}, privateStreams{};
    int width{}, height{}, fpsMilli{}, compositionMode{}, audioSampleRate{}, audioChannels{};
    std::array<VideoDescriptor, 26> videos{};
    std::array<std::uint8_t, 26> streamIds{};
  };
  bool ParseSfdHeader(std::span<const std::byte> data, HeaderInfo& result);
} // namespace moho::sfd
