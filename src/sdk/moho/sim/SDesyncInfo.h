#pragma once
#include <cstdint>

#include "gpg/core/algorithms/MD5.h"

namespace moho
{
  struct SDesyncInfo
  {
    /**
     * Address: 0x00743120 (FUN_00743120, Moho::SDesyncInfo::SDesyncInfo)
     *
     * What it does:
     * Initializes one desync entry from beat/army metadata and both checksum
     * digest payloads.
     */
    SDesyncInfo(std::int32_t beat, std::int32_t army, const gpg::MD5Digest& hash1, const gpg::MD5Digest& hash2);

    SDesyncInfo() = default;

    int32_t beat;
    int32_t army;
    gpg::MD5Digest hash1;
    gpg::MD5Digest hash2;
  };

  static_assert(sizeof(SDesyncInfo) == 0x28, "SDesyncInfo size must be 0x28");
} // namespace moho
