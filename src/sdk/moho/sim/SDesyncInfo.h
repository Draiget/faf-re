#pragma once
#include <cstdint>

#include "gpg/core/algorithms/MD5.h"

namespace moho
{
  struct SDesyncInfo
  {
    int32_t beat;
    int32_t army;
    gpg::MD5Digest hash1;
    gpg::MD5Digest hash2;
  };
} // namespace moho
