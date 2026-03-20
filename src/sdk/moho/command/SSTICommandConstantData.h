#pragma once
#include <cstdint>

#include "legacy/containers/String.h"
#include "wm3/Quaternion.h"

namespace moho
{
  struct REntityBlueprint;

  struct SSTICommandConstantData
  {
    int32_t cmd;
    void* unk0;
    Wm3::Quatf origin;
    float unk1;
    REntityBlueprint* blueprint;
    msvc8::string unk2;
  };
} // namespace moho
