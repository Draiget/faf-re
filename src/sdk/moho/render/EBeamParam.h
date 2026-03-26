#pragma once

#include <cstdint>

namespace moho
{
  /**
   * Address: 0x00770B80 (FUN_00770B80)
   *
   * What it does:
   * Runtime beam effect scalar parameter lanes.
   */
  enum EBeamParam : std::int32_t
  {
    BEAM_POSITION = 0,
    BEAM_POSITION_X = 0,
    BEAM_POSITION_Y = 1,
    BEAM_POSITION_Z = 2,
    BEAM_ENDPOSITION = 3,
    BEAM_ENDPOSITION_X = 3,
    BEAM_ENDPOSITION_Y = 4,
    BEAM_ENDPOSITION_Z = 5,
    BEAM_LENGTH = 6,
    BEAM_LIFETIME = 7,
    BEAM_STARTCOLOR = 8,
    BEAM_STARTCOLOR_R = 8,
    BEAM_STARTCOLOR_G = 9,
    BEAM_STARTCOLOR_B = 10,
    BEAM_STARTCOLOR_A = 11,
    BEAM_ENDCOLOR = 12,
    BEAM_ENDCOLOR_R = 12,
    BEAM_ENDCOLOR_G = 13,
    BEAM_ENDCOLOR_B = 14,
    BEAM_ENDCOLOR_A = 15,
    BEAM_THICKNESS = 16,
    BEAM_USHIFT = 17,
    BEAM_VSHIFT = 18,
    BEAM_REPEATRATE = 19,
    BEAM_LODCUTOFF = 20,
    BEAM_LASTPARAM = 21,
  };

  static_assert(sizeof(EBeamParam) == 0x4, "EBeamParam size must be 4 bytes");
} // namespace moho
