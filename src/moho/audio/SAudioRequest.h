#pragma once

#include <cstddef>
#include <cstdint>

#include "Wm3Vector3.h"

namespace gpg
{
  class RType;
  class RRef;
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CSndParams;
  class HSound;
  enum ELayer : std::int32_t;

  enum class EAudioRequestType : std::int32_t
  {
    EntitySound = 0,
    StartLoop = 1,
    StopLoop = 2,
  };

  /**
   * Sound request payload consumed by user-side audio.
   *
   * Binary shape:
   * - +0x00: world-space position
   * - +0x0C: sim layer
   * - +0x10: 2D/3D sound parameter pointer
   * - +0x14: optional loop-handle pointer
   * - +0x18: request opcode (0/1/2)
   */
  struct SAudioRequest
  {
    inline static gpg::RType* sType = nullptr;

    Wm3::Vec3f position;           // +0x00
    ELayer layer;                  // +0x0C
    CSndParams* params;            // +0x10
    HSound* sound;                 // +0x14
    EAudioRequestType requestType; // +0x18

    /**
     * Address: 0x004E4D30 (FUN_004E4D30, Moho::SAudioRequest::MemberDeserialize)
     *
     * What it does:
     * Loads request position/layer and tracked pointer lanes.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x004E4DB0 (FUN_004E4DB0, Moho::SAudioRequest::MemberSerialize)
     *
     * What it does:
     * Stores request position/layer and tracked pointer lanes.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  static_assert(sizeof(SAudioRequest) == 0x1C, "SAudioRequest size must be 0x1C");
  static_assert(offsetof(SAudioRequest, position) == 0x00, "SAudioRequest::position offset must be 0x00");
  static_assert(offsetof(SAudioRequest, layer) == 0x0C, "SAudioRequest::layer offset must be 0x0C");
  static_assert(offsetof(SAudioRequest, params) == 0x10, "SAudioRequest::params offset must be 0x10");
  static_assert(offsetof(SAudioRequest, sound) == 0x14, "SAudioRequest::sound offset must be 0x14");
  static_assert(offsetof(SAudioRequest, requestType) == 0x18, "SAudioRequest::requestType offset must be 0x18");
} // namespace moho
