#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/misc/WeakPtr.h"
#include "Wm3Vector3.h"

namespace moho
{
  class UserEntity;

  enum class UserTargetType : std::int32_t
  {
    None = 0,
    Entity = 1,
    Position = 2,
  };

  /**
   * `Moho::UserTarget`: the UI-side command target, as mangled in
   * `?ISSUE_SetCommandTarget@Moho@@YAXPAVUserCommand@1@ABVUserTarget@1@@Z`
   * (0x008B0EE0). The sim-side network form is `SSTITarget`, which carries an
   * entity id instead of a live weak reference (`ConvertUserCommandTargetToSSTITarget`,
   * 0x008BECD0).
   *
   * Layout evidence: the local command-issue event constructor (0x008B3DC0)
   * zeroes `+0x18/+0x1C/+0x20` of the event (type and weak link) and leaves the
   * position alone; `sub_8BED50` (0x008BED50) and `sub_8BEE30` (0x008BEE30)
   * read type @0, the owner-link slot @4 and the position @0xC.
   *
   * Address: 0x008B3E50 (FUN_008B3E50 -- the implicit copy assignment: copies
   * the type, relinks `targetEntity` only when the two owner-link slots
   * differ, copies the position; reached from the "set target" event at
   * 0x008B4A68.)
   */
  struct UserTarget
  {
    UserTargetType targetType{UserTargetType::None}; // +0x00
    WeakPtr<UserEntity> targetEntity;                // +0x04
    Wm3::Vector3<float> position;                    // +0x0C
  };

  static_assert(offsetof(UserTarget, targetEntity) == 0x04, "UserTarget::targetEntity offset must be 0x04");
  static_assert(offsetof(UserTarget, position) == 0x0C, "UserTarget::position offset must be 0x0C");
  static_assert(sizeof(UserTarget) == 0x18, "UserTarget size must be 0x18");
} // namespace moho
