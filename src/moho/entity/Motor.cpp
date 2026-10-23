#include "Motor.h"

namespace moho
{
  /**
   * Address: 0x00694AC0 (FUN_00694AC0, Moho::Motor::Motor)
   *
   * What it does:
   * Initializes one base motor object and applies the base vftable.
   */
  Motor::Motor() = default;

  /**
   * Address: 0x00694AB0 (FUN_00694AB0, Moho::Motor::Func1)
   *
   * What it does:
   * Base no-op bind hook; derived motors may keep owner-specific state.
   */
  void Motor::BindEntity(Entity*) {}

  /**
   * Address: 0x00694AD0 (FUN_00694AD0, Moho::Motor::dtr)
   *
   * What it does:
   * Base scalar deleting destructor body.
   */
  Motor::~Motor() = default;
} // namespace moho
