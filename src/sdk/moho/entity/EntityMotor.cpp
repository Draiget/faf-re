#include "EntityMotor.h"

namespace moho
{
  /**
   * Address: 0x00694AB0 (FUN_00694AB0, Moho::Motor::Func1)
   *
   * What it does:
   * Base no-op bind hook; derived motors may keep owner-specific state.
   */
  void EntityMotor::BindEntity(Entity*) {}

  /**
   * Address: 0x00694AD0 (FUN_00694AD0, Moho::Motor::dtr)
   *
   * What it does:
   * Base scalar deleting destructor body.
   */
  EntityMotor::~EntityMotor() = default;
} // namespace moho
