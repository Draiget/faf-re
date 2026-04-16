#include "EntityMotor.h"

#include <cstdint>

namespace moho
{
  namespace
  {
    struct EntityMotorRuntimeView
    {
      void* vtable;
    };

    /**
     * Address: 0x00694D90 (FUN_00694D90)
     *
     * What it does:
     * Rebinds one motor runtime payload to the base `Motor` vtable lane.
     */
    [[maybe_unused]] [[nodiscard]] EntityMotorRuntimeView* ResetEntityMotorBaseVtableLane(
      EntityMotorRuntimeView* const runtime
    ) noexcept
    {
      static std::uint8_t sEntityMotorRuntimeVTableTag = 0;
      if (runtime != nullptr) {
        runtime->vtable = &sEntityMotorRuntimeVTableTag;
      }
      return runtime;
    }
  } // namespace

  /**
   * Address: 0x00694AC0 (FUN_00694AC0, Moho::Motor::Motor)
   *
   * What it does:
   * Initializes one base motor object and applies the base vftable lane.
   */
  EntityMotor::EntityMotor() = default;

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
