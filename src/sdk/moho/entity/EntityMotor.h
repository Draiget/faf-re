#pragma once

namespace gpg
{
  class RType;
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class Entity;

  /**
   * RTTI/vtable evidence:
   * - Moho::Motor (emit): slot0 0x00694AB0, slot1 pure in base, slot2 0x00694AD0.
   * - Derived motors (MotorFallDown/MotorSinkAway) implement slot1 as Update.
   */
  class EntityMotor
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00694AC0 (FUN_00694AC0, Moho::Motor::Motor)
     *
     * What it does:
     * Initializes one motor base object and applies the base vftable lane.
     */
    EntityMotor();

    /**
     * Address: 0x00694AB0 (FUN_00694AB0, Moho::Motor::Func1)
     *
     * What it does:
     * Binds/rebinds the motor to an owning entity.
     */
    virtual void BindEntity(Entity*);

    /**
     * Address: 0x00A82547 (FUN_00A82547) in base (`_purecall`), overridden in derived motor classes.
     *
     * What it does:
     * Advances motor state for one entity tick.
     */
    virtual void Update(Entity*) = 0;

    /**
     * Address: 0x00694AD0 (FUN_00694AD0, Moho::Motor::dtr)
     *
     * What it does:
     * Base scalar deleting destructor.
     */
    virtual ~EntityMotor();

    /**
     * Address: 0x00694940 (FUN_00694940, Moho::MotorSerializer::Deserialize)
     *
     * What it does:
     * No-op load callback: the base motor has no serialized fields of its own.
     */
    void MemberDeserialize(gpg::ReadArchive*) noexcept {}

    /**
     * Address: 0x00694950 (FUN_00694950, Moho::MotorSerializer::Serialize)
     *
     * What it does:
     * No-op save callback: the base motor has no serialized fields of its own.
     */
    void MemberSerialize(gpg::WriteArchive*) const noexcept {}
  };

#if defined(_M_IX86)
  static_assert(sizeof(EntityMotor) == 0x04, "EntityMotor size must be 0x04");
#endif

  using Motor = EntityMotor;
} // namespace moho
