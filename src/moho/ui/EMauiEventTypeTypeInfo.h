#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Owns reflected metadata for the `EMauiEventType` enum.
   */
  class EMauiEventTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00795A10 (FUN_00795A10, Moho::EMauiEventTypeTypeInfo::ctor)
     *
     * What it does:
     * Preregisters the reflected `EMauiEventType` enum metadata.
     */
    EMauiEventTypeTypeInfo();

    /**
     * Address: 0x00795AA0 (FUN_00795AA0, Moho::EMauiEventTypeTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting-destructor lane for MAUI event enum metadata.
     */
    ~EMauiEventTypeTypeInfo() override;

    /**
     * Address: 0x00795A90 (FUN_00795A90, Moho::EMauiEventTypeTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type label for MAUI event values.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00795A70 (FUN_00795A70, Moho::EMauiEventTypeTypeInfo::Init)
     *
     * What it does:
     * Writes enum width, installs event labels, and finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x00795AD0 (FUN_00795AD0, Moho::EMauiEventTypeTypeInfo::AddEnums)
     *
     * What it does:
     * Registers the `MET_` event name/value map in reflected enum metadata.
     */
    void AddEnums();
  };

  static_assert(sizeof(EMauiEventTypeTypeInfo) == 0x78, "EMauiEventTypeTypeInfo size must be 0x78");
} // namespace moho
