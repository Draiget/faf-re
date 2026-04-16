#pragma once

#include <cstdint>

namespace gpg
{
  class RType;
  class ReadArchive;
  class WriteArchive;
}

namespace moho
{
  /**
   * Minimal formation-instance interface view used by transport/runtime callers.
   *
   * Address ownership:
   * - `CAiFormationInstance` slot-0 implementation: 0x0059BD60 (`FUN_0059BD60`)
   *
   * What it does:
   * Invokes instance destructor and optionally frees storage when bit0 of
   * `deleteFlags` is set.
   */
  class IFormationInstance
  {
  public:
    inline static gpg::RType* sType = nullptr;
    inline static gpg::RType* sPointerType = nullptr;

    /**
     * Address: 0x00569450 (FUN_00569450, Moho::IFormationInstance::IFormationInstance)
     *
     * What it does:
     * Initializes the base runtime lane and self-links the embedded
     * formation-status broadcaster node.
     */
    IFormationInstance();

    /**
     * Address: 0x00565C70 (FUN_00565C70, Moho::IFormationInstance::~IFormationInstance)
     *
     * What it does:
     * Unlinks the embedded formation-status broadcaster lane from its
     * intrusive listener list.
     */
    ~IFormationInstance();

    /**
     * Address: 0x0059D010 (FUN_0059D010, Moho::IFormationInstance::GetPointerType)
     *
     * What it does:
     * Lazily resolves and caches the reflection descriptor for
     * `IFormationInstance*`.
     */
    [[nodiscard]] static gpg::RType* GetPointerType();

    /**
     * Address: 0x00570D80 (FUN_00570D80, Moho::IFormationInstance::MemberDeserialize)
     *
     * What it does:
     * Loads reflected formation-status broadcaster payload for this instance.
     */
    static void MemberDeserialize(IFormationInstance* object, gpg::ReadArchive* archive);

    /**
     * Address: 0x00570DD0 (FUN_00570DD0, Moho::IFormationInstance::MemberSerialize)
     *
     * What it does:
     * Saves reflected formation-status broadcaster payload for this instance.
     */
    static void MemberSerialize(const IFormationInstance* object, gpg::WriteArchive* archive);

    virtual void operator_delete(std::int32_t deleteFlags) = 0;
  };

  static_assert(sizeof(IFormationInstance) == 0x04, "IFormationInstance size must be 0x04");
} // namespace moho
