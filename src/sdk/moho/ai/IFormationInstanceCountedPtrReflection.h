#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/IFormationInstance.h"
#include "moho/misc/CountedObject.h"

namespace gpg
{
  /**
   * Address: 0x0059E640 (FUN_0059E640, gpg::RRef_IFormationInstance)
   *
   * What it does:
   * Builds a reflected reference for `IFormationInstance*`, normalizing to the
   * runtime-derived owner type and adjusting the base subobject pointer.
   */
  RRef* RRef_IFormationInstance(RRef* out, moho::IFormationInstance* value);
}

namespace moho
{
  template <class T>
  class RCountedPtrType;

  /**
   * VFTABLE: 0x00E2EA00
   * COL: 0x00E7F0B0
   */
  template <>
  class RCountedPtrType<moho::IFormationInstance> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x006EBF30 (FUN_006EBF30, Moho::RCountedPtrType<Moho::IFormationInstance>::RCountedPtrType)
     *
     * What it does:
     * Constructs and preregisters the reflected descriptor for `CountedPtr<IFormationInstance>`.
     */
    RCountedPtrType();

    /**
     * Address: 0x006EC110 (FUN_006EC110, Moho::RCountedPtrType<Moho::IFormationInstance>::dtr)
     * Slot: 2
     */
    ~RCountedPtrType() override;

    /**
     * Address: 0x006E9D80 (FUN_006E9D80, Moho::RCountedPtrType<Moho::IFormationInstance>::GetName)
     * Slot: 3
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006E9E40 (FUN_006E9E40, Moho::RCountedPtrType<Moho::IFormationInstance>::GetLexical)
     * Slot: 4
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x006E9FC0 (FUN_006E9FC0, Moho::RCountedPtrType<Moho::IFormationInstance>::IsIndexed)
     * Slot: 6
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x006E9FD0 (FUN_006E9FD0, Moho::RCountedPtrType<Moho::IFormationInstance>::IsPointer)
     * Slot: 7
     */
    [[nodiscard]] const gpg::RIndexed* IsPointer() const override;

    /**
     * Address: 0x006E9E20 (FUN_006E9E20, Moho::RCountedPtrType<Moho::IFormationInstance>::Init)
     * Slot: 9
     *
     * What it does:
     * Binds the shared-pointer serializer callbacks and reflected size metadata.
     */
    void Init() override;

    /**
     * Address: 0x006E9FF0 (FUN_006E9FF0, Moho::RCountedPtrType<Moho::IFormationInstance>::SubscriptIndex)
     * Slot: 0
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x006E9FE0 (FUN_006E9FE0, Moho::RCountedPtrType<Moho::IFormationInstance>::GetCount)
     * Slot: 1
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x006EAAC0 (FUN_006EAAC0, Moho::RCountedPtrType<Moho::IFormationInstance>::SerLoad)
     * Slot: 11
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006EAB10 (FUN_006EAB10, Moho::RCountedPtrType<Moho::IFormationInstance>::SerSave)
     * Slot: 12
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
  };

  static_assert(sizeof(IntrusiveRefCountView<moho::IFormationInstance>) == 0x08, "IntrusiveRefCountView<IFormationInstance> size must be 0x08");
  static_assert(offsetof(IntrusiveRefCountView<moho::IFormationInstance>, mRefCount) == 0x04, "IntrusiveRefCountView<IFormationInstance>::mRefCount offset must be 0x04");
  static_assert(sizeof(RCountedPtrType<moho::IFormationInstance>) == 0x68, "RCountedPtrType<IFormationInstance> size must be 0x68");

  /**
   * Address: 0x00BD9030 (FUN_00BD9030, register_IFormationInstanceCountedPtrReflection)
   *
   * What it does:
   * Ensures the counted-pointer descriptor is constructed and schedules cleanup
   * at process exit.
   */
  void register_IFormationInstanceCountedPtrReflection();
} // namespace moho
