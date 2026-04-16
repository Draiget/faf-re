#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/WeakPtr.h"

namespace moho
{
  class IEffect;

  /**
   * Address: 0x0066A1D0 (FUN_0066A1D0)
   *
   * What it does:
   * Rebinds one `WeakPtr<IEffect>` node to a new owner-link slot and relinks
   * it at the head of the destination owner's intrusive weak chain.
   */
  [[nodiscard]] WeakPtr<IEffect>* RelinkWeakPtrIEffect(WeakPtr<IEffect>* weak, IEffect* effect) noexcept;

  struct WeakPtr_IEffect
  {
    /**
     * Address: 0x006751B0 (FUN_006751B0, Moho::WeakPtr_IEffect::Deserialize)
     *
     * What it does:
     * Deserializes one `WeakPtr<IEffect>` payload from a tracked pointer lane.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006751E0 (FUN_006751E0, Moho::WeakPtr_IEffect::Serialize)
     *
     * What it does:
     * Serializes one `WeakPtr<IEffect>` payload as an unowned tracked pointer.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
  };

  template <class T>
  class RWeakPtrType;

  template <>
  class RWeakPtrType<IEffect> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x006748B0 (FUN_006748B0, Moho::RWeakPtrType_IEffect::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00674970 (FUN_00674970, Moho::RWeakPtrType_IEffect::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x00674B00 (FUN_00674B00, Moho::RWeakPtrType_IEffect::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x00674B10 (FUN_00674B10, Moho::RWeakPtrType_IEffect::IsPointer)
     */
    [[nodiscard]] const gpg::RIndexed* IsPointer() const override;

    /**
     * Address: 0x00674950 (FUN_00674950, Moho::RWeakPtrType_IEffect::Init)
     */
    void Init() override;

    /**
     * Address: 0x00674B50 (FUN_00674B50, Moho::RWeakPtrType_IEffect::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x00674B20 (FUN_00674B20, Moho::RWeakPtrType_IEffect::GetCount)
     */
    size_t GetCount(void* obj) const override;
  };

  static_assert(sizeof(RWeakPtrType<IEffect>) == 0x68, "RWeakPtrType<IEffect> size must be 0x68");

  /**
   * Address: 0x00675A50 (FUN_00675A50, register_WeakPtr_IEffect_Type_00)
   *
   * What it does:
   * Constructs/preregisters RTTI for `WeakPtr<IEffect>`.
   */
  [[nodiscard]] gpg::RType* register_WeakPtr_IEffect_Type_00();

  /**
   * Address: 0x00BFC4F0 (FUN_00BFC4F0, cleanup_WeakPtr_IEffect_Type)
   *
   * What it does:
   * Tears down startup-owned `WeakPtr<IEffect>` reflection storage.
   */
  void cleanup_WeakPtr_IEffect_Type();

  /**
   * Address: 0x00BD4DD0 (FUN_00BD4DD0, register_WeakPtr_IEffect_Type_AtExit)
   *
   * What it does:
   * Registers `WeakPtr<IEffect>` reflection and installs process-exit teardown.
   */
  int register_WeakPtr_IEffect_Type_AtExit();
} // namespace moho
