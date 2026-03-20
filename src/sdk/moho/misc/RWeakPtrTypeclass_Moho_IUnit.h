#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/WeakPtr.h"
#include "moho/unit/core/IUnit.h"

namespace moho
{
  template <class T>
  class RWeakPtrType;

  /**
   * Address family:
   * - 0x00541600 / 0x005416C0 / 0x00541850 / 0x00541860 / 0x005416A0 (FA)
   * - 0x1012EFC0 / 0x1012F080 / 0x1012F1D0 / 0x1012F1E0 / 0x1012F060 (MohoEngine)
   *
   * What it is:
   * Reflection helper specialization for `WeakPtr<IUnit>`.
   */
  template <>
  class RWeakPtrType<IUnit> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x00541600 (FA), 0x1012EFC0 (MohoEngine)
     *
     * What it does:
     * Builds/caches lexical type name `"WeakPtr<%s>"` from `IUnit` reflection type.
     */
    const char* GetName() const override;

    /**
     * Address: 0x005416C0 (FA), 0x1012F080 (MohoEngine)
     *
     * What it does:
     * Returns `"NULL"` for empty weak pointers, otherwise wraps pointee lexical with brackets.
     */
    msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x00541850 (FA), 0x1012F1D0 (MohoEngine)
     */
    const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x00541860 (FA), 0x1012F1E0 (MohoEngine)
     */
    const gpg::RIndexed* IsPointer() const override;

    /**
     * Address: 0x005416A0 (FA), 0x1012F060 (MohoEngine)
     *
     * What it does:
     * Initializes size/version and weak-pointer serialization callbacks.
     */
    void Init() override;

    /**
     * Address: 0x00541920 (FA), 0x1012F220 (MohoEngine)
     *
     * What it does:
     * Returns element 0 as `RRef` (asserts on any other index).
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x00541910 (FA), 0x1012F1F0 (MohoEngine)
     *
     * What it does:
     * Returns 1 only when weak pointer has a non-sentinel target.
     */
    size_t GetCount(void* obj) const override;
  };

  static_assert(sizeof(RWeakPtrType<IUnit>) == 0x68, "RWeakPtrType<IUnit> size must be 0x68");
} // namespace moho
