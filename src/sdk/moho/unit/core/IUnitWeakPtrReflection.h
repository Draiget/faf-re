#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/WeakPtr.h"
#include "moho/unit/core/IUnit.h"

namespace moho
{
  template <class T>
  class RWeakPtrType;

  /**
   * Address: 0x00541400 (FUN_00541400, preregister_IUnitTypeInfoStartup)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `IUnit`.
   */
  [[nodiscard]] gpg::RType* preregister_IUnitTypeInfoStartup();

  /**
   * Address: 0x00541B40 (FUN_00541B40, preregister_WeakPtrIUnitTypeStartup)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `WeakPtr<IUnit>`.
   */
  [[nodiscard]] gpg::RType* preregister_WeakPtrIUnitTypeStartup();

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
     * Address: 0x005418A0 (FUN_005418A0, Moho::RWeakPtrType_IUnit::SubscriptIndex)
     * Address: 0x1012F220 (MohoEngine)
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

namespace gpg
{
  template <class T>
  class RFastVectorType;

  /**
   * Address family:
   * - 0x0056BDF0 / 0x0056BEB0 / 0x0056BF40 / 0x0056BE90 (FA)
   * - 0x1015A110 / 0x1015A1D0 / 0x1015A270 / 0x1015A1B0 (MohoEngine)
   *
   * What it is:
   * Reflection helper specialization for `fastvector<WeakPtr<IUnit>>`.
   */
  template <>
  class RFastVectorType<moho::WeakPtr<moho::IUnit>> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x0056BDF0 (FA), 0x1015A110 (MohoEngine)
     *
     * What it does:
     * Builds/caches lexical type name `"fastvector<%s>"` from `WeakPtr<IUnit>` reflection type.
     */
    const char* GetName() const override;

    /**
     * Address: 0x0056BEB0 (FA), 0x1015A1D0 (MohoEngine)
     *
     * What it does:
     * Appends vector size info to the base lexical string.
     */
    msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x0056BF40 (FA), 0x1015A270 (MohoEngine)
     */
    const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x0056BE90 (FA), 0x1015A1B0 (MohoEngine)
     *
     * What it does:
     * Initializes size/version and vector serialization callbacks.
     */
    void Init() override;

    /**
     * Address: 0x0056BF20 (FA), 0x1015A310 (MohoEngine)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x0056BF10 (FA), 0x1015A280 (MohoEngine)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x0056BF00 (FA), 0x1015A290 (MohoEngine)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(
    sizeof(RFastVectorType<moho::WeakPtr<moho::IUnit>>) == 0x68,
    "RFastVectorType<WeakPtr<IUnit>> size must be 0x68"
  );

  /**
   * Address: 0x00571B90 (FUN_00571B90, preregister_FastVectorWeakPtrIUnitTypeStartup)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for
   * `gpg::fastvector<moho::WeakPtr<moho::IUnit>>`.
   */
  [[nodiscard]] gpg::RType* preregister_FastVectorWeakPtrIUnitTypeStartup();
} // namespace gpg
