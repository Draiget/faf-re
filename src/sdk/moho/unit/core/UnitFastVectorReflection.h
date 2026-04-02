#pragma once

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/WeakPtr.h"

namespace moho
{
  class Entity;
  class ReconBlip;
} // namespace moho

namespace gpg
{
  template <class T>
  class RFastVectorType;

  template <>
  class RFastVectorType<moho::WeakPtr<moho::Entity>> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x006AE400 (FUN_006AE400, gpg::RFastVectorType_WeakPtr_Entity::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006AE4C0 (FUN_006AE4C0, gpg::RFastVectorType_WeakPtr_Entity::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x006AE550 (FUN_006AE550, gpg::RFastVectorType_WeakPtr_Entity::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x006AE4A0 (FUN_006AE4A0, gpg::RFastVectorType_WeakPtr_Entity::Init)
     */
    void Init() override;

    /**
     * Address: 0x006AE5F0 (FUN_006AE5F0, gpg::RFastVectorType_WeakPtr_Entity::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x006AE560 (FUN_006AE560, gpg::RFastVectorType_WeakPtr_Entity::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x006AE570 (FUN_006AE570, gpg::RFastVectorType_WeakPtr_Entity::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(
    sizeof(RFastVectorType<moho::WeakPtr<moho::Entity>>) == 0x68,
    "RFastVectorType<WeakPtr<Entity>> size must be 0x68"
  );

  template <>
  class RFastVectorType<moho::ReconBlip*> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x006AE630 (FUN_006AE630, gpg::RFastVectorType_ReconBlip_P::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006AE6D0 (FUN_006AE6D0, gpg::RFastVectorType_ReconBlip_P::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x006AE760 (FUN_006AE760, gpg::RFastVectorType_ReconBlip_P::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x006AE6B0 (FUN_006AE6B0, gpg::RFastVectorType_ReconBlip_P::Init)
     */
    void Init() override;

    /**
     * Address: 0x006AE7A0 (FUN_006AE7A0, gpg::RFastVectorType_ReconBlip_P::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x006AE770 (FUN_006AE770, gpg::RFastVectorType_ReconBlip_P::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x006AE780 (FUN_006AE780, gpg::RFastVectorType_ReconBlip_P::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(RFastVectorType<moho::ReconBlip*>) == 0x68, "RFastVectorType<ReconBlip*> size must be 0x68");
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x006B1710 (FUN_006B1710, register_FastVectorWeakPtrEntityType_00)
   *
   * What it does:
   * Constructs/preregisters RTTI for `fastvector<WeakPtr<Entity>>`.
   */
  [[nodiscard]] gpg::RType* register_FastVectorWeakPtrEntityType_00();

  /**
   * Address: 0x00BFDB80 (FUN_00BFDB80, cleanup_FastVectorWeakPtrEntityType)
   *
   * What it does:
   * Tears down startup-owned `fastvector<WeakPtr<Entity>>` reflection storage.
   */
  void cleanup_FastVectorWeakPtrEntityType();

  /**
   * Address: 0x00BD6BE0 (FUN_00BD6BE0, register_FastVectorWeakPtrEntityType_AtExit)
   *
   * What it does:
   * Registers `fastvector<WeakPtr<Entity>>` reflection and installs process-exit teardown.
   */
  int register_FastVectorWeakPtrEntityType_AtExit();

  /**
   * Address: 0x006B1780 (FUN_006B1780, register_FastVectorReconBlipPtrType_00)
   *
   * What it does:
   * Constructs/preregisters RTTI for `fastvector<ReconBlip*>`.
   */
  [[nodiscard]] gpg::RType* register_FastVectorReconBlipPtrType_00();

  /**
   * Address: 0x00BFDB20 (FUN_00BFDB20, cleanup_FastVectorReconBlipPtrType)
   *
   * What it does:
   * Tears down startup-owned `fastvector<ReconBlip*>` reflection storage.
   */
  void cleanup_FastVectorReconBlipPtrType();

  /**
   * Address: 0x00BD6C00 (FUN_00BD6C00, register_FastVectorReconBlipPtrType_AtExit)
   *
   * What it does:
   * Registers `fastvector<ReconBlip*>` reflection and installs process-exit teardown.
   */
  int register_FastVectorReconBlipPtrType_AtExit();
} // namespace moho
