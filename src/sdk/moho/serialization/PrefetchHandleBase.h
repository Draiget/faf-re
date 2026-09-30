#pragma once

#include <cstddef>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
}

namespace moho
{
  class CPrefetchSet;
  class PrefetchHandleBase;
  struct ResourceRecord;

  /**
   * What a prefetch handle shares: the record it prefetches, what the prefetch
   * thread produced for it, and, once something loaded it, the resource itself,
   * held strongly so the resource outlives every other user while the handle
   * does. `ResourceRecord::mPrefetch` refers back to it weakly.
   *
   * Address: 0x004A9920 (FUN_004A9920 -- the implicit destructor: `mResource`
   * then `mPrefetchData` released; reached from the control block's `dispose`
   * 0x004AFA80 and `checked_delete` 0x004AFAE0 and 0x004AFC11. Formerly
   * `ReleaseDualSharedPairs` over a `DualSharedPairCleanupView` in
   * moho/resource/ResourceManager.cpp (RULE ONE), removed 2026-09-30.)
   */
  class PrefetchData
  {
  public:
    explicit PrefetchData(ResourceRecord* const record) noexcept
      : mRecord(record)
    {}

    ResourceRecord* mRecord;                  // +0x00
    boost::shared_ptr<void> mPrefetchData;    // +0x04 (`ResourceFactoryBase::Preload`'s result)
    boost::shared_ptr<void> mResource;        // +0x0C
  };
  static_assert(offsetof(PrefetchData, mRecord) == 0x00, "PrefetchData::mRecord offset must be 0x00");
  static_assert(offsetof(PrefetchData, mPrefetchData) == 0x04, "PrefetchData::mPrefetchData offset must be 0x04");
  static_assert(offsetof(PrefetchData, mResource) == 0x0C, "PrefetchData::mResource offset must be 0x0C");
  static_assert(sizeof(PrefetchData) == 0x14, "PrefetchData size must be 0x14");

  /**
   * Address: 0x004ABF30 (FUN_004ABF30, ?RES_PrefetchResource@Moho@@YA?AVPrefetchHandleBase@1@VStrArg@gpg@@PBVRType@4@@Z)
   *
   * What it does:
   * `ResourceManager::PrefetchResource` on the singleton.
   */
  [[nodiscard]] PrefetchHandleBase RES_PrefetchResource(gpg::StrArg resourcePath, const gpg::RType* type);

  /**
   * Address: 0x004A5060 (FUN_004A5060, Moho::RES_RegisterPrefetchType)
   *
   * What it does:
   * Registers one textual prefetch key to resolved reflected type metadata.
   */
  void RES_RegisterPrefetchType(gpg::StrArg key, gpg::RType* type);

  /**
   * Address: helper around FUN_004A5AA0/FUN_004A5BB0 map lanes.
   *
   * What it does:
   * Resolves one prefetch kind key to the registered reflected payload type.
   */
  [[nodiscard]] gpg::RType* RES_FindPrefetchType(gpg::StrArg key);

  /**
   * Address: 0x004A5120 (FUN_004A5120)
   *
   * What it does:
   * Ensures `CPrefetchSet` reflection descriptor preregistration is materialized.
   */
  void EnsurePrefetchSetTypeRegistration();

  /**
   * Address: 0x00BC5BC0 (FUN_00BC5BC0, register_PrefetchHandleBaseTypeInfo)
   *
   * What it does:
   * Materializes prefetch-handle type-info startup registration.
   */
  void register_PrefetchHandleBaseTypeInfo();

  class PrefetchHandleBase
  {
  public:
    static gpg::RType* sType;

    PrefetchHandleBase() = default;

    /**
     * Address: 0x0043CB70 (FUN_0043CB70, Moho::WeakPtr_PrefetchData::move)
     *
     * What it does:
     * Adopts `data`, taken by value: the member is copied from the parameter,
     * which is then released. `ResourceManager::PrefetchResource`
     * (0x004AB084), `RES_LoadPrefetchData` (0x004457E8) and
     * `CD3DDeviceResources::LoadPrefetchData` (0x0044156B) build their results
     * through it.
     */
    explicit PrefetchHandleBase(const boost::shared_ptr<PrefetchData> data)
      : mPtr(data)
    {}

    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x004AF0B0 (FUN_004AF0B0, Moho::PrefetchHandleBase::MemberDeserialize)
     *
     * What it does:
     * Reads path/type handle and resolves prefetch payload shared pointer.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * What it does:
     * Saves the resource path and type of the prefetched record. Inlined
     * into `SerSaveLoadHelper<PrefetchHandleBase>::Serialize` 0x004ABD40.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x004ABE00 (FUN_004ABE00, Moho::PrefetchHandleBase::GetName)
     *
     * What it does:
     * Returns the prefetch payload path lane for this handle.
     */
    [[nodiscard]] const msvc8::string& GetName() const;

    /**
     * Address: 0x004ABE10 (FUN_004ABE10, Moho::PrefetchHandleBase::GetResourceRType)
     *
     * What it does:
     * Returns the prefetch payload reflected resource type lane.
     */
    [[nodiscard]] gpg::RType* GetResourceRType() const;

  public:
    boost::shared_ptr<PrefetchData> mPtr; // +0x00
  };

  static_assert(offsetof(PrefetchHandleBase, mPtr) == 0x00, "PrefetchHandleBase::mPtr offset must be 0x00");
  static_assert(sizeof(PrefetchHandleBase) == 0x08, "PrefetchHandleBase size must be 0x08");
} // namespace moho
