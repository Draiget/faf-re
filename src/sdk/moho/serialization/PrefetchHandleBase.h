#pragma once

#include <cstddef>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/resource/PrefetchRuntime.h"

namespace gpg
{
  class ReadArchive;
}

namespace moho
{
  class CPrefetchSet;

  /**
   * Recovered shared prefetch-handle payload.
   *
   * Known mapped lanes:
   * - +0x00 owning request-runtime pointer
   * - +0x04 resolved resource shared `(px,pi)` pair
   * - +0x0C prefetch weak/shared tracking `(px,pi)` pair
   */
  class PrefetchData
  {
  public:
    PrefetchRequestRuntime* mRequest = nullptr; // +0x00
    boost::SharedCountPair mResolved{};         // +0x04
    boost::SharedCountPair mPrefetch{};         // +0x0C
  };
  static_assert(offsetof(PrefetchData, mRequest) == 0x00, "PrefetchData::mRequest offset must be 0x00");
  static_assert(offsetof(PrefetchData, mResolved) == 0x04, "PrefetchData::mResolved offset must be 0x04");
  static_assert(offsetof(PrefetchData, mPrefetch) == 0x0C, "PrefetchData::mPrefetch offset must be 0x0C");
  static_assert(sizeof(PrefetchData) == 0x14, "PrefetchData size must be 0x14");

  /**
   * Address: referenced by FUN_004AF0B0 call chain.
   *
   * What it does:
   * Resolves prefetch payload handle for one resource path and reflected type.
   */
  boost::shared_ptr<PrefetchData>* RES_PrefetchResource(
    boost::shared_ptr<PrefetchData>* outPrefetchData, gpg::StrArg resourcePath, const gpg::RType* type
  );

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

  /**
   * Address: 0x00BC5BE0 (FUN_00BC5BE0, register_PrefetchHandleBaseSerializer)
   *
   * What it does:
   * Materializes prefetch-handle serializer startup registration.
   */
  void register_PrefetchHandleBaseSerializer();

  class PrefetchHandleBase
  {
  public:
    static gpg::RType* sType;

    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x004AF0B0 (FUN_004AF0B0, Moho::PrefetchHandleBase::MemberDeserialize)
     *
     * What it does:
     * Reads path/type handle and resolves prefetch payload shared pointer.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

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
