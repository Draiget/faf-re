#include "moho/resource/CAniResourceSkelTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/resource/CAniResourceSkel.h"
#include "moho/resource/ResourceReflectionHelpers.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::CAniResourceSkelTypeInfo;

  alignas(TypeInfo) unsigned char gCAniResourceSkelTypeInfoStorage[sizeof(TypeInfo)];
  bool gCAniResourceSkelTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireCAniResourceSkelTypeInfo()
  {
    if (!gCAniResourceSkelTypeInfoConstructed) {
      new (gCAniResourceSkelTypeInfoStorage) TypeInfo();
      gCAniResourceSkelTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCAniResourceSkelTypeInfoStorage);
  }

  void cleanup_CAniResourceSkelTypeInfo()
  {
    if (!gCAniResourceSkelTypeInfoConstructed) {
      return;
    }

    AcquireCAniResourceSkelTypeInfo().~TypeInfo();
    gCAniResourceSkelTypeInfoConstructed = false;
  }

  struct CAniResourceSkelTypeInfoBootstrap
  {
    CAniResourceSkelTypeInfoBootstrap()
    {
      moho::register_CAniResourceSkelTypeInfo();
    }
  };

  CAniResourceSkelTypeInfoBootstrap gCAniResourceSkelTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00538580 (FUN_00538580, Moho::CAniResourceSkelTypeInfo::CAniResourceSkelTypeInfo)
   */
  CAniResourceSkelTypeInfo::CAniResourceSkelTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CAniResourceSkel), this);
  }

  /**
   * Address: 0x00538610 (FUN_00538610, Moho::CAniResourceSkelTypeInfo::dtr)
   */
  CAniResourceSkelTypeInfo::~CAniResourceSkelTypeInfo() = default;

  /**
   * Address: 0x00538600 (FUN_00538600, Moho::CAniResourceSkelTypeInfo::GetName)
   */
  const char* CAniResourceSkelTypeInfo::GetName() const
  {
    return "CAniResourceSkel";
  }

  /**
 * Address: 0x00539B20 (FUN_00539B20, Moho::CAniResourceSkelTypeInfo::AddBase_CAniSkel)
 *
 * What it does:
 * Registers `CAniSkel` as this type's reflected base at offset 0. The shared
 * resource_reflection::AddBase lane does the field construction; the binary
 * still emits this as a member of the type info, and Init reaches it here.
 */
void CAniResourceSkelTypeInfo::AddBase_CAniSkel(gpg::RType* const typeInfo)
{
  resource_reflection::AddBase(typeInfo, resource_reflection::ResolveCAniSkelType());
}

/**
   * Address: 0x005385E0 (FUN_005385E0, Moho::CAniResourceSkelTypeInfo::Init)
   *
   * What it does:
   * Initializes reflection metadata for `CAniResourceSkel` and registers
   * `CAniSkel` as the single base type.
   */
  void CAniResourceSkelTypeInfo::Init()
  {
    size_ = sizeof(CAniResourceSkel);
    gpg::RType::Init();
    AddBase_CAniSkel(this);
    Finish();
  }

  /**
   * Address: 0x00BC9060 (FUN_00BC9060, register_CAniResourceSkelTypeInfo)
   */
  void register_CAniResourceSkelTypeInfo()
  {
    (void)AcquireCAniResourceSkelTypeInfo();
    (void)std::atexit(&cleanup_CAniResourceSkelTypeInfo);
  }
} // namespace moho


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CAniResourceSkelTypeInfo_66d271, moho::register_CAniResourceSkelTypeInfo)
