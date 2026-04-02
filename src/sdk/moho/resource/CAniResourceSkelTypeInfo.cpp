#include "moho/resource/CAniResourceSkelTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/resource/CAniResourceSkel.h"
#include "moho/resource/ResourceReflectionHelpers.h"

#pragma init_seg(lib)

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
    resource_reflection::AddBase(this, resource_reflection::ResolveCAniSkelType());
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
