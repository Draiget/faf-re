#include "CAniDefaultSkelTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/animation/CAniDefaultSkel.h"
#include "moho/animation/CAniSkel.h"

namespace
{
  alignas(moho::CAniDefaultSkelTypeInfo)
    unsigned char gCAniDefaultSkelTypeInfoStorage[sizeof(moho::CAniDefaultSkelTypeInfo)]{};
  bool gCAniDefaultSkelTypeInfoConstructed = false;

  [[nodiscard]] moho::CAniDefaultSkelTypeInfo* AcquireCAniDefaultSkelTypeInfo()
  {
    if (!gCAniDefaultSkelTypeInfoConstructed) {
      new (gCAniDefaultSkelTypeInfoStorage) moho::CAniDefaultSkelTypeInfo();
      gCAniDefaultSkelTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::CAniDefaultSkelTypeInfo*>(gCAniDefaultSkelTypeInfoStorage);
  }

  void AddCAniSkelBase(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = gpg::LookupRType(typeid(moho::CAniSkel));

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  struct CAniDefaultSkelTypeInfoBootstrap
  {
    CAniDefaultSkelTypeInfoBootstrap()
    {
      (void)moho::register_CAniDefaultSkelTypeInfoAtexit();
    }
  };

  CAniDefaultSkelTypeInfoBootstrap gCAniDefaultSkelTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x0054A9C0 (FUN_0054A9C0, scalar deleting destructor thunk)
   */
  CAniDefaultSkelTypeInfo::~CAniDefaultSkelTypeInfo() = default;

  /**
   * Address: 0x0054A9B0 (FUN_0054A9B0)
   */
  const char* CAniDefaultSkelTypeInfo::GetName() const
  {
    return "CAniDefaultSkel";
  }

  /**
   * Address: 0x0054A990 (FUN_0054A990)
   *
   * What it does:
   * Initializes reflection metadata for `CAniDefaultSkel` and registers
   * `CAniSkel` as base metadata.
   */
  void CAniDefaultSkelTypeInfo::Init()
  {
    size_ = sizeof(CAniDefaultSkel);
    gpg::RType::Init();
    AddCAniSkelBase(this);
    Finish();
  }

  /**
   * Address: 0x0054A930 (FUN_0054A930, preregister_CAniDefaultSkelTypeInfo)
   */
  gpg::RType* preregister_CAniDefaultSkelTypeInfo()
  {
    CAniDefaultSkelTypeInfo* const typeInfo = AcquireCAniDefaultSkelTypeInfo();
    gpg::PreRegisterRType(typeid(CAniDefaultSkel), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BF44E0 (FUN_00BF44E0, cleanup_CAniDefaultSkelTypeInfo)
   */
  void cleanup_CAniDefaultSkelTypeInfo()
  {
    if (!gCAniDefaultSkelTypeInfoConstructed) {
      return;
    }

    CAniDefaultSkelTypeInfo* const typeInfo = AcquireCAniDefaultSkelTypeInfo();
    typeInfo->fields_ = msvc8::vector<gpg::RField>{};
    typeInfo->bases_ = msvc8::vector<gpg::RField>{};
  }

  /**
   * Address: 0x00BC98B0 (FUN_00BC98B0, register_CAniDefaultSkelTypeInfoAtexit)
   */
  int register_CAniDefaultSkelTypeInfoAtexit()
  {
    (void)preregister_CAniDefaultSkelTypeInfo();
    return std::atexit(&cleanup_CAniDefaultSkelTypeInfo);
  }
} // namespace moho
