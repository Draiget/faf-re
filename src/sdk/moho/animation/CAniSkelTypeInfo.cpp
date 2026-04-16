#include "CAniSkelTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/animation/CAniSkel.h"

namespace
{
  alignas(moho::CAniSkelTypeInfo) unsigned char gCAniSkelTypeInfoStorage[sizeof(moho::CAniSkelTypeInfo)]{};
  bool gCAniSkelTypeInfoConstructed = false;

  [[nodiscard]] moho::CAniSkelTypeInfo* AcquireCAniSkelTypeInfo()
  {
    if (!gCAniSkelTypeInfoConstructed) {
      new (gCAniSkelTypeInfoStorage) moho::CAniSkelTypeInfo();
      gCAniSkelTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::CAniSkelTypeInfo*>(gCAniSkelTypeInfoStorage);
  }

  struct CAniSkelTypeInfoBootstrap
  {
    CAniSkelTypeInfoBootstrap()
    {
      (void)moho::register_CAniSkelTypeInfoAtexit();
    }
  };

  CAniSkelTypeInfoBootstrap gCAniSkelTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00549FF0 (FUN_00549FF0, scalar deleting destructor thunk)
   */
  CAniSkelTypeInfo::~CAniSkelTypeInfo() = default;

  /**
   * Address: 0x00549FE0 (FUN_00549FE0)
   */
  const char* CAniSkelTypeInfo::GetName() const
  {
    return "CAniSkel";
  }

  /**
   * Address: 0x00549FC0 (FUN_00549FC0)
   *
   * What it does:
   * Initializes reflection metadata for `CAniSkel` (`sizeof = 0x2C`).
   */
  void CAniSkelTypeInfo::Init()
  {
    size_ = sizeof(CAniSkel);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00549F60 (FUN_00549F60, preregister_CAniSkelTypeInfo)
   */
  gpg::RType* preregister_CAniSkelTypeInfo()
  {
    CAniSkelTypeInfo* const typeInfo = AcquireCAniSkelTypeInfo();
    gpg::PreRegisterRType(typeid(CAniSkel), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00BF4480 (FUN_00BF4480, cleanup_CAniSkelTypeInfo)
   */
  void cleanup_CAniSkelTypeInfo()
  {
    if (!gCAniSkelTypeInfoConstructed) {
      return;
    }

    CAniSkelTypeInfo* const typeInfo = AcquireCAniSkelTypeInfo();
    typeInfo->fields_ = msvc8::vector<gpg::RField>{};
    typeInfo->bases_ = msvc8::vector<gpg::RField>{};
  }

  /**
   * Address: 0x00BC9890 (FUN_00BC9890, register_CAniSkelTypeInfoAtexit)
   */
  int register_CAniSkelTypeInfoAtexit()
  {
    (void)preregister_CAniSkelTypeInfo();
    return std::atexit(&cleanup_CAniSkelTypeInfo);
  }
} // namespace moho
