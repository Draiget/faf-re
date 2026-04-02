#include "moho/serialization/typeinfo/Sphere3fTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

namespace
{
  alignas(moho::Sphere3fTypeInfo) unsigned char gSphere3fTypeInfoStorage[sizeof(moho::Sphere3fTypeInfo)] = {};
  bool gSphere3fTypeInfoConstructed = false;

  [[nodiscard]] moho::Sphere3fTypeInfo& AcquireSphere3fTypeInfo()
  {
    if (!gSphere3fTypeInfoConstructed) {
      new (gSphere3fTypeInfoStorage) moho::Sphere3fTypeInfo();
      gSphere3fTypeInfoConstructed = true;
    }

    return *reinterpret_cast<moho::Sphere3fTypeInfo*>(gSphere3fTypeInfoStorage);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00472EB0 (FUN_00472EB0, Moho::Sphere3fTypeInfo::Sphere3fTypeInfo)
   */
  Sphere3fTypeInfo::Sphere3fTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(Wm3::Sphere3<float>), this);
  }

  /**
   * Address: 0x00472F40 (FUN_00472F40, Moho::Sphere3fTypeInfo::~Sphere3fTypeInfo)
   */
  Sphere3fTypeInfo::~Sphere3fTypeInfo()
  {
    fields_ = {};
    bases_ = {};
  }

  /**
   * Address: 0x00472F30 (FUN_00472F30, Moho::Sphere3fTypeInfo::GetName)
   */
  const char* Sphere3fTypeInfo::GetName() const
  {
    return "Sphere3f";
  }

  /**
   * Address: 0x00472F10 (FUN_00472F10, Moho::Sphere3fTypeInfo::Init)
   */
  void Sphere3fTypeInfo::Init()
  {
    size_ = sizeof(Wm3::Sphere3<float>);
    gpg::RType::Init();
    Finish();
  }

  /**
   * What it does:
   * Tears down startup-owned Sphere3f type metadata singleton storage.
   */
  static void cleanup_Sphere3fTypeInfo()
  {
    if (!gSphere3fTypeInfoConstructed) {
      return;
    }

    AcquireSphere3fTypeInfo().~Sphere3fTypeInfo();
    gSphere3fTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BC4950 (FUN_00BC4950, register_Sphere3fTypeInfo)
   */
  int register_Sphere3fTypeInfo()
  {
    (void)AcquireSphere3fTypeInfo();
    return std::atexit(&cleanup_Sphere3fTypeInfo);
  }
} // namespace moho

namespace
{
  struct Sphere3fTypeInfoBootstrap
  {
    Sphere3fTypeInfoBootstrap()
    {
      (void)moho::register_Sphere3fTypeInfo();
    }
  };

  [[maybe_unused]] Sphere3fTypeInfoBootstrap gSphere3fTypeInfoBootstrap;
} // namespace
