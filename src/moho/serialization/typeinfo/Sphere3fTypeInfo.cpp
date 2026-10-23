#include "moho/serialization/typeinfo/Sphere3fTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  [[nodiscard]] moho::Sphere3fTypeInfo& AcquireSphere3fTypeInfo()
  {
    static moho::Sphere3fTypeInfo sInstance;
    return sInstance;
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
   * Address: 0x00BC4950 (FUN_00BC4950, register_Sphere3fTypeInfo)
   */
  void register_Sphere3fTypeInfo()
  {
    (void)AcquireSphere3fTypeInfo();
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

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_Sphere3fTypeInfo_96ea18, moho::register_Sphere3fTypeInfo)
