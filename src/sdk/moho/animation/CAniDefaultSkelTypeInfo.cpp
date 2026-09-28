#include "CAniDefaultSkelTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/animation/CAniDefaultSkel.h"
#include "moho/animation/CAniSkel.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Address: 0x00BF44E0 (FUN_00BF44E0, atexit destructor of the CAniDefaultSkelTypeInfo object)
   */
  [[nodiscard]] moho::CAniDefaultSkelTypeInfo* AcquireCAniDefaultSkelTypeInfo()
  {
    static moho::CAniDefaultSkelTypeInfo sInstance;
    return &sInstance;
  }

  struct CAniDefaultSkelTypeInfoBootstrap
  {
    CAniDefaultSkelTypeInfoBootstrap()
    {
      moho::register_CAniDefaultSkelTypeInfoAtexit();
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
 * Address: 0x0054DDF0 (FUN_0054DDF0, Moho::CAniDefaultSkelTypeInfo::AddBase_CAniSkel)
 *
 * What it does:
 * Registers `CAniSkel` as this type's reflected base at offset 0.
 */
void CAniDefaultSkelTypeInfo::AddBase_CAniSkel(gpg::RType* const typeInfo)
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
    AddBase_CAniSkel(this);
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
   * Address: 0x00BC98B0 (FUN_00BC98B0, register_CAniDefaultSkelTypeInfoAtexit)
   */
  void register_CAniDefaultSkelTypeInfoAtexit()
  {
    (void)preregister_CAniDefaultSkelTypeInfo();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_CAniDefaultSkelTypeInfo_08e177, moho::preregister_CAniDefaultSkelTypeInfo)
