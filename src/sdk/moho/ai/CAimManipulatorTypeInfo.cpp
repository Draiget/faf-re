#include "moho/ai/CAimManipulatorTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAimManipulator.h"
#include "moho/animation/IAniManipulator.h"

namespace
{
  alignas(moho::CAimManipulatorTypeInfo) unsigned char gCAimManipulatorTypeInfoStorage[sizeof(moho::CAimManipulatorTypeInfo)] = {};
  bool gCAimManipulatorTypeInfoConstructed = false;

  [[nodiscard]] moho::CAimManipulatorTypeInfo* AcquireCAimManipulatorTypeInfo()
  {
    if (!gCAimManipulatorTypeInfoConstructed) {
      new (gCAimManipulatorTypeInfoStorage) moho::CAimManipulatorTypeInfo();
      gCAimManipulatorTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::CAimManipulatorTypeInfo*>(gCAimManipulatorTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedCAimManipulatorType()
  {
    gpg::RType* type = moho::CAimManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CAimManipulator));
      moho::CAimManipulator::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedIAniManipulatorType()
  {
    gpg::RType* type = moho::IAniManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IAniManipulator));
      moho::IAniManipulator::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RRef MakeCAimManipulatorRef(moho::CAimManipulator* const object)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = CachedCAimManipulatorType();
    return out;
  }

  /**
   * Address: 0x00BFA900 (FUN_00BFA900, cleanup_CAimManipulatorTypeInfo)
   *
   * What it does:
   * Tears down static `CAimManipulatorTypeInfo` storage at process exit.
   */
  void cleanup_CAimManipulatorTypeInfo()
  {
    if (!gCAimManipulatorTypeInfoConstructed) {
      return;
    }

    AcquireCAimManipulatorTypeInfo()->~CAimManipulatorTypeInfo();
    gCAimManipulatorTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0062FED0 (FUN_0062FED0, Moho::CAimManipulatorTypeInfo::CAimManipulatorTypeInfo)
   */
  CAimManipulatorTypeInfo::CAimManipulatorTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CAimManipulator), this);
  }

  /**
   * Address: 0x0062FF80 (FUN_0062FF80, scalar deleting thunk)
   */
  CAimManipulatorTypeInfo::~CAimManipulatorTypeInfo() = default;

  /**
   * Address: 0x0062FF70 (FUN_0062FF70, Moho::CAimManipulatorTypeInfo::GetName)
   */
  const char* CAimManipulatorTypeInfo::GetName() const
  {
    return "CAimManipulator";
  }

  /**
   * Address: 0x0062FF30 (FUN_0062FF30, Moho::CAimManipulatorTypeInfo::Init)
   */
  void CAimManipulatorTypeInfo::Init()
  {
    size_ = 0x110;
    newRefFunc_ = &CAimManipulatorTypeInfo::NewRef;
    ctorRefFunc_ = &CAimManipulatorTypeInfo::CtrRef;
    deleteFunc_ = &CAimManipulatorTypeInfo::Delete;
    dtrFunc_ = &CAimManipulatorTypeInfo::Destruct;
    AddBase_IAniManipulator(this);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00632EA0 (FUN_00632EA0, Moho::CAimManipulatorTypeInfo::NewRef)
   */
  gpg::RRef CAimManipulatorTypeInfo::NewRef()
  {
    return MakeCAimManipulatorRef(nullptr);
  }

  /**
   * Address: 0x00632F40 (FUN_00632F40, Moho::CAimManipulatorTypeInfo::CtrRef)
   */
  gpg::RRef CAimManipulatorTypeInfo::CtrRef(void* const objectStorage)
  {
    return MakeCAimManipulatorRef(static_cast<CAimManipulator*>(objectStorage));
  }

  /**
   * Address: 0x00632F20 (FUN_00632F20, Moho::CAimManipulatorTypeInfo::Delete)
   */
  void CAimManipulatorTypeInfo::Delete(void* const objectStorage)
  {
    (void)objectStorage;
  }

  /**
   * Address: 0x00632FB0 (FUN_00632FB0, Moho::CAimManipulatorTypeInfo::Destruct)
   */
  void CAimManipulatorTypeInfo::Destruct(void* const objectStorage)
  {
    (void)objectStorage;
  }

  /**
   * Address: 0x00632FD0 (FUN_00632FD0, Moho::CAimManipulatorTypeInfo::AddBase_IAniManipulator)
   */
  void CAimManipulatorTypeInfo::AddBase_IAniManipulator(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedIAniManipulatorType();
    if (!baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00BD2270 (FUN_00BD2270, register_CAimManipulatorTypeInfo)
   *
   * What it does:
   * Registers `CAimManipulator` RTTI startup owner and installs process-exit
   * cleanup for its static storage.
   */
  void register_CAimManipulatorTypeInfo()
  {
    (void)AcquireCAimManipulatorTypeInfo();
    (void)std::atexit(&cleanup_CAimManipulatorTypeInfo);
  }
} // namespace moho
