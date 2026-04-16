#include "moho/ai/CAiNavigatorAirTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiNavigatorAir.h"

using namespace moho;

namespace
{
  alignas(CAiNavigatorAirTypeInfo) unsigned char gCAiNavigatorAirTypeInfoStorage[sizeof(CAiNavigatorAirTypeInfo)] = {};
  bool gCAiNavigatorAirTypeInfoConstructed = false;

  [[nodiscard]] CAiNavigatorAirTypeInfo* AcquireCAiNavigatorAirTypeInfo()
  {
    if (!gCAiNavigatorAirTypeInfoConstructed) {
      new (gCAiNavigatorAirTypeInfoStorage) CAiNavigatorAirTypeInfo();
      gCAiNavigatorAirTypeInfoConstructed = true;
    }

    return reinterpret_cast<CAiNavigatorAirTypeInfo*>(gCAiNavigatorAirTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedCAiNavigatorImplType()
  {
    gpg::RType* type = CAiNavigatorImpl::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiNavigatorImpl));
      CAiNavigatorImpl::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x005A7E70 (FUN_005A7E70)
   *
   * What it does:
   * Adds the reflected `CAiNavigatorImpl` base entry to the air navigator RTTI
   * node.
   */
  void AddCAiNavigatorImplBase(gpg::RType& typeInfo)
  {
    gpg::RType* const baseType = CachedCAiNavigatorImplType();

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo.AddBase(baseField);
  }

  /**
   * Address: 0x00BF6EE0 (FUN_00BF6EE0)
   *
   * What it does:
   * Tears down startup-owned `CAiNavigatorAirTypeInfo` storage.
   */
  void cleanup_CAiNavigatorAirTypeInfo()
  {
    if (!gCAiNavigatorAirTypeInfoConstructed) {
      return;
    }

    AcquireCAiNavigatorAirTypeInfo()->~CAiNavigatorAirTypeInfo();
    gCAiNavigatorAirTypeInfoConstructed = false;
  }
} // namespace

/**
 * Address: 0x005A5460 (FUN_005A5460, ctor)
 *
 * What it does:
 * Preregisters `CAiNavigatorAir` RTTI so lookup resolves to this type helper.
 */
CAiNavigatorAirTypeInfo::CAiNavigatorAirTypeInfo()
{
  gpg::PreRegisterRType(typeid(CAiNavigatorAir), this);
}

/**
 * Address: 0x005A54F0 (FUN_005A54F0, scalar deleting thunk)
 */
CAiNavigatorAirTypeInfo::~CAiNavigatorAirTypeInfo() = default;

/**
 * Address: 0x005A54E0 (FUN_005A54E0, ?GetName@CAiNavigatorAirTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiNavigatorAirTypeInfo::GetName() const
{
  return "CAiNavigatorAir";
}

/**
 * Address: 0x005A54C0 (FUN_005A54C0, ?Init@CAiNavigatorAirTypeInfo@Moho@@UAEXXZ)
 */
void CAiNavigatorAirTypeInfo::Init()
{
  size_ = sizeof(CAiNavigatorAir);
  gpg::RType::Init();

  AddCAiNavigatorImplBase(*this);

  Finish();
}

/**
 * Address: 0x00BCC820 (FUN_00BCC820)
 *
 * What it does:
 * Constructs startup-owned `CAiNavigatorAirTypeInfo` storage and installs
 * process-exit cleanup.
 */
int moho::register_CAiNavigatorAirTypeInfo()
{
  (void)AcquireCAiNavigatorAirTypeInfo();
  return std::atexit(&cleanup_CAiNavigatorAirTypeInfo);
}

namespace
{
  struct CAiNavigatorAirTypeInfoBootstrap
  {
    CAiNavigatorAirTypeInfoBootstrap()
    {
      (void)moho::register_CAiNavigatorAirTypeInfo();
    }
  };

  [[maybe_unused]] CAiNavigatorAirTypeInfoBootstrap gCAiNavigatorAirTypeInfoBootstrap;
} // namespace

