#include "moho/ai/CAiNavigatorLandTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiNavigatorLand.h"

using namespace moho;

namespace
{
  alignas(CAiNavigatorLandTypeInfo) unsigned char gCAiNavigatorLandTypeInfoStorage[sizeof(CAiNavigatorLandTypeInfo)] = {};
  bool gCAiNavigatorLandTypeInfoConstructed = false;

  [[nodiscard]] CAiNavigatorLandTypeInfo* AcquireCAiNavigatorLandTypeInfo()
  {
    if (!gCAiNavigatorLandTypeInfoConstructed) {
      new (gCAiNavigatorLandTypeInfoStorage) CAiNavigatorLandTypeInfo();
      gCAiNavigatorLandTypeInfoConstructed = true;
    }

    return reinterpret_cast<CAiNavigatorLandTypeInfo*>(gCAiNavigatorLandTypeInfoStorage);
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
   * Address: 0x005A7D90 (FUN_005A7D90)
   *
   * What it does:
   * Adds the reflected `CAiNavigatorImpl` base entry to the land navigator
   * RTTI node.
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
   * Address: 0x00BF6E20 (FUN_00BF6E20)
   *
   * What it does:
   * Tears down startup-owned `CAiNavigatorLandTypeInfo` storage.
   */
  void cleanup_CAiNavigatorLandTypeInfo()
  {
    if (!gCAiNavigatorLandTypeInfoConstructed) {
      return;
    }

    AcquireCAiNavigatorLandTypeInfo()->~CAiNavigatorLandTypeInfo();
    gCAiNavigatorLandTypeInfoConstructed = false;
  }
} // namespace

/**
 * Address: 0x005A4560 (FUN_005A4560, ctor)
 *
 * What it does:
 * Preregisters `CAiNavigatorLand` RTTI so lookup resolves to this type helper.
 */
CAiNavigatorLandTypeInfo::CAiNavigatorLandTypeInfo()
{
  gpg::PreRegisterRType(typeid(CAiNavigatorLand), this);
}

/**
 * Address: 0x005A45F0 (FUN_005A45F0, scalar deleting thunk)
 */
CAiNavigatorLandTypeInfo::~CAiNavigatorLandTypeInfo() = default;

/**
 * Address: 0x005A45E0 (FUN_005A45E0, ?GetName@CAiNavigatorLandTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiNavigatorLandTypeInfo::GetName() const
{
  return "CAiNavigatorLand";
}

/**
 * Address: 0x005A45C0 (FUN_005A45C0, ?Init@CAiNavigatorLandTypeInfo@Moho@@UAEXXZ)
 */
void CAiNavigatorLandTypeInfo::Init()
{
  size_ = sizeof(CAiNavigatorLand);
  gpg::RType::Init();

  AddCAiNavigatorImplBase(*this);

  Finish();
}

/**
 * Address: 0x00BCC780 (FUN_00BCC780)
 *
 * What it does:
 * Constructs startup-owned `CAiNavigatorLandTypeInfo` storage and installs
 * process-exit cleanup.
 */
int moho::register_CAiNavigatorLandTypeInfo()
{
  (void)AcquireCAiNavigatorLandTypeInfo();
  return std::atexit(&cleanup_CAiNavigatorLandTypeInfo);
}

namespace
{
  struct CAiNavigatorLandTypeInfoBootstrap
  {
    CAiNavigatorLandTypeInfoBootstrap()
    {
      (void)moho::register_CAiNavigatorLandTypeInfo();
    }
  };

  [[maybe_unused]] CAiNavigatorLandTypeInfoBootstrap gCAiNavigatorLandTypeInfoBootstrap;
} // namespace
