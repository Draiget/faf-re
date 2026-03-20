#include "CAniDefaultSkelTypeInfo.h"

#include <typeinfo>

#include "moho/animation/CAniDefaultSkel.h"
#include "moho/animation/CAniSkel.h"

namespace
{
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
} // namespace moho
