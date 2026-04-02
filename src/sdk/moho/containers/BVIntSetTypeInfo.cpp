#include "moho/containers/BVIntSetTypeInfo.h"

#include <typeinfo>

#include "moho/containers/BVIntSet.h"

namespace moho
{
  /**
   * Address: 0x00401460 (FUN_00401460, Moho::BVIntSetTypeInfo::BVIntSetTypeInfo)
   *
   * What it does:
   * Constructs the descriptor and preregisters it for `BVIntSet` RTTI lookup.
   */
  BVIntSetTypeInfo::BVIntSetTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(BVIntSet), this);
  }

  /**
   * Address: 0x004014F0 (FUN_004014F0, deleting dtor lane)
   */
  BVIntSetTypeInfo::~BVIntSetTypeInfo() = default;

  /**
   * Address: 0x004014E0 (FUN_004014E0, Moho::BVIntSetTypeInfo::GetName)
   */
  const char* BVIntSetTypeInfo::GetName() const
  {
    return "BVIntSet";
  }

  /**
   * Address: 0x004014C0 (FUN_004014C0, Moho::BVIntSetTypeInfo::Init)
   *
   * What it does:
   * Sets BVIntSet size metadata and finalizes reflection setup.
   */
  void BVIntSetTypeInfo::Init()
  {
    size_ = sizeof(BVIntSet);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
