#include "moho/serialization/PrefetchHandleBaseTypeInfo.h"

#include <typeinfo>

#include "moho/serialization/PrefetchHandleBase.h"

namespace moho
{
  /**
   * Address: 0x004ABBF0 (FUN_004ABBF0, ??0PrefetchHandleBaseTypeInfo@Moho@@QAE@@Z)
   */
  PrefetchHandleBaseTypeInfo::PrefetchHandleBaseTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(PrefetchHandleBase), this);
  }

  /**
   * Address: 0x004ABC80 (FUN_004ABC80, Moho::PrefetchHandleBaseTypeInfo::dtr)
   */
  PrefetchHandleBaseTypeInfo::~PrefetchHandleBaseTypeInfo() = default;

  /**
   * Address: 0x004ABC70 (FUN_004ABC70, Moho::PrefetchHandleBaseTypeInfo::GetName)
   */
  const char* PrefetchHandleBaseTypeInfo::GetName() const
  {
    return "PrefetchHandleBase";
  }

  /**
   * Address: 0x004ABC50 (FUN_004ABC50, Moho::PrefetchHandleBaseTypeInfo::Init)
   */
  void PrefetchHandleBaseTypeInfo::Init()
  {
    size_ = sizeof(PrefetchHandleBase);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
