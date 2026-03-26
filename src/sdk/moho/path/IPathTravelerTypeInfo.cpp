#include "moho/path/IPathTravelerTypeInfo.h"

#include "moho/path/IPathTraveler.h"

namespace moho
{
  /**
   * Address: 0x0076D5F0 (FUN_0076D5F0, Moho::IPathTravelerTypeInfo::dtr)
   */
  IPathTravelerTypeInfo::~IPathTravelerTypeInfo() = default;

  /**
   * Address: 0x0076D5E0 (FUN_0076D5E0, Moho::IPathTravelerTypeInfo::GetName)
   */
  const char* IPathTravelerTypeInfo::GetName() const
  {
    return "IPathTraveler";
  }

  /**
   * Address: 0x0076D5C0 (FUN_0076D5C0, Moho::IPathTravelerTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::IPathTravelerTypeInfo::Init(gpg::RType *this);
   */
  void IPathTravelerTypeInfo::Init()
  {
    size_ = sizeof(IPathTraveler);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
