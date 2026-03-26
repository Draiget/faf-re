#include "moho/render/SEfxCurveTypeInfo.h"

#include "moho/render/SEfxCurve.h"

namespace moho
{
  /**
   * Address: 0x00514C90 (FUN_00514C90, Moho::SEfxCurveTypeInfo::dtr)
   */
  SEfxCurveTypeInfo::~SEfxCurveTypeInfo() = default;

  /**
   * Address: 0x00514C80 (FUN_00514C80, Moho::SEfxCurveTypeInfo::GetName)
   */
  const char* SEfxCurveTypeInfo::GetName() const
  {
    return "SEfxCurve";
  }

  /**
   * Address: 0x00514C60 (FUN_00514C60, Moho::SEfxCurveTypeInfo::Init)
   *
   * IDA signature:
   * int __thiscall Moho::SEfxCurveTypeInfo::Init(_DWORD *this);
   */
  void SEfxCurveTypeInfo::Init()
  {
    size_ = sizeof(SEfxCurve);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
