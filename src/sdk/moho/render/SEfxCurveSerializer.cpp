#include "moho/render/SEfxCurveSerializer.h"

#include "moho/render/SEfxCurve.h"

namespace moho
{
  /**
   * Address: 0x00515B30 (FUN_00515B30, gpg::SerSaveLoadHelper_SEfxCurve::Init)
   *
   * IDA signature:
   * void __thiscall gpg::SerSaveLoadHelper_SEfxCurve::Init(_DWORD *this);
   */
  void SEfxCurveSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = SEfxCurve::StaticGetClass();
    const gpg::RType::load_func_t loadCallback = mLoadCallback ? mLoadCallback : &SEfxCurve::DeserializeFromArchive;
    const gpg::RType::save_func_t saveCallback = mSaveCallback ? mSaveCallback : &SEfxCurve::SerializeToArchive;
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = loadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = saveCallback;
  }
} // namespace moho
