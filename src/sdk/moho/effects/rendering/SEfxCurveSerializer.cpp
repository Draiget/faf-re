#include "moho/effects/rendering/SEfxCurveSerializer.h"

#include "moho/effects/rendering/SEfxCurve.h"

namespace
{
  // Address: 0x010AAA14 -- process-global `SEfxCurveSerializer` singleton.
  // Constructing it runs SEfxCurveSerializer::SEfxCurveSerializer()
  // (0x00BC8440), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::SEfxCurveSerializer gSEfxCurveSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BC8440 (FUN_00BC8440, register_SEfxCurveSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  SEfxCurveSerializer::SEfxCurveSerializer()
    : mLoadCallback(&SEfxCurve::DeserializeFromArchive)
    , mSaveCallback(&SEfxCurve::SerializeToArchive)
  {}

  /**
   * Address: 0x00BF29D0 (FUN_00BF29D0, Moho::SEfxCurveSerializer::~SEfxCurveSerializer)
   *
   * What it does:
   * Unlinks this helper node from whatever intrusive list it currently sits
   * in and restores a self-linked sentinel state.
   */
  SEfxCurveSerializer::~SEfxCurveSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00515B30 (FUN_00515B30, gpg::SerSaveLoadHelper_SEfxCurve::Init)
   *
   * IDA signature:
   * void __thiscall gpg::SerSaveLoadHelper_SEfxCurve::Init(_DWORD *this);
   */
  void SEfxCurveSerializer::Init()
  {
    gpg::RType* const type = SEfxCurve::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
