#include "moho/effects/rendering/SEfxCurveSerializer.h"

#include <cstdlib>

#include "moho/effects/rendering/SEfxCurve.h"

namespace
{
  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext != nullptr && helper.mHelperPrev != nullptr) {
      static_cast<gpg::SerHelperBase*>(helper.mHelperNext)->mPrev = static_cast<gpg::SerHelperBase*>(helper.mHelperPrev);
      static_cast<gpg::SerHelperBase*>(helper.mHelperPrev)->mNext = static_cast<gpg::SerHelperBase*>(helper.mHelperNext);
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  moho::SEfxCurveSerializer gSEfxCurveSerializer{};

  [[nodiscard]] gpg::SerHelperBase* ResetSEfxCurveSerializerHelperLinks() noexcept
  {
    gSEfxCurveSerializer.mHelperNext->mPrev = gSEfxCurveSerializer.mHelperPrev;
    gSEfxCurveSerializer.mHelperPrev->mNext = gSEfxCurveSerializer.mHelperNext;
    gpg::SerHelperBase* const self = HelperSelfNode(gSEfxCurveSerializer);
    gSEfxCurveSerializer.mHelperPrev = self;
    gSEfxCurveSerializer.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x00514D90 (FUN_00514D90)
   *
   * What it does:
   * Unlinks `SEfxCurveSerializer` helper node from the global helper list and
   * restores self-linked sentinel links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupSEfxCurveSerializerHelperNodePrimary() noexcept
  {
    return ResetSEfxCurveSerializerHelperLinks();
  }

  /**
   * Address: 0x00514DC0 (FUN_00514DC0)
   *
   * What it does:
   * Secondary entrypoint for `SEfxCurveSerializer` helper unlink/reset.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupSEfxCurveSerializerHelperNodeSecondary() noexcept
  {
    return ResetSEfxCurveSerializerHelperLinks();
  }

  void cleanup_SEfxCurveSerializer()
  {
    (void)CleanupSEfxCurveSerializerHelperNodePrimary();
  }

  struct SEfxCurveSerializerBootstrap
  {
    SEfxCurveSerializerBootstrap()
    {
      moho::register_SEfxCurveSerializer();
    }
  };

  SEfxCurveSerializerBootstrap gSEfxCurveSerializerBootstrap;
} // namespace

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

  /**
   * Address: 0x00BC8440 (FUN_00BC8440, register_SEfxCurveSerializer)
   */
  void register_SEfxCurveSerializer()
  {
    InitializeHelperNode(gSEfxCurveSerializer);
    gSEfxCurveSerializer.mLoadCallback = &SEfxCurve::DeserializeFromArchive;
    gSEfxCurveSerializer.mSaveCallback = &SEfxCurve::SerializeToArchive;
    (void)std::atexit(&cleanup_SEfxCurveSerializer);
  }
} // namespace moho
