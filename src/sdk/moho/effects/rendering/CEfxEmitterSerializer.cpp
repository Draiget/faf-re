#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace
{
  struct CEfxEmitterSerializerRuntime
  {
    void* mVftable;
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CEfxEmitterSerializerRuntime, mHelperNext) == 0x04,
    "CEfxEmitterSerializerRuntime::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CEfxEmitterSerializerRuntime, mHelperPrev) == 0x08,
    "CEfxEmitterSerializerRuntime::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CEfxEmitterSerializerRuntime, mLoadCallback) == 0x0C,
    "CEfxEmitterSerializerRuntime::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CEfxEmitterSerializerRuntime, mSaveCallback) == 0x10,
    "CEfxEmitterSerializerRuntime::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CEfxEmitterSerializerRuntime) == 0x14, "CEfxEmitterSerializerRuntime size must be 0x14");

  CEfxEmitterSerializerRuntime gCEfxEmitterSerializer{};

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    helper.mHelperNext->mPrev = helper.mHelperPrev;
    helper.mHelperPrev->mNext = helper.mHelperNext;

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0065E190 (FUN_0065E190)
   *
   * What it does:
   * Unlinks the global CEfxEmitter serializer helper node and restores
   * self-links on the serializer node.
   */
  gpg::SerHelperBase* UnlinkCEfxEmitterSerializerNodeVariantA()
  {
    return UnlinkHelperNode(gCEfxEmitterSerializer);
  }

  /**
   * Address: 0x0065E1C0 (FUN_0065E1C0)
   *
   * What it does:
   * Runs the duplicate CEfxEmitter serializer helper-node unlink/reset lane.
   */
  gpg::SerHelperBase* UnlinkCEfxEmitterSerializerNodeVariantB()
  {
    return UnlinkHelperNode(gCEfxEmitterSerializer);
  }
} // namespace moho
