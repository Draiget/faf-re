#include "moho/unit/CUnitMotionSerHelpers.h"

#include <cstdlib>

#include "moho/unit/CUnitMotion.h"
#include "moho/unit/CUnitMotionConstruct.h"
#include "moho/unit/CUnitMotionSerializer.h"

namespace
{
  moho::CUnitMotionConstruct gCUnitMotionConstruct;
  moho::CUnitMotionSerializer gCUnitMotionSerializer;

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
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x006BA330 (FUN_006BA330)
   *
   * What it does:
   * Splices `CUnitMotionSerializer` out of its intrusive helper lane when
   * linked, then rewires helper links to the serializer self node.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitMotionSerializerHelperNodeVariantA() noexcept
  {
    return UnlinkHelperNode(gCUnitMotionSerializer);
  }

  /**
   * Address: 0x006BA360 (FUN_006BA360)
   *
   * What it does:
   * Secondary serializer helper unlink/reset variant sharing the same behavior.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkCUnitMotionSerializerHelperNodeVariantB() noexcept
  {
    return UnlinkCUnitMotionSerializerHelperNodeVariantA();
  }

  /**
   * Address: 0x006BAC40 (FUN_006BAC40, destroy_CUnitMotion)
   *
   * What it does:
   * Runs `CUnitMotion` teardown and frees the backing allocation when present.
   */
  void destroy_CUnitMotion(void* const objectPtr)
  {
    auto* const motion = static_cast<moho::CUnitMotion*>(objectPtr);
    if (!motion) {
      return;
    }

    motion->~CUnitMotion();
    ::operator delete(motion);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BFE0A0 (FUN_00BFE0A0, cleanup_CUnitMotionSerializer)
   */
  gpg::SerHelperBase* cleanup_CUnitMotionSerializer()
  {
    return UnlinkCUnitMotionSerializerHelperNodeVariantA();
  }

  /**
   * Address: 0x00BFE070 (FUN_00BFE070, cleanup_CUnitMotionConstruct)
   */
  gpg::SerHelperBase* cleanup_CUnitMotionConstruct()
  {
    gCUnitMotionConstruct.mHelperNext->mPrev = gCUnitMotionConstruct.mHelperPrev;
    gCUnitMotionConstruct.mHelperPrev->mNext = gCUnitMotionConstruct.mHelperNext;

    gpg::SerHelperBase* const self = HelperSelfNode(gCUnitMotionConstruct);
    gCUnitMotionConstruct.mHelperPrev = self;
    gCUnitMotionConstruct.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x00BD7240 (FUN_00BD7240, register_CUnitMotionConstruct)
   */
  int register_CUnitMotionConstruct()
  {
    InitializeHelperNode(gCUnitMotionConstruct);
    gCUnitMotionConstruct.mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&CUnitMotion::MemberConstruct);
    gCUnitMotionConstruct.mDeleteCallback = &destroy_CUnitMotion;
    gCUnitMotionConstruct.RegisterConstructFunction();
    return std::atexit(reinterpret_cast<void (*)()>(&cleanup_CUnitMotionConstruct));
  }

  /**
   * Address: 0x00BD7280 (FUN_00BD7280, register_CUnitMotionSerializer)
   */
  int register_CUnitMotionSerializer()
  {
    InitializeHelperNode(gCUnitMotionSerializer);
    gCUnitMotionSerializer.mLoadCallback =
      reinterpret_cast<gpg::RType::load_func_t>(&CUnitMotionSerializer::Deserialize);
    gCUnitMotionSerializer.mSaveCallback =
      reinterpret_cast<gpg::RType::save_func_t>(&CUnitMotionSerializer::Serialize);
    return std::atexit(reinterpret_cast<void (*)()>(&cleanup_CUnitMotionSerializer));
  }
} // namespace moho

namespace
{
  struct CUnitMotionSerHelpersBootstrap
  {
    CUnitMotionSerHelpersBootstrap()
    {
      (void)moho::register_CUnitMotionConstruct();
      (void)moho::register_CUnitMotionSerializer();
    }
  };

  [[maybe_unused]] CUnitMotionSerHelpersBootstrap gCUnitMotionSerHelpersBootstrap;
} // namespace
