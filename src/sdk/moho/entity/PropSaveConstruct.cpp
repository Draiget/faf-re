#include "moho/entity/PropSaveConstruct.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/Prop.h"
#include "moho/sim/Sim.h"

namespace gpg
{
  class SerSaveConstructArgsResult
  {
  public:
    void SetUnowned(unsigned int value);
  };
} // namespace gpg

namespace
{
  gpg::RType* gSimType = nullptr;
  moho::PropSaveConstruct gPropSaveConstruct;

  template <typename TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return &helper.mHelperLinks;
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperLinks.mNext = self;
    helper.mHelperLinks.mPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperLinks.mNext != nullptr && helper.mHelperLinks.mPrev != nullptr) {
      helper.mHelperLinks.mNext->mPrev = helper.mHelperLinks.mPrev;
      helper.mHelperLinks.mPrev->mNext = helper.mHelperLinks.mNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperLinks.mPrev = self;
    helper.mHelperLinks.mNext = self;
    return self;
  }

  /**
   * Address: 0x006FA500 (FUN_006FA500, sub_6FA500)
   *
   * What it does:
   * Serializes Prop save-construct owner argument (Sim pointer) as unowned tracked pointer.
   */
  void SaveConstructArgs_Prop(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const object = reinterpret_cast<moho::Prop*>(objectPtr);
    if (!archive || !object) {
      return;
    }

    gpg::RRef ownerRef{};
    ownerRef.mObj = object->SimulationRef;
    ownerRef.mType = object->SimulationRef ? ResolveCachedType<moho::Sim>(gSimType) : nullptr;
    gpg::WriteRawPointer(archive, ownerRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});

    if (result) {
      result->SetUnowned(0u);
    }
  }

  void CleanupPropSaveConstructAtexit()
  {
    (void)moho::cleanup_PropSaveConstruct();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006FA960 (FUN_006FA960, sub_6FA960)
   */
  void PropSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* type = Prop::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(Prop));
      Prop::sType = type;
    }

    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x00BFF1D0 (FUN_00BFF1D0, sub_BFF1D0)
   */
  gpg::SerHelperBase* cleanup_PropSaveConstruct()
  {
    return UnlinkHelperNode(gPropSaveConstruct);
  }

  /**
   * Address: 0x00BD98A0 (FUN_00BD98A0, sub_BD98A0)
   */
  void register_PropSaveConstruct()
  {
    InitializeHelperNode(gPropSaveConstruct);
    gPropSaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_Prop);
    gPropSaveConstruct.RegisterSaveConstructArgsFunction();
    (void)std::atexit(&CleanupPropSaveConstructAtexit);
  }
} // namespace moho

namespace
{
  struct PropSaveConstructBootstrap
  {
    PropSaveConstructBootstrap()
    {
      moho::register_PropSaveConstruct();
    }
  };

  PropSaveConstructBootstrap gPropSaveConstructBootstrap;
} // namespace


