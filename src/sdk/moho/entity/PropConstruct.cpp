#include "moho/entity/PropConstruct.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/Prop.h"
#include "moho/sim/Sim.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  gpg::RType* gSimType = nullptr;
  gpg::RType* gPropType = nullptr;
  moho::PropConstruct gPropConstruct;

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

  [[nodiscard]] moho::Sim* DecodePropConstructOwnerSim(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return nullptr;
    }

    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, gpg::RRef{});
    if (tracked.object == nullptr) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveCachedType<moho::Sim>(gSimType));
    return static_cast<moho::Sim*>(upcast.mObj);
  }

  /**
   * Address: 0x006FA6B0 (FUN_006FA6B0, sub_6FA6B0)
   *
   * What it does:
   * Reads owning Sim pointer from the archive, allocates Prop, and returns it
   * through `SerConstructResult` as an unowned reflected object.
   */
  void ConstructPropFromArchive(gpg::ReadArchive* const archive, gpg::SerConstructResult* const result)
  {
    moho::Sim* const ownerSim = DecodePropConstructOwnerSim(archive);
    moho::Prop* const object = new (std::nothrow) moho::Prop(ownerSim);

    if (!result) {
      return;
    }

    gpg::RRef objectRef{};
    objectRef.mObj = object;
    objectRef.mType = object ? object->GetClass() : ResolveCachedType<moho::Prop>(gPropType);
    result->SetUnowned(objectRef, 0u);
  }

  /**
   * Address: 0x006FA690 (FUN_006FA690, sub_6FA690)
   *
   * What it does:
   * Construct callback thunk forwarding to `ConstructPropFromArchive`.
   */
  void ConstructPropCallback(
    gpg::ReadArchive* const archive, const int, const int, gpg::SerConstructResult* const result
  )
  {
    ConstructPropFromArchive(archive, result);
  }

  /**
   * Address: 0x006FADD0 (FUN_006FADD0, sub_6FADD0)
   *
   * What it does:
   * Deletes constructed Prop via virtual destructor path.
   */
  void DeleteConstructedProp(void* const objectPtr)
  {
    auto* const object = static_cast<moho::Prop*>(objectPtr);
    if (!object) {
      return;
    }

    object->~Prop();
    ::operator delete(object);
  }

  void CleanupPropConstructAtexit()
  {
    (void)moho::cleanup_PropConstruct();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006FA9E0 (FUN_006FA9E0, sub_6FA9E0)
   */
  void PropConstruct::RegisterConstructFunction()
  {
    gpg::RType* type = Prop::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(Prop));
      Prop::sType = type;
    }

    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x00BFF200 (FUN_00BFF200, sub_BFF200)
   */
  gpg::SerHelperBase* cleanup_PropConstruct()
  {
    return UnlinkHelperNode(gPropConstruct);
  }

  /**
   * Address: 0x00BD98D0 (FUN_00BD98D0, sub_BD98D0)
   */
  void register_PropConstruct()
  {
    InitializeHelperNode(gPropConstruct);
    gPropConstruct.mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&ConstructPropCallback);
    gPropConstruct.mDeleteCallback = &DeleteConstructedProp;
    gPropConstruct.RegisterConstructFunction();
    (void)std::atexit(&CleanupPropConstructAtexit);
  }
} // namespace moho

namespace
{
  struct PropConstructBootstrap
  {
    PropConstructBootstrap()
    {
      moho::register_PropConstruct();
    }
  };

  PropConstructBootstrap gPropConstructBootstrap;
} // namespace
