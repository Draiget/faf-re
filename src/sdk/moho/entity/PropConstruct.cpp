#include "moho/entity/PropConstruct.h"

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

  template <typename TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
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
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD98D0 (FUN_00BD98D0, dynamic initializer for the global
   * `PropConstruct` singleton)
   */
  PropConstruct::PropConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&ConstructPropCallback))
    , mDeleteCallback(&DeleteConstructedProp)
  {}

  /**
   * Address: 0x00BFF200 (FUN_00BFF200, atexit target registered by the real
   * ctor above)
   */
  PropConstruct::~PropConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x006FA9E0 (FUN_006FA9E0, gpg::SerConstructHelper_Prop::Init)
   *
   * What it does:
   * Resolves `Prop` RTTI (caching into its own `sType` static, matching the
   * binary) and installs construct/delete callback lanes. Raw asm at
   * 0x006FA9E0 asserts only `serConstructFunc_ == nullptr` before
   * overwriting both fields unconditionally.
   */
  void PropConstruct::Init()
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
} // namespace moho

namespace
{
  moho::PropConstruct gPropConstruct;
} // namespace
