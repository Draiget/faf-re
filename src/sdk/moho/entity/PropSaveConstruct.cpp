#include "moho/entity/PropSaveConstruct.h"

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

  template <typename TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
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
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD98A0 (FUN_00BD98A0, dynamic initializer for the global
   * `PropSaveConstruct` singleton)
   */
  PropSaveConstruct::PropSaveConstruct()
    : mSaveConstructArgsCallback(reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_Prop))
  {}

  /**
   * Address: 0x00BFF1D0 (FUN_00BFF1D0, atexit target registered by the real
   * ctor above)
   */
  PropSaveConstruct::~PropSaveConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x006FA960 (FUN_006FA960, gpg::SerSaveConstructHelper_Prop::Init)
   */
  void PropSaveConstruct::Init()
  {
    gpg::RType* type = Prop::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(Prop));
      Prop::sType = type;
    }

    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }
} // namespace moho

namespace
{
  moho::PropSaveConstruct gPropSaveConstruct;
} // namespace
