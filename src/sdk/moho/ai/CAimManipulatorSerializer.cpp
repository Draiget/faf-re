#include "moho/ai/CAimManipulatorSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "moho/ai/CAimManipulator.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCAimManipulatorType()
  {
    gpg::RType* type = moho::CAimManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CAimManipulator));
      moho::CAimManipulator::sType = type;
    }
    return type;
  }

  // Address: 0x010B2148 -- process-global `CAimManipulatorSerializer`
  // singleton. Constructing it runs CAimManipulatorSerializer::
  // CAimManipulatorSerializer() (0x00BD2290), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~CAimManipulatorSerializer,
  // 0x00BFA960) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  moho::CAimManipulatorSerializer gCAimManipulatorSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x00630030 (FUN_00630030, Moho::CAimManipulatorSerializer::Deserialize)
   */
  void CAimManipulatorSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<CAimManipulator*>(static_cast<std::uintptr_t>(objectPtr));
    CAimManipulator::MemberDeserialize(object, archive);
  }

  /**
   * Address: 0x00630040 (FUN_00630040, Moho::CAimManipulatorSerializer::Serialize)
   */
  void CAimManipulatorSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<const CAimManipulator*>(static_cast<std::uintptr_t>(objectPtr));
    CAimManipulator::MemberSerialize(object, archive);
  }

  /**
   * Address: 0x00630060 (FUN_00630060,
   * ??0CAimManipulatorSerializer@Moho@@QAE@XZ)
   *
   * IDA signature:
   * Moho::CAimManipulatorSerializer *__thiscall
   * Moho::CAimManipulatorSerializer::CAimManipulatorSerializer(void);
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (0x009501D0 -- self-links
   * and splices into `sNewHelpers`), binds the load/save callback fields to
   * `Deserialize` (0x00630030) and `Serialize` (0x00630040), stamps the
   * vtable at 0x00E21420, and returns `this`.
   *
   * The dynamic initializer that runs it for the singleton is a separate body
   * at 0x00BD2290: it inlines this constructor over the object at 0x010B2148
   * and additionally pushes the destructor at 0x00BFA960 for `atexit`, which
   * is the part no source line here expresses.
   */
  CAimManipulatorSerializer::CAimManipulatorSerializer()
    : mDeserialize(&CAimManipulatorSerializer::Deserialize)
    , mSerialize(&CAimManipulatorSerializer::Serialize)
  {}

  /**
   * Address: 0x00BFA960 (FUN_00BFA960, ??1CAimManipulatorSerializer@Moho@@QAE@@Z)
   *
   * What it does:
   * Unlinks this helper node from whatever intrusive list it currently sits
   * in and restores a self-linked sentinel state.
   *
   * 0x00BFA960 is the copy the dynamic initializer registers with `atexit`
   * (pushed at 0x00BD229A). Two byte-identical siblings survive in this
   * translation unit's run at 0x00630090 and 0x006300C0 with no reference of
   * any kind; all three hard-code the singleton at 0x010B214C rather than
   * taking `this`, so they are the static-destructor emission rather than the
   * class destructor proper. The two extras are recorded as ICF twins of this
   * one.
   */
  CAimManipulatorSerializer::~CAimManipulatorSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00632D80 (FUN_00632D80)
   *
   * What it does:
   * Lazily resolves CAimManipulator RTTI and installs load/save callbacks from
   * this helper object into the type descriptor.
   */
  void CAimManipulatorSerializer::Init()
  {
    gpg::RType* const type = CachedCAimManipulatorType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BD2290 caller lane (`ManipulatorStartupRegistrations.cpp`'s
   * reflection bootstrap sequence)
   *
   * What it does:
   * Historically forced construction of the (then lazily-constructed)
   * `CAimManipulatorSerializer` singleton from an explicit registration
   * sequence. `gCAimManipulatorSerializer` is now a genuine namespace-scope
   * global, so its constructor already runs unconditionally at static-init
   * time; this call is kept only so `ManipulatorStartupRegistrations.cpp`'s
   * existing bootstrap sequence does not need editing.
   */
  void register_CAimManipulatorSerializer()
  {
  }
} // namespace moho
