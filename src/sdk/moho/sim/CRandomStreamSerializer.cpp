#include "moho/sim/CRandomStreamSerializer.h"

#include <cstddef>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/CRandomStreamTypeInfo.h"
#include "gpg/core/reflection/StaticInitPhase.h"

// Make CRandomStream type-info registration run before default-segment
// bootstrap objects that query RTTI during static initialization. This is
// orthogonal to CRandomStreamSerializer below: CRandomStreamTypeInfo derives
// from gpg::RType directly (not gpg::SerHelperBase) and its own real ctor
// (0x00BC3360) is independently __xc_a-reachable.
namespace
{
  [[nodiscard]] gpg::RType* CachedCRandomStreamType()
  {
    gpg::RType* type = moho::CRandomStream::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CRandomStream));
      moho::CRandomStream::sType = type;
    }
    return type;
  }

  alignas(moho::CRandomStreamTypeInfo) std::byte gCRandomStreamTypeInfoStorage[sizeof(moho::CRandomStreamTypeInfo)]{};
  bool gCRandomStreamTypeInfoInitialized = false;

  [[nodiscard]] moho::CRandomStreamTypeInfo& CRandomStreamTypeInfoSlot()
  {
    return *reinterpret_cast<moho::CRandomStreamTypeInfo*>(gCRandomStreamTypeInfoStorage);
  }

  /**
   * Address: 0x00BEE720 (FUN_00BEE720, ??1CRandomStreamTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Executes process-exit teardown for CRandomStream type-info startup storage.
   */
  void cleanup_CRandomStreamTypeInfo()
  {
    if (gCRandomStreamTypeInfoInitialized) {
      CRandomStreamTypeInfoSlot().~CRandomStreamTypeInfo();
      gCRandomStreamTypeInfoInitialized = false;
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BC3360 (FUN_00BC3360, register_CRandomStreamTypeInfo)
   *
   * What it does:
   * Startup thunk that materializes CRandomStream type-info storage and
   * registers its process-exit destructor.
   */
  void register_CRandomStreamTypeInfo()
  {
    if (!gCRandomStreamTypeInfoInitialized) {
      new (&CRandomStreamTypeInfoSlot()) CRandomStreamTypeInfo();
      gCRandomStreamTypeInfoInitialized = true;
    }
    (void)std::atexit(&cleanup_CRandomStreamTypeInfo);
  }

  /**
   * Address: 0x00BC3380 (FUN_00BC3380, dynamic initializer for the global
   * `CRandomStreamSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  CRandomStreamSerializer::CRandomStreamSerializer()
    : mLoadCallback(&CRandomStreamSerializer::Deserialize)
    , mSaveCallback(&CRandomStreamSerializer::Serialize)
  {}

  CRandomStreamSerializer::~CRandomStreamSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x0040F1D0 (FUN_0040F1D0, Moho::CRandomStreamSerializer::Deserialize)
   */
  void CRandomStreamSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*
  )
  {
    auto* const object = reinterpret_cast<CRandomStream*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }

    object->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0040F1E0 (FUN_0040F1E0, Moho::CRandomStreamSerializer::Serialize)
   */
  void CRandomStreamSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*
  )
  {
    const auto* const object = reinterpret_cast<const CRandomStream*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }

    object->MemberSerialize(archive);
  }

  /**
   * Address: 0x0040F380 (FUN_0040F380, gpg::SerSaveLoadHelper<class Moho::CRandomStream>::Init)
   *
   * What it does:
   * Resolves CRandomStream RTTI and installs load/save callbacks from this helper.
   */
  void CRandomStreamSerializer::Init()
  {
    gpg::RType* const type = CachedCRandomStreamType();
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

namespace
{
  // Address: 0x010A6A14 -- process-global `CRandomStreamSerializer` singleton.
  moho::CRandomStreamSerializer gCRandomStreamSerializer;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CRandomStreamTypeInfo_f08a86, moho::register_CRandomStreamTypeInfo)
