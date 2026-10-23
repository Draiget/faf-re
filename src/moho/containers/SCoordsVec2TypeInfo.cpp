#include "moho/containers/SCoordsVec2.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  /**
   * Address: 0x0050CAB0 (FUN_0050CAB0)
   *
   * What it does:
   * Lazily resolves and caches RTTI metadata for `SCoordsVec2`.
   */
  [[nodiscard]] gpg::RType* ResolveSCoordsVec2Type()
  {
    gpg::RType* type = moho::SCoordsVec2::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SCoordsVec2));
      moho::SCoordsVec2::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x0050BCC0 (FUN_0050BCC0)
   *
   * What it does:
   * Executes one non-deleting `gpg::RType` base-teardown lane for
   * `SCoordsVec2TypeInfo`.
   */
  [[maybe_unused]] void cleanup_SCoordsVec2TypeInfoRTypeBase(moho::SCoordsVec2TypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = msvc8::vector<gpg::RField>{};
    typeInfo->bases_ = msvc8::vector<gpg::RField>{};
  }
} // namespace

namespace moho
{
  gpg::RType* SCoordsVec2::sType = nullptr;

  /**
   * Address: 0x0050BBD0 (FUN_0050BBD0, Moho::SCoordsVec2TypeInfo::SCoordsVec2TypeInfo)
   *
   * What it does:
   * Preregisters the `SCoordsVec2` RTTI descriptor with the reflection map.
   */
  SCoordsVec2TypeInfo::SCoordsVec2TypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SCoordsVec2), this);
  }

  /**
   * What it does:
   * Releases the reflected field and base vector storage. Its deleting
   * destructor (vtable slot 2) is one of the `gpg::RType` teardown COMDAT
   * clones cited on `gpg::RType::~RType`.
   */
  SCoordsVec2TypeInfo::~SCoordsVec2TypeInfo() = default;

  /**
   * Address: 0x0050BC50 (FUN_0050BC50, Moho::SCoordsVec2TypeInfo::GetName)
   *
   * What it does:
   * Returns the reflected type label for `SCoordsVec2`.
   */
  const char* SCoordsVec2TypeInfo::GetName() const
  {
    return "SCoordsVec2";
  }

  /**
   * Address: 0x0050BC30 (FUN_0050BC30, Moho::SCoordsVec2TypeInfo::Init)
   *
   * What it does:
   * Sets the reflected size and finalizes the type.
   */
  void SCoordsVec2TypeInfo::Init()
  {
    size_ = sizeof(SCoordsVec2);
    gpg::RType::Init();
    Finish();
  }

  void SCoordsVec2::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    archive->ReadFloat(&x);
    archive->ReadFloat(&z);
  }

  void SCoordsVec2::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    archive->WriteFloat(x);
    archive->WriteFloat(z);
  }

  /**
   * Address: 0x00BC7CC0 (FUN_00BC7CC0, register_SCoordsVec2TypeInfo)
   * Address: 0x00BF20B0 (FUN_00BF20B0, atexit destructor of the SCoordsVec2TypeInfo object)
   *
   * What it does:
   * Constructs the static `SCoordsVec2TypeInfo` instance.
   */
  void register_SCoordsVec2TypeInfo()
  {
    static SCoordsVec2TypeInfo sInstance;
  }
} // namespace moho

namespace
{
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SCoordsVec2TypeInfo_ae87f1, moho::register_SCoordsVec2TypeInfo)

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SCoordsVec2>`, vtable 0x00E0DD2C.
   *
   * Address: 0x00BC7CE0 (FUN_00BC7CE0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF2110 (FUN_00BF2110 -- the global's destructor.)
   * Address: 0x0050BD70 (FUN_0050BD70 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x0050C700 (FUN_0050C700 -- an unreferenced copy of the `gpg::SerSaveLoadHelper<SCoordsVec2>` constructor on the same global.)
   * Address: 0x0050C730 (FUN_0050C730 -- `Init`.)
   * Address: 0x0050BD10 (FUN_0050BD10 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x0050BD40 (FUN_0050BD40 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct SCoordsVec2Serializer : gpg::SerSaveLoadHelper<SCoordsVec2>
  {};
} // namespace moho

namespace
{
  // Address: 0x010AA2BC -- process-global `SCoordsVec2Serializer` singleton.
  moho::SCoordsVec2Serializer gSCoordsVec2Serializer;
} // namespace
