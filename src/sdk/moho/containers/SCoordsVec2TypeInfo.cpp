#include "moho/containers/SCoordsVec2.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  alignas(moho::SCoordsVec2TypeInfo) unsigned char
    gSCoordsVec2TypeInfoStorage[sizeof(moho::SCoordsVec2TypeInfo)];
  bool gSCoordsVec2TypeInfoConstructed = false;

  [[nodiscard]] moho::SCoordsVec2TypeInfo& SCoordsVec2TypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::SCoordsVec2TypeInfo*>(gSCoordsVec2TypeInfoStorage);
  }

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

  void CleanupSCoordsVec2TypeInfoAtExit()
  {
    if (!gSCoordsVec2TypeInfoConstructed) {
      return;
    }

    SCoordsVec2TypeInfoStorageRef().~SCoordsVec2TypeInfo();
    gSCoordsVec2TypeInfoConstructed = false;
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
   * Address: 0x00BF20B0 (FUN_00BF20B0, Moho::SCoordsVec2TypeInfo::dtr)
   *
   * What it does:
   * Releases the reflected field and base vector storage.
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

  /**
   * Address: 0x0050BD10 (FUN_0050BD10, Moho::SCoordsVec2Serializer::Deserialize)
   *
   * What it does:
   * Loads the 2D coordinate lanes from archive storage in binary order.
   */
  void SCoordsVec2Serializer::Deserialize(gpg::ReadArchive* const archive, SCoordsVec2* const coords)
  {
    archive->ReadFloat(&coords->x);
    archive->ReadFloat(&coords->z);
  }

  /**
   * Address: 0x0050BD40 (FUN_0050BD40, Moho::SCoordsVec2Serializer::Serialize)
   *
   * What it does:
   * Stores the 2D coordinate lanes to archive storage in binary order.
   */
  void SCoordsVec2Serializer::Serialize(gpg::WriteArchive* const archive, SCoordsVec2* const coords)
  {
    archive->WriteFloat(coords->x);
    archive->WriteFloat(coords->z);
  }

  /**
   * Address: 0x00BC7CE0 (FUN_00BC7CE0, dynamic initializer for the global
   * `SCoordsVec2Serializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  SCoordsVec2Serializer::SCoordsVec2Serializer()
    : mDeserialize(reinterpret_cast<gpg::RType::load_func_t>(&SCoordsVec2Serializer::Deserialize))
    , mSerialize(reinterpret_cast<gpg::RType::save_func_t>(&SCoordsVec2Serializer::Serialize))
  {}

  /**
   * Address: 0x00BF2110 (FUN_00BF2110, Moho::SCoordsVec2Serializer::~SCoordsVec2Serializer)
   */
  SCoordsVec2Serializer::~SCoordsVec2Serializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x0050C730 (FUN_0050C730)
   *
   * What it does:
   * Lazily resolves `SCoordsVec2`'s RTTI and installs load/save callbacks
   * from this helper into the type descriptor.
   */
  void SCoordsVec2Serializer::Init()
  {
    gpg::RType* const type = ResolveSCoordsVec2Type();
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BC7CC0 (FUN_00BC7CC0, register_SCoordsVec2TypeInfo)
   *
   * What it does:
   * Installs the static `SCoordsVec2TypeInfo` instance and its shutdown hook.
   */
  void register_SCoordsVec2TypeInfo()
  {
    if (!gSCoordsVec2TypeInfoConstructed) {
      new (gSCoordsVec2TypeInfoStorage) SCoordsVec2TypeInfo();
      gSCoordsVec2TypeInfoConstructed = true;
    }

    (void)std::atexit(&CleanupSCoordsVec2TypeInfoAtExit);
  }
} // namespace moho

namespace
{
  // Address: 0x010AA2BC -- process-global `SCoordsVec2Serializer` singleton.
  moho::SCoordsVec2Serializer gSCoordsVec2Serializer;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SCoordsVec2TypeInfo_ae87f1, moho::register_SCoordsVec2TypeInfo)
