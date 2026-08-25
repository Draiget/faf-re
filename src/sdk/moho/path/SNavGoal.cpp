#include "moho/path/SNavGoal.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"
#include "moho/sim/SOCellPos.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  alignas(moho::SNavGoalTypeInfo) unsigned char gSNavGoalTypeInfoStorage[sizeof(moho::SNavGoalTypeInfo)];
  bool gSNavGoalTypeInfoConstructed = false;

  [[nodiscard]] moho::SNavGoalTypeInfo& SNavGoalTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::SNavGoalTypeInfo*>(gSNavGoalTypeInfoStorage);
  }

  // Address: 0x00BC7DA0 (FUN_00BC7DA0, register_SNavGoalSerializer) -- MSVC's
  // own compiler-generated dynamic initializer for this global runs the real
  // `gpg::SerSaveLoadHelper<SNavGoal>` ctor (self-links into `sNewHelpers`,
  // binds `mLoadCallback`/`mSaveCallback` to the template's `Deserialize`/
  // `Serialize`, installs the vtable) and registers the real mangled
  // destructor (`??1SNavGoalSerializer@Moho@@QAE@@Z`, 0x00BF2230) via
  // `atexit`. There is no hand-written "register" function for this in the
  // original source -- matches `gpg::PrimitiveSerHelper<T,IntType>`'s and
  // every other `gpg::SerSaveLoadHelper<T>` instantiation's already-
  // established modeling.
  moho::SNavGoalSerializer gSNavGoalSerializer;

  /**
   * Address: 0x0050C120 (FUN_0050C120)
   *
   * What it does:
   * Executes one non-deleting `gpg::RType` base-teardown lane for
   * `SNavGoalTypeInfo`.
   */
  [[maybe_unused]] void cleanup_SNavGoalTypeInfoRTypeBase(moho::SNavGoalTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = msvc8::vector<gpg::RField>{};
    typeInfo->bases_ = msvc8::vector<gpg::RField>{};
  }

  [[nodiscard]] gpg::RType* CachedRect2iType()
  {
    gpg::RType* cached = gpg::Rect2i::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(gpg::Rect2i));
      gpg::Rect2i::sType = cached;
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedELayerType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::ELayer));
    }
    return cached;
  }

  void CleanupSNavGoalTypeInfoAtExit()
  {
    if (!gSNavGoalTypeInfoConstructed) {
      return;
    }

    SNavGoalTypeInfoStorageRef().~SNavGoalTypeInfo();
    gSNavGoalTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  gpg::RType* SNavGoal::sType = nullptr;

  /**
   * Address: 0x005A2CB0 (FUN_005A2CB0, Moho::SNavGoal::SNavGoal)
   *
   * What it does:
   * Builds a one-cell goal rectangle from one cell coordinate and clears the
   * secondary rectangle/layer payload.
   */
  SNavGoal::SNavGoal(const SOCellPos cellPos) noexcept
  {
    mPos1.x0 = cellPos.x;
    mPos1.z0 = cellPos.z;
    mPos1.x1 = cellPos.x + 1;
    mPos1.z1 = cellPos.z + 1;

    mPos2.x0 = 0;
    mPos2.z0 = 0;
    mPos2.x1 = 0;
    mPos2.z1 = 0;
    mLayer = LAYER_None;
  }

  /**
   * Address: 0x0050CDB0 (FUN_0050CDB0, Moho::SNavGoal::MemberDeserialize)
   *
   * What it does:
   * Loads the first rectangle, secondary rectangle, and layer payload in
   * exact binary archive order.
   */
  void SNavGoal::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    const gpg::RRef ownerRef{};

    archive->Read(CachedRect2iType(), &mPos1, ownerRef);
    archive->Read(CachedRect2iType(), &mPos2, ownerRef);
    archive->Read(CachedELayerType(), &mLayer, ownerRef);
  }

  /**
   * Address: 0x0050CE60 (FUN_0050CE60, Moho::SNavGoal::MemberSerialize)
   *
   * What it does:
   * Stores the first rectangle, secondary rectangle, and layer payload in
   * exact binary archive order.
   */
  void SNavGoal::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    const gpg::RRef ownerRef{};

    archive->Write(CachedRect2iType(), &mPos1, ownerRef);
    archive->Write(CachedRect2iType(), &mPos2, ownerRef);
    archive->Write(CachedELayerType(), &mLayer, ownerRef);
  }

  /**
   * Address: 0x0050C030 (FUN_0050C030, Moho::SNavGoalTypeInfo::SNavGoalTypeInfo)
   *
   * What it does:
   * Preregisters the `SNavGoal` RTTI descriptor with the reflection map.
   */
  SNavGoalTypeInfo::SNavGoalTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SNavGoal), this);
  }

  /**
   * Address: 0x00BF21D0 (FUN_00BF21D0, Moho::SNavGoalTypeInfo::dtr)
   *
   * What it does:
   * Releases the reflected field and base vector storage.
   */
  SNavGoalTypeInfo::~SNavGoalTypeInfo() = default;

  /**
   * Address: 0x0050C0B0 (FUN_0050C0B0, Moho::SNavGoalTypeInfo::GetName)
   *
   * What it does:
   * Returns the reflected type label for `SNavGoal`.
   */
  const char* SNavGoalTypeInfo::GetName() const
  {
    return "SNavGoal";
  }

  /**
   * Address: 0x0050C090 (FUN_0050C090, Moho::SNavGoalTypeInfo::Init)
   *
   * What it does:
   * Sets the reflected size and finalizes the type.
   */
  void SNavGoalTypeInfo::Init()
  {
    size_ = sizeof(SNavGoal);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BC7D80 (FUN_00BC7D80, register_SNavGoalTypeInfo)
   *
   * What it does:
   * Installs the static `SNavGoalTypeInfo` instance and its shutdown hook.
   */
  void register_SNavGoalTypeInfo()
  {
    if (!gSNavGoalTypeInfoConstructed) {
      new (gSNavGoalTypeInfoStorage) SNavGoalTypeInfo();
      gSNavGoalTypeInfoConstructed = true;
    }

    (void)std::atexit(&CleanupSNavGoalTypeInfoAtExit);
  }

  /**
   * Address: 0x00BC7DA0 (FUN_00BC7DA0, register_SNavGoalSerializer)
   *
   * What it does:
   * Forces this translation unit's global `SNavGoalSerializer` instance to
   * link into the reflection bootstrap sequence. See the Doxygen comment on
   * the declaration (SNavGoal.h) and on `gSNavGoalSerializer` above for why
   * this function's body has no field-setting logic of its own.
   */
  void register_SNavGoalSerializer()
  {
    (void)gSNavGoalSerializer;
  }
} // namespace moho

namespace
{
  struct SNavGoalBootstrap
  {
    SNavGoalBootstrap()
    {
      moho::register_SNavGoalTypeInfo();
      moho::register_SNavGoalSerializer();
    }
  };

  [[maybe_unused]] SNavGoalBootstrap gSNavGoalBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SNavGoalTypeInfo_cc117b, moho::register_SNavGoalTypeInfo)
