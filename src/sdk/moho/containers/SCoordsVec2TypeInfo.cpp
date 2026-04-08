#include "moho/containers/SCoordsVec2.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"

#pragma init_seg(lib)

namespace
{
  alignas(moho::SCoordsVec2TypeInfo) unsigned char
    gSCoordsVec2TypeInfoStorage[sizeof(moho::SCoordsVec2TypeInfo)];
  bool gSCoordsVec2TypeInfoConstructed = false;

  alignas(moho::SCoordsVec2Serializer) unsigned char
    gSCoordsVec2SerializerStorage[sizeof(moho::SCoordsVec2Serializer)];
  bool gSCoordsVec2SerializerConstructed = false;

  [[nodiscard]] moho::SCoordsVec2TypeInfo& SCoordsVec2TypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::SCoordsVec2TypeInfo*>(gSCoordsVec2TypeInfoStorage);
  }

  [[nodiscard]] moho::SCoordsVec2Serializer& SCoordsVec2SerializerStorageRef() noexcept
  {
    return *reinterpret_cast<moho::SCoordsVec2Serializer*>(gSCoordsVec2SerializerStorage);
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  template <typename TSerializer>
  void InitializeHelperNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  template <typename TSerializer>
  void UnlinkHelperNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    InitializeHelperNode(serializer);
  }

  void CleanupSCoordsVec2TypeInfoAtExit()
  {
    if (!gSCoordsVec2TypeInfoConstructed) {
      return;
    }

    SCoordsVec2TypeInfoStorageRef().~SCoordsVec2TypeInfo();
    gSCoordsVec2TypeInfoConstructed = false;
  }

  void CleanupSCoordsVec2SerializerAtExit()
  {
    if (!gSCoordsVec2SerializerConstructed) {
      return;
    }

    moho::SCoordsVec2Serializer& serializer = SCoordsVec2SerializerStorageRef();
    UnlinkHelperNode(serializer);
    serializer.~SCoordsVec2Serializer();
    gSCoordsVec2SerializerConstructed = false;
  }
} // namespace

namespace moho
{
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

  /**
   * Address: 0x00BC7CE0 (FUN_00BC7CE0, register_SCoordsVec2Serializer)
   *
   * What it does:
   * Installs serializer callbacks for `SCoordsVec2` and registers shutdown
   * unlink/destruction.
   */
  void register_SCoordsVec2Serializer()
  {
    if (!gSCoordsVec2SerializerConstructed) {
      new (gSCoordsVec2SerializerStorage) SCoordsVec2Serializer();
      gSCoordsVec2SerializerConstructed = true;
    }

    InitializeHelperNode(SCoordsVec2SerializerStorageRef());
    SCoordsVec2SerializerStorageRef().mDeserialize =
      reinterpret_cast<gpg::RType::load_func_t>(&SCoordsVec2Serializer::Deserialize);
    SCoordsVec2SerializerStorageRef().mSerialize =
      reinterpret_cast<gpg::RType::save_func_t>(&SCoordsVec2Serializer::Serialize);
    (void)std::atexit(&CleanupSCoordsVec2SerializerAtExit);
  }

  SCoordsVec2Serializer::~SCoordsVec2Serializer() noexcept = default;
} // namespace moho

namespace
{
  struct SCoordsVec2Bootstrap
  {
    SCoordsVec2Bootstrap()
    {
      moho::register_SCoordsVec2TypeInfo();
      moho::register_SCoordsVec2Serializer();
    }
  };

  [[maybe_unused]] SCoordsVec2Bootstrap gSCoordsVec2Bootstrap;
} // namespace
