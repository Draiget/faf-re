#include "moho/sim/SOCellPos.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"

#pragma init_seg(lib)

namespace
{
  alignas(moho::SOCellPosTypeInfo) unsigned char
    gSOCellPosTypeInfoStorage[sizeof(moho::SOCellPosTypeInfo)];
  bool gSOCellPosTypeInfoConstructed = false;

  alignas(moho::SOCellPosSerializer) unsigned char
    gSOCellPosSerializerStorage[sizeof(moho::SOCellPosSerializer)];
  bool gSOCellPosSerializerConstructed = false;

  [[nodiscard]] moho::SOCellPosTypeInfo& SOCellPosTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::SOCellPosTypeInfo*>(gSOCellPosTypeInfoStorage);
  }

  [[nodiscard]] moho::SOCellPosSerializer& SOCellPosSerializerStorageRef() noexcept
  {
    return *reinterpret_cast<moho::SOCellPosSerializer*>(gSOCellPosSerializerStorage);
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

  void CleanupSOCellPosTypeInfoAtExit()
  {
    if (!gSOCellPosTypeInfoConstructed) {
      return;
    }

    SOCellPosTypeInfoStorageRef().~SOCellPosTypeInfo();
    gSOCellPosTypeInfoConstructed = false;
  }

  void CleanupSOCellPosSerializerAtExit()
  {
    if (!gSOCellPosSerializerConstructed) {
      return;
    }

    moho::SOCellPosSerializer& serializer = SOCellPosSerializerStorageRef();
    UnlinkHelperNode(serializer);
    serializer.~SOCellPosSerializer();
    gSOCellPosSerializerConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0050BE00 (FUN_0050BE00, Moho::SOCellPosTypeInfo::SOCellPosTypeInfo)
   *
   * What it does:
   * Preregisters the `SOCellPos` RTTI descriptor with the reflection map.
   */
  SOCellPosTypeInfo::SOCellPosTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SOCellPos), this);
  }

  /**
   * Address: 0x00BF2140 (FUN_00BF2140, Moho::SOCellPosTypeInfo::dtr)
   *
   * What it does:
   * Releases the reflected field and base vector storage.
   */
  SOCellPosTypeInfo::~SOCellPosTypeInfo() = default;

  /**
   * Address: 0x0050BE80 (FUN_0050BE80, Moho::SOCellPosTypeInfo::GetName)
   *
   * What it does:
   * Returns the reflected type label for `SOCellPos`.
   */
  const char* SOCellPosTypeInfo::GetName() const
  {
    return "SOCellPos";
  }

  /**
   * Address: 0x0050BE60 (FUN_0050BE60, Moho::SOCellPosTypeInfo::Init)
   *
   * What it does:
   * Sets the reflected size and finalizes the type.
   */
  void SOCellPosTypeInfo::Init()
  {
    size_ = sizeof(SOCellPos);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x0050BF40 (FUN_0050BF40, Moho::SOCellPosSerializer::Deserialize)
   *
   * What it does:
   * Loads the 2D cell coordinate lanes from archive storage in binary order.
   */
  void SOCellPosSerializer::Deserialize(gpg::ReadArchive* const archive, SOCellPos* const cellPos)
  {
    archive->ReadShort(&cellPos->x);
    archive->ReadShort(&cellPos->z);
  }

  /**
   * Address: 0x0050BF70 (FUN_0050BF70, Moho::SOCellPosSerializer::Serialize)
   *
   * What it does:
   * Stores the 2D cell coordinate lanes to archive storage in binary order.
   */
  void SOCellPosSerializer::Serialize(gpg::WriteArchive* const archive, SOCellPos* const cellPos)
  {
    archive->WriteShort(cellPos->x);
    archive->WriteShort(cellPos->z);
  }

  /**
   * Address: 0x00BC7D20 (FUN_00BC7D20, register_SOCellPosTypeInfo)
   *
   * What it does:
   * Installs the static `SOCellPosTypeInfo` instance and its shutdown hook.
   */
  int register_SOCellPosTypeInfo()
  {
    if (!gSOCellPosTypeInfoConstructed) {
      new (gSOCellPosTypeInfoStorage) SOCellPosTypeInfo();
      gSOCellPosTypeInfoConstructed = true;
    }

    return std::atexit(&CleanupSOCellPosTypeInfoAtExit);
  }

  /**
   * Address: 0x00BC7D40 (FUN_00BC7D40, register_SOCellPosSerializer)
   *
   * What it does:
   * Installs serializer callbacks for `SOCellPos` and registers shutdown
   * unlink/destruction.
   */
  void register_SOCellPosSerializer()
  {
    if (!gSOCellPosSerializerConstructed) {
      new (gSOCellPosSerializerStorage) SOCellPosSerializer();
      gSOCellPosSerializerConstructed = true;
    }

    InitializeHelperNode(SOCellPosSerializerStorageRef());
    SOCellPosSerializerStorageRef().mDeserialize =
      reinterpret_cast<gpg::RType::load_func_t>(&SOCellPosSerializer::Deserialize);
    SOCellPosSerializerStorageRef().mSerialize =
      reinterpret_cast<gpg::RType::save_func_t>(&SOCellPosSerializer::Serialize);
    (void)std::atexit(&CleanupSOCellPosSerializerAtExit);
  }

  SOCellPosSerializer::~SOCellPosSerializer() noexcept = default;
} // namespace moho

namespace
{
  struct SOCellPosBootstrap
  {
    SOCellPosBootstrap()
    {
      (void)moho::register_SOCellPosTypeInfo();
      moho::register_SOCellPosSerializer();
    }
  };

  [[maybe_unused]] SOCellPosBootstrap gSOCellPosBootstrap;
} // namespace
