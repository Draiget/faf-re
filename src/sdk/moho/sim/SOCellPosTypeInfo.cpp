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

  /**
   * Address: 0x0050CAD0 (FUN_0050CAD0)
   *
   * What it does:
   * Lazily resolves and caches RTTI metadata for `SOCellPos`.
   */
  [[nodiscard]] gpg::RType* ResolveSOCellPosType()
  {
    gpg::RType* type = moho::SOCellPos::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SOCellPos));
      moho::SOCellPos::sType = type;
    }
    return type;
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
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(TSerializer& serializer) noexcept
  {
    if (serializer.mHelperNext != nullptr && serializer.mHelperPrev != nullptr) {
      serializer.mHelperNext->mPrev = serializer.mHelperPrev;
      serializer.mHelperPrev->mNext = serializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x0050BFD0 (FUN_0050BFD0)
   *
   * What it does:
   * Unlinks the `SOCellPosSerializer` helper node and resets both links to
   * the serializer self-node.
   */
  [[nodiscard]] gpg::SerHelperBase* CleanupSOCellPosSerializerVariant1() noexcept
  {
    return UnlinkHelperNode(SOCellPosSerializerStorageRef());
  }

  /**
   * Address: 0x0050C000 (FUN_0050C000)
   *
   * What it does:
   * Duplicate lane of `SOCellPosSerializer` helper-node unlink/reset.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* CleanupSOCellPosSerializerVariant2() noexcept
  {
    return UnlinkHelperNode(SOCellPosSerializerStorageRef());
  }

  /**
   * Address: 0x0050BEF0 (FUN_0050BEF0)
   *
   * What it does:
   * Executes one non-deleting `gpg::RType` base-teardown lane for
   * `SOCellPosTypeInfo`.
   */
  [[maybe_unused]] void cleanup_SOCellPosTypeInfoRTypeBase(moho::SOCellPosTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = msvc8::vector<gpg::RField>{};
    typeInfo->bases_ = msvc8::vector<gpg::RField>{};
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
    (void)CleanupSOCellPosSerializerVariant1();
    serializer.~SOCellPosSerializer();
    gSOCellPosSerializerConstructed = false;
  }
} // namespace

namespace moho
{
  gpg::RType* SOCellPos::sType = nullptr;

  /**
   * Address: 0x0050AC10 (FUN_0050AC10)
   *
   * What it does:
   * Writes the canonical invalid cell-position sentinel (`x = z = 0x8000`).
   */
  [[maybe_unused]] [[nodiscard]] SOCellPos* InitializeInvalidSOCellPos(SOCellPos* const result) noexcept
  {
    result->x = static_cast<std::int16_t>(0x8000);
    result->z = static_cast<std::int16_t>(0x8000);
    return result;
  }

  /**
   * Address: 0x0050AC20 (FUN_0050AC20)
   *
   * What it does:
   * Writes one `(x, z)` pair into a `SOCellPos` lane.
   */
  [[maybe_unused]] [[nodiscard]] SOCellPos* AssignSOCellPosLanes(
    SOCellPos* const result,
    const std::int16_t x,
    const std::int16_t z
  ) noexcept
  {
    result->x = x;
    result->z = z;
    return result;
  }

  /**
   * Address: 0x0050AC40 (FUN_0050AC40)
   *
   * What it does:
   * Returns the `x` lane of one `SOCellPos`.
   */
  [[maybe_unused]] [[nodiscard]] std::int16_t ReadSOCellPosX(const SOCellPos* const value) noexcept
  {
    return value->x;
  }

  /**
   * Address: 0x0050AC50 (FUN_0050AC50)
   *
   * What it does:
   * Returns the `z` lane of one `SOCellPos`.
   */
  [[maybe_unused]] [[nodiscard]] std::int16_t ReadSOCellPosZ(const SOCellPos* const value) noexcept
  {
    return value->z;
  }

  /**
   * Address: 0x005A2C70 (FUN_005A2C70)
   *
   * What it does:
   * Returns whether two cell-position lanes carry identical `(x, z)` values.
   */
  bool operator==(const SOCellPos& lhs, const SOCellPos& rhs) noexcept
  {
    return lhs.x == rhs.x && lhs.z == rhs.z;
  }

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
   * Address: 0x0050BFA0 (FUN_0050BFA0)
   *
   * What it does:
   * Initializes `SOCellPosSerializer` helper links and callback lanes.
   */
  [[nodiscard]] SOCellPosSerializer* initialize_SOCellPosSerializerVariant1()
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
    return &SOCellPosSerializerStorageRef();
  }

  /**
   * Address: 0x0050C7A0 (FUN_0050C7A0)
   *
   * What it does:
   * Duplicate lane of `SOCellPosSerializer` callback initialization.
   */
  [[maybe_unused]] [[nodiscard]] SOCellPosSerializer* initialize_SOCellPosSerializerVariant2()
  {
    return initialize_SOCellPosSerializerVariant1();
  }

  /**
   * Address: 0x0050AEB0 (FUN_0050AEB0, Moho::Invalid<Moho::SOCellPos>)
   *
   * What it does:
   * Lazily initializes one process-static invalid cell position
   * (`x = z = 0x8000`) and returns it by reference.
   */
  template <>
  const SOCellPos& Invalid<SOCellPos>()
  {
    static SOCellPos invalidCellPos{};
    static bool initialized = false;
    if (!initialized) {
      (void)InitializeInvalidSOCellPos(&invalidCellPos);
      initialized = true;
    }

    return invalidCellPos;
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
    (void)initialize_SOCellPosSerializerVariant1();
    (void)ResolveSOCellPosType();
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
