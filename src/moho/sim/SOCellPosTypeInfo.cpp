#include "moho/sim/SOCellPos.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  /**
   * Address: 0x00BF2140 (FUN_00BF2140, atexit destructor of the SOCellPosTypeInfo object)
   */
  [[nodiscard]] moho::SOCellPosTypeInfo* AcquireSOCellPosTypeInfo()
  {
    static moho::SOCellPosTypeInfo sInstance;
    return &sInstance;
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
   * What it does:
   * Releases the reflected field and base vector storage. The vtable-slot
   * body (0x0050BE90) is identical to `gpg::RType`'s teardown and is cited
   * there (Reflection.h).
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

  void SOCellPos::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    archive->ReadShort(&x);
    archive->ReadShort(&z);
  }

  void SOCellPos::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    archive->WriteShort(x);
    archive->WriteShort(z);
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
   * Constructs the static `SOCellPosTypeInfo` instance, which preregisters it.
   */
  void register_SOCellPosTypeInfo()
  {
    (void)AcquireSOCellPosTypeInfo();
  }

} // namespace moho

namespace
{
  struct SOCellPosTypeInfoBootstrap
  {
    SOCellPosTypeInfoBootstrap()
    {
      (void)moho::register_SOCellPosTypeInfo();
    }
  };

  [[maybe_unused]] SOCellPosTypeInfoBootstrap gSOCellPosTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SOCellPosTypeInfo_9a89ee, moho::register_SOCellPosTypeInfo)

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SOCellPos>`, vtable 0x00E0DD6C.
   *
   * Address: 0x00BC7D40 (FUN_00BC7D40 -- constructs the global and registers its destructor.)
   * Address: 0x00BF21A0 (FUN_00BF21A0 -- the global's destructor.)
   * Address: 0x0050BFA0 (FUN_0050BFA0 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x0050C7A0 (FUN_0050C7A0 -- an unreferenced copy of the `gpg::SerSaveLoadHelper<SOCellPos>` constructor on the same global.)
   * Address: 0x0050C7D0 (FUN_0050C7D0 -- `Init`.)
   * Address: 0x0050BF40 (FUN_0050BF40 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x0050BF70 (FUN_0050BF70 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct SOCellPosSerializer : gpg::SerSaveLoadHelper<SOCellPos>
  {};
} // namespace moho

namespace
{
  // Address: 0x010AA334 -- process-global `SOCellPosSerializer` singleton.
  moho::SOCellPosSerializer gSOCellPosSerializer;
} // namespace
