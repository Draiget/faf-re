#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/Rect2.h"
#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum ELayer : std::int32_t;
  struct SOCellPos;

  /**
   * Recovered goal rectangle payload passed to land/air navigator goal evaluators.
   *
   * Evidence:
   * - CAiNavigatorLand::SetGoal (0x005A3ED0) writes/copies 9 dwords.
   * - CAiNavigatorAir::SetGoal (0x005A4C60) consumes rectangle bounds from this payload.
   */
  struct SNavGoal
  {
    union
    {
      struct
      {
        std::int32_t minX;
        std::int32_t minZ;
        std::int32_t maxX;
        std::int32_t maxZ;
        std::int32_t aux0;
        std::int32_t aux1;
        std::int32_t aux2;
        std::int32_t aux3;
        std::int32_t aux4;
      };
      struct
      {
        gpg::Rect2i mPos1;
        gpg::Rect2i mPos2;
        ELayer mLayer;
      };
    };

    SNavGoal() = default;

    /**
     * Address: 0x005A2CB0 (FUN_005A2CB0, Moho::SNavGoal::SNavGoal)
     *
     * What it does:
     * Builds a one-cell navigation goal rectangle from one map cell coordinate
     * and clears secondary bounds/layer lanes.
     */
    explicit SNavGoal(SOCellPos cellPos) noexcept;

    static gpg::RType* sType;

    /**
     * Address: 0x0050CDB0 (FUN_0050CDB0, Moho::SNavGoal::MemberDeserialize)
     *
     * IDA signature:
     * void __usercall Moho::SNavGoal::MemberDeserialize(Moho::SNavGoal *a1@<eax>, gpg::ReadArchive *a2@<ebx>);
     *
     * What it does:
     * Loads the first rectangle, secondary rectangle, and layer payload in
     * exact binary archive order.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0050CE60 (FUN_0050CE60, Moho::SNavGoal::MemberSerialize)
     *
     * What it does:
     * Stores the first rectangle, secondary rectangle, and layer payload in
     * exact binary archive order.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  using SAiNavigatorGoal = SNavGoal;

  static_assert(sizeof(SNavGoal) == 0x24, "SNavGoal size must be 0x24");
  static_assert(offsetof(SNavGoal, minX) == 0x00, "SNavGoal::minX offset must be 0x00");
  static_assert(offsetof(SNavGoal, minZ) == 0x04, "SNavGoal::minZ offset must be 0x04");
  static_assert(offsetof(SNavGoal, maxX) == 0x08, "SNavGoal::maxX offset must be 0x08");
  static_assert(offsetof(SNavGoal, maxZ) == 0x0C, "SNavGoal::maxZ offset must be 0x0C");
  static_assert(offsetof(SNavGoal, aux0) == 0x10, "SNavGoal::aux0 offset must be 0x10");
  static_assert(offsetof(SNavGoal, aux1) == 0x14, "SNavGoal::aux1 offset must be 0x14");
  static_assert(offsetof(SNavGoal, aux2) == 0x18, "SNavGoal::aux2 offset must be 0x18");
  static_assert(offsetof(SNavGoal, aux3) == 0x1C, "SNavGoal::aux3 offset must be 0x1C");
  static_assert(offsetof(SNavGoal, aux4) == 0x20, "SNavGoal::aux4 offset must be 0x20");
  static_assert(offsetof(SNavGoal, mPos1) == 0x00, "SNavGoal::mPos1 offset must be 0x00");
  static_assert(offsetof(SNavGoal, mPos2) == 0x10, "SNavGoal::mPos2 offset must be 0x10");
  static_assert(offsetof(SNavGoal, mLayer) == 0x20, "SNavGoal::mLayer offset must be 0x20");

  /**
   * Owns reflected metadata for `SNavGoal`.
   */
  class SNavGoalTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0050C030 (FUN_0050C030, Moho::SNavGoalTypeInfo::SNavGoalTypeInfo)
     *
     * What it does:
     * Preregisters the `SNavGoal` RTTI descriptor with the reflection map.
     */
    SNavGoalTypeInfo();

    /**
     * Address: 0x00BF21D0 (FUN_00BF21D0, Moho::SNavGoalTypeInfo::dtr)
     *
     * What it does:
     * Releases the reflected field and base vector storage.
     */
    ~SNavGoalTypeInfo() override;

    /**
     * Address: 0x0050C0B0 (FUN_0050C0B0, Moho::SNavGoalTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type label for `SNavGoal`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050C090 (FUN_0050C090, Moho::SNavGoalTypeInfo::Init)
     *
     * What it does:
     * Sets the reflected size and finalizes the type.
     */
    void Init() override;
  };

  /**
   * VFTABLE: 0x00E0DDB4
   *
   * Demangled: gpg::SerSaveLoadHelper<struct Moho::SNavGoal>
   *
   * Per-instantiation addresses (one compiler-emitted body per `T`; see the
   * template's class-level comment in Reflection.h for the general shape):
   *  - ctor / compiler dynamic-initializer (`register_SNavGoalSerializer`):
   *    0x00BC7DA0 (__xc_a-reachable; dead zero-xref COMDAT duplicates:
   *    0x0050C190, 0x0050C840)
   *  - dtor: 0x00BF2230 (`??1SNavGoalSerializer@Moho@@QAE@@Z`)
   *  - Init(): 0x0050C870
   *  - Deserialize(): 0x0050C170
   *  - Serialize(): 0x0050C180
   */
  using SNavGoalSerializer = gpg::SerSaveLoadHelper<SNavGoal>;

  static_assert(sizeof(SNavGoalTypeInfo) == 0x64, "SNavGoalTypeInfo size must be 0x64");

  /**
   * Address: 0x00BC7D80 (FUN_00BC7D80, register_SNavGoalTypeInfo)
   *
   * What it does:
   * Installs the static `SNavGoalTypeInfo` instance and its shutdown hook.
   */
  void register_SNavGoalTypeInfo();

  /**
   * Address: 0x00BC7DA0 (FUN_00BC7DA0, register_SNavGoalSerializer)
   *
   * What it does:
   * Forces this translation unit's global `SNavGoalSerializer` instance to
   * link into the reflection bootstrap sequence ahead of default-segment
   * consumers that query SNavGoal RTTI during static initialization. The
   * ctor/vtable-install/atexit-dtor-registration sequence this address
   * decompiles to is MSVC's own compiler-generated dynamic initializer for
   * that global, not hand-written source -- see `gpg::SerSaveLoadHelper<T>`
   * in Reflection.h.
   */
  void register_SNavGoalSerializer();
} // namespace moho
