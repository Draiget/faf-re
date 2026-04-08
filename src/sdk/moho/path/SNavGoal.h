#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/Rect2.h"
#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum ELayer : std::int32_t;

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

    static gpg::RType* sType;

    /**
     * Address: 0x0050CDB0 (FUN_0050CDB0, Moho::SNavGoal::MemberDeserialize)
     *
     * What it does:
     * Loads the first rectangle, secondary rectangle, and layer payload in
     * exact binary archive order.
     */
    static void MemberDeserialize(SNavGoal* object, gpg::ReadArchive* archive);

    /**
     * Address: 0x0050CE60 (FUN_0050CE60, Moho::SNavGoal::MemberSerialize)
     *
     * What it does:
     * Stores the first rectangle, secondary rectangle, and layer payload in
     * exact binary archive order.
     */
    static void MemberSerialize(const SNavGoal* object, gpg::WriteArchive* archive);
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
   * Serializer helper for `SNavGoal` archive lanes.
   */
  class SNavGoalSerializer
  {
  public:
    /**
     * Address: 0x0050C170 (FUN_0050C170, Moho::SNavGoalSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading to `SNavGoal::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, SNavGoal* goal);

    /**
     * Address: 0x0050C180 (FUN_0050C180, Moho::SNavGoalSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving to `SNavGoal::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, SNavGoal* goal);

    /**
     * Address: 0x0050C870 (FUN_0050C870, Moho::SNavGoalSerializer::RegisterSerializeFunctions)
     *
     * What it does:
     * Binds the serializer callbacks into `SNavGoal` RTTI.
     */
    void RegisterSerializeFunctions();

    virtual ~SNavGoalSerializer() noexcept;

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;    // +0x10
  };

  static_assert(offsetof(SNavGoalSerializer, mHelperNext) == 0x04, "SNavGoalSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(SNavGoalSerializer, mHelperPrev) == 0x08, "SNavGoalSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(SNavGoalSerializer, mDeserialize) == 0x0C, "SNavGoalSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(SNavGoalSerializer, mSerialize) == 0x10, "SNavGoalSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(SNavGoalSerializer) == 0x14, "SNavGoalSerializer size must be 0x14");
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
   * Installs serializer callbacks for `SNavGoal` and registers shutdown
   * unlink/destruction.
   */
  void register_SNavGoalSerializer();
} // namespace moho
