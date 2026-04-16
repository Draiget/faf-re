#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  template <class T>
  [[nodiscard]] const T& Invalid();

  struct SOCellPos
  {
    static gpg::RType* sType;

    int16_t x;
    int16_t z;
  };

  /**
   * Address: 0x005A2C70 (FUN_005A2C70)
   *
   * What it does:
   * Returns whether two cell-position lanes carry identical `(x, z)` values.
   */
  [[nodiscard]] bool operator==(const SOCellPos& lhs, const SOCellPos& rhs) noexcept;

  /**
   * Owns reflected metadata for `SOCellPos`.
   */
  class SOCellPosTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0050BE00 (FUN_0050BE00, Moho::SOCellPosTypeInfo::SOCellPosTypeInfo)
     *
     * What it does:
     * Preregisters the `SOCellPos` RTTI descriptor with the reflection map.
     */
    SOCellPosTypeInfo();

    /**
     * Address: 0x00BF2140 (FUN_00BF2140, Moho::SOCellPosTypeInfo::dtr)
     *
     * What it does:
     * Releases the reflected field and base vector storage.
     */
    ~SOCellPosTypeInfo() override;

    /**
     * Address: 0x0050BE80 (FUN_0050BE80, Moho::SOCellPosTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type label for `SOCellPos`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0050BE60 (FUN_0050BE60, Moho::SOCellPosTypeInfo::Init)
     *
     * What it does:
     * Sets the reflected size and finalizes the type.
     */
    void Init() override;
  };

  /**
   * Serializer helper for `SOCellPos` archive lanes.
   */
  class SOCellPosSerializer
  {
  public:
    /**
     * Address: 0x0050BF40 (FUN_0050BF40, Moho::SOCellPosSerializer::Deserialize)
     *
     * What it does:
     * Loads the 2D cell coordinate lanes from archive storage in binary order.
     */
    static void Deserialize(gpg::ReadArchive* archive, SOCellPos* cellPos);

    /**
     * Address: 0x0050BF70 (FUN_0050BF70, Moho::SOCellPosSerializer::Serialize)
     *
     * What it does:
     * Stores the 2D cell coordinate lanes to archive storage in binary order.
     */
    static void Serialize(gpg::WriteArchive* archive, SOCellPos* cellPos);

    virtual ~SOCellPosSerializer() noexcept;

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;    // +0x10
  };

  static_assert(offsetof(SOCellPosSerializer, mHelperNext) == 0x04, "SOCellPosSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(SOCellPosSerializer, mHelperPrev) == 0x08, "SOCellPosSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(SOCellPosSerializer, mDeserialize) == 0x0C, "SOCellPosSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(SOCellPosSerializer, mSerialize) == 0x10, "SOCellPosSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(SOCellPosSerializer) == 0x14, "SOCellPosSerializer size must be 0x14");
  static_assert(sizeof(SOCellPosTypeInfo) == 0x64, "SOCellPosTypeInfo size must be 0x64");
  static_assert(sizeof(SOCellPos) == 0x04, "SOCellPos size must be 0x04");
  static_assert(offsetof(SOCellPos, x) == 0x00, "SOCellPos::x offset must be 0x00");
  static_assert(offsetof(SOCellPos, z) == 0x02, "SOCellPos::z offset must be 0x02");

  /**
   * Address: 0x0050AEB0 (FUN_0050AEB0, Moho::Invalid<Moho::SOCellPos>)
   *
   * What it does:
   * Returns process-lifetime singleton invalid cell coordinates
   * (`x = z = 0x8000`).
   */
  template <>
  [[nodiscard]] const SOCellPos& Invalid<SOCellPos>();

  /**
   * Address: 0x00BC7D20 (FUN_00BC7D20, register_SOCellPosTypeInfo)
   *
   * What it does:
   * Installs the static `SOCellPosTypeInfo` instance and its shutdown hook.
   */
  int register_SOCellPosTypeInfo();

  /**
   * Address: 0x00BC7D40 (FUN_00BC7D40, register_SOCellPosSerializer)
   *
   * What it does:
   * Installs serializer callbacks for `SOCellPos` and registers shutdown
   * unlink/destruction.
   */
  void register_SOCellPosSerializer();
} // namespace moho
