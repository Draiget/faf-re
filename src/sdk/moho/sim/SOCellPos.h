#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/HashMap.h"

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
   * Reinterprets one cell coordinate as the single 32-bit word the engine's
   * hashed containers key on.
   *
   * The pathfinder's node table hashes and orders cells by this packed value
   * rather than field-by-field - every call site reads the whole dword
   * (`mov edx, [ebp+8]` at 0x00769386 feeding `ldiv`, and the unsigned `cmp`
   * that orders a bucket window), so the packing is observable and must match.
   */
  [[nodiscard]] inline std::uint32_t PackCellKey(const SOCellPos& cell) noexcept
  {
    return static_cast<std::uint32_t>(static_cast<std::uint16_t>(cell.x))
         | (static_cast<std::uint32_t>(static_cast<std::uint16_t>(cell.z)) << 16);
  }

  /**
   * Address: 0x00769560 (FUN_00769560) / 0x0076AC60 / 0x007692F0 (inlined `stdext::hash_value`)
   *
   * What it does:
   * Hashes one cell for `msvc8::hash_map`. Found by argument-dependent lookup,
   * which is how the container picks this up in place of the integral default.
   */
  [[nodiscard]] inline std::size_t hash_value(const SOCellPos& cell) noexcept
  {
    return msvc8::hash_value(static_cast<long>(static_cast<std::int32_t>(PackCellKey(cell))));
  }

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
   * VFTABLE: 0x00E0DD6C
   *
   * Serializer helper for `SOCellPos` archive lanes.
   */
  class SOCellPosSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC7D40 (FUN_00BC7D40, register_SOCellPosSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields. Confirmed from raw disassembly: calls
     * `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7SOCellPosSerializer@Moho@@6B@` -- no eager `Init()` call exists
     * here.
     */
    SOCellPosSerializer();

    /**
     * Address: 0x00BF21A0 (FUN_00BF21A0, Moho::SOCellPosSerializer::~SOCellPosSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SOCellPosSerializer();

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

    /**
     * What it does:
     * Binds SOCellPos load/save callbacks into reflected RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;    // +0x10
  };

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
} // namespace moho
